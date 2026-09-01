// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package tcpgw

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	gw "github.com/varwof/gateway-core"
	"github.com/varwof/gateway/capreg"
)

// Gateway is a TCP Layer 4 zero-trust security gateway instance.
type Gateway struct {
	bundle         *Bundle
	lang           string
	logger         *slog.Logger
	cfg            *Config
	mappings       map[string]*Mapping
	tunnels        map[string]*Tunnel
	crlCaches      map[string]*gw.CRLCache
	ocspCaches     map[string]*gw.OCSPCache
	audit          *gw.AuditLogger
	tsa            *gw.TSAClient
	auditChain     *gw.AuditChain
	tsaProof       *gw.TSAProofLogger
	mu             sync.RWMutex
	stopCh         chan struct{}
	renewalCh      chan struct{}
	revoker        *gw.Revoker
	stopGuard      *gw.StopGuard
	mgmt           *gw.ManagementServer
	mesh           *Mesh
	meshListener   net.Listener
	connRegistry   *gw.ConnRegistry
	pluginRegistry *gw.PluginRegistry
	policyMgr      *gw.PolicyManager
	nonceCache     *gw.NonceCache
	connExpiry     *gw.ConnExpiryRegistry
	connExpiryStop func()
	renewalMgr     *gw.ConfirmedRenewalManager
	auditIndex     *gw.AuditIndex
	riskMonitor    *gw.RiskMonitor
	chainRefs      *gw.ChainRefStore
	chainSyncer    *gw.ChainSyncer
	capReg         *capreg.Loader
}

// NewGateway creates a TCP gateway instance.
func NewGateway(cfg *Config, bundle *Bundle, lang string, audit *gw.AuditLogger, tsa *gw.TSAClient, tsaProof *gw.TSAProofLogger, logger *slog.Logger) *Gateway {
	if logger == nil {
		logger = slog.Default()
	}
	cfg.SetDefaults()
	g := &Gateway{
		bundle:       bundle,
		lang:         lang,
		logger:       logger,
		cfg:          cfg,
		mappings:     make(map[string]*Mapping),
		tunnels:      make(map[string]*Tunnel),
		crlCaches:    make(map[string]*gw.CRLCache),
		ocspCaches:   make(map[string]*gw.OCSPCache),
		audit:        audit,
		tsa:          tsa,
		auditChain:   gw.NewAuditChain(1000, nil),
		tsaProof:     tsaProof,
		stopCh:       make(chan struct{}),
		renewalCh:    make(chan struct{}),
		stopGuard:    gw.NewStopGuard(),
		connRegistry: gw.NewConnRegistry(),
		nonceCache:   gw.NewNonceCache(),
		connExpiry:   gw.NewConnExpiryRegistry(),
	}
	if tsaProof != nil {
		tsaProof.SetAuditChain(g.auditChain)
	}
	if cfg.VarwofCore != nil {
		revoker, err := gw.NewRevoker(*cfg.VarwofCore)
		if err == nil {
			g.revoker = revoker
		}
	}
	if g.revoker != nil {
		g.revoker.SetConnRegistry(g.connExpiry)
	}
	g.connExpiryStop = g.connExpiry.StartExpiryLoop(0, g.stopCh)
	if len(cfg.Peers) > 0 {
		g.mesh = NewMesh(cfg.Peers, logger)
	}
	if len(cfg.CapabilityPlugins) > 0 {
		g.pluginRegistry = gw.NewPluginRegistry()
		if err := gw.BuildPluginsFromConfig(g.pluginRegistry, cfg.CapabilityPlugins); err != nil {
			logger.Warn("failed to build plugin registry", "error", err)
		}
	}
	if g.pluginRegistry == nil {
		g.pluginRegistry = gw.NewPluginRegistry()
	}
	g.policyMgr = gw.NewPolicyManager(g.pluginRegistry)
	if cfg.RiskMonitor != nil {
		g.riskMonitor = gw.NewRiskMonitor(gw.RiskMonitorConfig{
			Rules:  cfg.RiskMonitor.Rules,
			Logger: logger,
			OnAction: func(agentId, action, reason string) {
				g.handleRiskAction(agentId, action, reason)
			},
		})
	}
	if cfg.AuditIndexFile != "" {
		idx, err := gw.NewAuditIndex(cfg.AuditIndexFile)
		if err == nil {
			g.auditIndex = idx
		} else {
			logger.Warn("failed to open audit index", "file", cfg.AuditIndexFile, "error", err)
		}
	}
	g.chainRefs = gw.NewChainRefStore()
	if len(cfg.ChainPeers) > 0 {
		peers := make([]gw.ChainSyncClient, 0, len(cfg.ChainPeers))
		for _, p := range cfg.ChainPeers {
			url := p.URL
			if url != "" && !strings.HasSuffix(url, "/") {
				url += "/"
			}
			peers = append(peers, gw.ChainSyncClient{
				Peer:       p.Name,
				URL:        url + "api/v1/gateway/audit/chain",
				HTTPClient: gw.NewChainHTTPClient(p.TLSConfig),
			})
		}
		g.chainSyncer = gw.NewChainSyncer(g.chainRefs, peers, 0)
	}
	if cfg.ShortLived != nil {
		g.renewalMgr = gw.NewConfirmedRenewalManager(cfg.ShortLived, g.connExpiry, func(newCert *x509.Certificate) {
			if newCert == nil {
				return
			}
			logger.Info("confirmed renewal: new cert issued",
				"serial", newCert.SerialNumber.String(),
				"expiry", newCert.NotAfter.Format(time.RFC3339))
		})
	}
	g.loadAuthorizationPolicy()
	g.loadCapabilityRegistry(g.cfg)
	return g
}

// loadAuthorizationPolicy loads the authorization_file (with signature verification) and sets it as the global policy.
func (g *Gateway) loadAuthorizationPolicy() {
	cfg := g.cfg
	if cfg.AuthorizationFile == "" {
		return
	}
	fallbackCA := ""
	for _, m := range cfg.Mappings {
		if m.TLS != nil && m.TLS.CACertFile != "" {
			fallbackCA = m.TLS.CACertFile
			break
		}
	}
	if fallbackCA == "" && cfg.Management != nil && cfg.Management.TLS != nil {
		fallbackCA = cfg.Management.TLS.CACertFile
	}
	opts, err := cfg.PolicySigning.BuildPolicyVerifyOptions(fallbackCA)
	if err != nil {
		g.logger.Warn("policy_signing: build verify opts failed", "error", err)
		return
	}
	require := false
	if cfg.PolicySigning != nil {
		require = cfg.PolicySigning.Require
	}
	suffix := ".sig"
	if cfg.PolicySigning != nil && cfg.PolicySigning.SigSuffix != "" {
		suffix = cfg.PolicySigning.SigSuffix
	}
	if err := gw.LoadGatewayPolicy(cfg.AuthorizationFile, suffix, opts, require); err != nil {
		g.logger.Warn("authorization policy load failed", "error", err)
		return
	}
	g.logger.Info("authorization policy loaded", "path", cfg.AuthorizationFile)
}

// loadCapabilityRegistry loads the capability registry (single source of register).
// Only enabled when capability_schemes is explicitly configured (data plane validation opt-in, backward compatible):
//
//	specified directory → disk override; empty string directory but non-empty config → embedded scheme.
//
// On successful load, sets the gateway-core package-level registry (for data plane pipeline validation).
// During Reload, calls with newCfg for hot reload; on failure, keeps the existing registry (non-blocking).
func (g *Gateway) loadCapabilityRegistry(cfg *Config) {
	if cfg == nil || cfg.CapabilitySchemes == "" {
		return
	}
	loader := g.capReg
	if loader == nil {
		var err error
		loader, err = capreg.New(cfg.CapabilitySchemes)
		if err != nil {
			g.logger.Warn("capability registry load failed, keeping existing", "error", err)
			return
		}
		g.capReg = loader
	} else if err := loader.Reload(cfg.CapabilitySchemes); err != nil {
		g.logger.Warn("capability registry reload failed, keeping existing", "error", err)
		return
	}
	gw.SetGlobalCapabilityRegistry(loader)
	g.logger.Info("capability registry loaded", "schemes", len(loader.Registry().SchemeIDs()), "dir", cfg.CapabilitySchemes)
}

// handleRiskAction handles disposition actions triggered by risk rules:
// Disconnect (drop all connections for the agent) + conditional revocation (on revoke action).
func (g *Gateway) handleRiskAction(agentId, action, reason string) {
	var serials []string
	g.mu.RLock()
	if g.connRegistry != nil {
		for _, ci := range g.connRegistry.ListConnections() {
			if ci.AgentId == agentId && ci.Serial != "" {
				serials = append(serials, ci.Serial)
			}
		}
		disconnected := g.connRegistry.DisconnectByAgentId(agentId)
		g.logger.Warn("risk action executed",
			"agent_id", agentId, "action", action, "reason", reason,
			"disconnected", disconnected, "serials", serials)
	} else {
		g.logger.Warn("risk action executed (no registry)",
			"agent_id", agentId, "action", action, "reason", reason)
	}
	registry := g.connExpiry
	g.mu.RUnlock()
	if g.audit != nil {
		g.audit.Log(gw.AuditEntry{
			Action:     "risk_action",
			Target:     "gateway",
			TargetID:   agentId,
			AgentId:    agentId,
			DenyReason: reason,
			Protocol:   "tcp",
			Decision:   action,
			Mapping:    "risk_monitor",
		})
	}
	// Revoke action: conditionally revoke certificate serials identified by connection details
	// G2(c): Security-triggered proactive revocation (risk monitor disconnect) must not be bypassed by renewal markers.
	if action == "revoke" && g.revoker != nil && registry != nil {
		for _, serial := range serials {
			cert := registry.Certificate(serial)
			if cert != nil {
				g.revoker.RevokeClientCertForced(cert, g.audit)
			}
		}
	}
}

// UpdateServerCert hot-swaps the gateway server TLS certificate without interruption.
func (g *Gateway) UpdateServerCert(cert *tls.Certificate) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, m := range g.mappings {
		m.UpdateCert(cert)
	}
}

// Start starts all TCP gateway mappings, tunnels, and mesh services.
func (g *Gateway) Start() error {
	for i := range g.cfg.Mappings {
		cfg := g.cfg.Mappings[i]

		var crlCache *gw.CRLCache
		if cfg.TLS != nil && cfg.TLS.CRLURL != "" {
			caCert, err := gw.LoadCACert(cfg.TLS.CACertFile)
			if err != nil {
				return fmt.Errorf("mapping %q: load CA cert: %w", cfg.Name, err)
			}
			crlCache = gw.NewCRLCache(caCert, cfg.TLS.CRLURL, cfg.TLS.CRLRefreshSec, g.bundle, g.lang)
			go crlCache.Start(g.stopCh)
			// W40 (2026-08-16): Key by mapping name — previously keyed by crl_url,
			// when two mappings shared crl_url they overwrote each other, and handleCRLReload
			// only refreshed the last one; consistent with the cfg.Name+"/ocsp" pattern for ocspCaches below.
			g.crlCaches[cfg.Name+"/crl"] = crlCache
		}

		ocspCache := buildOCSPCache(cfg.TLS, g.bundle, g.lang)
		if ocspCache != nil {
			g.ocspCaches[cfg.Name+"/ocsp"] = ocspCache
		}

		m, err := NewMapping(cfg, crlCache, ocspCache, g.audit, g.tsa, g.bundle, g.lang, g.revoker, g.logger, g.connRegistry, g.nonceCache)
		if err != nil {
			return fmt.Errorf("create mapping %q: %w", cfg.Name, err)
		}
		if cfg.Protocol == ProtocolTCPMesh && g.mesh != nil {
			m.SetMesh(g.mesh)
		}
		m.pluginRegistry = g.pluginRegistry
		m.policyVersion = func() uint64 {
			if g.policyMgr == nil {
				return 0
			}
			return g.policyMgr.CurrentVersion()
		}
		m.policyResolver = func(agentID string) (uint64, *gw.PluginRegistry) {
			if g.policyMgr == nil {
				return 0, nil
			}
			return g.policyMgr.SelectRegistry(agentID)
		}
		m.riskMonitor = g.riskMonitor
		g.mappings[cfg.Name] = m

		if err := m.Start(); err != nil {
			return fmt.Errorf("start mapping %q: %w", cfg.Name, err)
		}
		MappingUp.Set(1, cfg.Name)
	}

	for i := range g.cfg.Tunnels {
		cfg := g.cfg.Tunnels[i]
		t, err := NewTunnel(cfg, g.logger)
		if err != nil {
			return fmt.Errorf("create tunnel %q: %w", cfg.Name, err)
		}
		g.tunnels[cfg.Name] = t
		if err := t.Start(); err != nil {
			return fmt.Errorf("start tunnel %q: %w", cfg.Name, err)
		}
	}

	if g.cfg.Management != nil {
		ms, err := g.startManagement()
		if err != nil {
			return fmt.Errorf("management API: %w", err)
		}
		g.mgmt = ms
	}

	if g.mesh != nil {
		if err := g.startMeshListener(); err != nil {
			return fmt.Errorf("mesh listener: %w", err)
		}
	}

	if g.tsaProof != nil {
		g.tsaProof.Start(g.stopCh)
	}

	if g.chainSyncer != nil {
		g.chainSyncer.Start()
	}

	return nil
}

// Stop gracefully shuts down the TCP gateway (idempotent).
func (g *Gateway) Stop() {
	if !g.stopGuard.Stop() {
		return
	}
	if g.chainSyncer != nil {
		g.chainSyncer.Stop()
	}
	if g.nonceCache != nil {
		g.nonceCache.Stop()
	}
	close(g.renewalCh)
	close(g.stopCh)

	if g.mgmt != nil {
		g.mgmt.Stop()
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	for _, m := range g.mappings {
		m.Stop()
		MappingUp.Set(0, m.Name())
	}
	for _, t := range g.tunnels {
		t.Stop()
	}
	if g.meshListener != nil {
		g.meshListener.Close()
	}
	if g.tsaProof != nil {
		g.tsaProof.Stop()
	}
	if g.auditIndex != nil {
		if err := g.auditIndex.Close(); err != nil {
			g.logger.Warn("audit index close failed", "error", err)
		}
	}
}

func (g *Gateway) startManagement() (*gw.ManagementServer, error) {
	cfg := g.cfg.Management

	cert, err := gw.LoadCert(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}

	tlsCfg, err := gw.MTLSServerConfig(cfg.TLS.CACertFile, cert, cfg.TLS.CipherSuites, cfg.TLS.MinTLSVersion)
	if err != nil {
		return nil, fmt.Errorf("TLS config: %w", err)
	}

	ms := gw.NewManagementServer(gw.ManagementServerConfig{
		Listen:                  cfg.Listen,
		TLSConfig:               tlsCfg,
		BuildInfo:               buildInfo,
		AuditLogger:             g.audit,
		AuditChain:              g.auditChain,
		Translator:              g.bundle,
		Lang:                    g.lang,
		PluginRegistry:          g.pluginRegistry,
		PolicyManager:           g.policyMgr,
		ConfirmedRenewalManager: g.renewalMgr,
		AuditIndex:              g.auditIndex,
		ConnRegistry:            g.connRegistry,
		ChainRefs:               g.chainRefs,
	})

	ms.RegisterHandler("/api/v1/gateway/mappings", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			g.handleListMappings(w, r)
		case http.MethodPost:
			g.handleAddMapping(w, r)
		default:
			gw.WriteMgmtError(w, http.StatusMethodNotAllowed, g.bundle.T(g.lang, "api.method_not_allowed"))
		}
	}, gw.RoleAdmin)
	ms.RegisterHandler("/api/v1/gateway/mappings/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			g.handleRemoveMapping(w, r)
		} else {
			gw.WriteMgmtError(w, http.StatusMethodNotAllowed, g.bundle.T(g.lang, "api.method_not_allowed"))
		}
	}, gw.RoleAdmin)
	ms.RegisterHandler("/api/v1/gateway/disconnect-agent",
		gw.MakeDisconnectByAgentHandler(g.connRegistry, g.bundle, g.lang),
		gw.RoleAdmin)
	ms.RegisterHandler("/api/v1/gateway/disconnect-user",
		gw.MakeDisconnectByUserHandler(g.connRegistry, g.bundle, g.lang),
		gw.RoleAdmin)
	ms.RegisterHandler("/api/v1/gateway/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			g.handleConfigReload(w, r)
		} else {
			gw.WriteMgmtError(w, http.StatusMethodNotAllowed, g.bundle.T(g.lang, "api.method_not_allowed"))
		}
	}, gw.RoleAdmin)
	ms.RegisterHandler("/api/v1/gateway/crl/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			g.handleCRLReload(w, r)
		} else {
			gw.WriteMgmtError(w, http.StatusMethodNotAllowed, g.bundle.T(g.lang, "api.method_not_allowed"))
		}
	}, gw.RoleAdmin)
	if g.mesh != nil {
		ms.RegisterHandler("/api/v1/gateway/peers", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				g.handleListPeers(w, r)
			} else {
				gw.WriteMgmtError(w, http.StatusMethodNotAllowed, g.bundle.T(g.lang, "api.method_not_allowed"))
			}
		}, gw.RoleOps)
	}
	ms.RegisterHandler("/api/v1/gateway/renew", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			g.handleRenew(w, r)
		} else {
			gw.WriteMgmtError(w, http.StatusMethodNotAllowed, g.bundle.T(g.lang, "api.method_not_allowed"))
		}
	}, gw.RoleOps, gw.RoleAdmin)

	g.logger.Info(g.bundle.T(g.lang, "api.listening"), "listen", cfg.Listen)
	// W34 (2026-08-16): Previously `go ms.Start()` discarded the error, so management API bind
	// failure (port in use) went silently unnoticed. Errors after startup must be logged.
	go func() {
		if err := ms.Start(); err != nil {
			g.logger.Error("management API server error", "listen", cfg.Listen, "error", err)
		}
	}()
	return ms, nil
}

func (g *Gateway) handleListMappings(w http.ResponseWriter, _ *http.Request) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	type mappingInfo struct {
		Name       string       `json:"name"`
		Listen     string       `json:"listen"`
		Target     string       `json:"target"`
		TLSMode    string       `json:"tls_mode"`
		State      MappingState `json:"state"`
		Conns      int64        `json:"conns"`
		Healthy    bool         `json:"healthy"`
		PerIPLimit int          `json:"per_ip_limit,omitempty"`
		TotalLimit int          `json:"total_limit,omitempty"`
	}
	infos := make([]mappingInfo, 0, len(g.mappings))
	for _, m := range g.mappings {
		info := mappingInfo{
			Name:    m.Name(),
			Listen:  m.cfg.Listen,
			Target:  m.cfg.Target,
			TLSMode: m.cfg.DisplayTLSMode(),
			State:   m.State(),
			Conns:   m.Conns(),
			Healthy: m.Healthy(),
		}
		if l := m.cfg.MaxConnsPerIP(); l > 0 {
			info.PerIPLimit = l
		}
		if l := m.cfg.MaxTotalConns(); l > 0 {
			info.TotalLimit = l
		}
		infos = append(infos, info)
	}
	writeJSON(w, http.StatusOK, infos)
}

func (g *Gateway) handleAddMapping(w http.ResponseWriter, r *http.Request) {
	var cfg MappingConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	// W14 (2026-08-16): API-added mappings must go through the same validation as file config.
	// Previously validate() was not run, and invalid tls_mode etc. only errored at Start time.
	if err := (&Config{Mappings: []MappingConfig{cfg}}).validate(); err != nil {
		writeAPIError(w, http.StatusBadRequest, "validate: "+err.Error())
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.mappings[cfg.Name]; exists {
		writeAPIError(w, http.StatusConflict, g.bundle.T(g.lang, "api.mapping_exists"))
		return
	}

	var crlCache *gw.CRLCache
	if cfg.TLS != nil && cfg.TLS.CRLURL != "" {
		caCert, err := gw.LoadCACert(cfg.TLS.CACertFile)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "load CA cert: "+err.Error())
			return
		}
		crlCache = gw.NewCRLCache(caCert, cfg.TLS.CRLURL, cfg.TLS.CRLRefreshSec, g.bundle, g.lang)
		go crlCache.Start(g.stopCh)
		// W40 (2026-08-16): Key by mapping name (see Start()).
		g.crlCaches[cfg.Name+"/crl"] = crlCache
	}

	ocspCache := buildOCSPCache(cfg.TLS, g.bundle, g.lang)

	m, err := NewMapping(cfg, crlCache, ocspCache, g.audit, g.tsa, g.bundle, g.lang, g.revoker, g.logger, g.connRegistry, g.nonceCache)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cfg.Protocol == ProtocolTCPMesh && g.mesh != nil {
		m.SetMesh(g.mesh)
	}
	// W14 (2026-08-16): Wire up plugin/policy consistently with Start/Reload.
	// Previously dynamically added mappings ran the admission pipeline with nil registry + policy version 0,
	// inconsistent with file-based config.
	m.pluginRegistry = g.pluginRegistry
	m.policyVersion = func() uint64 {
		if g.policyMgr == nil {
			return 0
		}
		return g.policyMgr.CurrentVersion()
	}
	m.policyResolver = func(agentID string) (uint64, *gw.PluginRegistry) {
		if g.policyMgr == nil {
			return 0, nil
		}
		return g.policyMgr.SelectRegistry(agentID)
	}
	m.riskMonitor = g.riskMonitor
	if err := m.Start(); err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	g.mappings[cfg.Name] = m
	g.cfg.Mappings = append(g.cfg.Mappings, cfg)

	if err := g.cfg.Save(); err != nil {
		g.logger.Warn(g.bundle.T(g.lang, "api.config_persist"), "error", err)
	}

	writeJSON(w, http.StatusCreated, map[string]string{"status": "ok", "name": cfg.Name})
}

func (g *Gateway) handleRemoveMapping(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Path[len("/api/v1/gateway/mappings/"):]

	g.mu.Lock()
	defer g.mu.Unlock()

	m, exists := g.mappings[name]
	if !exists {
		writeAPIError(w, http.StatusNotFound, g.bundle.T(g.lang, "api.mapping_not_found"))
		return
	}
	m.Stop()
	delete(g.mappings, name)
	// W13 (2026-08-16): Reset gauge consistent with Reload removal; otherwise
	// MappingUp stays at 1 causing false-positive monitoring that the listener is still alive.
	MappingUp.Set(0, name)

	for i, mc := range g.cfg.Mappings {
		if mc.Name == name {
			g.cfg.Mappings = append(g.cfg.Mappings[:i], g.cfg.Mappings[i+1:]...)
			break
		}
	}

	if err := g.cfg.Save(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "config persist failed: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "name": name})
}

func (g *Gateway) handleCRLReload(w http.ResponseWriter, _ *http.Request) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	errs := make([]string, 0)
	for _, cache := range g.crlCaches {
		if err := cache.ForceRefresh(); err != nil {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) > 0 {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"reloaded": len(g.crlCaches) - len(errs),
			"errors":   errs,
		})
	} else {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"reloaded": len(g.crlCaches),
			"errors":   []string{},
		})
	}
}

func (g *Gateway) handleRenew(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		gw.WriteMgmtError(w, http.StatusUnauthorized, "mTLS required")
		return
	}
	clientCert := r.TLS.PeerCertificates[0]

	var req struct {
		SerialHex    string `json:"serial_hex"`
		NewPubKeyPEM string `json:"new_pub_key_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		gw.WriteMgmtError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	currentSerial := clientCert.SerialNumber.Text(16)
	if req.SerialHex == "" || req.NewPubKeyPEM == "" {
		gw.WriteMgmtError(w, http.StatusBadRequest, "serial_hex and new_pub_key_pem required")
		return
	}

	// Finding 11: the request fields must be bound to the presented identity
	// instead of being ignored. serial_hex must reference the exact certificate
	// the caller presented via mTLS, and new_pub_key_pem must be the public key
	// of that certificate — proving the caller controls the key it is renewing.
	if req.SerialHex != currentSerial {
		gw.WriteMgmtError(w, http.StatusBadRequest, "serial_hex does not match the presented certificate")
		return
	}

	pubKey, err := parsePublicKeyPEM([]byte(req.NewPubKeyPEM))
	if err != nil {
		gw.WriteMgmtError(w, http.StatusBadRequest, "invalid public key: "+err.Error())
		return
	}
	if clientCert.PublicKey == nil ||
		!publicKeysEqual(clientCert.PublicKey, pubKey) {
		gw.WriteMgmtError(w, http.StatusBadRequest, "new_pub_key_pem does not match the presented certificate")
		return
	}

	srcIP := r.RemoteAddr
	entry := gw.NewAuditEntryFromConn(srcIP, "", "", clientCert)
	entry.Action = "renew_request"
	entry.SetV12Fields("tcp", "", "", "", "allow")
	g.audit.Log(entry)

	if g.cfg.ShortLived == nil {
		gw.WriteMgmtError(w, http.StatusServiceUnavailable, "short-lived cert issuance not configured")
		return
	}

	issueClient, err := gw.NewIssueClient(*g.cfg.ShortLived)
	if err != nil {
		g.logger.Error("renew: create issue client", "error", err)
		gw.WriteMgmtError(w, http.StatusInternalServerError, "issue client init failed")
		return
	}

	san := clientCert.Subject.CommonName
	if len(clientCert.DNSNames) > 0 {
		san = clientCert.DNSNames[0]
	}

	// W38 (2026-08-16): Issuance validity follows short_lived.default_validity config,
	// default 10 days (previously hardcoded 10).
	validity := 10
	if g.cfg.ShortLived.DefaultValidity > 0 {
		validity = g.cfg.ShortLived.DefaultValidity
	}
	issueReq := &gw.IssueRequest{
		CN:       clientCert.Subject.CommonName,
		SAN:      san,
		Profile:  "client",
		Validity: validity,
	}

	result, err := issueClient.Issue(issueReq)
	if err != nil {
		g.logger.Error("renew: issue cert failed", "error", err, "serial", currentSerial)
		entry := gw.NewAuditEntryDenied(srcIP, "", "", "renew issue failed: "+err.Error(), clientCert)
		g.audit.Log(entry)
		gw.WriteMgmtError(w, http.StatusInternalServerError, "certificate issuance failed: "+err.Error())
		return
	}

	newCert, err := result.Certificate()
	if err != nil {
		g.logger.Error("renew: parse new cert", "error", err)
		gw.WriteMgmtError(w, http.StatusInternalServerError, "parse new cert failed")
		return
	}

	entry2 := gw.NewAuditEntryFromConn(srcIP, "", "", clientCert)
	entry2.Action = "renew"
	entry2.SetV12Fields("tcp", currentSerial, result.SerialNumber, "", "allow")
	g.audit.Log(entry2)

	g.logger.Info("renew: success",
		"old_serial", currentSerial,
		"new_serial", result.SerialNumber,
		"new_expiry", newCert.NotAfter.Format(time.RFC3339))

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"allowed":    true,
		"cert_pem":   result.CertPEM,
		"key_pem":    result.KeyPEM,
		"new_expiry": newCert.NotAfter.Format(time.RFC3339),
	})
}

func (g *Gateway) handleListPeers(w http.ResponseWriter, _ *http.Request) {
	type peerInfo struct {
		Name string `json:"name"`
		Addr string `json:"addr"`
	}
	infos := make([]peerInfo, 0, len(g.cfg.Peers))
	for _, p := range g.cfg.Peers {
		infos = append(infos, peerInfo{Name: p.Name, Addr: p.Addr})
	}
	writeJSON(w, http.StatusOK, infos)
}

// Reload hot-reloads the TCP gateway configuration.
func (g *Gateway) Reload() error {
	if g.cfg.configPath == "" {
		if err := g.cfg.Save(); err != nil {
			return fmt.Errorf("save cli config for reload: %w", err)
		}
	}
	newCfg, err := LoadConfig(g.cfg.configPath)
	if err != nil {
		return fmt.Errorf("load config for reload: %w", err)
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	// Hot-update risk monitor rules (SIGHUP reload follows new config).
	if newCfg.RiskMonitor != nil {
		if g.riskMonitor == nil {
			g.riskMonitor = gw.NewRiskMonitor(gw.RiskMonitorConfig{
				Rules:  newCfg.RiskMonitor.Rules,
				Logger: g.logger,
				OnAction: func(agentId, action, reason string) {
					g.handleRiskAction(agentId, action, reason)
				},
			})
		} else {
			g.riskMonitor.SetRules(newCfg.RiskMonitor.Rules)
		}
	}

	// Rebuild plugin registry from new config (published via PolicyManager, source=sighup)
	if g.policyMgr != nil {
		if _, err := g.policyMgr.Publish(newCfg.CapabilityPlugins, "sighup", ""); err != nil {
			g.logger.Warn("failed to publish policy on reload", "error", err)
		}
		g.pluginRegistry = g.policyMgr.Registry()
	} else {
		newReg := gw.NewPluginRegistry()
		if err := gw.BuildPluginsFromConfig(newReg, newCfg.CapabilityPlugins); err != nil {
			g.logger.Warn("failed to rebuild plugin registry", "error", err)
		}
		g.pluginRegistry = newReg
	}

	// Hot-update capability registry (capability_schemes changes take effect immediately).
	g.loadCapabilityRegistry(newCfg)

	oldMappings := g.mappings
	newMappings := make(map[string]*Mapping)

	oldByName := make(map[string]MappingConfig)
	for _, m := range g.cfg.Mappings {
		oldByName[m.Name] = m
	}

	newByName := make(map[string]MappingConfig)
	for _, m := range newCfg.Mappings {
		newByName[m.Name] = m
	}

	// M1: tear down the previous lifecycle. The old crlCaches and mappings were
	// started against g.stopCh; closing it stops their refresh goroutines so a
	// reload does not leak goroutines or accumulate stale caches. A fresh
	// g.stopCh is created for the new set.
	close(g.stopCh)
	g.stopCh = make(chan struct{})
	g.crlCaches = make(map[string]*gw.CRLCache)

	// Restart ConnExpiryRegistry cleanup loop: it is bound to the closed old stopCh;
	// without restart, transitional entries (expired/renewal-marked) would linger permanently (W04).
	if g.connExpiryStop != nil {
		g.connExpiryStop()
	}
	g.connExpiryStop = g.connExpiry.StartExpiryLoop(0, g.stopCh)

	for name, mc := range newByName {
		old, exists := oldMappings[name]
		if !exists {
			var crlCache *gw.CRLCache
			if mc.TLS != nil && mc.TLS.CRLURL != "" {
				caCert, err := gw.LoadCACert(mc.TLS.CACertFile)
				if err != nil {
					return fmt.Errorf("mapping %q: load CA cert: %w", name, err)
				}
				crlCache = gw.NewCRLCache(caCert, mc.TLS.CRLURL, mc.TLS.CRLRefreshSec, g.bundle, g.lang)
				go crlCache.Start(g.stopCh)
				// W40 (2026-08-16): Key by mapping name.
				g.crlCaches[name+"/crl"] = crlCache
			}
			ocspCache := buildOCSPCache(mc.TLS, g.bundle, g.lang)
			m, err := NewMapping(mc, crlCache, ocspCache, g.audit, g.tsa, g.bundle, g.lang, g.revoker, g.logger, g.connRegistry, g.nonceCache)
			if err != nil {
				return fmt.Errorf("create mapping %q during reload: %w", name, err)
			}
			if mc.Protocol == ProtocolTCPMesh && g.mesh != nil {
				m.SetMesh(g.mesh)
			}
			m.pluginRegistry = g.pluginRegistry
			m.policyVersion = func() uint64 {
				if g.policyMgr == nil {
					return 0
				}
				return g.policyMgr.CurrentVersion()
			}
			m.policyResolver = func(agentID string) (uint64, *gw.PluginRegistry) {
				if g.policyMgr == nil {
					return 0, nil
				}
				return g.policyMgr.SelectRegistry(agentID)
			}
			m.riskMonitor = g.riskMonitor
			if err := m.Start(); err != nil {
				return fmt.Errorf("restart mapping %q during reload: %w", name, err)
			}
			newMappings[name] = m
			g.logger.Info(g.bundle.T(g.lang, "reload.mapping_started"), "name", name)
		} else {
			oldCfg := oldByName[name]
			if !configsEqual(oldCfg, mc) {
				old.Stop()
				var crlCache *gw.CRLCache
				if mc.TLS != nil && mc.TLS.CRLURL != "" {
					caCert, err := gw.LoadCACert(mc.TLS.CACertFile)
					if err != nil {
						return fmt.Errorf("mapping %q: load CA cert: %w", name, err)
					}
					crlCache = gw.NewCRLCache(caCert, mc.TLS.CRLURL, mc.TLS.CRLRefreshSec, g.bundle, g.lang)
					go crlCache.Start(g.stopCh)
					// W40 (2026-08-16): Key by mapping name.
					g.crlCaches[name+"/crl"] = crlCache
				}
				ocspCache := buildOCSPCache(mc.TLS, g.bundle, g.lang)
				m, err := NewMapping(mc, crlCache, ocspCache, g.audit, g.tsa, g.bundle, g.lang, g.revoker, g.logger, g.connRegistry, g.nonceCache)
				if err != nil {
					return fmt.Errorf("restart mapping %q during reload: %w", name, err)
				}
				if mc.Protocol == ProtocolTCPMesh && g.mesh != nil {
					m.SetMesh(g.mesh)
				}
				m.pluginRegistry = g.pluginRegistry
				m.policyVersion = func() uint64 {
					if g.policyMgr == nil {
						return 0
					}
					return g.policyMgr.CurrentVersion()
				}
				m.riskMonitor = g.riskMonitor
				if err := m.Start(); err != nil {
					return fmt.Errorf("create mapping %q during reload: %w", name, err)
				}
				newMappings[name] = m
				g.logger.Info(g.bundle.T(g.lang, "reload.mapping_restarted"), "name", name)
			} else {
				old.pluginRegistry = g.pluginRegistry
				old.policyVersion = func() uint64 {
					if g.policyMgr == nil {
						return 0
					}
					return g.policyMgr.CurrentVersion()
				}
				old.policyResolver = func(agentID string) (uint64, *gw.PluginRegistry) {
					if g.policyMgr == nil {
						return 0, nil
					}
					return g.policyMgr.SelectRegistry(agentID)
				}
				old.riskMonitor = g.riskMonitor
				newMappings[name] = old
			}
		}
	}

	for name, m := range oldMappings {
		if _, keep := newByName[name]; !keep {
			m.Stop()
			// W13 (2026-08-16): Reset gauge after removing mapping; otherwise
			// MappingUp stays at 1 causing false-positive monitoring that the listener is still alive.
			MappingUp.Set(0, name)
			g.logger.Info(g.bundle.T(g.lang, "reload.mapping_stopped"), "name", name)
		}
	}

	// W13 (2026-08-16): Reload now handles tunnel hot-reload. Previously tunnel section changes
	// (add/delete/config change) were silently discarded, only fully shut down at Stop().
	oldTunnels := g.tunnels
	newTunnels := make(map[string]*Tunnel)
	oldTunnelByName := make(map[string]TunnelConfig)
	for _, t := range g.cfg.Tunnels {
		oldTunnelByName[t.Name] = t
	}
	newTunnelByName := make(map[string]TunnelConfig)
	for _, t := range newCfg.Tunnels {
		newTunnelByName[t.Name] = t
	}
	for name, tc := range newTunnelByName {
		if old, exists := oldTunnels[name]; exists {
			if tunnelsEqual(oldTunnelByName[name], tc) {
				newTunnels[name] = old
				continue
			}
			old.Stop()
		}
		t, err := NewTunnel(tc, g.logger)
		if err != nil {
			return fmt.Errorf("create tunnel %q during reload: %w", name, err)
		}
		if err := t.Start(); err != nil {
			return fmt.Errorf("start tunnel %q during reload: %w", name, err)
		}
		newTunnels[name] = t
		g.logger.Info(g.bundle.T(g.lang, "reload.mapping_started"), "name", name)
	}
	for name, t := range oldTunnels {
		if _, keep := newTunnelByName[name]; !keep {
			t.Stop()
			g.logger.Info(g.bundle.T(g.lang, "reload.mapping_stopped"), "name", name)
		}
	}
	g.tunnels = newTunnels

	g.mappings = newMappings
	g.cfg = newCfg
	g.cfg.configPath = newCfg.configPath

	// Update management server PluginRegistry
	if g.mgmt != nil {
		g.mgmt.UpdatePluginRegistry(g.pluginRegistry)
	}

	if err := g.cfg.Save(); err != nil {
		g.logger.Warn(g.bundle.T(g.lang, "reload.persist_config"), "error", err)
	}

	g.logger.Info(g.bundle.T(g.lang, "gateway.reloaded"))
	return nil
}

func configsEqual(a, b MappingConfig) bool {
	aJSON, _ := json.Marshal(a)
	bJSON, _ := json.Marshal(b)
	return string(aJSON) == string(bJSON)
}

func tunnelsEqual(a, b TunnelConfig) bool {
	aJSON, _ := json.Marshal(a)
	bJSON, _ := json.Marshal(b)
	return string(aJSON) == string(bJSON)
}

func (g *Gateway) handleConfigReload(w http.ResponseWriter, _ *http.Request) {
	if err := g.Reload(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"status": "error", "error": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func buildOCSPCache(tls *gw.TLSConfig, bundle *Bundle, lang string) *gw.OCSPCache {
	if tls == nil || tls.OCSPCacheTTLSec == 0 {
		return nil
	}
	ttl := time.Duration(tls.OCSPCacheTTLSec) * time.Second
	fallback := tls.OCSPFallback
	if fallback == "" {
		fallback = gw.OCSPFallbackDeny
	}
	return gw.NewOCSPCache(ttl, fallback, bundle, lang)
}

func writeAPIError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func parsePublicKeyPEM(data []byte) (interface{}, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM data")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	return pub, nil
}

// publicKeysEqual reports whether two crypto public keys are identical.
// Key types not recognized are compared byte-for-byte (fails closed on
// mismatch); nil keys never match.
func publicKeysEqual(a, b interface{}) bool {
	if a == nil || b == nil {
		return false
	}
	switch ka := a.(type) {
	case *rsa.PublicKey:
		kb, ok := b.(*rsa.PublicKey)
		if !ok || ka.N == nil || kb.N == nil {
			return false
		}
		return ka.E == kb.E && ka.N.Cmp(kb.N) == 0
	case *ecdsa.PublicKey:
		kb, ok := b.(*ecdsa.PublicKey)
		if !ok || ka.Curve != kb.Curve {
			return false
		}
		return ka.X.Cmp(kb.X) == 0 && ka.Y.Cmp(kb.Y) == 0
	case ed25519.PublicKey:
		kb, ok := b.(ed25519.PublicKey)
		return ok && bytes.Equal(ka, kb)
	default:
		return reflect.DeepEqual(a, b)
	}
}
