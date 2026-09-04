// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package udpgw

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	gw "github.com/varwof/gateway-core"
	"github.com/varwof/gateway/capreg"
)

// Listener UDP listener interface, unified for UDP and QUIC proxy types.
type Listener interface {
	Start() error
	Stop()
	Name() string
	ActiveClients() int
	Config() ListenerConfig
	SetPluginRegistry(reg *gw.PluginRegistry)
	// SetPolicyVersionFn injects the current policy version retrieval function (task 5a).
	SetPolicyVersionFn(fn func() uint64)
	// SetPolicyResolverFn injects the function that selects policy version registry by Agent ID (task 5b).
	SetPolicyResolverFn(fn func(agentID string) (uint64, *gw.PluginRegistry))
	// SetRiskMonitor injects the high-risk behavior monitor (2026-08-15, monitoring presentation layer automated response).
	SetRiskMonitor(rm *gw.RiskMonitor)
}

// Gateway UDP three-layer zero-trust security gateway instance.
type Gateway struct {
	bundle         *Bundle
	lang           string
	logger         *slog.Logger
	cfg            *Config
	listeners      map[string]Listener
	crlCaches      map[string]*gw.CRLCache
	ocspCaches     map[string]*gw.OCSPCache
	audit          *gw.AuditLogger
	tsa            *gw.TSAClient
	auditChain     *gw.AuditChain
	tsaProof       *gw.TSAProofLogger
	revoker        *gw.Revoker
	mu             sync.RWMutex
	stopCh         chan struct{}
	renewalCh      chan struct{}
	stopGuard      *gw.StopGuard
	mgmt           *gw.ManagementServer
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

// NewGateway creates a UDP gateway instance.
func NewGateway(cfg *Config, bundle *Bundle, lang string, logger *slog.Logger, audit *gw.AuditLogger, tsa *gw.TSAClient, tsaProof *gw.TSAProofLogger) *Gateway {
	if logger == nil {
		logger = slog.Default()
	}
	cfg.SetDefaults()
	g := &Gateway{
		bundle:       bundle,
		lang:         lang,
		logger:       logger,
		cfg:          cfg,
		listeners:    make(map[string]Listener),
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
	if err := g.loadCapabilityRegistry(g.cfg); err != nil {
		// Startup proceeds but loudly: capability_schemes is configured yet no
		// registry could be established, so capability validation is disabled.
		g.logger.Error("capability validation DISABLED: capability_schemes configured but registry failed to load", "error", err)
	}
	return g
}

// loadAuthorizationPolicy loads authorization_file (with signature verification) and sets it as the global policy.
func (g *Gateway) loadAuthorizationPolicy() {
	cfg := g.cfg
	if cfg.AuthorizationFile == "" {
		return
	}
	fallbackCA := ""
	for _, l := range cfg.Listeners {
		if l.TLS != nil && l.TLS.CACertFile != "" {
			fallbackCA = l.TLS.CACertFile
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

// loadCapabilityRegistry loads the capability registry (register single source).
// Only enabled when capability_schemes is explicitly configured (data plane verification opt-in, backward compatible):
//
//	Specified directory → disk override; directory is empty string but config is non-empty → embedded scheme.
//
// On successful load, sets the gateway-core package-level registry (for data plane pipeline verification).
// On Reload, calls with newCfg for hot reload; on reload failure with an
// existing registry, keeps the existing registry (non-blocking). Returns an
// error only when capability_schemes is configured but no registry can be
// established at all (fail-closed: the caller must abort the reload instead of
// silently running without capability validation).
func (g *Gateway) loadCapabilityRegistry(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	if cfg.CapabilitySchemes == "" {
		// Capability validation was unset (e.g. removed on a SIGHUP reload): disable it
		// instead of leaving a previously-loaded registry active. SetGlobalCapabilityRegistry(nil)
		// is documented to disable capability registration validation.
		gw.SetGlobalCapabilityRegistry(nil)
		g.logger.Info("capability registry disabled (capability_schemes unset)")
		return nil
	}
	loader := g.capReg
	if loader == nil {
		var err error
		loader, err = capreg.New(cfg.CapabilitySchemes)
		if err != nil {
			// No existing registry to fall back to — fail-closed: the caller
			// aborts the reload rather than silently leaving capability
			// validation disabled while the config asks for it.
			g.logger.Error("capability registry initial load failed", "error", err)
			return fmt.Errorf("load capability registry: %w", err)
		}
		g.capReg = loader
	} else if err := loader.Reload(cfg.CapabilitySchemes); err != nil {
		g.logger.Warn("capability registry reload failed, keeping existing", "error", err)
		return nil
	}
	gw.SetGlobalCapabilityRegistry(loader)
	g.logger.Info("capability registry loaded", "schemes", len(loader.Registry().SchemeIDs()), "dir", cfg.CapabilitySchemes)
	return nil
}

func newListener(lc ListenerConfig, crlCache *gw.CRLCache, ocspCache *gw.OCSPCache, logger *slog.Logger, audit *gw.AuditLogger, tsa *gw.TSAClient, stopCh chan struct{}, bundle *Bundle, lang string, revoker *gw.Revoker, connRegistry *gw.ConnRegistry, nonceCache *gw.NonceCache) (Listener, error) {
	switch lc.Protocol {
	case ProtocolQUIC:
		return NewQUICProxy(lc, crlCache, ocspCache, logger, audit, tsa, stopCh, bundle, lang, revoker, connRegistry, nonceCache)
	default:
		return NewUDPProxy(lc, crlCache, ocspCache, logger, audit, tsa, stopCh, bundle, lang, revoker, connRegistry, nonceCache)
	}
}

// Start starts all UDP gateway listeners and management services.
func (g *Gateway) Start() error {
	for i := range g.cfg.Listeners {
		lc := g.cfg.Listeners[i]

		var crlCache *gw.CRLCache
		if lc.TLS != nil && lc.TLS.CRLURL != "" {
			caCert, err := gw.LoadCACert(lc.TLS.CACertFile)
			if err != nil {
				return fmt.Errorf("listener %q: load CA cert: %w", lc.Name, err)
			}
			crlCache = gw.NewCRLCache(caCert, lc.TLS.CRLURL, lc.TLS.CRLRefreshSec, g.bundle, g.lang)
			go crlCache.Start(g.stopCh)
			g.crlCaches[lc.TLS.CRLURL] = crlCache
		}

		ocspCache := buildOCSPCache(lc.TLS, g.bundle, g.lang)

		p, err := newListener(lc, crlCache, ocspCache, g.logger, g.audit, g.tsa, g.stopCh, g.bundle, g.lang, g.revoker, g.connRegistry, g.nonceCache)
		if err != nil {
			return fmt.Errorf("create listener %q: %w", lc.Name, err)
		}
		p.SetPluginRegistry(g.pluginRegistry)
		p.SetPolicyVersionFn(func() uint64 {
			if g.policyMgr == nil {
				return 0
			}
			return g.policyMgr.CurrentVersion()
		})
		p.SetPolicyResolverFn(g.policyResolver())
		p.SetRiskMonitor(g.riskMonitor)
		g.listeners[lc.Name] = p

		if err := p.Start(); err != nil {
			return fmt.Errorf("start listener %q: %w", lc.Name, err)
		}
	}

	if g.cfg.Management != nil {
		ms, err := g.startManagement()
		if err != nil {
			return fmt.Errorf("management API: %w", err)
		}
		g.mgmt = ms
	}

	if g.tsaProof != nil {
		g.tsaProof.Start(g.stopCh)
	}

	if g.chainSyncer != nil {
		g.chainSyncer.Start()
	}

	return nil
}

// UpdateServerCert updates the gateway server TLS certificate without interruption.
func (g *Gateway) UpdateServerCert(cert *tls.Certificate) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, p := range g.listeners {
		if quic, ok := p.(*QUICProxy); ok {
			quic.UpdateCert(cert)
		}
	}
}

// policyResolver constructs a closure that selects policy version registry by Agent ID (task 5b).
// Returns a nil closure when policyMgr is not initialized (caller falls back to pluginRegistry).
func (g *Gateway) policyResolver() func(agentID string) (uint64, *gw.PluginRegistry) {
	if g.policyMgr == nil {
		return nil
	}
	return g.policyMgr.SelectRegistry
}

// Stop gracefully shuts down the UDP gateway (idempotent).
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

	if g.tsaProof != nil {
		g.tsaProof.Stop()
	}
	if g.auditIndex != nil {
		if err := g.auditIndex.Close(); err != nil {
			g.logger.Warn("audit index close failed", "error", err)
		}
	}

	for _, p := range g.listeners {
		p.Stop()
	}
}

// handleRiskAction handles disposition actions triggered by risk rules:
// Disconnect (disconnect all connections for the agent) + conditional revocation (on revoke action).
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
			Protocol:   "udp",
			Decision:   action,
			Mapping:    "risk_monitor",
		})
	}
	// G2(c): Security-triggered proactive revocation (risk monitor disconnect) must not be allowed through by renewal flags.
	if action == "revoke" && g.revoker != nil && registry != nil {
		for _, serial := range serials {
			if cert := registry.Certificate(serial); cert != nil {
				g.revoker.RevokeClientCertForced(cert, g.audit)
			}
		}
	}
}

// Reload hot-reloads the UDP gateway configuration.
func (g *Gateway) Reload() error {
	if g.cfg.configPath == "" {
		if err := g.cfg.Save(); err != nil {
			return fmt.Errorf("save cli config for reload: %w", err)
		}
	}
	newCfg, err := LoadConfig(g.cfg.configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	// Hot-reload risk monitoring rules (SIGHUP reload follows new config).
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

	// Hot-reload capability registry (capability_schemes changes take effect immediately).
	// Fail-closed: if capability_schemes is configured but no registry can be
	// established (and there is no existing registry to keep), abort the reload
	// instead of silently running without capability validation.
	if err := g.loadCapabilityRegistry(newCfg); err != nil {
		return err
	}

	// M1: tear down the previous lifecycle. Old crlCaches and listeners were
	// started against g.stopCh; closing it stops their refresh goroutines so a
	// reload does not leak goroutines or accumulate stale caches.
	close(g.stopCh)
	g.stopCh = make(chan struct{})

	// Restart ConnExpiryRegistry cleanup loop (W04).
	if g.connExpiryStop != nil {
		g.connExpiryStop()
	}
	g.connExpiryStop = g.connExpiry.StartExpiryLoop(0, g.stopCh)

	oldListeners := g.listeners
	newListeners := make(map[string]Listener)

	for _, lc := range newCfg.Listeners {
		if old, exists := oldListeners[lc.Name]; exists {
			if configsEqual(lc, old.Config()) {
				old.SetPluginRegistry(g.pluginRegistry)
				old.SetPolicyVersionFn(func() uint64 {
					if g.policyMgr == nil {
						return 0
					}
					return g.policyMgr.CurrentVersion()
				})
				old.SetPolicyResolverFn(g.policyResolver())
				old.SetRiskMonitor(g.riskMonitor)
				newListeners[lc.Name] = old
				continue
			}
			old.Stop()
		}

		var crlCache *gw.CRLCache
		if lc.TLS != nil && lc.TLS.CRLURL != "" {
			caCert, err := gw.LoadCACert(lc.TLS.CACertFile)
			if err != nil {
				return fmt.Errorf("listener %q: load CA cert: %w", lc.Name, err)
			}
			crlCache = gw.NewCRLCache(caCert, lc.TLS.CRLURL, lc.TLS.CRLRefreshSec, g.bundle, g.lang)
			go crlCache.Start(g.stopCh)
		}

		ocspCache := buildOCSPCache(lc.TLS, g.bundle, g.lang)

		p, err := newListener(lc, crlCache, ocspCache, g.logger, g.audit, g.tsa, g.stopCh, g.bundle, g.lang, g.revoker, g.connRegistry, g.nonceCache)
		if err != nil {
			return fmt.Errorf("create listener %q: %w", lc.Name, err)
		}
		p.SetPluginRegistry(g.pluginRegistry)
		p.SetPolicyVersionFn(func() uint64 {
			if g.policyMgr == nil {
				return 0
			}
			return g.policyMgr.CurrentVersion()
		})
		p.SetPolicyResolverFn(g.policyResolver())
		p.SetRiskMonitor(g.riskMonitor)
		if err := p.Start(); err != nil {
			return fmt.Errorf("start listener %q: %w", lc.Name, err)
		}
		newListeners[lc.Name] = p
	}

	for name, p := range oldListeners {
		if _, keep := newListeners[name]; !keep {
			p.Stop()
		}
	}

	g.listeners = newListeners
	g.cfg = newCfg
	g.cfg.configPath = newCfg.configPath

	// Update management server PluginRegistry
	if g.mgmt != nil {
		g.mgmt.UpdatePluginRegistry(g.pluginRegistry)
	}

	if err := g.cfg.Save(); err != nil {
		g.logger.Warn(g.bundle.T(g.lang, "api.config_persist"), "error", err)
	}

	return nil
}

func configsEqual(a, b ListenerConfig) bool {
	aJSON, _ := json.Marshal(a)
	bJSON, _ := json.Marshal(b)
	return string(aJSON) == string(bJSON)
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

	ms.RegisterHandler("/api/v1/gateway/listeners", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			g.handleListListeners(w, r)
		case http.MethodPost:
			g.handleAddListener(w, r)
		default:
			gw.WriteMgmtError(w, http.StatusMethodNotAllowed, g.bundle.T(g.lang, "api.method_not_allowed"))
		}
	}, gw.RoleAdmin)
	ms.RegisterHandler("/api/v1/gateway/listeners/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			g.handleRemoveListener(w, r)
		} else {
			gw.WriteMgmtError(w, http.StatusMethodNotAllowed, g.bundle.T(g.lang, "api.method_not_allowed"))
		}
	}, gw.RoleAdmin)
	ms.RegisterHandler("/api/v1/gateway/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := g.Reload(); err != nil {
				gw.WriteMgmtJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			gw.WriteMgmtJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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
	ms.RegisterHandler("/api/v1/gateway/disconnect-agent",
		gw.MakeDisconnectByAgentHandler(g.connRegistry, g.bundle, g.lang),
		gw.RoleAdmin)
	ms.RegisterHandler("/api/v1/gateway/disconnect-user",
		gw.MakeDisconnectByUserHandler(g.connRegistry, g.bundle, g.lang),
		gw.RoleAdmin)

	g.logger.Info(g.bundle.T(g.lang, "api.listening"), "listen", cfg.Listen)
	// W34 (2026-08-16): Previously `go ms.Start()` discarded the error, so management API bind
	// failure (port occupied) was silently ignored. Any errors after startup must be logged.
	go func() {
		if err := ms.Start(); err != nil {
			g.logger.Error("management API server error", "listen", cfg.Listen, "error", err)
		}
	}()
	return ms, nil
}

func (g *Gateway) handleListListeners(w http.ResponseWriter, _ *http.Request) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	type info struct {
		Name   string `json:"name"`
		Listen string `json:"listen"`
		Mode   string `json:"tls_mode"`
		Active int    `json:"active_clients"`
	}
	infos := make([]info, 0, len(g.listeners))
	for _, p := range g.listeners {
		infos = append(infos, info{
			Name:   p.Name(),
			Listen: p.Config().Listen,
			Mode:   p.Config().DisplayTLSMode(),
			Active: p.ActiveClients(),
		})
	}
	writeJSON(w, http.StatusOK, infos)
}

func (g *Gateway) handleAddListener(w http.ResponseWriter, r *http.Request) {
	var lc ListenerConfig
	if err := json.NewDecoder(r.Body).Decode(&lc); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.listeners[lc.Name]; exists {
		writeAPIError(w, http.StatusConflict, g.bundle.T(g.lang, "api.listener_exists"))
		return
	}

	var crlCache *gw.CRLCache
	if lc.TLS != nil && lc.TLS.CRLURL != "" {
		caCert, err := gw.LoadCACert(lc.TLS.CACertFile)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "load CA cert: "+err.Error())
			return
		}
		crlCache = gw.NewCRLCache(caCert, lc.TLS.CRLURL, lc.TLS.CRLRefreshSec, g.bundle, g.lang)
		go crlCache.Start(g.stopCh)
		g.crlCaches[lc.TLS.CRLURL] = crlCache
	}

	ocspCache := buildOCSPCache(lc.TLS, g.bundle, g.lang)

	p, err := newListener(lc, crlCache, ocspCache, g.logger, g.audit, g.tsa, g.stopCh, g.bundle, g.lang, g.revoker, g.connRegistry, g.nonceCache)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	p.SetPluginRegistry(g.pluginRegistry)
	p.SetRiskMonitor(g.riskMonitor)
	if err := p.Start(); err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	g.listeners[lc.Name] = p
	g.cfg.Listeners = append(g.cfg.Listeners, lc)

	if err := g.cfg.Save(); err != nil {
		g.logger.Warn(g.bundle.T(g.lang, "api.config_persist"), "error", err)
	}

	writeJSON(w, http.StatusCreated, map[string]string{"status": "ok", "name": lc.Name})
}

func (g *Gateway) handleRemoveListener(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Path[len("/api/v1/gateway/listeners/"):]

	g.mu.Lock()
	defer g.mu.Unlock()

	p, exists := g.listeners[name]
	if !exists {
		writeAPIError(w, http.StatusNotFound, g.bundle.T(g.lang, "api.listener_not_found"))
		return
	}
	p.Stop()
	delete(g.listeners, name)

	for i, lc := range g.cfg.Listeners {
		if lc.Name == name {
			g.cfg.Listeners = append(g.cfg.Listeners[:i], g.cfg.Listeners[i+1:]...)
			break
		}
	}

	if err := g.cfg.Save(); err != nil {
		g.logger.Warn(g.bundle.T(g.lang, "api.config_persist"), "error", err)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "name": name})
}

func (g *Gateway) handleCRLReload(w http.ResponseWriter, _ *http.Request) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	errs := make([]string, 0)
	for url, cache := range g.crlCaches {
		if err := cache.ForceRefresh(); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", url, err))
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

func parseInt(s string) int {
	if s == "" {
		return 0
	}
	var n int
	fmt.Sscanf(s, "%d", &n)
	if n < 0 {
		return 0
	}
	return n
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func buildOCSPCache(tc *gw.TLSConfig, bundle *Bundle, lang string) *gw.OCSPCache {
	if tc == nil || tc.OCSPCacheTTLSec == 0 {
		return nil
	}
	ttl := time.Duration(tc.OCSPCacheTTLSec) * time.Second
	fallback := tc.OCSPFallback
	if fallback == "" {
		fallback = gw.OCSPFallbackDeny
	}
	return gw.NewOCSPCache(ttl, fallback, bundle, lang)
}
