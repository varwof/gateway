// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package httpgw

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
	"github.com/varwof/register"
	"github.com/varwof/register/ruleexec"
)

// Gateway is a Layer 7 zero-trust reverse proxy gateway instance.
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
	RenewalCh      chan struct{}
	stopGuard      *gw.StopGuard
	stopChOnce     sync.Once
	renewalChOnce  sync.Once
	mgmt           *gw.ManagementServer
	connRegistry   *gw.ConnRegistry
	pluginRegistry *gw.PluginRegistry
	policyMgr      *gw.PolicyManager
	nonceCache     *gw.NonceCache
	connExpiry     *gw.ConnExpiryRegistry
	connExpiryStop func()
	renewalMgr     *gw.ConfirmedRenewalManager
	taskRegistry   *gw.TaskRegistry
	auditIndex     *gw.AuditIndex
	riskMonitor    *gw.RiskMonitor
	chainRefs      *gw.ChainRefStore
	chainSyncer    *gw.ChainSyncer
	capReg         *capreg.Loader
}

// NewGateway creates an HTTP gateway instance.
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
		listeners:    make(map[string]Listener),
		crlCaches:    make(map[string]*gw.CRLCache),
		ocspCaches:   make(map[string]*gw.OCSPCache),
		audit:        audit,
		tsa:          tsa,
		auditChain:   gw.NewAuditChain(1000, nil),
		tsaProof:     tsaProof,
		stopCh:       make(chan struct{}),
		RenewalCh:    make(chan struct{}),
		stopGuard:    gw.NewStopGuard(),
		connRegistry: gw.NewConnRegistry(),
		nonceCache:   gw.NewNonceCache(),
		connExpiry:   gw.NewConnExpiryRegistry(),
		taskRegistry: gw.NewTaskRegistry(),
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
	if _, err := g.loadRulePlugins(cfg, g.pluginRegistry); err != nil {
		logger.Warn("failed to load rule plugins", "error", err)
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
	g.loadAuthorizationPolicyFor(g.cfg)
}

// loadAuthorizationPolicyFor loads the authorization_file (with signature verification) from
// the given config and sets it as the global policy. Called with newCfg during Reload to
// implement W26 authorization_file hot-reload.
func (g *Gateway) loadAuthorizationPolicyFor(cfg *Config) {
	fallbackCA := ""
	for _, l := range cfg.Listeners {
		if l.TLS != nil && l.TLS.CACertFile != "" {
			fallbackCA = l.TLS.CACertFile
			break
		}
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
// loadRulePlugins loads signed rules from cfg.RuleSchemes into the
// capability plugin registry (opt-in; same style as capability_schemes).
// RuleSignerCert is the trust anchor for PKCS#7 rule signatures.
func (g *Gateway) loadRulePlugins(cfg *Config, reg *gw.PluginRegistry) ([]string, error) {
	if cfg.RuleSchemes == "" {
		return nil, nil
	}
	if cfg.RuleSignerCert == "" {
		return nil, fmt.Errorf("rule_schemes requires rule_signer_cert")
	}
	roots, err := register.LoadTrustRoots(cfg.RuleSignerCert)
	if err != nil {
		return nil, fmt.Errorf("load rule trust roots: %w", err)
	}
	schemes, err := ruleexec.RegisterRulePluginsFromDir(reg, cfg.RuleSchemes, roots, nil)
	if err != nil {
		return nil, fmt.Errorf("register rule plugins: %w", err)
	}
	g.logger.Info("rule plugins registered", "schemes", len(schemes), "dir", cfg.RuleSchemes)
	return schemes, nil
}

// Only enabled when capability_schemes is explicitly configured (data plane
// verification opt-in, backward-compatible):
//
//	Specified directory -> disk override; empty string but non-empty config -> embedded scheme.
//
// On successful load, sets the gateway-core package-level registry (for data plane pipeline verification).
// Called with newCfg during Reload for hot-reload; on failure, keeps existing registry (non-blocking).
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

// Start starts all HTTP gateway listeners and management services.
func (g *Gateway) Start() error {
	for i := range g.cfg.Listeners {
		cfg := g.cfg.Listeners[i]

		var crlCache *gw.CRLCache
		if cfg.TLS != nil && cfg.TLS.CRLURL != "" {
			caCert, err := gw.LoadCACert(cfg.TLS.CACertFile)
			if err != nil {
				return fmt.Errorf("listener %q: load CA cert: %w", cfg.Name, err)
			}
			crlCache = gw.NewCRLCache(caCert, cfg.TLS.CRLURL, cfg.TLS.CRLRefreshSec, g.bundle, g.lang)
			go crlCache.Start(g.stopCh)
			g.crlCaches[cfg.TLS.CRLURL] = crlCache
		}

		ocspCache := buildOCSPCache(cfg.TLS, g.bundle, g.lang)

		p, err := g.newListener(cfg, crlCache, ocspCache, g.nonceCache)
		if err != nil {
			return fmt.Errorf("create listener %q: %w", cfg.Name, err)
		}
		p.SetLogger(g.logger)
		p.SetPluginRegistry(g.pluginRegistry)
		p.SetTaskRegistry(g.taskRegistry)
		p.SetConnRegistry(g.connRegistry)
		p.SetRevoker(g.revoker)
		p.SetRiskMonitor(g.riskMonitor)
		p.SetPolicyVersionFn(func() uint64 {
			if g.policyMgr == nil {
				return 0
			}
			return g.policyMgr.CurrentVersion()
		})
		p.SetPolicyResolverFn(g.policyResolver())
		g.listeners[cfg.Name] = p

		if err := p.Start(); err != nil {
			return fmt.Errorf("start listener %q: %w", cfg.Name, err)
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
		p.UpdateCert(cert)
	}
}

// policyResolver constructs a closure that selects the policy version registry by agent identifier (Task 5b).
// Returns a nil closure when policyMgr is uninitialized (caller falls back to pluginRegistry).
func (g *Gateway) policyResolver() func(agentID string) (uint64, *gw.PluginRegistry) {
	if g.policyMgr == nil {
		return nil
	}
	return g.policyMgr.SelectRegistry
}

// Stop gracefully shuts down the HTTP gateway (idempotent).
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
	g.renewalChOnce.Do(func() { close(g.RenewalCh) })
	g.stopChOnce.Do(func() { close(g.stopCh) })

	if g.mgmt != nil {
		g.mgmt.Stop()
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	for _, p := range g.listeners {
		p.Stop()
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

// handleRiskAction handles actions triggered by risk rules:
// Disconnect (terminate all connections for this agent) + conditional revocation (on revoke action).
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
			Protocol:   "http",
			Decision:   action,
			Mapping:    "risk_monitor",
		})
	}
	if action == "revoke" && g.revoker != nil && registry != nil {
		for _, serial := range serials {
			if cert := registry.Certificate(serial); cert != nil {
				// G2(c): Proactive security-triggered revocation (risk monitor disconnect) must not be
				// allowed through by the renewal flag.
				g.revoker.RevokeClientCertForced(cert, g.audit)
			}
		}
	}
}

// Reload hot-reloads the HTTP gateway configuration.
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

	if _, err := g.loadRulePlugins(newCfg, g.pluginRegistry); err != nil {
		g.logger.Warn("failed to load rule plugins on reload", "error", err)
	}

	// Hot-update authorization_file policy (W26: previously Reload did not reload the policy,
	// requiring a restart after modifying authorization_file to take effect).
	g.loadAuthorizationPolicyFor(newCfg)

	// Hot-update capability registry (capability_schemes changes take effect immediately).
	g.loadCapabilityRegistry(newCfg)

	oldListeners := g.listeners

	// W26 (2026-08-16): Atomic Reload. The original implementation closed g.stopCh first and then
	// constructed listeners one by one; any construction failure midway left a half-old half-new
	// state with a stale g.cfg. Changed to two phases:
	//   Phase 1: Construct only (newListener + new CRL cache, no Start, no tear down).
	//            Any construction error -> close new stopCh to stop new cache goroutines; old lifecycle
	//            remains untouched, Reload returns error, config stays consistent.
	//   Phase 2: Only after all constructions succeed, close old stopCh (tear down old lifecycle),
	//            start new listeners, stop removed old listeners.
	newStopCh := make(chan struct{})

	// Phase 1: Construction (pending stores new listeners to Start and their corresponding old listeners).
	type pendingListener struct {
		li  Listener
		old Listener // Old listener with the same name (port occupied, must Stop before starting new one)
	}
	pending := make([]pendingListener, 0, len(newCfg.Listeners))
	newListeners := make(map[string]Listener)

	for _, lc := range newCfg.Listeners {
		if old, exists := oldListeners[lc.Name]; exists && configsEqual(lc, old.Config()) {
			// Retaining listener: CRL cache must be replaced with an instance bound to the new stopCh,
			// otherwise revocation checking will be permanently disabled after SIGHUP (W16). The old cache's
			// refresh goroutine stops when the old stopCh is closed.
			var newCache *gw.CRLCache
			if lc.TLS != nil && lc.TLS.CRLURL != "" {
				caCert, err := gw.LoadCACert(lc.TLS.CACertFile)
				if err != nil {
					close(newStopCh)
					return fmt.Errorf("listener %q: load CA cert: %w", lc.Name, err)
				}
				newCache = gw.NewCRLCache(caCert, lc.TLS.CRLURL, lc.TLS.CRLRefreshSec, g.bundle, g.lang)
				go newCache.Start(newStopCh)
			}
			old.SetCRLCache(newCache)
			old.SetPluginRegistry(g.pluginRegistry)
			old.SetTaskRegistry(g.taskRegistry)
			old.SetConnRegistry(g.connRegistry)
			old.SetRevoker(g.revoker)
			old.SetRiskMonitor(g.riskMonitor)
			old.SetPolicyVersionFn(func() uint64 {
				if g.policyMgr == nil {
					return 0
				}
				return g.policyMgr.CurrentVersion()
			})
			old.SetPolicyResolverFn(g.policyResolver())
			newListeners[lc.Name] = old
			continue
		}

		var crlCache *gw.CRLCache
		if lc.TLS != nil && lc.TLS.CRLURL != "" {
			caCert, err := gw.LoadCACert(lc.TLS.CACertFile)
			if err != nil {
				close(newStopCh)
				return fmt.Errorf("listener %q: load CA cert: %w", lc.Name, err)
			}
			crlCache = gw.NewCRLCache(caCert, lc.TLS.CRLURL, lc.TLS.CRLRefreshSec, g.bundle, g.lang)
			go crlCache.Start(newStopCh)
		}

		ocspCache := buildOCSPCache(lc.TLS, g.bundle, g.lang)

		p, err := g.newListener(lc, crlCache, ocspCache, g.nonceCache)
		if err != nil {
			close(newStopCh)
			return fmt.Errorf("create listener %q: %w", lc.Name, err)
		}
		p.SetLogger(g.logger)
		p.SetPluginRegistry(g.pluginRegistry)
		p.SetTaskRegistry(g.taskRegistry)
		p.SetConnRegistry(g.connRegistry)
		p.SetRiskMonitor(g.riskMonitor)
		p.SetPolicyVersionFn(func() uint64 {
			if g.policyMgr == nil {
				return 0
			}
			return g.policyMgr.CurrentVersion()
		})
		p.SetPolicyResolverFn(g.policyResolver())

		var oldLi Listener
		if old, exists := oldListeners[lc.Name]; exists {
			oldLi = old
		}
		pending = append(pending, pendingListener{li: p, old: oldLi})
	}

	// Phase 2: All constructions succeeded, begin tearing down old lifecycle.
	g.stopChOnce.Do(func() { close(g.stopCh) })
	g.stopCh = newStopCh
	g.stopChOnce = sync.Once{} // reset for new channel

	// Restart ConnExpiryRegistry cleanup loop (W04).
	if g.connExpiryStop != nil {
		g.connExpiryStop()
	}
	g.connExpiryStop = g.connExpiry.StartExpiryLoop(0, g.stopCh)

	for _, pl := range pending {
		// Stop old listener with the same name first (same port), then start new instance.
		if pl.old != nil {
			pl.old.Stop()
		}
		if err := pl.li.Start(); err != nil {
			g.stopChOnce.Do(func() { close(g.stopCh) })
			return fmt.Errorf("start listener %q: %w", pl.li.Name(), err)
		}
		newListeners[pl.li.Name()] = pl.li
	}

	for name, p := range oldListeners {
		if _, keep := newListeners[name]; !keep {
			p.Stop()
		}
	}

	g.listeners = newListeners
	// W33 (2026-08-16): Rebuild crlCaches snapshot to avoid accumulating stale entries
	// across reloads (this map is used by the management API for full refresh/monitoring;
	// even write-only usage must stay consistent with the current listener set).
	// Old cache goroutines have already stopped with the old stopCh.
	g.crlCaches = make(map[string]*gw.CRLCache)
	for _, lc := range newCfg.Listeners {
		if lc.TLS == nil || lc.TLS.CRLURL == "" {
			continue
		}
		li, ok := newListeners[lc.Name]
		if !ok {
			continue
		}
		switch v := li.(type) {
		case *ProxyListener:
			if v.CRLCache() != nil {
				g.crlCaches[lc.Name+"/crl"] = v.CRLCache()
			}
		case *QUICListener:
			if v.CRLCache() != nil {
				g.crlCaches[lc.Name+"/crl"] = v.CRLCache()
			}
		}
	}
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
	ms.RegisterHandler("/api/v1/gateway/disconnect-agent",
		gw.MakeDisconnectByAgentHandler(g.connRegistry, g.bundle, g.lang),
		gw.RoleAdmin)
	ms.RegisterHandler("/api/v1/gateway/disconnect-user",
		gw.MakeDisconnectByUserHandler(g.connRegistry, g.bundle, g.lang),
		gw.RoleAdmin)

	// A3/A5: Task lifecycle management API. PUT registers a task, DELETE unregisters,
	// POST /tasks/{id}/complete triggers conditional revocation.
	ms.RegisterHandler("/api/v1/gateway/tasks/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/gateway/tasks/")
		if id == "" {
			gw.WriteMgmtError(w, http.StatusBadRequest, g.bundle.T(g.lang, "api.task_id_required"))
			return
		}
		switch r.Method {
		case http.MethodPut:
			var body struct {
				Serial  string `json:"serial"`
				AgentID string `json:"agent_id"`
				Note    string `json:"note"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil && body.Serial == "" {
				gw.WriteMgmtError(w, http.StatusBadRequest, g.bundle.T(g.lang, "api.invalid_json"))
				return
			}
			g.taskRegistry.Register(id, body.Serial, body.AgentID, body.Note, time.Now().Unix())
			gw.WriteMgmtJSON(w, http.StatusOK, map[string]string{"task_id": id, "status": "registered"})
		case http.MethodDelete:
			rec := g.taskRegistry.Unregister(id)
			gw.WriteMgmtJSON(w, http.StatusOK, map[string]any{"task_id": id, "unregistered": rec != nil})
		case http.MethodPost:
			// Completion signal: find the certificate serial number associated with the task and revoke it.
			rec := g.taskRegistry.Complete(id, time.Now().Unix())
			if rec == nil {
				gw.WriteMgmtError(w, http.StatusNotFound, g.bundle.T(g.lang, "api.task_not_found"))
				return
			}
			if rec.Serial == "" {
				gw.WriteMgmtError(w, http.StatusBadRequest, g.bundle.T(g.lang, "api.task_no_serial"))
				return
			}
			if g.revoker != nil {
				if cert := g.connExpiry.Certificate(rec.Serial); cert != nil {
					// G2(c): Task completion triggers proactive security revocation ("revoke when done"),
					// must not be allowed through by the renewal flag.
					g.revoker.RevokeClientCertForced(cert, g.audit)
				}
			}
			g.taskRegistry.Unregister(id)
			gw.WriteMgmtJSON(w, http.StatusOK, map[string]any{"task_id": id, "serial": rec.Serial, "status": "completed"})
		default:
			gw.WriteMgmtError(w, http.StatusMethodNotAllowed, g.bundle.T(g.lang, "api.method_not_allowed"))
		}
	}, gw.RoleAdmin)

	g.logger.Info(g.bundle.T(g.lang, "api.listening"), "listen", cfg.Listen)
	// W34 (2026-08-16): Previously `go ms.Start()` discarded the error; management API bind
	// failure (port occupied) went unnoticed. Must log errors after startup.
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

	type listenerInfo struct {
		Name   string     `json:"name"`
		Listen string     `json:"listen"`
		Mode   string     `json:"tls_mode"`
		State  ProxyState `json:"state"`
		Conns  int64      `json:"conns"`
		Routes int        `json:"routes"`
	}
	infos := make([]listenerInfo, 0, len(g.listeners))
	for _, p := range g.listeners {
		infos = append(infos, listenerInfo{
			Name:   p.Name(),
			Listen: p.Config().Listen,
			Mode:   p.Config().DisplayTLSMode(),
			State:  p.State(),
			Conns:  p.Conns(),
			Routes: len(p.Config().Routes),
		})
	}
	writeJSON(w, http.StatusOK, infos)
}

func (g *Gateway) handleAddListener(w http.ResponseWriter, r *http.Request) {
	var cfg ListenerConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	// W23 (2026-08-16): API-added listeners must go through the same validation and factory
	// as file-based config. Previously bypassed validate + newListener -- invalid tls_mode
	// (e.g. typo "h3") was silently swallowed by NewProxyListener as plaintext; invalid config
	// was not caught until Start.
	if err := (&Config{Listeners: []ListenerConfig{cfg}}).validate(); err != nil {
		writeAPIError(w, http.StatusBadRequest, "validate: "+err.Error())
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.listeners[cfg.Name]; exists {
		writeAPIError(w, http.StatusConflict, g.bundle.T(g.lang, "api.listener_exists"))
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
		g.crlCaches[cfg.TLS.CRLURL] = crlCache
	}

	ocspCache := buildOCSPCache(cfg.TLS, g.bundle, g.lang)

	p, err := g.newListener(cfg, crlCache, ocspCache, g.nonceCache)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	p.SetLogger(g.logger)
	p.SetPluginRegistry(g.pluginRegistry)
	p.SetTaskRegistry(g.taskRegistry)
	p.SetConnRegistry(g.connRegistry)
	p.SetRevoker(g.revoker)
	p.SetRiskMonitor(g.riskMonitor)
	p.SetPolicyVersionFn(func() uint64 {
		if g.policyMgr == nil {
			return 0
		}
		return g.policyMgr.CurrentVersion()
	})
	p.SetPolicyResolverFn(g.policyResolver())
	if err := p.Start(); err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	g.listeners[cfg.Name] = p
	g.cfg.Listeners = append(g.cfg.Listeners, cfg)

	if err := g.cfg.Save(); err != nil {
		g.logger.Warn(g.bundle.T(g.lang, "api.config_persist"), "error", err)
	}

	writeJSON(w, http.StatusCreated, map[string]string{"status": "ok", "name": cfg.Name})
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

func buildOCSPCache(t *gw.TLSConfig, bundle *Bundle, lang string) *gw.OCSPCache {
	if t == nil {
		return nil
	}
	// W28 (2026-08-16): OCSP is only enabled when `ocsp_fallback` or `ocsp_cache_ttl_sec`
	// is explicitly configured (otherwise stays in pure CRL mode, backward-compatible).
	// The old implementation required TTL>0, causing OCSP to be silently disabled when
	// `ocsp_fallback` was configured but TTL was not.
	if t.OCSPFallback == "" && t.OCSPCacheTTLSec == 0 {
		return nil
	}
	ttl := time.Duration(t.OCSPCacheTTLSec) * time.Second
	if ttl <= 0 {
		ttl = 300 * time.Second
	}
	fallback := t.OCSPFallback
	if fallback == "" {
		fallback = gw.OCSPFallbackDeny
	}
	return gw.NewOCSPCache(ttl, fallback, bundle, lang)
}
