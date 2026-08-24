// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package httpgw

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	pathpkg "path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gw "github.com/varwof/gateway-core"
	"golang.org/x/net/http2"
)

// certSpkiHashHex returns the SHA-256 of the cert's SubjectPublicKeyInfo in hex.
func certSpkiHashHex(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// ProxyState represents the running state of the HTTP proxy.
type ProxyState string

const (
	// ProxyStopped is when the proxy has stopped.
	ProxyStopped ProxyState = "stopped"
	// ProxyRunning is when the proxy is running.
	ProxyRunning ProxyState = "running"
)

// Route is the HTTP routing rule, containing path matching and backend forwarding configuration.
type Route struct {
	Path                 string
	Target               *url.URL
	AllowMethods         []string
	AllowRoles           []string
	BackendProtocol      string
	RequiredCapabilities []string
	CapabilityScheme     string
	CapabilityPrefix     string
	handler              http.Handler
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// ProxyListener is the HTTP listener instance, handling routing and proxy forwarding.
type ProxyListener struct {
	cfg       ListenerConfig
	server    *http.Server
	listener  net.Listener
	tlsCfg    *tls.Config
	transport *http.Transport
	crlCache  atomic.Pointer[gw.CRLCache]
	ocspCache *gw.OCSPCache
	audit     *gw.AuditLogger
	tsa       *gw.TSAClient
	bundle    *Bundle
	lang      string
	logger    *slog.Logger
	state     atomic.Value
	mu        sync.Mutex
	stopCh    chan struct{}
	conns     int64
	ipConns   map[string]int64
	ipMu      sync.Mutex
	// connIPs tracks per-IP connection counts by underlying TCP connection (W21: ConnContext
	// updates on connection establish/close). Distinct from request-level ipConns -- under
	// HTTP/1.1 keep-alive and HTTP/2 multiplexing a single connection carries multiple requests,
	// so per-IP limits must count by connection, otherwise a single client with 100 concurrent
	// streams would exhaust max_conns_per_ip.
	connIPs        map[string]int64
	routes         []Route
	certTracker    *gw.ConnectionTracker
	revoker        *gw.Revoker
	serverCert     atomic.Value // *tls.Certificate for dynamic rotation
	pluginRegistry *gw.PluginRegistry
	nonceCache     *gw.NonceCache
	taskRegistry   *gw.TaskRegistry
	// policyVersion returns the current effective policy version number (Task 5a: audit binds version).
	policyVersion func() uint64
	// policyResolver selects the policy version registry by agent identifier (Task 5b: branch control/canary).
	// Injected by the gateway as g.policyMgr.SelectRegistry; falls back to pluginRegistry when nil.
	policyResolver func(agentID string) (uint64, *gw.PluginRegistry)
	// riskMonitor is the high-risk behavior monitor (2026-08-15). Pipeline does not record violation signals when nil.
	riskMonitor *gw.RiskMonitor
	// connRegistry is the connection registry (monitoring presentation + risk disconnect linkage, shared with Gateway).
	connRegistry *gw.ConnRegistry
}

// NewProxyListener creates an HTTP proxy listener instance.
func NewProxyListener(cfg ListenerConfig, crlCache *gw.CRLCache, ocspCache *gw.OCSPCache, audit *gw.AuditLogger, tsa *gw.TSAClient, stopCh chan struct{}, bundle *Bundle, lang string, revoker *gw.Revoker, nonceCache *gw.NonceCache) (*ProxyListener, error) {
	p := &ProxyListener{
		cfg:          cfg,
		crlCache:     atomic.Pointer[gw.CRLCache]{},
		ocspCache:    ocspCache,
		audit:        audit,
		revoker:      revoker,
		tsa:          tsa,
		stopCh:       stopCh,
		bundle:       bundle,
		lang:         lang,
		logger:       slog.Default(),
		ipConns:      make(map[string]int64),
		connIPs:      make(map[string]int64),
		certTracker:  gw.NewConnectionTracker(),
		nonceCache:   nonceCache,
		taskRegistry: gw.NewTaskRegistry(),
		transport: &http.Transport{
			MaxIdleConns:          200,
			MaxIdleConnsPerHost:   50,
			MaxConnsPerHost:       100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			// W17: Backend hangs after accept with no response header limit -> client request hangs forever.
			// Aligned with QUIC path (quic.go:431), set 30s fallback.
			ResponseHeaderTimeout: 30 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2: true,
		},
	}
	if crlCache != nil {
		p.crlCache.Store(crlCache)
	}
	p.state.Store(ProxyStopped)

	for _, rc := range cfg.Routes {
		target, err := url.Parse(rc.Target)
		if err != nil {
			return nil, fmt.Errorf("parse target %q: %w", rc.Target, err)
		}
		rp := httputil.NewSingleHostReverseProxy(target)
		rp.Transport = p.transportForProtocol(rc.BackendProtocol, rc.UpstreamTLS)
		// W37 (2026-08-16): X-Forwarded-For defaults to "append" semantics -- client-controllable,
		// left-most entries can be forged, backends trusting the left-most entry can be deceived.
		// The gateway is the mTLS boundary; override to carry only the peer IP (clearing the client
		// chain), so backends only see the trusted source.
		defaultDirector := rp.Director
		rp.Director = func(req *http.Request) {
			defaultDirector(req)
			host, _, err := net.SplitHostPort(req.RemoteAddr)
			if err != nil {
				host = req.RemoteAddr
			}
			req.Header.Set("X-Forwarded-For", host)
		}
		route := Route{
			Path:                 rc.Path,
			Target:               target,
			AllowMethods:         rc.AllowMethods,
			AllowRoles:           rc.AllowRoles,
			BackendProtocol:      rc.BackendProtocol,
			RequiredCapabilities: rc.RequiredCapabilities,
			CapabilityScheme:     rc.CapabilityScheme,
			CapabilityPrefix:     rc.CapabilityPrefix,
			handler:              rp,
		}
		p.routes = append(p.routes, route)
	}

	return p, nil
}

// Start starts the HTTP proxy listener and registers data plane routes.
func (p *ProxyListener) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.state.Load().(ProxyState) == ProxyRunning {
		s := fmt.Sprintf(p.bundle.T(p.lang, "listener.already_running"), p.cfg.Name)
		return errors.New(s)
	}

	var err error
	p.listener, err = net.Listen("tcp", p.cfg.Listen)
	if err != nil {
		p.state.Store(ProxyStopped)
		return fmt.Errorf("listener %q listen %s: %w", p.cfg.Name, p.cfg.Listen, err)
	}

	mode := p.cfg.effectiveMode()
	if mode == gw.TLSModeMTLS || mode == gw.TLSModeServer {
		t := p.cfg.TLS
		if t == nil || t.CertFile == "" {
			p.listener.Close()
			return fmt.Errorf("listener %q: cert_file required for TLS mode", p.cfg.Name)
		}
		cert, err := gw.LoadCert(t.CertFile, t.KeyFile)
		if err != nil {
			p.listener.Close()
			return err
		}
		p.serverCert.Store(cert)

		if mode == gw.TLSModeMTLS {
			p.tlsCfg, err = gw.MTLSServerConfig(t.CACertFile, cert, t.CipherSuites, t.MinTLSVersion)
			if err != nil {
				p.listener.Close()
				return err
			}
		} else {
			p.tlsCfg = gw.ServerTLSConfig(cert, t.CipherSuites, t.MinTLSVersion)
		}
		// HTTP/2 + HTTP/1.1 ALPN — enable gRPC/HTTP2 support
		p.tlsCfg.NextProtos = []string{"h2", "http/1.1"}
		p.tlsCfg.ClientSessionCache = tls.NewLRUClientSessionCache(4096)
		p.tlsCfg.GetCertificate = p.getCert
		if t.CACertFile != "" {
			gw.StartOCSPStapling(cert, p.tlsCfg, t.CACertFile, p.stopCh, p.bundle, p.lang)
		}
		p.listener = tls.NewListener(p.listener, p.tlsCfg)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/_timestamp", p.handleTimestamp)
	mux.HandleFunc("/", p.handleRequest)

	idleTimeout := 120 * time.Second
	readHeaderTimeout := 30 * time.Second
	writeTimeout := 300 * time.Second
	if t := p.cfg.TLS.IdleTimeout(); t > 0 {
		idleTimeout = t
	}
	if p.cfg.HTTPExt != nil {
		if p.cfg.HTTPExt.ReadHeaderTimeoutSec > 0 {
			readHeaderTimeout = time.Duration(p.cfg.HTTPExt.ReadHeaderTimeoutSec) * time.Second
		}
		if p.cfg.HTTPExt.WriteTimeoutSec > 0 {
			writeTimeout = time.Duration(p.cfg.HTTPExt.WriteTimeoutSec) * time.Second
		}
	}

	p.server = &http.Server{
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          slog.NewLogLogger(p.logger.Handler(), slog.LevelError),
		ConnContext:       p.trackConn,
		ConnState:         p.trackConnState,
	}

	go func() {
		if err := p.server.Serve(p.listener); err != nil && err != http.ErrServerClosed {
			p.logger.Warn(p.bundle.T(p.lang, "listener.serve_error"), "name", p.cfg.Name, "error", err)
		}
	}()

	p.state.Store(ProxyRunning)
	// W25 (2026-08-16): Set ListenerUp for HTTP listener (previously only set in QUIC path).
	ListenerUp.Set(1, p.cfg.Name)
	p.logger.Info(p.bundle.T(p.lang, "listener.listening"),
		"name", p.cfg.Name, "listen", p.cfg.Listen, "protocol", p.cfg.Protocol, "routes", len(p.routes))
	return nil
}

// trackConn registers per-IP connection counts on each underlying TCP connection establishment (W21).
// Returns a context with a cleanup callback: decrements connIPs on ctx done (connection close).
// Cannot rely on ctx auto-cancellation -- instead uses ConnState (StateNew/StateClosed/Hijacked)
// to precisely hook the connection lifecycle; this function only attaches net.Conn to context for request reading.
func (p *ProxyListener) trackConn(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connKey{}, c)
}

// trackConnState hooks the http.Server connection state machine: per-IP +1 on New,
// -1 on Closed/Hijacked (W21: count by connection, not by request).
func (p *ProxyListener) trackConnState(c net.Conn, st http.ConnState) {
	host := c.RemoteAddr().String()
	if h, _, err := net.SplitHostPort(c.RemoteAddr().String()); err == nil {
		host = h
	}
	switch st {
	case http.StateNew:
		// W25 (2026-08-16): Wire up ConnectionsAccepted (previously registered but never incremented).
		ConnectionsAccepted.Inc(p.cfg.Name)
		p.ipMu.Lock()
		p.connIPs[host]++
		p.ipMu.Unlock()
	case http.StateClosed, http.StateHijacked:
		p.ipMu.Lock()
		p.connIPs[host]--
		if p.connIPs[host] <= 0 {
			delete(p.connIPs, host)
		}
		p.ipMu.Unlock()
	}
}

// connKey is the context key type for storing the underlying net.Conn.
type connKey struct{}

// Stop gracefully shuts down the HTTP proxy listener.
func (p *ProxyListener) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.state.Load().(ProxyState) == ProxyStopped {
		return nil
	}

	if p.server != nil {
		// W29 (2026-08-16): Graceful shutdown instead of hard Close -- in-flight requests have a 10s
		// drain window, preventing requests in progress from being aborted during SIGTERM/SIGHUP listener replacement.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = p.server.Shutdown(ctx)
		cancel()
	}
	p.state.Store(ProxyStopped)
	// W25 (2026-08-16): Set to 0 when HTTP listener stops.
	ListenerUp.Set(0, p.cfg.Name)
	p.logger.Info(p.bundle.T(p.lang, "listener.stopped"), "name", p.cfg.Name)
	return nil
}

// State returns the current state of the proxy listener.
func (p *ProxyListener) State() ProxyState {
	return p.state.Load().(ProxyState)
}

// Name returns the proxy listener name.
func (p *ProxyListener) Name() string {
	return p.cfg.Name
}

// Conns returns the current active connection count.
func (p *ProxyListener) Conns() int64 {
	return atomic.LoadInt64(&p.conns)
}

// Config returns the proxy listener configuration.
func (p *ProxyListener) Config() ListenerConfig { return p.cfg }

// Addr returns the proxy listener listen address.
func (p *ProxyListener) Addr() net.Addr {
	if p.listener != nil {
		return p.listener.Addr()
	}
	return nil
}

// handleTimestamp handles the GET /_timestamp endpoint.
// Returns the server time for client time synchronization.
func (p *ProxyListener) handleTimestamp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeProxyError(w, http.StatusMethodNotAllowed, "http.method_not_allowed", "GET required")
		return
	}

	resp := map[string]interface{}{
		"timestamp": time.Now().Unix(),
		"iso8601":   time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (p *ProxyListener) handleRequest(w http.ResponseWriter, r *http.Request) {
	// W19: Trusted identity header namespace is only allowed to be injected by the gateway;
	// any client-submitted values are stripped. X-Client-Cert-* / X-Agent-* are treated by
	// backends as trusted identity assertions; if the gateway does not overwrite them (non
	// Delegated-Agent or plain listener), forged headers passed through constitute identity spoofing.
	// Unconditionally deleted from any client (mTLS / plain) here; real values are only re-injected
	// on the server assertion path (HasDelegatedAgentOU + ForwardClientCertDEREnabled).
	// Note: X-AIC-Task-* are gateway-consumed control headers (task registration/completion signals)
	// and must not be stripped here -- kept until after pipeline reads them, deleted before forwarding
	// (see task tracking section).
	for _, h := range []string{
		"X-Client-Cert-DER", "X-Client-Cert-SPKI-Hash", "X-Client-Cert-Serial",
		"X-Client-Cert-CN", "X-Client-Cert-Principal", "X-Client-Cert-Agent-ID",
		"X-Agent-TTL",
	} {
		r.Header.Del(h)
	}

	// L2: RemoteAddr may be a Unix socket path (no host:port), where
	// SplitHostPort fails. Fall back to the full RemoteAddr so the per-IP map
	// key stays stable (a failed split would otherwise yield "" and corrupt the
	// increment/decrement accounting).
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	atomic.AddInt64(&p.conns, 1)
	defer atomic.AddInt64(&p.conns, -1)

	p.ipMu.Lock()
	p.ipConns[host]++
	maxIP := 0
	if t := p.cfg.TLS; t != nil {
		maxIP = t.MaxConnsPerIP
	}
	// W21: max_conns_per_ip is checked against underlying connections (connIPs) -- under
	// HTTP/1.1 keep-alive and HTTP/2 multiplexing a single connection carries multiple requests;
	// counting by request would allow a single client's concurrent streams to exhaust the limit.
	// Request-level ipConns is only used for concurrent request statistics display.
	connCount := p.connIPs[host]
	p.ipMu.Unlock()

	defer func() {
		p.ipMu.Lock()
		p.ipConns[host]--
		if p.ipConns[host] <= 0 {
			delete(p.ipConns, host)
		}
		p.ipMu.Unlock()
	}()

	if maxIP > 0 && connCount > int64(maxIP) {
		writeProxyError(w, http.StatusTooManyRequests, "http.too_many_requests",
			p.bundle.T(p.lang, "http.too_many_requests"))
		return
	}

	maxTotal := 0
	if t := p.cfg.TLS; t != nil {
		maxTotal = t.MaxTotalConns
	}
	if maxTotal > 0 && atomic.LoadInt64(&p.conns) > int64(maxTotal) {
		writeProxyError(w, http.StatusServiceUnavailable, "http.server_busy",
			p.bundle.T(p.lang, "http.server_busy"))
		return
	}

	var clientCert *x509.Certificate
	var result *gw.PipelineResult
	var matchedRoute *Route
	if p.cfg.effectiveMode() == gw.TLSModeMTLS {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			writeProxyError(w, http.StatusUnauthorized, "http.mtls_required",
				p.bundle.T(p.lang, "http.mtls_required"))
			return
		}
		clientCert = r.TLS.PeerCertificates[0]

		// Determine RequiredCapabilities from matched route (early match for pipeline)
		var requiredCaps []string
		matchedRoute, _ = p.matchRoute(r.URL.Path)
		if matchedRoute != nil {
			requiredCaps = matchedRoute.RequiredCapabilities
		}

		// Determine CapabilityScheme
		var capScheme string
		if matchedRoute != nil {
			capScheme = matchedRoute.CapabilityScheme
		}

		// Auto-derive RequiredCapabilities from HTTP method if CapabilityScheme is set
		if capScheme != "" && len(requiredCaps) == 0 && matchedRoute != nil {
			prefix := matchedRoute.CapabilityPrefix
			if prefix == "" {
				prefix = "cap"
			}
			requiredCaps = deriveRequiredCaps(prefix, r.Method)
		}

		// Unified admission pipeline: CRL -> OCSP -> RBAC -> AIC/GS -> Plugins
		chain := r.TLS.PeerCertificates
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		result = gw.RunAccessPipeline(chain, &gw.PipelineConfig{
			CRLCache:                 p.crlCache.Load(),
			OCSPCache:                p.ocspCache,
			CheckScope:               gw.CheckFullChain,
			RequireAIC:               p.cfg.TLS.RequireAICEnabled(),
			RequireSPIFFE:            p.cfg.TLS.RequireSPIFFEEnabled(),
			AllowedSPIFFEIDs:         p.cfg.TLS.AllowedSPIFFEIDs,
			SPIFFETrustDomain:        p.cfg.TLS.SPIFFETrustDomain,
			RequiredCapabilities:     requiredCaps,
			DisallowRepresentative:   p.cfg.TLS.DisallowRepresentativeEnabled(),
			RequireUserAuth:          p.cfg.TLS.RequireUserAuthEnabled(),
			ClientIP:                 clientIP,
			HTTPFacts:                httpFactsFor(r),
			EnforceConstraints:       true,
			StrictConstraints:        true,
			CapabilityPluginRegistry: p.pluginRegistry,
			CapabilityPluginResolver: p.policyResolver,
			PolicyVersion:            p.currentPolicyVersion(),
			AuditLogger:              p.audit,
			NonceCache:               p.nonceCache,
			RiskMonitor:              p.riskMonitor,
			// G2(b): When OCSP fallback is allow (fail-open), enforce offline certificate lifetime <=1h.
			OfflineMaxCertLifetime: gw.OfflineLifetimeFor(p.cfg.TLS.OCSPFallback),
		})
		if !result.Granted {
			p.audit.Log(gw.NewAuditEntryDenied(r.RemoteAddr, p.cfg.Name, r.URL.Path,
				result.DenyReason, clientCert))
			writeProxyError(w, http.StatusForbidden, "http.access_denied",
				fmt.Sprintf(p.bundle.T(p.lang, "http.access_denied"), result.DenyReason))
			return
		}

		// G4: Delegated-Agent identity must use server-asserted values, never trust client-filled
		// headers (otherwise any backend identity can be spoofed). Identity is derived from the
		// core-signed AIC/GatewaySession. B2 (forward_client_cert_der): passes the verified client
		// certificate itself via X-Client-Cert-DER; the backend looks up the DB by certificate to
		// restore principal/revocation/audit. The deprecated X-Agent-User username path (B1) is no
		// longer injected. X-Agent-TTL is only injected with session expiry when certificate
		// passthrough is enabled.
		if gw.HasDelegatedAgentOU(clientCert) {
			_, expiry, reason := gw.DelegatedAgentServerIdentity(clientCert, result.Principal, result.GatewaySession)
			if reason != "" {
				p.audit.Log(gw.NewAuditEntryDenied(r.RemoteAddr, p.cfg.Name, r.URL.Path,
					reason, clientCert))
				writeProxyError(w, http.StatusForbidden, "http.access_denied",
					fmt.Sprintf(p.bundle.T(p.lang, "http.access_denied"), reason))
				return
			}
			if p.cfg.HTTPExt.ForwardClientCertDEREnabled() {
				r.Header.Set("X-Client-Cert-DER", base64.StdEncoding.EncodeToString(clientCert.Raw))
				// Structured convenience views of the same certificate; the
				// DER header remains the authoritative source.
				r.Header.Set("X-Client-Cert-SPKI-Hash", certSpkiHashHex(clientCert))
				r.Header.Set("X-Client-Cert-Serial", clientCert.SerialNumber.Text(16))
				r.Header.Set("X-Client-Cert-CN", clientCert.Subject.CommonName)
				if aic, err := gw.ParseAIC(clientCert); err == nil && aic != nil {
					r.Header.Set("X-Client-Cert-Principal", aic.PrincipalUid.String())
					if aic.AgentId != "" {
						r.Header.Set("X-Client-Cert-Agent-ID", aic.AgentId)
					}
				}
				if !expiry.IsZero() {
					r.Header.Set("X-Agent-TTL", expiry.UTC().Format(time.RFC3339))
				}
			}
		}
	}

	if clientCert != nil && p.cfg.TLS != nil && p.cfg.TLS.MaxConnsPerCert > 0 {
		if !p.certTracker.Add(result.Serial, int64(p.cfg.TLS.MaxConnsPerCert)) {
			p.audit.Log(gw.AuditEntry{
				Action:       "cert_conn_limit",
				SrcIP:        r.RemoteAddr,
				ClientCN:     clientCert.Subject.CommonName,
				ClientSerial: result.Serial,
				Mapping:      p.cfg.Name,
				Target:       r.URL.Path,
			})
			writeProxyError(w, http.StatusTooManyRequests, "http.cert_conn_limit",
				p.bundle.T(p.lang, "http.cert_conn_limit"))
			return
		}
		defer p.certTracker.Remove(result.Serial)
	}
	if clientCert != nil {
		// P2-A-15: Register connection lifecycle in ConnExpiryRegistry;
		// on close, the Revoker decides whether to skip revocation based on the renewal flag.
		if p.revoker != nil {
			if reg := p.revoker.Registry(); reg != nil {
				defer reg.Register(gw.NormalizeSerial(clientCert.SerialNumber), clientCert)()
			}
			defer p.revoker.RevokeClientCert(clientCert, p.audit)
		}
		// Monitoring presentation + risk disconnect linkage: request-level connection registration
		// (including srcIP/protocol/serial), enabling /connections, /access-points, /agents, and
		// risk revoke to locate and take effect.
		if p.connRegistry != nil && result != nil {
			unreg := p.connRegistry.RegisterConn(result.AgentId, result.Principal,
				host, "http", gw.NormalizeSerial(clientCert.SerialNumber),
				func() { closeResponseWriterConn(w) })
			defer unreg()
		}
		// A3/A4: Task lifecycle tracking. When the request carries X-AIC-Task-Id, register task ->
		// certificate serial number mapping; when X-AIC-Task-Status: completed, immediately trigger
		// conditional revocation ("revoke when done", without waiting for connection close), and
		// unregister the task record.
		if p.taskRegistry != nil {
			if taskID := gw.TaskIDFromHeader(r.Header.Get); taskID != "" {
				p.taskRegistry.Register(taskID, gw.NormalizeSerial(clientCert.SerialNumber),
					clientCert.Subject.CommonName, r.URL.Path, time.Now().Unix())
			}
			if taskID, done := gw.TaskCompletedFromHeader(r.Header.Get, clientCert.Subject.CommonName); done {
				p.logger.Info("task complete signal: revoking client cert",
					"task_id", taskID,
					"serial", gw.NormalizeSerial(clientCert.SerialNumber),
					"cn", clientCert.Subject.CommonName)
				if p.audit != nil {
					p.audit.Log(gw.AuditEntry{
						Action:       "task_complete_revoke",
						Target:       "task",
						TargetID:     taskID,
						ClientCN:     clientCert.Subject.CommonName,
						ClientSerial: gw.NormalizeSerial(clientCert.SerialNumber),
					})
				}
				// Immediate revocation (bypassing the connection close path). G2(c): Task completion
				// is proactive security revocation ("revoke when done"), must not be allowed through
				// by the renewal flag.
				p.revoker.RevokeClientCertForced(clientCert, p.audit)
				p.taskRegistry.Unregister(taskID)
			}
		}
		// P4.2: GatewaySession enforcement (AllowedCIDRs + HardTimeout)
		if gs := result.GatewaySession; gs != nil {
			remoteHost, _, _ := net.SplitHostPort(r.RemoteAddr)
			if len(gs.AllowedCIDRs) > 0 && !gs.CIDRAllowed(remoteHost) {
				p.audit.Log(gw.NewAuditEntryDenied(r.RemoteAddr, p.cfg.Name, r.URL.Path,
					"session CIDR not allowed", clientCert))
				writeProxyError(w, http.StatusForbidden, "http.access_denied",
					p.bundle.T(p.lang, "http.access_denied"))
				return
			}
			if gs.HardTimeoutLimit() > 0 {
				reqCtx, cancel := context.WithCancel(r.Context())
				r = r.WithContext(reqCtx)
				go func() {
					timer := time.NewTimer(time.Duration(gs.HardTimeoutLimit()) * time.Second)
					defer timer.Stop()
					select {
					case <-timer.C:
						cancel()
					case <-reqCtx.Done():
					}
				}()
			}
		}
	}

	path := r.URL.Path
	if matchedRoute == nil {
		matchedRoute, _ = p.matchRoute(path)
	}
	if matchedRoute == nil {
		p.audit.Log(gw.AuditEntry{
			Action:  "no_route",
			SrcIP:   r.RemoteAddr,
			Mapping: p.cfg.Name,
			Target:  path,
		})
		writeProxyError(w, http.StatusNotFound, "http.no_route",
			p.bundle.T(p.lang, "http.no_route"))
		return
	}

	if len(matchedRoute.AllowMethods) > 0 {
		allowed := false
		for _, m := range matchedRoute.AllowMethods {
			if r.Method == m {
				allowed = true
				break
			}
		}
		if !allowed {
			writeProxyError(w, http.StatusMethodNotAllowed, "http.method_not_allowed",
				p.bundle.T(p.lang, "http.method_not_allowed"))
			return
		}
	}

	if len(matchedRoute.AllowRoles) > 0 {
		// Fail-closed: a route that requires roles but has no authenticated
		// client certificate (e.g. a non-mTLS listener) must be denied, never
		// silently allowed.
		if clientCert == nil {
			p.audit.Log(gw.AuditEntry{
				Action:  "denied",
				SrcIP:   r.RemoteAddr,
				Mapping: p.cfg.Name,
				Target:  path,
				Roles:   matchedRoute.AllowRoles,
			})
			writeProxyError(w, http.StatusForbidden, "http.forbidden",
				p.bundle.T(p.lang, "http.forbidden"))
			return
		}
		roles := gw.ExtractRoles(clientCert)
		if !gw.CheckRole(roles, matchedRoute.AllowRoles) {
			p.audit.Log(gw.AuditEntry{
				Action:   "denied",
				SrcIP:    r.RemoteAddr,
				ClientCN: clientCert.Subject.CommonName,
				Mapping:  p.cfg.Name,
				Target:   path,
				Roles:    roles,
			})
			writeProxyError(w, http.StatusForbidden, "http.forbidden",
				p.bundle.T(p.lang, "http.forbidden"))
			return
		}
	}

	// P0-2: cert expiry check — enforce on every request to catch expiry during keep-alive.
	// G2(a): Short-lived certificates (including AIC) are forcibly checked; cannot be
	// disabled by disconnect_on_expiry=false.
	if clientCert != nil && time.Now().After(clientCert.NotAfter) &&
		(p.cfg.TLS.DisconnectOnExpiryEnabled() || gw.HasAIC(clientCert)) {
		w.Header().Set("Connection", "close")
		writeProxyError(w, http.StatusUnauthorized, "http.cert_expired",
			fmt.Sprintf(p.bundle.T(p.lang, "http.cert_expired"), clientCert.NotAfter.Format(time.RFC3339)))
		return
	}

	// P0-1: forward client cert info to backend via headers
	if clientCert != nil && p.cfg.HTTPExt.ForwardClientCertEnabled() {
		r.Header.Set("X-Forwarded-Client-CN", clientCert.Subject.CommonName)
		if len(clientCert.Subject.Organization) > 0 {
			r.Header.Set("X-Forwarded-Client-O", strings.Join(clientCert.Subject.Organization, ","))
		}
		if len(clientCert.Subject.OrganizationalUnit) > 0 {
			r.Header.Set("X-Forwarded-Client-OU", strings.Join(clientCert.Subject.OrganizationalUnit, ","))
		}
		r.Header.Set("X-Forwarded-Client-Serial", clientCert.SerialNumber.Text(16))
		r.Header.Set("X-Forwarded-Client-NotAfter", clientCert.NotAfter.Format(time.RFC3339))
	}

	// AIC mTLS mode A: inject X-AIC-* headers when AIC extension is present
	if clientCert != nil && p.cfg.HTTPExt.TLSTerminationEnabled() {
		aic, err := gw.ParseAIC(clientCert)
		if err == nil && aic != nil {
			r.Header.Set("X-AIC-Agent-Id", aic.AgentId)
			r.Header.Set("X-AIC-Principal-Uid", aic.PrincipalUid.String())
			if len(aic.Capabilities) > 0 {
				var caps []string
				for _, c := range aic.Capabilities {
					caps = append(caps, c.CapabilityId)
				}
				r.Header.Set("X-AIC-Capabilities", strings.Join(caps, ","))
			}
			if aic.DelegationAuthorization.Timestamp.Unix() > 0 {
				r.Header.Set("X-AIC-Verified-By", aic.DelegationAuthorization.SignatureAlgorithm.Algorithm.String())
			}
		}
		if result != nil && result.GatewaySession != nil {
			r.Header.Set("X-GS-Max-Concurrent", fmt.Sprintf("%d", result.GatewaySession.MaxConcurrent))
			r.Header.Set("X-GS-Hard-Timeout", fmt.Sprintf("%d", result.GatewaySession.HardTimeout))
		}
	}

	// WebSocket: detect Upgrade header after route match, delegate to ws_connect/ws_close audit handler
	if isWebSocketRequest(r) {
		p.serveWebSocket(w, r, matchedRoute, clientCert, path)
		return
	}

	isGRPC := isGRPCRequest(r)

	start := time.Now()
	// W19: Task control headers are gateway-consumed signals; after reading, they must be
	// deleted before forwarding -- otherwise backends see the forgeable X-AIC-Task-* (identity spoofing).
	r.Header.Del("X-AIC-Task-Id")
	r.Header.Del("X-AIC-Task-Status")
	srw := &statusResponseWriter{ResponseWriter: w, status: http.StatusOK}
	matchedRoute.handler.ServeHTTP(srw, r)

	entry := gw.AuditEntry{
		Action:   "completed",
		SrcIP:    r.RemoteAddr,
		Mapping:  p.cfg.Name,
		Target:   path,
		TargetID: matchedRoute.Target.String(),
		Duration: time.Since(start).Round(time.Millisecond).String(),
	}
	if isGRPC {
		entry.TargetID += " (grpc)"
	}
	if clientCert != nil {
		entry.ClientCN = clientCert.Subject.CommonName
		entry.Roles = gw.ExtractRoles(clientCert)
		entry.SetV12Fields("http", p.cfg.Name, "", "", "allow")
	}
	p.audit.Log(entry)

	// Prometheus metrics. L3: use the matched route pattern (bounded label
	// cardinality) rather than the raw request path, which is unbounded and can
	// exhaust the metric series.
	metricPath := path
	if matchedRoute != nil {
		metricPath = matchedRoute.Path
	}
	statusClass := fmt.Sprintf("%dxx", srw.status/100)
	if isGRPC {
		// W27: gRPC is counted here uniformly (removed previous duplicate counting by raw path);
		// status label uses "grpc" to distinguish from HTTP status class, route uses normalized pattern.
		statusClass = "grpc"
	}
	HTTPRequestsTotal.Inc(p.cfg.Name, metricPath, r.Method, statusClass)
	HTTPRequestDuration.Observe(time.Since(start).Seconds(), p.cfg.Name, metricPath)
}

// upstreamTLSConfig builds the backend reverse-connect TLS configuration (W18: upstream_mtls).
// Returns nil to validate against system roots (original behavior). Returns error on
// CACertFile/CertFile read failure.
func upstreamTLSConfig(u *UpstreamTLSConfig, defaultServerName string) (*tls.Config, error) {
	if u == nil {
		return nil, nil
	}
	tc := &tls.Config{
		ServerName:         u.ServerName,
		InsecureSkipVerify: u.InsecureSkipVerify,
	}
	if tc.ServerName == "" {
		tc.ServerName = defaultServerName
	}
	if u.CACertFile != "" {
		pem, err := os.ReadFile(u.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("upstream_tls: read ca_cert_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("upstream_tls: no certificates in %s", u.CACertFile)
		}
		tc.RootCAs = pool
	}
	if u.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(u.CertFile, u.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("upstream_tls: load client cert: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	return tc, nil
}

func (p *ProxyListener) transportForProtocol(proto string, upstream *UpstreamTLSConfig) http.RoundTripper {
	switch proto {
	case BackendProtoH2C:
		return &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
				return net.DialTimeout(network, addr, 10*time.Second)
			},
			MaxHeaderListSize: 0xffff,
		}
	case BackendProtoH1:
		tr := p.transport.Clone()
		tr.ForceAttemptHTTP2 = false
		if tc, err := upstreamTLSConfig(upstream, p.cfg.Name); err != nil {
			// W18: Config errors should not be silent -- log and fall back to system root (equivalent to no custom mTLS).
			p.logger.Error("transportForProtocol: upstream tls config", "route", proto, "error", err)
		} else if tc != nil {
			tr.TLSClientConfig = tc
		}
		return tr
	default:
		if tc, err := upstreamTLSConfig(upstream, p.cfg.Name); err != nil {
			p.logger.Error("transportForProtocol: upstream tls config", "route", proto, "error", err)
		} else if tc != nil {
			tr := p.transport.Clone()
			tr.TLSClientConfig = tc
			return tr
		}
		return p.transport
	}
}

// deriveRequiredCaps derives RequiredCapabilities from the capability prefix and HTTP method.
// MySQL-like capability prefixes (legacy short "mysql" or register scheme_id whose product
// contains "mysql", e.g. "varwof/demo-mysql-v1") map HTTP methods to SQL operations:
// GET->SELECT, POST->INSERT, PUT->UPDATE, DELETE->DELETE; other prefixes use
// the HTTP method name directly.
func deriveRequiredCaps(prefix, method string) []string {
	sqlOp := method
	isMySQL := prefix == "mysql"
	if !isMySQL {
		// scheme_id format: vendor/product-vN, extract product part
		if idx := strings.Index(prefix, "/"); idx > 0 {
			product := prefix[idx+1:]
			// Strip -vN suffix before checking
			if dashIdx := strings.LastIndex(product, "-v"); dashIdx > 0 {
				product = product[:dashIdx]
			}
			isMySQL = product == "mysql" || strings.Contains(product, "mysql")
		}
	}
	if isMySQL {
		switch method {
		case "GET":
			sqlOp = "SELECT"
		case "POST":
			sqlOp = "INSERT"
		case "PUT":
			sqlOp = "UPDATE"
		case "DELETE":
			sqlOp = "DELETE"
		}
	}
	return []string{prefix + ":" + sqlOp + ":*"}
}

func (p *ProxyListener) matchRoute(path string) (*Route, int) {
	var best *Route
	bestLen := -1

	// H4: normalize the request path before matching so that "//", "./",
	// "/x/../" and other variants cannot slip past an exact/prefix route and
	// fall through to a broader allow-all route (RBAC bypass).
	cleaned := pathpkg.Clean(path)
	if cleaned == "/" {
		cleaned = ""
	}
	// normalize case for case-insensitive matching (paths are case-sensitive
	// at the application layer; lowercasing avoids case-spoofing bypasses).
	lower := strings.ToLower(cleaned)

	// normalize path: strip trailing slash for consistent matching (/api/admin == /api/admin/)
	normalized := strings.TrimSuffix(path, "/")

	for i := range p.routes {
		pattern := p.routes[i].Path
		lowerPattern := strings.ToLower(pattern)

		if strings.HasSuffix(lowerPattern, "/*") {
			prefix := strings.TrimSuffix(lowerPattern, "/*")
			// check prefix match with path separator boundary
			if strings.HasPrefix(lower, prefix) && len(prefix) > bestLen {
				// ensure path ends after prefix with / or EOS — prevents /api/internal2 matching /api/internal/**
				if rest := strings.TrimPrefix(lower, prefix); rest == "" || strings.HasPrefix(rest, "/") {
					best = &p.routes[i]
					bestLen = len(prefix)
				}
			}
			// also match normalized path (after trailing-slash cleanup)
			if normalized != path && strings.HasPrefix(strings.ToLower(strings.TrimSuffix(path, "/")), prefix) && len(prefix) > bestLen {
				if rest := strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(path, "/")), prefix); rest == "" || strings.HasPrefix(rest, "/") {
					best = &p.routes[i]
					bestLen = len(prefix)
				}
			}
		} else if lowerPattern == lower || (normalized != path && lowerPattern == strings.ToLower(normalized)) {
			if len(pattern) > bestLen {
				best = &p.routes[i]
				bestLen = len(pattern)
			}
		}
	}
	return best, bestLen
}

type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

// WriteHeader implements http.ResponseWriter.
func (s *statusResponseWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Flush passes through the underlying flush (W20: supports real-time push for SSE/chunked/gRPC streams).
// http.NewResponseController requires the FlushError interface to pass through Flush.
func (s *statusResponseWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the underlying ResponseWriter (W20: ResponseController uses this to access
// Flusher/Hijacker/Pusher interfaces, enabling streaming proxy).
func (s *statusResponseWriter) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

// FlushError passes through the underlying FlushError (Go 1.20+ ResponseController prefers this).
func (s *statusResponseWriter) FlushError() error {
	if f, ok := s.ResponseWriter.(interface{ FlushError() error }); ok {
		return f.FlushError()
	}
	s.ResponseWriter.(http.Flusher).Flush()
	return nil
}

func writeProxyError(w http.ResponseWriter, status int, key, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(errorResponse{Error: key, Message: message})
}

// closeResponseWriterConn force-closes the client connection (used for risk disconnect).
// No-op when Hijack capability is not available.
func closeResponseWriterConn(w http.ResponseWriter) {
	if rc := http.NewResponseController(w); rc != nil {
		if conn, _, err := rc.Hijack(); err == nil && conn != nil {
			conn.Close()
		}
	}
}

// isWebSocketRequest checks whether the request is a WebSocket upgrade.
func isWebSocketRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

// isGRPCRequest checks whether the request is a gRPC call.
func isGRPCRequest(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return strings.HasPrefix(ct, "application/grpc")
}

// serveWebSocket proxies a WebSocket connection.
// Uses Go 1.26 httputil.ReverseProxy native WebSocket support,
// injects ws_connect / ws_close audit events around the proxy.
func (p *ProxyListener) serveWebSocket(w http.ResponseWriter, r *http.Request, route *Route, clientCert *x509.Certificate, path string) {
	entry := gw.AuditEntry{
		Action:   string(gw.ActionWSConnect),
		SrcIP:    r.RemoteAddr,
		Mapping:  p.cfg.Name,
		Target:   path,
		TargetID: route.Target.String(),
	}
	if clientCert != nil {
		entry.ClientCN = clientCert.Subject.CommonName
		entry.Roles = gw.ExtractRoles(clientCert)
	}

	// W30 (2026-08-16): The old implementation logged ws_connect before ServeHTTP -- upgrade failures
	// (backend rejection/network error) were counted as a connection. Changed to use hijack-probing
	// wrapper writer: only when ReverseProxy truly Hijacks (upgrade successful) is ws_connect logged
	// + active count incremented; ws_close is logged after ServeHTTP returns (session ends).
	tw := &wsHijackRecorder{ResponseWriter: w, onHijack: func() {
		p.audit.Log(entry)
		WSConnectionsTotal.Inc(p.cfg.Name)
		WSConnectionsActive.Add(1, p.cfg.Name)
	}}

	start := time.Now()
	route.handler.ServeHTTP(tw, r)

	if tw.connected {
		WSConnectionsActive.Add(-1, p.cfg.Name)
		closeEntry := entry
		closeEntry.Action = string(gw.ActionWSClose)
		closeEntry.Duration = time.Since(start).Round(time.Millisecond).String()
		p.audit.Log(closeEntry)
	}
}

// wsHijackRecorder wraps ResponseWriter to detect whether a real WebSocket
// upgrade (Hijack) occurred. The reverseProxy's WS support calls Hijack on
// successful upgrade; on failure it only writes a normal error response.
// onHijack fires only once on a real hijack.
type wsHijackRecorder struct {
	http.ResponseWriter
	onHijack  func()
	connected bool
}

// Hijack passes through the underlying http.Hijacker's Hijack capability, and fires
// onHijack once on successful hijack (upgrade confirmed). Returns an error when the
// underlying does not support hijack.
func (w *wsHijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	// Pass through Hijacker capability; http.ResponseController requires Unwrap to return the underlying.
	hw, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying writer does not support hijacking")
	}
	conn, rw, err := hw.Hijack()
	if err == nil && !w.connected {
		w.connected = true
		if w.onHijack != nil {
			w.onHijack()
		}
	}
	return conn, rw, err
}

// Unwrap returns the underlying ResponseWriter for http.ResponseController / protocol detection.
func (w *wsHijackRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (p *ProxyListener) getCert(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := p.serverCert.Load(); c != nil {
		return c.(*tls.Certificate), nil
	}
	// M7: returning (nil, nil) makes crypto/tls fall back to tlsCfg.Certificates[0];
	// if that is also empty (e.g. short-lived cert rotation has not completed its
	// first write) the handshake silently fails. Return an explicit error so the
	// failure is observable rather than a confusing handshake abort.
	return nil, fmt.Errorf("listener %q: no server certificate available yet", p.cfg.Name)
}

// UpdateCert updates the proxy TLS certificate without interruption.
func (p *ProxyListener) UpdateCert(cert *tls.Certificate) {
	p.serverCert.Store(cert)
}

// SetLogger sets the structured logger.
func (p *ProxyListener) SetLogger(logger *slog.Logger) {
	if logger != nil {
		p.logger = logger
	}
}

// SetPluginRegistry sets the capability plugin registry.
func (p *ProxyListener) SetPluginRegistry(reg *gw.PluginRegistry) {
	p.pluginRegistry = reg
}

// SetTaskRegistry sets the task lifecycle registry (A3: shared with Gateway management API).
// When not injected, ProxyListener uses its own independent registry.
func (p *ProxyListener) SetTaskRegistry(reg *gw.TaskRegistry) {
	if reg != nil {
		p.taskRegistry = reg
	}
}

// SetConnRegistry injects the connection registry (monitoring presentation + risk disconnect linkage).
func (p *ProxyListener) SetConnRegistry(reg *gw.ConnRegistry) {
	if reg != nil {
		p.connRegistry = reg
	}
}

// SetRevoker injects the revoker (W22: interface unified; HTTP path injected via NewProxyListener construction).
func (p *ProxyListener) SetRevoker(r *gw.Revoker) {
	if r != nil {
		p.revoker = r
	}
}

// SetPolicyVersionFn sets the current policy version getter function (Task 5a).
func (p *ProxyListener) SetPolicyVersionFn(fn func() uint64) {
	p.policyVersion = fn
}

// SetPolicyResolverFn sets the function that selects policy version registry by agent identifier (Task 5b).
// Falls back to pluginRegistry when nil (no branch control).
func (p *ProxyListener) SetPolicyResolverFn(fn func(agentID string) (uint64, *gw.PluginRegistry)) {
	p.policyResolver = fn
}

// SetRiskMonitor injects the high-risk behavior monitor (2026-08-15).
func (p *ProxyListener) SetRiskMonitor(rm *gw.RiskMonitor) {
	p.riskMonitor = rm
}

// SetCRLCache hot-swaps the CRL cache (W16). When reloading and retaining a listener, Gateway
// injects a cache bound to the new stopCh; the old refresh goroutine stops with the old stopCh.
func (p *ProxyListener) SetCRLCache(cache *gw.CRLCache) {
	if cache == nil {
		return
	}
	p.crlCache.Store(cache)
}

// CRLCache returns the current CRL cache (W33: used for reload to rebuild crlCaches snapshot). May be nil.
func (p *ProxyListener) CRLCache() *gw.CRLCache {
	return p.crlCache.Load()
}

// currentPolicyVersion returns the current effective policy version number (Task 5a).
func (p *ProxyListener) currentPolicyVersion() uint64 {
	if p.policyVersion == nil {
		return 0
	}
	return p.policyVersion()
}
