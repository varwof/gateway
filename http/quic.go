// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package httpgw

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	gw "github.com/varwof/gateway-core"
)

// QUICListener is the HTTP/3 QUIC listener instance.
type QUICListener struct {
	cfg       ListenerConfig
	crl       atomic.Pointer[gw.CRLCache]
	ocsp      *gw.OCSPCache
	audit     *gw.AuditLogger
	tsa       *gw.TSAClient
	bundle    *Bundle
	lang      string
	logger    *slog.Logger
	stopCh    chan struct{}
	mux       *http.ServeMux
	localAddr net.Addr

	tlsCfg         *tls.Config
	h3server       *http3.Server
	ln             *quic.Listener
	tr             *quic.Transport
	running        atomic.Bool
	active         atomic.Int64
	ipConns        map[string]int64
	ipMu           sync.Mutex
	certTracker    *gw.ConnectionTracker
	serverCert     atomic.Value
	wg             sync.WaitGroup
	pluginRegistry *gw.PluginRegistry
	nonceCache     *gw.NonceCache
	// W22: Runtime dependency injection aligned with ProxyListener. Previously SetTaskRegistry/
	// SetConnRegistry were no-ops; H3/tunnel data plane had no revocation/monitoring/task linkage.
	revoker      *gw.Revoker
	connRegistry *gw.ConnRegistry
	taskRegistry *gw.TaskRegistry
	// connIPs tracks per-IP connection counts by QUIC connection (updated on ConnContext establish/close).
	connIPs map[string]int64
	conns   int64
	// policyVersion returns the current effective policy version number (Task 5a).
	policyVersion func() uint64
	// policyResolver selects the policy version registry by agent identifier (Task 5b: branch control/canary).
	policyResolver func(agentID string) (uint64, *gw.PluginRegistry)
	// riskMonitor is the high-risk behavior monitor (2026-08-15). Pipeline does not record violation signals when nil.
	riskMonitor *gw.RiskMonitor

	// backendTransport is a shared, pooled HTTP Transport reused across
	// requests (M5) to avoid per-request client/goroutine leaks.
	backendTransport *http.Transport
	backendMu        sync.Mutex
}

func newQUICListener(cfg ListenerConfig, crl *gw.CRLCache, ocsp *gw.OCSPCache, audit *gw.AuditLogger, tsa *gw.TSAClient, stopCh chan struct{}, bundle *Bundle, lang string, nonceCache *gw.NonceCache) *QUICListener {
	q := &QUICListener{
		cfg:         cfg,
		ocsp:        ocsp,
		audit:       audit,
		tsa:         tsa,
		bundle:      bundle,
		lang:        lang,
		stopCh:      stopCh,
		ipConns:     make(map[string]int64),
		connIPs:     make(map[string]int64),
		certTracker: gw.NewConnectionTracker(),
		nonceCache:  nonceCache,
	}
	if crl != nil {
		q.crl.Store(crl)
	}
	return q
}

// Name returns the QUIC listener name.
func (q *QUICListener) Name() string { return q.cfg.Name }

// Config returns the QUIC listener configuration.
func (q *QUICListener) Config() ListenerConfig { return q.cfg }

// State returns the QUIC listener current state.
// State returns the QUIC listener state (W36: previously always returned Running;
// after Stop the management API falsely reported it as running).
func (q *QUICListener) State() ProxyState {
	if q.running.Load() {
		return ProxyRunning
	}
	return ProxyStopped
}

// Conns returns the current active connection count.
func (q *QUICListener) Conns() int64 { return q.active.Load() }

// SetLogger sets the structured logger.
func (q *QUICListener) SetLogger(logger *slog.Logger) { q.logger = logger }

// SetPluginRegistry sets the capability plugin registry.
func (q *QUICListener) SetPluginRegistry(reg *gw.PluginRegistry) { q.pluginRegistry = reg }

// SetTaskRegistry sets the task lifecycle registry (A3, QUIC data plane integration).
func (q *QUICListener) SetTaskRegistry(reg *gw.TaskRegistry) { q.taskRegistry = reg }

// SetConnRegistry sets the connection registry (QUIC data plane integration, monitoring presentation + risk disconnect linkage).
func (q *QUICListener) SetConnRegistry(reg *gw.ConnRegistry) { q.connRegistry = reg }

// SetRevoker sets the revoker (W22, H3 request path completion signal -> conditional revocation).
func (q *QUICListener) SetRevoker(r *gw.Revoker) { q.revoker = r }

// SetPolicyVersionFn sets the current policy version getter function (Task 5a).
func (q *QUICListener) SetPolicyVersionFn(fn func() uint64) { q.policyVersion = fn }

// SetPolicyResolverFn sets the function that selects policy version registry by agent identifier (Task 5b).
func (q *QUICListener) SetPolicyResolverFn(fn func(agentID string) (uint64, *gw.PluginRegistry)) {
	q.policyResolver = fn
}

// SetRiskMonitor injects the high-risk behavior monitor (2026-08-15, QUIC data plane pipeline records signals).
func (q *QUICListener) SetRiskMonitor(rm *gw.RiskMonitor) { q.riskMonitor = rm }

// SetCRLCache hot-swaps the CRL cache (W16, injects new cache when reloading and retaining a listener).
func (q *QUICListener) SetCRLCache(cache *gw.CRLCache) {
	if cache == nil {
		return
	}
	q.crl.Store(cache)
}

// CRLCache returns the current CRL cache (W33: used for reload to rebuild crlCaches snapshot). May be nil.
func (q *QUICListener) CRLCache() *gw.CRLCache {
	return q.crl.Load()
}

// currentPolicyVersion returns the current effective policy version number (Task 5a).
func (q *QUICListener) currentPolicyVersion() uint64 {
	if q.policyVersion == nil {
		return 0
	}
	return q.policyVersion()
}

// Addr returns the QUIC listener listen address.
func (q *QUICListener) Addr() net.Addr { return q.localAddr }

// Start starts the QUIC/H3 listener.
func (q *QUICListener) Start() error {
	if !q.running.CompareAndSwap(false, true) {
		return fmt.Errorf("listener %q: already running", q.cfg.Name)
	}

	cert, err := gw.LoadCert(q.cfg.TLS.CertFile, q.cfg.TLS.KeyFile)
	if err != nil {
		q.running.Store(false)
		return err
	}
	q.serverCert.Store(cert)

	q.tlsCfg = &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: q.getCert,
	}

	var allowRoles []string
	for _, r := range q.cfg.Routes {
		if len(r.AllowRoles) > 0 {
			allowRoles = r.AllowRoles
			break
		}
	}

	if q.cfg.TLS.CACertFile != "" {
		caPool, err := gw.LoadCA(q.cfg.TLS.CACertFile)
		if err != nil {
			q.running.Store(false)
			return fmt.Errorf("listener %q: load CA: %w", q.cfg.Name, err)
		}
		q.tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		q.tlsCfg.ClientCAs = caPool
	}

	addr, err := net.ResolveUDPAddr("udp", q.cfg.Listen)
	if err != nil {
		q.running.Store(false)
		return fmt.Errorf("resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		q.running.Store(false)
		return fmt.Errorf("listen udp: %w", err)
	}
	q.localAddr = conn.LocalAddr()

	idleTimeout := time.Duration(q.cfg.TLS.IdleTimeoutSec) * time.Second
	if idleTimeout <= 0 {
		idleTimeout = 30 * time.Second
	}

	quicCfg := &quic.Config{
		MaxIdleTimeout:                 idleTimeout,
		KeepAlivePeriod:                30 * time.Second,
		InitialStreamReceiveWindow:     10 * 1024 * 1024,
		MaxStreamReceiveWindow:         20 * 1024 * 1024,
		InitialConnectionReceiveWindow: 20 * 1024 * 1024,
		MaxConnectionReceiveWindow:     40 * 1024 * 1024,
	}

	switch q.cfg.Protocol {
	case ProtocolH3:
		q.tlsCfg.NextProtos = []string{"h3", "h3-29"}
		q.mux = http.NewServeMux()
		q.mux.HandleFunc("/", q.handleH3Request)
		q.h3server = &http3.Server{
			Handler:    q.mux,
			TLSConfig:  q.tlsCfg,
			QUICConfig: quicCfg,
			// W22: Count per-IP connections by QUIC connection (not request) (aligned with W21) --
			// H3 multiplexes many requests over one connection; per-IP limits must count by
			// underlying QUIC connection.
			ConnContext: q.connContext,
		}
		_ = allowRoles
		go func() {
			if err := q.h3server.Serve(conn); err != nil {
				if q.running.Load() {
					q.logger.Error("h3 server error", "name", q.cfg.Name, "error", err)
				}
			}
		}()

	case ProtocolQUIC:
		q.tlsCfg.NextProtos = []string{"hq", "hq-29"}
		q.tr = &quic.Transport{Conn: conn}
		q.ln, err = q.tr.Listen(q.tlsCfg, quicCfg)
		if err != nil {
			conn.Close()
			q.running.Store(false)
			return fmt.Errorf("quic listen: %w", err)
		}
		go q.serve()
	}

	ListenerUp.Set(1, q.cfg.Name)
	q.logger.Info("listener.listening",
		"name", q.cfg.Name, "listen", q.cfg.Listen, "protocol", q.cfg.Protocol)
	return nil
}

// Stop gracefully shuts down the QUIC listener.
func (q *QUICListener) Stop() error {
	if !q.running.CompareAndSwap(true, false) {
		return nil
	}
	if q.h3server != nil {
		q.h3server.Close()
	}
	if q.ln != nil {
		q.ln.Close()
	}
	if q.tr != nil {
		q.tr.Close()
	}
	ListenerUp.Set(0, q.cfg.Name)
	q.wg.Wait()
	return nil
}

// UpdateCert updates the QUIC TLS certificate without interruption.
func (q *QUICListener) UpdateCert(cert *tls.Certificate) {
	q.serverCert.Store(cert)
}

func (q *QUICListener) getCert(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if cert, ok := q.serverCert.Load().(*tls.Certificate); ok {
		return cert, nil
	}
	return nil, fmt.Errorf("no server certificate")
}

// --- H3 mode: HTTP/3 request handling ---

// connContext tracks per-QUIC-connection source IP for W21-aligned per-IP
// connection limits. H3 multiplexes many requests over one QUIC connection, so
// the limit must count connections (not requests). The context lives as long as
// the QUIC connection; on cancellation we decrement.
func (q *QUICListener) connContext(ctx context.Context, c quic.Connection) context.Context {
	host := c.RemoteAddr().String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	q.ipMu.Lock()
	q.connIPs[host]++
	q.ipMu.Unlock()
	go func() {
		<-ctx.Done()
		q.ipMu.Lock()
		q.connIPs[host]--
		if q.connIPs[host] <= 0 {
			delete(q.connIPs, host)
		}
		q.ipMu.Unlock()
	}()
	return ctx
}

func (q *QUICListener) handleH3Request(w http.ResponseWriter, r *http.Request) {
	q.active.Add(1)
	defer q.active.Add(-1)

	q.proxyH3Request(w, r)
}

func (q *QUICListener) proxyH3Request(w http.ResponseWriter, r *http.Request) {
	// W22/W19: Trusted identity header namespace is only allowed to be injected by the gateway;
	// any client-submitted values are stripped. Consistent with HTTP proxy handleRequest to
	// prevent forged identity headers from being passed through for spoofing.
	for _, h := range []string{
		"X-Client-Cert-DER", "X-Client-Cert-SPKI-Hash", "X-Client-Cert-Serial",
		"X-Client-Cert-CN", "X-Client-Cert-Principal", "X-Client-Cert-Agent-ID",
		"X-Agent-TTL",
	} {
		r.Header.Del(h)
	}

	clientIP := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		clientIP = h
	}
	atomic.AddInt64(&q.conns, 1)
	defer atomic.AddInt64(&q.conns, -1)

	// W21: per-IP connection limit (counted by QUIC connection). connContext maintains connIPs.
	q.ipMu.Lock()
	maxIP := 0
	if q.cfg.TLS != nil {
		maxIP = q.cfg.TLS.MaxConnsPerIP
	}
	connCount := q.connIPs[clientIP]
	q.ipMu.Unlock()
	if maxIP > 0 && connCount > int64(maxIP) {
		writeProxyError(w, http.StatusTooManyRequests, "http.too_many_requests",
			q.bundle.T(q.lang, "http.too_many_requests"))
		return
	}

	maxTotal := 0
	if q.cfg.TLS != nil {
		maxTotal = q.cfg.TLS.MaxTotalConns
	}
	if maxTotal > 0 && atomic.LoadInt64(&q.conns) > int64(maxTotal) {
		writeProxyError(w, http.StatusServiceUnavailable, "http.server_busy",
			q.bundle.T(q.lang, "http.server_busy"))
		return
	}

	var clientCert *x509.Certificate
	var result *gw.PipelineResult
	var matchedRoute *RouteConfig

	if q.tlsCfg.ClientAuth == tls.RequireAndVerifyClientCert && r.TLS != nil {
		peerCerts := r.TLS.PeerCertificates
		if len(peerCerts) > 0 {
			clientCert = peerCerts[0]
		}

		var allowRoles []string
		var requiredCaps []string
		path := r.URL.Path
		for i := range q.cfg.Routes {
			if matchPath(q.cfg.Routes[i].Path, path) {
				allowRoles = q.cfg.Routes[i].AllowRoles
				requiredCaps = q.cfg.Routes[i].RequiredCapabilities
				matchedRoute = &q.cfg.Routes[i]
				break
			}
		}

		result = gw.RunAccessPipeline(peerCerts, &gw.PipelineConfig{
			CRLCache:                 q.crl.Load(),
			OCSPCache:                q.ocsp,
			AllowRoles:               allowRoles,
			CheckScope:               gw.CheckFullChain,
			RequireAIC:               q.cfg.TLS.RequireAICEnabled(),
			RequireSPIFFE:            q.cfg.TLS.RequireSPIFFEEnabled(),
			AllowedSPIFFEIDs:         q.cfg.TLS.AllowedSPIFFEIDs,
			SPIFFETrustDomain:        q.cfg.TLS.SPIFFETrustDomain,
			DisallowRepresentative:   q.cfg.TLS.DisallowRepresentativeEnabled(),
			RequireUserAuth:          q.cfg.TLS.RequireUserAuthEnabled(),
			RequiredCapabilities:     requiredCaps,
			ClientIP:                 clientIP,
			EnforceConstraints:       true,
			StrictConstraints:        true,
			CapabilityPluginRegistry: q.pluginRegistry,
			CapabilityPluginResolver: q.policyResolver,
			PolicyVersion:            q.currentPolicyVersion(),

			AuditLogger: q.audit,
			NonceCache:  q.nonceCache,
			RiskMonitor: q.riskMonitor,
			// G2(b): When OCSP fallback is allow (fail-open), enforce offline certificate lifetime <=1h.
			OfflineMaxCertLifetime: gw.OfflineLifetimeFor(q.cfg.TLS.OCSPFallback),
		})
		if !result.Granted {
			q.audit.Log(gw.NewAuditEntryDenied(r.RemoteAddr, q.cfg.Name, r.URL.Path,
				result.DenyReason, clientCert))
			writeProxyError(w, http.StatusForbidden, "http.access_denied",
				fmt.Sprintf(q.bundle.T(q.lang, "http.access_denied"), result.DenyReason))
			return
		}

		// W22: per-cert connection limit (aligned with HTTP proxy).
		if q.cfg.TLS.MaxConnsPerCert > 0 {
			if !q.certTracker.Add(result.Serial, int64(q.cfg.TLS.MaxConnsPerCert)) {
				q.audit.Log(gw.AuditEntry{
					Action:       "cert_conn_limit",
					SrcIP:        r.RemoteAddr,
					ClientCN:     clientCert.Subject.CommonName,
					ClientSerial: result.Serial,
					Mapping:      q.cfg.Name,
					Target:       r.URL.Path,
				})
				writeProxyError(w, http.StatusTooManyRequests, "http.cert_conn_limit",
					q.bundle.T(q.lang, "http.cert_conn_limit"))
				return
			}
			defer q.certTracker.Remove(result.Serial)
		}

		if clientCert != nil {
			// W22: Lifecycle registration + revocation linkage (aligned with HTTP proxy).
			if q.revoker != nil {
				if reg := q.revoker.Registry(); reg != nil {
					defer reg.Register(gw.NormalizeSerial(clientCert.SerialNumber), clientCert)()
				}
				defer q.revoker.RevokeClientCert(clientCert, q.audit)
			}
			if q.connRegistry != nil && result != nil {
				unreg := q.connRegistry.RegisterConn(result.AgentId, result.Principal,
					clientIP, "h3", gw.NormalizeSerial(clientCert.SerialNumber),
					func() { closeResponseWriterConn(w) })
				defer unreg()
			}
			// W22: Task lifecycle tracking (A3/A5).
			if q.taskRegistry != nil {
				if taskID := gw.TaskIDFromHeader(r.Header.Get); taskID != "" {
					q.taskRegistry.Register(taskID, gw.NormalizeSerial(clientCert.SerialNumber),
						clientCert.Subject.CommonName, r.URL.Path, time.Now().Unix())
				}
				if taskID, done := gw.TaskCompletedFromHeader(r.Header.Get, clientCert.Subject.CommonName); done {
					if q.audit != nil {
						q.audit.Log(gw.AuditEntry{
							Action:       "task_complete_revoke",
							Target:       "task",
							TargetID:     taskID,
							ClientCN:     clientCert.Subject.CommonName,
							ClientSerial: gw.NormalizeSerial(clientCert.SerialNumber),
						})
					}
					if q.revoker != nil {
						q.revoker.RevokeClientCertForced(clientCert, q.audit)
					}
					q.taskRegistry.Unregister(taskID)
				}
			}
		}

		// G4: Delegated-Agent — use server-asserted values only. B2
		// (forward_client_cert_der): forward the verified client certificate
		// via X-Client-Cert-DER; the deprecated X-Agent-User username path
		// (B1) is no longer injected.
		if gw.HasDelegatedAgentOU(clientCert) {
			_, expiry, reason := gw.DelegatedAgentServerIdentity(clientCert, result.Principal)
			if reason != "" {
				http.Error(w, reason, http.StatusForbidden)
				return
			}
			if q.cfg.HTTPExt.ForwardClientCertDEREnabled() {
				r.Header.Set("X-Client-Cert-DER", base64.StdEncoding.EncodeToString(clientCert.Raw))
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

		// W22: Per-request certificate expiry check (DisconnectOnExpiry, aligned with HTTP proxy).
		if time.Now().After(clientCert.NotAfter) &&
			(q.cfg.TLS.DisconnectOnExpiryEnabled() || gw.HasAIC(clientCert)) {
			writeProxyError(w, http.StatusUnauthorized, "http.cert_expired",
				fmt.Sprintf(q.bundle.T(q.lang, "http.cert_expired"), clientCert.NotAfter.Format(time.RFC3339)))
			return
		}

		// Inject X-AIC-* headers matching HTTP proxy behavior
		if q.cfg.HTTPExt.ForwardClientCertEnabled() {
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

		if q.cfg.HTTPExt.TLSTerminationEnabled() {
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
			}
		}
	}

	path := r.URL.Path
	for i := range q.cfg.Routes {
		if matchPath(q.cfg.Routes[i].Path, path) {
			matchedRoute = &q.cfg.Routes[i]
			break
		}
	}
	if matchedRoute == nil {
		q.audit.Log(gw.AuditEntry{
			Action:  "no_route",
			SrcIP:   r.RemoteAddr,
			Mapping: q.cfg.Name,
			Target:  path,
		})
		writeProxyError(w, http.StatusNotFound, "http.no_route",
			q.bundle.T(q.lang, "http.no_route"))
		return
	}

	// W22: Route-level method and role restrictions (aligned with HTTP proxy).
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
				q.bundle.T(q.lang, "http.method_not_allowed"))
			return
		}
	}
	if len(matchedRoute.AllowRoles) > 0 {
		if clientCert == nil {
			q.audit.Log(gw.AuditEntry{
				Action:  "denied",
				SrcIP:   r.RemoteAddr,
				Mapping: q.cfg.Name,
				Target:  path,
				Roles:   matchedRoute.AllowRoles,
			})
			writeProxyError(w, http.StatusForbidden, "http.forbidden",
				q.bundle.T(q.lang, "http.forbidden"))
			return
		}
		roles := gw.ExtractRoles(clientCert)
		if !gw.CheckRole(roles, matchedRoute.AllowRoles) {
			q.audit.Log(gw.AuditEntry{
				Action:   "denied",
				SrcIP:    r.RemoteAddr,
				ClientCN: clientCert.Subject.CommonName,
				Mapping:  q.cfg.Name,
				Target:   path,
				Roles:    roles,
			})
			writeProxyError(w, http.StatusForbidden, "http.forbidden",
				q.bundle.T(q.lang, "http.forbidden"))
			return
		}
	}

	// W22: Per-request completed audit + request metrics (aligned with HTTP proxy).
	// W19: Task control headers are gateway-consumed signals; must be deleted after reading and before forwarding.
	r.Header.Del("X-AIC-Task-Id")
	r.Header.Del("X-AIC-Task-Status")

	start := time.Now()
	srw := &statusResponseWriter{ResponseWriter: w, status: http.StatusOK}
	q.proxyToBackend(srw, r, *matchedRoute)

	entry := gw.AuditEntry{
		Action:   "completed",
		SrcIP:    r.RemoteAddr,
		Mapping:  q.cfg.Name,
		Target:   path,
		TargetID: matchedRoute.Target,
		Duration: time.Since(start).Round(time.Millisecond).String(),
	}
	if isGRPCRequest(r) {
		entry.TargetID += " (grpc)"
	}
	if clientCert != nil {
		entry.ClientCN = clientCert.Subject.CommonName
		entry.Roles = gw.ExtractRoles(clientCert)
		entry.SetV12Fields("h3", q.cfg.Name, "", "", "allow")
	}
	q.audit.Log(entry)

	metricPath := path
	if matchedRoute != nil {
		metricPath = matchedRoute.Path
	}
	statusClass := fmt.Sprintf("%dxx", srw.status/100)
	if isGRPCRequest(r) {
		statusClass = "grpc"
	}
	HTTPRequestsTotal.Inc(q.cfg.Name, metricPath, r.Method, statusClass)
	HTTPRequestDuration.Observe(time.Since(start).Seconds(), q.cfg.Name, metricPath)
}

func matchPath(pattern, path string) bool {
	if pattern == "" {
		return path == "/"
	}
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(path) >= len(prefix) && path[:len(prefix)] == prefix &&
			(len(path) == len(prefix) || path[len(prefix)] == '/')
	}
	return pattern == path
}

// backendHTTPClient returns a shared http.Client with a pooled Transport (M5).
// A single Transport is reused across all proxied requests so connections are
// pooled instead of leaked; IdleConnTimeout reclaims idle connections and
// ResponseHeaderTimeout bounds slow backend responses.
func (q *QUICListener) backendTransportShared() *http.Transport {
	q.backendMu.Lock()
	defer q.backendMu.Unlock()
	if q.backendTransport == nil {
		q.backendTransport = &http.Transport{
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		}
	}
	return q.backendTransport
}

func (q *QUICListener) proxyToBackend(w http.ResponseWriter, r *http.Request, route RouteConfig) {
	// W22: Target parsing -- supports "http://host:port" / "https://host:port" and bare
	// "host:port". Bare host:port is rejected by url.Parse (IP) or misidentified as scheme
	// (localhost); uniformly prepends "http://" when no valid http/https scheme is present.
	raw := route.Target
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		if u, err = url.Parse("http://" + raw); err != nil {
			http.Error(w, "invalid target", http.StatusInternalServerError)
			return
		}
	}

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	outReq.URL.Scheme = u.Scheme
	outReq.URL.Host = u.Host
	outReq.Host = u.Host

	tr := q.backendTransportShared()
	if u.Scheme == "https" && route.UpstreamTLS != nil {
		// W18/W22: HTTPS backend custom CA + client certificate reverse-connect.
		if tc, err := upstreamTLSConfig(route.UpstreamTLS, u.Host); err == nil && tc != nil {
			tr = tr.Clone()
			tr.TLSClientConfig = tc
		}
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: tr,
	}
	resp, err := client.Do(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers using canonical keys (M5: avoid header-case issues).
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)

	// client.Timeout (30s) bounds the entire exchange including body copy, so a
	// slow or hung backend cannot block this handler indefinitely.
	_, _ = io.Copy(w, resp.Body)
}

// --- QUIC tunnel mode: raw stream forwarding ---

func (q *QUICListener) serve() {
	for {
		conn, err := q.ln.Accept(context.Background())
		if err != nil {
			if q.running.Load() {
				q.logger.Error("quic accept error", "name", q.cfg.Name, "error", err)
			}
			return
		}
		q.wg.Add(1)
		go q.handleConnection(conn)
	}
}

func (q *QUICListener) handleConnection(conn quic.Connection) {
	defer q.wg.Done()
	state := conn.ConnectionState().TLS
	peerCerts := state.PeerCertificates
	var clientCert *x509.Certificate
	if len(peerCerts) > 0 {
		clientCert = peerCerts[0]
	}

	var allowRoles []string
	var requiredCaps []string
	if len(q.cfg.Routes) > 0 {
		allowRoles = q.cfg.Routes[0].AllowRoles
		requiredCaps = q.cfg.Routes[0].RequiredCapabilities
	}

	clientIP := ""
	if h, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
		clientIP = h
	}

	result := gw.RunAccessPipeline(peerCerts, &gw.PipelineConfig{
		CRLCache:                 q.crl.Load(),
		OCSPCache:                q.ocsp,
		AllowRoles:               allowRoles,
		CheckScope:               gw.CheckFullChain,
		RequireAIC:               q.cfg.TLS.RequireAICEnabled(),
		RequireSPIFFE:            q.cfg.TLS.RequireSPIFFEEnabled(),
		AllowedSPIFFEIDs:         q.cfg.TLS.AllowedSPIFFEIDs,
		SPIFFETrustDomain:        q.cfg.TLS.SPIFFETrustDomain,
		DisallowRepresentative:   q.cfg.TLS.DisallowRepresentativeEnabled(),
		RequireUserAuth:          q.cfg.TLS.RequireUserAuthEnabled(),
		RequiredCapabilities:     requiredCaps,
		ClientIP:                 clientIP,
		EnforceConstraints:       true,
		StrictConstraints:        true,
		CapabilityPluginRegistry: q.pluginRegistry,
		CapabilityPluginResolver: q.policyResolver,
		PolicyVersion:            q.currentPolicyVersion(),
		AuditLogger:              q.audit,
		NonceCache:               q.nonceCache,
		RiskMonitor:              q.riskMonitor,
		// G2(b): When OCSP fallback is allow (fail-open), enforce offline certificate lifetime <=1h.
		OfflineMaxCertLifetime: gw.OfflineLifetimeFor(q.cfg.TLS.OCSPFallback),
	})
	if !result.Granted {
		conn.CloseWithError(0, result.DenyReason)
		return
	}

	if q.cfg.TLS.MaxConnsPerIP > 0 {
		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		q.ipMu.Lock()
		if q.ipConns[host] >= int64(q.cfg.TLS.MaxConnsPerIP) {
			q.ipMu.Unlock()
			conn.CloseWithError(0, "per-IP connection limit exceeded")
			return
		}
		q.ipConns[host]++
		q.ipMu.Unlock()
		defer func() {
			q.ipMu.Lock()
			q.ipConns[host]--
			if q.ipConns[host] <= 0 {
				delete(q.ipConns, host)
			}
			q.ipMu.Unlock()
		}()
	}

	if q.cfg.TLS.MaxConnsPerCert > 0 && clientCert != nil {
		serial := clientCert.SerialNumber.Text(16)
		if !q.certTracker.Add(serial, int64(q.cfg.TLS.MaxConnsPerCert)) {
			conn.CloseWithError(0, "per-cert limit exceeded")
			return
		}
		defer q.certTracker.Remove(serial)
	}

	// W22: Total connection limit (aligned with HTTP proxy's MaxTotalConns).
	if q.cfg.TLS.MaxTotalConns > 0 {
		q.ipMu.Lock()
		total := q.active.Load()
		q.ipMu.Unlock()
		// Attempt reservation: under concurrency, use CAS for simplicity -- the window race between
		// check-then-increment is acceptable (aligned with HTTP proxy's atomic assertion semantics).
		if total >= int64(q.cfg.TLS.MaxTotalConns) {
			conn.CloseWithError(0, "total connection limit exceeded")
			return
		}
	}

	// W22: Certificate expiry forced disconnect (DisconnectOnExpiry, unconditional for AIC).
	if clientCert != nil && time.Now().After(clientCert.NotAfter) &&
		(q.cfg.TLS.DisconnectOnExpiryEnabled() || gw.HasAIC(clientCert)) {
		conn.CloseWithError(0, "client certificate expired")
		return
	}

	// W22: Lifecycle registration + revocation linkage (aligned with HTTP proxy / TCP gateway).
	if clientCert != nil && q.revoker != nil {
		if reg := q.revoker.Registry(); reg != nil {
			defer reg.Register(gw.NormalizeSerial(clientCert.SerialNumber), clientCert)()
		}
		defer q.revoker.RevokeClientCert(clientCert, q.audit)
	}
	if clientCert != nil && q.connRegistry != nil && result != nil {
		unreg := q.connRegistry.RegisterConn(result.AgentId, result.Principal,
			clientIP, "quic-tunnel", gw.NormalizeSerial(clientCert.SerialNumber),
			func() { conn.CloseWithError(0, "kick") })
		defer unreg()
	}

	q.active.Add(1)
	defer q.active.Add(-1)

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		// W31: handleStream must be tracked in q.wg -- only then can Stop()'s wg.Wait() wait
		// for tunnel path to exit; otherwise in-flight streams leak after Stop. srcIP is passed
		// from the connection (quic.Stream does not expose its owning connection).
		q.wg.Add(1)
		go func(s quic.Stream) {
			defer q.wg.Done()
			q.handleStream(s, conn.RemoteAddr().String())
		}(stream)
	}
}

func (q *QUICListener) handleStream(stream quic.Stream, srcIP string) {
	defer stream.Close()

	// W31: Tunnel path adds per-stream audit. Records connection establishment and completion,
	// aligned with HTTP data plane (completed audit).
	start := time.Now()
	target := ""
	if len(q.cfg.Routes) > 0 {
		target = q.cfg.Routes[0].Target
	}
	q.audit.Log(gw.AuditEntry{
		Action:  "connected",
		SrcIP:   srcIP,
		Mapping: q.cfg.Name,
		Target:  target,
	})
	defer func() {
		q.audit.Log(gw.AuditEntry{
			Action:   "disconnected",
			SrcIP:    srcIP,
			Mapping:  q.cfg.Name,
			Target:   target,
			Duration: time.Since(start).Round(time.Millisecond).String(),
		})
	}()

	if target == "" {
		return
	}

	upstream, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()

	// W31: Use stream context to unblock io.Copy -- when client closes connection (stream ctx
	// cancel) or gateway Stops, cancel read/write + close upstream to make both io.Copy return
	// immediately; q.wg.Wait() no longer hangs.
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-stream.Context().Done():
			stream.CancelRead(0)
			stream.CancelWrite(0)
			upstream.Close()
		case <-q.stopCh:
			stream.CancelRead(0)
			stream.CancelWrite(0)
			upstream.Close()
		case <-stopWatch:
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(upstream, stream) // nolint:errcheck
	}()
	go func() {
		defer wg.Done()
		io.Copy(stream, upstream) // nolint:errcheck
	}()
	wg.Wait()
}
