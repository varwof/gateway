// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package udpgw

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	gw "github.com/varwof/gateway-core"
)

// QUICProxy QUIC/HTTP3 proxy instance.
type QUICProxy struct {
	cfg    ListenerConfig
	crl    *gw.CRLCache
	ocsp   *gw.OCSPCache
	audit  *gw.AuditLogger
	tsa    *gw.TSAClient
	bundle *Bundle
	lang   string
	logger *slog.Logger
	stopCh chan struct{}
	tlsCfg *tls.Config

	listener       *quic.Listener
	running        atomic.Bool
	active         atomic.Int64
	certTracker    *gw.ConnectionTracker
	revoker        *gw.Revoker
	ipConns        map[string]int64
	ipMu           sync.Mutex
	serverCert     atomic.Value
	connRegistry   *gw.ConnRegistry
	pluginRegistry *gw.PluginRegistry
	nonceCache     *gw.NonceCache
	// policyVersion returns the current effective policy version (task 5a).
	policyVersion func() uint64
	// policyResolver selects policy version registry by Agent ID (task 5b: branch control/canary).
	policyResolver func(agentID string) (uint64, *gw.PluginRegistry)
	// riskMonitor high-risk behavior monitor (2026-08-15). When nil, the pipeline does not record violation signals.
	riskMonitor *gw.RiskMonitor

	wg sync.WaitGroup
}

// NewQUICProxy creates a QUIC/HTTP3 proxy instance.
func NewQUICProxy(cfg ListenerConfig, crl *gw.CRLCache, ocsp *gw.OCSPCache, logger *slog.Logger, audit *gw.AuditLogger, tsa *gw.TSAClient, stopCh chan struct{}, bundle *Bundle, lang string, revoker *gw.Revoker, connRegistry *gw.ConnRegistry, nonceCache *gw.NonceCache) (*QUICProxy, error) {
	if logger == nil {
		logger = slog.Default()
	}
	return &QUICProxy{
		cfg:          cfg,
		crl:          crl,
		ocsp:         ocsp,
		audit:        audit,
		tsa:          tsa,
		bundle:       bundle,
		lang:         lang,
		logger:       logger,
		stopCh:       stopCh,
		certTracker:  gw.NewConnectionTracker(),
		ipConns:      make(map[string]int64),
		connRegistry: connRegistry,
		nonceCache:   nonceCache,
	}, nil
}

// Name returns the listener name.
func (q *QUICProxy) Name() string { return q.cfg.Name }

// Config returns the listener configuration.
func (q *QUICProxy) Config() ListenerConfig { return q.cfg }

// SetPluginRegistry sets the capability plugin registry.
func (q *QUICProxy) SetPluginRegistry(reg *gw.PluginRegistry) { q.pluginRegistry = reg }

// SetPolicyVersionFn sets the current policy version retrieval function (task 5a).
func (q *QUICProxy) SetPolicyVersionFn(fn func() uint64) { q.policyVersion = fn }

// SetPolicyResolverFn sets the function that selects policy version registry by Agent ID (task 5b).
func (q *QUICProxy) SetPolicyResolverFn(fn func(agentID string) (uint64, *gw.PluginRegistry)) {
	q.policyResolver = fn
}

// SetRiskMonitor injects the high-risk behavior monitor (2026-08-15, pipeline records signals).
func (q *QUICProxy) SetRiskMonitor(rm *gw.RiskMonitor) { q.riskMonitor = rm }

// currentPolicyVersion returns the current effective policy version (task 5a).
func (q *QUICProxy) currentPolicyVersion() uint64 {
	if q.policyVersion == nil {
		return 0
	}
	return q.policyVersion()
}

// Start starts QUIC listening and forwarding.
func (q *QUICProxy) Start() error {
	if !q.running.CompareAndSwap(false, true) {
		return fmt.Errorf(q.bundle.T(q.lang, "listener.already_running"), q.cfg.Name)
	}

	if q.cfg.TLS == nil || q.cfg.TLS.CertFile == "" {
		q.running.Store(false)
		return fmt.Errorf("listener %q: cert_file required for QUIC mode", q.cfg.Name)
	}

	cert, err := gw.LoadCert(q.cfg.TLS.CertFile, q.cfg.TLS.KeyFile)
	if err != nil {
		q.running.Store(false)
		return err
	}
	q.serverCert.Store(cert)

	q.tlsCfg = &tls.Config{
		NextProtos:     []string{"h3", "hq"},
		MinVersion:     tls.VersionTLS13,
		GetCertificate: q.getCert,
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

	tr := &quic.Transport{
		Conn: conn,
	}
	q.listener, err = tr.Listen(q.tlsCfg, &quic.Config{
		MaxIdleTimeout:                 q.cfg.ReadTimeout(),
		KeepAlivePeriod:                30 * time.Second,
		InitialStreamReceiveWindow:     10 * 1024 * 1024, // 10 MB initial window
		MaxStreamReceiveWindow:         20 * 1024 * 1024, // 20 MB max window
		InitialConnectionReceiveWindow: 20 * 1024 * 1024, // 20 MB initial connection window
		MaxConnectionReceiveWindow:     40 * 1024 * 1024, // 40 MB max connection window
	})
	if err != nil {
		conn.Close()
		q.running.Store(false)
		return fmt.Errorf("quic listen: %w", err)
	}

	ListenerUp.Set(1, q.cfg.Name)
	q.logger.Info(q.bundle.T(q.lang, "listener.listening"), "name", q.cfg.Name, "listen", q.cfg.Listen, "tls_mode", q.cfg.DisplayTLSMode())
	// Track the serve loop itself in wg: serve() spawns handleConnection /
	// handleStream goroutines which also Add() to the same wg, so Stop()'s
	// wg.Wait() correctly waits for serve to exit (no more Adds) and then for
	// all in-flight connections/streams to drain.
	q.wg.Add(1)
	go func() {
		defer q.wg.Done()
		q.serve()
	}()

	return nil
}

// Stop stops QUIC listening and forwarding (idempotent).
func (q *QUICProxy) Stop() {
	if !q.running.CompareAndSwap(true, false) {
		return
	}
	if q.listener != nil {
		q.listener.Close()
	}
	ListenerUp.Set(0, q.cfg.Name)
	q.wg.Wait()
	q.logger.Info(q.bundle.T(q.lang, "listener.stopped"), "name", q.cfg.Name)
}

// ActiveClients returns the current active client count.
func (q *QUICProxy) ActiveClients() int {
	return int(q.active.Load())
}

func (q *QUICProxy) serve() {
	for {
		conn, err := q.listener.Accept(context.Background())
		if err != nil {
			if q.running.Load() {
				q.logger.Warn(q.bundle.T(q.lang, "listener.serve_error"), "name", q.cfg.Name, "error", err)
			}
			return
		}

		ConnectionsAccepted.Inc(q.cfg.Name)
		q.active.Add(1)
		ActiveClients.Set(q.active.Load(), q.cfg.Name)
		q.wg.Add(1)
		go q.handleConnection(conn)
	}
}

func (q *QUICProxy) handleConnection(conn quic.Connection) {
	var certSerial string
	var clientCert *x509.Certificate
	peerCerts := conn.ConnectionState().TLS.PeerCertificates
	if len(peerCerts) > 0 {
		certSerial = peerCerts[0].SerialNumber.Text(16)
		clientCert = peerCerts[0]
	}

	// P2-A-15: Register with ConnExpiryRegistry on connection establishment, read renewal flag on close for revocation assessment.
	if q.revoker != nil && clientCert != nil {
		if reg := q.revoker.Registry(); reg != nil {
			defer reg.Register(gw.NormalizeSerial(clientCert.SerialNumber), clientCert)()
		}
	}

	defer func() {
		conn.CloseWithError(0, "bye")
		q.active.Add(-1)
		ActiveClients.Set(q.active.Load(), q.cfg.Name)
		if certSerial != "" {
			q.certTracker.Remove(certSerial)
		}
		q.wg.Done()
		if q.revoker != nil && clientCert != nil {
			q.revoker.RevokeClientCert(clientCert, q.audit)
		}
	}()

	// Unified admission pipeline: CRL → OCSP → RBAC → AIC/GS → Plugins
	if clientCert != nil && len(peerCerts) > 0 {
		clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		result := gw.RunAccessPipeline(peerCerts, &gw.PipelineConfig{
			CRLCache:                 q.crl,
			OCSPCache:                q.ocsp,
			AllowRoles:               q.cfg.AllowRoles(),
			CheckScope:               gw.CheckFullChain,
			RequireAIC:               q.cfg.RequireAICEnabled(),
			RequireSPIFFE:            q.cfg.TLS.RequireSPIFFEEnabled(),
			AllowedSPIFFEIDs:         q.cfg.TLS.AllowedSPIFFEIDs,
			SPIFFETrustDomain:        q.cfg.TLS.SPIFFETrustDomain,
			DisallowRepresentative:   q.cfg.DisallowRepresentativeEnabled(),
			RequireUserAuth:          q.cfg.RequireUserAuthEnabled(),
			RequiredCapabilities:     q.cfg.RequiredCapabilities(),
			ClientIP:                 clientIP,
			EnforceConstraints:       true,
			StrictConstraints:        true,
			CapabilityPluginRegistry: q.pluginRegistry,
			CapabilityPluginResolver: q.policyResolver,
			PolicyVersion:            q.currentPolicyVersion(),
			AuditLogger:              q.audit,
			NonceCache:               q.nonceCache,
			RiskMonitor:              q.riskMonitor,
			// G2(b): When OCSP fallback is allow (fail-open), enforce offline certificate lifetime ≤1h.
			OfflineMaxCertLifetime: gw.OfflineLifetimeFor(q.cfg.OCSPFallback()),
		})
		if !result.Granted {
			if q.audit != nil {
				entry := gw.NewAuditEntryDenied(conn.RemoteAddr().String(), q.cfg.Name, "",
					result.DenyReason, clientCert)
				q.audit.Log(entry)
			}
			return
		}

		// Delegated-Agent check
		if reason := gw.CheckDelegatedAgentCert(clientCert, result.GatewaySession); reason != "" {
			if q.audit != nil {
				entry := gw.NewAuditEntryDenied(conn.RemoteAddr().String(), q.cfg.Name, "", reason, clientCert)
				q.audit.Log(entry)
			}
			return
		}

		certSerial = result.Serial

		// P4.2: GatewaySession enforcement
		if result.GatewaySession != nil {
			remoteAddr := conn.RemoteAddr().String()
			if len(result.GatewaySession.AllowedCIDRs) > 0 {
				host, _, _ := net.SplitHostPort(remoteAddr)
				allowed := false
				for _, cidr := range result.GatewaySession.AllowedCIDRs {
					_, cidrNet, err := net.ParseCIDR(cidr)
					if err != nil {
						continue
					}
					ip := net.ParseIP(host)
					if ip != nil && cidrNet.Contains(ip) {
						allowed = true
						break
					}
				}
				if !allowed {
					q.logger.Warn("session CIDR not allowed",
						"name", q.cfg.Name, "remote", remoteAddr, "client", clientCert.Subject.CommonName)
					conn.CloseWithError(0, "session CIDR not allowed")
					return
				}
			}
			if result.GatewaySession.HardTimeoutLimit() > 0 {
				go func() {
					timer := time.NewTimer(time.Duration(result.GatewaySession.HardTimeoutLimit()) * time.Second)
					defer timer.Stop()
					select {
					case <-timer.C:
						conn.CloseWithError(0, "session timeout")
					case <-conn.Context().Done():
					case <-q.stopCh:
					}
				}()
			}
			if q.connRegistry != nil {
				aic, _ := gw.ParseAIC(clientCert)
				agentId := ""
				principalUid := ""
				if aic != nil {
					agentId = aic.AgentId
					principalUid = aic.PrincipalUid.String()
				}
				remove := q.connRegistry.RegisterConn(agentId, principalUid, remoteAddr, "quic", gw.NormalizeSerial(clientCert.SerialNumber), func() {
					conn.CloseWithError(0, "disconnected by admin")
				})
				go func() {
					<-q.stopCh
					remove()
				}()
			}
		}
	}

	// B09 — total connection limit for QUIC
	if max := q.cfg.MaxTotalConns(); max > 0 && q.active.Load() >= int64(max) {
		if q.audit != nil && clientCert != nil {
			entry := gw.NewAuditEntryDenied(conn.RemoteAddr().String(), q.cfg.Name, "",
				"total connection limit exceeded", clientCert)
			q.audit.Log(entry)
		}
		return
	}

	// per-IP connection limit
	srcHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if max := q.cfg.MaxConnsPerIP(); max > 0 {
		q.ipMu.Lock()
		count := q.ipConns[srcHost]
		if count >= int64(max) {
			q.ipMu.Unlock()
			if q.audit != nil && clientCert != nil {
				entry := gw.NewAuditEntryDenied(conn.RemoteAddr().String(), q.cfg.Name, "",
					"per-IP connection limit exceeded", clientCert)
				q.audit.Log(entry)
			}
			return
		}
		q.ipConns[srcHost] = count + 1
		q.ipMu.Unlock()
		defer func() {
			q.ipMu.Lock()
			q.ipConns[srcHost]--
			if q.ipConns[srcHost] <= 0 {
				delete(q.ipConns, srcHost)
			}
			q.ipMu.Unlock()
		}()
	}

	if max := q.cfg.MaxConnsPerCert(); max > 0 && certSerial != "" {
		if !q.certTracker.Add(certSerial, int64(max)) {
			if q.audit != nil && clientCert != nil {
				entry := gw.NewAuditEntryDenied(conn.RemoteAddr().String(), q.cfg.Name, "",
					"per-cert connection limit exceeded", clientCert)
				q.audit.Log(entry)
			}
			return
		}
	}

	// per-connection token bucket for byte-level rate limiting
	var bucket *gw.TokenBucket
	if bps := q.cfg.ConnectionBPS(); bps > 0 {
		burst := q.cfg.ConnectionBurst()
		if burst <= 0 {
			burst = bps
		}
		// TokenBucket.WaitN can never complete when n > burst (refill is capped
		// at burst), and io.Copy writes in ~32KB chunks. Floor the burst so a
		// small BPS/burst cannot deadlock handleStream in an infinite WaitN loop.
		if burst < 64*1024 {
			burst = 64 * 1024
		}
		bucket = gw.NewTokenBucket(float64(bps), burst)
	}

	// B04 — QUIC cert expiry monitor.
	// G2(a): Short-lived certificates (including AIC) enforce "connection duration ≤ remaining certificate lifetime", cannot be
	// disabled by disconnect_on_expiry (otherwise a 5-minute cert connection could stay open for 5 days);
	// non-AIC long-lived identity certificates retain original config gating.
	if clientCert != nil && (q.cfg.DisconnectOnExpiryEnabled() || gw.HasAIC(clientCert)) {
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if time.Now().After(clientCert.NotAfter) {
						if q.audit != nil {
							entry := gw.NewAuditEntryDenied(conn.RemoteAddr().String(), q.cfg.Name, "",
								"certificate expired", clientCert)
							q.audit.Log(entry)
						}
						conn.CloseWithError(0, "certificate expired")
						return
					}
				case <-conn.Context().Done():
					return
				}
			}
		}()
	}

	if q.audit != nil && clientCert != nil {
		entry := gw.NewAuditEntryFromConn(conn.RemoteAddr().String(), q.cfg.Name, "", clientCert)
		entry.Action = string(gw.ActionConnected)
		entry.SetV12Fields("quic", q.cfg.Name, "", "", "allow")
		q.audit.Log(entry)
	}

	var clientCN string
	if clientCert != nil {
		clientCN = clientCert.Subject.CommonName
	}

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		q.wg.Add(1)
		go q.handleStream(stream, clientCN, bucket)
	}
}

type rateLimitedWriter struct {
	w      io.Writer
	bucket *gw.TokenBucket
}

// Write implements rate-limited writing.
func (w *rateLimitedWriter) Write(p []byte) (int, error) {
	w.bucket.WaitN(len(p))
	return w.w.Write(p)
}

func (q *QUICProxy) handleStream(stream quic.Stream, clientCN string, bucket *gw.TokenBucket) {
	defer func() {
		stream.Close()
		q.wg.Done()
	}()

	start := time.Now()
	target := selectTarget(q.cfg.Routes)
	if target == "" {
		PacketDroppedTotal.Inc(q.cfg.Name, "no_route")
		return
	}

	remote, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		PacketDroppedTotal.Inc(q.cfg.Name, "resolve")
		return
	}

	upstream, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		PacketDroppedTotal.Inc(q.cfg.Name, "connect")
		return
	}
	defer upstream.Close()

	PacketsTotal.Inc(q.cfg.Name, "forwarded")

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if bucket != nil {
			io.Copy(&rateLimitedWriter{w: upstream, bucket: bucket}, stream)
		} else {
			io.Copy(upstream, stream)
		}
	}()
	go func() {
		defer wg.Done()
		if q.cfg.ReadTimeoutSec > 0 {
			upstream.SetReadDeadline(time.Now().Add(time.Duration(q.cfg.ReadTimeoutSec) * time.Second))
		}
		if bucket != nil {
			io.Copy(&rateLimitedWriter{w: stream, bucket: bucket}, upstream)
		} else {
			io.Copy(stream, upstream)
		}
	}()

	ProxyLatency.Observe(time.Since(start).Seconds(), q.cfg.Name, "quic")
	wg.Wait()
}

func (q *QUICProxy) getCert(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := q.serverCert.Load(); c != nil {
		return c.(*tls.Certificate), nil
	}
	return nil, nil
}

// UpdateCert updates the QUIC server TLS certificate without interruption.
func (q *QUICProxy) UpdateCert(cert *tls.Certificate) {
	q.serverCert.Store(cert)
}

// quicRouteCounter provides round-robin distribution for multi-route QUIC
// configs (M4 fix).
var quicRouteCounter uint64

func selectTarget(routes []RouteConfig) string {
	if len(routes) == 0 {
		return ""
	}
	if len(routes) == 1 {
		return routes[0].Target
	}
	// M4: distribute across routes instead of always hitting routes[0].
	// Round-robin keyed to the route slice so multi-route QUIC configs
	// actually load-balance (consistent with UDP proxy hash routing).
	idx := int(atomic.AddUint64(&quicRouteCounter, 1)) % len(routes)
	return routes[idx].Target
}
