// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package tcpgw

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	gw "github.com/varwof/gateway-core"
)

// MappingState represents the running state of a TCP mapping.
type MappingState string

const (
	// MappingStopped indicates the mapping has stopped.
	MappingStopped MappingState = "stopped"
	// MappingRunning indicates the mapping is running.
	MappingRunning MappingState = "running"
	// MappingFailed indicates the mapping failed to start.
	MappingFailed MappingState = "failed"
	// MappingUnhealthy indicates the mapping backend health check failed.
	MappingUnhealthy MappingState = "unhealthy"
)

// certExpiryCheckInterval is the certificate expiry active check interval (W38: named constant replacing magic number 5s).
const certExpiryCheckInterval = 5 * time.Second

// Mapping is a TCP port mapping instance that handles proxying from a single listener to a backend.
type Mapping struct {
	cfg            MappingConfig
	listener       net.Listener
	tlsCfg         *tls.Config
	crlCache       *gw.CRLCache
	ocspCache      *gw.OCSPCache
	audit          *gw.AuditLogger
	tsa            *gw.TSAClient
	bundle         *Bundle
	lang           string
	logger         *slog.Logger
	state          atomic.Value
	mu             sync.Mutex
	stopCh         chan struct{}
	wg             sync.WaitGroup
	conns          int64
	ipConns        map[string]int64
	ipMu           sync.Mutex
	healthy        atomic.Bool
	certTracker    *gw.ConnectionTracker
	revoker        *gw.Revoker
	serverCert     atomic.Value
	mesh           *Mesh
	connRegistry   *gw.ConnRegistry
	pluginRegistry *gw.PluginRegistry
	nonceCache     *gw.NonceCache
	// policyVersion returns the current effective policy version (task 5a: decision audit binding version).
	// Injected by the gateway as a closure of g.policyMgr.CurrentVersion, returns 0 when nil.
	policyVersion func() uint64
	// policyResolver selects the policy version registry by agent identifier (task 5b: branch control/canary).
	// Injected by the gateway as g.policyMgr.SelectRegistry, falls back to pluginRegistry when nil.
	policyResolver func(agentID string) (uint64, *gw.PluginRegistry)
	// riskMonitor is the high-risk behavior monitor (2026-08-15). When nil, the pipeline does not record violation signals.
	riskMonitor *gw.RiskMonitor
}

// idleConn wraps net.Conn so that every Read/Write rolls the deadline to
// now+idle — implementing a true "idle timeout" (W05). Go's deadline is fixed once set
// and does not auto-extend with I/O; calling SetDeadline(now+idle) directly is actually
// "absolute connection lifetime" (continuously active connections would also be cut off,
// overlapping with max_connection_duration_sec).
type idleConn struct {
	net.Conn
	idle time.Duration
}

// Read rolls the deadline to now+idle before each read (activity-refreshed idle timeout, W05).
func (c *idleConn) Read(p []byte) (int, error) {
	if c.idle > 0 {
		c.Conn.SetDeadline(time.Now().Add(c.idle))
	}
	return c.Conn.Read(p)
}

// enableTCPKeepAlive enables keepalive on a TCP connection (W10: Go only enables keepalive
// for dialed connections; accepted connections default to off — dead peer detection relies
// on ~15min OS retransmit timeout).
func enableTCPKeepAlive(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(tcpKeepAlivePeriod)
	}
}

// tcpKeepAlivePeriod is the keepalive probe interval (W10).
const tcpKeepAlivePeriod = 60 * time.Second

// acceptErrorBackoff is the Accept error backoff interval (W12: prevents log flooding
// and CPU spinning during persistent EMFILE/ENFILE failures).
const acceptErrorBackoff = 200 * time.Millisecond

// Write rolls the deadline to now+idle before each write (activity-refreshed idle timeout, W05).
func (c *idleConn) Write(p []byte) (int, error) {
	if c.idle > 0 {
		c.Conn.SetDeadline(time.Now().Add(c.idle))
	}
	return c.Conn.Write(p)
}

// CloseWrite half-closes the write direction (W06: TCP half-close). Delegates to the
// underlying connection; falls back to full close if the underlying connection does
// not support CloseWrite.
func (c *idleConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// halfCloseWrite closes the write direction (TCP FIN), preserving the read direction
// to receive remaining response from the peer (W06). Connections supporting the
// CloseWrite interface (*net.TCPConn / *tls.Conn) get graceful half-close;
// otherwise falls back to full close (compatible with abstract connections that
// don't support half-close, like net.Pipe).
func halfCloseWrite(c net.Conn) {
	if c == nil {
		return
	}
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}

// NewMapping creates a TCP port mapping instance.
func NewMapping(cfg MappingConfig, crlCache *gw.CRLCache, ocspCache *gw.OCSPCache, audit *gw.AuditLogger, tsa *gw.TSAClient, bundle *Bundle, lang string, revoker *gw.Revoker, logger *slog.Logger, connRegistry *gw.ConnRegistry, nonceCache *gw.NonceCache) (*Mapping, error) {
	if logger == nil {
		logger = slog.Default()
	}
	m := &Mapping{
		cfg:          cfg,
		crlCache:     crlCache,
		ocspCache:    ocspCache,
		audit:        audit,
		tsa:          tsa,
		bundle:       bundle,
		lang:         lang,
		logger:       logger,
		revoker:      revoker,
		stopCh:       make(chan struct{}),
		ipConns:      make(map[string]int64),
		certTracker:  gw.NewConnectionTracker(),
		connRegistry: connRegistry,
		nonceCache:   nonceCache,
	}
	m.healthy.Store(true)
	m.state.Store(MappingStopped)
	return m, nil
}

// SetRiskMonitor injects the risk monitor (can be updated during hot reload).
func (m *Mapping) SetRiskMonitor(rm *gw.RiskMonitor) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.riskMonitor = rm
}

// Start starts TCP mapping listening and forwarding.
func (m *Mapping) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state.Load().(MappingState) == MappingRunning {
		return fmt.Errorf("mapping %q already running", m.cfg.Name)
	}

	var err error
	mode := m.cfg.effectiveMode()
	switch mode {
	case "mesh", gw.TLSModeNone:
		m.listener, err = net.Listen("tcp", m.cfg.Listen)
	case gw.TLSModeServer:
		t := m.cfg.TLS
		cert, e := gw.LoadCert(t.CertFile, t.KeyFile)
		if e != nil {
			return fmt.Errorf("mapping %q: %w", m.cfg.Name, e)
		}
		m.serverCert.Store(cert)
		m.tlsCfg = gw.ServerTLSConfig(cert, t.CipherSuites, t.MinTLSVersion)
		m.tlsCfg.GetCertificate = m.getCert
		if t.CACertFile != "" {
			gw.StartOCSPStapling(cert, m.tlsCfg, t.CACertFile, m.stopCh, m.bundle, m.lang)
		}
		m.listener, err = tls.Listen("tcp", m.cfg.Listen, m.tlsCfg)
	case gw.TLSModeMTLS:
		t := m.cfg.TLS
		cert, e := gw.LoadCert(t.CertFile, t.KeyFile)
		if e != nil {
			return fmt.Errorf("mapping %q: %w", m.cfg.Name, e)
		}
		m.serverCert.Store(cert)
		m.tlsCfg, err = gw.MTLSServerConfig(t.CACertFile, cert, t.CipherSuites, t.MinTLSVersion)
		if err != nil {
			return fmt.Errorf("mapping %q: %w", m.cfg.Name, err)
		}
		m.tlsCfg.GetCertificate = m.getCert
		gw.StartOCSPStapling(cert, m.tlsCfg, t.CACertFile, m.stopCh, m.bundle, m.lang)
		m.listener, err = tls.Listen("tcp", m.cfg.Listen, m.tlsCfg)
	default:
		return fmt.Errorf("mapping %q: unsupported protocol/tls mode %q/%q", m.cfg.Name, m.cfg.Protocol, mode)
	}

	if err != nil {
		m.state.Store(MappingFailed)
		return fmt.Errorf("mapping %q listen %s: %w", m.cfg.Name, m.cfg.Listen, err)
	}

	m.state.Store(MappingRunning)
	m.logger.Info(m.bundle.T(m.lang, "mapping.listening"),
		"name", m.cfg.Name, "listen", m.cfg.Listen, "target", m.cfg.Target,
		"protocol", m.cfg.Protocol, "tls_mode", mode)

	go m.acceptLoop()
	go m.healthCheckLoop()
	return nil
}

// Stop stops the TCP mapping, closing the listener and all connections.
func (m *Mapping) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.state.Load().(MappingState)
	if state == MappingStopped {
		return nil
	}

	close(m.stopCh)
	if m.listener != nil {
		m.listener.Close()
	}
	m.wg.Wait()
	m.state.Store(MappingStopped)
	m.logger.Info(m.bundle.T(m.lang, "mapping.stopped"), "name", m.cfg.Name)
	return nil
}

// State returns the current running state of the mapping.
func (m *Mapping) State() MappingState {
	state := m.state.Load().(MappingState)
	if state == MappingRunning && !m.healthy.Load() {
		return MappingUnhealthy
	}
	return state
}

// Conns returns the current active connection count.
func (m *Mapping) Conns() int64 {
	return atomic.LoadInt64(&m.conns)
}

// Name returns the mapping name.
func (m *Mapping) Name() string {
	return m.cfg.Name
}

// currentPolicyVersion returns the current effective policy version (task 5a). Returns 0 when closure is not injected.
func (m *Mapping) currentPolicyVersion() uint64 {
	if m.policyVersion == nil {
		return 0
	}
	return m.policyVersion()
}

// Healthy returns the backend health check status.
func (m *Mapping) Healthy() bool {
	return m.healthy.Load()
}

// dialTimeout returns the backend dial timeout (W38: configurable, default 10s).
func (m *Mapping) dialTimeout() time.Duration {
	return m.cfg.DialTimeout()
}

func (m *Mapping) acceptLoop() {
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			select {
			case <-m.stopCh:
				return
			default:
			}
			m.logger.Warn(m.bundle.T(m.lang, "mapping.accept_error"), "name", m.cfg.Name, "error", err)
			// W12 (2026-08-16): Accept error hot loop without backoff — EMFILE/ENFILE persistent
			// failure causes log flooding + CPU spinning. Brief backoff (interruptible by stopCh).
			select {
			case <-time.After(acceptErrorBackoff):
			case <-m.stopCh:
				return
			}
			continue
		}
		// W10 (2026-08-16): Enable keepalive on accepted connections — Go only auto-enables
		// keepalive for dialed connections; accepted connections default off, dead peer
		// detection relies on ~15min OS retransmit timeout.
		enableTCPKeepAlive(conn)

		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

		var maxIP, maxTotal int
		maxIP = m.cfg.MaxConnsPerIP()
		maxTotal = m.cfg.MaxTotalConns()

		// W15 (2026-08-16): Use atomic counter for total instead of holding ipMu lock to sum O(unique IPs).
		// The previous implementation held ipMu on every accept and iterated the entire map — a hotspot
		// with many client IPs; m.conns is already precisely maintained by handleConn defer
		// (+1 after accept limit passes, -1 on disconnect), semantically equivalent
		// (current active connection count) and lock-free.
		m.ipMu.Lock()
		ipCount := m.ipConns[host]
		m.ipMu.Unlock()
		total := atomic.LoadInt64(&m.conns) + 1 // include the incoming connection

		if maxIP > 0 && ipCount >= int64(maxIP) {
			m.logger.Warn(m.bundle.T(m.lang, "mapping.per_ip_limit"),
				"name", m.cfg.Name, "host", host, "ip_count", ipCount, "max_ip", maxIP)
			conn.Close()
			continue
		}
		if maxTotal > 0 && total > int64(maxTotal) {
			m.logger.Warn(m.bundle.T(m.lang, "mapping.total_conn_limit"),
				"name", m.cfg.Name, "total", total, "max_total", maxTotal)
			conn.Close()
			continue
		}

		// Only count the connection after it has passed both limits, so a
		// rejected connection never leaks the per-IP/total counters.
		m.ipMu.Lock()
		m.ipConns[host]++
		m.ipMu.Unlock()

		// W03: wg.Add must run inside m.mu and re-check stopCh — Stop() holds m.mu and calls
		// wg.Wait(); if Add and Wait run concurrently (counter at 0) it's a WaitGroup race;
		// and Stop closes(stopCh) inside the lock, so re-checking here prevents orphaned connections
		// after Stop returns.
		m.mu.Lock()
		select {
		case <-m.stopCh:
			m.mu.Unlock()
			conn.Close()
			return
		default:
		}
		m.wg.Add(1)
		m.mu.Unlock()

		ConnectionsAccepted.Inc(m.cfg.Name)
		atomic.AddInt64(&m.conns, 1)
		go m.handleConn(conn)
	}
}

func (m *Mapping) handleConn(incoming net.Conn) {
	// conn is a stable reference for the connection's lifetime: watcher/expiry/io.Copy
	// all use it, avoiding closure reads of the `incoming` variable that gets re-bound
	// later (W03 watcher and W05 idleConn wrapping re-bind incoming, triggering a data race).
	conn := incoming
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	defer func() {
		conn.Close()
		m.wg.Done()
		atomic.AddInt64(&m.conns, -1)
		m.ipMu.Lock()
		m.ipConns[host]--
		if m.ipConns[host] <= 0 {
			delete(m.ipConns, host)
		}
		m.ipMu.Unlock()
	}()

	var hardDeadline time.Duration
	hardDeadline = m.cfg.MaxConnectionDuration()
	ctx := context.Background()
	if hardDeadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, time.Now().Add(hardDeadline))
		defer cancel()
	}
	// W03: stopCh/ctx watcher — Stop()/Reload() and connection hard timeout must force-disconnect
	// the connection, otherwise idle keep-alive connections (without idle_timeout) would make
	// io.Copy block forever, m.wg.Wait() hang indefinitely while holding the lock, and block
	// the management API. Previously the stopCh branch was empty and only started when
	// hardDeadline>0; idle connections survived forever.
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-m.stopCh:
			conn.Close()
		}
	}()

	if !m.healthy.Load() {
		m.logger.Warn(m.bundle.T(m.lang, "mapping.backend_unhealthy"), "name", m.cfg.Name)
		return
	}

	var idleTimeout time.Duration
	idleTimeout = m.cfg.IdleTimeout()
	// W39: Do not use a one-shot SetDeadline here — its semantics is "absolute connection lifetime",
	// conflicting with W05 idleConn's per-I/O rolling refresh. Idle timeout is fully handled by
	// idleConn wrapping (applied on both proxy and mesh paths).
	if m.cfg.Protocol == ProtocolTCPMesh {
		m.handleMesh(incoming, idleTimeout)
		return
	}

	srcIP := incoming.RemoteAddr().String()
	var clientCert *x509.Certificate

	mode := m.cfg.effectiveMode()
	if mode == gw.TLSModeMTLS {
		tlsConn, ok := incoming.(*tls.Conn)
		if !ok {
			return
		}
		// H5: SetDeadline — anti-DoS (slow handshake protection). Only protects the handshake phase,
		// cleared afterwards to avoid conflicting with W05 idleConn's rolling deadline (W39).
		if idleTimeout > 0 {
			incoming.SetDeadline(time.Now().Add(idleTimeout))
		}
		if err := tlsConn.Handshake(); err != nil {
			m.logger.Warn(m.bundle.T(m.lang, "mapping.tls_handshake_failed"), "name", m.cfg.Name, "src_ip", srcIP, "error", err)
			return
		}
		incoming.SetDeadline(time.Time{})
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			return
		}
		clientCert = state.PeerCertificates[0]

		// Unified admission pipeline: CRL → OCSP → RBAC → AIC/GS → Plugins
		result := gw.RunAccessPipeline(state.PeerCertificates, &gw.PipelineConfig{
			CRLCache:                 m.crlCache,
			OCSPCache:                m.ocspCache,
			AllowRoles:               m.cfg.TLS.AllowRoles,
			CheckScope:               gw.CheckFullChain,
			RequireAIC:               m.cfg.RequireAICEnabled(),
			RequireSPIFFE:            m.cfg.TLS.RequireSPIFFEEnabled(),
			AllowedSPIFFEIDs:         m.cfg.TLS.AllowedSPIFFEIDs,
			SPIFFETrustDomain:        m.cfg.TLS.SPIFFETrustDomain,
			DisallowRepresentative:   m.cfg.DisallowRepresentativeEnabled(),
			RequireUserAuth:          m.cfg.RequireUserAuthEnabled(),
			ClientIP:                 host,
			RequiredCapabilities:     m.cfg.TLS.RequiredCapabilities,
			EnforceConstraints:       true,
			StrictConstraints:        true,
			CapabilityPluginRegistry: m.pluginRegistry,
			CapabilityPluginResolver: m.policyResolver,
			PolicyVersion:            m.currentPolicyVersion(),
			AuditLogger:              m.audit,
			NonceCache:               m.nonceCache,
			RiskMonitor:              m.riskMonitor,
			// G2(b): When OCSP fallback is allow (fail-open), enforce offline cert validity ≤1h.
			OfflineMaxCertLifetime: gw.OfflineLifetimeFor(m.cfg.TLS.OCSPFallback),
		})
		if !result.Granted {
			entry := gw.NewAuditEntryDenied(srcIP, m.cfg.Name, m.cfg.Target, result.DenyReason, clientCert)
			m.audit.Log(entry)
			return
		}

		if !m.certTracker.Add(result.Serial, int64(m.cfg.MaxConnsPerCert())) {
			entry := gw.NewAuditEntryDenied(srcIP, m.cfg.Name, m.cfg.Target,
				"per-cert connection limit exceeded", clientCert)
			m.audit.Log(entry)
			return
		}
		defer m.certTracker.Remove(result.Serial)
		// H1: do not revoke on every disconnect — that destroys long-lived
		// agent certs and floods the CA/audit. Only revoke when revocation on
		// disconnect is explicitly opted in via disconnect_on_expiry=true
		// (default-off). Short-lived certs are rotated per connection and are
		// the intended use case for disconnect-revoke.
		// Skip revocation if cert was renewed (migrating state).
		t := m.cfg.TLS
		if m.revoker != nil && t != nil &&
			t.DisconnectOnExpiry != nil && *t.DisconnectOnExpiry {
			// P2-A-15: Register connection lifecycle with ConnExpiryRegistry;
			// on close, Revoker decides whether to skip revocation based on the renewal marker.
			if reg := m.revoker.Registry(); reg != nil && clientCert != nil {
				defer reg.Register(gw.NormalizeSerial(clientCert.SerialNumber), clientCert)()
			}
			defer m.revoker.RevokeClientCert(clientCert, m.audit)
		}
		unregister := m.connRegistry.RegisterConn(result.AgentId, result.Principal, srcIP, "tcp", gw.NormalizeSerial(clientCert.SerialNumber), func() { conn.Close() })
		defer unregister()

		// P4.2: GatewaySession enforcement (AllowedCIDRs + HardTimeout)
		if gs := result.GatewaySession; gs != nil {
			if len(gs.AllowedCIDRs) > 0 {
				host, _, _ := net.SplitHostPort(srcIP)
				if !gs.CIDRAllowed(host) {
					entry := gw.NewAuditEntryDenied(srcIP, m.cfg.Name, m.cfg.Target,
						"session CIDR not allowed", clientCert)
					m.audit.Log(entry)
					return
				}
			}
			if gs.HardTimeoutLimit() > 0 {
				go func() {
					timer := time.NewTimer(time.Duration(gs.HardTimeoutLimit()) * time.Second)
					defer timer.Stop()
					select {
					case <-timer.C:
						conn.Close()
					case <-ctx.Done():
					}
				}()
			}
		}

		// P0-2: disconnect on cert expiry.
		// G2(a): Short-lived certs (including AIC) enforce "connection duration ≤ certificate remaining validity",
		// cannot be disabled by disconnect_on_expiry=false (otherwise a 5-minute cert's connection could stay open 5 days);
		// non-AIC long-lived identity certs retain the original config gate.
		expiryCtx, expiryCancel := context.WithCancel(context.Background())
		defer expiryCancel()
		forceExpiry := gw.HasAIC(clientCert)
		if forceExpiry || m.cfg.DisconnectOnExpiryEnabled() {
			var certPtr atomic.Pointer[x509.Certificate]
			certPtr.Store(clientCert)

			go func() {
				// W38: Certificate expiry check interval named constant (originally magic number 5s).
				ticker := time.NewTicker(certExpiryCheckInterval)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						currentCert := certPtr.Load()
						if time.Now().After(currentCert.NotAfter) {
							conn.Close()
							return
						}
					case <-expiryCtx.Done():
						return
					}
				}
			}()
		}

		// G3: Periodic recheck of authorizationConstraints within long-lived connections. TCP data plane
		// is transparent long connections; constraints are only checked once at handshake; time-window and
		// other time-expiring constraints are not rechecked after crossing the window (nighttime window
		// connections remain active during daytime). When ConstraintRecheckSec is enabled, AIC + PA
		// constraints are re-evaluated at the interval; violations disconnect the connection and audit.
		if recheck := m.cfg.ConstraintRecheckInterval(); recheck > 0 {
			var aicCons, paCons []gw.Capability
			if result.AIC != nil {
				aicCons = result.AIC.AuthorizationConstraints
			}
			if result.PrincipalAuthorization != nil {
				paCons = result.PrincipalAuthorization.AuthorizationConstraints
			}
			if len(aicCons) > 0 || len(paCons) > 0 {
				recheckCtx, recheckCancel := context.WithCancel(context.Background())
				defer recheckCancel()
				go gw.ConstraintRecheckLoop(aicCons, paCons, host, recheck, recheckCtx.Done(), func(reason string) {
					m.logger.Warn(m.bundle.T(m.lang, "mapping.constraint_violated"),
						"name", m.cfg.Name, "src_ip", srcIP, "reason", reason)
					entry := gw.NewAuditEntryDenied(srcIP, m.cfg.Name, m.cfg.Target,
						"constraint recheck violation: "+reason, clientCert)
					m.audit.Log(entry)
					conn.Close()
				})
			}
		}
	}

	// W05: Use activity-refreshed idle timeout wrapping (per-I/O rolling deadline) instead of
	// a one-shot SetDeadline (which is absolute connection lifetime, overlapping with max_connection_duration_sec).
	// Wrapping must be after TLS type assertions/pipeline to avoid breaking *tls.Conn assertions.
	if idleTimeout > 0 {
		incoming = &idleConn{Conn: incoming, idle: idleTimeout}
	}

	target, err := net.DialTimeout("tcp", m.cfg.Target, m.dialTimeout())
	if err != nil {
		m.logger.Error(m.bundle.T(m.lang, "mapping.dial_target_error"),
			"name", m.cfg.Name, "target", m.cfg.Target, "error", err)
		return
	}
	defer target.Close()

	if idleTimeout > 0 {
		target = &idleConn{Conn: target, idle: idleTimeout}
	}

	ConnectionsTotal.Inc(m.cfg.Name)
	ConnectionsActive.Add(1, m.cfg.Name)

	start := time.Now()
	entry := gw.NewAuditEntryFromConn(srcIP, m.cfg.Name, m.cfg.Target, clientCert)
	entry.Action = string(gw.ActionConnected)
	entry.SetV12Fields("tcp", "", "", "", "allow")
	m.audit.Log(entry)

	var bytesIn, bytesOut int64
	done := make(chan struct{}, 2)

	// Propagate connection close between the two directions so the proxy
	// loop terminates when either side closes. Otherwise the reverse
	// io.Copy blocks forever on a backend that is itself waiting for input
	// (e.g. an echo server), deadlocking handleConn and Stop().
	// W06: Half-close (CloseWrite) instead of full close — client FIN indicates
	// request end but still expects response; calling Close() directly tears down
	// the entire connection and truncates remaining backend data.
	go func() {
		n, _ := io.Copy(target, incoming)
		bytesOut = n
		halfCloseWrite(target)
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(incoming, target)
		bytesIn = n
		halfCloseWrite(incoming)
		done <- struct{}{}
	}()

	<-done
	<-done

	// W25 alignment (2026-08-16): Removed BytesTo* (high-cardinality cert_serial label, and
	// never consumed by monitoring). Byte counts are still recorded in audit entries BytesIn/BytesOut.

	entry.Action = string(gw.ActionDisconnected)
	entry.Duration = time.Since(start).Round(time.Millisecond).String()
	entry.BytesIn = bytesIn
	entry.BytesOut = bytesOut
	m.audit.Log(entry)

	ConnectionDuration.Observe(time.Since(start).Seconds(), m.cfg.Name)
	ConnectionsActive.Add(-1, m.cfg.Name)
}

// SetMesh sets the Mesh peer network instance.
func (m *Mapping) SetMesh(mesh *Mesh) {
	m.mesh = mesh
}

func (m *Mapping) handleMesh(incoming net.Conn, idleTimeout time.Duration) {
	// conn is a stable reference: watcher closes using conn, avoiding race with W05 idleConn re-binding incoming.
	conn := incoming
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	defer conn.Close()

	if m.mesh == nil {
		m.logger.Warn("mesh: mesh not configured", "peer", m.cfg.MeshPeerName)
		MeshDialErrors.Inc(m.cfg.MeshPeerName)
		return
	}

	peer := m.mesh.Peer(m.cfg.MeshPeerName)
	if peer == nil {
		m.logger.Warn("mesh: peer not found", "peer", m.cfg.MeshPeerName)
		MeshDialErrors.Inc(m.cfg.MeshPeerName)
		return
	}

	start := time.Now()
	peerConn, err := peer.DialConn(m.cfg.Target, m.dialTimeout())
	if err != nil {
		m.logger.Error("mesh: dial peer failed", "peer", m.cfg.MeshPeerName, "target", m.cfg.Target, "error", err)
		MeshDialErrors.Inc(m.cfg.MeshPeerName)
		return
	}
	defer peerConn.Close()

	// W03: Mesh forwarding can also block on idle connections; Stop() must disconnect both directions.
	meshWatch := make(chan struct{})
	defer close(meshWatch)
	go func() {
		select {
		case <-m.stopCh:
			conn.Close()
			peerConn.Close()
		case <-meshWatch:
		}
	}()

	// W05: Mesh forwarding also applies activity-refreshed idle timeout (one-shot SetDeadline is semantically wrong).
	if idleTimeout > 0 {
		incoming = &idleConn{Conn: incoming, idle: idleTimeout}
		peerConn = &idleConn{Conn: peerConn, idle: idleTimeout}
	}

	MeshConnectionsActive.Add(1, m.cfg.MeshPeerName)
	defer MeshConnectionsActive.Add(-1, m.cfg.MeshPeerName)

	m.logger.Info("mesh: forwarding", "peer", m.cfg.MeshPeerName, "target", m.cfg.Target, "src", host)

	var wg sync.WaitGroup
	wg.Add(2)
	// W06: Half-close (CloseWrite) instead of full close, avoiding truncation of remaining peer response.
	go func() {
		defer wg.Done()
		io.Copy(peerConn, incoming)
		halfCloseWrite(peerConn)
	}()
	go func() {
		defer wg.Done()
		io.Copy(incoming, peerConn)
		halfCloseWrite(incoming)
	}()
	wg.Wait()

	ConnectionDuration.Observe(time.Since(start).Seconds(), m.cfg.Name)
}

func (m *Mapping) getCert(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := m.serverCert.Load(); c != nil {
		return c.(*tls.Certificate), nil
	}
	return nil, nil
}

// UpdateCert hot-swaps the mapping's server TLS certificate without interruption.
func (m *Mapping) UpdateCert(cert *tls.Certificate) {
	m.serverCert.Store(cert)
}

func (m *Mapping) healthCheckLoop() {
	interval := m.cfg.HealthCheckInterval()
	if interval <= 0 {
		return
	}

	useHTTP := m.cfg.HealthCheckURL() != ""

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	client := &http.Client{Timeout: 5 * time.Second}

	for {
		select {
		case <-ticker.C:
			var err error
			if useHTTP {
				var resp *http.Response
				resp, err = client.Get(m.cfg.HealthCheckURL())
				if err == nil {
					resp.Body.Close()
					if resp.StatusCode >= 500 {
						err = fmt.Errorf("HTTP %d", resp.StatusCode)
					}
				}
			} else {
				var conn net.Conn
				conn, err = net.DialTimeout("tcp", m.cfg.Target, m.dialTimeout())
				if err == nil {
					conn.Close()
				}
			}
			if err != nil {
				if m.healthy.Load() {
					m.logger.Warn(m.bundle.T(m.lang, "health.check_failed"), "name", m.cfg.Name, "error", err)
				}
				m.healthy.Store(false)
			} else {
				if !m.healthy.Load() {
					m.logger.Info(m.bundle.T(m.lang, "health.check_restored"), "name", m.cfg.Name)
				}
				m.healthy.Store(true)
			}
		case <-m.stopCh:
			return
		}
	}
}
