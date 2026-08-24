package udpgw

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v2"
	gw "github.com/varwof/gateway-core"
)

// UDPProxy UDP plaintext/DTLS proxy instance.
type UDPProxy struct {
	cfg    ListenerConfig
	crl    *gw.CRLCache
	ocsp   *gw.OCSPCache
	audit  *gw.AuditLogger
	tsa    *gw.TSAClient
	bundle *Bundle
	lang   string
	logger *slog.Logger
	stopCh chan struct{}

	conn     *net.UDPConn
	dtlsLn   net.Listener
	running  atomic.Bool
	activeIP int32
	usedPkts atomic.Int64
	// totalPktsWindowStart is the start of the sliding window for the total
	// packet limit (M2: prevents a permanent one-way fuse). The limit is
	// enforced only within a rolling window; once the window elapses the
	// in-window counter is reset.
	totalPktsWindowStart atomic.Int64

	// clients is a refcount of distinct active client IPs (M3: previously
	// activeIP counted in-flight packets, not clients, skewing the metric).
	clients sync.Map // map[string]int32

	mu             sync.Mutex
	rateLimit      map[string]*rateBucket
	certTracker    *gw.ConnectionTracker
	revoker        *gw.Revoker
	connRegistry   *gw.ConnRegistry
	pluginRegistry *gw.PluginRegistry
	nonceCache     *gw.NonceCache
	// policyVersion returns the current effective policy version (task 5a).
	policyVersion func() uint64
	// policyResolver selects policy version registry by Agent ID (task 5b: branch control/canary).
	policyResolver func(agentID string) (uint64, *gw.PluginRegistry)
	// riskMonitor high-risk behavior monitor (2026-08-15). When nil, the pipeline does not record violation signals.
	riskMonitor *gw.RiskMonitor
}

type rateBucket struct {
	count   int64
	resetAt time.Time
}

// NewUDPProxy creates a UDP plaintext/DTLS proxy instance.
func NewUDPProxy(cfg ListenerConfig, crl *gw.CRLCache, ocsp *gw.OCSPCache, logger *slog.Logger, audit *gw.AuditLogger, tsa *gw.TSAClient, stopCh chan struct{}, bundle *Bundle, lang string, revoker *gw.Revoker, connRegistry *gw.ConnRegistry, nonceCache *gw.NonceCache) (*UDPProxy, error) {
	if logger == nil {
		logger = slog.Default()
	}
	return &UDPProxy{
		cfg:          cfg,
		crl:          crl,
		ocsp:         ocsp,
		audit:        audit,
		tsa:          tsa,
		bundle:       bundle,
		lang:         lang,
		logger:       logger,
		stopCh:       stopCh,
		rateLimit:    make(map[string]*rateBucket),
		certTracker:  gw.NewConnectionTracker(),
		connRegistry: connRegistry,
		nonceCache:   nonceCache,
	}, nil
}

// Name returns the listener name.
func (p *UDPProxy) Name() string { return p.cfg.Name }

// Config returns the listener configuration.
func (p *UDPProxy) Config() ListenerConfig { return p.cfg }

// SetPluginRegistry sets the capability plugin registry.
func (p *UDPProxy) SetPluginRegistry(reg *gw.PluginRegistry) { p.pluginRegistry = reg }

// SetPolicyVersionFn sets the current policy version retrieval function (task 5a).
func (p *UDPProxy) SetPolicyVersionFn(fn func() uint64) { p.policyVersion = fn }

// SetPolicyResolverFn sets the function that selects policy version registry by Agent ID (task 5b).
func (p *UDPProxy) SetPolicyResolverFn(fn func(agentID string) (uint64, *gw.PluginRegistry)) {
	p.policyResolver = fn
}

// SetRiskMonitor injects the high-risk behavior monitor (2026-08-15, pipeline records signals).
func (p *UDPProxy) SetRiskMonitor(rm *gw.RiskMonitor) { p.riskMonitor = rm }

// currentPolicyVersion returns the current effective policy version (task 5a).
func (p *UDPProxy) currentPolicyVersion() uint64 {
	if p.policyVersion == nil {
		return 0
	}
	return p.policyVersion()
}

// Start starts UDP listening and forwarding.
func (p *UDPProxy) Start() error {
	if !p.running.CompareAndSwap(false, true) {
		return fmt.Errorf(p.bundle.T(p.lang, "listener.already_running"), p.cfg.Name)
	}

	switch p.cfg.effectiveMode() {
	case gw.TLSModeNone:
		addr, err := net.ResolveUDPAddr("udp", p.cfg.Listen)
		if err != nil {
			p.running.Store(false)
			return fmt.Errorf("resolve address: %w", err)
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			p.running.Store(false)
			return fmt.Errorf("listen: %w", err)
		}
		p.conn = conn
		ListenerUp.Set(1, p.cfg.Name)
		p.logger.Info(p.bundle.T(p.lang, "listener.listening"), "name", p.cfg.Name, "listen", p.cfg.Listen, "tls_mode", p.cfg.DisplayTLSMode())
		go p.serve()

	case gw.TLSModeServer, gw.TLSModeMTLS:
		if p.cfg.TLS == nil {
			p.running.Store(false)
			return fmt.Errorf("tls config required for %s mode", p.cfg.Protocol)
		}
		cert, err := loadCert(p.cfg.TLS)
		if err != nil {
			p.running.Store(false)
			return fmt.Errorf("load cert for DTLS: %w", err)
		}
		dtlsCfg := &dtls.Config{
			Certificates: []tls.Certificate{cert},
		}
		if p.cfg.CipherSuites() != nil {
			cs := buildDTLSCipherSuites(p.cfg.CipherSuites())
			if cs != nil {
				dtlsCfg.CipherSuites = cs
			}
		}

		caCert, err := gw.LoadCACert(p.cfg.TLS.CACertFile)
		if err != nil {
			p.running.Store(false)
			return fmt.Errorf("load CA cert: %w", err)
		}
		caPool := x509.NewCertPool()
		caPool.AddCert(caCert)
		// G1: pure DTLS must also enforce mutual auth — otherwise the
		// "zero-trust" gateway forwards unauthenticated traffic.
		dtlsCfg.ClientAuth = dtls.RequireAndVerifyClientCert
		dtlsCfg.ClientCAs = caPool

		addr, err := net.ResolveUDPAddr("udp", p.cfg.Listen)
		if err != nil {
			p.running.Store(false)
			return fmt.Errorf("resolve address: %w", err)
		}
		ln, err := dtls.Listen("udp", addr, dtlsCfg)
		if err != nil {
			p.running.Store(false)
			return fmt.Errorf("dtls listen: %w", err)
		}
		p.dtlsLn = ln
		ListenerUp.Set(1, p.cfg.Name)
		p.logger.Info(p.bundle.T(p.lang, "listener.listening"), "name", p.cfg.Name, "listen", p.cfg.Listen, "tls_mode", p.cfg.DisplayTLSMode())
		go p.serveDTLS()
	}

	return nil
}

// Stop stops UDP listening and forwarding (idempotent).
func (p *UDPProxy) Stop() {
	if !p.running.CompareAndSwap(true, false) {
		return
	}
	if p.conn != nil {
		p.conn.Close()
	}
	if p.dtlsLn != nil {
		p.dtlsLn.Close()
	}
	ListenerUp.Set(0, p.cfg.Name)
	p.logger.Info(p.bundle.T(p.lang, "listener.stopped"), "name", p.cfg.Name)
}

// ActiveClients returns the current active client count.
func (p *UDPProxy) ActiveClients() int {
	return p.activeClientCount()
}

func (p *UDPProxy) activeClientCount() int {
	n := 0
	p.clients.Range(func(_, _ interface{}) bool {
		n++
		return true
	})
	return n
}

func (p *UDPProxy) serve() {
	buf := make([]byte, p.cfg.MaxPacketSize)
	for {
		// Tie the serve loop to the running state (not stopCh) so a hot-reload
		// that keeps this listener unchanged does not kill its serve goroutine:
		// Reload closes g.stopCh to stop old refresh/listen goroutines, but
		// unchanged listeners must keep serving.
		if !p.running.Load() {
			return
		}

		if p.cfg.ReadTimeoutSec > 0 {
			p.conn.SetReadDeadline(time.Now().Add(time.Duration(p.cfg.ReadTimeoutSec) * time.Second))
		}

		n, src, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if p.running.Load() {
				p.logger.Warn(p.bundle.T(p.lang, "listener.serve_error"), "name", p.cfg.Name, "error", err)
			}
			return
		}

		PacketsTotal.Inc(p.cfg.Name, "received")
		activeIP := p.trackClient(src)

		data := make([]byte, n)
		copy(data, buf[:n])
		go p.handlePacket(src, data, activeIP)
	}
}

func (p *UDPProxy) trackClient(src *net.UDPAddr) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	var maxPkts int
	if maxPkts = p.cfg.MaxPktsPerIP(); maxPkts > 0 {
		key := src.String()
		bucket, exists := p.rateLimit[key]
		now := time.Now()
		if !exists || now.After(bucket.resetAt) {
			p.rateLimit[key] = &rateBucket{count: 1, resetAt: now.Add(1 * time.Second)}
		} else if bucket.count >= int64(maxPkts) {
			PacketDroppedTotal.Inc(p.cfg.Name, "rate_limit")
			return false
		} else {
			bucket.count++
		}
	}

	return true
}

// totalPktsWindowSec is the duration over which MaxTotalPkts is enforced
// (M2). After the window elapses the in-window counter resets, so the limit is
// a rolling rate cap rather than a permanent one-way fuse.
const totalPktsWindowSec = 60

func (p *UDPProxy) totalLimitReached() bool {
	if p.cfg.MaxTotalPkts() <= 0 {
		return false
	}
	now := time.Now().UnixNano()
	window := int64(totalPktsWindowSec) * int64(time.Second)
	start := p.totalPktsWindowStart.Load()
	if start == 0 {
		// Lazily initialize the window start on first use.
		if p.totalPktStartInit(now) {
			start = now
		} else {
			start = p.totalPktsWindowStart.Load()
		}
	}
	if now-start >= window {
		// Window elapsed: roll it forward and reset the in-window counter so a
		// past burst does not permanently fuse the listener.
		if p.totalPktsWindowStart.CompareAndSwap(start, now) {
			p.usedPkts.Store(0)
		}
		return false
	}
	return p.usedPkts.Load() >= int64(p.cfg.MaxTotalPkts())
}

// totalPktStartInit lazily initializes the rolling-window start on first use.
func (p *UDPProxy) totalPktStartInit(now int64) bool {
	return p.totalPktsWindowStart.CompareAndSwap(0, now)
}

// countPacket atomically increments the in-window packet counter, but only if
// the rolling-window limit has not been reached. It uses a CAS loop so
// concurrent callers cannot overshoot the cap (M2: previously a check-then-add
// TOCTOU allowed usedPkts to exceed MaxTotalPkts). Returns true if the packet
// is allowed.
func (p *UDPProxy) countPacket() bool {
	if p.cfg.MaxTotalPkts() <= 0 {
		return true
	}
	now := time.Now().UnixNano()
	window := int64(totalPktsWindowSec) * int64(time.Second)
	for {
		start := p.totalPktsWindowStart.Load()
		if start == 0 {
			if !p.totalPktStartInit(now) {
				continue
			}
			start = now
		}
		if now-start >= window {
			if p.totalPktsWindowStart.CompareAndSwap(start, now) {
				p.usedPkts.Store(0)
			}
			continue
		}
		cur := p.usedPkts.Load()
		if cur >= int64(p.cfg.MaxTotalPkts()) {
			return false
		}
		if p.usedPkts.CompareAndSwap(cur, cur+1) {
			return true
		}
		// Another goroutine mutated the counter; retry.
	}
}

func (p *UDPProxy) handlePacket(src *net.UDPAddr, data []byte, allowed bool) {
	if !allowed {
		return
	}

	if !p.countPacket() {
		PacketDroppedTotal.Inc(p.cfg.Name, "total_limit")
		return
	}

	start := time.Now()
	// M3: count distinct active clients by IP, not in-flight packets.
	key := src.String()
	val, _ := p.clients.LoadOrStore(key, int32(0))
	p.clients.Store(key, val.(int32)+1)
	defer func() {
		v, _ := p.clients.Load(key)
		if v.(int32) <= 1 {
			p.clients.Delete(key)
		} else {
			p.clients.Store(key, v.(int32)-1)
		}
	}()
	ActiveClients.Set(int64(p.activeClientCount()), p.cfg.Name)

	target := p.selectTarget(src.String())
	if target == "" {
		PacketDroppedTotal.Inc(p.cfg.Name, "no_route")
		return
	}

	remote, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		PacketDroppedTotal.Inc(p.cfg.Name, "resolve")
		return
	}

	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		PacketDroppedTotal.Inc(p.cfg.Name, "connect")
		return
	}
	defer conn.Close()

	if _, err := conn.Write(data); err != nil {
		PacketDroppedTotal.Inc(p.cfg.Name, "write")
		return
	}

	resp := make([]byte, p.cfg.MaxPacketSize)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(resp)
	if err != nil {
		PacketDroppedTotal.Inc(p.cfg.Name, "read_response")
		return
	}

	if _, err := p.conn.WriteToUDP(resp[:n], src); err != nil {
		PacketDroppedTotal.Inc(p.cfg.Name, "write_response")
		return
	}

	ProxyLatency.Observe(time.Since(start).Seconds(), p.cfg.Name, p.cfg.DisplayTLSMode())
	PacketsTotal.Inc(p.cfg.Name, "forwarded")
}

func (p *UDPProxy) serveDTLS() {
	for {
		conn, err := p.dtlsLn.Accept()
		if err != nil {
			if p.running.Load() {
				p.logger.Warn(p.bundle.T(p.lang, "listener.serve_error"), "name", p.cfg.Name, "error", err)
			}
			return
		}
		ConnectionsAccepted.Inc(p.cfg.Name)
		PacketsTotal.Inc(p.cfg.Name, "dtls_accept")
		go p.handleDTLSConn(conn)
	}
}

func (p *UDPProxy) handleDTLSConn(dtlsConn net.Conn) {
	defer dtlsConn.Close()

	start := time.Now()
	var certSerial string

	if p.cfg.ReadTimeoutSec > 0 {
		dtlsConn.SetReadDeadline(time.Now().Add(time.Duration(p.cfg.ReadTimeoutSec) * time.Second))
	}

	buf := make([]byte, p.cfg.MaxPacketSize)
	n, err := dtlsConn.Read(buf)
	if err != nil {
		PacketDroppedTotal.Inc(p.cfg.Name, "dtls_read")
		return
	}
	firstData := make([]byte, n)
	copy(firstData, buf[:n])

	if p.cfg.effectiveMode() == gw.TLSModeMTLS || p.cfg.effectiveMode() == gw.TLSModeServer {
		state := dtlsConn.(*dtls.Conn).ConnectionState()
		if len(state.PeerCertificates) == 0 {
			return
		}
		chain := make([]*x509.Certificate, len(state.PeerCertificates))
		for i, raw := range state.PeerCertificates {
			chain[i], err = x509.ParseCertificate(raw)
			if err != nil {
				return
			}
		}
		clientCert := chain[0]
		clientIP, _, _ := net.SplitHostPort(dtlsConn.RemoteAddr().String())

		// Unified admission pipeline: CRL → OCSP → RBAC → AIC/GS → Plugins
		result := gw.RunAccessPipeline(chain, &gw.PipelineConfig{
			CRLCache:                 p.crl,
			OCSPCache:                p.ocsp,
			AllowRoles:               p.cfg.AllowRoles(),
			CheckScope:               gw.CheckFullChain,
			RequireAIC:               p.cfg.RequireAICEnabled(),
			RequireSPIFFE:            p.cfg.TLS.RequireSPIFFEEnabled(),
			AllowedSPIFFEIDs:         p.cfg.TLS.AllowedSPIFFEIDs,
			SPIFFETrustDomain:        p.cfg.TLS.SPIFFETrustDomain,
			DisallowRepresentative:   p.cfg.DisallowRepresentativeEnabled(),
			RequireUserAuth:          p.cfg.RequireUserAuthEnabled(),
			RequiredCapabilities:     p.cfg.RequiredCapabilities(),
			ClientIP:                 clientIP,
			EnforceConstraints:       true,
			StrictConstraints:        true,
			CapabilityPluginRegistry: p.pluginRegistry,
			CapabilityPluginResolver: p.policyResolver,
			PolicyVersion:            p.currentPolicyVersion(),
			AuditLogger:              p.audit,
			NonceCache:               p.nonceCache,
			RiskMonitor:              p.riskMonitor,
			// G2(b): When OCSP fallback is allow (fail-open), enforce offline certificate lifetime ≤1h.
			OfflineMaxCertLifetime: gw.OfflineLifetimeFor(p.cfg.OCSPFallback()),
		})
		if !result.Granted {
			if p.audit != nil {
				entry := gw.NewAuditEntryDenied(dtlsConn.RemoteAddr().String(), p.cfg.Name, "",
					result.DenyReason, clientCert)
				p.audit.Log(entry)
			}
			return
		}

		// Delegated-Agent check
		if reason := gw.CheckDelegatedAgentCert(clientCert, result.GatewaySession); reason != "" {
			if p.audit != nil {
				entry := gw.NewAuditEntryDenied(dtlsConn.RemoteAddr().String(), p.cfg.Name, "", reason, clientCert)
				p.audit.Log(entry)
			}
			return
		}

		certSerial = result.Serial
		if !p.certTracker.Add(certSerial, int64(p.cfg.MaxConnsPerCert())) {
			if p.audit != nil {
				entry := gw.NewAuditEntryDenied(dtlsConn.RemoteAddr().String(), p.cfg.Name, "", "per-cert connection limit exceeded", clientCert)
				p.audit.Log(entry)
			}
			return
		}
		defer p.certTracker.Remove(certSerial)
		if p.revoker != nil {
			// P2-A-15: Connection lifecycle registered with ConnExpiryRegistry,
			// Revoker checks renewal flag on close to decide whether to skip revocation.
			if reg := p.revoker.Registry(); reg != nil && clientCert != nil {
				defer reg.Register(gw.NormalizeSerial(clientCert.SerialNumber), clientCert)()
			}
			defer p.revoker.RevokeClientCert(clientCert, p.audit)
		}
		// B03 — DTLS cert expiry monitor.
		// G2(a): Short-lived certificates (including AIC) enforce "connection duration ≤ remaining certificate lifetime", cannot be
		// disabled by disconnect_on_expiry (otherwise a 5-minute cert connection could stay open for 5 days);
		// non-AIC long-lived identity certificates retain original config gating.
		if gw.HasAIC(clientCert) || p.cfg.DisconnectOnExpiryEnabled() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				ticker := time.NewTicker(5 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						if time.Now().After(clientCert.NotAfter) {
							if p.audit != nil {
								entry := gw.NewAuditEntryDenied(dtlsConn.RemoteAddr().String(), p.cfg.Name, "",
									"certificate expired", clientCert)
								p.audit.Log(entry)
							}
							dtlsConn.Close()
							return
						}
					case <-ctx.Done():
						return
					}
				}
			}()
		}

		// P4.2: GatewaySession enforcement
		if result.GatewaySession != nil {
			remoteAddr := dtlsConn.RemoteAddr().String()
			if len(result.GatewaySession.AllowedCIDRs) > 0 {
				host, _, _ := net.SplitHostPort(remoteAddr)
				allowed := false
				for _, cidr := range result.GatewaySession.AllowedCIDRs {
					_, cidrNet, e := net.ParseCIDR(cidr)
					if e != nil {
						continue
					}
					ip := net.ParseIP(host)
					if ip != nil && cidrNet.Contains(ip) {
						allowed = true
						break
					}
				}
				if !allowed {
					if p.audit != nil && clientCert != nil {
						entry := gw.NewAuditEntryDenied(remoteAddr, p.cfg.Name, "",
							"session CIDR not allowed", clientCert)
						p.audit.Log(entry)
					}
					dtlsConn.Close()
					return
				}
			}
			if result.GatewaySession.HardTimeoutLimit() > 0 {
				go func() {
					timer := time.NewTimer(time.Duration(result.GatewaySession.HardTimeoutLimit()) * time.Second)
					defer timer.Stop()
					select {
					case <-timer.C:
						dtlsConn.Close()
					case <-p.stopCh:
					}
				}()
			}
			if p.connRegistry != nil && clientCert != nil {
				aic, _ := gw.ParseAIC(clientCert)
				agentId := ""
				principalUid := ""
				if aic != nil {
					agentId = aic.AgentId
					principalUid = aic.PrincipalUid.String()
				}
				remove := p.connRegistry.RegisterConn(agentId, principalUid, remoteAddr, "dtls", gw.NormalizeSerial(clientCert.SerialNumber), func() {
					dtlsConn.Close()
				})
				go func() {
					<-p.stopCh
					remove()
				}()
			}
		}

		if p.audit != nil {
			entry := gw.NewAuditEntryFromConn(dtlsConn.RemoteAddr().String(), p.cfg.Name, "", clientCert)
			entry.Action = string(gw.ActionConnected)
			entry.SetV12Fields("dtls", p.cfg.Name, "", "", "allow")
			p.audit.Log(entry)
		}
	}

	if p.totalLimitReached() {
		PacketDroppedTotal.Inc(p.cfg.Name, "total_limit")
		return
	}

	remoteAddr := dtlsConn.RemoteAddr().(*net.UDPAddr)
	if !p.trackClient(remoteAddr) {
		PacketDroppedTotal.Inc(p.cfg.Name, "rate_limit")
		return
	}

	target := p.selectTarget(dtlsConn.RemoteAddr().String())
	if target == "" {
		PacketDroppedTotal.Inc(p.cfg.Name, "no_route")
		return
	}

	remote, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		PacketDroppedTotal.Inc(p.cfg.Name, "resolve")
		return
	}

	backend, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		PacketDroppedTotal.Inc(p.cfg.Name, "connect")
		return
	}
	defer backend.Close()

	if _, err := backend.Write(firstData); err != nil {
		PacketDroppedTotal.Inc(p.cfg.Name, "write")
		return
	}

	readBuf := make([]byte, p.cfg.MaxPacketSize)
	backend.SetReadDeadline(time.Now().Add(5 * time.Second))
	m, err := backend.Read(readBuf)
	if err != nil {
		PacketDroppedTotal.Inc(p.cfg.Name, "read_response")
		return
	}

	dtlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := dtlsConn.Write(readBuf[:m]); err != nil {
		PacketDroppedTotal.Inc(p.cfg.Name, "write_response")
		return
	}

	// Stay alive for more request-response cycles on this DTLS connection
	if p.cfg.ReadTimeoutSec > 0 {
		for {
			dtlsConn.SetReadDeadline(time.Now().Add(time.Duration(p.cfg.ReadTimeoutSec) * time.Second))
			nr, rerr := dtlsConn.Read(readBuf)
			if rerr != nil {
				break
			}
			if _, werr := backend.Write(readBuf[:nr]); werr != nil {
				break
			}
			backend.SetReadDeadline(time.Now().Add(5 * time.Second))
			mr, rerr := backend.Read(readBuf)
			if rerr != nil {
				break
			}
			dtlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, werr := dtlsConn.Write(readBuf[:mr]); werr != nil {
				break
			}
		}
	}

	p.usedPkts.Add(1)
	ProxyLatency.Observe(time.Since(start).Seconds(), p.cfg.Name, p.cfg.DisplayTLSMode())
	BytesToTargetTotal.Add(uint64(len(firstData)), p.cfg.Name, certSerial)
	PacketsTotal.Inc(p.cfg.Name, "forwarded")
}

func loadCert(tc *gw.TLSConfig) (tls.Certificate, error) {
	certFile, keyFile := tc.CertFile, tc.KeyFile
	if certFile == "" {
		return tls.Certificate{}, fmt.Errorf("cert_file required for DTLS")
	}
	if keyFile == "" {
		return tls.Certificate{}, fmt.Errorf("key_file required for DTLS")
	}
	return tls.LoadX509KeyPair(certFile, keyFile)
}

func buildDTLSCipherSuites(names []string) []dtls.CipherSuiteID {
	var out []dtls.CipherSuiteID
	for _, n := range names {
		switch n {
		case "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":
			out = append(out, dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
		case "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":
			out = append(out, dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
		case "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":
			out = append(out, dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
		case "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":
			out = append(out, dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
		}
	}
	return out
}

// selectTarget performs deterministic routing based on source address (not packet content).
// H5: The original implementation used data[0]^data[len-1] (fully attacker-controllable) for routing, which
// in unauthenticated plain mode could direct traffic to arbitrary backends (SSRF-like).
// Changed to source IP hash-based routing, stable and not manipulable by
// individual packet content.
func (p *UDPProxy) selectTarget(srcKey string) string {
	if len(p.cfg.Routes) == 0 {
		return ""
	}

	if len(p.cfg.Routes) == 1 {
		return p.cfg.Routes[0].Target
	}

	var h uint32
	for i := 0; i < len(srcKey); i++ {
		h = h*31 + uint32(srcKey[i])
	}
	idx := int(h % uint32(len(p.cfg.Routes)))
	return p.cfg.Routes[idx].Target
}
