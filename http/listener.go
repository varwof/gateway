package httpgw

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"

	gw "github.com/varwof/gateway-core"
)

// Listener is the HTTP listener interface, unifying HTTP and H2C/WS/gRPC proxying.
type Listener interface {
	Start() error
	Stop() error
	Name() string
	Config() ListenerConfig
	UpdateCert(cert *tls.Certificate)
	SetLogger(logger *slog.Logger)
	SetPluginRegistry(reg *gw.PluginRegistry)
	// SetTaskRegistry injects the task lifecycle registry (A3, shared with Gateway management API).
	SetTaskRegistry(reg *gw.TaskRegistry)
	// SetConnRegistry injects the connection registry (monitoring presentation + risk disconnect linkage, shared with Gateway management API).
	SetConnRegistry(reg *gw.ConnRegistry)
	// SetRevoker injects the revoker (W22: H3/QUIC data plane conditional revocation linkage).
	SetRevoker(r *gw.Revoker)
	// SetPolicyVersionFn injects the current policy version getter function (Task 5a).
	SetPolicyVersionFn(fn func() uint64)
	// SetPolicyResolverFn injects the function that selects policy version registry by agent identifier (Task 5b).
	SetPolicyResolverFn(fn func(agentID string) (uint64, *gw.PluginRegistry))
	// SetRiskMonitor injects the high-risk behavior monitor (2026-08-15, automated monitoring presentation response).
	SetRiskMonitor(rm *gw.RiskMonitor)
	// SetCRLCache hot-swaps the CRL cache (W16: when reloading and retaining a listener, injects a cache
	// bound to the new stopCh, preventing revocation checks from becoming permanently ineffective after SIGHUP).
	SetCRLCache(cache *gw.CRLCache)
	State() ProxyState
	Conns() int64
	Addr() net.Addr
}

func (g *Gateway) newListener(cfg ListenerConfig, crlCache *gw.CRLCache, ocspCache *gw.OCSPCache, nonceCache *gw.NonceCache) (Listener, error) {
	switch cfg.Protocol {
	case ProtocolH3, ProtocolQUIC:
		return newQUICListener(cfg, crlCache, ocspCache, g.audit, g.tsa, g.stopCh, g.bundle, g.lang, nonceCache), nil
	case ProtocolHTTP1, ProtocolHTTP2, ProtocolH2C, ProtocolGRPC, ProtocolWS, ProtocolWSS:
		return NewProxyListener(cfg, crlCache, ocspCache, g.audit, g.tsa, g.stopCh, g.bundle, g.lang, g.revoker, nonceCache)
	default:
		return nil, fmt.Errorf("unsupported protocol %q", cfg.Protocol)
	}
}
