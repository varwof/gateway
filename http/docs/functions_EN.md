# gateway-http Features

## Exported Types

```go
type Config struct {
    Locale            string            `json:"locale,omitempty"`
    Listeners         []ListenerConfig  `json:"listeners"`
    Management        *MgmtConfig       `json:"management,omitempty"`
    ShortLived        *gw.IssueConfig   `json:"short_lived,omitempty"`
    VarwofCore        *gw.RevokerConfig `json:"varwof_core,omitempty"`
    CapabilityPlugins gw.PluginConfigs  `json:"capability_plugins,omitempty"`
    AuthorizationFile string            `json:"authorization_file,omitempty"`
    CapabilitySchemes string            `json:"capability_schemes,omitempty"`
    TSAProofFile      string            `json:"tsa_proof_file,omitempty"`
    TSAProofIntervalSec int             `json:"tsa_proof_interval_sec,omitempty"`
}

type ListenerConfig struct {
    Name     string         `json:"name"`
    Listen   string         `json:"listen"`
    Protocol string         `json:"protocol,omitempty"`
    TLS      *gw.TLSConfig  `json:"tls,omitempty"`
    HTTPExt  *gw.HTTPExtra  `json:"http_ext,omitempty"`
    Routes   []RouteConfig  `json:"routes"`
}

type RouteConfig struct {
    Path                 string   `json:"path"`
    Target               string   `json:"target"`
    AllowMethods         []string `json:"allow_methods,omitempty"`
    AllowRoles           []string `json:"allow_roles,omitempty"`
    BackendProtocol      string   `json:"backend_protocol,omitempty"`
    RequiredCapabilities []string `json:"required_capabilities,omitempty"`
    CapabilityScheme     string   `json:"capability_scheme,omitempty"`
    CapabilityPrefix     string   `json:"capability_prefix,omitempty"`
}

type TLSConfig struct { /* gw.TLSConfig — unified TLS/mTLS block, see config.md */ }
type HTTPExtra struct { /* gw.HTTPExtra — http_ext block, see config.md */ }
type MgmtConfig struct { Listen string; TLS *gw.TLSConfig }
```

## Exported Functions

### Configuration

```go
func LoadConfig(path string) (*Config, error)
func BuildConfigFromCLI(listeners, routes []string, g *CLIGlobals) (*Config, error)
```

### Gateway Lifecycle

```go
func NewGateway(cfg *Config, bundle *Bundle, lang string, audit *gw.AuditLogger, tsa *gw.TSAClient, tsaProof *gw.TSAProofLogger, logger *slog.Logger) *Gateway
func (g *Gateway) Start() error
func (g *Gateway) Stop()
func (g *Gateway) Reload() error
func (g *Gateway) UpdateServerCert(cert *tls.Certificate)
```

### Listener Interface

```go
type Listener interface {
    Start() error
    Stop() error
    Name() string
    Config() ListenerConfig
    UpdateCert(cert *tls.Certificate)
    SetLogger(logger *slog.Logger)
    SetPluginRegistry(reg *gw.PluginRegistry)
    State() ProxyState
    Conns() int64
    Addr() net.Addr
}
```

### ProxyListener (HTTP/HTTPS)

```go
func NewProxyListener(cfg ListenerConfig, crlCache *gw.CRLCache, ocspCache *gw.OCSPCache, audit *gw.AuditLogger, tsa *gw.TSAClient, stopCh chan struct{}, bundle *Bundle, lang string, revoker *gw.Revoker, capEngine *gw.CapabilityEngine, nonceCache *gw.NonceCache, userCertCache *gw.UserCertCache) (*ProxyListener, error)
func (p *ProxyListener) Start() error
func (p *ProxyListener) Stop() error
func (p *ProxyListener) State() ProxyState
func (p *ProxyListener) Name() string
func (p *ProxyListener) Conns() int64
func (p *ProxyListener) Config() ListenerConfig
func (p *ProxyListener) Addr() net.Addr
func (p *ProxyListener) UpdateCert(cert *tls.Certificate)
func (p *ProxyListener) SetLogger(logger *slog.Logger)
func (p *ProxyListener) SetPluginRegistry(reg *gw.PluginRegistry)
```

### QUICListener (HTTP3/QUIC)

```go
func NewQUICListener(cfg ListenerConfig, ...) (*QUICListener, error)
func (q *QUICListener) Start() error
func (q *QUICListener) Stop() error
// ... same as the Listener interface
```

**W22 (2026-08-16): H3/QUIC listener fully aligned with the HTTP proxy (no longer a second-class citizen)**
- The H3 request path is isomorphic to `handleRequest`: trusted identity header stripping (W19), per-IP (ConnContext counted per QUIC connection, W21 semantics)/per-cert/total connection limits, DisconnectOnExpiry, revoker/ConnExpiryRegistry/task lifecycle registration, per-request completed audit + `HTTPRequestsTotal`/`HTTPRequestDuration` metrics, AllowMethods/AllowRoles fail-closed, no_route audit
- The QUIC tunnel connection path gained total connection limits, disconnect on certificate expiry, and revoker/ConnExpiryRegistry registration
- `proxyToBackend` rewritten: target supports `http://host:port` / `https://host:port` / bare `host:port`; HTTPS backends can configure `upstream_tls` (custom CA + mTLS connection)

## Request Processing Pipeline

```
0. Trusted identity header stripping (W19, 2026-08-16): X-Client-Cert-* / X-Agent-TTL submitted by clients are unconditionally removed; real values are re-injected only at the server-side assertion path (Delegated-Agent + certificate pass-through); X-AIC-Task-* are gateway-self-consumed control headers (task registration/completion signals), kept until after pipeline reads and deleted before forwarding — preventing forged identity headers from reaching the backend
0a. per-IP connection-level limit (W21, 2026-08-16): max_conns_per_ip counts underlying TCP connections (ConnState New/Closed); under HTTP/1.1 keep-alive and HTTP/2 multiplexing, multiple requests over one connection are not double-counted
1. per-IP rate limiting
2. Global connection limit
3. mTLS client certificate extraction
4. Session validation (RequireDelegation + X-Session-ID)
5. Route pre-matching (capability determination)
6. Automatic capability derivation (CapabilityScheme → HTTP method → capability ID)
7. RunAccessPipeline: CRL → OCSP → RBAC → AIC → constraint enforcement → plugins
7a. Authorization constraint enforcement (G1, 2026-08-16): authorizationConstraints embedded in AIC/PA (allowed-cidr / time-window / geo-fence / max-concurrent) are enforced by the gateway on every request (`EnforceConstraints`/`StrictConstraints` always true); unknown constraint types fail closed (strict), so time windows/CIDRs/geo-fences signed into certificates are no longer merely advisory at runtime
8. Delegated Agent identity (X-Client-Cert-DER + X-Client-Cert-{SPKI-Hash,Serial,CN,Principal,Agent-ID}, X-Agent-TTL) — certificate pass-through (B2); the deprecated X-Agent-User username path (B1) is no longer injected
9. per-cert connection limit
10. Automatic revocation of short-lived certificates
11. GatewaySession enforcement (CIDR + hard timeout)
12. Route matching (longest prefix)
13. Method allowlist check
14. RBAC role check (fail-closed)
15. Certificate expiry check — G2(a): includes mandatory enforcement for short-lived AIC certificates (cannot be disabled via `disconnect_on_expiry=false`) + offline mode (`ocsp_fallback:"allow"`) forces remaining validity ≤1h (G2(b)); task-completion revocation goes through Forced (G2(c), not bypassed by renewal marks)
16. Forward client certificate headers
17. AIC header injection
18. WebSocket/gRPC detection → delegate
19. httputil.ReverseProxy forwarding (backend ResponseHeaderTimeout 30s as a safety net, W17; upstream_tls custom CA + client certificate for HTTPS backend connections, W18)
20. Audit log + metrics
```

## Predefined Metrics

| Variable | Prometheus Name | Labels |
|------|--------------|------|
| `HTTPRequestsTotal` | `pki_gateway_http_requests_total` | listener, route, method, status |
| `HTTPRequestDuration` | `pki_gateway_http_request_duration_seconds` | listener, route |
| `WSConnectionsActive` | `pki_gateway_http_ws_connections_active` | listener |
| `WSConnectionsTotal` | `pki_gateway_http_ws_connections_total` | listener |
| `ListenerUp` | `pki_gateway_http_up` | listener |
| `ConnectionsAccepted` | `pki_gateway_http_connections_accepted_total` | listener |

> Note (W25, 2026-08-16): `BytesToTargetTotal`/`BytesToClientTotal` have been removed — they never incremented, and the `cert_serial` label has high cardinality (the audit "also noted" this). `ConnectionsAccepted` is now wired through a ConnState hook (+1 for each new connection); `ListenerUp` is set on both HTTP and QUIC paths.

`HTTPRequestDuration` histogram buckets: 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 seconds

## Monitoring Presentation and Risk Closed Loop (2026-08-15)

New management APIs (shared lib endpoints):

| Endpoint | Method | Role | Description |
|------|------|------|------|
| `/api/v1/gateway/audit/search` | GET | audit/admin | Audit full-text search (requires `audit_index_file`) |
| `/api/v1/gateway/connections` | GET | ops/admin | Real-time connection details |
| `/api/v1/gateway/access-points` | GET | ops/admin | IP access points (aggregated by source IP) |
| `/api/v1/gateway/agents` | GET | ops/admin | Real-time agent directory status |
| `/api/v1/gateway/audit/chain` | GET | audit/admin | Cross-gateway audit chain DAG references (local chain head + peer gateway chain references) |

Configuration items: `audit_index_file` (enables audit search), `risk_monitor` (behavioral violation → kick + revoke closed loop). The pipeline records violation signals at behavioral rejection points (`plugin_deny` / `parameter_overflow` / `out_of_cidr`); once a rule threshold is reached it executes `disconnect` (kick) or `revoke` (kick + conditional revocation), with handling events written to the audit log under the `risk_action` action. The HTTP data plane registers connections (including srcIP/protocol/serial) after each mTLS request passes admission, making connection monitoring effective in tandem with risk-based kicking/revocation.

## Cross-Gateway Audit Chain DAG References (2026-08-15)

When the `chain_peers` configuration item (a list of peer gateway management API base URLs) is enabled, the gateway periodically fetches the peer's `GET /api/v1/gateway/audit/chain` chain head and writes it into the local `ChainRefStore`. Each gateway's local `AuditChain` is a vertical hash chain, and the recorded peer `ChainRef`s form horizontal anchoring: during verification, the peer's self-exposed chain head is checked against the local reference, and batch verification asserts `previous == locally recorded root` (chain continuity); any unilateral tampering breaks reference consistency — a consensus-free cross-gateway audit evidence DAG. Combined with Merkle audit proofs (`/audit/verify`), cross-gateway chains can be cross-verified.
