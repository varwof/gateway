# gateway-udp Features

## Exported Types

```go
type Config struct {
    Locale            string            `json:"locale,omitempty"`
    Listeners         []ListenerConfig  `json:"listeners"`
    Management        *ManagementConfig `json:"management,omitempty"`
    VarwofCore        *gw.RevokerConfig `json:"varwof_core,omitempty"`
    ShortLived        *gw.IssueConfig   `json:"short_lived,omitempty"`
    CapabilityPlugins gw.PluginConfigs  `json:"capability_plugins,omitempty"`
    AuthorizationFile string            `json:"authorization_file,omitempty"`
    CapabilitySchemes string            `json:"capability_schemes,omitempty"`
    TSAProofFile      string            `json:"tsa_proof_file,omitempty"`
    TSAProofIntervalSec int             `json:"tsa_proof_interval_sec,omitempty"`
}

type ListenerConfig struct {
    Name           string        `json:"name"`
    Listen         string        `json:"listen"`
    Protocol       string        `json:"protocol"`
    TLS            *gw.TLSConfig `json:"tls,omitempty"`
    UDPExt         *gw.UDPExtra  `json:"udp_ext,omitempty"`
    Routes         []RouteConfig `json:"routes,omitempty"`
    ReadTimeoutSec int           `json:"read_timeout_sec,omitempty"`
    MaxPacketSize  int           `json:"max_packet_size,omitempty"`
}

type RouteConfig struct {
    Target     string   `json:"target"`
    AllowRoles []string `json:"allow_roles,omitempty"`
}

// gw.TLSConfig (gateway-core, json:"tls")
type TLSConfig struct {
    Mode                  string   `json:"mode,omitempty"` // none / server / mtls
    CACertFile            string   `json:"ca_cert_file,omitempty"`
    CertFile              string   `json:"cert_file,omitempty"`
    KeyFile               string   `json:"key_file,omitempty"`
    MinTLSVersion         string   `json:"min_tls_version,omitempty"`
    CipherSuites          []string `json:"cipher_suites,omitempty"`
    CRLURL                string   `json:"crl_url,omitempty"`
    CRLRefreshSec         int      `json:"crl_refresh_sec,omitempty"`
    OCSPCacheTTLSec       int      `json:"ocsp_cache_ttl_sec,omitempty"`
    OCSPFallback          string   `json:"ocsp_fallback,omitempty"`
    TSAURL                string   `json:"tsa_url,omitempty"`
    TSACertFile           string   `json:"tsa_cert_file,omitempty"`
    AuditFile             string   `json:"audit_file,omitempty"`
    AuditMaxSizeMB        int      `json:"audit_max_size_mb,omitempty"`
    AuditMaxBackups       int      `json:"audit_max_backups,omitempty"`
    MaxConnsPerIP         int      `json:"max_conns_per_ip,omitempty"`
    MaxConnsPerCert       int      `json:"max_conns_per_cert,omitempty"`
    MaxTotalConns         int      `json:"max_total_conns,omitempty"`
    IdleTimeoutSec        int      `json:"idle_timeout_sec,omitempty"`
    RequireAIC            *bool    `json:"require_aic,omitempty"`
    DisallowRepresentative *bool   `json:"disallow_representative,omitempty"`
    RequireUserAuth       *bool    `json:"require_user_auth,omitempty"`
    DisconnectOnExpiry    *bool    `json:"disconnect_on_expiry,omitempty"`
    AllowRoles            []string `json:"allow_roles,omitempty"`
    RequiredCapabilities  []string `json:"required_capabilities,omitempty"`
    CapabilityScheme      string   `json:"capability_scheme,omitempty"`
}

// gw.UDPExtra (gateway-core, json:"udp_ext")
type UDPExtra struct {
    RequireDelegation     *bool `json:"require_delegation,omitempty"`
    MaxPktsPerIP          int   `json:"max_pkts_per_ip,omitempty"`
    MaxTotalPkts          int   `json:"max_total_pkts,omitempty"`
    ConnectionBPS         int64 `json:"connection_bps,omitempty"`
    ConnectionBurst       int64 `json:"connection_burst,omitempty"`
    DisconnectOnExpirySec int   `json:"disconnect_on_expiry_sec,omitempty"`
}

type ManagementConfig struct {
    Listen string        `json:"listen"`
    TLS    *gw.TLSConfig `json:"tls"`
}

type Listener interface {
    Start() error
    Stop()
    Name() string
    ActiveClients() int
    Config() ListenerConfig
    SetPluginRegistry(reg *gw.PluginRegistry)
}
```

## Exported Functions

### Configuration

```go
func LoadConfig(path string) (*Config, error)
func BuildConfigFromCLI(listeners []string, g *CLIGlobals) (*Config, error)
```

### Gateway Lifecycle

```go
func NewGateway(cfg *Config, bundle *Bundle, lang string, logger *slog.Logger, audit *gw.AuditLogger, tsa *gw.TSAClient, tsaProof *gw.TSAProofLogger) *Gateway
func (g *Gateway) Start() error
func (g *Gateway) Stop()
func (g *Gateway) Reload() error
func (g *Gateway) UpdateServerCert(cert *tls.Certificate)
```

### Listener Factory

```go
func newListener(lc ListenerConfig, ...) (Listener, error)
```

Creates a `QUICProxy` (quic) or `UDPProxy` (udp/dtls/udp+mtls) based on `protocol`.

### i18n

```go
func NewBundle() *Bundle
func (b *Bundle) T(lang, key string, args ...any) string
func DetectLang(cliLang, cfgLocale, envLang string) string
```

## Connection Handling Flow

```
1. UDP ReadFrom → parse source IP
2. per-IP packet rate limit
3. Global total packet limit
4. Hash-based route distribution → select target
5. DTLS/QUIC modes:
   a. TLS handshake
   b. Extract client certificate
   c. RunAccessPipeline: CRL → OCSP → RBAC → AIC → constraint enforcement → plugins
   c1. Authorization constraint enforcement (G1, 2026-08-16): authorizationConstraints embedded in AIC/PA (allowed-cidr / time-window / geo-fence / max-concurrent) are enforced at handshake (`EnforceConstraints`/`StrictConstraints` are always true); unknown constraint types fail closed (strict)
   d. per-cert connection limit
   e. per-IP QUIC connection count limit
   f. TokenBucket byte rate limiting
   g. Certificate expiry monitoring — G2(a): short-lived certificates containing an AIC are forced to "connection duration ≤ certificate remaining validity" (`disconnect_on_expiry` cannot be disabled); G2(b): with `ocsp_fallback:"allow"` (fail-open), the pipeline forces remaining validity ≤1h
6. Forward UDP packets to target
7. Record audit log
8. Update metrics
```

## Audit Actions

| Action | Description |
|--------|------|
| `connected` | DTLS/QUIC connection established |
| `disconnected` | Connection closed |
| `denied` | RBAC/AIC denial |
| `revoked` | Certificate revoked |
| `plugin_decision` | Plugin decision |

## Configuration Validation

`validate()` checks:
- listener `name` is required
- listener `listen` is required
- listener `protocol` must be `udp`/`dtls`/`udp+mtls`/`quic`
- `udp+mtls` mode requires `tls.ca_cert_file` (`dtls`/`udp+mtls`/`quic` require `tls.cert_file` + `tls.key_file`)
- `quic` mode requires `tls.cert_file`
- route `target` is required

## Monitoring Presentation and Risk Closed Loop (2026-08-15)

New management APIs (shared lib endpoints):

| Endpoint | Method | Role | Description |
|------|------|------|------|
| `/api/v1/gateway/audit/search` | GET | audit/admin | Audit full-text search (requires `audit_index_file`) |
| `/api/v1/gateway/connections` | GET | ops/admin | Real-time connection details |
| `/api/v1/gateway/access-points` | GET | ops/admin | IP access points (aggregated by source IP) |
| `/api/v1/gateway/agents` | GET | ops/admin | Agent directory real-time status |
| `/api/v1/gateway/audit/chain` | GET | audit/admin | Cross-gateway audit chain DAG references (local chain head + peer gateway chain references) |

Configuration options: `audit_index_file` (enables audit search), `risk_monitor` (behavioral violation → kick + revoke closed loop). The pipeline automatically records violation signals at behavior-level rejection points (`plugin_deny` / `parameter_overflow` / `out_of_cidr`); once a rule threshold is reached, it executes `disconnect` (kick) or `revoke` (kick + conditional revocation), and handling events are written to the audit log with the `risk_action` action. Data-plane connection registration includes srcIP/protocol/serial metadata, enabling effective linkage between connection monitoring and risk-based kick/revoke.

## Cross-Gateway Audit Chain DAG References (2026-08-15)

When the `chain_peers` configuration option (list of peer gateway management API base URLs) is enabled, the gateway periodically fetches the peer's `GET /api/v1/gateway/audit/chain` chain head and writes it to the local `ChainRefStore`. Each gateway's local `AuditChain` forms a vertical hash chain, while recorded peer `ChainRef`s provide horizontal anchoring: during verification, the peer's self-exposed chain head is checked against the local reference, advancing batch validation with `previous == locally recorded root` (chain continuity); any unilateral tampering breaks reference consistency — a consensus-free cross-gateway audit evidence DAG. Combined with Merkle audit proofs (`/audit/verify`), cross-gateway chain cross-validation can be achieved.
