# gateway-tcp Features

## Exported Types

```go
type Config struct {
    Locale            string            `json:"locale,omitempty"`
    Mappings          []MappingConfig   `json:"mappings"`
    Tunnels           []TunnelConfig    `json:"tunnels,omitempty"`
    Management        *ManagementConfig `json:"management,omitempty"`
    Peers             []MeshPeerConfig  `json:"peers,omitempty"`
    MeshListen        string            `json:"mesh_listen,omitempty"`
    ShortLived        *gw.IssueConfig   `json:"short_lived,omitempty"`
    VarwofCore        *gw.RevokerConfig `json:"varwof_core,omitempty"`
    CapabilityPlugins gw.PluginConfigs  `json:"capability_plugins,omitempty"`
    AuthorizationFile string            `json:"authorization_file,omitempty"`
    CapabilitySchemes string            `json:"capability_schemes,omitempty"`
    TSAProofFile      string            `json:"tsa_proof_file,omitempty"`
    TSAProofIntervalSec int             `json:"tsa_proof_interval_sec,omitempty"`
}

type MappingConfig struct {
    Name        string         `json:"name"`
    Listen      string         `json:"listen"`
    Target      string         `json:"target"`
    Protocol    string         `json:"protocol"`
    TLS         *gw.TLSConfig  `json:"tls,omitempty"`
    TCPExt      *gw.TCPExtra   `json:"tcp_ext,omitempty"`
    MeshPeerName string        `json:"mesh_peer,omitempty"`
}

type TLSConfig = gw.TLSConfig

type TCPExtra = gw.TCPExtra

type TunnelConfig struct {
    Name        string `json:"name"`
    Listen      string `json:"listen"`
    GatewayAddr string `json:"gateway_addr"`
    CertFile    string `json:"cert_file"`
    KeyFile     string `json:"key_file"`
    CACertFile  string `json:"ca_cert_file"`
}

type ManagementConfig struct {
    Listen string      `json:"listen"`
    TLS    *gw.TLSConfig `json:"tls"`
}

type MeshPeerConfig struct {
    Name        string `json:"name"`
    Addr        string `json:"addr"`
    CACertFile  string `json:"ca_cert_file"`
    CertFile    string `json:"cert_file"`
    KeyFile     string `json:"key_file"`
}
```

## Exported Functions

### Configuration

```go
func LoadConfig(path string) (*Config, error)
func BuildConfigFromCLI(maps, tunnels []string, g *CLIGlobals) (*Config, error)
```

### Gateway Lifecycle

```go
func NewGateway(cfg *Config, bundle *Bundle, lang string, audit *gw.AuditLogger, tsa *gw.TSAClient, tsaProof *gw.TSAProofLogger, logger *slog.Logger) *Gateway
func (g *Gateway) Start() error
func (g *Gateway) Stop()
func (g *Gateway) Reload() error
func (g *Gateway) UpdateServerCert(cert *tls.Certificate)
```

### Mapping

```go
func NewMapping(cfg MappingConfig, crlCache *gw.CRLCache, ocspCache *gw.OCSPCache, audit *gw.AuditLogger, tsa *gw.TSAClient, bundle *Bundle, lang string, revoker *gw.Revoker, logger *slog.Logger, connRegistry *gw.ConnRegistry, nonceCache *gw.NonceCache, userCertCache *gw.UserCertCache, connExpiry *gw.ConnExpiryRegistry) (*Mapping, error)
func (m *Mapping) Start() error
func (m *Mapping) Stop() error
func (m *Mapping) State() MappingState
func (m *Mapping) Conns() int64
func (m *Mapping) Name() string
func (m *Mapping) Healthy() bool
func (m *Mapping) SetMesh(mesh *Mesh)
func (m *Mapping) UpdateCert(cert *tls.Certificate)
```

### Tunnel

```go
func NewTunnel(cfg TunnelConfig, logger *slog.Logger) (*Tunnel, error)
func (t *Tunnel) Start() error
func (t *Tunnel) Stop() error
func (t *Tunnel) State() TunnelState
func (t *Tunnel) Conns() int64
func (t *Tunnel) Name() string
```

### Mesh

```go
func NewMesh(peers []MeshPeerConfig, logger *slog.Logger) *Mesh
func (m *Mesh) Peer(name string) *meshPeer
func (m *Mesh) Peers() []string
func (p *meshPeer) DialConn(target string, timeout time.Duration) (net.Conn, error)
func HandlePeerRequest(peerConn net.Conn, logger *slog.Logger)
```

### i18n

```go
func NewBundle() *Bundle
func (b *Bundle) T(lang, key string, args ...any) string
func (b *Bundle) Ef(lang, key string, args ...any) error
func DetectLang(cliLang, cfgLocale, envLang string) string
```

## State Machine

```
mapping:  stopped → running → unhealthy → running
          stopped ← stopped (Stop from any state)

tunnel:   stopped → running → failed
          stopped ← stopped (Stop from any state)
```

## Connection Handling Flow

```
1. Rate limit check (per-IP + global)
2. Increment counters
3. Start goroutine
4. Hard timeout setup (MaxConnectionDurationSec)
5. Backend health check
6. Idle timeout setup
7. mesh mode? → handleMesh() → peer.DialConn() → bidirectional proxying
7a. Inbound mesh listener (W01/W02 fix, 2026-08-16): when `mesh_server_tls` is configured, uses an mTLS server handshake (requires the peer certificate; unauthenticated raw TCP connections fail at handshake); forwarding targets are validated against the `mesh_allowed_targets` whitelist (when empty, defaults to loopback + RFC1918/ULA private networks only, eliminating public SSRF); rejections are counted as `MeshTargetRejected`
8. mTLS mode:
   a. TLS handshake
   b. Extract client certificate
   c. Session delegation (RequireDelegation)
   d. RunAccessPipeline: CRL → OCSP → RBAC → AIC → constraint enforcement → plugins
   d1. Authorization constraint enforcement (G1, 2026-08-16): authorizationConstraints embedded in the AIC/PA (allowed-cidr / time-window / geo-fence / max-concurrent) are enforced by the gateway at handshake (`EnforceConstraints`/`StrictConstraints` always true); unknown constraint types fail closed (strict); time windows/CIDRs/geo-fences signed into certificates are no longer merely decorative at runtime
   d2. Periodic constraint re-check for long-lived connections (G3, 2026-08-16): the TCP data plane consists of pass-through long-lived connections, and constraints are checked only once at handshake — time-decaying constraints such as time-window are not re-checked after their window passes (e.g. a night-window connection still alive during the day). After configuring `constraint_recheck_sec`, AIC + PA authorizationConstraints are re-evaluated at that interval; violations disconnect the connection and record a `constraint recheck violation` audit entry
   e. Per-cert connection limit
   f. Expiry disconnect (DisconnectOnExpiry)
   f1. Forced expiry disconnect (G2(a), 2026-08-16): short-lived certificates containing an AIC force "connection duration ≤ certificate remaining validity"; this cannot be disabled with `disconnect_on_expiry=false` (otherwise a connection on a 5-minute certificate could stay open for 5 days); non-AIC long-lived identity certificates retain the configuration gate
   f2. Offline-mode validity cap (G2(b), 2026-08-16): with `ocsp_fallback:"allow"` (fail-open), the pipeline forces certificate remaining validity ≤1h and rejects beyond that
   g. ConnRegistry registration (for the force-disconnect API)
   h. GatewaySession enforcement (AllowedCIDRs, HardTimeout)
   i. Certificate expiry monitor goroutine
9. Dial backend (10s timeout)
10. Bidirectional io.Copy (two goroutines + done channel)
11. Audit logging (connected → disconnected)
12. Update metrics
13. Cleanup: close connection, decrement counters, unregister
```

## Predefined Metrics

| Variable | Prometheus Name | Labels |
|------|--------------|------|
| `ConnectionsActive` | `pki_gateway_mapping_connections_active` | mapping |
| `ConnectionsTotal` | `pki_gateway_mapping_connections_total` | mapping |
| `ConnectionDuration` | `pki_gateway_mapping_connection_duration_seconds` | mapping |
| `MappingUp` | `pki_gateway_mapping_up` | mapping |
| `ConnectionsAccepted` | `pki_gateway_mapping_connections_accepted_total` | mapping |
| `MeshRequestsReceived` | `pki_gateway_mesh_requests_received_total` | — |
| `MeshConnectionsActive` | `pki_gateway_mesh_connections_active` | peer |
| `MeshDialErrors` | `pki_gateway_mesh_dial_errors_total` | peer |
| `MeshTargetRejected` | `pki_gateway_mesh_target_rejected_total` | — |

`ConnectionDuration` histogram buckets: 0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60, 300, 3600 seconds

> Note (2026-08-16, W25 alignment): `BytesToTargetTotal`/`BytesToClientTotal` have been removed — the `cert_serial` label is high-cardinality (one series per certificate, growing with issuance), and byte counts are already recorded in audit entry `BytesIn`/`BytesOut`. Removed on both the TCP and HTTP sides for consistency.

## Monitoring Presentation and Risk Closed Loop (2026-08-15)

New management APIs (shared lib endpoints):

| Endpoint | Method | Roles | Description |
|------|------|------|------|
| `/api/v1/gateway/audit/search` | GET | audit/admin | Audit full-text search (requires `audit_index_file`) |
| `/api/v1/gateway/connections` | GET | ops/admin | Real-time connection details |
| `/api/v1/gateway/access-points` | GET | ops/admin | IP access points (aggregated by source IP) |
| `/api/v1/gateway/agents` | GET | ops/admin | Agent directory real-time status |
| `/api/v1/gateway/audit/chain` | GET | audit/admin | Cross-gateway audit chain DAG references (local chain heads + peer gateway chain references) |

Configuration options: `audit_index_file` (enables audit search), `risk_monitor` (behavior violation → kick + revoke closed loop). The pipeline automatically records violation signals at behavior-level rejection points (`plugin_deny` / `parameter_overflow` / `out_of_cidr`); once a rule threshold is reached, it executes `disconnect` (kick) or `revoke` (kick + conditional revocation), and the action event is written to the audit log with the `risk_action` action. Data-plane connection registration includes srcIP/protocol/serial metadata, enabling linkage between connection monitoring and risk-based kicks/revocations.

## Cross-Gateway Audit Chain DAG References (2026-08-15)

When enabled, the `chain_peers` configuration option (list of peer gateway management API base URLs) makes the gateway periodically fetch the peer's `GET /api/v1/gateway/audit/chain` chain head and write it into the local `ChainRefStore`. Each gateway's local `AuditChain` is a vertical hash chain, while recorded peer `ChainRef`s provide horizontal anchoring: verification checks that the peer's self-published chain head matches the local reference and that advancing batches satisfy `previous == locally recorded root` (chain continuity); any unilateral tampering breaks reference consistency — a consensus-free cross-gateway audit evidence DAG. Combined with Merkle audit proofs (`/audit/verify`), cross-gateway chains can be cross-verified.
