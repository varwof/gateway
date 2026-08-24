# gateway-tcp 功能特性

## 导出类型

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

## 导出函数

### 配置

```go
func LoadConfig(path string) (*Config, error)
func BuildConfigFromCLI(maps, tunnels []string, g *CLIGlobals) (*Config, error)
```

### Gateway 生命周期

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

## 状态机

```
mapping:  stopped → running → unhealthy → running
          stopped ← stopped (Stop from any state)

tunnel:   stopped → running → failed
          stopped ← stopped (Stop from any state)
```

## 连接处理流程

```
1. 速率限制检查 (per-IP + 全局)
2. 递增计数器
3. 启动 goroutine
4. 硬超时设置 (MaxConnectionDurationSec)
5. 后端健康检查
6. 空闲超时设置
7. mesh 模式? → handleMesh() → peer.DialConn() → 双向代理
7a. 入站 mesh listener（W01/W02 修复，2026-08-16）：配置 `mesh_server_tls` 时用 mTLS 服务端握手（要求对端 peer 证书，未认证的裸 TCP 连接握手即失败）；转发目标经 `mesh_allowed_targets` 白名单校验（空则默认仅回环 + RFC1918/ULA 私网，杜绝公网 SSRF），拒绝计 `MeshTargetRejected`
8. mTLS 模式:
   a. TLS 握手
   b. 提取客户端证书
   c. 会话委托 (RequireDelegation)
   d. RunAccessPipeline: CRL → OCSP → RBAC → AIC → 约束执行 → 插件
   d1. 授权约束强制执行（G1，2026-08-16）：AIC/PA 内嵌 authorizationConstraints（allowed-cidr / time-window / geo-fence / max-concurrent）在握手时由网关强制执行（`EnforceConstraints`/`StrictConstraints` 恒为 true）；未知约束类型 fail-closed（strict），证书内签的时间窗/CIDR/地理围栏运行时不再纸面化
   d2. 长连接约束周期复查（G3，2026-08-16）：TCP 数据面为透传长连接，约束仅在握手时查一次——time-window 等随时间失效的约束跨窗后不复查（如夜间窗口连接白天仍活跃）。配置 `constraint_recheck_sec` 后按该间隔重新评估 AIC + PA 的 authorizationConstraints，违规即断开连接并记录 `constraint recheck violation` 审计
   e. per-cert 连接限制
   f. 过期断开 (DisconnectOnExpiry)
   f1. 强制过期断开（G2(a)，2026-08-16）：含 AIC 的短时证书强制"连接时长 ≤ 证书剩余有效期"，`disconnect_on_expiry=false` 不可关闭（否则 5 分钟证书的连接可开 5 天）；非 AIC 长身份证书保留配置门控
   f2. 离线模式有效期上限（G2(b)，2026-08-16）：`ocsp_fallback:"allow"`（fail-open）时管线强制证书剩余有效期 ≤1h，超限拒绝
   g. ConnRegistry 注册 (用于强制断开 API)
   h. GatewaySession 执行 (AllowedCIDRs, HardTimeout)
   i. 证书过期监控 goroutine
9. 拨号后端 (10s 超时)
10. 双向 io.Copy (两个 goroutine + done channel)
11. 审计日志 (connected → disconnected)
12. 更新指标
13. 清理: 关闭连接, 减少计数, 注销
```

## 预定义指标

| 变量 | Prometheus 名 | 标签 |
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

`ConnectionDuration` 直方图桶：0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60, 300, 3600 秒

> 注（2026-08-16，W25 对齐）：`BytesToTargetTotal`/`BytesToClientTotal` 已移除——`cert_serial` 标签高基数（每证书一个序列，随签发增长），且字节量已记录在审计条目 `BytesIn`/`BytesOut`。TCP 与 HTTP 侧一并删除，保持一致。

## 监控呈现与风险闭环（2026-08-15）

新增管理 API（共享 lib 端点）：

| 端点 | 方法 | 角色 | 说明 |
|------|------|------|------|
| `/api/v1/gateway/audit/search` | GET | audit/admin | 审计全文检索（需 `audit_index_file`） |
| `/api/v1/gateway/connections` | GET | ops/admin | 实时连接明细 |
| `/api/v1/gateway/access-points` | GET | ops/admin | IP 接入点（按来源 IP 聚合） |
| `/api/v1/gateway/agents` | GET | ops/admin | Agent 目录实时状态 |
| `/api/v1/gateway/audit/chain` | GET | audit/admin | 跨网关审计链 DAG 引用（本地链头 + 对等网关链引用） |

配置项：`audit_index_file`（启用审计检索）、`risk_monitor`（行为违规 → 踢线 + 吊销闭环）。管线在行为级拒绝点（`plugin_deny` / `parameter_overflow` / `out_of_cidr`）自动记录违规信号，达到规则阈值后执行 `disconnect`（踢线）或 `revoke`（踢线 + 条件性吊销），处置事件以 `risk_action` 动作写入审计。数据面连接注册包含 srcIP/protocol/serial 元数据，使连接监控与风险踢线/吊销联动生效。

## 跨网关审计链 DAG 引用（2026-08-15）

`chain_peers` 配置项（对等网关管理 API 基址列表）启用后，网关周期性拉取对端 `GET /api/v1/gateway/audit/chain` 链头写入本地 `ChainRefStore`。各网关本地 `AuditChain` 为纵向哈希链，对端记录的 `ChainRef` 构成横向锚定：验证时核对对端自我暴露链头与本地引用一致，推进批次校验 `previous == 本地记录 root`（链连续），任何单方篡改都会破坏引用一致性——免共识排序的跨网关审计证据 DAG。配合 Merkle 审计证明（`/audit/verify`）可实现跨网关链交叉验证。
