# gateway-udp 功能特性

## 导出类型

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

// gw.TLSConfig（gateway-core，json:"tls"）
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

// gw.UDPExtra（gateway-core，json:"udp_ext"）
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

## 导出函数

### 配置

```go
func LoadConfig(path string) (*Config, error)
func BuildConfigFromCLI(listeners []string, g *CLIGlobals) (*Config, error)
```

### Gateway 生命周期

```go
func NewGateway(cfg *Config, bundle *Bundle, lang string, logger *slog.Logger, audit *gw.AuditLogger, tsa *gw.TSAClient, tsaProof *gw.TSAProofLogger) *Gateway
func (g *Gateway) Start() error
func (g *Gateway) Stop()
func (g *Gateway) Reload() error
func (g *Gateway) UpdateServerCert(cert *tls.Certificate)
```

### Listener 工厂

```go
func newListener(lc ListenerConfig, ...) (Listener, error)
```

根据 `protocol` 创建 `QUICProxy`（quic）或 `UDPProxy`（udp/dtls/udp+mtls）。

### i18n

```go
func NewBundle() *Bundle
func (b *Bundle) T(lang, key string, args ...any) string
func DetectLang(cliLang, cfgLocale, envLang string) string
```

## 连接处理流程

```
1. UDP ReadFrom → 解析来源 IP
2. per-IP 包速率限制
3. 全局包总量限制
4. 哈希路由分发 → 选择目标
5. DTLS/QUIC 模式:
   a. TLS 握手
   b. 提取客户端证书
   c. RunAccessPipeline: CRL → OCSP → RBAC → AIC → 约束执行 → 插件
   c1. 授权约束强制执行（G1，2026-08-16）：AIC/PA 内嵌 authorizationConstraints（allowed-cidr / time-window / geo-fence / max-concurrent）握手时强制执行（`EnforceConstraints`/`StrictConstraints` 恒为 true）；未知约束类型 fail-closed（strict）
   d. per-cert 连接限制
   e. per-IP QUIC 连接数限制
   f. TokenBucket 字节限速
   g. 证书过期监控 — G2(a)：含 AIC 短时证书强制"连接时长 ≤ 证书剩余有效期"（`disconnect_on_expiry` 不可关闭）；G2(b)：`ocsp_fallback:"allow"`（fail-open）时管线强制剩余有效期 ≤1h
6. 转发 UDP 包到目标
7. 记录审计日志
8. 更新指标
```

## 审计动作

| Action | 说明 |
|--------|------|
| `connected` | DTLS/QUIC 连接建立 |
| `disconnected` | 连接断开 |
| `denied` | RBAC/AIC 拒绝 |
| `revoked` | 证书被吊销 |
| `plugin_decision` | 插件决策 |

## 配置校验

`validate()` 检查：
- listener `name` 必填
- listener `listen` 必填
- listener `protocol` 必须为 `udp`/`dtls`/`udp+mtls`/`quic`
- `udp+mtls` 模式需要 `tls.ca_cert_file`（`dtls`/`udp+mtls`/`quic` 需要 `tls.cert_file` + `tls.key_file`）
- `quic` 模式需要 `tls.cert_file`
- 路由 `target` 必填

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
