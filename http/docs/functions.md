# gateway-http 功能特性

## 导出类型

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

type TLSConfig struct { /* gw.TLSConfig — 统一 TLS/mTLS 块，见 config.md */ }
type HTTPExtra struct { /* gw.HTTPExtra — http_ext 块，见 config.md */ }
type MgmtConfig struct { Listen string; TLS *gw.TLSConfig }
```

## 导出函数

### 配置

```go
func LoadConfig(path string) (*Config, error)
func BuildConfigFromCLI(listeners, routes []string, g *CLIGlobals) (*Config, error)
```

### Gateway 生命周期

```go
func NewGateway(cfg *Config, bundle *Bundle, lang string, audit *gw.AuditLogger, tsa *gw.TSAClient, tsaProof *gw.TSAProofLogger, logger *slog.Logger) *Gateway
func (g *Gateway) Start() error
func (g *Gateway) Stop()
func (g *Gateway) Reload() error
func (g *Gateway) UpdateServerCert(cert *tls.Certificate)
```

### Listener 接口

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
// ... 同 Listener 接口
```

**W22（2026-08-16）：H3/QUIC 监听器全面对齐 HTTP proxy（不再二等公民）**
- H3 请求路径与 `handleRequest` 同构：可信身份头剥离（W19）、per-IP（ConnContext 按 QUIC 连接计数，W21 语义）/per-cert/total 连接限制、DisconnectOnExpiry、revoker/ConnExpiryRegistry/task 生命周期注册、每请求 completed 审计 + `HTTPRequestsTotal`/`HTTPRequestDuration` 指标、AllowMethods/AllowRoles fail-closed、no_route 审计
- QUIC tunnel 连接路径补 total 限制、证书过期断开、revoker/ConnExpiryRegistry 注册
- `proxyToBackend` 重写：target 支持 `http://host:port` / `https://host:port` / 裸 `host:port`，HTTPS 后端可配 `upstream_tls`（自定义 CA + mTLS 回连）

## 请求处理流程

```
0. 可信身份头剥离（W19，2026-08-16）：X-Client-Cert-* / X-Agent-TTL 由客户端提交的一律无条件删除，仅在服务端断言路径（Delegated-Agent + 证书透传）重新注入真实值；X-AIC-Task-* 是网关自消费控制头（任务注册/完成信号），保留到管线读取后、转发前删除——杜绝伪造身份头透传到后端
0a. per-IP 连接级限制（W21，2026-08-16）：max_conns_per_ip 按底层 TCP 连接计数（ConnState New/Closed），HTTP/1.1 keep-alive 与 HTTP/2 多路复用下单连接多请求不重复计数
1. per-IP 速率限制
2. 全局连接限制
3. mTLS 客户端证书提取
4. 会话验证 (RequireDelegation + X-Session-ID)
5. 路由预匹配 (能力确定)
6. 自动能力推导 (CapabilityScheme → HTTP method → capability ID)
7. RunAccessPipeline: CRL → OCSP → RBAC → AIC → 约束执行 → 插件
7a. 授权约束强制执行（G1，2026-08-16）：AIC/PA 内嵌 authorizationConstraints（allowed-cidr / time-window / geo-fence / max-concurrent）每请求由网关强制执行（`EnforceConstraints`/`StrictConstraints` 恒为 true）；未知约束类型 fail-closed（strict），证书内签的时间窗/CIDR/地理围栏运行时不再纸面化
8. 委托 Agent 身份 (X-Client-Cert-DER + X-Client-Cert-{SPKI-Hash,Serial,CN,Principal,Agent-ID}, X-Agent-TTL) — 证书透传（B2），已废弃的 X-Agent-User 用户名路径（B1）不再注入
9. per-cert 连接限制
10. 自动吊销短命证书
11. GatewaySession 执行 (CIDR + 硬超时)
12. 路由匹配 (最长前缀)
13. 方法白名单检查
14. RBAC 角色检查 (fail-closed)
15. 证书过期检查 — G2(a)：含 AIC 短时证书强制（`disconnect_on_expiry=false` 不可关闭）+ 离线模式（`ocsp_fallback:"allow"`）强制剩余有效期 ≤1h（G2(b)）；任务完成吊销走 Forced（G2(c)，不被续期标记放行）
16. 转发客户端证书 Header
17. AIC Header 注入
18. WebSocket/gRPC 检测 → 委托
19. httputil.ReverseProxy 转发（后端 ResponseHeaderTimeout 30s 兜底，W17；upstream_tls 自定义 CA + 客户端证书回连 HTTPS 后端，W18）
20. 审计日志 + 指标
```

## 预定义指标

| 变量 | Prometheus 名 | 标签 |
|------|--------------|------|
| `HTTPRequestsTotal` | `pki_gateway_http_requests_total` | listener, route, method, status |
| `HTTPRequestDuration` | `pki_gateway_http_request_duration_seconds` | listener, route |
| `WSConnectionsActive` | `pki_gateway_http_ws_connections_active` | listener |
| `WSConnectionsTotal` | `pki_gateway_http_ws_connections_total` | listener |
| `ListenerUp` | `pki_gateway_http_up` | listener |
| `ConnectionsAccepted` | `pki_gateway_http_connections_accepted_total` | listener |

> 注（W25，2026-08-16）：`BytesToTargetTotal`/`BytesToClientTotal` 已移除——它们从不递增，且 `cert_serial` label 高基数（审计"另记"亦指出）。`ConnectionsAccepted` 已通过 ConnState hook 接通（每新连接 +1）；`ListenerUp` HTTP/QUIC 路径均已置位。

`HTTPRequestDuration` 直方图桶：0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 秒

## 监控呈现与风险闭环（2026-08-15）

新增管理 API（共享 lib 端点）：

| 端点 | 方法 | 角色 | 说明 |
|------|------|------|------|
| `/api/v1/gateway/audit/search` | GET | audit/admin | 审计全文检索（需 `audit_index_file`） |
| `/api/v1/gateway/connections` | GET | ops/admin | 实时连接明细 |
| `/api/v1/gateway/access-points` | GET | ops/admin | IP 接入点（按来源 IP 聚合） |
| `/api/v1/gateway/agents` | GET | ops/admin | Agent 目录实时状态 |
| `/api/v1/gateway/audit/chain` | GET | audit/admin | 跨网关审计链 DAG 引用（本地链头 + 对等网关链引用） |

配置项：`audit_index_file`（启用审计检索）、`risk_monitor`（行为违规 → 踢线 + 吊销闭环）。管线在行为级拒绝点（`plugin_deny` / `parameter_overflow` / `out_of_cidr`）自动记录违规信号，达到规则阈值后执行 `disconnect`（踢线）或 `revoke`（踢线 + 条件性吊销），处置事件以 `risk_action` 动作写入审计。HTTP 数据面在每次 mTLS 请求通过准入后注册连接（含 srcIP/protocol/serial），使连接监控与风险踢线/吊销联动生效。

## 跨网关审计链 DAG 引用（2026-08-15）

`chain_peers` 配置项（对等网关管理 API 基址列表）启用后，网关周期性拉取对端 `GET /api/v1/gateway/audit/chain` 链头写入本地 `ChainRefStore`。各网关本地 `AuditChain` 为纵向哈希链，对端记录的 `ChainRef` 构成横向锚定：验证时核对对端自我暴露链头与本地引用一致，推进批次校验 `previous == 本地记录 root`（链连续），任何单方篡改都会破坏引用一致性——免共识排序的跨网关审计证据 DAG。配合 Merkle 审计证明（`/audit/verify`）可实现跨网关链交叉验证。
