# gateway-http 配置参考

## 配置文件位置

| 平台 | 路径 |
|------|------|
| Linux | `/etc/varwof/gateway-http/gateway-http.json` |
| Windows | `%ProgramData%\varwof\gateway-http\gateway-http.json` |

## 顶层配置 (Config)

```json
{
  "locale": "zh",
  "listeners": [...],
  "management": {...},
  "short_lived": {...},
  "varwof_core": {...},
  "capability_plugins": {...},
  "authorization_file": "/etc/pki/authz.json",
  "policy_signing": {
    "enabled": true,
    "ca_file": "/etc/pki/issuing-ca.pem",
    "require_admin_ou": true,
    "require": false,
    "sig_suffix": ".sig"
  },
  "tsa_proof_file": "/var/log/gateway/proof.jsonl",
  "tsa_proof_interval_sec": 300
}
```

## 顶层配置字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `authorization_file` | string | 授权策略文件路径（authz.json，OU→角色映射）。加载成功后作为 RBAC 角色解析的优先来源，未配置时使用硬编码的 `gateway:` OU 前缀角色 |
| `capability_schemes` | string | 能力注册目录路径（register 规范）。**显式配置后启用数据面能力注册校验**（opt-in，向后兼容）：AIC 声明的能力必须已注册，未注册即拒绝连接（fail-closed）。目录结构 `vendor/product/v*.json`；磁盘文件覆盖同名嵌入式方案（embedded 内嵌 varwof/core、varwof/gateway、oracle/mysql、x-vendor/acme 等），改 JSON 后 SIGHUP 热重载即时生效。未配置时数据面不校验能力注册 |
| `policy_signing` | object | 策略文件 PKCS#7 签名校验配置。启用后加载 authorization_file 前先验签，签名者必须是本 PKI 签发的 admin 角色证书（OU=admin/gateway:admin），CA 链由 `ca_file`（缺省回退第一个 listener 的 `ca_cert_file`）验证。`require: true` 时签名缺失即拒绝加载 |
| `audit_index_file` | string | 审计 FTS 索引文件路径（bbolt）。设置后启用 `GET /api/v1/gateway/audit/search` 全文检索端点 |
| `risk_monitor` | object | 高风险 agent 自动处置规则。设置后启用"行为违规 → 踢线 + 吊销"响应式闭环：管线在行为级拒绝点（插件 deny / 参数越界 / CIDR 越界）自动记录违规信号，达到规则阈值后由网关执行断开（+ 吊销） |
| `chain_peers` | ChainPeerConfig[] | 否 | 跨网关审计链引用对等端点。每项为对等网关管理 API 基址（如 `https://gw2:9443`），网关周期性拉取对端 `GET /api/v1/gateway/audit/chain` 链头写入本地 `ChainRefStore`，构成跨网关审计证据 DAG（免共识排序）。字段：`name`（对等网关名称）、`url`（对等网关管理 API 基址），TLS 复用管理 API 客户端证书 |

`risk_monitor` 字段：

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `rules[].name` | string | - | 规则名（审计/日志标识） |
| `rules[].signals` | []string | - | 触发信号：`plugin_deny`、`parameter_overflow`、`out_of_cidr`；`*` 匹配全部 |
| `rules[].threshold` | int | - | 窗口内违规次数阈值，达到即触发处置 |
| `rules[].window_seconds` | int | 60 | 计数窗口（秒） |
| `rules[].action` | string | - | `disconnect`（踢线）或 `revoke`（踢线 + 条件性吊销） |
| `rules[].reason` | string | - | 处置原因（写入审计与日志） |

`policy_signing` 字段：

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `false` | 启用签名校验 |
| `ca_file` | string | 首个 listener 的 ca_cert_file | 信任的 CA 链 PEM |
| `require_admin_ou` | bool | `true` | 强制签名者为 admin OU（nil=默认 true）|
| `require` | bool | `false` | 签名缺失时：true=拒绝，false=降级警告 |
| `sig_suffix` | string | `".sig"` | 签名文件后缀 |

策略签名由 `core pki policy sign` 或 `varwof-cli policy sign` 生成（使用管理员证书）。

## ListenerConfig

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | string | **是** | 唯一监听器名称 |
| `listen` | string | **是** | 监听地址 |
| `protocol` | string | **是** | 传输+应用协议：`http1` / `http2` / `h2c` / `grpc` / `ws` / `wss` / `h3` / `quic`（见 Protocol 表） |
| `tls` | TLSConfig | 条件 | 统一 TLS/mTLS 配置块。`protocol=h3/quic` 必填（`cert_file`）；`tls.mode=mtls` 时必填（`ca_cert_file`） |
| `http_ext` | HTTPExtra | 否 | HTTP 特有扩展字段（读头/写响应超时、证书透传、TLS 终止） |
| `routes` | []RouteConfig | **是** | 至少一个路由 |

## RouteConfig

| 字段 | 类型 | 说明 |
|------|------|------|
| `path` | string | **是**。URL 路径模式（`/prefix/*` 或精确匹配） |
| `target` | string | **是**。后端地址（`http://host:port` / `https://host:port` / 裸 `host:port`，W22：QUIC/H3 路径同样支持三种形式） |
| `allow_methods` | []string | HTTP 方法白名单 |
| `allow_roles` | []string | RBAC 角色 |
| `backend_protocol` | string | `h1` / `h2` / `h2c`（默认 H2 over TLS） |
| `required_capabilities` | []string | 要求的 AIC 能力 |
| `capability_scheme` | string | 能力方案 |
| `capability_prefix` | string | 能力 ID 前缀 |
| `upstream_tls` | object | 后端回连 TLS/mTLS 配置（W18）。设置后 HTTPS 后端用自定义 CA 验证对端并携带网关客户端证书（双向认证），不再按系统根验证。字段：`ca_cert_file`（后端 CA，留空按系统根）、`cert_file`/`key_file`（网关客户端证书）、`server_name`（SNI 覆盖，留空用目标 host）、`insecure_skip_verify`（跳过后端校验，仅测试/自签内网） |

## TLSConfig

统一 TLS/mTLS 配置块（旧 `MTLSConfig` 的字段全部收纳于此），位于 listener 的 `tls` 字段内。`mode` 字段选择认证模式（`none` / `server` / `mtls`）。HTTP 特有字段已移至 `http_ext`（见 HTTPExtra）。

```json
{
  "tls": {
    "mode": "mtls",
    "ca_cert_file": "/etc/pki/ca.pem",
    "cert_file": "/etc/pki/server.pem",
    "key_file": "/etc/pki/server.key",
    "min_tls_version": "1.2",
    "cipher_suites": ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"],
    "crl_url": "http://crl.example.com/ca.crl",
    "crl_refresh_sec": 300,
    "ocsp_cache_ttl_sec": 300,
    "ocsp_fallback": "allow",
    "tsa_url": "http://tsa.example.com",
    "tsa_cert_file": "/etc/pki/tsa.pem",
    "allow_roles": ["gateway:admin", "gateway:ops"],
    "audit_file": "/var/log/gateway/audit.log",
    "audit_max_size_mb": 100,
    "audit_max_backups": 3,
    "max_conns_per_ip": 100,
    "max_conns_per_cert": 50,
    "max_total_conns": 10000,
    "idle_timeout_sec": 300,
    "disconnect_on_expiry": true,
    "require_aic": true,
    "disallow_representative": false,
    "require_user_auth": false,
    "required_capabilities": ["http:proxy"]
  }
}
```

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `mode` | string | — | TLS 认证模式：`none` / `server` / `mtls`。`protocol=h3/quic` 时缺省由 `ca_cert_file` 是否存在推导（有→`mtls`，无→`server`），其余协议缺省为 `none` |
| `ca_cert_file` | string | 必填(mtls) | CA 证书路径 |
| `jwt_ca_file` | string | — | **可选**。AIC-JWT Bearer 信任根 CA 证书路径（HTTP 专用）。设置后，未携带 mTLS 客户端证书的请求可用 `Authorization: Bearer <AIC-JWT>` 认证；mTLS 证书优先。留空禁用 Bearer 认证。kid 约定与 X.509 载体一致（`base64url(SHA-256(SPKI))`），与 core `/.well-known/jwks.json` 绑定相同 |
| `cert_file` | string | — | 服务端证书 |
| `key_file` | string | — | 服务端私钥 |
| `crl_url` | string | — | CRL 分发点 URL |
| `crl_refresh_sec` | int | 300 | CRL 刷新间隔 |
| `ocsp_cache_ttl_sec` | int | 300 | OCSP 缓存 TTL |
| `ocsp_fallback` | string | `"allow"` | OCSP 失败策略。**`"allow"`（fail-open）时强制离线证书剩余有效期 ≤1h（G2(b)）** |
| `tsa_url` | string | — | TSA 服务 URL |
| `tsa_cert_file` | string | — | TSA CA 证书 |
| `allow_roles` | []string | — | RBAC 角色 |
| `audit_file` | string | — | 审计日志路径 |
| `max_conns_per_ip` | int | 0 | per-IP 限制 |
| `max_conns_per_cert` | int | 0 | per-cert 限制 |
| `max_total_conns` | int | 0 | 全局限制 |
| `idle_timeout_sec` | int | 0 | 空闲超时 |
| `audit_max_size_mb` | int | 100 | 审计最大 MB |
| `audit_max_backups` | int | 3 | 审计备份数 |
| `disconnect_on_expiry` | bool | true | 证书过期断开 |
| `require_aic` | bool | false | 要求 AIC |
| `disallow_representative` | bool | 同 require_aic | 禁止代理模式 |
| `require_user_auth` | bool | false | 要求用户认证 |
| `cipher_suites` | []string | 安全默认 | TLS 密码套件 |
| `min_tls_version` | string | `"1.2"` | 最低 TLS 版本 |

## HTTPExtra（`http_ext` 块）

HTTP 特有扩展字段，位于 listener 的 `http_ext` 字段内。旧 `MTLSConfig` 中的 HTTP 相关字段全部移入此块。

```json
{
  "http_ext": {
    "read_header_timeout_sec": 30,
    "write_timeout_sec": 300,
    "forward_client_cert": true,
    "forward_client_cert_der": false,
    "tls_termination": true
  }
}
```

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `read_header_timeout_sec` | int | 30 | 读请求头超时（秒），0=默认 30s（W32，慢头防护） |
| `write_timeout_sec` | int | 300 | 写响应超时（秒），0=默认 300s（W32）。gRPC/WS 长流连接持续写，配小值会误杀，需按业务调 |
| `forward_client_cert` | bool | true | 转发客户端证书 Header |
| `forward_client_cert_der` | bool | false | 证书透传（B2）：以 `X-Client-Cert-DER` 把已验证客户端证书透传给后端，替代已废弃的 `X-Agent-User` 用户名路径（B1）；需配合 core `serve.trusted_gateway_ous` 使用 |
| `tls_termination` | bool | true | TLS 终止 + AIC Header 注入 |

## 后端协议

| 协议 | 说明 |
|------|------|
| `h2`（默认） | H2 over TLS |
| `h1` | HTTP/1.1（禁用 HTTP/2 尝试） |
| `h2c` | 明文 HTTP/2（无 TLS） |

## Protocol

| Protocol | 生效 TLS 模式 | 说明 |
|------|-----------|------|
| `http1` | `none`（默认）/ `server` / `mtls` | HTTP/1.1。不配 `tls` 块为明文；配 `tls.mode=server` 启用单向 TLS，配 `tls.mode=mtls` 启用双向 mTLS |
| `http2` | `none`（默认）/ `server` / `mtls` | HTTP/2（TLS）。**mTLS 零信任场景的标准组合：`protocol:"http2"` + `tls:{"mode":"mtls",...}`** |
| `h2c` | `none` | 明文 HTTP/2（无 TLS） |
| `grpc` | `none`（默认）/ `server` / `mtls` | gRPC（HTTP/2 + protobuf） |
| `ws` | `none` | WebSocket（HTTP 升级） |
| `wss` | `none`（默认）/ `server` / `mtls` | WebSocket over TLS |
| `h3` | `server` / `mtls`（内置 TLS 1.3） | HTTP/3（QUIC 上的 HTTP）。必须提供 `cert_file` |
| `quic` | `server` / `mtls`（内置 TLS 1.3） | 原始 QUIC 流隧道。必须提供 `cert_file` |

> 旧 `tls_mode` 字段（`plain`/`server`/`mtls`/`h3`/`quic`）已移除：协议语义与 TLS 认证模式分离。协议由 `protocol` 指定，认证模式由 `tls.mode` 指定。

## 管理 API 端点

| 方法 | 路径 | 角色 | 说明 |
|------|------|------|------|
| GET | `/api/v1/gateway/health` | 公开 | 健康检查（仅 mTLS） |
| GET | `/api/v1/gateway/metrics` | ops, admin | Prometheus 指标 |
| GET | `/api/v1/gateway/audit` | audit, admin | 审计日志查询 |
| POST | `/api/v1/gateway/audit/verify` | audit, admin | Merkle 哈希链验证 |
| GET | `/api/v1/gateway/listeners` | admin | 列出 HTTP 监听器 |
| POST | `/api/v1/gateway/listeners` | admin | 添加 HTTP 监听器 |
| DELETE | `/api/v1/gateway/listeners/{name}` | admin | 删除 HTTP 监听器 |
| GET | `/api/v1/gateway/plugins` | ops, admin | 列出能力插件 |
| GET | `/api/v1/gateway/plugins/{scheme}` | ops, admin | 查看单个插件 |
| PUT | `/api/v1/gateway/plugins` | admin | 替换全部插件 |
| DELETE | `/api/v1/gateway/plugins` | admin | 清空全部插件 |
| GET | `/api/v1/gateway/capabilities` | ops, admin | 列出能力配置 |
| GET | `/api/v1/gateway/capabilities/{scheme}` | ops, admin | 查看单个方案 |
| PUT | `/api/v1/gateway/capabilities` | admin | 替换全部配置 |
| PUT | `/api/v1/gateway/capabilities/{scheme}` | admin | 替换单个方案 |
| POST | `/api/v1/gateway/capabilities/{scheme}/capabilities` | admin | 添加能力规则 |
| DELETE | `/api/v1/gateway/capabilities/{scheme}` | admin | 删除方案 |
| DELETE | `/api/v1/gateway/capabilities/{scheme}/capabilities/{id}` | admin | 删除能力规则 |
| POST | `/api/v1/gateway/capabilities/validate` | admin | 校验配置 |
| POST | `/api/v1/gateway/disconnect-agent` | admin | 按 Agent ID 断开连接 |
| POST | `/api/v1/gateway/disconnect-user` | admin | 按 Principal UID 断开连接 |
| POST | `/api/v1/gateway/reload` | admin | 热重载配置 |

Data plane endpoints (proxy port):

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| GET | `/_timestamp` | 无 | 服务端时间同步 |

> 注（W24，2026-08-16）：文档曾宣称 `/_auth`/`/_heartbeat`/`/_session` 数据面端点，但代码从未实现，已从文档移除。长连接会话语义由 GatewaySession 执行（CIDR + 硬超时）与证书生命周期（CRL/OCSP/DisconnectOnExpiry）覆盖。

## CLI 参数

`--config` 和 `--listener/--route` 互斥。

### --listener KV 键

`name`, `listen`, `protocol`, `tls-mode`, `ca-cert`, `cert`, `key`, `crl-url`, `crl-refresh-sec`, `ocsp-cache-ttl-sec`, `ocsp-fallback`, `tsa-url`, `tsa-cert-file`, `audit-file`, `max-conns-per-ip`, `max-conns-per-cert`, `max-total-conns`, `idle-timeout-sec`, `read-header-timeout-sec`, `write-timeout-sec`, `forward-client-cert`, `forward-client-cert-der`, `tls-termination`, `disconnect-on-expiry`, `cipher-suites`（分号分隔）, `min-tls-version`, `audit-max-size-mb`, `audit-max-backups`

> `tls-mode` 是 CLI 兼容键（`protocol` 缺省为 `http2`）。示例：`name=api,listen=:443,protocol=http2,tls-mode=mtls,ca-cert=ca.pem,...`

### --route KV 键

`listener`, `path`, `target`, `allow-roles`（分号分隔）
