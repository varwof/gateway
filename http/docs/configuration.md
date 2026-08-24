# 配置参考

## 顶层结构

```json
{
  "listeners": [],
  "management": {}
}
```

| 字段 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `listeners` | `[]ListenerConfig` | 是 | 监听器列表，至少一项 |
| `management` | `MgmtConfig` | 否 | 管理 API 配置 |

## ListenerConfig

```json
{
  "name": "api-gateway",
  "listen": ":443",
  "protocol": "http2",
  "tls": {
    "mode": "mtls",
    "ca_cert_file": "/etc/pki/ca.pem",
    "cert_file": "/etc/pki/server.pem",
    "key_file": "/etc/pki/server.key"
  },
  "http_ext": {
    "read_header_timeout_sec": 30,
    "write_timeout_sec": 300
  },
  "routes": []
}
```

| 字段 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `name` | `string` | 是 | 监听器名称，唯一标识，运行时增删用 |
| `listen` | `string` | 是 | 监听地址，格式 `:port` 或 `host:port` |
| `protocol` | `string` | 是 | 传输+应用协议：`http1` / `http2` / `h2c` / `grpc` / `ws` / `wss` / `h3` / `quic` |
| `tls` | `TLSConfig` | 条件 | TLS/mTLS 配置（`tls.mode=none` 时忽略） |
| `http_ext` | `HTTPExtra` | 否 | HTTP 特有扩展字段（超时/证书透传/TLS 终止） |
| `routes` | `[]RouteConfig` | 是 | 路由规则，至少一项 |

### protocol 说明

| 协议 | 生效 TLS 模式 | 描述 | TLS 配置 | 典型场景 |
|------|------|----------|----------|----------|
| `http1` | `none` / `server` / `mtls` | HTTP/1.1 | 按 `tls.mode` 决定 | 遗留 HTTP |
| `http2` | `none` / `server` / `mtls` | HTTP/2（TLS） | 按 `tls.mode` 决定 | **mTLS 零信任：`protocol:"http2"` + `tls.mode:"mtls"`** |
| `h2c` | `none` | 明文 HTTP/2，无 TLS | 不需要 | 内部调试、与上游 TLS 终止器配合 |
| `grpc` | `none` / `server` / `mtls` | gRPC（HTTP/2 + protobuf） | 按 `tls.mode` 决定 | gRPC 服务 |
| `ws` | `none` | WebSocket（HTTP 升级） | 不需要 | WebSocket 代理 |
| `wss` | `none` / `server` / `mtls` | WebSocket over TLS | 按 `tls.mode` 决定 | 安全 WebSocket |
| `h3` | `server` / `mtls`（内置 TLS 1.3） | HTTP/3（QUIC 上的 HTTP） | 需 `cert_file` + `key_file` | HTTP/3 服务 |
| `quic` | `server` / `mtls`（内置 TLS 1.3） | 原始 QUIC 流隧道 | 需 `cert_file` + `key_file` | QUIC 流隧道 |

## TLSConfig

```json
{
  "tls": {
    "mode": "mtls",
    "ca_cert_file": "/etc/varwof/gateway-http/ca.pem",
    "cert_file": "/etc/varwof/gateway-http/server.pem",
    "key_file": "/etc/varwof/gateway-http/server.key",
    "crl_url": "http://crl.varwof.com/gateway-ca.crl",
    "crl_refresh_sec": 300,
    "tsa_url": "http://127.0.0.1:3180/tsa",
    "audit_file": "/var/log/gateway-http/audit.log",
    "audit_max_size_mb": 100,
    "audit_max_backups": 3,
    "max_conns_per_ip": 100,
    "max_total_conns": 1000,
    "idle_timeout_sec": 120
  }
}
```

| 字段 | 类型 | 默认值 | 必需 | 说明 |
|------|------|--------|------|------|
| `mode` | `string` | — | 否 | TLS 认证模式：`none` / `server` / `mtls`。`h3`/`quic` 协议缺省由 `ca_cert_file` 是否存在推导（有→`mtls`，无→`server`） |
| `ca_cert_file` | `string` | — | `mtls` 模式必填 | CA 证书文件路径（PEM），用于验证客户端证书链 |
| `cert_file` | `string` | — | `server`/`mtls` 模式必填 | 服务器证书文件路径（PEM） |
| `key_file` | `string` | — | `server`/`mtls` 模式必填 | 服务器私钥文件路径（PEM） |
| `crl_url` | `string` | — | 否 | CRL 分发点 URL，设置后启用 CRL 吊销检查 |
| `crl_refresh_sec` | `int` | `300` | 否 | CRL 刷新间隔（秒） |
| `tsa_url` | `string` | — | 否 | TSA 服务 URL（RFC 3161），设置后审计日志加盖时间戳 |
| `audit_file` | `string` | — | 否 | 审计日志文件路径，设置后启用请求级审计 |
| `audit_max_size_mb` | `int` | `100` | 否 | 审计日志单文件最大大小（MB），超出后轮转 |
| `audit_max_backups` | `int` | `3` | 否 | 审计日志最大备份数 |
| `max_conns_per_ip` | `int` | `0`（不限制） | 否 | 单 IP 最大并发连接数 |
| `max_total_conns` | `int` | `0`（不限制） | 否 | 总并发连接数上限 |
| `idle_timeout_sec` | `int` | `0`（不超时） | 否 | HTTP 空闲连接超时（秒） |
| `disconnect_on_expiry` | `bool` | `true` | 否 | 证书过期时拒绝请求并发送 `Connection: close` |
| `cipher_suites` | `[]string` | AEAD 套件集 | 否 | TLS 密码套件白名单（可选项见下文） |
| `min_tls_version` | `string` | `"1.2"` | 否 | 最低 TLS 版本（`"1.2"` 或 `"1.3"`） |

### HTTPExtra（`http_ext` 块）

HTTP 特有扩展字段（旧 `MTLSConfig` 中的 HTTP 字段移入此块）：

| 字段 | 类型 | 默认值 | 必需 | 说明 |
|------|------|--------|------|------|
| `read_header_timeout_sec` | `int` | `30` | 否 | 读请求头超时（秒），0=默认 30s（W32，慢头防护） |
| `write_timeout_sec` | `int` | `300` | 否 | 写响应超时（秒），0=默认 300s（W32） |
| `forward_client_cert` | `bool` | `true` | 否 | 透传客户端证书信息到后端（`X-Forwarded-Client-*` 头部） |
| `forward_client_cert_der` | `bool` | `false` | 否 | 证书透传（B2）：以 `X-Client-Cert-DER` 透传已验证客户端证书到后端，替代已废弃的 `X-Agent-User` 用户名路径（B1）；需配合 core `serve.trusted_gateway_ous` |
| `tls_termination` | `bool` | `true` | 否 | TLS 终止 + AIC Header 注入 |

### cipher_suites 可用选项

| 值 | 对应 Go 常量 | TLS 版本 |
|----|-------------|----------|
| `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | `tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | 1.2 |
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | `tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | 1.2 |
| `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` | `tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` | 1.2 |
| `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | `tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | 1.2 |
| `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305` | `tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305` | 1.2 |
| `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305` | `tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305` | 1.2 |
| `TLS_AES_128_GCM_SHA256` | `tls.TLS_AES_128_GCM_SHA256` | 1.3 |
| `TLS_AES_256_GCM_SHA384` | `tls.TLS_AES_256_GCM_SHA384` | 1.3 |
| `TLS_CHACHA20_POLY1305_SHA256` | `tls.TLS_CHACHA20_POLY1305_SHA256` | 1.3 |

省略时使用全部 AEAD 密码套件。列表为空或全部无效时也会回退至默认集。

### CRL 配置说明

- `crl_url` 指向 DER 或 PEM 格式的 CRL 文件
- 启动时同步等待首次 CRL 拉取成功（失败后每 5s 重试）
- 刷新时验证 CRL 签名（`CheckCRLSignature`）和 Issuer DN 一致性
- 每请求遍历客户端证书链中非根证书，逐一检查吊销状态
- CRL 过期（超过 `nextUpdate`）后 `IsRevoked` 返回错误而非允许通过

### 审计配置说明

- 审计日志为 JSON 行格式，每行一个 `SignedAuditEntry`
- 若配置了 `tsa_url`，每条审计日志在写入前先请求 TSA 时间戳，附加为 `"tst"` 字段
- 日志自动轮转：当前文件达到 `audit_max_size_mb` 后，依次重命名 `.1`、`.2`、`.3`，超出 `audit_max_backups` 的旧日志被删除

## RouteConfig

```json
{
  "path": "/api/internal/*",
  "target": "http://127.0.0.1:8080",
  "allow_roles": ["gateway:internal-api"]
}
```

| 字段 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `path` | `string` | 是 | 路径匹配模式 |
| `target` | `string` | 是 | 后端目标 URL（支持 `http://` 和 `https://`） |
| `allow_roles` | `[]string` | 否 | 允许访问的角色列表，未设置或空列表表示允许所有已认证请求 |

### 路径匹配规则

| 模式 | 行为 | 示例 |
|------|------|------|
| 精确路径 `/health` | 仅匹配 `/health` | `/health` ✅、`/health/` ❌ |
| 前缀通配 `/api/*` | 匹配 `/api/` 开头的任意路径 | `/api/v1/users` ✅、`/api/` ✅、`/api` ❌ |
| 最长匹配优先 | 同时匹配多条时取前缀最长的 | `/api/*` vs `/api/v1/*` → 后者命中 |

**注意事项**：
- `/*` 通配匹配所有路径（catch-all 路由应放在最后）
- 无匹配路由时返回 404 Not Found
- 路由顺序不影响匹配结果（始终按最长匹配优先）

### allow_roles 规则

| 角色值 | 含义 |
|--------|------|
| `gateway:admin` | 仅限管理员 |
| `gateway:internal-api` | 内部 API 调用 |
| `gateway:*` | 任何 `gateway:` 前缀角色（通配） |
| 空列表 | 所有经过 mTLS 认证的请求（不检查角色） |

角色从客户端证书的 OU 字段提取。支持多 OU，任一匹配即通过。

## ManagementConfig

```json
{
  "listen": ":8444",
  "tls": {
    "ca_cert_file": "/etc/varwof/gateway-http/admin-ca.pem",
    "cert_file": "/etc/varwof/gateway-http/management.pem",
    "key_file": "/etc/varwof/gateway-http/management.key"
  }
}
```

| 字段 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `listen` | `string` | 是 | 管理 API 监听地址 |
| `tls` | `TLSConfig` | 是 | mTLS 配置（`ca_cert_file`、`cert_file`、`key_file`） |

访问管理 API 需要客户端证书含 `gateway:admin` 角色。

## 完整示例

```json
{
  "listeners": [
    {
      "name": "public-api",
      "listen": ":443",
      "protocol": "http2",
      "tls": {
        "mode": "mtls",
        "ca_cert_file": "/etc/varwof/gateway-http/ca.pem",
        "cert_file": "/etc/varwof/gateway-http/server.pem",
        "key_file": "/etc/varwof/gateway-http/server.key",
        "crl_url": "http://crl.varwof.com/gateway-ca.crl",
        "crl_refresh_sec": 600,
        "tsa_url": "http://tsa.varwof.com:3180/tsa",
        "audit_file": "/var/log/gateway-http/audit.log",
        "audit_max_size_mb": 200,
        "audit_max_backups": 7,
        "max_conns_per_ip": 50,
        "max_total_conns": 2000,
        "idle_timeout_sec": 60,
        "disconnect_on_expiry": true,
        "cipher_suites": ["TLS_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"],
        "min_tls_version": "1.2"
      },
      "http_ext": {
        "forward_client_cert": true
      },
      "routes": [
        { "path": "/api/v1/public/*", "target": "http://127.0.0.1:8080",
          "allow_roles": ["gateway:public"] },
        { "path": "/api/v1/internal/*", "target": "http://127.0.0.1:8081",
          "allow_roles": ["gateway:internal-api"] },
        { "path": "/health", "target": "http://127.0.0.1:8082" }
      ]
    },
    {
      "name": "admin-portal",
      "listen": ":444",
      "protocol": "http2",
      "tls": {
        "mode": "mtls",
        "ca_cert_file": "/etc/varwof/gateway-http/admin-ca.pem",
        "cert_file": "/etc/varwof/gateway-http/admin-server.pem",
        "key_file": "/etc/varwof/gateway-http/admin-server.key",
        "crl_url": "http://crl.varwof.com/admin-ca.crl",
        "audit_file": "/var/log/gateway-http/admin-audit.log"
      },
      "routes": [
        { "path": "/*", "target": "http://127.0.0.1:3000",
          "allow_roles": ["gateway:admin"] }
      ]
    }
  ],
  "management": {
    "listen": ":8444",
    "tls": {
      "ca_cert_file": "/etc/varwof/gateway-http/admin-ca.pem",
      "cert_file": "/etc/varwof/gateway-http/management.pem",
      "key_file": "/etc/varwof/gateway-http/management.key"
    }
  }
}
```
