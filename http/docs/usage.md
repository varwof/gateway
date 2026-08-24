# gateway-http 使用指南

## 路径路由

### 精确匹配

```json
{"path": "/health", "target": "http://backend:8080"}
```

### 通配符匹配

```json
{"path": "/api/*", "target": "http://api-backend:8080"}
```

匹配规则：
- 最长前缀优先（`/api/v2/*` 优先于 `/api/*`）
- 大小写不敏感
- 自动规范化（`//` → `/`，`/../` → `/`）
- 路径边界检查（`/api/internal2` 不匹配 `/api/internal/*`）

## 路径级 RBAC

```json
{
  "routes": [
    {"path": "/admin/*", "target": "http://admin:8080", "allow_roles": ["gateway:admin"]},
    {"path": "/api/*", "target": "http://api:8080", "allow_roles": ["gateway:admin", "gateway:ops"]},
    {"path": "/health", "target": "http://api:8080"}
  ]
}
```

无 `allow_roles` 的路由对所有角色开放。有 `allow_roles` 的路由需要客户端证书包含匹配角色。

## 后端协议选择

### H2C（明文 HTTP/2）

```json
{"path": "/grpc/*", "target": "http://grpc-backend:8080", "backend_protocol": "h2c"}
```

适用于 gRPC 服务。使用 `http2.Transport{AllowHTTP: true}`。

### H1（HTTP/1.1）

```json
{"path": "/legacy/*", "target": "http://legacy:8080", "backend_protocol": "h1"}
```

强制使用 HTTP/1.1，禁用 HTTP/2 尝试。

### H2 over TLS（默认）

```json
{"path": "/api/*", "target": "https://api:443"}
```

## WebSocket 代理

自动检测 `Upgrade: websocket` Header，透传升级：

```json
{
  "routes": [
    {"path": "/ws/*", "target": "http://ws-backend:8080"}
  ]
}
```

客户端发送标准 WebSocket 升级请求，网关自动代理 101 握手和后续帧。

## gRPC 代理

自动检测 `Content-Type: application/grpc`，透明代理：

```json
{
  "listeners": [{
    "name": "grpc-proxy",
    "listen": ":443",
    "protocol": "grpc",
    "tls": {"mode": "mtls", "ca_cert_file": "ca.pem", "cert_file": "server.pem", "key_file": "server.key"},
    "routes": [
      {"path": "/", "target": "h2c://grpc-backend:8080", "backend_protocol": "h2c"}
    ]
  }]
}
```

## AIC Header 注入

网关自动将以下 Header 注入到后端请求：

| Header | 说明 |
|--------|------|
| `X-Forwarded-Client-CN` | 客户端证书 CN |
| `X-Forwarded-Client-O` | 客户端证书 O |
| `X-Forwarded-Client-OU` | 客户端证书 OU |
| `X-Forwarded-Client-Serial` | 证书序列号 |
| `X-Forwarded-Client-NotAfter` | 证书过期时间 |
| `X-AIC-Agent-Id` | AIC Agent ID |
| `X-AIC-Principal-Uid` | AIC Principal UID |
| `X-AIC-Capabilities` | AIC 能力列表 |
| `X-GS-Max-Concurrent` | GatewaySession 最大并发 |
| `X-GS-Hard-Timeout` | GatewaySession 硬超时 |

## QUIC/HTTP3

```json
{
  "listeners": [{
    "name": "h3-listener",
    "listen": ":443",
    "protocol": "h3",
    "tls": {"mode": "mtls", "ca_cert_file": "ca.pem", "cert_file": "server.pem", "key_file": "server.key"},
    "routes": [{"path": "/", "target": "http://backend:8080"}]
  }]
}
```

QUIC 流控窗口：`InitialStreamReceiveWindow=10MB`，`MaxStreamReceiveWindow=20MB`。

## 会话委托

启用双证书模式（Agent + User）：

```json
{
  "tls": {
    "require_delegation": true,
    "session_timeout_sec": 300,
    "heartbeat_interval_sec": 60,
    "heartbeat_timeout_sec": 180
  }
}
```

> 注：以上委托相关字段与下述内部端点（`/_auth`/`/_heartbeat`/`/_session`）为文档历史遗留描述，HTTP 网关代码并未实现（W24，2026-08-16）。长连接会话语义由 GatewaySession 执行（CIDR + 硬超时）与证书生命周期（CRL/OCSP/DisconnectOnExpiry）覆盖。

内部端点：
- `POST /_auth` — 认证 + 获取 session_id
- `GET /_timestamp` — 服务器时间同步
- `POST /_heartbeat` — 会话保活
- `DELETE /_session` — 注销

## Prometheus 指标

| 指标名 | 类型 | 标签 | 说明 |
|--------|------|------|------|
| `pki_gateway_http_requests_total` | Counter | listener, route, method, status | HTTP 请求总数 |
| `pki_gateway_http_request_duration_seconds` | Histogram | listener, route | 请求延迟分布 |
| `pki_gateway_http_ws_connections_active` | Gauge | listener | 活跃 WS 连接 |
| `pki_gateway_http_ws_connections_total` | Counter | listener | WS 连接总数 |
| `pki_gateway_http_up` | Gauge | listener | 监听器状态 |
| `pki_gateway_http_connections_accepted_total` | Counter | listener | 接受连接总数 |
| `pki_gateway_http_bytes_to_target_total` | Counter | listener, cert_serial | 发往后端字节 |
| `pki_gateway_http_bytes_to_client_total` | Counter | listener, cert_serial | 发往客户端字节 |
