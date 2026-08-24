# gateway-http Usage Guide

## Path Routing

### Exact Matching

```json
{"path": "/health", "target": "http://backend:8080"}
```

### Wildcard Matching

```json
{"path": "/api/*", "target": "http://api-backend:8080"}
```

Matching rules:
- Longest prefix wins (`/api/v2/*` takes precedence over `/api/*`)
- Case-insensitive
- Automatic normalization (`//` → `/`, `/../` → `/`)
- Path boundary checking (`/api/internal2` does not match `/api/internal/*`)

## Path-Level RBAC

```json
{
  "routes": [
    {"path": "/admin/*", "target": "http://admin:8080", "allow_roles": ["gateway:admin"]},
    {"path": "/api/*", "target": "http://api:8080", "allow_roles": ["gateway:admin", "gateway:ops"]},
    {"path": "/health", "target": "http://api:8080"}
  ]
}
```

Routes without `allow_roles` are open to all roles. Routes with `allow_roles` require the client certificate to contain a matching role.

## Backend Protocol Selection

### H2C (Cleartext HTTP/2)

```json
{"path": "/grpc/*", "target": "http://grpc-backend:8080", "backend_protocol": "h2c"}
```

Suitable for gRPC services. Uses `http2.Transport{AllowHTTP: true}`.

### H1 (HTTP/1.1)

```json
{"path": "/legacy/*", "target": "http://legacy:8080", "backend_protocol": "h1"}
```

Forces HTTP/1.1 and disables HTTP/2 negotiation.

### H2 over TLS (default)

```json
{"path": "/api/*", "target": "https://api:443"}
```

## WebSocket Proxying

Automatically detects the `Upgrade: websocket` header and passes through the upgrade:

```json
{
  "routes": [
    {"path": "/ws/*", "target": "http://ws-backend:8080"}
  ]
}
```

When the client sends a standard WebSocket upgrade request, the gateway automatically proxies the 101 handshake and subsequent frames.

## gRPC Proxying

Automatically detects `Content-Type: application/grpc` and proxies transparently:

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

## AIC Header Injection

The gateway automatically injects the following headers into backend requests:

| Header | Description |
|--------|------|
| `X-Forwarded-Client-CN` | Client certificate CN |
| `X-Forwarded-Client-O` | Client certificate O |
| `X-Forwarded-Client-OU` | Client certificate OU |
| `X-Forwarded-Client-Serial` | Certificate serial number |
| `X-Forwarded-Client-NotAfter` | Certificate expiration time |
| `X-AIC-Agent-Id` | AIC Agent ID |
| `X-AIC-Principal-Uid` | AIC Principal UID |
| `X-AIC-Capabilities` | AIC capability list |
| `X-GS-Max-Concurrent` | GatewaySession maximum concurrency |
| `X-GS-Hard-Timeout` | GatewaySession hard timeout |

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

QUIC flow control windows: `InitialStreamReceiveWindow=10MB`, `MaxStreamReceiveWindow=20MB`.

## Session Delegation

Enables dual-certificate mode (Agent + User):

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

> Note: The delegation fields above and the internal endpoints below (`/_auth`/`/_heartbeat`/`/_session`) are historical documentation leftovers; the HTTP gateway never implemented them in code (W24, 2026-08-16). Long-lived session semantics are covered by GatewaySession enforcement (CIDR + hard timeout) and certificate lifecycle (CRL/OCSP/DisconnectOnExpiry).

Internal endpoints:
- `POST /_auth` — authenticate + obtain session_id
- `GET /_timestamp` — server time synchronization
- `POST /_heartbeat` — session keep-alive
- `DELETE /_session` — log out

## Prometheus Metrics

| Metric | Type | Labels | Description |
|--------|------|------|------|
| `pki_gateway_http_requests_total` | Counter | listener, route, method, status | Total HTTP requests |
| `pki_gateway_http_request_duration_seconds` | Histogram | listener, route | Request latency distribution |
| `pki_gateway_http_ws_connections_active` | Gauge | listener | Active WS connections |
| `pki_gateway_http_ws_connections_total` | Counter | listener | Total WS connections |
| `pki_gateway_http_up` | Gauge | listener | Listener status |
| `pki_gateway_http_connections_accepted_total` | Counter | listener | Total accepted connections |
| `pki_gateway_http_bytes_to_target_total` | Counter | listener, cert_serial | Bytes sent to backend |
| `pki_gateway_http_bytes_to_client_total` | Counter | listener, cert_serial | Bytes sent to client |
