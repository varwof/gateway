# Configuration Reference

## Top-Level Structure

```json
{
  "listeners": [],
  "management": {}
}
```

| Field | Type | Required | Description |
|------|------|------|------|
| `listeners` | `[]ListenerConfig` | Yes | Listener list, at least one entry |
| `management` | `MgmtConfig` | No | Management API configuration |

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

| Field | Type | Required | Description |
|------|------|------|------|
| `name` | `string` | Yes | Listener name; unique identifier used for runtime add/remove |
| `listen` | `string` | Yes | Listen address, in the format `:port` or `host:port` |
| `protocol` | `string` | Yes | Transport+application protocol: `http1` / `http2` / `h2c` / `grpc` / `ws` / `wss` / `h3` / `quic` |
| `tls` | `TLSConfig` | Conditional | TLS/mTLS configuration (ignored when `tls.mode=none`) |
| `http_ext` | `HTTPExtra` | No | HTTP-specific extension fields (timeouts / client cert forwarding / TLS termination) |
| `routes` | `[]RouteConfig` | Yes | Routing rules, at least one entry |

### protocol Description

| Protocol | Effective TLS Mode | Description | TLS Configuration | Typical Scenarios |
|------|------|----------|----------|----------|
| `http1` | `none` / `server` / `mtls` | HTTP/1.1 | Depends on `tls.mode` | Legacy HTTP |
| `http2` | `none` / `server` / `mtls` | HTTP/2 (TLS) | Depends on `tls.mode` | **mTLS zero trust: `protocol:"http2"` + `tls.mode:"mtls"`** |
| `h2c` | `none` | Cleartext HTTP/2, no TLS | Not required | Internal debugging, pairing with an upstream TLS terminator |
| `grpc` | `none` / `server` / `mtls` | gRPC (HTTP/2 + protobuf) | Depends on `tls.mode` | gRPC services |
| `ws` | `none` | WebSocket (HTTP upgrade) | Not required | WebSocket proxying |
| `wss` | `none` / `server` / `mtls` | WebSocket over TLS | Depends on `tls.mode` | Secure WebSocket |
| `h3` | `server` / `mtls` (built-in TLS 1.3) | HTTP/3 (HTTP over QUIC) | Requires `cert_file` + `key_file` | HTTP/3 services |
| `quic` | `server` / `mtls` (built-in TLS 1.3) | Raw QUIC stream tunnel | Requires `cert_file` + `key_file` | QUIC stream tunnel |

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

| Field | Type | Default | Required | Description |
|------|------|--------|------|------|
| `mode` | `string` | — | No | TLS authentication mode: `none` / `server` / `mtls`. For the `h3`/`quic` protocols the default is derived from whether `ca_cert_file` is present (present → `mtls`, absent → `server`) |
| `ca_cert_file` | `string` | — | Required in `mtls` mode | CA certificate file path (PEM), used to verify client certificate chains |
| `cert_file` | `string` | — | Required in `server`/`mtls` modes | Server certificate file path (PEM) |
| `key_file` | `string` | — | Required in `server`/`mtls` modes | Server private key file path (PEM) |
| `crl_url` | `string` | — | No | CRL distribution point URL; setting it enables CRL revocation checking |
| `crl_refresh_sec` | `int` | `300` | No | CRL refresh interval (seconds) |
| `tsa_url` | `string` | — | No | TSA service URL (RFC 3161); setting it timestamps audit log entries |
| `audit_file` | `string` | — | No | Audit log file path; setting it enables request-level auditing |
| `audit_max_size_mb` | `int` | `100` | No | Maximum audit log file size (MB); rotates when exceeded |
| `audit_max_backups` | `int` | `3` | No | Maximum number of audit log backups |
| `max_conns_per_ip` | `int` | `0` (unlimited) | No | Maximum concurrent connections per IP |
| `max_total_conns` | `int` | `0` (unlimited) | No | Total concurrent connection limit |
| `idle_timeout_sec` | `int` | `0` (no timeout) | No | HTTP idle connection timeout (seconds) |
| `disconnect_on_expiry` | `bool` | `true` | No | Reject requests and send `Connection: close` when the certificate has expired |
| `cipher_suites` | `[]string` | AEAD suite set | No | TLS cipher suite allowlist (see options below) |
| `min_tls_version` | `string` | `"1.2"` | No | Minimum TLS version (`"1.2"` or `"1.3"`) |

### HTTPExtra (`http_ext` block)

HTTP-specific extension fields (the HTTP fields of the legacy `MTLSConfig` have moved here):

| Field | Type | Default | Required | Description |
|------|------|--------|------|------|
| `read_header_timeout_sec` | `int` | `30` | No | Request header read timeout (seconds); 0 = default 30s (W32, slowloris protection) |
| `write_timeout_sec` | `int` | `300` | No | Response write timeout (seconds); 0 = default 300s (W32) |
| `forward_client_cert` | `bool` | `true` | No | Forward client certificate information to the backend (`X-Forwarded-Client-*` headers) |
| `forward_client_cert_der` | `bool` | `false` | No | Certificate pass-through (B2): forwards the verified client certificate to the backend via `X-Client-Cert-DER`, replacing the deprecated `X-Agent-User` username path (B1); must be used together with core `serve.trusted_gateway_ous` |
| `tls_termination` | `bool` | `true` | No | TLS termination + AIC header injection |

### Available cipher_suites Options

| Value | Corresponding Go Constant | TLS Version |
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

When omitted, all AEAD cipher suites are used. An empty list or a list where all entries are invalid also falls back to the default set.

### CRL Configuration Notes

- `crl_url` points to a CRL file in DER or PEM format
- At startup, the first CRL fetch is awaited synchronously (retried every 5s on failure)
- On refresh, the CRL signature (`CheckCRLSignature`) and Issuer DN consistency are verified
- For each request, every non-root certificate in the client certificate chain is traversed and its revocation status checked one by one
- After the CRL expires (past `nextUpdate`), `IsRevoked` returns an error instead of allowing through

### Audit Configuration Notes

- The audit log is JSON Lines format, one `SignedAuditEntry` per line
- If `tsa_url` is configured, each audit entry requests a TSA timestamp before being written, attached as the `"tst"` field
- Logs rotate automatically: when the current file reaches `audit_max_size_mb`, files are renamed sequentially to `.1`, `.2`, `.3`, and old logs beyond `audit_max_backups` are deleted

## RouteConfig

```json
{
  "path": "/api/internal/*",
  "target": "http://127.0.0.1:8080",
  "allow_roles": ["gateway:internal-api"]
}
```

| Field | Type | Required | Description |
|------|------|------|------|
| `path` | `string` | Yes | Path matching pattern |
| `target` | `string` | Yes | Backend target URL (supports `http://` and `https://`) |
| `allow_roles` | `[]string` | No | Allowed role list; unset or empty means all authenticated requests are allowed |

### Path Matching Rules

| Pattern | Behavior | Example |
|------|------|------|
| Exact path `/health` | Matches only `/health` | `/health` ✅, `/health/` ❌ |
| Prefix wildcard `/api/*` | Matches any path starting with `/api/` | `/api/v1/users` ✅, `/api/` ✅, `/api` ❌ |
| Longest match wins | When multiple patterns match, the longest prefix wins | `/api/*` vs `/api/v1/*` → the latter matches |

**Notes**:
- `/*` matches all paths (catch-all routes should be placed last)
- Returns 404 Not Found when no route matches
- Route order does not affect matching results (longest match always wins)

### allow_roles Rules

| Role Value | Meaning |
|--------|------|
| `gateway:admin` | Administrators only |
| `gateway:internal-api` | Internal API calls |
| `gateway:*` | Any role with the `gateway:` prefix (wildcard) |
| Empty list | All requests authenticated via mTLS (no role check) |

Roles are extracted from the OU field of the client certificate. Multiple OUs are supported; any match passes.

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

| Field | Type | Required | Description |
|------|------|------|------|
| `listen` | `string` | Yes | Management API listen address |
| `tls` | `TLSConfig` | Yes | mTLS configuration (`ca_cert_file`, `cert_file`, `key_file`) |

Accessing the management API requires a client certificate containing the `gateway:admin` role.

## Complete Example

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
