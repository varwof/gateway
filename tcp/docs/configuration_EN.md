# Configuration Reference

## Top-Level Structure

```json
{
  "defaults":  { ... },
  "mappings":  [ ... ],
  "tunnels":   [ ... ],
  "management": { ... }
}
```

| Field | Type | Required | Description |
|------|------|------|------|
| `defaults` | MappingDefaults | No | Global defaults; fields omitted in a mapping inherit from here |
| `mappings` | []MappingConfig | No | List of TCP port forwarding mappings |
| `tunnels` | []TunnelConfig | No | List of advanced tunnel configurations (alternative to or coexisting with mappings) |
| `management` | ManagementConfig | No | Management API configuration |

## MappingDefaults

```json
{
  "tls": { ... },
  "protocol": "tcp+mtls",
  "max_conns_per_ip": 10,
  "max_total_conns": 1000,
  "idle_timeout_sec": 300,
  "health_check_sec": 0,
  "audit_max_size_mb": 100,
  "audit_max_backups": 3
}
```

| Field | Type | Default | Description |
|------|------|--------|------|
| `tls` | TLSConfig | — | Default TLS authentication configuration |
| `protocol` | string | `"tcp+mtls"` | Default protocol |
| `max_conns_per_ip` | int | `10` | Max concurrent connections per IP |
| `max_total_conns` | int | `1000` | Global max concurrent connections |
| `idle_timeout_sec` | int | `300` | Idle connection timeout (seconds) |
| `health_check_sec` | int | `0` | Health check interval (0 = disabled) |
| `audit_max_size_mb` | int | `100` | Audit log file rotation size |
| `audit_max_backups` | int | `3` | Number of audit log backups retained |

## MappingConfig

Defines one port forwarding rule:

```json
{
  "name": "string",
  "listen": "string",
  "target": "string",
  "protocol": "tcp|tcp+mtls|tcp+mesh",
  "tls": { "mode": "mtls|server|none", ... },
  "tcp_ext": { ... },
  "max_conns_per_ip": 10,
  "max_total_conns": 1000,
  "idle_timeout_sec": 300,
  "health_check_sec": 10,
  "health_check_timeout_sec": 5,
  "audit_file": "string",
  "audit_max_size_mb": 100,
  "audit_max_backups": 3
}
```

| Field | Type | Required | Description |
|------|------|------|------|
| `name` | string | Yes | Mapping name, used for identification and API management |
| `listen` | string | Yes | Listen address, format `host:port`; host may be omitted |
| `target` | string | Yes | Target address, format `host:port`; multiple comma-separated values enable round-robin |
| `protocol` | string | No | Protocol: `tcp` (plaintext, or TLS via `tls.mode`), `tcp+mtls` (mutual mTLS), `tcp+mesh` (Mesh) |
| `tls` | TLSConfig | No | TLS configuration; required when protocol=tcp+mtls |
| `tcp_ext` | TCPExtra | No | TCP-specific extension fields (see TCPExtra) |
| `max_conns_per_ip` | int | No | Max concurrent connections per IP |
| `max_total_conns` | int | No | Mapping-level max concurrent connections |
| `idle_timeout_sec` | int | No | Idle connection timeout |
| `health_check_sec` | int | No | Health check interval (seconds); inherits from defaults by default |
| `health_check_timeout_sec` | int | No | Health check timeout (seconds) |
| `audit_file` | string | No | Audit log file path; auditing is disabled if omitted |
| `audit_max_size_mb` | int | No | Audit log rotation size |
| `audit_max_backups` | int | No | Number of audit logs retained |

### protocol Details

| Protocol | Client Authentication | Use Case |
|------|-----------|----------|
| `tcp+mtls` | Certificate required | Zero-trust gateways, database proxies, management interfaces |
| `tcp` (`tls.mode=server`) | None | Encryption only, standard TLS proxy |
| `tcp` | None | Plaintext forwarding (debugging or internal networks only) |

## TLSConfig

```json
{
  "tls": {
    "mode": "mtls",
    "ca_cert_file": "/etc/pki/ca.crt",
    "cert_file": "/etc/pki/gateway.crt",
    "key_file": "/etc/pki/gateway.key",
    "crl_url": "http://crl.example.com/ca.crl",
    "crl_cache_ttl_sec": 900,
    "crl_timeout_sec": 10,
    "tsa_url": "http://tsa.example.com/tsa",
    "tsa_client_cert_file": "",
    "tsa_client_key_file": "",
    "tsa_cert_file": "",
    "allow_roles": ["admin", "readonly"],
    "audit_file": "",
    "max_conns_per_ip": 10,
    "max_total_conns": 1000,
    "idle_timeout_sec": 300,
    "audit_max_size_mb": 100,
    "audit_max_backups": 3
  },
  "tcp_ext": {
    "health_check_sec": 0,
    "health_check_url": ""
  }
}
```

| Field | Type | Required | Description |
|------|------|------|------|
| `mode` | string | No | TLS authentication mode: `none` / `server` / `mtls` |
| `ca_cert_file` | string | Yes | CA certificate file PEM |
| `cert_file` | string | Yes | Server certificate PEM |
| `key_file` | string | Yes | Server private key PEM |
| `crl_url` | string | Yes | CRL distribution point URL (HTTP/HTTPS supported) |
| `crl_cache_ttl_sec` | int | No | CRL cache TTL (default 900) |
| `crl_timeout_sec` | int | No | CRL download timeout (default 10) |
| `tsa_url` | string | No | TSA service URL; audit logs are not timestamp-signed when unset |
| `tsa_client_cert_file` | string | No | TSA client authentication certificate (if the TSA requires it) |
| `tsa_client_key_file` | string | No | TSA client private key |
| `tsa_cert_file` | string | No | TSA certificate file (used to verify timestamp signatures) |
| `allow_roles` | []string | No | Allowed roles list; all authenticated connections are allowed when unset |
| `audit_file` | string | No | Audit log file path |
| `max_conns_per_ip` | int | No | Max connections per IP |
| `max_total_conns` | int | No | Max total connections |
| `idle_timeout_sec` | int | No | Idle timeout |
| `disconnect_on_expiry` | bool | No | Proactively disconnect on certificate expiry (default true) |
| `cipher_suites` | []string | No | TLS cipher suite whitelist (AEAD suite set by default) |
| `min_tls_version` | string | No | Minimum TLS version (`"1.2"` or `"1.3"`, default `"1.2"`) |
| `audit_max_size_mb` | int | No | Log rotation size |
| `audit_max_backups` | int | No | Log backup count |

### TCPExtra (`tcp_ext` block)

TCP-specific extension fields:

| Field | Type | Required | Description |
|------|------|------|------|
| `health_check_sec` | int | No | Health check interval |
| `health_check_url` | string | No | HTTP health check URL (replaces TCP dialing when set) |

## TunnelConfig

Used for advanced tunnel configuration with additional transport-layer controls:

```json
{
  "name": "ssh-bastion",
  "listen": ":2222",
  "target": "10.0.0.1:22",
  "protocol": "tcp+mtls",
  "keepalive_sec": 30,
  "tcp_buf_size": 65536,
  "tls": { ... }
}
```

| Field | Type | Required | Description |
|------|------|------|------|
| `name` | string | Yes | Tunnel name |
| `listen` | string | Yes | Listen address |
| `target` | string | Yes | Target address |
| `protocol` | string | No | Same as MappingConfig |
| `keepalive_sec` | int | No | TCP keepalive interval (seconds) |
| `tcp_buf_size` | int | No | TCP read/write buffer size (bytes) |
| `tls` | TLSConfig | No | TLS configuration |

## ManagementConfig

```json
{
  "listen": ":7444",
  "tls": {
    "mode": "mtls",
    "allow_roles": ["admin"],
    "ca_cert_file": "/etc/pki/ca.crt",
    "cert_file": "/etc/pki/gateway-mgmt.crt",
    "key_file": "/etc/pki/gateway-mgmt.key",
    "crl_url": "http://crl.example.com/ca.crl"
  }
}
```

| Field | Type | Required | Description |
|------|------|------|------|
| `listen` | string | No | Management API listen address (default `:7444`) |
| `tls` | TLSConfig | No | Management API mTLS configuration; may use different certificates independently of the data plane |

## Complete Example

```json
{
  "defaults": {
    "tls": {
      "mode": "mtls",
      "ca_cert_file": "/etc/pki/ca.crt",
      "cert_file": "/etc/pki/gateway.crt",
      "key_file": "/etc/pki/gateway.key",
      "crl_url": "http://crl.example.com/ca.crl",
      "tsa_url": "http://tsa.example.com/tsa",
      "allow_roles": ["admin"],
      "max_conns_per_ip": 20,
      "max_total_conns": 2000,
      "idle_timeout_sec": 600,
      "audit_max_size_mb": 200,
      "audit_max_backups": 7,
      "disconnect_on_expiry": true,
      "health_check_url": "http://127.0.0.1:8080/health",
      "cipher_suites": ["TLS_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"],
      "min_tls_version": "1.2"
    },
    "protocol": "tcp+mtls",
    "health_check_sec": 15
  },
  "mappings": [
    {
      "name": "postgres-prod",
      "listen": ":7443",
      "target": "10.0.1.10:5432,10.0.1.11:5432",
      "tls": {
        "mode": "mtls",
        "allow_roles": ["admin"],
        "audit_file": "/var/log/gateway-tcp/pg.audit.jsonl"
      }
    },
    {
      "name": "redis-staging",
      "listen": ":7445",
      "target": "10.0.2.20:6379",
      "protocol": "tcp",
      "tls": {
        "mode": "server",
        "audit_file": "/var/log/gateway-tcp/redis-staging.audit.jsonl"
      }
    }
  ],
  "tunnels": [
    {
      "name": "ssh-bastion",
      "listen": ":2222",
      "target": "10.0.0.1:22",
      "keepalive_sec": 30
    }
  ],
  "management": {
    "listen": ":7444",
    "tls": {
      "mode": "mtls",
      "allow_roles": ["admin"],
      "audit_file": "/var/log/gateway-tcp/mgmt.audit.jsonl"
    }
  }
}
```
