# gateway-tcp Configuration Reference

## Configuration File Location

| Platform | Path |
|------|------|
| Linux | `/etc/varwof/gateway-tcp/gateway-tcp.json` |
| Windows | `%ProgramData%\varwof\gateway-tcp\gateway-tcp.json` |

`--config` / `-c` overrides the default path.

## Top-Level Configuration (Config)

```json
{
  "locale": "zh",
  "mappings": [...],
  "tunnels": [...],
  "management": {...},
  "peers": [...],
  "mesh_listen": ":9091",
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

| Field | Type | Required | Description |
|------|------|------|------|
| `locale` | string | No | `"zh"` or `"en"`; auto-detected by default |
| `mappings` | []MappingConfig | **Yes** | TCP port forwarding rules |
| `tunnels` | []TunnelConfig | No | Tunnel clients |
| `management` | ManagementConfig | No | Management API |
| `peers` | []MeshPeerConfig | No | Mesh peers |
| `mesh_listen` | string | No | Mesh listen address |
| `mesh_server_tls` | TLSConfig | No | Inbound Mesh server-side mTLS configuration (`ca_cert_file` verifies peer certificates; `cert_file`/`key_file` are this node's server certificate). Required when `mesh_listen` is configured; otherwise inbound listens in plaintext (recommended only for isolated internal networks) |
| `mesh_allowed_targets` | []string | No | Inbound Mesh forwarding target whitelist. When empty, only loopback and RFC1918/ULA/link-local private network targets are allowed (SSRF protection); entries may be added in forms such as `"10.0.0.5:8080"` (exact host:port), `"192.168.1.0/24"` (CIDR), `"*.internal.example:443"` (domain suffix) |
| `short_lived` | IssueConfig | No | Short-lived certificate auto-issuance |
| `varwof_core` | RevokerConfig | No | Varwof Core connection (revocation) |
| `capability_plugins` | PluginConfigs | No | Capability plugin configuration |
| `authorization_file` | string | No | Path to the authz.json policy file. When loaded successfully, it becomes the preferred source for RBAC role resolution |
| `capability_schemes` | string | No | Capability registry directory path (register specification). **When explicitly configured, enables data-plane capability registry validation** (opt-in, backward compatible): capabilities declared in the AIC must be registered, otherwise the connection is rejected (fail-closed). Directory layout `vendor/product/v*.json`; on-disk files override embedded schemes with the same name; changes to the JSON take effect immediately via SIGHUP hot reload. Without this setting, the data plane does not validate capability registration |
| `policy_signing` | PolicySigningConfig | No | PKCS#7 signature verification configuration for the policy file. When enabled, the signature is verified before loading authorization_file; the signer must be an admin certificate issued by this PKI (OU=admin/gateway:admin), and the CA chain is verified via `ca_file` (falls back to the first mapping's ca_cert_file by default); with `require: true`, loading is refused if the signature is missing |
| `audit_index_file` | string | No | Audit FTS index file path (bbolt). When set, enables the `GET /api/v1/gateway/audit/search` full-text search endpoint |
| `risk_monitor` | RiskMonitorConfig | No | Automatic handling rules for high-risk agents. When set, enables a reactive "behavior violation → disconnect + revoke" closed loop: the pipeline automatically records violation signals at behavior-level rejection points (plugin deny / parameter overflow / CIDR violation); once a rule threshold is reached, the gateway performs the disconnect (+ revocation) |
| `chain_peers` | ChainPeerConfig[] | No | Cross-gateway audit chain reference peer endpoints. Each entry is a peer gateway management API base URL (e.g. `https://gw2:9443`); the gateway periodically fetches the peer's `GET /api/v1/gateway/audit/chain` chain head and writes it into the local `ChainRefStore`, forming a cross-gateway audit evidence DAG (consensus-free ordering) |

`chain_peers` fields: `name` (peer gateway name), `url` (peer gateway management API base URL). TLS configuration reuses the management API client certificate.

### RiskMonitorConfig

```json
{
  "risk_monitor": {
    "rules": [
      {
        "name": "capability-abuse",
        "signals": ["plugin_deny", "parameter_overflow"],
        "threshold": 3,
        "window_seconds": 60,
        "action": "revoke",
        "reason": "repeated capability abuse"
      },
      {
        "name": "cidr-violation",
        "signals": ["out_of_cidr"],
        "threshold": 1,
        "window_seconds": 60,
        "action": "disconnect",
        "reason": "operation outside allowed CIDRs"
      }
    ]
  }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `rules[].name` | string | Yes | Rule name (audit/log identifier) |
| `rules[].signals` | []string | Yes | Trigger signal types: `plugin_deny` (capability plugin denial), `parameter_overflow` (parameter overflow), `out_of_cidr` (source IP out of range); `*` matches all |
| `rules[].threshold` | int | Yes | Violation count threshold within the window; handling triggers when reached |
| `rules[].window_seconds` | int | No | Counting window (seconds), default 60 |
| `rules[].action` | string | Yes | `disconnect` (kick) or `revoke` (kick + conditional revocation) |
| `rules[].reason` | string | Yes | Reason for the action (written to audit and logs) |

## MappingConfig

```json
{
  "name": "db-proxy",
  "listen": ":8443",
  "target": "10.0.0.1:3306",
  "protocol": "tcp+mtls",
  "tls": {
    "mode": "mtls",
    "ca_cert_file": "/etc/pki/ca.pem",
    "cert_file": "/etc/pki/server.pem",
    "key_file": "/etc/pki/server.key",
    "allow_roles": ["gateway:admin"]
  },
  "tcp_ext": {
    "max_connection_duration_sec": 3600
  }
}
```

| Field | Type | Required | Description |
|------|------|------|------|
| `name` | string | **Yes** | Unique mapping identifier |
| `listen` | string | **Yes** | Listen address (e.g. `:8443`, `127.0.0.1:8443`) |
| `target` | string | **Yes** | Backend address (e.g. `db:3306`) |
| `protocol` | string | **Yes** | `tcp` / `tcp+mtls` / `tcp+mesh` (see the Protocol table) |
| `tls` | TLSConfig | Conditional | Required when `protocol=tcp+mtls`; optional when `protocol=tcp` (`tls.mode: server/mtls` enables TLS/mTLS) |
| `tcp_ext` | TCPExtra | No | TCP-specific extension fields (connection duration/session timeout/constraint recheck/health check/dial timeout/renewal/delegation) |
| `mesh_peer` | string | Conditional | Required when `protocol=tcp+mesh` |

### Protocol

| Protocol | Effective TLS Mode | Description |
|------|-----------|------|
| `tcp` | `none` (default) / `server` / `mtls` | Plain TCP forwarding. Without a `tls` block it is plaintext; with `tls.mode=server` it enables one-way TLS, with `tls.mode=mtls` mutual mTLS |
| `tcp+mtls` | `mtls` | TCP + mutual mTLS (full mutual authentication + CRL/OCSP/RBAC). Always use this protocol when "client certificate authentication" is required; the `tls` block is required |
| `tcp+mesh` | mesh | Proxied through a Mesh peer (protocol enforces symmetric mTLS, W01); `mesh_peer` is required |

> **`client` mode is not supported (W07, 2026-08-16)**: the TLS server handshake must present a server certificate; "client certificate only" cannot be implemented in the listener role, and `mtls` already covers that semantic. Configuring `tls.mode:"client"` (or the legacy `tls_mode:"client"`) is explicitly rejected during startup validation, with an error message directing you to use `mtls` instead.

## TLSConfig

Unified TLS configuration block (all fields of the legacy `MTLSConfig` are collected here), located in the mapping's `tls` field. TCP-specific fields have been moved to `tcp_ext` (see TCPExtra).

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
    "required_capabilities": ["tcp:forward"],
    "capability_scheme": "custom"
  }
}
```

| Field | Type | Default | Description |
|------|------|--------|------|
| `mode` | string | — | TLS authentication mode: `none` / `server` / `mtls`. `protocol=tcp+mtls` implies `mtls` |
| `ca_cert_file` | string | Required (mtls) | CA certificate path |
| `cert_file` | string | — | Server certificate |
| `key_file` | string | — | Server private key |
| `min_tls_version` | string | `"1.2"` | Minimum TLS version |
| `cipher_suites` | []string | Secure defaults | TLS cipher suites |
| `crl_url` | string | — | CRL distribution point URL |
| `crl_refresh_sec` | int | 300 | CRL refresh interval |
| `ocsp_cache_ttl_sec` | int | 300 | OCSP cache TTL |
| `ocsp_fallback` | string | `"allow"` | OCSP failure policy: allow/deny/crl. **With `"allow"` (fail-open), remaining validity of offline certificates is forced to ≤1h (G2(b))** |
| `tsa_url` | string | — | TSA service URL |
| `tsa_cert_file` | string | — | TSA CA certificate |
| `allow_roles` | []string | — | Allowed RBAC roles |
| `audit_file` | string | — | Audit log path |
| `audit_max_size_mb` | int | 100 | Max audit file size in MB |
| `audit_max_backups` | int | 3 | Number of audit backups |
| `max_conns_per_ip` | int | 0 | Per-IP connection limit |
| `max_conns_per_cert` | int | 0 | Per-cert connection limit |
| `max_total_conns` | int | 0 | Global connection limit |
| `idle_timeout_sec` | int | 0 | Idle timeout (seconds), refreshed on activity (deadline rolls forward on every I/O so active connections are never cut off; 0 = unlimited) |
| `disconnect_on_expiry` | bool | true | Automatically disconnect on certificate expiry |
| `require_aic` | bool | false | Require the AIC extension |
| `disallow_representative` | bool | Same as require_aic | Disallow representative mode |
| `require_user_auth` | bool | false | Require a user certificate |
| `required_capabilities` | []string | — | Required AIC capabilities |
| `capability_scheme` | string | — | Capability scheme filter |

## TCPExtra (`tcp_ext` block)

TCP-specific extension fields, located in the mapping's `tcp_ext` field. The TCP-related fields of the legacy `MTLSConfig` have all moved into this block.

```json
{
  "tcp_ext": {
    "max_connection_duration_sec": 3600,
    "session_timeout_sec": 0,
    "constraint_recheck_sec": 0,
    "health_check_sec": 30,
    "health_check_url": "http://backend:8080/health",
    "dial_timeout_sec": 10,
    "renewal_enabled": true,
    "renewal_window_sec": 120,
    "require_delegation": false
  }
}
```

| Field | Type | Default | Description |
|------|------|--------|------|
| `max_connection_duration_sec` | int | 0 | Hard timeout (seconds), maximum connection lifetime (independent of idle timeout) |
| `session_timeout_sec` | int | 0 | Session validity period (seconds); 0 = unlimited |
| `constraint_recheck_sec` | int | 0 | Periodic re-check interval (seconds) for authorizationConstraints on long-lived connections. The TCP data plane consists of pass-through long-lived connections, so constraints are checked only once at handshake; time-decaying constraints such as time-window are not re-checked after their window passes (e.g. a night-window connection still alive during the day). When >0, AIC + PA constraints are re-evaluated at this interval; violations disconnect the connection and are audited; 0 = disabled (default) |
| `health_check_sec` | int | 0 | Health check interval |
| `health_check_url` | string | — | HTTP health check URL |
| `dial_timeout_sec` | int | 10 | Backend dial timeout (seconds); 0 or unset = 10 (W38, configurable) |
| `renewal_enabled` | bool | false | Enable certificate renewal |
| `renewal_window_sec` | int | 120 | Renewal window (seconds) |
| `require_delegation` | bool | false | Dual-certificate mode (Agent + User) |

## TunnelConfig

```json
{
  "name": "client-tunnel",
  "listen": "127.0.0.1:3306",
  "gateway_addr": "gateway.example.com:8443",
  "cert_file": "/etc/pki/client.pem",
  "key_file": "/etc/pki/client.key",
  "ca_cert_file": "/etc/pki/ca.pem"
}
```

| Field | Type | Required | Description |
|------|------|------|------|
| `name` | string | **Yes** | Tunnel identifier |
| `listen` | string | **Yes** | Local listen address |
| `gateway_addr` | string | **Yes** | Remote gateway address |
| `cert_file` | string | **Yes** | Client certificate |
| `key_file` | string | **Yes** | Client private key |
| `ca_cert_file` | string | **Yes** | CA certificate |

## ManagementConfig

```json
{
  "management": {
    "listen": ":9090",
    "tls": {
      "mode": "mtls",
      "ca_cert_file": "/etc/pki/ca.pem",
      "cert_file": "/etc/pki/mgmt.pem",
      "key_file": "/etc/pki/mgmt.key"
    }
  }
}
```

## MeshPeerConfig

```json
{
  "peers": [
    {
      "name": "gateway-b",
      "addr": "10.0.0.2:9091",
      "ca_cert_file": "/etc/pki/ca.pem",
      "cert_file": "/etc/pki/peer.pem",
      "key_file": "/etc/pki/peer.key"
    }
  ]
}
```

## CLI Flags

### Global Flags

| Flag | Short | Type | Default | Description |
|------|------|------|--------|------|
| `--config` | `-c` | string | Platform default | Configuration file path |
| `--lang` | `-l` | string | Auto | Language |
| `--listener` | `-L` | KV | — | Mapping definition (repeatable) |
| `--tunnel` | `-t` | KV | — | Tunnel definition (repeatable) |
| `--crl-refresh-sec` | | int | 300 | CRL refresh |
| `--ocsp-cache-ttl-sec` | | int | 300 | OCSP TTL |
| `--ocsp-fallback` | | string | allow | OCSP fallback |
| `--tsa-url` | | string | — | TSA URL |
| `--audit-file` | | string | — | Audit file |
| `--management-listen` | | string | — | Management API address |

`--config` and `--listener` are mutually exclusive.

### --map KV Keys

`name`, `listen`, `target`, `protocol`, `ca-cert`, `cert`, `key`, `allow-roles` (semicolon-separated), `crl-url`, `crl-refresh-sec`, `ocsp-cache-ttl-sec`, `ocsp-fallback`, `tsa-url`, `audit-file`, `max-conns-per-ip`, `max-total-conns`, `idle-timeout-sec`, `health-check-sec`, `health-check-url`, `disconnect-on-expiry`, `cipher-suites` (semicolon-separated), `min-tls-version`, `audit-max-size-mb`, `audit-max-backups`

## Management API Endpoints

| Method | Path | Roles | Description |
|------|------|------|------|
| GET | `/api/v1/gateway/health` | Public | Health check |
| GET | `/api/v1/gateway/metrics` | ops, admin | Prometheus metrics |
| GET | `/api/v1/gateway/audit` | audit, admin | Audit log query |
| POST | `/api/v1/gateway/audit/verify` | audit, admin | Merkle hash chain verification |
| GET | `/api/v1/gateway/mappings` | admin | List TCP mappings |
| POST | `/api/v1/gateway/mappings` | admin | Add a TCP mapping |
| DELETE | `/api/v1/gateway/mappings/{name}` | admin | Delete a TCP mapping |
| GET | `/api/v1/gateway/plugins` | ops, admin | List capability plugins |
| GET | `/api/v1/gateway/plugins/{scheme}` | ops, admin | View a single plugin |
| PUT | `/api/v1/gateway/plugins` | admin | Replace all plugins |
| DELETE | `/api/v1/gateway/plugins` | admin | Clear all plugins |
| POST | `/api/v1/gateway/disconnect-agent` | admin | Disconnect by Agent ID |
| POST | `/api/v1/gateway/disconnect-user` | admin | Disconnect by Principal UID |
| POST | `/api/v1/gateway/reload` | admin | Hot-reload configuration |
| POST | `/api/v1/gateway/crl/reload` | admin | Force CRL refresh |
| GET | `/api/v1/gateway/peers` | ops | List Mesh peers |
| POST | `/api/v1/gateway/renew` | ops, admin | Short-lived certificate renewal |
