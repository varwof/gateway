# CLI Reference

## Synopsis

```
gateway-http [--config <file> | --listener <kv>... --route <kv>...] [flags]
gateway-http server [flags]                    # default subcommand
gateway-http help
```

Without a subcommand, defaults to `server` mode. Shows help when arguments are insufficient.

## Subcommands

| Subcommand | Description |
|--------|------|
| `server` (default)| Starts the HTTP reverse proxy gateway |
| `help` | Shows help |

---

## server

### Usage

```
gateway-http server [flags]
gateway-http [flags]                    # equivalent when server is omitted
```

### Flags

| Flag | Short | Type | Default | Description |
|------|--------|------|--------|------|
| `--config` | `-c` | string | auto-detected | Configuration file path (JSON) |
| `--lang` | `-l` | string | `en` | Language (`zh`/`en`) |
| `--listener` | `-L` | string | — | Listener definition (key=value,...), repeatable |
| `--route` | `-r` | string | — | Route definition (key=value,...), repeatable |
| `--crl-refresh-sec` | | int | `300` | Global CRL refresh interval (seconds) |
| `--ocsp-cache-ttl-sec` | | int | `300` | Global OCSP cache TTL (seconds) |
| `--ocsp-fallback` | | string | `allow` | OCSP fallback policy (`allow`/`deny`/`crl`) |
| `--tsa-url` | | string | — | TSA service URL |
| `--audit-file` | | string | — | Audit log file path |
| `--audit-max-size-mb` | | int | `100` | Maximum audit log file size (MB) |
| `--audit-max-backups` | | int | `3` | Maximum number of audit log backups |
| `--management-listen` | | string | — | Management API listen address |
| `--mgmt-ca-cert` | | string | — | Management API CA certificate |
| `--mgmt-cert` | | string | — | Management API server certificate |
| `--mgmt-key` | | string | — | Management API server private key |
| `--mgmt-crl-url` | | string | — | Management API CRL URL |
| `--mgmt-ocsp-fallback` | | string | `allow` | Management API OCSP fallback policy |

### --listener KV Format

Use `--listener` (`-L`) to define listeners directly on the command line. Repeat the flag to define multiple listeners.

All keys use **hyphenated** format; supported keys:

| Key | Required | Description |
|-----|------|------|
| `name` | Yes | Listener name (matches the route's `listener` field) |
| `listen` | Yes | Listen address (`:port` or `host:port`) |
| `protocol` | No | Protocol (`http1`/`http2`/`h2c`/`grpc`/`ws`/`wss`/`h3`/`quic`), defaults to `http2` |
| `tls-mode` | No | TLS authentication mode (compatibility key): `server`/`mtls`, defaults to `none` (cleartext). With the default `protocol=http2` this is equivalent to `protocol=http2,tls-mode=...` |
| `ca-cert` | mtls mode | CA certificate PEM path |
| `cert` | server/mtls mode | Server certificate PEM path |
| `key` | server/mtls mode | Server private key PEM path |
| `crl-url` | No | CRL distribution point URL |
| `crl-refresh-sec` | No | CRL refresh interval (seconds) |
| `ocsp-cache-ttl-sec` | No | OCSP cache TTL (seconds) |
| `ocsp-fallback` | No | OCSP fallback policy |
| `tsa-url` | No | TSA service URL |
| `audit-file` | No | Audit log file path |
| `max-conns-per-ip` | No | Maximum concurrent connections per IP |
| `max-conns-per-cert` | No | Maximum concurrent connections per certificate |
| `max-total-conns` | No | Total concurrent connection limit |
| `idle-timeout-sec` | No | Idle timeout (seconds) |
| `read-header-timeout-sec` | No | Request header read timeout (seconds) |
| `write-timeout-sec` | No | Response write timeout (seconds) |
| `disconnect-on-expiry` | No | Reject requests when the certificate has expired (set to `false` to disable) |
| `forward-client-cert` | No | Forward client certificate information to the backend (set to `false` to disable) |
| `forward-client-cert-der` | No | Certificate pass-through (B2): forwards the verified client certificate to the backend via `X-Client-Cert-DER` (set to `true` to enable) |
| `tls-termination` | No | TLS termination + AIC header injection (set to `false` to disable) |
| `cipher-suites` | No | TLS cipher suite allowlist (semicolon-separated) |
| `min-tls-version` | No | Minimum TLS version (`1.2`/`1.3`) |
| `audit-max-size-mb` | No | Audit log rotation size |
| `audit-max-backups` | No | Number of audit log backups |

### --route KV Format

Use `--route` (`-r`) to define routing rules. Multiple routes are associated with their listener via the `listener` field.

| Key | Required | Description |
|-----|------|------|
| `listener` | Yes | Owning listener name (matches `--listener name=`) |
| `path` | Yes | URL path (supports the `*` wildcard) |
| `target` | Yes | Backend target URL (e.g. `http://127.0.0.1:8080`) |
| `allow-roles` | No | Allowed role list (semicolon-separated) |

> **Note**: `--config` and `--listener`/`--route` are mutually exclusive and cannot be used together.

### Examples

```bash
# Use a configuration file
gateway-http --config /etc/varwof/gateway-http/gateway-http.json

# Define listeners and routes on the command line with --listener + --route
gateway-http \
  -L name=api,listen=:4433,protocol=http2,tls-mode=mtls,ca-cert=ca.pem,cert=cert.pem,key=key.pem,crl-url=http://crl/ca.crl \
  -r listener=api,path=/api/v1,target=http://be:8080,allow-roles=gateway:admin \
  -r listener=api,path=/,target=http://web:3000 \
  --tsa-url http://tsa:3180/tsa

# Single-line mode
gateway-http -L name=mtls,listen=:443,protocol=http2,tls-mode=mtls,ca-cert=ca.pem,cert=cert.pem,key=key.pem,disconnect-on-expiry=true,forward-client-cert=false,cipher-suites=TLS_AES_128_GCM_SHA256,min-tls-version=1.3 -r listener=mtls,path=/api/*,target=http://backend:8080,allow-roles=gateway:admin

# Plain HTTP (cleartext, h2c) mode
gateway-http -L name=plain,listen=:8080,protocol=h2c -r listener=plain,path=/*,target=http://app:3000
```

---

## Environment Variables

| Variable | Description |
|------|------|
| `LANG` | Language detection (`zh_CN.UTF-8` → Chinese, others → English); `--lang` and the config file's `locale` take higher precedence |

---

## Mode Selection

| Condition | Behavior |
|------|------|
| No `--config`, no `--listener`/`--route` | Auto-detects the default configuration file path; shows help if the file does not exist |
| Only `--config` | Reads the JSON configuration file |
| Only `--listener`/`--route` | Builds the configuration from CLI flags, ignoring the configuration file |
| Both `--config` and `--listener`/`--route` | Exits with an error (mutually exclusive) |

---

## Configuration File Paths

| Platform | Default Path |
|------|---------|
| Linux | `/etc/varwof/gateway-http/gateway-http.json` |
| Windows | `%ProgramData%\varwof\gateway-http\gateway-http.json` |

---

## Signals

| Signal | Behavior |
|------|------|
| `SIGINT` / `SIGTERM` | Graceful shutdown |
| `SIGHUP` (Unix) | Hot-reloads configuration |
| `POST /api/v1/gateway/reload` (Windows) | Hot-reloads configuration |
