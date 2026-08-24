# CLI Reference

## Synopsis

```
gateway-tcp [--config <file> | --map <kv>...] [flags]
gateway-tcp server [flags]                         # default subcommand
gateway-tcp tunnel [--config <file> | --tunnel <kv>...] [flags]
gateway-tcp audit --entry <file> [--tsa-url <url>]
gateway-tcp help
```

Defaults to `server` mode when no subcommand is given. Shows help when arguments are missing.

## Subcommands

| Subcommand | Description |
|--------|------|
| `server` (default) | Start the TCP security gateway |
| `tunnel` | Start client tunnel mode |
| `audit` | Verify TSA timestamp signatures of audit logs |
| `help` | Show top-level help |

---

## server

### Usage

```
gateway-tcp server [flags]
gateway-tcp [flags]                    # equivalent when server is omitted
```

### Flags

| Flag | Short Alias | Type | Default | Description |
|------|--------|------|--------|------|
| `--config` | `-c` | string | auto-detect | Configuration file path (JSON) |
| `--lang` | `-l` | string | `en` | Language (`zh`/`en`) |
| `--map` | `-m` | string | — | Mapping definition (key=value,...), repeatable |
| `--tunnel` | `-t` | string | — | Tunnel definition (key=value,...), repeatable |
| `--crl-refresh-sec` | | int | `300` | Global CRL refresh interval (seconds) |
| `--ocsp-cache-ttl-sec` | | int | `300` | Global OCSP cache TTL (seconds) |
| `--ocsp-fallback` | | string | `allow` | OCSP fallback policy (`allow`/`deny`/`crl`) |
| `--tsa-url` | | string | — | TSA service URL |
| `--tsa-cert-file` | | string | — | TSA certificate file |
| `--audit-file` | | string | — | Audit log file path |
| `--audit-max-size-mb` | | int | `100` | Max audit log file size (MB) |
| `--audit-max-backups` | | int | `3` | Max audit log backups |
| `--management-listen` | | string | — | Management API listen address |
| `--mgmt-ca-cert` | | string | — | Management API CA certificate |
| `--mgmt-cert` | | string | — | Management API server certificate |
| `--mgmt-key` | | string | — | Management API server private key |
| `--mgmt-crl-url` | | string | — | Management API CRL URL |
| `--mgmt-ocsp-fallback` | | string | `allow` | Management API OCSP fallback policy |

### --map KV Format

Use `--map` (`-m`) to define mappings directly on the command line without a configuration file. Repeat the flag multiple times to define multiple mappings.

All keys use the **hyphenated** format. Supported keys:

| Key | Required | Description |
|-----|------|------|
| `name` | Yes | Mapping name |
| `listen` | Yes | Listen address (`host:port`) |
| `target` | Yes | Target address (`host:port`, comma-separated list for round-robin) |
| `protocol` | Yes | `tcp` / `tcp+mtls` / `tcp+mesh` |
| `ca-cert` | tcp+mtls protocol | CA certificate PEM path |
| `cert` | tcp+mtls protocol | Server certificate PEM path |
| `key` | tcp+mtls protocol | Server private key PEM path |
| `crl-url` | No | CRL distribution point URL |
| `crl-refresh-sec` | No | CRL refresh interval (seconds) |
| `ocsp-cache-ttl-sec` | No | OCSP cache TTL (seconds) |
| `ocsp-fallback` | No | OCSP fallback policy |
| `tsa-url` | No | TSA service URL |
| `tsa-cert-file` | No | TSA certificate file |
| `allow-roles` | No | Allowed roles list (semicolon-separated) |
| `audit-file` | No | Audit log file path |
| `max-conns-per-ip` | No | Max concurrent connections per IP |
| `max-total-conns` | No | Total concurrent connection limit |
| `idle-timeout-sec` | No | Idle timeout (seconds) |
| `health-check-sec` | No | Health check interval (seconds) |
| `health-check-url` | No | HTTP health check URL (replaces TCP dialing when set) |
| `disconnect-on-expiry` | No | Disconnect proactively on certificate expiry (set to `false` to disable) |
| `cipher-suites` | No | TLS cipher suite whitelist (semicolon-separated; see the `cipher_suites` table in the configuration reference) |
| `min-tls-version` | No | Minimum TLS version (`1.2`/`1.3`) |
| `audit-max-size-mb` | No | Audit log rotation size |
| `audit-max-backups` | No | Audit log backup count |

> **Note**: `--config` and `--map`/`--tunnel` are mutually exclusive and cannot be used together.

### --tunnel KV Format

| Key | Required | Description |
|-----|------|------|
| `name` | Yes | Tunnel name |
| `listen` | Yes | Listen address |
| `gateway-addr` | Yes | Gateway address |
| `cert-file` | Yes | Client certificate PEM |
| `key-file` | Yes | Client private key PEM |
| `ca-cert-file` | Yes | CA certificate PEM |

### Examples

```bash
# Using a configuration file
gateway-tcp --config /etc/varwof/gateway-tcp/server.json

# Define a single mapping on the command line with --map
gateway-tcp -m name=postgres,listen=:7443,target=db:5432,protocol=tcp+mtls,\
  ca-cert=/etc/pki/ca.crt,cert=/etc/pki/gw.crt,key=/etc/pki/gw.key,\
  crl-url=http://crl.example.com/ca.crl,allow-roles=admin

# Multiple mappings + global settings
gateway-tcp \
  -m name=web,listen=:8443,target=web:8080,protocol=tcp+mtls,ca-cert=ca.pem,cert=cert.pem,key=key.pem,allow-roles=admin \
  -m name=api,listen=:9443,target=api:8080,protocol=tcp+mtls,ca-cert=ca.pem,cert=cert.pem,key=key.pem,allow-roles=admin;readonly \
  --tsa-url http://tsa:3180/tsa \
  --audit-file /var/log/gateway-tcp/audit.jsonl

# Single-line mode (no spaces around equals signs)
gateway-tcp -m name=db,listen=:5443,target=pg:5432,protocol=tcp+mtls,ca-cert=ca.crt,cert=server.crt,key=server.key,crl-url=http://crl/ca.crl,disconnect-on-expiry=false,cipher-suites=TLS_AES_128_GCM_SHA256;TLS_AES_256_GCM_SHA384,min-tls-version=1.3
```

---

## tunnel

### Usage

```
gateway-tcp tunnel --config <file>
gateway-tcp tunnel --map <kv>...
```

### Flags

| Flag | Short Alias | Type | Default | Description |
|------|--------|------|--------|------|
| `--config` | `-c` | string | auto-detect | Configuration file path |
| `--lang` | `-l` | string | `en` | Language (`zh`/`en`) |
| `--map` | `-m` | string | — | Tunnel definition (key=value,...), repeatable |

### Examples

```bash
gateway-tcp tunnel --map name=bastion,listen=:2222,gateway-addr=10.0.0.1:7443,\
  cert-file=client.pem,key-file=client.key,ca-cert-file=ca.pem
```

---

## audit

### Usage

```
gateway-tcp audit --entry <file> [--tsa-url <url>] [--lang <lang>]
```

### Flags

| Flag | Short Alias | Type | Default | Description |
|------|--------|------|--------|------|
| `--entry` | | string | — | Audit log JSON file path (required) |
| `--tsa-url` | | string | — | TSA service URL |
| `--lang` | `-l` | string | `en` | Language |

### Examples

```bash
gateway-tcp audit --entry /var/log/gateway-tcp/audit.2026-07-05.jsonl \
  --tsa-url http://tsa:3180/tsa
```

---

## Environment Variables

| Variable | Description |
|------|------|
| `LANG` | Language detection (`zh_CN.UTF-8` → Chinese, otherwise → English); `--lang` and the configuration file `locale` take higher precedence |

---

## Mode Selection

| Condition | Behavior |
|------|------|
| No `--config`, no `--map`/`--tunnel` | Auto-detect the default configuration file path; show help if the file does not exist |
| Only `--config` | Read the JSON configuration file |
| Only `--map`/`--tunnel` | Build configuration from CLI flags, ignoring the configuration file |
| Both `--config` and `--map`/`--tunnel` | Exit with an error (mutually exclusive) |

---

## Configuration File Paths

| Platform | Default Path |
|------|---------|
| Linux | `/etc/varwof/gateway-tcp/server.json` |
| macOS | `/usr/local/etc/gateway-tcp/server.json` |
| Windows | `%ProgramData%\varwof\gateway-tcp\server.json` |

---

## Signals

| Signal | Behavior |
|------|------|
| `SIGINT` / `SIGTERM` | Graceful shutdown (waits for active connections to finish) |
| `SIGHUP` (Unix) | Hot-reload configuration |
| `POST /api/v1/gateway/reload` (Windows) | Hot-reload configuration |
