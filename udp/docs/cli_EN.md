# CLI Reference

## Usage

```
gateway-udp [--config <file> | --listener <kv>...] [flags]
```

## Global Flags

| Flag | Short | Description |
|------|------|------|
| `--config <file>` | `-c` | JSON configuration file path |
| `--lang <lang>` | `-l` | Language (zh/en) |
| `--listener <kv>` | `-L` | Listener definition (key=value, repeatable) |

## Listener key=value Format

```
name=<name>,listen=<addr>,protocol=<udp|dtls|udp+mtls|quic>,
ca-cert=<path>,cert=<path>,key=<path>,
routes=<target>[;<target>...],
allow-roles=<role>[;<role>...],
crl-url=<url>,crl-refresh-sec=<n>,
ocsp-url=<url>,ocsp-cache-ttl-sec=<n>,ocsp-fallback=<s>,
audit-file=<path>,audit-max-size-mb=<n>,audit-max-backups=<n>
```

## TSA Flags

| Flag | Description |
|------|------|
| `--tsa-url <url>` | TSA server URL |
| `--tsa-cert-file <path>` | TSA client certificate |
| `--tsa-proof-file <path>` | TSA audit proof log |
| `--tsa-proof-interval-sec <n>` | TSA proof interval |

## Management API Flags

| Flag | Description |
|------|------|
| `--management-listen <addr>` | Management API listen address |
| `--mgmt-ca-cert <path>` | Management API CA certificate |
| `--mgmt-cert <path>` | Management API server certificate |
| `--mgmt-key <path>` | Management API server key |

## Audit Flags

| Flag | Description |
|------|------|
| `--audit-file <path>` | Audit log file path |
| `--audit-max-size-mb <n>` | Audit log max size in MB (default 100) |
| `--audit-max-backups <n>` | Audit log backup count (default 3) |
