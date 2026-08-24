# Varwof Gateway Quick Start

> Zero-trust security gateway | TCP/HTTP/UDP three protocols | mTLS + CRL/OCSP + RBAC + short-lived certificates

## Installation

```bash
go build -o gateway-tcp ./cmd/tcp
go build -o gateway-http ./cmd/http
go build -o gateway-udp ./cmd/udp
```

## Minimal Configuration

```json
{
  "server": {
    "tls_mode": "mtls",
    "cert_file": "/etc/pki/server.pem",
    "key_file": "/etc/pki/server-key.pem",
    "client_ca_file": "/etc/pki/ca.pem"
  },
  "listeners": [
    {
      "name": "https",
      "listen": ":443",
      "protocol": "http",
      "tls_mode": "mtls"
    }
  ]
}
```

## Starting

```bash
# HTTP gateway (file configuration)
gateway-http --config config.json

# TCP gateway (CLI mode)
gateway-tcp \
  --listener name=db,listen=:8443,target=10.0.0.1:3306,tls-mode=mtls,ca-cert=ca.pem

# UDP gateway
gateway-udp --config udp-config.json

# Hot reload (common to all three gateways)
kill -HUP <pid>
```

## Connection Testing

```bash
# mTLS connection test
openssl s_client -connect localhost:8443 \
  -cert client.pem -key client.key -CAfile ca.pem

# Management API health check
curl -sk --cert admin.pem --key admin.key \
  https://127.0.0.1:9443/api/v1/gateway/health
```

## Three-Protocol Feature Overview

| Feature | TCP | HTTP | UDP |
|------|-----|------|-----|
| TLS modes | plain/server/mtls/mesh | plain/mtls | plain/dtls/mtls/quic |
| RBAC | ✓ | Path-level | ✓ |
| Connection limits | per-IP/per-cert/global | Concurrent connection limit | per-IP packet rate |
| Audit logs | ✓ | ✓ | ✓ (DTLS/QUIC) |
| Short-lived certificates | ✓ | ✓ | ✓ |
| Hot reload | SIGHUP + API | SIGHUP + API | SIGHUP + API |
| Mesh federation | ✓ | — | — |

## Next Steps

- [API Reference](api.md) — All management API endpoints
- [Configuration Reference](config.md) — Full configuration fields
- [CLI Reference](cli.md) — Command-line arguments
