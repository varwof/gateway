# gateway-tcp Quick Start

> Zero-trust Layer-4 TCP security gateway | mTLS mutual authentication + CRL/OCSP + RBAC + short-lived certificates

## Installation

```bash
go build -o gateway-tcp .
```

## Minimal Configuration File

```json
{
  "mappings": [
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
        "crl_url": "http://crl.example.com/ca.crl",
        "allow_roles": ["gateway:admin"]
      }
    }
  ]
}
```

## Start

```bash
# File configuration mode
gateway-tcp --config /etc/varwof/gateway-tcp/gateway-tcp.json

# CLI mode (no configuration file needed)
gateway-tcp \
  --listener name=db-proxy,listen=:8443,target=10.0.0.1:3306,protocol=tcp+mtls,ca-cert=/etc/pki/ca.pem

# Hot reload
kill -HUP <pid>
```

## Connection Test

```bash
# Client mTLS connection
openssl s_client -connect localhost:8443 \
  -cert client.pem -key client.key -CAfile ca.pem

# Management API
curl -sk --cert admin.pem --key admin.key \
  https://127.0.0.1:9090/api/v1/gateway/health
```

## Key Features

| Feature | Description |
|------|------|
| Protocols | tcp / tcp+mtls / tcp+mesh |
| Security pipeline | CRL → OCSP → RBAC → AIC → plugins |
| Connection limits | per-IP / per-cert / global |
| Idle timeout | idle_timeout_sec |
| Hard timeout | max_connection_duration_sec |
| Health check | TCP or HTTP probe |
| Tunnel mode | Client tunneling through mTLS |
| Mesh federation | Multi-gateway peer proxying |
| Hot reload | SIGHUP + POST /reload |
| Short-lived certificates | Automatic issuance + 30s renewal polling |
| Audit log | JSON Lines + Merkle hash chain |

## Next Steps

- [Configuration Reference](config.md) — Full configuration options
- [Usage Guide](usage.md) — Detailed mode descriptions
- [Examples](examples.md) — Real-world scenario configurations
- [Features](functions.md) — API reference
