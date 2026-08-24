# gateway-http Quick Start

> Zero-trust HTTP layer-7 reverse proxy | mTLS + path-level RBAC + gRPC/WebSocket + QUIC/HTTP3

## Installation

```bash
go build -o gateway-http .
```

## Minimal Configuration

```json
{
  "listeners": [{
    "name": "web-proxy",
    "listen": ":443",
    "protocol": "http2",
    "tls": {
      "mode": "mtls",
      "ca_cert_file": "/etc/pki/ca.pem",
      "cert_file": "/etc/pki/server.pem",
      "key_file": "/etc/pki/server.key"
    },
    "routes": [
      {"path": "/api/*", "target": "http://127.0.0.1:8080", "allow_roles": ["gateway:admin"]},
      {"path": "/health", "target": "http://127.0.0.1:8080"}
    ]
  }]
}
```

## Start

```bash
gateway-http --config /etc/varwof/gateway-http/gateway-http.json

# CLI mode
gateway-http \
  --listener name=web,listen=:443,protocol=http2,tls-mode=mtls,ca-cert=ca.pem,cert=server.pem,key=server.key \
  --route listener=web,path=/api/*,target=http://127.0.0.1:8080,allow-roles=gateway:admin
```

## Key Features

| Feature | Description |
|------|------|
| Protocol | http1 / http2 / h2c / grpc / ws / wss / h3 / quic (`tls.mode` decides none/server/mtls) |
| Path routing | Longest-prefix matching + wildcards |
| Path-level RBAC | per-route allow_roles |
| Backend protocols | h1 / h2 / h2c per-route |
| Certificate injection | X-Forwarded-Client-* headers |
| AIC injection | X-AIC-* headers to backend |
| WebSocket | Native upgrade proxying |
| gRPC | Transparent H2C/H2 proxying |
| QUIC/HTTP3 | QUIC stream tunnel |

## Next Steps

- [Configuration Reference](config_EN.md) — full configuration options
- [Usage Guide](usage_EN.md) — details on each mode
- [Examples](examples_EN.md) — real-world scenario configurations
- [Features](functions_EN.md) — API reference
