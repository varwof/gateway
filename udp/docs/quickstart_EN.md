# gateway-udp Quick Start

> Zero-trust UDP layer-3 security gateway | Plain UDP / DTLS / mTLS DTLS / QUIC/HTTP3

## Installation

```bash
go build -o gateway-udp .
```

## Minimal Configuration

```json
{
  "listeners": [{
    "name": "dns-forward",
    "listen": ":5353",
    "protocol": "udp",
    "routes": [{"target": "8.8.8.8:53"}]
  }]
}
```

## Launch

```bash
gateway-udp --config /etc/varwof/gateway-udp/gateway-udp.json

# CLI mode
gateway-udp -L name=dns,listen=:5353,protocol=udp,routes=8.8.8.8:53

# DTLS mode
gateway-udp -L name=dtls,listen=:5354,protocol=dtls,cert=server.pem,key=server.key,routes=8.8.8.8:53
```

## Protocol Modes

| protocol | Description |
|------|------|
| `udp` | Plaintext UDP forwarding |
| `dtls` | DTLS encryption (server certificate) |
| `udp+mtls` | Mutual mTLS DTLS (full security pipeline) |
| `quic` | QUIC/HTTP3 proxy |

## Key Features

| Feature | Description |
|------|------|
| UDP packet forwarding | Hash-based route distribution |
| per-IP rate limiting | Packet rate limits |
| Global limits | Total packet count limit |
| per-IP QUIC connections | max_conns_per_ip |
| TokenBucket | per-connection byte-level rate limiting |
| Certificate expiry disconnect | Automatic audit + disconnect |
| Audit logging | DTLS/QUIC connections + RBAC denials |
| Latency metrics | ProxyLatency histogram |
| Management API | mTLS + RBAC |
| Hot reload | SIGHUP |

## Next Steps

- [Configuration Reference](config.md) — Full configuration options
- [Usage Guide](usage.md) — Detailed explanation of each mode
- [Examples](examples.md) — Real-world scenario configurations
- [Features](functions.md) — API reference
