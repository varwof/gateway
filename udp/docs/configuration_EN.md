# Configuration Reference

## JSON Structure

```json
{
  "listeners": [
    {
      "name": "dns-proxy",
      "listen": "127.0.0.1:5353",
      "protocol": "udp+mtls",
      "read_timeout_sec": 30,
      "max_packet_size": 4096,
      "tls": {
        "mode": "mtls",
        "ca_cert_file": "/etc/varwof/gateway-udp/ca.pem",
        "cert_file": "/etc/varwof/gateway-udp/server.pem",
        "key_file": "/etc/varwof/gateway-udp/server.key",
        "crl_url": "http://crl.example.com/ca.crl",
        "crl_refresh_sec": 1800,
        "ocsp_cache_ttl_sec": 300,
        "ocsp_fallback": "allow | deny",
        "allow_roles": ["gateway:admin"],
        "audit_file": "/var/log/gateway-udp/audit.log",
        "audit_max_size_mb": 100,
        "audit_max_backups": 3
      },
      "udp_ext": {
        "max_pkts_per_ip": 1000
      },
      "routes": [
        { "target": "8.8.8.8:53" }
      ]
    }
  ],
  "tsa_proof_file": "/var/log/gateway-udp/tsa-proof.log",
  "tsa_proof_interval_sec": 3600,
  "management": {
    "listen": "127.0.0.1:9092",
    "tls": {
      "mode": "mtls",
      "ca_cert_file": "/etc/varwof/gateway-udp/ca.pem",
      "cert_file": "/etc/varwof/gateway-udp/management.pem",
      "key_file": "/etc/varwof/gateway-udp/management.key"
    }
  }
}
```

## Protocol Modes

| protocol | Transport | Authentication | Use Case |
|------|------|------|------|
| `udp` | Plaintext UDP | None | DNS forwarding, performance-first |
| `dtls` | DTLS encryption | Server certificate | Secure tunnel, strong compatibility |
| `udp+mtls` | DTLS encryption | Mutual mTLS + RBAC | VPN, enterprise-grade security |
| `quic` | QUIC | Built-in TLS 1.3 (mTLS optional) | HTTP3, high performance |

## TLS Configuration

| Field | Required | Description |
|------|------|------|
| `mode` | No | `none` / `server` / `mtls`; derived from `protocol` when unset |
| `ca_cert_file` | udp+mtls | CA certificate for verifying clients |
| `cert_file` | dtls/udp+mtls/quic | Server certificate (including intermediate CA) |
| `key_file` | dtls/udp+mtls/quic | Server private key |
| `crl_url` | No | CRL download URL |
| `crl_refresh_sec` | No | CRL refresh interval (default 1800) |
| `ocsp_cache_ttl_sec` | No | OCSP cache TTL (default 300) |
| `ocsp_fallback` | No | OCSP failure fallback policy |
| `allow_roles` | No | Allowed roles list |
| `audit_file` | No | Audit log path |

## UDP Extension Configuration (udp_ext)

| Field | Description |
|------|------|
| `max_pkts_per_ip` | per-IP packet rate limit |
| `max_total_pkts` | Global total packet limit |
| `connection_bps` | per-connection byte rate limit |
| `connection_burst` | per-connection burst capacity |
| `disconnect_on_expiry_sec` | Auto-disconnect on certificate expiry (seconds) |

## TSA Configuration

| Field | Description |
|------|------|
| `tsa_url` | TSA server address |
| `tsa_proof_file` | TSA audit proof log |
| `tsa_proof_interval_sec` | Proof interval (seconds) |

## Management API

| Endpoint | Method | Description | Permission |
|------|------|------|------|
| `/api/v1/gateway/listeners` | GET | List listeners | admin |
| `/api/v1/gateway/listeners` | POST | Add listener | admin |
| `/api/v1/gateway/listeners/` | DELETE | Delete listener | admin |
| `/api/v1/gateway/audit` | GET | Query audit logs | audit+admin |
| `/api/v1/gateway/reload` | POST | Hot reload configuration | admin |
| `/api/v1/gateway/health` | GET | Health check | Public |
| `/api/v1/gateway/metrics` | GET | Prometheus metrics | ops+admin |
