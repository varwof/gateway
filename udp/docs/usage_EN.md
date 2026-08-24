# gateway-udp Usage Guide

## Plain UDP Forwarding

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

Directly forwards UDP packets without encryption. Suitable for scenarios such as internal network DNS forwarding.

## DTLS Encryption

```json
{
  "listeners": [{
    "name": "dtls-proxy",
    "listen": ":5354",
    "protocol": "dtls",
    "tls": {
      "mode": "server",
      "cert_file": "/etc/pki/server.pem",
      "key_file": "/etc/pki/server.key"
    },
    "routes": [{"target": "8.8.8.8:53"}]
  }]
}
```

Server-side DTLS encryption; clients must connect using a DTLS library.

## mTLS DTLS (Mutual Authentication)

```json
{
  "listeners": [{
    "name": "secure-dns",
    "listen": ":5355",
    "protocol": "udp+mtls",
    "tls": {
      "mode": "mtls",
      "ca_cert_file": "/etc/pki/ca.pem",
      "cert_file": "/etc/pki/server.pem",
      "key_file": "/etc/pki/server.key",
      "crl_url": "http://crl.example.com/ca.crl",
      "allow_roles": ["gateway:admin"],
      "audit_file": "/var/log/gateway/udp-audit.log"
    },
    "routes": [{"target": "8.8.8.8:53", "allow_roles": ["gateway:admin"]}]
  }]
}
```

Full security pipeline: CRL → OCSP → RBAC → AIC → Plugins

## QUIC/HTTP3

```json
{
  "listeners": [{
    "name": "quic-proxy",
    "listen": ":4433",
    "protocol": "quic",
    "tls": {
      "mode": "mtls",
      "ca_cert_file": "/etc/pki/ca.pem",
      "cert_file": "/etc/pki/server.pem",
      "key_file": "/etc/pki/server.key"
    },
    "routes": [{"target": "backend:8080"}]
  }]
}
```

QUIC stream multiplexing, supporting HTTP3 requests or raw QUIC stream tunnels.

## Packet Rate Limiting

```json
{
  "tls": {
    "max_conns_per_ip": 10
  },
  "udp_ext": {
    "max_pkts_per_ip": 1000,
    "max_total_pkts": 100000,
    "connection_bps": 1000000,
    "connection_burst": 1000000
  }
}
```

| Limit Type | Description |
|---------|------|
| per-IP packet rate | Maximum packets per second |
| Global packet total | Total packet count limit |
| per-IP connections | QUIC maximum concurrent connections (`tls.max_conns_per_ip`) |
| per-connection BPS | Byte-level rate limiting |

## Automatic Disconnect on Certificate Expiry

```json
{
  "udp_ext": {
    "disconnect_on_expiry_sec": 60
  }
}
```

Connections are automatically disconnected within 60 seconds after certificate expiry, with an audit log entry recorded.

## Latency Metrics

The UDP gateway uses the `ProxyLatency` histogram to track packet forwarding latency:

```
pki_gateway_udp_proxy_latency_seconds{listener="...",target="..."}
```

Buckets: 1ms, 5ms, 10ms, 50ms, 100ms, 500ms, 1s, 5s

## Hot Reload

```bash
kill -HUP <pid>
# or
curl -sk --cert admin.pem --key admin.key -X POST \
  https://127.0.0.1:9092/api/v1/gateway/reload
```

## Structured Logging

All logs are output in `key=value` format:

```
time=2026-07-09T10:00:00Z level=INFO msg="DTLS connection established" listener=dtls-proxy client_cn=admin@example.com
time=2026-07-09T10:00:01Z level=WARN msg="RBAC denied" listener=dtls-proxy client_cn=unknown reason="no matching role"
```
