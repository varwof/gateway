# gateway-udp Examples

## Example 1: DNS Forwarding

```json
{
  "listeners": [{
    "name": "dns",
    "listen": ":5353",
    "protocol": "udp",
    "routes": [{"target": "8.8.8.8:53"}]
  }]
}
```

## Example 2: DTLS-Encrypted DNS

```json
{
  "listeners": [{
    "name": "dtls-dns",
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

## Example 3: mTLS DTLS + Audit

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
    "udp_ext": {
      "max_pkts_per_ip": 1000,
      "disconnect_on_expiry_sec": 60
    },
    "routes": [{"target": "8.8.8.8:53", "allow_roles": ["gateway:admin"]}]
  }]
}
```

## Example 4: QUIC/HTTP3 Proxy

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

## Example 5: CLI Quick Start

```bash
# Plain UDP
gateway-udp -L name=dns,listen=:5353,protocol=udp,routes=8.8.8.8:53

# DTLS
gateway-udp -L name=dtls,listen=:5354,protocol=dtls,cert=server.pem,key=server.key,routes=8.8.8.8:53

# mTLS + audit
gateway-udp \
  -L name=secure,listen=:5355,protocol=udp+mtls,ca-cert=ca.pem,cert=server.pem,key=server.key,allow-roles=gateway:admin,audit-file=/var/log/udp.log,routes=8.8.8.8:53

# QUIC
gateway-udp -L name=quic,listen=:4433,protocol=quic,cert=server.pem,key=server.key,routes=backend:8080
```

## Example 6: Management API

```bash
# Health check
curl -sk --cert admin.pem --key admin.key \
  https://127.0.0.1:9092/api/v1/gateway/health

# List listeners
curl -sk --cert admin.pem --key admin.key \
  https://127.0.0.1:9092/api/v1/gateway/listeners

# Audit logs
curl -sk --cert auditor.pem --key auditor.key \
  "https://127.0.0.1:9092/api/v1/gateway/audit?limit=10"

# Prometheus metrics
curl -sk --cert ops.pem --key ops.key \
  https://127.0.0.1:9092/api/v1/gateway/metrics
```

## Example 7: Python Client

```python
import requests

BASE = "https://127.0.0.1:9092/api/v1/gateway"

# Health check
r = requests.get(f"{BASE}/health",
    cert=("admin.pem", "admin.key"), verify=False)
print(r.json())

# Audit logs
r = requests.get(f"{BASE}/audit?limit=5",
    cert=("auditor.pem", "auditor.key"), verify=False)
for entry in r.json():
    print(f"[{entry['time']}] {entry['action']} - {entry['client_cn']}")
```

## Example 8: AIC + Capability Plugins

```json
{
  "capability_plugins": {
    "dns:query": {
      "type": "allowlist",
      "config": {
        "allowed": ["dns:query", "dns:zone-transfer"],
        "default_deny": true
      }
    }
  },
  "listeners": [{
    "name": "aic-dns",
    "listen": ":5355",
    "protocol": "udp+mtls",
    "tls": {
      "mode": "mtls",
      "ca_cert_file": "/etc/pki/ca.pem",
      "cert_file": "/etc/pki/server.pem",
      "key_file": "/etc/pki/server.key",
      "require_aic": true,
      "capability_scheme": "dns"
    },
    "routes": [{"target": "8.8.8.8:53", "allow_roles": ["gateway:admin"]}]
  }]
}
```
