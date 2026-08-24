# gateway-udp 示例

## 示例 1：DNS 转发

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

## 示例 2：DTLS 加密 DNS

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

## 示例 3：mTLS DTLS + 审计

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

## 示例 4：QUIC/HTTP3 代理

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

## 示例 5：CLI 快速启动

```bash
# Plain UDP
gateway-udp -L name=dns,listen=:5353,protocol=udp,routes=8.8.8.8:53

# DTLS
gateway-udp -L name=dtls,listen=:5354,protocol=dtls,cert=server.pem,key=server.key,routes=8.8.8.8:53

# mTLS + 审计
gateway-udp \
  -L name=secure,listen=:5355,protocol=udp+mtls,ca-cert=ca.pem,cert=server.pem,key=server.key,allow-roles=gateway:admin,audit-file=/var/log/udp.log,routes=8.8.8.8:53

# QUIC
gateway-udp -L name=quic,listen=:4433,protocol=quic,cert=server.pem,key=server.key,routes=backend:8080
```

## 示例 6：管理 API

```bash
# 健康检查
curl -sk --cert admin.pem --key admin.key \
  https://127.0.0.1:9092/api/v1/gateway/health

# 列出监听器
curl -sk --cert admin.pem --key admin.key \
  https://127.0.0.1:9092/api/v1/gateway/listeners

# 审计日志
curl -sk --cert auditor.pem --key auditor.key \
  "https://127.0.0.1:9092/api/v1/gateway/audit?limit=10"

# Prometheus 指标
curl -sk --cert ops.pem --key ops.key \
  https://127.0.0.1:9092/api/v1/gateway/metrics
```

## 示例 7：Python 客户端

```python
import requests

BASE = "https://127.0.0.1:9092/api/v1/gateway"

# 健康检查
r = requests.get(f"{BASE}/health",
    cert=("admin.pem", "admin.key"), verify=False)
print(r.json())

# 审计日志
r = requests.get(f"{BASE}/audit?limit=5",
    cert=("auditor.pem", "auditor.key"), verify=False)
for entry in r.json():
    print(f"[{entry['time']}] {entry['action']} - {entry['client_cn']}")
```

## 示例 8：AIC + 能力插件

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
