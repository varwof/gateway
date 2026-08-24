# gateway-udp 使用指南

## Plain UDP 转发

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

直接转发 UDP 包，无加密。适用于内部网络 DNS 转发等场景。

## DTLS 加密

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

服务端 DTLS 加密，客户端需使用 DTLS 库连接。

## mTLS DTLS（双向认证）

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

完整安全管线：CRL → OCSP → RBAC → AIC → 插件

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

QUIC 流多路复用，支持 HTTP3 请求或原始 QUIC 流隧道。

## 包速率限制

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

| 限制类型 | 说明 |
|---------|------|
| per-IP 包速率 | 每秒最大包数 |
| 全局包总量 | 总包数限制 |
| per-IP 连接数 | QUIC 最大并发连接（`tls.max_conns_per_ip`） |
| per-connection BPS | 字节级限速 |

## 证书过期自动断开

```json
{
  "udp_ext": {
    "disconnect_on_expiry_sec": 60
  }
}
```

证书过期后 60 秒内自动断开连接，记录审计日志。

## 延迟指标

UDP 网关使用 `ProxyLatency` 直方图跟踪包转发延迟：

```
pki_gateway_udp_proxy_latency_seconds{listener="...",target="..."}
```

桶：1ms, 5ms, 10ms, 50ms, 100ms, 500ms, 1s, 5s

## 热重载

```bash
kill -HUP <pid>
# 或
curl -sk --cert admin.pem --key admin.key -X POST \
  https://127.0.0.1:9092/api/v1/gateway/reload
```

## 结构化日志

所有日志输出为 `key=value` 格式：

```
time=2026-07-09T10:00:00Z level=INFO msg="DTLS connection established" listener=dtls-proxy client_cn=admin@example.com
time=2026-07-09T10:00:01Z level=WARN msg="RBAC denied" listener=dtls-proxy client_cn=unknown reason="no matching role"
```
