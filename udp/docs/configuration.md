# 配置参考

## JSON 结构

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

## Protocol 模式

| protocol | 传输 | 认证 | 用途 |
|------|------|------|------|
| `udp` | UDP 明文 | 无 | DNS 转发，性能优先 |
| `dtls` | DTLS 加密 | 服务端证书 | 安全隧道，兼容性强 |
| `udp+mtls` | DTLS 加密 | 双向 mTLS + RBAC | VPN，企业级安全 |
| `quic` | QUIC | 内置 TLS 1.3（可 mTLS） | HTTP3，高性能 |

## TLS 配置

| 字段 | 必需 | 说明 |
|------|------|------|
| `mode` | 否 | `none` / `server` / `mtls`；缺省由 `protocol` 推导 |
| `ca_cert_file` | udp+mtls | CA 证书，用于验证客户端 |
| `cert_file` | dtls/udp+mtls/quic | 服务端证书（含中间 CA） |
| `key_file` | dtls/udp+mtls/quic | 服务端私钥 |
| `crl_url` | 否 | CRL 下载地址 |
| `crl_refresh_sec` | 否 | CRL 刷新间隔（默认 1800） |
| `ocsp_cache_ttl_sec` | 否 | OCSP 缓存 TTL（默认 300） |
| `ocsp_fallback` | 否 | OCSP 故障降级策略 |
| `allow_roles` | 否 | 允许的角色列表 |
| `audit_file` | 否 | 审计日志路径 |

## UDP 扩展配置（udp_ext）

| 字段 | 说明 |
|------|------|
| `max_pkts_per_ip` | per-IP 包速率限制 |
| `max_total_pkts` | 全局包总量限制 |
| `connection_bps` | per-connection 字节限速 |
| `connection_burst` | per-connection 突发容量 |
| `disconnect_on_expiry_sec` | 证书过期自动断开（秒） |

## TSA 配置

| 字段 | 说明 |
|------|------|
| `tsa_url` | TSA 服务器地址 |
| `tsa_proof_file` | TSA 审计证明日志 |
| `tsa_proof_interval_sec` | 证明间隔（秒） |

## 管理 API

| 端点 | 方法 | 说明 | 权限 |
|------|------|------|------|
| `/api/v1/gateway/listeners` | GET | 列出监听器 | admin |
| `/api/v1/gateway/listeners` | POST | 添加监听器 | admin |
| `/api/v1/gateway/listeners/` | DELETE | 删除监听器 | admin |
| `/api/v1/gateway/audit` | GET | 查询审计日志 | audit+admin |
| `/api/v1/gateway/reload` | POST | 热重载配置 | admin |
| `/api/v1/gateway/health` | GET | 健康检查 | 公开 |
| `/api/v1/gateway/metrics` | GET | Prometheus 指标 | ops+admin |
