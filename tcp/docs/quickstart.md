# gateway-tcp 快速开始

> 零信任 TCP 四层安全网关 | mTLS 双向认证 + CRL/OCSP + RBAC + 短命证书

## 安装

```bash
go build -o gateway-tcp .
```

## 最小配置文件

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

## 启动

```bash
# 文件配置模式
gateway-tcp --config /etc/varwof/gateway-tcp/gateway-tcp.json

# CLI 模式（无需配置文件）
gateway-tcp \
  --listener name=db-proxy,listen=:8443,target=10.0.0.1:3306,protocol=tcp+mtls,ca-cert=/etc/pki/ca.pem

# 热重载
kill -HUP <pid>
```

## 连接测试

```bash
# 客户端 mTLS 连接
openssl s_client -connect localhost:8443 \
  -cert client.pem -key client.key -CAfile ca.pem

# 管理 API
curl -sk --cert admin.pem --key admin.key \
  https://127.0.0.1:9090/api/v1/gateway/health
```

## 关键特性

| 特性 | 说明 |
|------|------|
| 协议 | tcp / tcp+mtls / tcp+mesh |
| 安全管线 | CRL → OCSP → RBAC → AIC → 插件 |
| 连接限制 | per-IP / per-cert / 全局 |
| 空闲超时 | idle_timeout_sec |
| 硬超时 | max_connection_duration_sec |
| 健康检查 | TCP 或 HTTP 探测 |
| 隧道模式 | 客户端穿透 mTLS 隧道 |
| Mesh 联邦 | 多网关 peer 代理 |
| 热重载 | SIGHUP + POST /reload |
| 短命证书 | 自动签发 + 30s 续签轮询 |
| 审计日志 | JSON Lines + Merkle 哈希链 |

## 下一步

- [配置参考](config.md) — 完整配置项
- [使用指南](usage.md) — 各模式详解
- [示例](examples.md) — 实际场景配置
- [功能特性](functions.md) — API 参考
