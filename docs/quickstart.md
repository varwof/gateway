# Varwof Gateway 快速开始

> 零信任安全网关 | TCP/HTTP/UDP 三协议 | mTLS + CRL/OCSP + RBAC + 短命证书

## 安装

```bash
go build -o gateway-tcp ./cmd/tcp
go build -o gateway-http ./cmd/http
go build -o gateway-udp ./cmd/udp
```

## 最小配置

```json
{
  "server": {
    "tls_mode": "mtls",
    "cert_file": "/etc/pki/server.pem",
    "key_file": "/etc/pki/server-key.pem",
    "client_ca_file": "/etc/pki/ca.pem"
  },
  "listeners": [
    {
      "name": "https",
      "listen": ":443",
      "protocol": "http",
      "tls_mode": "mtls"
    }
  ]
}
```

## 启动

```bash
# HTTP 网关（文件配置）
gateway-http --config config.json

# TCP 网关（CLI 模式）
gateway-tcp \
  --listener name=db,listen=:8443,target=10.0.0.1:3306,tls-mode=mtls,ca-cert=ca.pem

# UDP 网关
gateway-udp --config udp-config.json

# 热重载（三网关通用）
kill -HUP <pid>
```

## 连接测试

```bash
# mTLS 连接测试
openssl s_client -connect localhost:8443 \
  -cert client.pem -key client.key -CAfile ca.pem

# 管理 API 健康检查
curl -sk --cert admin.pem --key admin.key \
  https://127.0.0.1:9443/api/v1/gateway/health
```

## 三协议特性速查

| 特性 | TCP | HTTP | UDP |
|------|-----|------|-----|
| TLS 模式 | plain/server/mtls/mesh | plain/mtls | plain/dtls/mtls/quic |
| RBAC | ✓ | 路径级 | ✓ |
| 连接限制 | per-IP/per-cert/全局限 | 并发连接限制 | per-IP 包速率 |
| 审计日志 | ✓ | ✓ | ✓（DTLS/QUIC） |
| 短命证书 | ✓ | ✓ | ✓ |
| 热重载 | SIGHUP + API | SIGHUP + API | SIGHUP + API |
| Mesh 联邦 | ✓ | — | — |

## 下一步

- [API 参考](api.md) — 管理 API 全部端点
- [配置参考](config.md) — 完整配置字段
- [CLI 参考](cli.md) — 命令行参数
