# Varwof Gateway

三层零信任安全网关，整合 TCP/HTTP/UDP 协议，提供 mTLS 双向认证和细粒度权限控制。

## 特性

- **TCP 网关 (L4)**：透明代理 + mTLS
- **HTTP 网关 (L7)**：反向代理 + 路径级 RBAC
- **UDP 网关 (L3)**：DTLS/QUIC + 限速
- CRL/OCSP 实时吊销检查
- AIC 能力验证
- 结构化日志 (slog)
- Prometheus 指标

## 安装

```bash
go get github.com/varwof/gateway
```

## 配置

```json
{
  "listeners": [
    {
      "name": "https",
      "listen": ":443",
      "protocol": "http2",
      "tls": {
        "mode": "mtls",
        "cert_file": "server.pem",
        "key_file": "server-key.pem",
        "ca_cert_file": "ca.pem"
      },
      "routes": [
        { "path": "/", "target": "http://127.0.0.1:8080" }
      ]
    }
  ]
}
```

## 运行

```bash
gateway --config config.json
```

## 许可证

Apache-2.0
