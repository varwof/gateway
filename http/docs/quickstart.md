# gateway-http 快速开始

> 零信任 HTTP 七层反向代理 | mTLS + 路径级 RBAC + gRPC/WebSocket + QUIC/HTTP3

## 安装

```bash
go build -o gateway-http .
```

## 最小配置

```json
{
  "listeners": [{
    "name": "web-proxy",
    "listen": ":443",
    "protocol": "http2",
    "tls": {
      "mode": "mtls",
      "ca_cert_file": "/etc/pki/ca.pem",
      "cert_file": "/etc/pki/server.pem",
      "key_file": "/etc/pki/server.key"
    },
    "routes": [
      {"path": "/api/*", "target": "http://127.0.0.1:8080", "allow_roles": ["gateway:admin"]},
      {"path": "/health", "target": "http://127.0.0.1:8080"}
    ]
  }]
}
```

## 启动

```bash
gateway-http --config /etc/varwof/gateway-http/gateway-http.json

# CLI 模式
gateway-http \
  --listener name=web,listen=:443,protocol=http2,tls-mode=mtls,ca-cert=ca.pem,cert=server.pem,key=server.key \
  --route listener=web,path=/api/*,target=http://127.0.0.1:8080,allow-roles=gateway:admin
```

## 关键特性

| 特性 | 说明 |
|------|------|
| Protocol | http1 / http2 / h2c / grpc / ws / wss / h3 / quic（`tls.mode` 决定 none/server/mtls） |
| 路径路由 | 最长前缀匹配 + 通配符 |
| 路径级 RBAC | per-route allow_roles |
| 后端协议 | h1 / h2 / h2c per-route |
| 证书注入 | X-Forwarded-Client-* Header |
| AIC 注入 | X-AIC-* Header 到后端 |
| WebSocket | 原生升级代理 |
| gRPC | 透明 H2C/H2 代理 |
| QUIC/HTTP3 | QUIC 流隧道 |

## 下一步

- [配置参考](config.md) — 完整配置项
- [使用指南](usage.md) — 各模式详解
- [示例](examples.md) — 实际场景配置
- [功能特性](functions.md) — API 参考
