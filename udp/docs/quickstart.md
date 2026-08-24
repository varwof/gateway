# gateway-udp 快速开始

> 零信任 UDP 三层安全网关 | Plain UDP / DTLS / mTLS DTLS / QUIC/HTTP3

## 安装

```bash
go build -o gateway-udp .
```

## 最小配置

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

## 启动

```bash
gateway-udp --config /etc/varwof/gateway-udp/gateway-udp.json

# CLI 模式
gateway-udp -L name=dns,listen=:5353,protocol=udp,routes=8.8.8.8:53

# DTLS 模式
gateway-udp -L name=dtls,listen=:5354,protocol=dtls,cert=server.pem,key=server.key,routes=8.8.8.8:53
```

## Protocol 模式

| protocol | 说明 |
|------|------|
| `udp` | 明文 UDP 转发 |
| `dtls` | DTLS 加密（服务端证书） |
| `udp+mtls` | 双向 mTLS DTLS（完整安全管线） |
| `quic` | QUIC/HTTP3 代理 |

## 关键特性

| 特性 | 说明 |
|------|------|
| UDP 包转发 | 哈希路由分发 |
| per-IP 限速 | 包速率限制 |
| 全局限制 | 总包数限制 |
| per-IP QUIC 连接数 | max_conns_per_ip |
| TokenBucket | per-connection 字节限速 |
| 证书过期断开 | 自动审计 + 断开 |
| 审计日志 | DTLS/QUIC 连接 + RBAC 拒绝 |
| 延迟指标 | ProxyLatency 直方图 |
| 管理 API | mTLS + RBAC |
| 热重载 | SIGHUP |

## 下一步

- [配置参考](config.md) — 完整配置项
- [使用指南](usage.md) — 各模式详解
- [示例](examples.md) — 实际场景配置
- [功能特性](functions.md) — API 参考
