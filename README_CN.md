# varwof-gateway

> 三层零信任安全网关 —— TCP/HTTP/UDP 协议整合，mTLS 双向认证 + 细粒度 RBAC + AIC 能力验证

[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/varwof/gateway)](https://pkg.go.dev/github.com/varwof/gateway)

[English](README.md)

## 什么是 varwof-gateway？

三层零信任安全网关，整合 TCP/HTTP/UDP 协议，提供 mTLS 双向认证和细粒度权限控制。

## 快速开始

```bash
go build -o gateway .

cat > config.json <<EOF
{
  "listeners": [{
    "name": "https",
    "listen": ":443",
    "tls": { "mode": "mtls", "cert_file": "server.pem", "key_file": "server-key.pem", "ca_cert_file": "ca.pem" },
    "routes": [{ "path": "/", "target": "http://127.0.0.1:8080" }]
  }]
}
EOF

gateway --config config.json
```

## 安装

```bash
go build -o gateway .
```

## 特性

| 层级 | 协议 | 功能 |
|------|------|------|
| **L4** | TCP | 透明代理 + mTLS |
| **L7** | HTTP | 反向代理 + 路径级 RBAC |
| **L3** | UDP | DTLS/QUIC + 限速 |

通用特性：CRL/OCSP 实时吊销检查、AIC 能力验证、结构化日志、Prometheus 指标、热重载、管理 API。

gateway 是 varwof 生态的**前端接入层**。本项目是 [Open Invention Network](https://openinventionnetwork.com/) 成员。

## 链接

| | |
|---|---|
| 主页 | https://varwof.com |
| 社区 | https://varwof.org |
| IETF 草案 | [draft-wei-aic-identity-cert](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/) |
| 许可证 | Apache-2.0 |
| 成员 | [Open Invention Network](https://openinventionnetwork.com/) |
