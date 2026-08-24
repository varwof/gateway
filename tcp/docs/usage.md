# gateway-tcp 使用指南

## 协议详解

### tcp 协议（明文转发）

```json
{
  "name": "tcp-forward",
  "listen": ":9090",
  "target": "10.0.0.1:3306",
  "protocol": "tcp"
}
```

无 TLS，直接转发 TCP 流量。适用于内部网络。如需服务端单向 TLS，配 `protocol: tcp` + `tls.mode: server`。

### tcp+mtls 协议（双向 mTLS）

```json
{
  "name": "secure-db",
  "listen": ":8443",
  "target": "db:3306",
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
```

客户端必须提供有效证书，经过 CRL → OCSP → RBAC → AIC → 插件全管线检查。

### tcp+mesh 协议（联邦代理）

```json
{
  "name": "mesh-proxy",
  "listen": ":8443",
  "target": "10.0.0.1:3306",
  "protocol": "tcp+mesh",
  "mesh_peer": "gateway-b"
}
```

流量通过 mesh peer 代理到目标。需配置 `peers` 和 `mesh_listen`。

## 连接限制

```json
{
  "tls": {
    "max_conns_per_ip": 100,
    "max_conns_per_cert": 50,
    "max_total_conns": 10000,
    "idle_timeout_sec": 300
  },
  "tcp_ext": {
    "max_connection_duration_sec": 3600
  }
}
```

| 限制类型 | 说明 |
|---------|------|
| per-IP | 同一客户端 IP 最大并发连接 |
| per-cert | 同一证书最大并发连接 |
| 全局 | 整个映射最大连接数 |
| 空闲超时 | 无数据传输时断开 |
| 硬超时 | 最大连接时长 |

## 健康检查

```json
{
  "tcp_ext": {
    "health_check_sec": 30,
    "health_check_url": "http://backend:8080/health"
  }
}
```

- `health_check_url` 为空：TCP 探测（端口可达性）
- `health_check_url` 有值：HTTP GET 探测（200 = 健康）

映射状态：`running` → `unhealthy`（检查失败）→ `running`（恢复）

## 隧道模式

客户端本地监听，穿透 mTLS 到网关：

```bash
# 启动网关
gateway-tcp --config gateway.json

# 启动隧道客户端
gateway-tcp tunnel \
  --map name=db-tunnel,listen=127.0.0.1:3306,gateway-addr=gateway:8443,cert=client.pem,key=client.key,ca-cert=ca.pem
```

隧道自动重连（指数退避 1s → 30s）。

## Mesh 联邦

多网关互联：

```json
{
  "mesh_listen": ":9091",
  "peers": [
    {"name": "gateway-b", "addr": "10.0.0.2:9091", "ca_cert_file": "ca.pem", "cert_file": "peer.pem", "key_file": "peer.key"}
  ],
  "mappings": [
    {"name": "mesh-proxy", "listen": ":8443", "target": "10.0.0.1:3306", "protocol": "tcp+mesh", "mesh_peer": "gateway-b"}
  ]
}
```

## 热重载

```bash
# SIGHUP
kill -HUP <pid>

# 管理 API
curl -sk --cert admin.pem --key admin.key -X POST \
  https://127.0.0.1:9090/api/v1/gateway/reload
```

重载逻辑：对比新旧配置，仅重启变更的映射，保持不变的映射。

## 短命证书

```json
{
  "short_lived": {
    "CoreURL": "https://pki-core:4433",
    "CertFile": "/tmp/gw-cert.pem",
    "KeyFile": "/tmp/gw-key.pem",
    "CACertFile": "/etc/pki/ca.pem",
    "DefaultCA": "issuing",
    "Timeout": 10000000000,
    "RetryCount": 3
  }
}
```

启动时自动签发证书，后台每 30s 检查续签。

## 审计日志

每条审计记录包含：

```json
{
  "time": "2026-07-09T10:00:00Z",
  "action": "connected",
  "src_ip": "192.168.1.1",
  "client_cn": "admin@example.com",
  "client_serial": "ABCD1234...",
  "roles": ["gateway:admin"],
  "mapping": "db-proxy",
  "target": "10.0.0.1:3306",
  "bytes_in": 1024,
  "bytes_out": 2048,
  "duration": "5.2s"
}
```

## Prometheus 指标

| 指标名 | 类型 | 标签 | 说明 |
|--------|------|------|------|
| `pki_gateway_mapping_connections_active` | Gauge | mapping | 活跃连接数 |
| `pki_gateway_mapping_connections_total` | Counter | mapping | 总连接数 |
| `pki_gateway_mapping_connection_duration_seconds` | Histogram | mapping | 连接时长分布 |
| `pki_gateway_mapping_up` | Gauge | mapping | 映射状态（1=正常） |
| `pki_gateway_mapping_bytes_to_target_total` | Counter | mapping, cert_serial | 发往后端字节 |
| `pki_gateway_mapping_bytes_to_client_total` | Counter | mapping, cert_serial | 发往客户端字节 |
| `pki_gateway_mesh_requests_received_total` | Counter | — | Mesh 请求总数 |
| `pki_gateway_mesh_connections_active` | Gauge | peer | 活跃 Mesh 连接 |
| `pki_gateway_mesh_dial_errors_total` | Counter | peer | Mesh 拨号错误 |
