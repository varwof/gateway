# 配置参考

## 顶层结构

```json
{
  "defaults":  { ... },
  "mappings":  [ ... ],
  "tunnels":   [ ... ],
  "management": { ... }
}
```

| 字段 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `defaults` | MappingDefaults | 否 | 全局默认值，mapping 中省略的字段从此继承 |
| `mappings` | []MappingConfig | 否 | TCP 端口转发映射列表 |
| `tunnels` | []TunnelConfig | 否 | 高级隧道配置列表（与 mappings 二选一或并存） |
| `management` | ManagementConfig | 否 | 管理 API 配置 |

## MappingDefaults

```json
{
  "tls": { ... },
  "protocol": "tcp+mtls",
  "max_conns_per_ip": 10,
  "max_total_conns": 1000,
  "idle_timeout_sec": 300,
  "health_check_sec": 0,
  "audit_max_size_mb": 100,
  "audit_max_backups": 3
}
```

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `tls` | TLSConfig | — | 默认 TLS 认证配置 |
| `protocol` | string | `"tcp+mtls"` | 默认协议 |
| `max_conns_per_ip` | int | `10` | 每 IP 最大并发连接数 |
| `max_total_conns` | int | `1000` | 全局最大并发连接数 |
| `idle_timeout_sec` | int | `300` | 空闲连接超时（秒） |
| `health_check_sec` | int | `0` | 健康检查间隔（0=不启用） |
| `audit_max_size_mb` | int | `100` | 审计日志文件轮换大小 |
| `audit_max_backups` | int | `3` | 审计日志保留备份数 |

## MappingConfig

定义一条端口转发规则：

```json
{
  "name": "string",
  "listen": "string",
  "target": "string",
  "protocol": "tcp|tcp+mtls|tcp+mesh",
  "tls": { "mode": "mtls|server|none", ... },
  "tcp_ext": { ... },
  "max_conns_per_ip": 10,
  "max_total_conns": 1000,
  "idle_timeout_sec": 300,
  "health_check_sec": 10,
  "health_check_timeout_sec": 5,
  "audit_file": "string",
  "audit_max_size_mb": 100,
  "audit_max_backups": 3
}
```

| 字段 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `name` | string | 是 | 映射名称，用于标识和 API 管理 |
| `listen` | string | 是 | 监听地址，格式 `host:port`，host 可省略 |
| `target` | string | 是 | 目标地址，格式 `host:port`，支持多个逗号分隔实现轮询 |
| `protocol` | string | 否 | 协议：`tcp`（明文，或经 `tls.mode` 启用 TLS）、`tcp+mtls`（双向 mTLS）、`tcp+mesh`（Mesh） |
| `tls` | TLSConfig | 否 | TLS 配置，protocol=tcp+mtls 时必需 |
| `tcp_ext` | TCPExtra | 否 | TCP 特有扩展字段（见 TCPExtra） |
| `max_conns_per_ip` | int | 否 | 每 IP 最大并发连接数 |
| `max_total_conns` | int | 否 | 映射级别最大并发连接数 |
| `idle_timeout_sec` | int | 否 | 空闲连接超时 |
| `health_check_sec` | int | 否 | 健康检查间隔（秒），默认继承 defaults |
| `health_check_timeout_sec` | int | 否 | 健康检查超时（秒） |
| `audit_file` | string | 否 | 审计日志文件路径，省略则不记录审计 |
| `audit_max_size_mb` | int | 否 | 审计日志轮换大小 |
| `audit_max_backups` | int | 否 | 审计日志保留数 |

### protocol 说明

| Protocol | 客户端认证 | 适用场景 |
|------|-----------|----------|
| `tcp+mtls` | 必需证书 | 零信任网关、数据库代理、管理接口 |
| `tcp`（`tls.mode=server`） | 无 | 仅加密、标准 TLS 代理 |
| `tcp` | 无 | 明文转发（仅用于调试或内网场景） |

## TLSConfig

```json
{
  "tls": {
    "mode": "mtls",
    "ca_cert_file": "/etc/pki/ca.crt",
    "cert_file": "/etc/pki/gateway.crt",
    "key_file": "/etc/pki/gateway.key",
    "crl_url": "http://crl.example.com/ca.crl",
    "crl_cache_ttl_sec": 900,
    "crl_timeout_sec": 10,
    "tsa_url": "http://tsa.example.com/tsa",
    "tsa_client_cert_file": "",
    "tsa_client_key_file": "",
    "tsa_cert_file": "",
    "allow_roles": ["admin", "readonly"],
    "audit_file": "",
    "max_conns_per_ip": 10,
    "max_total_conns": 1000,
    "idle_timeout_sec": 300,
    "audit_max_size_mb": 100,
    "audit_max_backups": 3
  },
  "tcp_ext": {
    "health_check_sec": 0,
    "health_check_url": ""
  }
}
```

| 字段 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `mode` | string | 否 | TLS 认证模式：`none` / `server` / `mtls` |
| `ca_cert_file` | string | 是 | CA 证书文件 PEM |
| `cert_file` | string | 是 | 服务端证书 PEM |
| `key_file` | string | 是 | 服务端私钥 PEM |
| `crl_url` | string | 是 | CRL 分发点 URL（支持 HTTP/HTTPS） |
| `crl_cache_ttl_sec` | int | 否 | CRL 缓存有效期（默认 900） |
| `crl_timeout_sec` | int | 否 | CRL 下载超时（默认 10） |
| `tsa_url` | string | 否 | TSA 服务 URL，不设置则不签名审计日志 |
| `tsa_client_cert_file` | string | 否 | TSA 客户端认证证书（如 TSA 需要） |
| `tsa_client_key_file` | string | 否 | TSA 客户端私钥 |
| `tsa_cert_file` | string | 否 | TSA 证书文件（用于验证时间戳签名） |
| `allow_roles` | []string | 否 | 允许的角色列表，不设置则允许所有已认证连接 |
| `audit_file` | string | 否 | 审计日志文件路径 |
| `max_conns_per_ip` | int | 否 | 每 IP 最大连接数 |
| `max_total_conns` | int | 否 | 最大总连接数 |
| `idle_timeout_sec` | int | 否 | 空闲超时 |
| `disconnect_on_expiry` | bool | 否 | 证书过期时主动断开连接（默认 true） |
| `cipher_suites` | []string | 否 | TLS 密码套件白名单（默认 AEAD 套件集） |
| `min_tls_version` | string | 否 | 最低 TLS 版本（`"1.2"` 或 `"1.3"`，默认 `"1.2"`） |
| `audit_max_size_mb` | int | 否 | 日志轮换大小 |
| `audit_max_backups` | int | 否 | 日志备份数 |

### TCPExtra（`tcp_ext` 块）

TCP 特有扩展字段：

| 字段 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `health_check_sec` | int | 否 | 健康检查间隔 |
| `health_check_url` | string | 否 | HTTP 健康检查 URL（设置后代替 TCP 拨号） |

## TunnelConfig

用于高级隧道配置，支持额外的传输层控制：

```json
{
  "name": "ssh-bastion",
  "listen": ":2222",
  "target": "10.0.0.1:22",
  "protocol": "tcp+mtls",
  "keepalive_sec": 30,
  "tcp_buf_size": 65536,
  "tls": { ... }
}
```

| 字段 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `name` | string | 是 | 隧道名称 |
| `listen` | string | 是 | 监听地址 |
| `target` | string | 是 | 目标地址 |
| `protocol` | string | 否 | 同 MappingConfig |
| `keepalive_sec` | int | 否 | TCP keepalive 间隔（秒） |
| `tcp_buf_size` | int | 否 | TCP 读写缓冲区大小（字节） |
| `tls` | TLSConfig | 否 | TLS 配置 |

## ManagementConfig

```json
{
  "listen": ":7444",
  "tls": {
    "mode": "mtls",
    "allow_roles": ["admin"],
    "ca_cert_file": "/etc/pki/ca.crt",
    "cert_file": "/etc/pki/gateway-mgmt.crt",
    "key_file": "/etc/pki/gateway-mgmt.key",
    "crl_url": "http://crl.example.com/ca.crl"
  }
}
```

| 字段 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `listen` | string | 否 | 管理 API 监听地址（默认 `:7444`） |
| `tls` | TLSConfig | 否 | 管理 API 的 mTLS 配置，可独立于数据面使用不同证书 |

## 完整示例

```json
{
  "defaults": {
    "tls": {
      "mode": "mtls",
      "ca_cert_file": "/etc/pki/ca.crt",
      "cert_file": "/etc/pki/gateway.crt",
      "key_file": "/etc/pki/gateway.key",
      "crl_url": "http://crl.example.com/ca.crl",
      "tsa_url": "http://tsa.example.com/tsa",
      "allow_roles": ["admin"],
      "max_conns_per_ip": 20,
      "max_total_conns": 2000,
      "idle_timeout_sec": 600,
      "audit_max_size_mb": 200,
      "audit_max_backups": 7,
      "disconnect_on_expiry": true,
      "health_check_url": "http://127.0.0.1:8080/health",
      "cipher_suites": ["TLS_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"],
      "min_tls_version": "1.2"
    },
    "protocol": "tcp+mtls",
    "health_check_sec": 15
  },
  "mappings": [
    {
      "name": "postgres-prod",
      "listen": ":7443",
      "target": "10.0.1.10:5432,10.0.1.11:5432",
      "tls": {
        "mode": "mtls",
        "allow_roles": ["admin"],
        "audit_file": "/var/log/gateway-tcp/pg.audit.jsonl"
      }
    },
    {
      "name": "redis-staging",
      "listen": ":7445",
      "target": "10.0.2.20:6379",
      "protocol": "tcp",
      "tls": {
        "mode": "server",
        "audit_file": "/var/log/gateway-tcp/redis-staging.audit.jsonl"
      }
    }
  ],
  "tunnels": [
    {
      "name": "ssh-bastion",
      "listen": ":2222",
      "target": "10.0.0.1:22",
      "keepalive_sec": 30
    }
  ],
  "management": {
    "listen": ":7444",
    "tls": {
      "mode": "mtls",
      "allow_roles": ["admin"],
      "audit_file": "/var/log/gateway-tcp/mgmt.audit.jsonl"
    }
  }
}
```
