# gateway-tcp 示例

## 示例 1：数据库 mTLS 代理

```json
{
  "mappings": [{
    "name": "mysql-secure",
    "listen": ":8443",
    "target": "db-primary:3306",
    "protocol": "tcp+mtls",
    "tls": {
      "mode": "mtls",
      "ca_cert_file": "/etc/pki/ca.pem",
      "cert_file": "/etc/pki/server.pem",
      "key_file": "/etc/pki/server.key",
      "crl_url": "http://crl.example.com/ca.crl",
      "allow_roles": ["gateway:admin"],
      "max_conns_per_ip": 20,
      "idle_timeout_sec": 600,
      "audit_file": "/var/log/gateway/mysql-audit.log"
    },
    "tcp_ext": {
      "max_connection_duration_sec": 3600
    }
  }]
}
```

## 示例 2：多端口转发

```json
{
  "mappings": [
    {
      "name": "redis",
      "listen": ":6379",
      "target": "redis:6379",
      "protocol": "tcp"
    },
    {
      "name": "postgres",
      "listen": ":5432",
      "target": "postgres:5432",
      "protocol": "tcp+mtls",
      "tls": {
        "mode": "mtls",
        "ca_cert_file": "/etc/pki/ca.pem",
        "cert_file": "/etc/pki/pg-server.pem",
        "key_file": "/etc/pki/pg-server.key",
        "allow_roles": ["gateway:admin", "gateway:ops"]
      }
    }
  ],
  "management": {
    "listen": ":9090",
    "tls": {
      "mode": "mtls",
      "ca_cert_file": "/etc/pki/ca.pem",
      "cert_file": "/etc/pki/mgmt.pem",
      "key_file": "/etc/pki/mgmt.key"
    }
  }
}
```

## 示例 3：CLI 快速启动

```bash
# 简单 TCP 转发
gateway-tcp -L name=forward,listen=:9090,target=backend:8080,protocol=tcp

# mTLS 代理
gateway-tcp \
  -L name=secure,listen=:8443,target=db:3306,protocol=tcp+mtls,ca-cert=ca.pem,cert=server.pem,key=server.key,allow-roles=gateway:admin

# 多映射
gateway-tcp \
  -L name=redis,listen=:6379,target=redis:6379,protocol=tcp \
  -L name=pg,listen=:5432,target=pg:5432,protocol=tcp+mtls,ca-cert=ca.pem
```

## 示例 4：Mesh 联邦

```json
{
  "mesh_listen": ":9091",
  "peers": [
    {
      "name": "gw-b",
      "addr": "10.0.0.2:9091",
      "ca_cert_file": "/etc/pki/ca.pem",
      "cert_file": "/etc/pki/gw-a.pem",
      "key_file": "/etc/pki/gw-a.key"
    }
  ],
  "mappings": [
    {
      "name": "remote-db",
      "listen": ":8443",
      "target": "10.0.0.1:3306",
      "protocol": "tcp+mesh",
      "mesh_peer": "gw-b"
    }
  ]
}
```

## 示例 5：隧道客户端

```bash
# 网关端
gateway-tcp --config gateway.json

# 客户端（本地 3306 → 穿透网关 → 远端 DB）
gateway-tcp tunnel \
  -t name=db-tunnel,listen=127.0.0.1:3306,gateway-addr=gateway.example.com:8443,cert=client.pem,key=client.key,ca-cert=ca.pem
```

## 示例 6：管理 API 操作

```bash
# 列出映射
curl -sk --cert admin.pem --key admin.key \
  https://127.0.0.1:9090/api/v1/gateway/mappings

# 添加映射
curl -sk --cert admin.pem --key admin.key -X POST \
  -H 'Content-Type: application/json' \
  -d '{"name":"new-proxy","listen":":8444","target":"backend:8080","protocol":"tcp"}' \
  https://127.0.0.1:9090/api/v1/gateway/mappings

# 删除映射
curl -sk --cert admin.pem --key admin.key -X DELETE \
  https://127.0.0.1:9090/api/v1/gateway/mappings/new-proxy

# 热重载
curl -sk --cert admin.pem --key admin.key -X POST \
  https://127.0.0.1:9090/api/v1/gateway/reload

# Prometheus 指标
curl -sk --cert ops.pem --key ops.key \
  https://127.0.0.1:9090/api/v1/gateway/metrics
```

## 示例 7：短命证书自动签发

```json
{
  "short_lived": {
    "CoreURL": "https://pki-core:4433",
    "CertFile": "/tmp/gw-cert.pem",
    "KeyFile": "/tmp/gw-key.pem",
    "CACertFile": "/etc/pki/ca.pem",
    "DefaultCA": "issuing",
    "DefaultKeyType": "ecdsa",
    "Timeout": 10000000000,
    "RetryCount": 3
  },
  "mappings": [{
    "name": "auto-cert-proxy",
    "listen": ":8443",
    "target": "backend:8080",
    "protocol": "tcp+mtls",
    "tls": {
      "mode": "mtls",
      "ca_cert_file": "/etc/pki/ca.pem",
      "allow_roles": ["gateway:admin"]
    }
  }]
}
```

## 示例 8：AIC + 能力插件

```json
{
  "capability_plugins": {
    "file:access": {
      "type": "allowlist",
      "config": {
        "allowed": ["file:read", "file:write"],
        "default_deny": true
      }
    }
  },
  "mappings": [{
    "name": "aic-proxy",
    "listen": ":8443",
    "target": "backend:8080",
    "protocol": "tcp+mtls",
    "tls": {
      "mode": "mtls",
      "ca_cert_file": "/etc/pki/ca.pem",
      "require_aic": true,
      "required_capabilities": ["tcp:forward"],
      "capability_scheme": "file"
    }
  }]
}
```
