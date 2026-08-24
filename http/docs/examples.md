# gateway-http 示例

## 示例 1：API 反向代理 + 路径级 RBAC

```json
{
  "listeners": [{
    "name": "api-proxy",
    "listen": ":443",
    "protocol": "http2",
    "tls": {
      "mode": "mtls",
      "ca_cert_file": "/etc/pki/ca.pem",
      "cert_file": "/etc/pki/server.pem",
      "key_file": "/etc/pki/server.key",
      "crl_url": "http://crl.example.com/ca.crl"
    },
    "routes": [
      {"path": "/admin/*", "target": "http://127.0.0.1:8081", "allow_roles": ["gateway:admin"]},
      {"path": "/api/*", "target": "http://127.0.0.1:8080", "allow_roles": ["gateway:admin", "gateway:ops"]},
      {"path": "/health", "target": "http://127.0.0.1:8080"}
    ]
  }]
}
```

## 示例 2：gRPC 代理

```json
{
  "listeners": [{
    "name": "grpc-proxy",
    "listen": ":443",
    "protocol": "grpc",
    "tls": {
      "mode": "mtls",
      "ca_cert_file": "/etc/pki/ca.pem",
      "cert_file": "/etc/pki/server.pem",
      "key_file": "/etc/pki/server.key"
    },
    "routes": [
      {"path": "/", "target": "h2c://grpc-backend:8080", "backend_protocol": "h2c"}
    ]
  }]
}
```

## 示例 3：WebSocket + HTTP 混合代理

```json
{
  "listeners": [{
    "name": "mixed-proxy",
    "listen": ":443",
    "protocol": "http2",
    "tls": {"mode": "mtls", "ca_cert_file": "ca.pem", "cert_file": "server.pem", "key_file": "server.key"},
    "routes": [
      {"path": "/ws/*", "target": "http://ws-backend:8080"},
      {"path": "/api/*", "target": "http://api-backend:8080", "allow_roles": ["gateway:admin"]},
      {"path": "/", "target": "http://web-backend:8080"}
    ]
  }]
}
```

## 示例 4：CLI 快速启动

```bash
# 简单 HTTP 代理
gateway-http \
  --listener name=web,listen=:8080,protocol=http2 \
  --route listener=web,path=/,target=http://backend:8080

# mTLS + RBAC
gateway-http \
  --listener name=secure,listen=:443,protocol=http2,tls-mode=mtls,ca-cert=ca.pem,cert=server.pem,key=server.key \
  --route listener=secure,path=/api/*,target=http://backend:8080,allow-roles=gateway:admin
```

## 示例 5：H1 后端（遗留服务）

```json
{
  "routes": [
    {"path": "/legacy/*", "target": "http://legacy-app:8080", "backend_protocol": "h1"}
  ]
}
```

## 示例 6：管理 API

```bash
# 列出监听器
curl -sk --cert admin.pem --key admin.key \
  https://127.0.0.1:9090/api/v1/gateway/listeners

# 热重载
curl -sk --cert admin.pem --key admin.key -X POST \
  https://127.0.0.1:9090/api/v1/gateway/reload

# Prometheus 指标
curl -sk --cert ops.pem --key ops.key \
  https://127.0.0.1:9090/api/v1/gateway/metrics
```

## 示例 7：能力方案 + 自动推导

```json
{
  "listeners": [{
    "name": "mysql-proxy",
    "listen": ":443",
    "protocol": "http2",
    "tls": {
      "mode": "mtls",
      "ca_cert_file": "ca.pem",
      "require_aic": true
    },
    "routes": [
      {"path": "/", "target": "http://mysql:3306", "capability_scheme": "mysql", "capability_prefix": "db"}
    ]
  }]
}
```

自动推导：`GET → db:select`，`POST → db:insert`，`PUT → db:update`，`DELETE → db:delete`

## 示例 8：短命证书 + 管理 API

```json
{
  "short_lived": {
    "CoreURL": "https://pki-core:4433",
    "CertFile": "/tmp/gw-cert.pem",
    "KeyFile": "/tmp/gw-key.pem",
    "CACertFile": "/etc/pki/ca.pem",
    "DefaultCA": "issuing"
  },
  "management": {
    "listen": ":9090",
    "tls": {"ca_cert_file": "ca.pem", "cert_file": "mgmt.pem", "key_file": "mgmt.key"}
  },
  "listeners": [{
    "name": "web",
    "listen": ":443",
    "protocol": "http2",
    "tls": {"mode": "mtls", "ca_cert_file": "ca.pem"},
    "routes": [{"path": "/", "target": "http://backend:8080"}]
  }]
}
```
