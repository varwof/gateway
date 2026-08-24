# gateway-http Examples

## Example 1: API Reverse Proxy + Path-Level RBAC

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

## Example 2: gRPC Proxy

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

## Example 3: WebSocket + HTTP Mixed Proxy

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

## Example 4: CLI Quick Start

```bash
# Simple HTTP proxy
gateway-http \
  --listener name=web,listen=:8080,protocol=http2 \
  --route listener=web,path=/,target=http://backend:8080

# mTLS + RBAC
gateway-http \
  --listener name=secure,listen=:443,protocol=http2,tls-mode=mtls,ca-cert=ca.pem,cert=server.pem,key=server.key \
  --route listener=secure,path=/api/*,target=http://backend:8080,allow-roles=gateway:admin
```

## Example 5: H1 Backend (Legacy Service)

```json
{
  "routes": [
    {"path": "/legacy/*", "target": "http://legacy-app:8080", "backend_protocol": "h1"}
  ]
}
```

## Example 6: Management API

```bash
# List listeners
curl -sk --cert admin.pem --key admin.key \
  https://127.0.0.1:9090/api/v1/gateway/listeners

# Hot reload
curl -sk --cert admin.pem --key admin.key -X POST \
  https://127.0.0.1:9090/api/v1/gateway/reload

# Prometheus metrics
curl -sk --cert ops.pem --key ops.key \
  https://127.0.0.1:9090/api/v1/gateway/metrics
```

## Example 7: Capability Scheme + Automatic Derivation

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

Automatic derivation: `GET → db:select`, `POST → db:insert`, `PUT → db:update`, `DELETE → db:delete`

## Example 8: Short-Lived Certificates + Management API

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
