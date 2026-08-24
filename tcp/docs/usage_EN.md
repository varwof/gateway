# gateway-tcp Usage Guide

## Protocols in Detail

### tcp Protocol (Plaintext Forwarding)

```json
{
  "name": "tcp-forward",
  "listen": ":9090",
  "target": "10.0.0.1:3306",
  "protocol": "tcp"
}
```

No TLS; TCP traffic is forwarded directly. Suitable for internal networks. For one-way server TLS, use `protocol: tcp` + `tls.mode: server`.

### tcp+mtls Protocol (Mutual mTLS)

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

Clients must present a valid certificate and pass the full pipeline check: CRL → OCSP → RBAC → AIC → plugins.

### tcp+mesh Protocol (Federated Proxy)

```json
{
  "name": "mesh-proxy",
  "listen": ":8443",
  "target": "10.0.0.1:3306",
  "protocol": "tcp+mesh",
  "mesh_peer": "gateway-b"
}
```

Traffic is proxied to the target through a mesh peer. Requires `peers` and `mesh_listen` to be configured.

## Connection Limits

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

| Limit Type | Description |
|---------|------|
| per-IP | Max concurrent connections from the same client IP |
| per-cert | Max concurrent connections using the same certificate |
| Global | Max connections for the entire mapping |
| Idle timeout | Disconnect when no data is transferred |
| Hard timeout | Maximum connection duration |

## Health Check

```json
{
  "tcp_ext": {
    "health_check_sec": 30,
    "health_check_url": "http://backend:8080/health"
  }
}
```

- `health_check_url` empty: TCP probe (port reachability)
- `health_check_url` set: HTTP GET probe (200 = healthy)

Mapping state: `running` → `unhealthy` (check failed) → `running` (recovered)

## Tunnel Mode

The client listens locally and tunnels through mTLS to the gateway:

```bash
# Start the gateway
gateway-tcp --config gateway.json

# Start the tunnel client
gateway-tcp tunnel \
  --map name=db-tunnel,listen=127.0.0.1:3306,gateway-addr=gateway:8443,cert=client.pem,key=client.key,ca-cert=ca.pem
```

The tunnel reconnects automatically (exponential backoff 1s → 30s).

## Mesh Federation

Interconnecting multiple gateways:

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

## Hot Reload

```bash
# SIGHUP
kill -HUP <pid>

# Management API
curl -sk --cert admin.pem --key admin.key -X POST \
  https://127.0.0.1:9090/api/v1/gateway/reload
```

Reload logic: compares old and new configuration, restarting only changed mappings and leaving unchanged ones intact.

## Short-Lived Certificates

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

Certificates are issued automatically at startup; a background job checks renewal every 30s.

## Audit Log

Each audit record contains:

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

## Prometheus Metrics

| Metric Name | Type | Labels | Description |
|--------|------|------|------|
| `pki_gateway_mapping_connections_active` | Gauge | mapping | Active connections |
| `pki_gateway_mapping_connections_total` | Counter | mapping | Total connections |
| `pki_gateway_mapping_connection_duration_seconds` | Histogram | mapping | Connection duration distribution |
| `pki_gateway_mapping_up` | Gauge | mapping | Mapping state (1 = healthy) |
| `pki_gateway_mapping_bytes_to_target_total` | Counter | mapping, cert_serial | Bytes sent to backend |
| `pki_gateway_mapping_bytes_to_client_total` | Counter | mapping, cert_serial | Bytes sent to client |
| `pki_gateway_mesh_requests_received_total` | Counter | — | Total Mesh requests |
| `pki_gateway_mesh_connections_active` | Gauge | peer | Active Mesh connections |
| `pki_gateway_mesh_dial_errors_total` | Counter | peer | Mesh dial errors |
