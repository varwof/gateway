# Management API Reference

> Unified management REST API for the three gateways | mTLS authentication + RBAC role control

## Authentication

All management API endpoints are protected by mTLS. The client certificate's OU field encodes roles and must satisfy the RBAC role required by the endpoint.

**Role permission matrix:**

| Role | Permission Scope |
|------|----------|
| `gateway:admin` | Full control (add/delete mappings/listeners, hot reload, disconnect, revoke) |
| `gateway:ops` | Operations read (metrics, connections, peers, renewals) |
| `gateway:audit` | Audit read (audit logs, audit chains) |

## Base Path

```
https://<gateway-mgmt>:<port>/api/v1/gateway/
```

The management API port is specified by `management.listen` in the configuration file (default TCP:9090 / HTTP:9443 / UDP:9090).

---

## Common Endpoints (Shared by All Three Gateways)

### Health Check

```
GET /api/v1/gateway/health
```

**RBAC:** Public (no mTLS required)

**Response 200:**
```json
{"status": "ok"}
```

### Metrics

```
GET /api/v1/gateway/metrics
```

**RBAC:** `gateway:ops` / `gateway:admin`

Returns metrics in Prometheus text format.

### Configuration Hot Reload

```
POST /api/v1/gateway/reload
```

**RBAC:** `gateway:admin`

**Response 200:**
```json
{"status": "ok"}
```

Equivalent to sending a `SIGHUP` signal.

### Disconnect Agent

```
POST /api/v1/gateway/disconnect-agent
Content-Type: application/json

{"agent_id": "agent-123", "reason": "high-risk behavior"}
```

**RBAC:** `gateway:admin`

Disconnects all active connections of the specified agent. Triggers conditional revocation (when `revoker` is configured).

### Disconnect User

```
POST /api/v1/gateway/disconnect-user
Content-Type: application/json

{"user": "zhangsan", "reason": "session expired"}
```

**RBAC:** `gateway:admin`

---

## TCP Gateway Endpoints

### List Mappings

```
GET /api/v1/gateway/mappings
```

**RBAC:** `gateway:admin`

**Response 200:**
```json
[
  {
    "name": "db-proxy",
    "listen": ":8443",
    "target": "10.0.0.1:3306",
    "tls_mode": "mtls",
    "state": "running",
    "conns": 5,
    "healthy": true,
    "per_ip_limit": 100,
    "total_limit": 500
  }
]
```

### Add Mapping

```
POST /api/v1/gateway/mappings
Content-Type: application/json

{
  "name": "new-service",
  "listen": ":8444",
  "target": "10.0.0.2:8080",
  "tls_mode": "mtls",
  "mtls": {
    "ca_cert_file": "/etc/pki/ca.pem",
    "cert_file": "/etc/pki/server.pem",
    "key_file": "/etc/pki/server.key",
    "allow_roles": ["gateway:ops"]
  }
}
```

**RBAC:** `gateway:admin`

**Response 201:** `{"status": "ok", "name": "new-service"}`

**Error 409:** Mapping name already exists

### Delete Mapping

```
DELETE /api/v1/gateway/mappings/{name}
```

**RBAC:** `gateway:admin`

### Force CRL Refresh

```
POST /api/v1/gateway/crl/reload
```

**RBAC:** `gateway:admin`

**Response 200:**
```json
{"reloaded": 3, "errors": []}
```

### Client Certificate Renewal

```
POST /api/v1/gateway/renew
Content-Type: application/json

{
  "serial_hex": "0a1b2c...",
  "new_pub_key_pem": "-----BEGIN PUBLIC KEY-----\n..."
}
```

**RBAC:** `gateway:ops` / `gateway:admin`

Requires an mTLS client certificate. Issues a new certificate and returns it in PEM format.

### Mesh Peer List

```
GET /api/v1/gateway/peers
```

**RBAC:** `gateway:ops` (only available when Mesh is enabled on the TCP gateway)

---

## HTTP Gateway Endpoints

### List Listeners

```
GET /api/v1/gateway/listeners
```

**RBAC:** `gateway:admin`

**Response 200:**
```json
[
  {
    "name": "https",
    "listen": ":443",
    "tls_mode": "mtls",
    "state": "running",
    "conns": 12,
    "routes": 5
  }
]
```

### Add Listener

```
POST /api/v1/gateway/listeners
Content-Type: application/json

{
  "name": "api-gw",
  "listen": ":8443",
  "tls_mode": "mtls",
  "mtls": {
    "ca_cert_file": "/etc/pki/ca.pem",
    "cert_file": "/etc/pki/server.pem",
    "key_file": "/etc/pki/server.key"
  },
  "routes": [
    {
      "path": "/api/v1/*",
      "target": "http://backend:8080",
      "allow_roles": ["gateway:admin"]
    }
  ]
}
```

**RBAC:** `gateway:admin`

**Response 201:** `{"status": "ok", "name": "api-gw"}`

### Delete Listener

```
DELETE /api/v1/gateway/listeners/{name}
```

**RBAC:** `gateway:admin`

### Task Management

#### Register Task

```
PUT /api/v1/gateway/tasks/{task_id}
Content-Type: application/json

{"serial": "0a1b2c...", "agent_id": "agent-123", "note": "deploy job"}
```

**RBAC:** `gateway:admin`

#### Unregister Task

```
DELETE /api/v1/gateway/tasks/{task_id}
```

**RBAC:** `gateway:admin`

#### Complete Task (triggers conditional revocation)

```
POST /api/v1/gateway/tasks/{task_id}/complete
```

**RBAC:** `gateway:admin`

Marks the task as completed and automatically revokes the associated client certificate ("revoke upon completion").

---

## UDP Gateway Endpoints

### List Listeners

```
GET /api/v1/gateway/listeners
```

**RBAC:** `gateway:admin`

**Response 200:**
```json
[
  {
    "name": "dtls-gw",
    "listen": ":5353",
    "tls_mode": "dtls",
    "active_clients": 8
  }
]
```

### Add Listener

```
POST /api/v1/gateway/listeners
Content-Type: application/json

{
  "name": "quic-proxy",
  "listen": ":4433",
  "tls_mode": "quic",
  "mtls": {
    "ca_cert_file": "/etc/pki/ca.pem",
    "cert_file": "/etc/pki/server.pem",
    "key_file": "/etc/pki/server.key"
  },
  "routes": [
    {"target": "10.0.0.5:8080"}
  ]
}
```

**RBAC:** `gateway:admin`

### Delete Listener

```
DELETE /api/v1/gateway/listeners/{name}
```

**RBAC:** `gateway:admin`

### Force CRL Refresh

```
POST /api/v1/gateway/crl/reload
```

**RBAC:** `gateway:admin`

---

## Shared Endpoints (All Gateways)

### Audit Log Query

```
GET /api/v1/gateway/audit
```

**RBAC:** `gateway:audit` / `gateway:admin`

**Query parameters:**

| Parameter | Type | Description |
|------|------|------|
| `since` | RFC3339 | Start time |
| `until` | RFC3339 | End time |
| `action` | string | Audit action filter |
| `client_cn` | string | Client CN filter |
| `limit` | int | Maximum number of entries returned |

### Audit Full-Text Search

```
GET /api/v1/gateway/audit/search?q=keyword&action=denied&limit=50
```

**RBAC:** `gateway:audit` / `gateway:admin`

Requires `audit_index_file` to be configured.

### Real-Time Connection Details

```
GET /api/v1/gateway/connections
```

**RBAC:** `gateway:ops` / `gateway:admin`

### IP Access Point Aggregation

```
GET /api/v1/gateway/access-points
```

**RBAC:** `gateway:ops` / `gateway:admin`

### Agent Directory

```
GET /api/v1/gateway/agents
```

**RBAC:** `gateway:ops` / `gateway:admin`

### Audit Chain DAG References

```
GET /api/v1/gateway/audit/chain
```

**RBAC:** `gateway:audit` / `gateway:admin`

### Policy Management

```
GET  /api/v1/gateway/policy          # Current policy
GET  /api/v1/gateway/policy/{role}   # Query by role
GET  /api/v1/gateway/policies/versions  # Version history
POST /api/v1/gateway/policies/rollback  # Rollback
PUT  /api/v1/gateway/plugins         # Update plugin configuration
```

**RBAC:** Read `gateway:ops` / Write `gateway:admin`

### Renewal Status

```
GET  /api/v1/gateway/renewal/status     # Renewal status
POST /api/v1/gateway/renewal/request    # Request renewal
POST /api/v1/gateway/renewal/confirm    # Confirm renewal
POST /api/v1/gateway/renewal/reject     # Reject renewal
```

---

## Error Response Format

```json
{"error": "description message"}
```

Common HTTP status codes:

| Status Code | Meaning |
|--------|------|
| 200 | Success |
| 201 | Created |
| 400 | Malformed request |
| 401 | mTLS authentication failed |
| 403 | Insufficient RBAC permissions |
| 404 | Resource not found |
| 405 | HTTP method not allowed |
| 409 | Resource already exists (conflict) |
| 500 | Internal server error |
| 503 | Service unavailable |
