# Management API Reference

All management APIs are authenticated via mTLS and require the client certificate to contain the corresponding RBAC role. Server-side configuration is specified through the `management` section.

## Authentication

- TLS mutual authentication (`tls.RequireAndVerifyClientCert`)
- The client certificate must be issued by the CA specified in `management.tls.ca_cert_file`
- The certificate OU must contain the corresponding RBAC role
- No certificate → `401 Unauthorized`
- Insufficient role → `403 Forbidden`

## Role Permission Matrix

| Endpoint | admin | ops | audit |
|------|-------|-----|-------|
| `/health` | ✅ | ✅ | ✅ |
| `/metrics` | ✅ | ✅ | ❌ |
| `/audit*` | ✅ | ❌ | ✅ |
| `/plugins*` | ✅ | ✅ | ❌ |
| `/capabilities*` | ✅ | ❌ | ❌ |
| `/listeners` | ✅ | ❌ | ❌ |
| `/reload` | ✅ | ❌ | ❌ |
| `/disconnect-*` | ✅ | ❌ | ❌ |
| `/tasks*` | ✅ | ❌ | ❌ |

## Endpoints

### GET /api/v1/gateway/health

Health check. No authentication required; public endpoint.

**Response 200**:
```json
{
  "status": "ok"
}
```

---

### GET /api/v1/gateway/metrics

Metrics in Prometheus format. Includes gateway-level and listener-level Counter/Gauge/Histogram.

**Roles**: `gateway:ops`, `gateway:admin`

**Response 200**: `Content-Type: text/plain; charset=utf-8`
```
# HELP pki_gateway_connections_active Active connections
# TYPE pki_gateway_connections_active gauge
pki_gateway_connections_active{listener="api-gateway"} 12
```

---

### GET /api/v1/gateway/audit

Query audit logs. Supports time ranges, pagination, filtering, and sorting.

**Roles**: `gateway:audit`, `gateway:admin`

**Query parameters**:

| Parameter | Type | Required | Description |
|------|------|------|------|
| `since` | `string` | No | Start time, RFC 3339 format |
| `until` | `string` | No | End time, RFC 3339 format |
| `limit` | `int` | No | Maximum number of entries returned |
| `offset` | `int` | No | Skip the first N entries |
| `sort` | `string` | No | `asc` (default) or `desc` |
| `action` | `string` | No | Filter by action type |
| `cn` | `string` | No | Filter by client certificate CN |
| `serial` | `string` | No | Filter by certificate serial number |
| `mapping` | `string` | No | Filter by listener name |

**Response 200**:
```json
[
  {
    "time": "2026-07-05T10:00:00.123456Z",
    "action": "proxied",
    "src_ip": "192.168.1.100:54321",
    "client_cn": "admin.varwof.com",
    "roles": ["gateway:admin"],
    "mapping": "api-gateway",
    "target": "/api/v1/users",
    "target_id": "http://127.0.0.1:8080"
  }
]
```

**Errors**:

| Status Code | Condition |
|--------|------|
| `400` | Invalid `since` format |
| `404` | Audit log not configured |

**Note**: Audit entries are read from the log file configured in `audit_file`. Old files are automatically archived at startup, and the API only queries files from the current startup cycle.

---

### POST /api/v1/gateway/audit/verify

Verify Merkle audit entries. Submit audit entry content and return the Merkle proof verification result.

**Roles**: `gateway:audit`, `gateway:admin`

**Request body**:
```json
{
  "entry": { "action": "proxied", "time": "2026-07-05T10:00:00.123456Z" },
  "proof": ["abc123...", "def456..."]
}
```

**Response 200**:
```json
{
  "valid": true,
  "root_hash": "abcdef...",
  "index": 42
}
```

---

### GET /api/v1/gateway/listeners

List all running Listeners.

**Role**: `gateway:admin`

**Response 200**:
```json
[
  {
    "name": "api-gateway",
    "listen": ":443",
    "tls_mode": "mtls",
    "state": "running",
    "conns": 12,
    "routes": 3
  }
]
```

| Field | Type | Description |
|------|------|------|
| `name` | `string` | Listener name |
| `listen` | `string` | Listen address |
| `tls_mode` | `string` | Effective TLS authentication mode (derived from `protocol` + `tls.mode`): `plain` / `server` / `mtls`. Note: this is a management API response field (`DisplayTLSMode`), distinct from the config file's `protocol` field |
| `state` | `string` | `"running"` or `"stopped"` |
| `conns` | `int` | Current concurrent connection count |
| `routes` | `int` | Number of route rules |

---

### POST /api/v1/gateway/listeners

Add a new Listener at runtime.

**Role**: `gateway:admin`

**Request body**:
```json
{
  "name": "extra",
  "listen": ":4434",
  "protocol": "http2",
  "tls": {
    "mode": "mtls",
    "ca_cert_file": "/etc/varwof/gateway-http/ca.pem",
    "cert_file": "/etc/varwof/gateway-http/server.pem",
    "key_file": "/etc/varwof/gateway-http/server.key",
    "crl_url": "http://crl.varwof.com/gateway-ca.crl",
    "audit_file": "/var/log/gateway-http/audit.log"
  },
  "routes": [
    { "path": "/*", "target": "http://127.0.0.1:9090",
      "allow_roles": ["gateway:*"] }
  ]
}
```

**Response 201**:
```json
{ "status": "ok", "name": "extra" }
```

**Errors**:

| Status Code | Condition |
|--------|------|
| `400` | Request body parsing failed or field validation failed |
| `409` | Listener name already exists |

---

### DELETE /api/v1/gateway/listeners/{name}

Stop and remove the specified Listener.

**Role**: `gateway:admin`

**Response 200**:
```json
{ "status": "ok", "name": "api-gateway" }
```

**Errors**:

| Status Code | Condition |
|--------|------|
| `404` | Listener does not exist |

---

### POST /api/v1/gateway/reload

Hot-reload the entire configuration. Re-reads from the configuration file and compares changes:

**Role**: `gateway:admin`

- Unchanged Listeners keep running
- Changed Listeners stop the old instance and start a new instance
- Listeners removed from the configuration are stopped
- Newly added Listeners are started

The short-lived certificate auto-renewal loop and the ConnExpiryRegistry cleanup loop keep running after reload (W04 fix: the renewal loop is bound to an independent `renewalCh` and only stops on process exit; the cleanup loop restarts with the new `stopCh`).

**Response 200**:
```json
{ "status": "ok" }
```

**Errors**:

| Status Code | Condition |
|--------|------|
| `500` | Configuration file read/validation/startup failed |

---

### PUT /api/v1/gateway/tasks/{taskId}

Register task context (A3: task ID → certificate serial number mapping). Agents register when starting a task, and upon completion, a completion signal triggers conditional revocation.

**Role**: `gateway:admin`

**Request body** (optional):
```json
{ "serial": "0000...AABB", "agent_id": "agent-1", "note": "batch-job" }
```

**Response 200**:
```json
{ "task_id": "job-42", "status": "registered" }
```

### POST /api/v1/gateway/tasks/{taskId}/complete

Complete a task and trigger conditional revocation (A5: Agent actively reports task completion). The gateway revokes the certificate serial number associated with the task.

**Role**: `gateway:admin`

**Response 200**:
```json
{ "task_id": "job-42", "serial": "0000...AABB", "status": "completed" }
```

**Response 404**: Task not registered.

### DELETE /api/v1/gateway/tasks/{taskId}

Unregister a task record (A3, does not trigger revocation).

**Role**: `gateway:admin`

**Response 200**:
```json
{ "task_id": "job-42", "unregistered": true }
```

## Data Plane Task Completion Signal (A4)

The Agent carries the following HTTP headers in a request to mark task completion, and the gateway immediately revokes that certificate ("revoke after use", without waiting for connection close):

- `X-AIC-Task-Id`: Task ID (optional; falls back to the client certificate CN if absent)
- `X-AIC-Task-Status: completed`: Task completion signal

```http
POST /api/data HTTP/1.1
X-AIC-Task-Id: job-42
X-AIC-Task-Status: completed
```

Upon receiving the completion signal, the gateway: audits `task_complete_revoke` → immediately revokes the client certificate → unregisters the task record.

---

### GET /api/v1/gateway/plugins

List all registered capability plugins.

**Roles**: `gateway:ops`, `gateway:admin`

**Response 200**:
```json
[
  { "scheme": "allowlist", "type": "builtin" },
  { "scheme": "denylist", "type": "builtin" }
]
```

---

### GET /api/v1/gateway/plugins/{scheme}

View details of the plugin for the specified Scheme.

**Roles**: `gateway:ops`, `gateway:admin`

**Path parameters**:

| Parameter | Description |
|------|------|
| `scheme` | Plugin Scheme identifier |

**Response 200**:
```json
{ "scheme": "allowlist", "type": "builtin" }
```

**Errors**:

| Status Code | Condition |
|--------|------|
| `404` | Plugin not found |

---

### PUT /api/v1/gateway/plugins

Replace the entire plugin configuration. Rebuilds the plugin registry in bulk based on JSON configuration.

**Role**: `gateway:admin`

**Request body**:
```json
[
  { "scheme": "allowlist", "type": "builtin", "config": { "domains": ["trusted.com"] } },
  { "scheme": "webhook", "type": "webhook", "config": { "url": "http://hook:8080/check" } }
]
```

**Response 200**:
```json
{ "status": "ok", "action": "plugins_replaced", "policy_version": 1 }
```

> The gateway is bound to a `PolicyManager`: each replacement produces a monotonically increasing `policy_version`. See `GET /api/v1/gateway/policies/versions` and `POST /api/v1/gateway/policies/rollback` for details.

**Errors**:

| Status Code | Condition |
|--------|------|
| `400` | JSON parsing failed or configuration validation failed |

---

### DELETE /api/v1/gateway/plugins

Clear all registered plugins.

**Role**: `gateway:admin`

**Response 200**:
```json
{ "status": "ok", "action": "plugins_cleared" }
```

---

### GET /api/v1/gateway/policies/versions

List all policy version snapshots (including the currently active version, in ascending order). Each management API publish or SIGHUP hot-reload produces a new version.

**Roles**: `gateway:ops`, `gateway:admin`

**Response 200**:
```json
{
  "current_version": 2,
  "count": 2,
  "versions": [
    {
      "version": 1,
      "source": "api",
      "operator": "admin",
      "timestamp": "2026-08-13T10:20:00Z",
      "configs": {}
    }
  ]
}
```

---

### POST /api/v1/gateway/policies/rollback

Rebuild the policy registry to the content of the specified version, producing a new monotonically increasing version number.

**Role**: `gateway:admin`

**Request body**:
```json
{ "version": 1 }
```

**Response 200**:
```json
{ "status": "ok", "action": "policy_rolled_back", "new_version": 3 }
```

**Errors**:

| Status Code | Condition |
|--------|------|
| `400` | Unknown version or below the `MinRollbackVersion` lower bound |

---

### GET /api/v1/gateway/policies/branches

List current policy branch rules (task 5b: branch control / canary release).

**Roles**: `gateway:ops`, `gateway:admin`

**Response 200**:
```json
{
  "current_version": 2,
  "count": 1,
  "branches": [
    { "id": "canary", "agent_id": "agent-canary-*", "version": 1, "priority": 10, "comment": "canary rollout" }
  ]
}
```

---

### PUT /api/v1/gateway/policies/branches

Replace all branch rules. Agents matching a branch use the branch version's policy (both decisions and auditing are bound to the branch version), while the rest fall back to the currently active version.

**Role**: `gateway:admin`

**Request body**:
```json
{
  "branches": [
    { "id": "canary", "agent_id": "agent-canary-*", "version": 1, "priority": 10, "comment": "canary rollout" }
  ]
}
```

**Response 200**:
```json
{ "status": "ok", "action": "policy_branches_replaced", "count": 1 }
```

**Errors**:

| Status Code | Condition |
|--------|------|
| `400` | Missing/duplicate ID, empty AgentID, or reference to an unpublished version |

---

### DELETE /api/v1/gateway/policies/branches

Clear all branch rules, restoring all Agents to the currently active version.

**Role**: `gateway:admin`

**Response 200**:
```json
{ "status": "ok", "action": "policy_branches_cleared" }
```

---

### GET /api/v1/gateway/capabilities

List all capability configuration schemes (Schemes).

**Roles**: `gateway:ops`, `gateway:admin`

**Response 200**:
```json
["tunnel:prod", "gateway:admin"]
```

---

### GET /api/v1/gateway/capabilities/{scheme}

View detailed configuration of the specified Scheme.

**Roles**: `gateway:ops`, `gateway:admin`

**Path parameters**:

| Parameter | Description |
|------|------|
| `scheme` | Capability scheme identifier |

**Response 200**:
```json
{
  "scheme": "tunnel:prod",
  "capabilities": [
    { "id": "allow", "permission": "connect" }
  ]
}
```

**Errors**:

| Status Code | Condition |
|--------|------|
| `404` | Scheme does not exist |

---

### PUT /api/v1/gateway/capabilities

Replace all capability configuration schemes.

**Role**: `gateway:admin`

**Request body**:
```json
{
  "schemes": [
    { "scheme": "tunnel:prod", "capabilities": [{ "id": "allow", "permission": "connect" }] }
  ]
}
```

**Response 200**:
```json
{ "status": "ok" }
```

**Errors**:

| Status Code | Condition |
|--------|------|
| `400` | JSON parsing failed or configuration validation failed |

---

### PUT /api/v1/gateway/capabilities/{scheme}

Replace the configuration of the specified Scheme.

**Role**: `gateway:admin`

**Path parameters**:

| Parameter | Description |
|------|------|
| `scheme` | Capability scheme identifier |

**Request body**:
```json
{
  "capabilities": [
    { "id": "allow", "permission": "connect" }
  ]
}
```

**Response 200**:
```json
{ "status": "ok" }
```

---

### POST /api/v1/gateway/capabilities/{scheme}/capabilities

Add a capability rule to the specified Scheme.

**Role**: `gateway:admin`

**Path parameters**:

| Parameter | Description |
|------|------|
| `scheme` | Capability scheme identifier |

**Request body**:
```json
{ "id": "deny", "permission": "disconnect" }
```

**Response 201**:
```json
{ "status": "ok", "capability_id": "deny" }
```

**Errors**:

| Status Code | Condition |
|--------|------|
| `400` | Request body parsing failed |
| `404` | Scheme does not exist |

---

### DELETE /api/v1/gateway/capabilities/{scheme}

Delete the specified Scheme and all of its capability rules.

**Role**: `gateway:admin`

**Path parameters**:

| Parameter | Description |
|------|------|
| `scheme` | Capability scheme identifier |

**Response 200**:
```json
{ "status": "ok", "scheme": "tunnel:prod" }
```

**Errors**:

| Status Code | Condition |
|--------|------|
| `404` | Scheme does not exist |

---

### DELETE /api/v1/gateway/capabilities/{scheme}/capabilities/{id}

Delete a capability rule from the specified Scheme.

**Role**: `gateway:admin`

**Path parameters**:

| Parameter | Description |
|------|------|
| `scheme` | Capability scheme identifier |
| `id` | Capability rule ID |

**Response 200**:
```json
{ "status": "ok", "capability_id": "deny" }
```

**Errors**:

| Status Code | Condition |
|--------|------|
| `404` | Scheme or Capability does not exist |

---

### POST /api/v1/gateway/capabilities/validate

Validate the legality of a capability configuration without persisting it.

**Role**: `gateway:admin`

**Request body**:
```json
{
  "schemes": [
    { "scheme": "test", "capabilities": [{ "id": "allow", "permission": "connect" }] }
  ]
}
```

**Response 200**:
```json
{ "valid": true }
```

**Errors**:

| Status Code | Condition |
|--------|------|
| `400` | Invalid configuration (with specific error message) |

---

### GET /api/v1/gateway/audit/search

Full-text audit search (requires `audit_index_file` to be configured; returns 404 if not configured).

**Roles**: `gateway:audit` or `gateway:admin`

**Query parameters**:

| Parameter | Type | Description |
|------|------|------|
| `q` | string | Full-text keyword (FTS sub-index) |
| `action` | string | Action filter (connected/disconnected/denied/…) |
| `agent_id` | string | Agent filter |
| `mapping` | string | Mapping/listener name filter |
| `client_cn` | string | Client CN filter |
| `since`/`until` | int | Time window (Unix seconds) |
| `limit` | int | Maximum number of entries returned (default 50) |

**Response 200**:
```json
{ "results": [ { "hash": "sha256:…", "entry": { "time": "…", "action": "deny", "agent_id": "agent-1" } } ], "count": 1 }
```

### GET /api/v1/gateway/connections

Real-time connection details (agent/principal/source IP/protocol/certificate serial number/establishment time).

**Roles**: `gateway:ops` or `gateway:admin`

**Response 200**:
```json
{ "connections": [ { "agent_id": "agent-1", "principal": "user@varwof.com", "src_ip": "10.0.0.5", "protocol": "http", "serial": "1A2B", "established": 1755200000 } ] }
```

### GET /api/v1/gateway/access-points

Aggregate active connections by source IP (detects suspicious access where multiple agents/multiple protocols share a source IP).

**Roles**: `gateway:ops` or `gateway:admin`

**Response 200**:
```json
{ "access_points": [ { "src_ip": "10.0.0.5", "connections": 2, "agents": ["agent-1", "agent-2"], "protocols": ["http"] } ] }
```

### GET /api/v1/gateway/agents

Directory of active agents and their real-time status.

**Roles**: `gateway:ops` or `gateway:admin`

**Response 200**:
```json
{ "agents": [ { "agent_id": "agent-1", "principal": "user@varwof.com", "connections": 2, "protocols": ["http"], "src_ips": ["10.0.0.5"], "serial": "1A2B", "last_seen": 1755200000 } ] }
```

### POST /api/v1/gateway/disconnect-agent

Disconnect all associated connections by `agent_id`.

**Role**: `gateway:admin`

**Request body**:
```json
{ "agent_id": "agent-001" }
```

**Response 200**:
```json
{ "status": "ok", "disconnected": 3, "agent_id": "agent-001" }
```

**Errors**:

| Status Code | Condition |
|--------|------|
| `400` | `agent_id` is empty |

---

### POST /api/v1/gateway/disconnect-user

Disconnect all associated connections by `principal_uid`.

**Role**: `gateway:admin`

**Request body**:
```json
{ "principal_uid": "user-abc-123" }
```

**Response 200**:
```json
{ "status": "ok", "disconnected": 2, "principal_uid": "user-abc-123" }
```

**Errors**:

| Status Code | Condition |
|--------|------|
| `400` | `principal_uid` is empty |

---

## Data Plane Endpoints

Data plane endpoints run on the HTTP proxy port (not the management port) and share the same listener as proxied requests to `GET /`. Endpoint paths start with `_` to avoid conflicts with backend paths; mTLS authentication is completed at the TLS handshake layer, with no separate RBAC required.

> Note (W24, 2026-08-16): This document previously claimed `/_auth`/`/_heartbeat`/`/_session` data plane endpoints, but they were never implemented in code and have been removed from this document. Long-lived connection session semantics are covered by GatewaySession enforcement (CIDR + hard timeout) and certificate lifecycle (CRL/OCSP/DisconnectOnExpiry).

### GET /_timestamp

Server time synchronization. Returns the current Unix timestamp and ISO 8601 string.

**Authentication**: None (public)

**Response 200**:
```json
{
  "timestamp": 1720156800,
  "iso8601": "2026-07-05T10:00:00Z"
}
```

---

## Status Code Summary

| Status Code | Meaning |
|--------|------|
| `200` | Success |
| `201` | Created successfully |
| `400` | Malformed request |
| `401` | mTLS authentication failed |
| `403` | Insufficient role |
| `404` | Resource does not exist |
| `409` | Resource already exists |
| `429` | Connection limit exceeded |
| `500` | Server error |

## Error Response Format

```json
{ "error": "listener already exists" }
```

Management API error responses use `Content-Type: application/json`.

Data plane API error response format:

```json
{ "error": "http.mtls_required", "message": "mTLS client certificate required" }
```
