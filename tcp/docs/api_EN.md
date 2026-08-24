# Management API Reference

The management API provides RESTful endpoints for dynamically managing gateway mappings, querying audits, monitoring health status, and managing runtime behavior.

## Authentication

All management API endpoints are protected by mTLS. Clients must present a certificate issued by a trusted CA, and the role encoded in the OU field must satisfy the RBAC role required by the endpoint.

## Base Path

```
https://<gateway-mgmt>:7444/api/v1/gateway/
```

## Endpoint List

### List Mappings

```
GET /api/v1/gateway/mappings
```

Returns all active TCP mapping configurations and their runtime states.

**RBAC roles:** `gateway:admin`

**Response 200:**

```json
[
  {
    "name": "postgres-prod",
    "listen": ":7443",
    "target": "10.0.1.10:5432,10.0.1.11:5432",
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
```

**RBAC roles:** `gateway:admin`

**Request body:**

```json
{
  "name": "mysql-prod",
  "listen": ":7446",
  "target": "10.0.1.30:3306",
  "protocol": "tcp+mtls",
  "tls": {
    "mode": "mtls",
    "allow_roles": ["admin"],
    "audit_file": "/var/log/gateway-tcp/mysql.audit.jsonl"
  }
}
```

**Response 201:**

```json
{
  "status": "ok",
  "name": "mysql-prod"
}
```

**Error 400:**

```json
{
  "error": "mapping 'mysql-prod' listen port 7446 already in use"
}
```

### Delete Mapping

```
DELETE /api/v1/gateway/mappings/{name}
```

**RBAC roles:** `gateway:admin`

**Path parameters:**

| Parameter | Type   | Description     |
|--------|--------|----------|
| `name` | string | Mapping name |

**Response 200:**

```json
{
  "status": "ok",
  "name": "mysql-prod"
}
```

**Error 404:**

```json
{
  "error": "mapping 'mysql-prod' not found"
}
```

### Hot Reload

```
POST /api/v1/gateway/reload
```

Reloads all mappings from the configuration file (without interrupting existing connections). The short-lived certificate auto-renewal loop and the ConnExpiryRegistry cleanup loop keep running across reloads (W04 fix: the renewal loop binds to a separate `renewalCh` and stops only on process exit; the cleanup loop restarts with the new `stopCh`).

**RBAC roles:** `gateway:admin`

**Response 200:**

```json
{
  "status": "ok"
}
```

### Force CRL Refresh

```
POST /api/v1/gateway/crl/reload
```

Immediately re-downloads and parses all CRLs (ignoring cache TTL).

**RBAC roles:** `gateway:admin`

**Response 200:**

```json
{
  "reloaded": 2,
  "errors": []
}
```

On partial failure, returns the number of refreshed caches and the error list:

```json
{
  "reloaded": 1,
  "errors": ["http://crl.example.com/ca.crl: connection refused"]
}
```

### Audit Query

```
GET /api/v1/gateway/audit?since=2025-01-01T00:00:00Z&until=2025-01-15T23:59:59Z&action=connect&mapping=postgres-prod&role=admin&limit=100&offset=0
```

**RBAC roles:** `gateway:audit`, `gateway:admin`

**Query parameters:**

| Parameter | Type     | Required | Description                                                         |
|----------|----------|------|--------------------------------------------------------------|
| `since`  | RFC3339  | No   | Start time                                                     |
| `until`  | RFC3339  | No   | End time                                                     |
| `action` | string   | No   | Filter by action type (connect / disconnect / deny)                  |
| `mapping`| string   | No   | Filter by mapping name                                               |
| `cn`     | string   | No   | Filter by client certificate CN                                         |
| `serial` | string   | No   | Filter by certificate serial number (hexadecimal)                                  |
| `role`   | string   | No   | Filter by role                                                   |
| `limit`  | int      | No   | Max entries returned (all entries returned if omitted)                               |
| `offset` | int      | No   | Pagination offset, used together with `limit`                                  |
| `sort`   | string   | No   | `asc` (default, forward) or `desc` (reverse). `desc` reads from the end of the file  |

**Response 200:**

```json
{
  "total": 152,
  "limit": 100,
  "offset": 0,
  "entries": [
    {
      "timestamp": "2025-01-15T10:00:30Z",
      "client_dn": "CN=alice@example.com,OU=gateway:admin",
      "role": "admin",
      "mapping": "postgres-prod",
      "target": "10.0.1.10:5432",
      "action": "connect",
      "duration_ms": 15000,
      "bytes_sent": 1024,
      "bytes_received": 4096,
      "tsa_signature": "MIIFvgYJKoZIhvcNAQcCo..."
    }
  ],
  "tsa_cert_url": "http://tsa.example.com/tsa-cert.pem"
}
```

The `tsa_signature` field is the DER encoding (Base64) of an RFC 3161 TimeStampResp and can be used to independently verify audit record integrity with the TSA certificate.

**Performance mechanisms:**

- **Startup archiving**: at startup the gateway automatically renames the old `audit.log` to `audit.log.<timestamp>.archived`; the API only searches the small current-session file
- **Time-based binary search jump**: the `since` parameter locates the file offset via binary search without reading the first half
- **Reverse reading**: `sort=desc` reads from the end of the file, suitable for fetching the latest records
- **Pagination truncation**: `limit`/`offset` truncate during reading; the full dataset is never loaded into memory

### Audit Verification

```
POST /api/v1/gateway/audit/verify
Content-Type: application/json
```

Verifies the integrity of an audit entry in the Merkle hash chain. The client provides the batch number, leaf hash, and proof path; the server returns the verification result.

**RBAC roles:** `gateway:audit`, `gateway:admin`

**Request body:**

```json
{
  "batch": 3,
  "leaf": "a1b2c3d4e5f6...",
  "proof": [
    {"sibling": "f0e1d2c3b4a5...", "left": true},
    {"sibling": "0a1b2c3d4e5f...", "left": false}
  ]
}
```

| Field   | Type             | Description                              |
|---------|------------------|-----------------------------------|
| `batch` | int              | Audit batch number (one batch per 1000 entries)    |
| `leaf`  | string           | Leaf node SHA-256 hash (hexadecimal) |
| `proof` | ProofStepJSON[]  | Merkle proof path                   |

**Response 200 (valid):**

```json
{
  "valid": true
}
```

**Response 200 (invalid):**

```json
{
  "valid": false,
  "error": "root hash mismatch"
}
```

### Health Check

```
GET /api/v1/gateway/health
```

**RBAC roles:** none required (public endpoint)

**Response 200:**

```json
{
  "status": "ok"
}
```

### Prometheus Metrics

```
GET /api/v1/gateway/metrics
```

Returns gateway runtime metrics in Prometheus format, including connection counts, request latency distributions, rejected connection counts, and more.

**RBAC roles:** `gateway:ops`, `gateway:admin`

**Response 200 (Content-Type: text/plain):**

```
# HELP pki_gateway_active_conns Active connections per mapping
# TYPE pki_gateway_active_conns gauge
pki_gateway_active_conns{mapping="postgres-prod"} 5
# HELP pki_gateway_conns_total Total connections handled
# TYPE pki_gateway_conns_total counter
pki_gateway_conns_total{mapping="postgres-prod"} 1520
# HELP pki_gateway_conn_duration_seconds Connection duration distribution
# TYPE pki_gateway_conn_duration_seconds histogram
pki_gateway_conn_duration_seconds_bucket{le="0.1"} 42
pki_gateway_conn_duration_seconds_bucket{le="0.5"} 389
pki_gateway_conn_duration_seconds_bucket{le="+Inf"} 1500
# HELP pki_gateway_build_info Build information
# TYPE pki_gateway_build_info gauge
pki_gateway_build_info{version="1.0.0"} 1
```

### List Capability Plugins

```
GET /api/v1/gateway/plugins
```

Returns a summary list of all registered capability plugins.

**RBAC roles:** `gateway:ops`, `gateway:admin`

**Response 200:**

```json
[
  {"scheme": "urn:varwof:capability:internal-allowlist", "type": "allowlist"},
  {"scheme": "urn:varwof:capability:internal-deny", "type": "denylist"}
]
```

### View Single Plugin

```
GET /api/v1/gateway/plugins/{scheme}
```

Queries the configuration summary of a single plugin by Scheme ID.

**RBAC roles:** `gateway:ops`, `gateway:admin`

**Path parameters:**

| Parameter | Type   | Description                            |
|----------|--------|----------------------------------|
| `scheme` | string | Capability plugin Scheme ID (URL-encoded) |

**Response 200:**

```json
{
  "scheme": "urn:varwof:capability:internal-allowlist",
  "type": "allowlist"
}
```

**Error 404:**

```json
{
  "error": "plugin not found"
}
```

### Replace All Plugins

```
PUT /api/v1/gateway/plugins
Content-Type: application/json
```

Replaces all capability plugins with the configuration in the request. This operation clears the existing plugin registry and rebuilds it from scratch.

**RBAC roles:** `gateway:admin`

**Request body:**

```json
[
  {
    "scheme": "urn:varwof:capability:internal-allowlist",
    "type": "allowlist",
    "config": {
      "allowed_roles": ["admin", "ops"]
    }
  },
  {
    "scheme": "urn:varwof:capability:custom-webhook",
    "type": "webhook",
    "config": {
      "url": "https://webhook.example.com/verify",
      "timeout_sec": 5
    }
  }
]
```

**Response 200:**

```json
{
  "status": "ok",
  "action": "plugins_replaced",
  "policy_version": 1
}
```

> The gateway is bound to a `PolicyManager`: every replacement produces a monotonically increasing `policy_version`. Version history can be viewed via `GET /api/v1/gateway/policies/versions` and rolled back via `POST /api/v1/gateway/policies/rollback`.

**Error 503:**

```json
{
  "error": "plugin registry not configured"
}
```

### Clear All Plugins

```
DELETE /api/v1/gateway/plugins
```

Clears all registered capability plugins.

**RBAC roles:** `gateway:admin`

**Response 200:**

```json
{
  "status": "ok",
  "action": "plugins_cleared"
}
```

### View Policy Version History

```
GET /api/v1/gateway/policies/versions
```

Lists all policy version snapshots (including the currently active version, ascending). Every management API publish or SIGHUP hot reload produces a new version.

**RBAC roles:** `gateway:ops` or `gateway:admin`

**Response 200:**

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
      "configs": {"ssh-access": {"type": "allowlist", "config": {"allow": ["read"]}}}
    },
    {
      "version": 2,
      "source": "sighup",
      "timestamp": "2026-08-13T11:00:00Z",
      "configs": {}
    }
  ]
}
```

### Roll Back Policy

```
POST /api/v1/gateway/policies/rollback
Content-Type: application/json
```

Rebuilds the policy registry to the content of the specified version and produces a new monotonically increasing version number.

**RBAC roles:** `gateway:admin`

**Request body:**

```json
{"version": 1}
```

**Response 200:**

```json
{
  "status": "ok",
  "action": "policy_rolled_back",
  "new_version": 3
}
```

**Error 400:** unknown version or below the `MinRollbackVersion` lower bound.

### Manage Policy Branches (Canary Rollout)

```
GET    /api/v1/gateway/policies/branches
PUT    /api/v1/gateway/policies/branches
DELETE /api/v1/gateway/policies/branches
```

Task 5b branch control: routes specific agents to specific policy versions by agent identity, enabling canary rollouts and multiple policy lines. Agents matching a branch use the branch version in both admission decisions and audit binding; all other agents fall back to the currently active version.

- **GET** (roles `gateway:ops`/`gateway:admin`) lists current branch rules:

```json
{
  "current_version": 2,
  "count": 1,
  "branches": [
    {"id": "canary", "agent_id": "agent-canary-*", "version": 1, "priority": 10, "comment": "canary rollout"}
  ]
}
```

- **PUT** (role `gateway:admin`) replaces all branch rules; request body:

```json
{
  "branches": [
    {"id": "canary", "agent_id": "agent-canary-*", "version": 1, "priority": 10, "comment": "canary rollout"}
  ]
}
```

Response `{"status":"ok","action":"policy_branches_replaced","count":1}`. Error `400`: missing/duplicate IDs, empty AgentID, or reference to an unpublished version.

- **DELETE** (role `gateway:admin`) clears all branches, restoring all agents to the currently active version.

Matching rules: `*` matches everything, `a-*` prefix match, others exact match; on multiple hits the first by descending `priority` wins.

### Audit Full-Text Search (Monitoring Presentation Layer, 2026-08-15)

```
GET /api/v1/gateway/audit/search?q=keyword&action=deny&agent_id=agent-1&mapping=m&client_cn=cn&since=1755200000&until=1755300000&limit=50
```

Full-text search over the audit index (requires `audit_index_file` to be configured; returns 404 otherwise). Search scopes can be combined: full-text keywords (FTS), action, agent, mapping, client CN, and time window (Unix seconds).

**RBAC roles:** `gateway:audit` or `gateway:admin`

**Response 200:**

```json
{
  "results": [
    {
      "hash": "sha256:…",
      "entry": { "time": "…", "action": "deny", "agent_id": "agent-1", "mapping": "…", "target": "…", "deny_reason": "…" }
    }
  ],
  "count": 3
}
```

### Real-Time Connection Details (Monitoring Presentation Layer, 2026-08-15)

```
GET /api/v1/gateway/connections
```

Returns details of currently active connections: agent, principal, source IP, protocol, certificate serial number, establishment time.

**RBAC roles:** `gateway:ops` or `gateway:admin`

**Response 200:**

```json
{
  "connections": [
    { "agent_id": "agent-1", "principal": "user@varwof.com", "src_ip": "10.0.0.5", "protocol": "tcp", "serial": "1A2B", "established": 1755200000 }
  ]
}
```

### IP Access Points (Monitoring Presentation Layer, 2026-08-15)

```
GET /api/v1/gateway/access-points
```

Aggregates active connections by source IP (detects suspicious access where multiple agents/protocols share the same source IP).

**RBAC roles:** `gateway:ops` or `gateway:admin`

**Response 200:**

```json
{
  "access_points": [
    { "src_ip": "10.0.0.5", "connections": 2, "agents": ["agent-1", "agent-2"], "protocols": ["tcp"] }
  ]
}
```

### Agent Directory (Monitoring Presentation Layer, 2026-08-15)

```
GET /api/v1/gateway/agents
```

Returns the list of active agents and their real-time status: connection count, last seen time, source IPs, protocols, certificate serial number.

**RBAC roles:** `gateway:ops` or `gateway:admin`

**Response 200:**

```json
{
  "agents": [
    { "agent_id": "agent-1", "principal": "user@varwof.com", "connections": 2, "protocols": ["tcp"], "src_ips": ["10.0.0.5"], "serial": "1A2B", "last_seen": 1755200000 }
  ]
}
```

### Disconnect by Agent

```
POST /api/v1/gateway/disconnect-agent
Content-Type: application/json
```

Disconnects all active connections of the agent identified by `agent_id`.

**RBAC roles:** `gateway:admin`

**Request body:**

```json
{
  "agent_id": "agent-abc123"
}
```

**Response 200:**

```json
{
  "status": "ok",
  "agent_id": "agent-abc123",
  "disconnected": 3
}
```

**Error 400:**

```json
{
  "error": "agent_id is required"
}
```

### Disconnect by User

```
POST /api/v1/gateway/disconnect-user
Content-Type: application/json
```

Disconnects all active connections of the user identified by `principal_uid`.

**RBAC roles:** `gateway:admin`

**Request body:**

```json
{
  "principal_uid": "user-xyz789"
}
```

**Response 200:**

```json
{
  "status": "ok",
  "principal_uid": "user-xyz789",
  "disconnected": 5
}
```

### List Mesh Peers (Conditional)

```
GET /api/v1/gateway/peers
```

Available only when the gateway has `peers` configured (mesh mode). Returns information for all configured peer nodes.

**RBAC roles:** `gateway:ops`

**Response 200:**

```json
[
  {"name": "peer-dc1", "addr": "10.0.0.1:7443"},
  {"name": "peer-dc2", "addr": "10.0.0.2:7443"}
]
```

**Error 404:**

Returned when mesh is not enabled.

### Manually Trigger Short-Lived Certificate Renewal

```
POST /api/v1/gateway/renew
Content-Type: application/json
```

Manually triggers short-lived certificate renewal for the current mTLS client certificate. The client authenticates with its current certificate identity and provides a new public key in the request body.

**RBAC roles:** `gateway:ops`, `gateway:admin`

**Request body:**

```json
{
  "serial_hex": "ABCD1234",
  "new_pub_key_pem": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0K..."
}
```

| Field            | Type   | Description                                                    |
|------------------|--------|----------------------------------------------------------|
| `serial_hex`     | string | Current certificate serial number (hexadecimal); must match the client certificate            |
| `new_pub_key_pem`| string | Public key of the new key pair (PKIX PEM format, Base64-encoded string)    |

**Response 200:**

```json
{
  "allowed": true,
  "cert_pem": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t...",
  "key_pem": "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQo...",
  "new_expiry": "2025-01-25T10:30:00Z"
}
```

**Error 400:**

```json
{
  "error": "serial_hex and new_pub_key_pem required"
}
```

**Error 503:**

```json
{
  "error": "short-lived cert issuance not configured"
}
```

## HTTP Status Codes

| Status Code | Description                       |
|--------|----------------------------|
| 200    | Success                       |
| 201    | Resource created successfully               |
| 400    | Invalid request parameters               |
| 401    | mTLS authentication failed              |
| 403    | Insufficient role permissions               |
| 404    | Resource not found                 |
| 409    | Resource conflict (e.g. mapping name already exists) |
| 500    | Internal error                   |
| 502    | Upstream service unavailable             |
| 503    | Service not configured                 |
