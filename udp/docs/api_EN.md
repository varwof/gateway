# Management API Reference

## Base URL

```
https://127.0.0.1:9092/api/v1/gateway/
```

All APIs require mTLS client certificate authentication; the OU determines the RBAC role. Permission matrix:

| Role | Accessible Endpoints |
|------|-----------|
| **admin** | All endpoints |
| **ops** | metrics, plugins (read-only) |
| **audit** | audit, audit/verify |
| Others / no certificate | health only |

## Endpoints

### Health Check

```bash
curl -sk --cert admin.pem --key admin.key \
  https://127.0.0.1:9092/api/v1/gateway/health
```

Response: `{"status":"ok"}`

### List Listeners

```bash
curl -sk --cert admin.pem --key admin.key \
  https://127.0.0.1:9092/api/v1/gateway/listeners
```

### Add Listener

```bash
curl -sk --cert admin.pem --key admin.key -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "name":"dns",
    "listen":"127.0.0.1:5353",
    "protocol":"udp",
    "routes":[{"target":"8.8.8.8:53"}]
  }' \
  https://127.0.0.1:9092/api/v1/gateway/listeners
```

### Delete Listener

```bash
curl -sk --cert admin.pem --key admin.key -X DELETE \
  https://127.0.0.1:9092/api/v1/gateway/listeners/dns
```

### Audit Log

Query parameters: `limit`, `since`, `until`, `offset`, `sort` (asc/desc), `action`, `cn`, `serial`, `mapping`

```bash
# Most recent 10 entries
curl -sk --cert auditor.pem --key auditor.key \
  "https://127.0.0.1:9092/api/v1/gateway/audit?limit=10"

# Filter by time range
curl -sk --cert auditor.pem --key auditor.key \
  "https://127.0.0.1:9092/api/v1/gateway/audit?since=2026-07-09T00:00:00Z&until=2026-07-10T00:00:00Z"

# Filter by client CN
curl -sk --cert auditor.pem --key auditor.key \
  "https://127.0.0.1:9092/api/v1/gateway/audit?cn=agent-sensor-01"

# Pagination
curl -sk --cert auditor.pem --key auditor.key \
  "https://127.0.0.1:9092/api/v1/gateway/audit?limit=20&offset=40&sort=desc"
```

### Audit Entry Verification

Verify an audit entry against the Merkle hash chain. Requires `batch`, `leaf`, and `proof` information obtained from the audit log.

```bash
curl -sk --cert admin.pem --key admin.key -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "batch": 1,
    "leaf": "a1b2c3d4e5f6...",
    "proof": [
      {"sibling": "f6e5d4c3b2a1...", "left": true},
      {"sibling": "112233445566...", "left": false}
    ]
  }' \
  https://127.0.0.1:9092/api/v1/gateway/audit/verify
```

Response (valid): `{"valid":true}`
Response (invalid): `{"valid":false,"error":"root hash mismatch"}`

### Prometheus Metrics

```bash
curl -sk --cert ops.pem --key ops.key \
  https://127.0.0.1:9092/api/v1/gateway/metrics
```

### Hot Reload

Reload the configuration file (equivalent to SIGHUP), refreshing listeners, CRL caches, and the plugin registry. The short-lived certificate auto-renewal loop and the ConnExpiryRegistry cleanup loop keep running after reload (W04 fix: the renewal loop is bound to a dedicated `renewalCh` and only stops on process exit; the cleanup loop restarts with the new `stopCh`).

```bash
curl -sk --cert admin.pem --key admin.key -X POST \
  https://127.0.0.1:9092/api/v1/gateway/reload
```

### Force CRL Cache Refresh

Perform a forced refresh for every configured CRL distribution point.

```bash
curl -sk --cert admin.pem --key admin.key -X POST \
  https://127.0.0.1:9092/api/v1/gateway/crl/reload
```

Response:

```json
{"reloaded":3,"errors":[]}
```

### List Plugins

Summary of all capability plugins in the registry.

```bash
curl -sk --cert ops.pem --key ops.key \
  https://127.0.0.1:9092/api/v1/gateway/plugins
```

Response:

```json
[
  {"scheme":"urn:varwof:capability:allowlist","type":"allowlist"},
  {"scheme":"urn:varwof:capability:rbac","type":"rbac"}
]
```

### View a Single Plugin

View plugin details by scheme.

```bash
curl -sk --cert ops.pem --key ops.key \
  https://127.0.0.1:9092/api/v1/gateway/plugins/urn:varwof:capability:allowlist
```

### Replace All Plugins

Replace the entire plugin registry with new configuration (full overwrite).

```bash
curl -sk --cert admin.pem --key admin.key -X PUT \
  -H "Content-Type: application/json" \
  -d '[
    {"scheme":"urn:varwof:capability:allowlist","type":"allowlist","config":{"allowed_agents":["sensor-*"]}},
    {"scheme":"urn:varwof:capability:denylist","type":"denylist","config":{"denied_agents":["compromised-*"]}}
  ]' \
  https://127.0.0.1:9092/api/v1/gateway/plugins
```

Response (includes `policy_version` when the gateway has a `PolicyManager` bound):

```json
{"status":"ok","action":"plugins_replaced","policy_version":1}
```

### View Policy Version History

List all policy version snapshots (including the currently active version, ascending). Each management API publish or SIGHUP hot reload produces a new version.

```bash
curl -sk --cert ops.pem --key ops.key \
  https://127.0.0.1:9092/api/v1/gateway/policies/versions
```

Response:

```json
{
  "current_version": 1,
  "count": 1,
  "versions": [
    {
      "version": 1,
      "source": "api",
      "operator": "admin",
      "timestamp": "2026-08-13T10:20:00Z",
      "configs": []
    }
  ]
}
```

### Roll Back Policy

Rebuild the policy registry to the content of a specified version, producing a new monotonically increasing version number.

```bash
curl -sk --cert admin.pem --key admin.key -X POST \
  -H "Content-Type: application/json" \
  -d '{"version":1}' \
  https://127.0.0.1:9092/api/v1/gateway/policies/rollback
```

Response:

```json
{"status":"ok","action":"policy_rolled_back","new_version":2}
```

### Manage Policy Branches (Canary Release)

Task 5b branch control: route specific Agents to specific policy versions by Agent identifier, enabling canary releases and multiple policy tracks. Agents matching a branch use the branch version in both admission decisions and audit binding; all others fall back to the currently active version.

```bash
# List branch rules (ops/admin)
curl -sk --cert ops.pem --key ops.key \
  https://127.0.0.1:9092/api/v1/gateway/policies/branches

# Replace all branch rules (admin)
curl -sk --cert admin.pem --key admin.key -X PUT \
  -H "Content-Type: application/json" \
  -d '{"branches":[{"id":"canary","agent_id":"agent-canary-*","version":1,"priority":10}]}' \
  https://127.0.0.1:9092/api/v1/gateway/policies/branches

# Clear branch rules (admin)
curl -sk --cert admin.pem --key admin.key -X DELETE \
  https://127.0.0.1:9092/api/v1/gateway/policies/branches
```

Matching rules: `*` matches everything, `a-*` matches prefixes, anything else is exact; when multiple branches match, the one with the highest `priority` wins.

### Clear All Plugins

```bash
curl -sk --cert admin.pem --key admin.key -X DELETE \
  https://127.0.0.1:9092/api/v1/gateway/plugins
```

### Full-Text Audit Search

Requires `audit_index_file` to be configured (returns 404 if not configured).

```bash
curl -sk --cert audit.pem --key audit.key \
  "https://127.0.0.1:9092/api/v1/gateway/audit/search?q=deny&agent_id=agent-sensor-01&limit=10"
```

**Roles**: `gateway:audit` or `gateway:admin`

Parameters: `q` (full text), `action`, `agent_id`, `mapping`, `client_cn`, `since`/`until` (Unix seconds), `limit`.

Response:

```json
{"results":[{"hash":"sha256:…","entry":{"time":"…","action":"denied","agent_id":"agent-sensor-01"}}],"count":1}
```

### Live Connection Details

```bash
curl -sk --cert ops.pem --key ops.key \
  https://127.0.0.1:9092/api/v1/gateway/connections
```

**Roles**: `gateway:ops` or `gateway:admin`

Response:

```json
{"connections":[{"agent_id":"agent-sensor-01","principal":"user@varwof.com","src_ip":"10.0.0.7","protocol":"dtls","serial":"1A2B","established":1755200000}]}
```

### IP Access Points

```bash
curl -sk --cert ops.pem --key ops.key \
  https://127.0.0.1:9092/api/v1/gateway/access-points
```

**Roles**: `gateway:ops` or `gateway:admin`

Response:

```json
{"access_points":[{"src_ip":"10.0.0.7","connections":2,"agents":["agent-sensor-01"],"protocols":["dtls","quic"]}]}
```

### Agent Directory

```bash
curl -sk --cert ops.pem --key ops.key \
  https://127.0.0.1:9092/api/v1/gateway/agents
```

**Roles**: `gateway:ops` or `gateway:admin`

Response:

```json
{"agents":[{"agent_id":"agent-sensor-01","principal":"user@varwof.com","connections":2,"protocols":["dtls"],"src_ips":["10.0.0.7"],"serial":"1A2B","last_seen":1755200000}]}
```

### Disconnect Agent Connections

Disconnect all active connections by `agent_id` (extracted from the AIC certificate).

```bash
curl -sk --cert admin.pem --key admin.key -X POST \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agent-sensor-01"}' \
  https://127.0.0.1:9092/api/v1/gateway/disconnect-agent
```

Response:

```json
{"status":"ok","disconnected":3,"agent_id":"agent-sensor-01"}
```

### Disconnect User Connections

Disconnect all active connections by `principal_uid`.

```bash
curl -sk --cert admin.pem --key admin.key -X POST \
  -H "Content-Type: application/json" \
  -d '{"principal_uid":"user-zhang@example.com"}' \
  https://127.0.0.1:9092/api/v1/gateway/disconnect-user
```

## Python Example

```python
import requests

BASE = "https://127.0.0.1:9092/api/v1/gateway"

# Health check (no RBAC)
r = requests.get(f"{BASE}/health",
    cert=("admin.pem", "admin.key"), verify=False)
print(r.json())

# List listeners
r = requests.get(f"{BASE}/listeners",
    cert=("admin.pem", "admin.key"), verify=False)
for lis in r.json():
    print(f"  {lis['name']} ({lis['tls_mode']}): {lis['listen']}")

# Add listener
payload = {
    "name": "dns", "listen": "127.0.0.1:5353",
    "protocol": "udp", "routes": [{"target": "8.8.8.8:53"}]
}
r = requests.post(f"{BASE}/listeners", json=payload,
    cert=("admin.pem", "admin.key"), verify=False)

# Audit log
r = requests.get(f"{BASE}/audit?limit=5",
    cert=("auditor.pem", "auditor.key"), verify=False)
for entry in r.json():
    print(f"  [{entry['time']}] {entry['action']} - {entry['client_cn']}")

# Audit entry verification
verify_payload = {
    "batch": 1,
    "leaf": "a1b2c3d4e5f67890abcdef1234567890",
    "proof": [
        {"sibling": "fedcba0987654321fedcba0987654321", "left": True}
    ]
}
r = requests.post(f"{BASE}/audit/verify", json=verify_payload,
    cert=("admin.pem", "admin.key"), verify=False)
print("proof valid:", r.json()["valid"])

# List plugins
r = requests.get(f"{BASE}/plugins",
    cert=("ops.pem", "ops.key"), verify=False)
print("plugins:", r.json())

# Replace all plugins
plugins = [
    {"scheme": "urn:varwof:capability:allowlist",
     "type": "allowlist",
     "config": {"allowed_agents": ["sensor-*"]}}
]
r = requests.put(f"{BASE}/plugins", json=plugins,
    cert=("admin.pem", "admin.key"), verify=False)

# Clear plugins
r = requests.delete(f"{BASE}/plugins",
    cert=("admin.pem", "admin.key"), verify=False)

# Force CRL refresh
r = requests.post(f"{BASE}/crl/reload",
    cert=("admin.pem", "admin.key"), verify=False)
print("crl reloaded:", r.json()["reloaded"])

# Disconnect agent
r = requests.post(f"{BASE}/disconnect-agent",
    json={"agent_id": "agent-sensor-01"},
    cert=("admin.pem", "admin.key"), verify=False)
print("disconnected:", r.json()["disconnected"])

# Disconnect user
r = requests.post(f"{BASE}/disconnect-user",
    json={"principal_uid": "user-zhang@example.com"},
    cert=("admin.pem", "admin.key"), verify=False)
print("disconnected:", r.json()["disconnected"])

# Prometheus metrics
r = requests.get(f"{BASE}/metrics",
    cert=("ops.pem", "ops.key"), verify=False)
print(r.text[:500])

# Hot reload
r = requests.post(f"{BASE}/reload",
    cert=("admin.pem", "admin.key"), verify=False)
print(r.json())
```

## Error Responses

All endpoints return the following on authentication failure:

```json
{"error":"mTLS required"}
```

On insufficient permissions:

```json
{"error":"insufficient permissions"}
```
