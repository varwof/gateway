# 管理 API 参考

## 基础地址

```
https://127.0.0.1:9092/api/v1/gateway/
```

所有 API 需 mTLS 客户端证书认证，OU 决定 RBAC 角色。权限矩阵：

| 角色 | 可访问端点 |
|------|-----------|
| **admin** | 全部端点 |
| **ops** | metrics, plugins（只读） |
| **audit** | audit, audit/verify |
| 其他 / 无证书 | 仅 health |

## 端点

### 健康检查

```bash
curl -sk --cert admin.pem --key admin.key \
  https://127.0.0.1:9092/api/v1/gateway/health
```

响应：`{"status":"ok"}`

### 列出监听器

```bash
curl -sk --cert admin.pem --key admin.key \
  https://127.0.0.1:9092/api/v1/gateway/listeners
```

### 添加监听器

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

### 删除监听器

```bash
curl -sk --cert admin.pem --key admin.key -X DELETE \
  https://127.0.0.1:9092/api/v1/gateway/listeners/dns
```

### 审计日志

查询参数：`limit`、`since`、`until`、`offset`、`sort`（asc/desc）、`action`、`cn`、`serial`、`mapping`

```bash
# 最近 10 条
curl -sk --cert auditor.pem --key auditor.key \
  "https://127.0.0.1:9092/api/v1/gateway/audit?limit=10"

# 按时间范围过滤
curl -sk --cert auditor.pem --key auditor.key \
  "https://127.0.0.1:9092/api/v1/gateway/audit?since=2026-07-09T00:00:00Z&until=2026-07-10T00:00:00Z"

# 按客户端 CN 过滤
curl -sk --cert auditor.pem --key auditor.key \
  "https://127.0.0.1:9092/api/v1/gateway/audit?cn=agent-sensor-01"

# 分页
curl -sk --cert auditor.pem --key auditor.key \
  "https://127.0.0.1:9092/api/v1/gateway/audit?limit=20&offset=40&sort=desc"
```

### 审计条目验证

向 Merkle 哈希链验证审计条目。需要从审计日志中获取 `batch`、`leaf` 和 `proof` 信息。

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

响应（有效）：`{"valid":true}`
响应（无效）：`{"valid":false,"error":"root hash mismatch"}`

### Prometheus 指标

```bash
curl -sk --cert ops.pem --key ops.key \
  https://127.0.0.1:9092/api/v1/gateway/metrics
```

### 热重载

重新加载配置文件（SIGHUP 等效），刷新监听器、CRL 缓存和插件注册表。短命证书自动续签循环与 ConnExpiryRegistry 清理循环在 reload 后保持运行（W04 修复：续签循环绑定独立 `renewalCh`，进程退出才停止；清理循环随新 `stopCh` 重启）。

```bash
curl -sk --cert admin.pem --key admin.key -X POST \
  https://127.0.0.1:9092/api/v1/gateway/reload
```

### 强制刷新 CRL 缓存

对每个已配置的 CRL 分发点执行强制刷新。

```bash
curl -sk --cert admin.pem --key admin.key -X POST \
  https://127.0.0.1:9092/api/v1/gateway/crl/reload
```

响应：

```json
{"reloaded":3,"errors":[]}
```

### 列出插件

注册表中所有能力插件摘要。

```bash
curl -sk --cert ops.pem --key ops.key \
  https://127.0.0.1:9092/api/v1/gateway/plugins
```

响应：

```json
[
  {"scheme":"urn:varwof:capability:allowlist","type":"allowlist"},
  {"scheme":"urn:varwof:capability:rbac","type":"rbac"}
]
```

### 查看单个插件

按 scheme 查看插件详情。

```bash
curl -sk --cert ops.pem --key ops.key \
  https://127.0.0.1:9092/api/v1/gateway/plugins/urn:varwof:capability:allowlist
```

### 替换全部插件

用新的配置替换整个插件注册表（全量覆盖）。

```bash
curl -sk --cert admin.pem --key admin.key -X PUT \
  -H "Content-Type: application/json" \
  -d '[
    {"scheme":"urn:varwof:capability:allowlist","type":"allowlist","config":{"allowed_agents":["sensor-*"]}},
    {"scheme":"urn:varwof:capability:denylist","type":"denylist","config":{"denied_agents":["compromised-*"]}}
  ]' \
  https://127.0.0.1:9092/api/v1/gateway/plugins
```

响应（网关绑定 `PolicyManager` 时含 `policy_version`）：

```json
{"status":"ok","action":"plugins_replaced","policy_version":1}
```

### 查看策略版本历史

列出全部策略版本快照（含当前生效版本，升序）。每次管理 API 发布或 SIGHUP 热重载产生一个新版本。

```bash
curl -sk --cert ops.pem --key ops.key \
  https://127.0.0.1:9092/api/v1/gateway/policies/versions
```

响应：

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

### 回滚策略

将策略注册表重建为指定版本内容，并产生新的单调递增版本号。

```bash
curl -sk --cert admin.pem --key admin.key -X POST \
  -H "Content-Type: application/json" \
  -d '{"version":1}' \
  https://127.0.0.1:9092/api/v1/gateway/policies/rollback
```

响应：

```json
{"status":"ok","action":"policy_rolled_back","new_version":2}
```

### 管理策略分支（灰度发布）

任务 5b 分支控制：按 Agent 标识将指定 Agent 路由到特定策略版本，实现金丝雀灰度与多策略线。命中分支的 Agent 在准入决策与审计绑定中均使用分支版本；其余回退当前生效版本。

```bash
# 列出分支规则（ops/admin）
curl -sk --cert ops.pem --key ops.key \
  https://127.0.0.1:9092/api/v1/gateway/policies/branches

# 全量替换分支规则（admin）
curl -sk --cert admin.pem --key admin.key -X PUT \
  -H "Content-Type: application/json" \
  -d '{"branches":[{"id":"canary","agent_id":"agent-canary-*","version":1,"priority":10}]}' \
  https://127.0.0.1:9092/api/v1/gateway/policies/branches

# 清空分支规则（admin）
curl -sk --cert admin.pem --key admin.key -X DELETE \
  https://127.0.0.1:9092/api/v1/gateway/policies/branches
```

匹配规则：`*` 全量、`a-*` 前缀、其余精确；同命中按 `priority` 降序取第一条。

### 清除全部插件

```bash
curl -sk --cert admin.pem --key admin.key -X DELETE \
  https://127.0.0.1:9092/api/v1/gateway/plugins
```

### 审计全文检索

需配置 `audit_index_file`（未配置返回 404）。

```bash
curl -sk --cert audit.pem --key audit.key \
  "https://127.0.0.1:9092/api/v1/gateway/audit/search?q=deny&agent_id=agent-sensor-01&limit=10"
```

**角色**：`gateway:audit` 或 `gateway:admin`

参数：`q`（全文）、`action`、`agent_id`、`mapping`、`client_cn`、`since`/`until`（Unix 秒）、`limit`。

响应：

```json
{"results":[{"hash":"sha256:…","entry":{"time":"…","action":"denied","agent_id":"agent-sensor-01"}}],"count":1}
```

### 实时连接明细

```bash
curl -sk --cert ops.pem --key ops.key \
  https://127.0.0.1:9092/api/v1/gateway/connections
```

**角色**：`gateway:ops` 或 `gateway:admin`

响应：

```json
{"connections":[{"agent_id":"agent-sensor-01","principal":"user@varwof.com","src_ip":"10.0.0.7","protocol":"dtls","serial":"1A2B","established":1755200000}]}
```

### IP 接入点

```bash
curl -sk --cert ops.pem --key ops.key \
  https://127.0.0.1:9092/api/v1/gateway/access-points
```

**角色**：`gateway:ops` 或 `gateway:admin`

响应：

```json
{"access_points":[{"src_ip":"10.0.0.7","connections":2,"agents":["agent-sensor-01"],"protocols":["dtls","quic"]}]}
```

### Agent 目录

```bash
curl -sk --cert ops.pem --key ops.key \
  https://127.0.0.1:9092/api/v1/gateway/agents
```

**角色**：`gateway:ops` 或 `gateway:admin`

响应：

```json
{"agents":[{"agent_id":"agent-sensor-01","principal":"user@varwof.com","connections":2,"protocols":["dtls"],"src_ips":["10.0.0.7"],"serial":"1A2B","last_seen":1755200000}]}
```

### 断开 Agent 连接

按 `agent_id` 断开所有活跃连接（从 AIC 证书中提取）。

```bash
curl -sk --cert admin.pem --key admin.key -X POST \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agent-sensor-01"}' \
  https://127.0.0.1:9092/api/v1/gateway/disconnect-agent
```

响应：

```json
{"status":"ok","disconnected":3,"agent_id":"agent-sensor-01"}
```

### 断开用户连接

按 `principal_uid` 断开所有活跃连接。

```bash
curl -sk --cert admin.pem --key admin.key -X POST \
  -H "Content-Type: application/json" \
  -d '{"principal_uid":"user-zhang@example.com"}' \
  https://127.0.0.1:9092/api/v1/gateway/disconnect-user
```

## Python 示例

```python
import requests

BASE = "https://127.0.0.1:9092/api/v1/gateway"

# 健康检查（无 RBAC）
r = requests.get(f"{BASE}/health",
    cert=("admin.pem", "admin.key"), verify=False)
print(r.json())

# 列出监听器
r = requests.get(f"{BASE}/listeners",
    cert=("admin.pem", "admin.key"), verify=False)
for lis in r.json():
    print(f"  {lis['name']} ({lis['tls_mode']}): {lis['listen']}")

# 添加监听器
payload = {
    "name": "dns", "listen": "127.0.0.1:5353",
    "protocol": "udp", "routes": [{"target": "8.8.8.8:53"}]
}
r = requests.post(f"{BASE}/listeners", json=payload,
    cert=("admin.pem", "admin.key"), verify=False)

# 审计日志
r = requests.get(f"{BASE}/audit?limit=5",
    cert=("auditor.pem", "auditor.key"), verify=False)
for entry in r.json():
    print(f"  [{entry['time']}] {entry['action']} - {entry['client_cn']}")

# 审计条目验证
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

# 列出插件
r = requests.get(f"{BASE}/plugins",
    cert=("ops.pem", "ops.key"), verify=False)
print("plugins:", r.json())

# 替换全部插件
plugins = [
    {"scheme": "urn:varwof:capability:allowlist",
     "type": "allowlist",
     "config": {"allowed_agents": ["sensor-*"]}}
]
r = requests.put(f"{BASE}/plugins", json=plugins,
    cert=("admin.pem", "admin.key"), verify=False)

# 清除插件
r = requests.delete(f"{BASE}/plugins",
    cert=("admin.pem", "admin.key"), verify=False)

# 强制刷新 CRL
r = requests.post(f"{BASE}/crl/reload",
    cert=("admin.pem", "admin.key"), verify=False)
print("crl reloaded:", r.json()["reloaded"])

# 断开 Agent
r = requests.post(f"{BASE}/disconnect-agent",
    json={"agent_id": "agent-sensor-01"},
    cert=("admin.pem", "admin.key"), verify=False)
print("disconnected:", r.json()["disconnected"])

# 断开用户
r = requests.post(f"{BASE}/disconnect-user",
    json={"principal_uid": "user-zhang@example.com"},
    cert=("admin.pem", "admin.key"), verify=False)
print("disconnected:", r.json()["disconnected"])

# Prometheus 指标
r = requests.get(f"{BASE}/metrics",
    cert=("ops.pem", "ops.key"), verify=False)
print(r.text[:500])

# 热重载
r = requests.post(f"{BASE}/reload",
    cert=("admin.pem", "admin.key"), verify=False)
print(r.json())
```

## 错误响应

所有端点在认证失败时返回：

```json
{"error":"mTLS required"}
```

权限不足时：

```json
{"error":"insufficient permissions"}
```
