# 管理 API 参考

管理 API 提供 RESTful 接口用于动态管理网关映射、查询审计、监控健康状态以及管理运行时行为。

## 认证方式

所有管理 API 端点均通过 mTLS 保护。客户端必须使用由受信任 CA 签发的证书，且 OU 字段编码的角色必须满足端点要求的 RBAC 角色。

## 基础路径

```
https://<gateway-mgmt>:7444/api/v1/gateway/
```

## 端点列表

### 获取映射列表

```
GET /api/v1/gateway/mappings
```

返回所有活跃的 TCP 映射配置及其运行时状态。

**RBAC 角色：** `gateway:admin`

**响应 200：**

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

### 添加映射

```
POST /api/v1/gateway/mappings
Content-Type: application/json
```

**RBAC 角色：** `gateway:admin`

**请求体：**

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

**响应 201：**

```json
{
  "status": "ok",
  "name": "mysql-prod"
}
```

**错误 400：**

```json
{
  "error": "mapping 'mysql-prod' listen port 7446 already in use"
}
```

### 删除映射

```
DELETE /api/v1/gateway/mappings/{name}
```

**RBAC 角色：** `gateway:admin`

**路径参数：**

| 参数   | 类型   | 说明     |
|--------|--------|----------|
| `name` | string | 映射名称 |

**响应 200：**

```json
{
  "status": "ok",
  "name": "mysql-prod"
}
```

**错误 404：**

```json
{
  "error": "mapping 'mysql-prod' not found"
}
```

### 热重载

```
POST /api/v1/gateway/reload
```

从配置文件重新加载所有映射（不中断现有连接）。短命证书自动续签循环与 ConnExpiryRegistry 清理循环在 reload 后保持运行（W04 修复：续签循环绑定独立 `renewalCh`，进程退出才停止；清理循环随新 `stopCh` 重启）。

**RBAC 角色：** `gateway:admin`

**响应 200：**

```json
{
  "status": "ok"
}
```

### 强制刷新 CRL

```
POST /api/v1/gateway/crl/reload
```

立即重新下载并解析所有 CRL（忽略缓存 TTL）。

**RBAC 角色：** `gateway:admin`

**响应 200：**

```json
{
  "reloaded": 2,
  "errors": []
}
```

部分失败时返回已刷新的缓存数和错误列表：

```json
{
  "reloaded": 1,
  "errors": ["http://crl.example.com/ca.crl: connection refused"]
}
```

### 审计查询

```
GET /api/v1/gateway/audit?since=2025-01-01T00:00:00Z&until=2025-01-15T23:59:59Z&action=connect&mapping=postgres-prod&role=admin&limit=100&offset=0
```

**RBAC 角色：** `gateway:audit`, `gateway:admin`

**查询参数：**

| 参数     | 类型     | 必需 | 说明                                                         |
|----------|----------|------|--------------------------------------------------------------|
| `since`  | RFC3339  | 否   | 起始时间                                                     |
| `until`  | RFC3339  | 否   | 结束时间                                                     |
| `action` | string   | 否   | 筛选动作类型（connect / disconnect / deny）                  |
| `mapping`| string   | 否   | 按映射名称筛选                                               |
| `cn`     | string   | 否   | 按客户端证书 CN 筛选                                         |
| `serial` | string   | 否   | 按证书序列号（十六进制）筛选                                  |
| `role`   | string   | 否   | 按角色筛选                                                   |
| `limit`  | int      | 否   | 返回条数上限（不传则返回全部）                               |
| `offset` | int      | 否   | 分页偏移，配合 `limit` 使用                                  |
| `sort`   | string   | 否   | `asc`（默认，正向）或 `desc`（反向）。`desc` 从文件末尾读取  |

**响应 200：**

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

`tsa_signature` 字段为 RFC 3161 TimeStampResp 的 DER 编码（Base64），可使用 TSA 证书独立验证审计记录的完整性。

**性能机制：**

- **启动归档**：网关启动时自动将旧 `audit.log` 重命名为 `audit.log.<timestamp>.archived`，API 只查当前会话的小文件
- **时间二分跳跃**：`since` 参数通过二分查找定位文件偏移，无需读取前半部分
- **反向读取**：`sort=desc` 从文件末尾读取，适合获取最新记录
- **分页截断**：`limit`/`offset` 在读取过程中截断，不加载全部数据到内存

### 审计验证

```
POST /api/v1/gateway/audit/verify
Content-Type: application/json
```

验证审计条目在 Merkle 哈希链中的完整性。客户端需提供批次号、叶子哈希值和证明路径，服务端返回验证结果。

**RBAC 角色：** `gateway:audit`, `gateway:admin`

**请求体：**

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

| 字段    | 类型             | 说明                              |
|---------|------------------|-----------------------------------|
| `batch` | int              | 审计批次编号（每 1000 条一批）    |
| `leaf`  | string           | 叶子节点 SHA-256 哈希值（十六进制） |
| `proof` | ProofStepJSON[]  | Merkle 证明路径                   |

**响应 200（有效）：**

```json
{
  "valid": true
}
```

**响应 200（无效）：**

```json
{
  "valid": false,
  "error": "root hash mismatch"
}
```

### 健康检查

```
GET /api/v1/gateway/health
```

**RBAC 角色：** 无需认证（公开端点）

**响应 200：**

```json
{
  "status": "ok"
}
```

### Prometheus 指标

```
GET /api/v1/gateway/metrics
```

返回 Prometheus 格式的网关运行时指标，包括连接数、请求延迟分布、拒绝连接数等。

**RBAC 角色：** `gateway:ops`, `gateway:admin`

**响应 200（Content-Type: text/plain）：**

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

### 列出能力插件

```
GET /api/v1/gateway/plugins
```

返回所有已注册的能力插件（Capability Plugin）摘要列表。

**RBAC 角色：** `gateway:ops`, `gateway:admin`

**响应 200：**

```json
[
  {"scheme": "urn:varwof:capability:internal-allowlist", "type": "allowlist"},
  {"scheme": "urn:varwof:capability:internal-deny", "type": "denylist"}
]
```

### 查看单个插件

```
GET /api/v1/gateway/plugins/{scheme}
```

按 Scheme ID 查询单个插件的配置摘要。

**RBAC 角色：** `gateway:ops`, `gateway:admin`

**路径参数：**

| 参数     | 类型   | 说明                            |
|----------|--------|----------------------------------|
| `scheme` | string | 能力插件的 Scheme ID（URL 编码） |

**响应 200：**

```json
{
  "scheme": "urn:varwof:capability:internal-allowlist",
  "type": "allowlist"
}
```

**错误 404：**

```json
{
  "error": "plugin not found"
}
```

### 替换所有插件

```
PUT /api/v1/gateway/plugins
Content-Type: application/json
```

用请求中的配置替换全部能力插件。此操作会清除现有插件注册表并从零重建。

**RBAC 角色：** `gateway:admin`

**请求体：**

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

**响应 200：**

```json
{
  "status": "ok",
  "action": "plugins_replaced",
  "policy_version": 1
}
```

> 网关已绑定 `PolicyManager`：每次替换产生单调递增的 `policy_version`。可通过 `GET /api/v1/gateway/policies/versions` 查看版本历史、`POST /api/v1/gateway/policies/rollback` 回滚。

**错误 503：**

```json
{
  "error": "plugin registry not configured"
}
```

### 清除所有插件

```
DELETE /api/v1/gateway/plugins
```

清除所有已注册的能力插件。

**RBAC 角色：** `gateway:admin`

**响应 200：**

```json
{
  "status": "ok",
  "action": "plugins_cleared"
}
```

### 查看策略版本历史

```
GET /api/v1/gateway/policies/versions
```

列出全部策略版本快照（含当前生效版本，升序）。每次管理 API 发布或 SIGHUP 热重载都会产生一个新版本。

**RBAC 角色：** `gateway:ops` 或 `gateway:admin`

**响应 200：**

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

### 回滚策略

```
POST /api/v1/gateway/policies/rollback
Content-Type: application/json
```

将策略注册表重建为指定版本内容，并产生新的单调递增版本号。

**RBAC 角色：** `gateway:admin`

**请求体：**

```json
{"version": 1}
```

**响应 200：**

```json
{
  "status": "ok",
  "action": "policy_rolled_back",
  "new_version": 3
}
```

**错误 400：** 未知版本或低于 `MinRollbackVersion` 下界。

### 管理策略分支（灰度发布）

```
GET    /api/v1/gateway/policies/branches
PUT    /api/v1/gateway/policies/branches
DELETE /api/v1/gateway/policies/branches
```

任务 5b 分支控制：按 Agent 标识将指定 Agent 路由到特定策略版本，实现金丝雀灰度与多策略线。命中分支的 Agent 在准入决策与审计绑定中均使用分支版本；其余 Agent 回退当前生效版本。

- **GET**（角色 `gateway:ops`/`gateway:admin`）列出当前分支规则：

```json
{
  "current_version": 2,
  "count": 1,
  "branches": [
    {"id": "canary", "agent_id": "agent-canary-*", "version": 1, "priority": 10, "comment": "canary rollout"}
  ]
}
```

- **PUT**（角色 `gateway:admin`）全量替换分支规则，请求体：

```json
{
  "branches": [
    {"id": "canary", "agent_id": "agent-canary-*", "version": 1, "priority": 10, "comment": "canary rollout"}
  ]
}
```

响应 `{"status":"ok","action":"policy_branches_replaced","count":1}`。错误 `400`：ID 缺失/重复、AgentID 为空、引用未发布版本。

- **DELETE**（角色 `gateway:admin`）清空全部分支，恢复所有 Agent 走当前生效版本。

匹配规则：`*` 全量、`a-*` 前缀、其余精确；同命中按 `priority` 降序取第一条。

### 审计全文检索（监控呈现层，2026-08-15）

```
GET /api/v1/gateway/audit/search?q=keyword&action=deny&agent_id=agent-1&mapping=m&client_cn=cn&since=1755200000&until=1755300000&limit=50
```

全文检索审计索引（需配置 `audit_index_file` 启用；未配置返回 404）。搜索范围可叠加：全文关键词（FTS）、动作、agent、映射、客户端 CN、时间窗（Unix 秒）。

**RBAC 角色：** `gateway:audit` 或 `gateway:admin`

**响应 200：**

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

### 实时连接明细（监控呈现层，2026-08-15）

```
GET /api/v1/gateway/connections
```

返回当前活跃连接明细：agent、principal、来源 IP、协议、证书序列号、建立时间。

**RBAC 角色：** `gateway:ops` 或 `gateway:admin`

**响应 200：**

```json
{
  "connections": [
    { "agent_id": "agent-1", "principal": "user@varwof.com", "src_ip": "10.0.0.5", "protocol": "tcp", "serial": "1A2B", "established": 1755200000 }
  ]
}
```

### IP 接入点（监控呈现层，2026-08-15）

```
GET /api/v1/gateway/access-points
```

按来源 IP 聚合活跃连接（检测多 agent/多协议共享同一来源 IP 的可疑接入）。

**RBAC 角色：** `gateway:ops` 或 `gateway:admin`

**响应 200：**

```json
{
  "access_points": [
    { "src_ip": "10.0.0.5", "connections": 2, "agents": ["agent-1", "agent-2"], "protocols": ["tcp"] }
  ]
}
```

### Agent 目录（监控呈现层，2026-08-15）

```
GET /api/v1/gateway/agents
```

返回活跃 agent 清单及其实时状态：连接数、最近连接时间、来源 IP、协议、证书序列号。

**RBAC 角色：** `gateway:ops` 或 `gateway:admin`

**响应 200：**

```json
{
  "agents": [
    { "agent_id": "agent-1", "principal": "user@varwof.com", "connections": 2, "protocols": ["tcp"], "src_ips": ["10.0.0.5"], "serial": "1A2B", "last_seen": 1755200000 }
  ]
}
```

### 按 Agent 断开连接

```
POST /api/v1/gateway/disconnect-agent
Content-Type: application/json
```

根据 `agent_id` 断开该代理的所有活跃连接。

**RBAC 角色：** `gateway:admin`

**请求体：**

```json
{
  "agent_id": "agent-abc123"
}
```

**响应 200：**

```json
{
  "status": "ok",
  "agent_id": "agent-abc123",
  "disconnected": 3
}
```

**错误 400：**

```json
{
  "error": "agent_id is required"
}
```

### 按用户断开连接

```
POST /api/v1/gateway/disconnect-user
Content-Type: application/json
```

根据 `principal_uid` 断开该用户的所有活跃连接。

**RBAC 角色：** `gateway:admin`

**请求体：**

```json
{
  "principal_uid": "user-xyz789"
}
```

**响应 200：**

```json
{
  "status": "ok",
  "principal_uid": "user-xyz789",
  "disconnected": 5
}
```

### 列出网格对等节点（条件性）

```
GET /api/v1/gateway/peers
```

仅在网关配置了 `peers`（网格模式）时可用。返回所有配置的对等节点信息。

**RBAC 角色：** `gateway:ops`

**响应 200：**

```json
[
  {"name": "peer-dc1", "addr": "10.0.0.1:7443"},
  {"name": "peer-dc2", "addr": "10.0.0.2:7443"}
]
```

**错误 404：**

网格未启用时返回 404。

### 手动触发短命证书续期

```
POST /api/v1/gateway/renew
Content-Type: application/json
```

手动触发当前 mTLS 客户端证书的短命证书续期。客户端通过其当前证书身份认证，并在请求体中提供新公钥。

**RBAC 角色：** `gateway:ops`, `gateway:admin`

**请求体：**

```json
{
  "serial_hex": "ABCD1234",
  "new_pub_key_pem": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0K..."
}
```

| 字段             | 类型   | 说明                                                    |
|------------------|--------|----------------------------------------------------------|
| `serial_hex`     | string | 当前证书序列号（十六进制），需与客户端证书匹配            |
| `new_pub_key_pem`| string | 新密钥对的公钥（PKIX PEM 格式，Base64 编码后的字符串）    |

**响应 200：**

```json
{
  "allowed": true,
  "cert_pem": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t...",
  "key_pem": "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQo...",
  "new_expiry": "2025-01-25T10:30:00Z"
}
```

**错误 400：**

```json
{
  "error": "serial_hex and new_pub_key_pem required"
}
```

**错误 503：**

```json
{
  "error": "short-lived cert issuance not configured"
}
```

## HTTP 状态码

| 状态码 | 说明                       |
|--------|----------------------------|
| 200    | 成功                       |
| 201    | 资源创建成功               |
| 400    | 请求参数错误               |
| 401    | mTLS 认证失败              |
| 403    | 角色权限不足               |
| 404    | 资源不存在                 |
| 409    | 资源冲突（如映射名已存在） |
| 500    | 内部错误                   |
| 502    | 上游服务不可用             |
| 503    | 服务未配置                 |
