# 管理 API 参考

所有管理 API 通过 mTLS 认证，需要客户端证书含对应 RBAC 角色。服务端配置通过 `management` 段指定。

## 认证

- TLS 双向认证（`tls.RequireAndVerifyClientCert`）
- 客户端证书必须由 `management.tls.ca_cert_file` 指定的 CA 签发
- 证书 OU 必须包含对应 RBAC 角色
- 无证书 → `401 Unauthorized`
- 角色不足 → `403 Forbidden`

## 角色权限矩阵

| 端点 | admin | ops | audit |
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

## 端点

### GET /api/v1/gateway/health

健康检查。无需认证，公开端点。

**响应 200**：
```json
{
  "status": "ok"
}
```

---

### GET /api/v1/gateway/metrics

Prometheus 格式指标。包含网关级和 listener 级 Counter/Gauge/Histogram。

**角色**：`gateway:ops`、`gateway:admin`

**响应 200**：`Content-Type: text/plain; charset=utf-8`
```
# HELP pki_gateway_connections_active Active connections
# TYPE pki_gateway_connections_active gauge
pki_gateway_connections_active{listener="api-gateway"} 12
```

---

### GET /api/v1/gateway/audit

查询审计日志。支持时间范围、分页、过滤、排序。

**角色**：`gateway:audit`、`gateway:admin`

**查询参数**：

| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `since` | `string` | 否 | 起始时间，RFC 3339 格式 |
| `until` | `string` | 否 | 结束时间，RFC 3339 格式 |
| `limit` | `int` | 否 | 最大返回条数 |
| `offset` | `int` | 否 | 跳过前 N 条 |
| `sort` | `string` | 否 | `asc`（默认）或 `desc` |
| `action` | `string` | 否 | 过滤动作类型 |
| `cn` | `string` | 否 | 按客户端证书 CN 筛选 |
| `serial` | `string` | 否 | 按证书序列号筛选 |
| `mapping` | `string` | 否 | 按监听器名称筛选 |

**响应 200**：
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

**错误**：

| 状态码 | 条件 |
|--------|------|
| `400` | `since` 格式无效 |
| `404` | 审计日志未配置 |

**说明**：审计条目读取自 `audit_file` 配置的日志文件。启动时自动归档旧文件，API 只查询当前启动周期的文件。

---

### POST /api/v1/gateway/audit/verify

验证 Merkle 审计条目。提交审计条目内容，返回 Merkle 证明验证结果。

**角色**：`gateway:audit`、`gateway:admin`

**请求体**：
```json
{
  "entry": { "action": "proxied", "time": "2026-07-05T10:00:00.123456Z" },
  "proof": ["abc123...", "def456..."]
}
```

**响应 200**：
```json
{
  "valid": true,
  "root_hash": "abcdef...",
  "index": 42
}
```

---

### GET /api/v1/gateway/listeners

列出所有运行中的 Listener。

**角色**：`gateway:admin`

**响应 200**：
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

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | `string` | Listener 名称 |
| `listen` | `string` | 监听地址 |
| `tls_mode` | `string` | 生效 TLS 认证模式（由 `protocol` + `tls.mode` 推导）：`plain` / `server` / `mtls`。注意：这是管理 API 响应字段（`DisplayTLSMode`），与配置文件中的 `protocol` 字段不同 |
| `state` | `string` | `"running"` 或 `"stopped"` |
| `conns` | `int` | 当前并发连接数 |
| `routes` | `int` | 路由规则数 |

---

### POST /api/v1/gateway/listeners

运行时添加新的 Listener。

**角色**：`gateway:admin`

**请求体**：
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

**响应 201**：
```json
{ "status": "ok", "name": "extra" }
```

**错误**：

| 状态码 | 条件 |
|--------|------|
| `400` | 请求体解析失败、字段校验不通过 |
| `409` | Listener 名称已存在 |

---

### DELETE /api/v1/gateway/listeners/{name}

停止并移除指定 Listener。

**角色**：`gateway:admin`

**响应 200**：
```json
{ "status": "ok", "name": "api-gateway" }
```

**错误**：

| 状态码 | 条件 |
|--------|------|
| `404` | Listener 不存在 |

---

### POST /api/v1/gateway/reload

热重载全部配置。从配置文件重新读取，对比变更：

**角色**：`gateway:admin`

- 未变化的 Listener 继续运行
- 有变化的 Listener 停止旧实例、启动新实例
- 配置中移除的 Listener 被停止
- 新增的 Listener 被启动

短命证书自动续签循环与 ConnExpiryRegistry 清理循环在 reload 后保持运行（W04 修复：续签循环绑定独立 `renewalCh`，进程退出才停止；清理循环随新 `stopCh` 重启）。

**响应 200**：
```json
{ "status": "ok" }
```

**错误**：

| 状态码 | 条件 |
|--------|------|
| `500` | 配置文件读取/校验/启动失败 |

---

### PUT /api/v1/gateway/tasks/{taskId}

注册任务上下文（A3：任务 ID → 证书序列号映射）。Agent 开始任务时注册，任务完成后通过完成信号触发条件性吊销。

**角色**：`gateway:admin`

**请求体**（可选）：
```json
{ "serial": "0000...AABB", "agent_id": "agent-1", "note": "batch-job" }
```

**响应 200**：
```json
{ "task_id": "job-42", "status": "registered" }
```

### POST /api/v1/gateway/tasks/{taskId}/complete

完成任务并触发条件性吊销（A5：Agent 主动上报任务完成）。网关吊销任务关联的证书序列号。

**角色**：`gateway:admin`

**响应 200**：
```json
{ "task_id": "job-42", "serial": "0000...AABB", "status": "completed" }
```

**响应 404**：任务未注册。

### DELETE /api/v1/gateway/tasks/{taskId}

注销任务记录（A3，不触发吊销）。

**角色**：`gateway:admin`

**响应 200**：
```json
{ "task_id": "job-42", "unregistered": true }
```

## 数据面任务完成信号（A4）

Agent 在请求中携带以下 HTTP Header 标记任务完成，网关立即吊销该证书（"用完即吊销"，不等连接关闭）：

- `X-AIC-Task-Id`: 任务 ID（可选；缺省用客户端证书 CN 兜底）
- `X-AIC-Task-Status: completed`: 任务完成信号

```http
POST /api/data HTTP/1.1
X-AIC-Task-Id: job-42
X-AIC-Task-Status: completed
```

收到完成信号后网关：审计 `task_complete_revoke` → 立即吊销客户端证书 → 注销任务记录。

---

### GET /api/v1/gateway/plugins

列出所有已注册的能力插件。

**角色**：`gateway:ops`、`gateway:admin`

**响应 200**：
```json
[
  { "scheme": "allowlist", "type": "builtin" },
  { "scheme": "denylist", "type": "builtin" }
]
```

---

### GET /api/v1/gateway/plugins/{scheme}

查看指定 Scheme 的插件详情。

**角色**：`gateway:ops`、`gateway:admin`

**路径参数**：

| 参数 | 说明 |
|------|------|
| `scheme` | 插件 Scheme 标识 |

**响应 200**：
```json
{ "scheme": "allowlist", "type": "builtin" }
```

**错误**：

| 状态码 | 条件 |
|--------|------|
| `404` | 插件未找到 |

---

### PUT /api/v1/gateway/plugins

替换全部插件配置。基于 JSON 配置批量重建插件注册表。

**角色**：`gateway:admin`

**请求体**：
```json
[
  { "scheme": "allowlist", "type": "builtin", "config": { "domains": ["trusted.com"] } },
  { "scheme": "webhook", "type": "webhook", "config": { "url": "http://hook:8080/check" } }
]
```

**响应 200**：
```json
{ "status": "ok", "action": "plugins_replaced", "policy_version": 1 }
```

> 网关已绑定 `PolicyManager`：每次替换产生单调递增的 `policy_version`。详见 `GET /api/v1/gateway/policies/versions` 与 `POST /api/v1/gateway/policies/rollback`。

**错误**：

| 状态码 | 条件 |
|--------|------|
| `400` | JSON 解析失败或配置校验不通过 |

---

### DELETE /api/v1/gateway/plugins

清空全部已注册插件。

**角色**：`gateway:admin`

**响应 200**：
```json
{ "status": "ok", "action": "plugins_cleared" }
```

---

### GET /api/v1/gateway/policies/versions

列出全部策略版本快照（含当前生效版本，升序）。每次管理 API 发布或 SIGHUP 热重载产生一个新版本。

**角色**：`gateway:ops`、`gateway:admin`

**响应 200**：
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

将策略注册表重建为指定版本内容，并产生新的单调递增版本号。

**角色**：`gateway:admin`

**请求体**：
```json
{ "version": 1 }
```

**响应 200**：
```json
{ "status": "ok", "action": "policy_rolled_back", "new_version": 3 }
```

**错误**：

| 状态码 | 条件 |
|--------|------|
| `400` | 未知版本或低于 `MinRollbackVersion` 下界 |

---

### GET /api/v1/gateway/policies/branches

列出当前策略分支规则（任务 5b：分支控制/灰度发布）。

**角色**：`gateway:ops`、`gateway:admin`

**响应 200**：
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

全量替换分支规则。命中分支的 Agent 走分支版本策略（决策与审计均绑定分支版本），其余回退当前生效版本。

**角色**：`gateway:admin`

**请求体**：
```json
{
  "branches": [
    { "id": "canary", "agent_id": "agent-canary-*", "version": 1, "priority": 10, "comment": "canary rollout" }
  ]
}
```

**响应 200**：
```json
{ "status": "ok", "action": "policy_branches_replaced", "count": 1 }
```

**错误**：

| 状态码 | 条件 |
|--------|------|
| `400` | ID 缺失/重复、AgentID 为空、引用未发布版本 |

---

### DELETE /api/v1/gateway/policies/branches

清空全部分支规则，恢复所有 Agent 走当前生效版本。

**角色**：`gateway:admin`

**响应 200**：
```json
{ "status": "ok", "action": "policy_branches_cleared" }
```

---

### GET /api/v1/gateway/capabilities

列出所有能力配置方案（Scheme）。

**角色**：`gateway:ops`、`gateway:admin`

**响应 200**：
```json
["tunnel:prod", "gateway:admin"]
```

---

### GET /api/v1/gateway/capabilities/{scheme}

查看指定 Scheme 的详细配置。

**角色**：`gateway:ops`、`gateway:admin`

**路径参数**：

| 参数 | 说明 |
|------|------|
| `scheme` | 能力方案标识 |

**响应 200**：
```json
{
  "scheme": "tunnel:prod",
  "capabilities": [
    { "id": "allow", "permission": "connect" }
  ]
}
```

**错误**：

| 状态码 | 条件 |
|--------|------|
| `404` | Scheme 不存在 |

---

### PUT /api/v1/gateway/capabilities

替换全部能力配置方案。

**角色**：`gateway:admin`

**请求体**：
```json
{
  "schemes": [
    { "scheme": "tunnel:prod", "capabilities": [{ "id": "allow", "permission": "connect" }] }
  ]
}
```

**响应 200**：
```json
{ "status": "ok" }
```

**错误**：

| 状态码 | 条件 |
|--------|------|
| `400` | JSON 解析失败或配置校验不通过 |

---

### PUT /api/v1/gateway/capabilities/{scheme}

替换指定 Scheme 的配置。

**角色**：`gateway:admin`

**路径参数**：

| 参数 | 说明 |
|------|------|
| `scheme` | 能力方案标识 |

**请求体**：
```json
{
  "capabilities": [
    { "id": "allow", "permission": "connect" }
  ]
}
```

**响应 200**：
```json
{ "status": "ok" }
```

---

### POST /api/v1/gateway/capabilities/{scheme}/capabilities

向指定 Scheme 添加一条能力规则。

**角色**：`gateway:admin`

**路径参数**：

| 参数 | 说明 |
|------|------|
| `scheme` | 能力方案标识 |

**请求体**：
```json
{ "id": "deny", "permission": "disconnect" }
```

**响应 201**：
```json
{ "status": "ok", "capability_id": "deny" }
```

**错误**：

| 状态码 | 条件 |
|--------|------|
| `400` | 请求体解析失败 |
| `404` | Scheme 不存在 |

---

### DELETE /api/v1/gateway/capabilities/{scheme}

删除指定 Scheme 及其所有能力规则。

**角色**：`gateway:admin`

**路径参数**：

| 参数 | 说明 |
|------|------|
| `scheme` | 能力方案标识 |

**响应 200**：
```json
{ "status": "ok", "scheme": "tunnel:prod" }
```

**错误**：

| 状态码 | 条件 |
|--------|------|
| `404` | Scheme 不存在 |

---

### DELETE /api/v1/gateway/capabilities/{scheme}/capabilities/{id}

从指定 Scheme 中删除一条能力规则。

**角色**：`gateway:admin`

**路径参数**：

| 参数 | 说明 |
|------|------|
| `scheme` | 能力方案标识 |
| `id` | 能力规则 ID |

**响应 200**：
```json
{ "status": "ok", "capability_id": "deny" }
```

**错误**：

| 状态码 | 条件 |
|--------|------|
| `404` | Scheme 或 Capability 不存在 |

---

### POST /api/v1/gateway/capabilities/validate

校验能力配置的合法性，不持久化。

**角色**：`gateway:admin`

**请求体**：
```json
{
  "schemes": [
    { "scheme": "test", "capabilities": [{ "id": "allow", "permission": "connect" }] }
  ]
}
```

**响应 200**：
```json
{ "valid": true }
```

**错误**：

| 状态码 | 条件 |
|--------|------|
| `400` | 配置不合法（含具体错误信息） |

---

### GET /api/v1/gateway/audit/search

审计全文检索（需配置 `audit_index_file`；未配置返回 404）。

**角色**：`gateway:audit` 或 `gateway:admin`

**查询参数**：

| 参数 | 类型 | 说明 |
|------|------|------|
| `q` | string | 全文关键词（FTS 子索引） |
| `action` | string | 动作过滤（connected/disconnected/denied/…） |
| `agent_id` | string | agent 过滤 |
| `mapping` | string | 映射/监听器名过滤 |
| `client_cn` | string | 客户端 CN 过滤 |
| `since`/`until` | int | 时间窗（Unix 秒） |
| `limit` | int | 返回条数上限（默认 50） |

**响应 200**：
```json
{ "results": [ { "hash": "sha256:…", "entry": { "time": "…", "action": "deny", "agent_id": "agent-1" } } ], "count": 1 }
```

### GET /api/v1/gateway/connections

实时连接明细（agent/principal/来源 IP/协议/证书序列号/建立时间）。

**角色**：`gateway:ops` 或 `gateway:admin`

**响应 200**：
```json
{ "connections": [ { "agent_id": "agent-1", "principal": "user@varwof.com", "src_ip": "10.0.0.5", "protocol": "http", "serial": "1A2B", "established": 1755200000 } ] }
```

### GET /api/v1/gateway/access-points

按来源 IP 聚合活跃连接（检测多 agent/多协议共享来源 IP 的可疑接入）。

**角色**：`gateway:ops` 或 `gateway:admin`

**响应 200**：
```json
{ "access_points": [ { "src_ip": "10.0.0.5", "connections": 2, "agents": ["agent-1", "agent-2"], "protocols": ["http"] } ] }
```

### GET /api/v1/gateway/agents

活跃 agent 目录及其实时状态。

**角色**：`gateway:ops` 或 `gateway:admin`

**响应 200**：
```json
{ "agents": [ { "agent_id": "agent-1", "principal": "user@varwof.com", "connections": 2, "protocols": ["http"], "src_ips": ["10.0.0.5"], "serial": "1A2B", "last_seen": 1755200000 } ] }
```

### POST /api/v1/gateway/disconnect-agent

按 `agent_id` 断开所有关联连接。

**角色**：`gateway:admin`

**请求体**：
```json
{ "agent_id": "agent-001" }
```

**响应 200**：
```json
{ "status": "ok", "disconnected": 3, "agent_id": "agent-001" }
```

**错误**：

| 状态码 | 条件 |
|--------|------|
| `400` | `agent_id` 为空 |

---

### POST /api/v1/gateway/disconnect-user

按 `principal_uid` 断开所有关联连接。

**角色**：`gateway:admin`

**请求体**：
```json
{ "principal_uid": "user-abc-123" }
```

**响应 200**：
```json
{ "status": "ok", "disconnected": 2, "principal_uid": "user-abc-123" }
```

**错误**：

| 状态码 | 条件 |
|--------|------|
| `400` | `principal_uid` 为空 |

---

## 数据面端点

数据面端点运行在 HTTP 代理端口（非管理端口），与 `GET /` 代理请求共享同一监听器。端点路径以 `_` 开头以避免与后端路径冲突，mTLS 认证通过 TLS 握手层完成，无需单独 RBAC。

> 注（W24，2026-08-16）：文档曾宣称 `/_auth`/`/_heartbeat`/`/_session` 数据面端点，但代码从未实现，已从本文档移除。长连接会话语义由 GatewaySession 执行（CIDR + 硬超时）与证书生命周期（CRL/OCSP/DisconnectOnExpiry）覆盖。

### GET /_timestamp

服务器时间同步。返回当前 Unix 时间戳和 ISO 8601 字符串。

**认证**：无（公开）

**响应 200**：
```json
{
  "timestamp": 1720156800,
  "iso8601": "2026-07-05T10:00:00Z"
}
```

---

## 状态码汇总

| 状态码 | 含义 |
|--------|------|
| `200` | 成功 |
| `201` | 创建成功 |
| `400` | 请求格式错误 |
| `401` | mTLS 认证失败 |
| `403` | 角色不足 |
| `404` | 资源不存在 |
| `409` | 资源已存在 |
| `429` | 连接数超限 |
| `500` | 服务端错误 |

## 错误响应格式

```json
{ "error": "listener already exists" }
```

管理 API 错误响应为 `Content-Type: application/json`。

数据面 API 错误响应格式：

```json
{ "error": "http.mtls_required", "message": "mTLS client certificate required" }
```
