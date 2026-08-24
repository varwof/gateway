# 管理 API 参考

> 三网关统一管理 REST API | mTLS 认证 + RBAC 角色控制

## 认证方式

所有管理 API 端点通过 mTLS 保护。客户端证书 OU 字段编码角色，必须满足端点要求的 RBAC 角色。

**角色权限矩阵：**

| 角色 | 权限范围 |
|------|----------|
| `gateway:admin` | 完全控制（增删映射/监听器、热重载、踢线、吊销） |
| `gateway:ops` | 运维读（指标、连接、对等节点、续期） |
| `gateway:audit` | 审计读（审计日志、审计链） |

## 基础路径

```
https://<gateway-mgmt>:<port>/api/v1/gateway/
```

管理 API 端口由配置文件 `management.listen` 指定（默认 TCP:9090 / HTTP:9443 / UDP:9090）。

---

## 通用端点（三网关共享）

### 健康检查

```
GET /api/v1/gateway/health
```

**RBAC：** 公开（无需 mTLS）

**响应 200：**
```json
{"status": "ok"}
```

### 指标

```
GET /api/v1/gateway/metrics
```

**RBAC：** `gateway:ops` / `gateway:admin`

返回 Prometheus 文本格式指标。

### 配置热重载

```
POST /api/v1/gateway/reload
```

**RBAC：** `gateway:admin`

**响应 200：**
```json
{"status": "ok"}
```

等效于发送 `SIGHUP` 信号。

### 踢线（按 Agent）

```
POST /api/v1/gateway/disconnect-agent
Content-Type: application/json

{"agent_id": "agent-123", "reason": "高风险行为"}
```

**RBAC：** `gateway:admin`

断开指定 Agent 的全部活跃连接。触发条件性吊销（`revoker` 配置时）。

### 踢线（按用户）

```
POST /api/v1/gateway/disconnect-user
Content-Type: application/json

{"user": "zhangsan", "reason": "会话过期"}
```

**RBAC：** `gateway:admin`

---

## TCP 网关端点

### 获取映射列表

```
GET /api/v1/gateway/mappings
```

**RBAC：** `gateway:admin`

**响应 200：**
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

### 添加映射

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

**RBAC：** `gateway:admin`

**响应 201：** `{"status": "ok", "name": "new-service"}`

**错误 409：** 映射名称已存在

### 删除映射

```
DELETE /api/v1/gateway/mappings/{name}
```

**RBAC：** `gateway:admin`

### CRL 强制刷新

```
POST /api/v1/gateway/crl/reload
```

**RBAC：** `gateway:admin`

**响应 200：**
```json
{"reloaded": 3, "errors": []}
```

### 客户端证书续期

```
POST /api/v1/gateway/renew
Content-Type: application/json

{
  "serial_hex": "0a1b2c...",
  "new_pub_key_pem": "-----BEGIN PUBLIC KEY-----\n..."
}
```

**RBAC：** `gateway:ops` / `gateway:admin`

需要 mTLS 客户端证书。签发新证书并返回 PEM。

### Mesh 对等节点列表

```
GET /api/v1/gateway/peers
```

**RBAC：** `gateway:ops`（仅 TCP 网关启用 Mesh 时可用）

---

## HTTP 网关端点

### 获取监听器列表

```
GET /api/v1/gateway/listeners
```

**RBAC：** `gateway:admin`

**响应 200：**
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

### 添加监听器

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

**RBAC：** `gateway:admin`

**响应 201：** `{"status": "ok", "name": "api-gw"}`

### 删除监听器

```
DELETE /api/v1/gateway/listeners/{name}
```

**RBAC：** `gateway:admin`

### 任务管理

#### 注册任务

```
PUT /api/v1/gateway/tasks/{task_id}
Content-Type: application/json

{"serial": "0a1b2c...", "agent_id": "agent-123", "note": "deploy job"}
```

**RBAC：** `gateway:admin`

#### 注销任务

```
DELETE /api/v1/gateway/tasks/{task_id}
```

**RBAC：** `gateway:admin`

#### 任务完成（触发条件性吊销）

```
POST /api/v1/gateway/tasks/{task_id}/complete
```

**RBAC：** `gateway:admin`

标记任务完成，自动吊销关联的客户端证书（"用完即吊销"）。

---

## UDP 网关端点

### 获取监听器列表

```
GET /api/v1/gateway/listeners
```

**RBAC：** `gateway:admin`

**响应 200：**
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

### 添加监听器

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

**RBAC：** `gateway:admin`

### 删除监听器

```
DELETE /api/v1/gateway/listeners/{name}
```

**RBAC：** `gateway:admin`

### CRL 强制刷新

```
POST /api/v1/gateway/crl/reload
```

**RBAC：** `gateway:admin`

---

## 共享端点（所有网关）

### 审计日志查询

```
GET /api/v1/gateway/audit
```

**RBAC：** `gateway:audit` / `gateway:admin`

**查询参数：**

| 参数 | 类型 | 说明 |
|------|------|------|
| `since` | RFC3339 | 起始时间 |
| `until` | RFC3339 | 截止时间 |
| `action` | string | 审计动作过滤 |
| `client_cn` | string | 客户端 CN 过滤 |
| `limit` | int | 返回条数上限 |

### 审计全文检索

```
GET /api/v1/gateway/audit/search?q=关键词&action=denied&limit=50
```

**RBAC：** `gateway:audit` / `gateway:admin`

需要配置 `audit_index_file`。

### 实时连接明细

```
GET /api/v1/gateway/connections
```

**RBAC：** `gateway:ops` / `gateway:admin`

### IP 接入点聚合

```
GET /api/v1/gateway/access-points
```

**RBAC：** `gateway:ops` / `gateway:admin`

### Agent 目录

```
GET /api/v1/gateway/agents
```

**RBAC：** `gateway:ops` / `gateway:admin`

### 审计链 DAG 引用

```
GET /api/v1/gateway/audit/chain
```

**RBAC：** `gateway:audit` / `gateway:admin`

### 策略管理

```
GET  /api/v1/gateway/policy          # 当前策略
GET  /api/v1/gateway/policy/{role}   # 按角色查询
GET  /api/v1/gateway/policies/versions  # 版本历史
POST /api/v1/gateway/policies/rollback  # 回滚
PUT  /api/v1/gateway/plugins         # 更新插件配置
```

**RBAC：** 读 `gateway:ops` / 写 `gateway:admin`

### 续期状态

```
GET  /api/v1/gateway/renewal/status     # 续期状态
POST /api/v1/gateway/renewal/request    # 请求续期
POST /api/v1/gateway/renewal/confirm    # 确认续期
POST /api/v1/gateway/renewal/reject     # 拒绝续期
```

---

## 错误响应格式

```json
{"error": "描述信息"}
```

常见 HTTP 状态码：

| 状态码 | 含义 |
|--------|------|
| 200 | 成功 |
| 201 | 已创建 |
| 400 | 请求格式错误 |
| 401 | mTLS 认证失败 |
| 403 | RBAC 权限不足 |
| 404 | 资源不存在 |
| 405 | HTTP 方法不允许 |
| 409 | 资源已存在（冲突） |
| 500 | 服务端内部错误 |
| 503 | 服务不可用 |
