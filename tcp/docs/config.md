# gateway-tcp 配置参考

## 配置文件位置

| 平台 | 路径 |
|------|------|
| Linux | `/etc/varwof/gateway-tcp/gateway-tcp.json` |
| Windows | `%ProgramData%\varwof\gateway-tcp\gateway-tcp.json` |

`--config` / `-c` 覆盖默认路径。

## 顶层配置 (Config)

```json
{
  "locale": "zh",
  "mappings": [...],
  "tunnels": [...],
  "management": {...},
  "peers": [...],
  "mesh_listen": ":9091",
  "short_lived": {...},
  "varwof_core": {...},
  "capability_plugins": {...},
  "authorization_file": "/etc/pki/authz.json",
  "policy_signing": {
    "enabled": true,
    "ca_file": "/etc/pki/issuing-ca.pem",
    "require_admin_ou": true,
    "require": false,
    "sig_suffix": ".sig"
  },
  "tsa_proof_file": "/var/log/gateway/proof.jsonl",
  "tsa_proof_interval_sec": 300
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `locale` | string | 否 | `"zh"` 或 `"en"`，默认自动检测 |
| `mappings` | []MappingConfig | **是** | TCP 端口转发规则 |
| `tunnels` | []TunnelConfig | 否 | 隧道客户端 |
| `management` | ManagementConfig | 否 | 管理 API |
| `peers` | []MeshPeerConfig | 否 | Mesh 对等节点 |
| `mesh_listen` | string | 否 | Mesh 监听地址 |
| `mesh_server_tls` | TLSConfig | 否 | 入站 Mesh 服务端 mTLS 配置（`ca_cert_file` 验证对端 peer 证书，`cert_file`/`key_file` 为本节点服务端证书）。配置了 `mesh_listen` 时必须提供，否则入站以明文监听（仅建议内网隔离网络使用） |
| `mesh_allowed_targets` | []string | 否 | 入站 Mesh 转发目标白名单。为空时仅允许本机回环与 RFC1918/ULA/链路本地私网目标（防 SSRF）；可追加形如 `"10.0.0.5:8080"`（精确 host:port）、`"192.168.1.0/24"`（CIDR）、`"*.internal.example:443"`（后缀域名）的条目 |
| `short_lived` | IssueConfig | 否 | 短命证书自动签发 |
| `varwof_core` | RevokerConfig | 否 | Varwof Core 连接（吊销） |
| `capability_plugins` | PluginConfigs | 否 | 能力插件配置 |
| `authorization_file` | string | 否 | authz.json 策略文件路径。加载成功后作为 RBAC 角色解析的优先来源 |
| `capability_schemes` | string | 否 | 能力注册目录路径（register 规范）。**显式配置后启用数据面能力注册校验**（opt-in，向后兼容）：AIC 声明的能力必须已注册，未注册即拒绝连接（fail-closed）。目录结构 `vendor/product/v*.json`；磁盘文件覆盖同名嵌入式方案，改 JSON 后 SIGHUP 热重载即时生效。未配置时数据面不校验能力注册 |
| `policy_signing` | PolicySigningConfig | 否 | 策略文件 PKCS#7 签名校验配置。启用后加载 authorization_file 前先验签，签名者须为本 PKI 签发的 admin 证书（OU=admin/gateway:admin），CA 链由 `ca_file`（缺省回退首个 mapping 的 ca_cert_file）验证；`require: true` 时签名缺失即拒绝加载 |
| `audit_index_file` | string | 否 | 审计 FTS 索引文件路径（bbolt）。设置后启用 `GET /api/v1/gateway/audit/search` 全文检索端点 |
| `risk_monitor` | RiskMonitorConfig | 否 | 高风险 agent 自动处置规则。设置后启用"行为违规 → 踢线 + 吊销"响应式闭环：管线在行为级拒绝点（插件 deny / 参数越界 / CIDR 越界）自动记录违规信号，达到规则阈值后由网关执行断开（+ 吊销） |
| `chain_peers` | ChainPeerConfig[] | 否 | 跨网关审计链引用对等端点。每项为对等网关管理 API 基址（如 `https://gw2:9443`），网关周期性拉取对端 `GET /api/v1/gateway/audit/chain` 链头写入本地 `ChainRefStore`，构成跨网关审计证据 DAG（免共识排序） |

`chain_peers` 字段：`name`（对等网关名称）、`url`（对等网关管理 API 基址）。TLS 配置复用管理 API 客户端证书。

### RiskMonitorConfig

```json
{
  "risk_monitor": {
    "rules": [
      {
        "name": "capability-abuse",
        "signals": ["plugin_deny", "parameter_overflow"],
        "threshold": 3,
        "window_seconds": 60,
        "action": "revoke",
        "reason": "repeated capability abuse"
      },
      {
        "name": "cidr-violation",
        "signals": ["out_of_cidr"],
        "threshold": 1,
        "window_seconds": 60,
        "action": "disconnect",
        "reason": "operation outside allowed CIDRs"
      }
    ]
  }
}
```

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `rules[].name` | string | 是 | 规则名（审计/日志标识） |
| `rules[].signals` | []string | 是 | 触发信号类型：`plugin_deny`（能力插件拒绝）、`parameter_overflow`（参数越界）、`out_of_cidr`（来源 IP 越界）；`*` 匹配全部 |
| `rules[].threshold` | int | 是 | 窗口内违规次数阈值，达到即触发处置 |
| `rules[].window_seconds` | int | 否 | 计数窗口（秒），默认 60 |
| `rules[].action` | string | 是 | `disconnect`（踢线）或 `revoke`（踢线 + 条件性吊销） |
| `rules[].reason` | string | 是 | 处置原因（写入审计与日志） |

## MappingConfig

```json
{
  "name": "db-proxy",
  "listen": ":8443",
  "target": "10.0.0.1:3306",
  "protocol": "tcp+mtls",
  "tls": {
    "mode": "mtls",
    "ca_cert_file": "/etc/pki/ca.pem",
    "cert_file": "/etc/pki/server.pem",
    "key_file": "/etc/pki/server.key",
    "allow_roles": ["gateway:admin"]
  },
  "tcp_ext": {
    "max_connection_duration_sec": 3600
  }
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | string | **是** | 唯一映射标识 |
| `listen` | string | **是** | 监听地址（如 `:8443`、`127.0.0.1:8443`） |
| `target` | string | **是** | 后端地址（如 `db:3306`） |
| `protocol` | string | **是** | `tcp` / `tcp+mtls` / `tcp+mesh`（见 Protocol 表） |
| `tls` | TLSConfig | 条件 | `protocol=tcp+mtls` 时必填；`protocol=tcp` 时可选（`tls.mode: server/mtls` 启用 TLS/mTLS） |
| `tcp_ext` | TCPExtra | 否 | TCP 特有扩展字段（连接时长/会话超时/约束复查/健康检查/拨号超时/续签/委托） |
| `mesh_peer` | string | 条件 | `protocol=tcp+mesh` 时必填 |

### Protocol

| Protocol | 生效 TLS 模式 | 说明 |
|------|-----------|------|
| `tcp` | `none`（默认）/ `server` / `mtls` | 纯 TCP 转发。不配 `tls` 块为明文；配 `tls.mode=server` 启用单向 TLS，配 `tls.mode=mtls` 启用双向 mTLS |
| `tcp+mtls` | `mtls` | TCP + 双向 mTLS（完整双向认证 + CRL/OCSP/RBAC）。需要"客户端证书认证"的场景一律用此协议，必须提供 `tls` 块 |
| `tcp+mesh` | mesh | 通过 Mesh peer 代理（协议强制对称 mTLS，W01），必须提供 `mesh_peer` |

> **`client` 模式不支持（W07，2026-08-16）**：TLS 服务端握手必须出示服务端证书，"仅客户端证书"在 listener 角色上不可实现，`mtls` 已覆盖该语义。配置 `tls.mode:"client"`（或旧式 `tls_mode:"client"`）将在启动校验时被显式拒绝，错误信息引导改用 `mtls`。

## TLSConfig

统一 TLS 配置块（旧 `MTLSConfig` 的字段全部收纳于此），位于 mapping 的 `tls` 字段内。TCP 特有字段已移至 `tcp_ext`（见 TCPExtra）。

```json
{
  "tls": {
    "mode": "mtls",
    "ca_cert_file": "/etc/pki/ca.pem",
    "cert_file": "/etc/pki/server.pem",
    "key_file": "/etc/pki/server.key",
    "min_tls_version": "1.2",
    "cipher_suites": ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"],
    "crl_url": "http://crl.example.com/ca.crl",
    "crl_refresh_sec": 300,
    "ocsp_cache_ttl_sec": 300,
    "ocsp_fallback": "allow",
    "tsa_url": "http://tsa.example.com",
    "tsa_cert_file": "/etc/pki/tsa.pem",
    "allow_roles": ["gateway:admin", "gateway:ops"],
    "audit_file": "/var/log/gateway/audit.log",
    "audit_max_size_mb": 100,
    "audit_max_backups": 3,
    "max_conns_per_ip": 100,
    "max_conns_per_cert": 50,
    "max_total_conns": 10000,
    "idle_timeout_sec": 300,
    "disconnect_on_expiry": true,
    "require_aic": true,
    "disallow_representative": false,
    "require_user_auth": false,
    "required_capabilities": ["tcp:forward"],
    "capability_scheme": "custom"
  }
}
```

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `mode` | string | — | TLS 认证模式：`none` / `server` / `mtls`。`protocol=tcp+mtls` 时隐含 `mtls` |
| `ca_cert_file` | string | 必填(mtls) | CA 证书路径 |
| `cert_file` | string | — | 服务端证书 |
| `key_file` | string | — | 服务端私钥 |
| `min_tls_version` | string | `"1.2"` | 最低 TLS 版本 |
| `cipher_suites` | []string | 安全默认 | TLS 密码套件 |
| `crl_url` | string | — | CRL 分发点 URL |
| `crl_refresh_sec` | int | 300 | CRL 刷新间隔 |
| `ocsp_cache_ttl_sec` | int | 300 | OCSP 缓存 TTL |
| `ocsp_fallback` | string | `"allow"` | OCSP 失败策略：allow/deny/crl。**`"allow"`（fail-open）时强制离线证书剩余有效期 ≤1h（G2(b)）** |
| `tsa_url` | string | — | TSA 服务 URL |
| `tsa_cert_file` | string | — | TSA CA 证书 |
| `allow_roles` | []string | — | 允许的 RBAC 角色 |
| `audit_file` | string | — | 审计日志路径 |
| `audit_max_size_mb` | int | 100 | 审计文件最大 MB |
| `audit_max_backups` | int | 3 | 审计备份数 |
| `max_conns_per_ip` | int | 0 | per-IP 连接限制 |
| `max_conns_per_cert` | int | 0 | per-cert 连接限制 |
| `max_total_conns` | int | 0 | 全局连接限制 |
| `idle_timeout_sec` | int | 0 | 空闲超时（秒），活动刷新（每次 I/O 滚动 deadline，活跃连接不会被掐断；0=不限） |
| `disconnect_on_expiry` | bool | true | 证书过期自动断开 |
| `require_aic` | bool | false | 要求 AIC 扩展 |
| `disallow_representative` | bool | 同 require_aic | 禁止代理模式 |
| `require_user_auth` | bool | false | 要求用户证书 |
| `required_capabilities` | []string | — | 要求的 AIC 能力 |
| `capability_scheme` | string | — | 能力方案过滤 |

## TCPExtra（`tcp_ext` 块）

TCP 特有扩展字段，位于 mapping 的 `tcp_ext` 字段内。旧 `MTLSConfig` 中的 TCP 相关字段全部移入此块。

```json
{
  "tcp_ext": {
    "max_connection_duration_sec": 3600,
    "session_timeout_sec": 0,
    "constraint_recheck_sec": 0,
    "health_check_sec": 30,
    "health_check_url": "http://backend:8080/health",
    "dial_timeout_sec": 10,
    "renewal_enabled": true,
    "renewal_window_sec": 120,
    "require_delegation": false
  }
}
```

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `max_connection_duration_sec` | int | 0 | 硬超时（秒），连接最长持续时间（与空闲超时独立） |
| `session_timeout_sec` | int | 0 | 会话有效时长（秒），0=不限 |
| `constraint_recheck_sec` | int | 0 | 长连接内 authorizationConstraints 周期复查间隔（秒）。TCP 数据面为透传长连接，约束只在握手时查一次；time-window 等随时间失效的约束跨窗后不复查（如夜间窗口连接白天仍活跃）。>0 时按该间隔重新评估 AIC + PA 的约束，违规即断开连接并审计；0=关闭（默认） |
| `health_check_sec` | int | 0 | 健康检查间隔 |
| `health_check_url` | string | — | HTTP 健康检查 URL |
| `dial_timeout_sec` | int | 10 | 后端拨号超时（秒），0 或未设=10（W38，可配置） |
| `renewal_enabled` | bool | false | 启用证书续签 |
| `renewal_window_sec` | int | 120 | 续签窗口（秒） |
| `require_delegation` | bool | false | 双证书模式（Agent + User） |

## TunnelConfig

```json
{
  "name": "client-tunnel",
  "listen": "127.0.0.1:3306",
  "gateway_addr": "gateway.example.com:8443",
  "cert_file": "/etc/pki/client.pem",
  "key_file": "/etc/pki/client.key",
  "ca_cert_file": "/etc/pki/ca.pem"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | string | **是** | 隧道标识 |
| `listen` | string | **是** | 本地监听地址 |
| `gateway_addr` | string | **是** | 远程网关地址 |
| `cert_file` | string | **是** | 客户端证书 |
| `key_file` | string | **是** | 客户端私钥 |
| `ca_cert_file` | string | **是** | CA 证书 |

## ManagementConfig

```json
{
  "management": {
    "listen": ":9090",
    "tls": {
      "mode": "mtls",
      "ca_cert_file": "/etc/pki/ca.pem",
      "cert_file": "/etc/pki/mgmt.pem",
      "key_file": "/etc/pki/mgmt.key"
    }
  }
}
```

## MeshPeerConfig

```json
{
  "peers": [
    {
      "name": "gateway-b",
      "addr": "10.0.0.2:9091",
      "ca_cert_file": "/etc/pki/ca.pem",
      "cert_file": "/etc/pki/peer.pem",
      "key_file": "/etc/pki/peer.key"
    }
  ]
}
```

## CLI 参数

### 全局标志

| 标志 | 简写 | 类型 | 默认值 | 说明 |
|------|------|------|--------|------|
| `--config` | `-c` | string | 平台默认 | 配置文件路径 |
| `--lang` | `-l` | string | 自动 | 语言 |
| `--listener` | `-L` | KV | — | 映射定义（可重复） |
| `--tunnel` | `-t` | KV | — | 隧道定义（可重复） |
| `--crl-refresh-sec` | | int | 300 | CRL 刷新 |
| `--ocsp-cache-ttl-sec` | | int | 300 | OCSP TTL |
| `--ocsp-fallback` | | string | allow | OCSP fallback |
| `--tsa-url` | | string | — | TSA URL |
| `--audit-file` | | string | — | 审计文件 |
| `--management-listen` | | string | — | 管理 API 地址 |

`--config` 和 `--listener` 互斥。

### --map KV 键

`name`, `listen`, `target`, `protocol`, `ca-cert`, `cert`, `key`, `allow-roles`（分号分隔）, `crl-url`, `crl-refresh-sec`, `ocsp-cache-ttl-sec`, `ocsp-fallback`, `tsa-url`, `audit-file`, `max-conns-per-ip`, `max-total-conns`, `idle-timeout-sec`, `health-check-sec`, `health-check-url`, `disconnect-on-expiry`, `cipher-suites`（分号分隔）, `min-tls-version`, `audit-max-size-mb`, `audit-max-backups`

## 管理 API 端点

| 方法 | 路径 | 角色 | 说明 |
|------|------|------|------|
| GET | `/api/v1/gateway/health` | 公开 | 健康检查 |
| GET | `/api/v1/gateway/metrics` | ops, admin | Prometheus 指标 |
| GET | `/api/v1/gateway/audit` | audit, admin | 审计日志查询 |
| POST | `/api/v1/gateway/audit/verify` | audit, admin | Merkle 哈希链验证 |
| GET | `/api/v1/gateway/mappings` | admin | 列出 TCP 映射 |
| POST | `/api/v1/gateway/mappings` | admin | 添加 TCP 映射 |
| DELETE | `/api/v1/gateway/mappings/{name}` | admin | 删除 TCP 映射 |
| GET | `/api/v1/gateway/plugins` | ops, admin | 列出能力插件 |
| GET | `/api/v1/gateway/plugins/{scheme}` | ops, admin | 查看单个插件 |
| PUT | `/api/v1/gateway/plugins` | admin | 替换全部插件 |
| DELETE | `/api/v1/gateway/plugins` | admin | 清空全部插件 |
| POST | `/api/v1/gateway/disconnect-agent` | admin | 按 Agent ID 断开连接 |
| POST | `/api/v1/gateway/disconnect-user` | admin | 按 Principal UID 断开连接 |
| POST | `/api/v1/gateway/reload` | admin | 热重载配置 |
| POST | `/api/v1/gateway/crl/reload` | admin | 强制刷新 CRL |
| GET | `/api/v1/gateway/peers` | ops | Mesh 节点列表 |
| POST | `/api/v1/gateway/renew` | ops, admin | 短命证书续期 |
