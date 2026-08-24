# gateway-udp 配置参考

## 配置文件位置

| 平台 | 路径 |
|------|------|
| Linux | `/etc/varwof/gateway-udp/gateway-udp.json` |

## 顶层配置 (Config)

```json
{
  "locale": "zh",
  "listeners": [...],
  "management": {...},
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

## 顶层配置字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `authorization_file` | string | authz.json 策略文件路径。加载成功后作为 RBAC 角色解析的优先来源 |
| `capability_schemes` | string | 能力注册目录路径（register 规范）。**显式配置后启用数据面能力注册校验**（opt-in，向后兼容）：AIC 声明的能力必须已注册，未注册即拒绝连接（fail-closed）。目录结构 `vendor/product/v*.json`；磁盘文件覆盖同名嵌入式方案，改 JSON 后 SIGHUP 热重载即时生效。未配置时数据面不校验能力注册 |
| `policy_signing` | object | 策略文件 PKCS#7 签名校验配置。启用后加载 authorization_file 前先验签，签名者须为本 PKI 签发的 admin 证书（OU=admin/gateway:admin），CA 链由 `ca_file`（缺省回退首个 listener 的 `ca_cert_file`）验证；`require: true` 时签名缺失即拒绝加载 |
| `audit_index_file` | string | 审计 FTS 索引文件路径（bbolt）。设置后启用 `GET /api/v1/gateway/audit/search` 全文检索端点 |
| `risk_monitor` | object | 高风险 agent 自动处置规则。设置后启用"行为违规 → 踢线 + 吊销"响应式闭环：管线在行为级拒绝点（插件 deny / 参数越界 / CIDR 越界）自动记录违规信号，达到规则阈值后由网关执行断开（+ 吊销） |
| `chain_peers` | ChainPeerConfig[] | 否 | 跨网关审计链引用对等端点。每项为对等网关管理 API 基址（如 `https://gw2:9443`），网关周期性拉取对端 `GET /api/v1/gateway/audit/chain` 链头写入本地 `ChainRefStore`，构成跨网关审计证据 DAG（免共识排序）。字段：`name`（对等网关名称）、`url`（对等网关管理 API 基址），TLS 复用管理 API 客户端证书 |

`risk_monitor` 字段：

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `rules[].name` | string | - | 规则名（审计/日志标识） |
| `rules[].signals` | []string | - | 触发信号：`plugin_deny`、`parameter_overflow`、`out_of_cidr`；`*` 匹配全部 |
| `rules[].threshold` | int | - | 窗口内违规次数阈值，达到即触发处置 |
| `rules[].window_seconds` | int | 60 | 计数窗口（秒） |
| `rules[].action` | string | - | `disconnect`（踢线）或 `revoke`（踢线 + 条件性吊销） |
| `rules[].reason` | string | - | 处置原因（写入审计与日志） |

`policy_signing` 字段：

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `false` | 启用签名校验 |
| `ca_file` | string | 首个 listener 的 ca_cert_file | 信任的 CA 链 PEM |
| `require_admin_ou` | bool | `true` | 强制签名者为 admin OU（nil=默认 true）|
| `require` | bool | `false` | 签名缺失时：true=拒绝，false=降级警告 |
| `sig_suffix` | string | `".sig"` | 签名文件后缀 |

策略签名由 `core pki policy sign` 或 `varwof-cli policy sign` 生成（使用管理员证书）。

## ListenerConfig

```json
{
  "name": "quic-proxy",
  "listen": ":4433",
  "protocol": "quic",
  "tls": {
    "mode": "mtls",
    "ca_cert_file": "/etc/pki/ca.pem",
    "cert_file": "/etc/pki/server.pem",
    "key_file": "/etc/pki/server.key"
  },
  "udp_ext": {
    "max_pkts_per_ip": 100,
    "max_total_pkts": 10000
  },
  "routes": [{"target": "backend:8080", "allow_roles": ["gateway:admin"]}],
  "read_timeout_sec": 30,
  "max_packet_size": 65535
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | string | **是** | 唯一监听器名称 |
| `listen` | string | **是** | UDP 监听地址 |
| `protocol` | string | **是** | `udp` / `dtls` / `udp+mtls` / `quic` |
| `tls` | TLSConfig | 条件 | 非明文模式必填（dtls/quic 需 `cert_file`，udp+mtls 另需 `ca_cert_file`） |
| `udp_ext` | UDPExtra | 否 | UDP 特有扩展字段（包速率限制、字节限速、过期断开等） |
| `routes` | []RouteConfig | **是** | 后端目标列表 |
| `read_timeout_sec` | int | 30 | 读超时（秒） |
| `max_packet_size` | int | 65535 | 最大 UDP 包大小 |

`protocol` 与 `tls.mode` 的对应关系（`tls.mode` 缺省时由 `protocol` 推导）：

| protocol | 默认 tls.mode | 说明 |
|----------|---------------|------|
| `udp` | `none` | 明文 UDP 包转发 |
| `dtls` | `server` | DTLS 加密（服务端证书） |
| `udp+mtls` | `mtls` | DTLS + 双向 mTLS |
| `quic` | `mtls` | QUIC 传输（内置 TLS 1.3，mTLS 走 tls 块） |

## RouteConfig

```json
{"target": "8.8.8.8:53", "allow_roles": ["gateway:admin"]}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `target` | string | **是**。后端地址 |
| `allow_roles` | []string | RBAC 角色 |

## TLSConfig

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `mode` | string | 依 protocol | `none` / `server` / `mtls`；缺省由 `protocol` 推导（udp→none、dtls→server、udp+mtls→mtls、quic→mtls） |
| `ca_cert_file` | string | 必填(udp+mtls) | CA 证书路径 |
| `cert_file` | string | 必填(dtls/udp+mtls/quic) | 服务端证书 |
| `key_file` | string | 必填(dtls/udp+mtls/quic) | 服务端私钥 |
| `min_tls_version` | string | — | 最低 TLS/DTLS 版本 |
| `cipher_suites` | []string | 安全默认 | DTLS 密码套件 |
| `crl_url` | string | — | CRL URL |
| `crl_refresh_sec` | int | 300 | CRL 刷新 |
| `ocsp_cache_ttl_sec` | int | 300 | OCSP TTL |
| `ocsp_fallback` | string | `"allow"` | OCSP fallback。**`"allow"`（fail-open）时强制离线证书剩余有效期 ≤1h（G2(b)）** |
| `tsa_url` | string | — | TSA URL |
| `tsa_cert_file` | string | — | TSA CA 证书 |
| `audit_file` | string | — | 审计日志路径 |
| `audit_max_size_mb` | int | 100 | 审计最大 MB |
| `audit_max_backups` | int | 3 | 审计备份数 |
| `max_conns_per_ip` | int | 0 | per-IP 连接数 |
| `max_conns_per_cert` | int | 0 | per-cert 连接限制 |
| `max_total_conns` | int | 0 | 全局连接限制 |
| `idle_timeout_sec` | int | 0 | 空闲超时 |
| `require_aic` | bool | false | 要求 AIC |
| `disallow_representative` | bool | 同 require_aic | 禁止代理模式 |
| `require_user_auth` | bool | false | 要求用户认证 |
| `disconnect_on_expiry` | bool | true | 证书过期自动断开（UDP 网关秒级控制见 `udp_ext.disconnect_on_expiry_sec`） |
| `allow_roles` | []string | — | RBAC 角色 |
| `required_capabilities` | []string | — | 要求的 AIC 能力 |
| `capability_scheme` | string | — | 能力方案 |

## UDPExtra

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `require_delegation` | bool | false | 双证书模式 |
| `max_pkts_per_ip` | int | 0 | per-IP 包速率限制 |
| `max_total_pkts` | int | 0 | 全局包总量限制 |
| `connection_bps` | int64 | 0 | per-connection 字节限速 |
| `connection_burst` | int64 | 0 | per-connection 突发 |
| `disconnect_on_expiry_sec` | int | 0 | 证书过期断开（秒） |

## QUIC 模式特殊配置

QUIC 使用 `quic-go` 库，流控窗口：
- `InitialStreamReceiveWindow`: 10MB
- `MaxStreamReceiveWindow`: 20MB

ALPN 协议：`h3`、`h3-29`（HTTP3）或 `hq`、`hq-29`（QUIC 隧道）

## 管理 API 端点

| 方法 | 路径 | 角色 | 说明 |
|------|------|------|------|
| GET | `/api/v1/gateway/health` | 公开 | 健康检查 |
| GET | `/api/v1/gateway/metrics` | ops, admin | Prometheus 指标 |
| GET | `/api/v1/gateway/audit` | audit, admin | 审计日志查询 |
| POST | `/api/v1/gateway/audit/verify` | audit, admin | Merkle 哈希链验证 |
| GET | `/api/v1/gateway/listeners` | admin | 列出 UDP 监听器 |
| POST | `/api/v1/gateway/listeners` | admin | 添加 UDP 监听器 |
| DELETE | `/api/v1/gateway/listeners/{name}` | admin | 删除 UDP 监听器 |
| GET | `/api/v1/gateway/plugins` | ops, admin | 列出能力插件 |
| GET | `/api/v1/gateway/plugins/{scheme}` | ops, admin | 查看单个插件 |
| PUT | `/api/v1/gateway/plugins` | admin | 替换全部插件 |
| DELETE | `/api/v1/gateway/plugins` | admin | 清空全部插件 |
| POST | `/api/v1/gateway/disconnect-agent` | admin | 按 Agent ID 断开连接 |
| POST | `/api/v1/gateway/disconnect-user` | admin | 按 Principal UID 断开连接 |
| POST | `/api/v1/gateway/reload` | admin | 热重载配置 |
| POST | `/api/v1/gateway/crl/reload` | admin | 强制刷新 CRL |

## CLI 参数

| 标志 | 简写 | 类型 | 默认值 | 说明 |
|------|------|------|--------|------|
| `--config` | `-c` | string | 平台默认 | 配置文件 |
| `--lang` | `-l` | string | 自动 | 语言 |
| `--listener` | `-L` | KV | — | 监听器定义（可重复） |
| `--tsa-url` | | string | — | TSA URL |
| `--audit-file` | | string | — | 审计文件 |
| `--management-listen` | | string | — | 管理 API 地址 |
| `--crl-refresh-sec` | | int | 300 | CRL 刷新 |
| `--ocsp-cache-ttl-sec` | | int | 300 | OCSP TTL |

### --listener KV 键

`name`, `listen`, `protocol`, `ca-cert`, `cert`, `key`, `routes`（分号分隔）, `allow-roles`（分号分隔）, `crl-url`, `crl-refresh-sec`, `ocsp-cache-ttl-sec`, `ocsp-fallback`, `tsa-url`, `tsa-cert-file`, `audit-file`, `audit-max-size-mb`, `audit-max-backups`, `max-pkts-per-ip`, `max-conns-per-cert`, `max-conns-per-ip`, `max-total-pkts`, `connection-bps`, `connection-burst`, `idle-timeout-sec`, `max-packet-size`, `read-timeout-sec`, `disconnect-on-expiry`, `cipher-suites`（分号分隔）, `min-tls-version`
