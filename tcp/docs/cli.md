# CLI 参考

## 概要

```
gateway-tcp [--config <file> | --map <kv>...] [flags]
gateway-tcp server [flags]                         # 默认子命令
gateway-tcp tunnel [--config <file> | --tunnel <kv>...] [flags]
gateway-tcp audit --entry <file> [--tsa-url <url>]
gateway-tcp help
```

无子命令时默认进入 `server` 模式。少参数时显示帮助。

## 子命令

| 子命令 | 说明 |
|--------|------|
| `server`（默认）| 启动 TCP 安全网关 |
| `tunnel` | 启动客户端隧道模式 |
| `audit` | 验证审计日志的 TSA 时间戳签名 |
| `help` | 显示顶层帮助 |

---

## server

### 用法

```
gateway-tcp server [flags]
gateway-tcp [flags]                    # 省略 server 时等同
```

### 标志

| 标志 | 短别名 | 类型 | 默认值 | 说明 |
|------|--------|------|--------|------|
| `--config` | `-c` | string | 自动检测 | 配置文件路径（JSON） |
| `--lang` | `-l` | string | `en` | 语言（`zh`/`en`） |
| `--map` | `-m` | string | — | Mapping 定义（key=value,...），可重复 |
| `--tunnel` | `-t` | string | — | Tunnel 定义（key=value,...），可重复 |
| `--crl-refresh-sec` | | int | `300` | 全局 CRL 刷新间隔（秒） |
| `--ocsp-cache-ttl-sec` | | int | `300` | 全局 OCSP 缓存 TTL（秒） |
| `--ocsp-fallback` | | string | `allow` | OCSP 降级策略（`allow`/`deny`/`crl`） |
| `--tsa-url` | | string | — | TSA 服务 URL |
| `--tsa-cert-file` | | string | — | TSA 证书文件 |
| `--audit-file` | | string | — | 审计日志文件路径 |
| `--audit-max-size-mb` | | int | `100` | 审计日志单文件最大大小（MB） |
| `--audit-max-backups` | | int | `3` | 审计日志最大备份数 |
| `--management-listen` | | string | — | 管理 API 监听地址 |
| `--mgmt-ca-cert` | | string | — | 管理 API CA 证书 |
| `--mgmt-cert` | | string | — | 管理 API 服务端证书 |
| `--mgmt-key` | | string | — | 管理 API 服务端私钥 |
| `--mgmt-crl-url` | | string | — | 管理 API CRL URL |
| `--mgmt-ocsp-fallback` | | string | `allow` | 管理 API OCSP 降级策略 |

### --map KV 格式

使用 `--map`（`-m`）可在命令行直接定义 mapping，无需配置文件。可重复使用多次定义多个 mapping。

所有 key 使用**连字符**格式，支持的 key：

| Key | 必需 | 说明 |
|-----|------|------|
| `name` | 是 | mapping 名称 |
| `listen` | 是 | 监听地址（`host:port`） |
| `target` | 是 | 目标地址（`host:port`，多个逗号分隔实现轮询） |
| `protocol` | 是 | `tcp` / `tcp+mtls` / `tcp+mesh` |
| `ca-cert` | tcp+mtls 协议 | CA 证书 PEM 路径 |
| `cert` | tcp+mtls 协议 | 服务端证书 PEM 路径 |
| `key` | tcp+mtls 协议 | 服务端私钥 PEM 路径 |
| `crl-url` | 否 | CRL 分发点 URL |
| `crl-refresh-sec` | 否 | CRL 刷新间隔（秒） |
| `ocsp-cache-ttl-sec` | 否 | OCSP 缓存 TTL（秒） |
| `ocsp-fallback` | 否 | OCSP 降级策略 |
| `tsa-url` | 否 | TSA 服务 URL |
| `tsa-cert-file` | 否 | TSA 证书文件 |
| `allow-roles` | 否 | 允许的角色列表（分号分割） |
| `audit-file` | 否 | 审计日志文件路径 |
| `max-conns-per-ip` | 否 | 每 IP 最大并发连接数 |
| `max-total-conns` | 否 | 总并发连接数上限 |
| `idle-timeout-sec` | 否 | 空闲超时（秒） |
| `health-check-sec` | 否 | 健康检查间隔（秒） |
| `health-check-url` | 否 | HTTP 健康检查 URL（设置后代替 TCP 拨号） |
| `disconnect-on-expiry` | 否 | 证书过期时主动断开（设为 `false` 关闭） |
| `cipher-suites` | 否 | TLS 密码套件白名单（分号分割，详见配置参考 `cipher_suites` 表） |
| `min-tls-version` | 否 | 最低 TLS 版本（`1.2`/`1.3`） |
| `audit-max-size-mb` | 否 | 审计日志轮换大小 |
| `audit-max-backups` | 否 | 审计日志备份数 |

> **注意**：`--config` 与 `--map`/`--tunnel` 互斥，不能同时使用。

### --tunnel KV 格式

| Key | 必需 | 说明 |
|-----|------|------|
| `name` | 是 | tunnel 名称 |
| `listen` | 是 | 监听地址 |
| `gateway-addr` | 是 | 网关地址 |
| `cert-file` | 是 | 客户端证书 PEM |
| `key-file` | 是 | 客户端私钥 PEM |
| `ca-cert-file` | 是 | CA 证书 PEM |

### 示例

```bash
# 使用配置文件
gateway-tcp --config /etc/varwof/gateway-tcp/server.json

# 使用 --map 在命令行定义单个 mapping
gateway-tcp -m name=postgres,listen=:7443,target=db:5432,protocol=tcp+mtls,\
  ca-cert=/etc/pki/ca.crt,cert=/etc/pki/gw.crt,key=/etc/pki/gw.key,\
  crl-url=http://crl.example.com/ca.crl,allow-roles=admin

# 多个 mapping + 全局设置
gateway-tcp \
  -m name=web,listen=:8443,target=web:8080,protocol=tcp+mtls,ca-cert=ca.pem,cert=cert.pem,key=key.pem,allow-roles=admin \
  -m name=api,listen=:9443,target=api:8080,protocol=tcp+mtls,ca-cert=ca.pem,cert=cert.pem,key=key.pem,allow-roles=admin;readonly \
  --tsa-url http://tsa:3180/tsa \
  --audit-file /var/log/gateway-tcp/audit.jsonl

# 单行模式（不带等号空格）
gateway-tcp -m name=db,listen=:5443,target=pg:5432,protocol=tcp+mtls,ca-cert=ca.crt,cert=server.crt,key=server.key,crl-url=http://crl/ca.crl,disconnect-on-expiry=false,cipher-suites=TLS_AES_128_GCM_SHA256;TLS_AES_256_GCM_SHA384,min-tls-version=1.3
```

---

## tunnel

### 用法

```
gateway-tcp tunnel --config <file>
gateway-tcp tunnel --map <kv>...
```

### 标志

| 标志 | 短别名 | 类型 | 默认值 | 说明 |
|------|--------|------|--------|------|
| `--config` | `-c` | string | 自动检测 | 配置文件路径 |
| `--lang` | `-l` | string | `en` | 语言（`zh`/`en`） |
| `--map` | `-m` | string | — | Tunnel 定义（key=value,...），可重复 |

### 示例

```bash
gateway-tcp tunnel --map name=bastion,listen=:2222,gateway-addr=10.0.0.1:7443,\
  cert-file=client.pem,key-file=client.key,ca-cert-file=ca.pem
```

---

## audit

### 用法

```
gateway-tcp audit --entry <file> [--tsa-url <url>] [--lang <lang>]
```

### 标志

| 标志 | 短别名 | 类型 | 默认值 | 说明 |
|------|--------|------|--------|------|
| `--entry` | | string | — | 审计日志 JSON 文件路径（必需） |
| `--tsa-url` | | string | — | TSA 服务 URL |
| `--lang` | `-l` | string | `en` | 语言 |

### 示例

```bash
gateway-tcp audit --entry /var/log/gateway-tcp/audit.2026-07-05.jsonl \
  --tsa-url http://tsa:3180/tsa
```

---

## 环境变量

| 变量 | 说明 |
|------|------|
| `LANG` | 语言检测（`zh_CN.UTF-8` → 中文，其他 → 英文）；`--lang` 和配置文件 `locale` 优先级更高 |

---

## 模式选择

| 条件 | 行为 |
|------|------|
| 无 `--config`、无 `--map`/`--tunnel` | 自动检测默认配置文件路径，文件不存在则显示帮助 |
| 仅有 `--config` | 读取 JSON 配置文件 |
| 仅有 `--map`/`--tunnel` | 从 CLI 参数构建配置，忽略配置文件 |
| 同时有 `--config` 和 `--map`/`--tunnel` | 报错退出（互斥） |

---

## 配置文件路径

| 平台 | 默认路径 |
|------|---------|
| Linux | `/etc/varwof/gateway-tcp/server.json` |
| macOS | `/usr/local/etc/gateway-tcp/server.json` |
| Windows | `%ProgramData%\varwof\gateway-tcp\server.json` |

---

## 信号

| 信号 | 行为 |
|------|------|
| `SIGINT` / `SIGTERM` | 优雅关闭（等待活跃连接完成） |
| `SIGHUP`（Unix） | 热重载配置 |
| `POST /api/v1/gateway/reload`（Windows） | 热重载配置 |
