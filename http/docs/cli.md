# CLI 参考

## 概要

```
gateway-http [--config <file> | --listener <kv>... --route <kv>...] [flags]
gateway-http server [flags]                    # 默认子命令
gateway-http help
```

无子命令时默认进入 `server` 模式。少参数时显示帮助。

## 子命令

| 子命令 | 说明 |
|--------|------|
| `server`（默认）| 启动 HTTP 反向代理网关 |
| `help` | 显示帮助 |

---

## server

### 用法

```
gateway-http server [flags]
gateway-http [flags]                    # 省略 server 时等同
```

### 标志

| 标志 | 短别名 | 类型 | 默认值 | 说明 |
|------|--------|------|--------|------|
| `--config` | `-c` | string | 自动检测 | 配置文件路径（JSON） |
| `--lang` | `-l` | string | `en` | 语言（`zh`/`en`） |
| `--listener` | `-L` | string | — | 监听器定义（key=value,...），可重复 |
| `--route` | `-r` | string | — | 路由定义（key=value,...），可重复 |
| `--crl-refresh-sec` | | int | `300` | 全局 CRL 刷新间隔（秒） |
| `--ocsp-cache-ttl-sec` | | int | `300` | 全局 OCSP 缓存 TTL（秒） |
| `--ocsp-fallback` | | string | `allow` | OCSP 降级策略（`allow`/`deny`/`crl`） |
| `--tsa-url` | | string | — | TSA 服务 URL |
| `--audit-file` | | string | — | 审计日志文件路径 |
| `--audit-max-size-mb` | | int | `100` | 审计日志单文件最大大小（MB） |
| `--audit-max-backups` | | int | `3` | 审计日志最大备份数 |
| `--management-listen` | | string | — | 管理 API 监听地址 |
| `--mgmt-ca-cert` | | string | — | 管理 API CA 证书 |
| `--mgmt-cert` | | string | — | 管理 API 服务端证书 |
| `--mgmt-key` | | string | — | 管理 API 服务端私钥 |
| `--mgmt-crl-url` | | string | — | 管理 API CRL URL |
| `--mgmt-ocsp-fallback` | | string | `allow` | 管理 API OCSP 降级策略 |

### --listener KV 格式

使用 `--listener`（`-L`）可在命令行直接定义监听器。可重复使用定义多个监听器。

所有 key 使用**连字符**格式，支持的 key：

| Key | 必需 | 说明 |
|-----|------|------|
| `name` | 是 | 监听器名称（对应 route 的 `listener` 字段） |
| `listen` | 是 | 监听地址（`:port` 或 `host:port`） |
| `protocol` | 否 | 协议（`http1`/`http2`/`h2c`/`grpc`/`ws`/`wss`/`h3`/`quic`），缺省 `http2` |
| `tls-mode` | 否 | TLS 认证模式（兼容键）：`server`/`mtls`，缺省 `none`（明文）。缺省 `protocol` 为 `http2` 时等价于 `protocol=http2,tls-mode=...` |
| `ca-cert` | mtls 模式 | CA 证书 PEM 路径 |
| `cert` | server/mtls 模式 | 服务端证书 PEM 路径 |
| `key` | server/mtls 模式 | 服务端私钥 PEM 路径 |
| `crl-url` | 否 | CRL 分发点 URL |
| `crl-refresh-sec` | 否 | CRL 刷新间隔（秒） |
| `ocsp-cache-ttl-sec` | 否 | OCSP 缓存 TTL（秒） |
| `ocsp-fallback` | 否 | OCSP 降级策略 |
| `tsa-url` | 否 | TSA 服务 URL |
| `audit-file` | 否 | 审计日志文件路径 |
| `max-conns-per-ip` | 否 | 每 IP 最大并发连接数 |
| `max-conns-per-cert` | 否 | 每证书最大并发连接数 |
| `max-total-conns` | 否 | 总并发连接数上限 |
| `idle-timeout-sec` | 否 | 空闲超时（秒） |
| `read-header-timeout-sec` | 否 | 读请求头超时（秒） |
| `write-timeout-sec` | 否 | 写响应超时（秒） |
| `disconnect-on-expiry` | 否 | 证书过期时拒绝请求（设为 `false` 关闭） |
| `forward-client-cert` | 否 | 透传客户端证书信息到后端（设为 `false` 关闭） |
| `forward-client-cert-der` | 否 | 证书透传（B2）：以 `X-Client-Cert-DER` 透传已验证客户端证书到后端（设为 `true` 启用） |
| `tls-termination` | 否 | TLS 终止 + AIC Header 注入（设为 `false` 关闭） |
| `cipher-suites` | 否 | TLS 密码套件白名单（分号分割） |
| `min-tls-version` | 否 | 最低 TLS 版本（`1.2`/`1.3`） |
| `audit-max-size-mb` | 否 | 审计日志轮换大小 |
| `audit-max-backups` | 否 | 审计日志备份数 |

### --route KV 格式

使用 `--route`（`-r`）定义路由规则。多个 route 通过 `listener` 字段关联到对应监听器。

| Key | 必需 | 说明 |
|-----|------|------|
| `listener` | 是 | 所属监听器名称（与 `--listener name=` 匹配） |
| `path` | 是 | URL 路径（支持 `*` 通配符） |
| `target` | 是 | 后端目标 URL（如 `http://127.0.0.1:8080`） |
| `allow-roles` | 否 | 允许的角色列表（分号分割） |

> **注意**：`--config` 与 `--listener`/`--route` 互斥，不能同时使用。

### 示例

```bash
# 使用配置文件
gateway-http --config /etc/varwof/gateway-http/gateway-http.json

# 使用 --listener + --route 在命令行定义
gateway-http \
  -L name=api,listen=:4433,protocol=http2,tls-mode=mtls,ca-cert=ca.pem,cert=cert.pem,key=key.pem,crl-url=http://crl/ca.crl \
  -r listener=api,path=/api/v1,target=http://be:8080,allow-roles=gateway:admin \
  -r listener=api,path=/,target=http://web:3000 \
  --tsa-url http://tsa:3180/tsa

# 单行模式
gateway-http -L name=mtls,listen=:443,protocol=http2,tls-mode=mtls,ca-cert=ca.pem,cert=cert.pem,key=key.pem,disconnect-on-expiry=true,forward-client-cert=false,cipher-suites=TLS_AES_128_GCM_SHA256,min-tls-version=1.3 -r listener=mtls,path=/api/*,target=http://backend:8080,allow-roles=gateway:admin

# 纯 HTTP（明文，h2c）模式
gateway-http -L name=plain,listen=:8080,protocol=h2c -r listener=plain,path=/*,target=http://app:3000
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
| 无 `--config`、无 `--listener`/`--route` | 自动检测默认配置文件路径，文件不存在则显示帮助 |
| 仅有 `--config` | 读取 JSON 配置文件 |
| 仅有 `--listener`/`--route` | 从 CLI 参数构建配置，忽略配置文件 |
| 同时有 `--config` 和 `--listener`/`--route` | 报错退出（互斥） |

---

## 配置文件路径

| 平台 | 默认路径 |
|------|---------|
| Linux | `/etc/varwof/gateway-http/gateway-http.json` |
| Windows | `%ProgramData%\varwof\gateway-http\gateway-http.json` |

---

## 信号

| 信号 | 行为 |
|------|------|
| `SIGINT` / `SIGTERM` | 优雅关闭 |
| `SIGHUP`（Unix） | 热重载配置 |
| `POST /api/v1/gateway/reload`（Windows） | 热重载配置 |
