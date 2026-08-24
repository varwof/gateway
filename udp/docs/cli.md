# CLI 参考

## 用法

```
gateway-udp [--config <file> | --listener <kv>...] [flags]
```

## 全局参数

| 参数 | 简写 | 说明 |
|------|------|------|
| `--config <file>` | `-c` | JSON 配置文件路径 |
| `--lang <lang>` | `-l` | 语言（zh/en） |
| `--listener <kv>` | `-L` | 监听器定义（key=value，可重复） |

## 监听器 key=value 格式

```
name=<name>,listen=<addr>,protocol=<udp|dtls|udp+mtls|quic>,
ca-cert=<path>,cert=<path>,key=<path>,
routes=<target>[;<target>...],
allow-roles=<role>[;<role>...],
crl-url=<url>,crl-refresh-sec=<n>,
ocsp-url=<url>,ocsp-cache-ttl-sec=<n>,ocsp-fallback=<s>,
audit-file=<path>,audit-max-size-mb=<n>,audit-max-backups=<n>
```

## TSA 参数

| 参数 | 说明 |
|------|------|
| `--tsa-url <url>` | TSA 服务器 URL |
| `--tsa-cert-file <path>` | TSA 客户端证书 |
| `--tsa-proof-file <path>` | TSA 审计证明日志 |
| `--tsa-proof-interval-sec <n>` | TSA 证明间隔 |

## 管理 API 参数

| 参数 | 说明 |
|------|------|
| `--management-listen <addr>` | 管理 API 监听地址 |
| `--mgmt-ca-cert <path>` | 管理 API CA 证书 |
| `--mgmt-cert <path>` | 管理 API 服务端证书 |
| `--mgmt-key <path>` | 管理 API 服务端密钥 |

## 审计参数

| 参数 | 说明 |
|------|------|
| `--audit-file <path>` | 审计日志文件路径 |
| `--audit-max-size-mb <n>` | 审计日志最大 MB（默认 100） |
| `--audit-max-backups <n>` | 审计日志备份数（默认 3） |
