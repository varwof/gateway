# Varwof Gateway

Three-layer zero-trust security gateways integrating TCP/HTTP/UDP protocols, providing mTLS mutual authentication and fine-grained access control.

## Features

- **TCP Gateway (L4)**: Transparent proxy + mTLS
- **HTTP Gateway (L7)**: Reverse proxy + path-level RBAC
- **UDP Gateway (L3)**: DTLS/QUIC + rate limiting
- CRL/OCSP real-time revocation checking
- AIC capability verification
- Structured logging (slog)
- Prometheus metrics

## Installation

```bash
go get github.com/varwof/gateway
```

## Configuration

```json
{
  "server": {
    "tls_mode": "mtls",
    "cert_file": "server.pem",
    "key_file": "server-key.pem",
    "client_ca_file": "ca.pem"
  },
  "listeners": [
    {
      "name": "https",
      "listen": ":443",
      "protocol": "http"
    }
  ]
}
```

## Running

```bash
gateway --config config.json
```

## License

Apache-2.0
