# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in `varwof/gateway`, please do not
open a public issue. Report it privately to
[pki@varwof.com](mailto:pki@varwof.com).

Please include:

- The affected version(s)
- A description of the vulnerability and its impact
- A minimal reproducer if available

You should receive an acknowledgement within a few business days.
We ask that you give us reasonable time to address the issue before
public disclosure.

## Scope

This project is the network gateway / reverse proxy (HTTP/HTTP3, TCP,
UDP/DTLS) for the zero-trust platform. Issues of interest include:

- Authentication / authorization bypass (mTLS, AIC-JWT bearer)
- SSRF / open-forward-proxy / amplification / reflection in the data
  plane (TCP mesh, UDP relay)
- Request smuggling / header injection into upstreams
- Resource-exhaustion / DoS (unbounded bodies, goroutine/session leaks,
  unbounded maps, slow handshakes)
- TLS/DTLS/QUIC misconfiguration
- Plaintext (unencrypted) data plane

## Supported Versions

Security fixes are applied to the latest release. Older releases are
supported on a best-effort basis.

## Funding note: no paid third-party audit

This is an individual / open-source project; no paid third-party
security audit has been conducted. Validation relies on internal
AI-assisted review, automated tests (race-enabled), and independent
cross-implementation exercise where available.

## Security Audit History

Review practice: development includes AI-assisted security review and
RFC compliance cross-checks (TLS (RFC 8446/5246), HTTP semantics, JOSE bearer (RFC 7519/9068), QUIC (RFC 9000)). Consolidated findings are
logged below; each is retained as a historical record after resolution.

### 2026-09-01 -- internal security review (AI-assisted), resolved

Method: internal security/correctness review of the current `main`,
assisted by AI tooling, with RFC cross-checks against TLS (RFC 8446/5246), HTTP semantics, JOSE bearer (RFC 7519/9068), QUIC (RFC 9000).
Status: all findings below were resolved in the 2026-09-01 security
pass (commit dfe8f85) and verified by the full test suite. Fixes were verified by the full test suite (race-enabled).

Next scheduled review: quarterly (next: 2026-12-01).
Independent exercise: third-party hostile testing exercised the capability plugins (2026-09).

### Resolved findings (2026-09-01)

### Security (high)

1. **Plaintext UDP mode is an unauthenticated open relay with
   amplification/reflection**
   (`udp/proxy.go:124-139` `TLSModeNone`, `:390-446` `handlePacket`).
   When `protocol=udp` with no TLS mode, `serve()` accepts every datagram
   from any source and forwards it to the configured backend with **no
   authentication at all**. `handlePacket` reads the response into a
   `MaxPacketSize` (default 65535) buffer (`:431`) and writes it back to
   `src` (`:439`), which is entirely attacker-controlled / spoofable. A
   remote attacker can (a) relay traffic into internal backends (DNS
   queries to an internal `:53`, etc.), and (b) send a small query with
   a spoofed victim `src` to make the gateway reflect a large response at
   the victim — an open reflection amplifier. The DTLS path is
   protected (`RequireAndVerifyClientCert`), but plaintext UDP is not.

2. **UDP `rateLimit` map grows without bound (memory-exhaustion DoS)**
   (`udp/proxy.go:296-316`). `trackClient` creates an entry in
   `p.rateLimit` for every unique source and never evicts it; with
   spoofed source IPs an attacker can grow this map without limit for the
   lifetime of the process.

3. **UDP goroutine-per-packet with no rate limiting by default**
   (`udp/proxy.go:292`, `proxy.go:431-442`). Each packet spawns
   `go p.handlePacket(...)`, which opens a fresh UDP socket and blocks up
   to 5 s on a synchronous read. `MaxPktsPerIP` and `MaxTotalPkts` default
   to 0 (disabled), so a modest flood sustains unbounded goroutines +
   sockets. Rate limits are opt-in and off by default.

### Security (medium)

4. **TCP slow-TLS-handshake DoS when `idle_timeout` is unset**
   (`tcp/mapping.go:441-443`). The deadline before `tlsConn.Handshake()`
   is only set when `idleTimeout > 0`; at the default 0 no deadline is
   applied, so a client can hold a connection during a slow/incomplete
   handshake indefinitely, consuming a goroutine per connection
   (slowloris).

5. **Mesh forwarder fails open: empty `mesh_allowed_targets` permits any
   private / cloud-metadata IP** (`tcp/mesh.go:216-218`). When no
   allowlist entries are configured, `Allow()` falls through to
   `isPrivate()`, which permits `10/8`, `172.16/12`, `192.168/16`,
   link-local and IPv6 ULA — including `169.254.169.254` cloud metadata.
   An authenticated mesh peer can forward to arbitrary internal /
   metadata addresses (SSRF) purely by requesting a literal private IP.
   The intended "block public SSRF, allow private" default is the
   opposite of deny-by-default for an inbound forwarding target.

6. **AIC-JWT bearer auth accepted over plaintext listeners**
   (`http/proxy.go:471-497`). The bearer fallback runs when
   `mode == MTLS || jwtVerifier != nil` and, when no client cert is
   presented, accepts a valid `Authorization: Bearer` token. On a
   `server`/`none` (plaintext HTTP) listener with the verifier configured,
   a network eavesdropper can capture and replay the bearer token with no
   proof-of-possession binding. (The deeper replay/revocation/issuer
   semantics of `VerifyBearer` live in `gateway-core` and should be
   reviewed there.)

7. **HTTP/3 path follows upstream redirects (gateway-initiated SSRF)**
   (`http/quic.go:711-715`). `proxyToBackend` uses `http.Client` with the
   default `CheckRedirect` (follows up to 10 redirects). If a configured
   backend returns a `30x`/`Location:` to an internal/loopback/metadata
   address, the gateway itself follows it and returns the body. The HTTP/1
   path (`httputil.ReverseProxy`) does not follow redirects — this is
   specific to the H3 data plane.

8. **No request/response body size limits on HTTP/3**
   (`http/quic.go:711-730`). No `MaxBytesReader` on the request body and
   no cap on `io.Copy(w, resp.Body)`; only the 30 s client `Timeout`
   bounds the exchange (a time cap, not a size cap), allowing unbounded
   uploads / large compressed responses.

9. **Mesh listener and tunnel have no connection limits**
   (`tcp/mesh.go:382-403`, `tcp/tunnel.go:119-159`). Unlike the mapping
   path, the mesh accept loop and the tunnel spawn a goroutine per
   accepted connection with no per-IP or total caps; a single peer/
   attacker node can exhaust goroutines / file descriptors.

10. **`max_total_conns` accounting counts requests, not connections**
    (`http/proxy.go:419,454`, `http/quic.go`). Limits are applied
    per-request; under keep-alive / HTTP/2 / HTTP/3 multiplexing a single
    connection issuing many requests bypasses the configured cap.

### Low / robustness

11. **Renew endpoint ignores its own request fields**
    (`tcp/gateway.go:678-732`). `serial_hex` and `new_pub_key_pem` are
    decoded and validated but **never used** for issuance — the new cert
    is always minted for the mTLS client's own CN/SAN with a fresh
    server-generated keypair. A client cannot rotate-in its requested key
    (misleading API, and a stale/misleading `serial_hex`), though this is
    **not** an impersonation vector (the issuance is bound to the
    authenticated client's identity).

12. **Tunnel backoff jitter uses `math/rand`** (`tcp/tunnel.go`),
    giving predictable reconnect timing.

13. **UDP response is delivered to a caller-supplied `src` even in
    authenticated modes** (`udp/proxy.go:439`); no anti-spoofing on the
    response path.

14. **CLI-saved config uses a predictable `/tmp` path with a 32-bit
    random suffix** (`tcp/config.go:94-95`). Low entropy (32 bits) for a
    local attacker to enumerate/symlink.

### Verified-clean / non-issues

- The HTTP/1 data plane correctly overwrites `X-Forwarded-For` with the
  trusted peer IP, strips the `X-Client-Cert-*`/`X-Agent-TTL` identity
  namespace, and relies on `httputil.ReverseProxy` hop-by-hop stripping.
- Bearer token parsing rejects CRLF (no header injection via the token).
- DTLS/QUIC effectively enforce mTLS (`RequireAndVerifyClientCert`,
  QUIC TLS1.3 floor, cipher whitelist).
- The exported `tcp.HandlePeerRequest` still goes through
  `proxyPeerToBackend`, which validates resolved IPs against the mesh
  matcher / link-local block — the mesh target allowlist is *not* skipped
  there (an earlier concern was checked and is not a finding).

### Environment (not a code bug)

15. `go.mod` declares `go 1.26.2` while the available toolchain is
    1.25.10; some analysis tooling fails in this environment.
