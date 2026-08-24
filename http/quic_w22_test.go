// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package httpgw

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
	pki "github.com/varwof/types"
)

// TestQUICProxyH3StripIdentityHeaders W22/W19: H3 request path must strip
// client-forged trusted identity headers; server-asserted values are injected afterwards.
func TestQUICProxyH3StripIdentityHeaders(t *testing.T) {
	backend, close := startEchoHeadersBackend(t)
	defer close()
	hostport := strings.TrimPrefix(backend, "http://")

	tru := true
	cert := makeExtCert(t, "agent-strip", []string{"Delegated-Agent"}, []string{"Acme"}, []pkix.Extension{
		{Id: pki.OIDAIC, Value: marshalTestAIC(t)},
	})

	q := newTestQUIC(ListenerConfig{
		Name: "h3", Protocol: ProtocolH3, TLS: &gw.TLSConfig{},
		HTTPExt: &gw.HTTPExtra{ForwardClientCert: &tru, TLSTermination: &tru, ForwardClientCertDER: &tru},
		Routes:  []RouteConfig{{Path: "/echo", Target: hostport}},
	})
	q.tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/echo", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	req.RemoteAddr = "127.0.0.1:50001"
	// Client-forged identity headers must be stripped before reaching the backend.
	req.Header.Set("X-Client-Cert-CN", "attacker")
	req.Header.Set("X-Client-Cert-Agent-ID", "attacker-agent")
	req.Header.Set("X-Agent-TTL", "9999-01-01T00:00:00Z")
	q.handleH3Request(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", rr.Code, rr.Body.String())
	}
	body := strings.ToLower(rr.Body.String())
	if strings.Contains(body, "attacker") {
		t.Errorf("forged identity headers leaked to backend:\n%s", rr.Body.String())
	}
	// Server-asserted values injected (Delegated-Agent + DER passthrough).
	for _, want := range []string{
		"x-client-cert-der: ",
		"x-client-cert-cn: agent-strip",
		"x-client-cert-agent-id: agent-h3",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing server-asserted header %q:\n%s", want, rr.Body.String())
		}
	}
}

// TestQUICProxyH3NoRouteAudit W22: logs no_route audit and returns 404 when no route matches.
func TestQUICProxyH3NoRouteAudit(t *testing.T) {
	backend, close := startEchoHeadersBackend(t)
	defer close()
	hostport := strings.TrimPrefix(backend, "http://")

	audit, entries := newTestAudit(t)
	defer audit.Close()

	q := newTestQUIC(ListenerConfig{
		Name: "h3", Protocol: ProtocolH3, TLS: &gw.TLSConfig{},
		Routes: []RouteConfig{{Path: "/echo", Target: hostport}},
	})
	q.audit = audit
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/nope", nil)
	req.RemoteAddr = "127.0.0.1:50002"
	q.handleH3Request(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", rr.Code)
	}

	found := false
	for _, e := range entries() {
		if e.Action == "no_route" && e.Mapping == "h3" && e.Target == "/nope" {
			found = true
		}
	}
	if !found {
		t.Error("no_route audit entry not recorded")
	}
}

// TestQUICProxyH3CompletedAudit W22: per-request completed audit entry.
func TestQUICProxyH3CompletedAudit(t *testing.T) {
	backend, close := startEchoHeadersBackend(t)
	defer close()
	hostport := strings.TrimPrefix(backend, "http://")

	audit, entries := newTestAudit(t)
	defer audit.Close()

	q := newTestQUIC(ListenerConfig{
		Name: "h3", Protocol: ProtocolH3, TLS: &gw.TLSConfig{},
		Routes: []RouteConfig{{Path: "/echo", Target: hostport}},
	})
	q.audit = audit
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/echo", nil)
	req.RemoteAddr = "127.0.0.1:50003"
	q.handleH3Request(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", rr.Code, rr.Body.String())
	}

	found := false
	for _, e := range entries() {
		if e.Action == "completed" && e.Mapping == "h3" && e.Target == "/echo" {
			found = true
		}
	}
	if !found {
		t.Error("completed audit entry not recorded")
	}
}

// TestQUICProxyH3TotalLimit W22: MaxTotalConns concurrent limit exceeded returns 503.
func TestQUICProxyH3TotalLimit(t *testing.T) {
	backend, close := startEchoHeadersBackend(t)
	defer close()
	hostport := strings.TrimPrefix(backend, "http://")

	q := newTestQUIC(ListenerConfig{
		Name: "h3", Protocol: ProtocolH3, TLS: &gw.TLSConfig{MaxTotalConns: 1},
		Routes: []RouteConfig{{Path: "/echo", Target: hostport}},
	})
	// One in-flight request already occupies MaxTotalConns=1 -> new request gets 503.
	atomicAddInt64(&q.conns, 1)
	defer atomicAddInt64(&q.conns, -1)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/echo", nil)
	req.RemoteAddr = "127.0.0.1:50004"
	q.handleH3Request(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", rr.Code)
	}
}

// TestQUICProxyH3AllowRolesFailClosed W22: AllowRoles route on plain H3 without
// client cert must fail-closed (aligned with HTTP proxy).
func TestQUICProxyH3AllowRolesFailClosed(t *testing.T) {
	backend, close := startEchoHeadersBackend(t)
	defer close()
	hostport := strings.TrimPrefix(backend, "http://")

	q := newTestQUIC(ListenerConfig{
		Name: "h3", Protocol: ProtocolH3, TLS: &gw.TLSConfig{},
		Routes: []RouteConfig{{Path: "/echo", Target: hostport, AllowRoles: []string{"gateway:admin"}}},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/echo", nil)
	req.RemoteAddr = "127.0.0.1:50005"
	q.handleH3Request(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403 (fail-closed)", rr.Code)
	}
}

// TestQUICProxyH3TaskHeaderNotForwarded W22/W19: task control headers read then stripped before forwarding.
func TestQUICProxyH3TaskHeaderNotForwarded(t *testing.T) {
	backend, close := startEchoHeadersBackend(t)
	defer close()
	hostport := strings.TrimPrefix(backend, "http://")

	q := newTestQUIC(ListenerConfig{
		Name: "h3", Protocol: ProtocolH3, TLS: &gw.TLSConfig{},
		Routes: []RouteConfig{{Path: "/echo", Target: hostport}},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/echo", nil)
	req.RemoteAddr = "127.0.0.1:50006"
	req.Header.Set("X-AIC-Task-Id", "task-123")
	req.Header.Set("X-AIC-Task-Status", "completed")
	q.handleH3Request(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d", rr.Code)
	}
	body := strings.ToLower(rr.Body.String())
	if strings.Contains(body, "task-123") || strings.Contains(body, "x-aic-task") {
		t.Errorf("task control headers leaked to backend:\n%s", rr.Body.String())
	}
}

// TestQUICProxyH3TargetScheme W22: both http:// and bare host:port backend targets are reachable.
func TestQUICProxyH3TargetScheme(t *testing.T) {
	backend, close := startEchoHeadersBackend(t)
	defer close()
	hostport := strings.TrimPrefix(backend, "http://")

	q := newTestQUIC(ListenerConfig{
		Name: "h3", Protocol: ProtocolH3, TLS: &gw.TLSConfig{},
		Routes: []RouteConfig{{Path: "/bare", Target: hostport}},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/bare", nil)
	req.RemoteAddr = "127.0.0.1:50007"
	q.handleH3Request(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("bare target code = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}

	q2 := newTestQUIC(ListenerConfig{
		Name: "h3", Protocol: ProtocolH3, TLS: &gw.TLSConfig{},
		Routes: []RouteConfig{{Path: "/schem", Target: backend}},
	})
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "http://x/schem", nil)
	req2.RemoteAddr = "127.0.0.1:50008"
	q2.handleH3Request(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("scheme target code = %d, want 200", rr2.Code)
	}
}

// TestQUICProxyH3PerIPLimit W22: per-IP connection limit enforced (ConnContext counting).
func TestQUICProxyH3PerIPLimit(t *testing.T) {
	backend, close := startEchoHeadersBackend(t)
	defer close()
	hostport := strings.TrimPrefix(backend, "http://")

	q := newTestQUIC(ListenerConfig{
		Name: "h3", Protocol: ProtocolH3, TLS: &gw.TLSConfig{MaxConnsPerIP: 1},
		Routes: []RouteConfig{{Path: "/echo", Target: hostport}},
	})
	q.connIPs = make(map[string]int64)
	// Same IP already has 2 QUIC connections (exceeds limit 1) -> new request gets 429.
	q.connIPs["127.0.0.1"] = 2

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/echo", nil)
	req.RemoteAddr = "127.0.0.1:50009"
	q.handleH3Request(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("code = %d, want 429", rr.Code)
	}
}

// TestQUICW22Wiring W22: after gateway wiring, QUIC listener's revoker/registry/task
// are all non-nil (previously SetTaskRegistry/SetConnRegistry were no-ops).
func TestQUICW22Wiring(t *testing.T) {
	pki := setupPKI(t)
	backend, close := startEchoHeadersBackend(t)
	defer close()
	hostport := strings.TrimPrefix(backend, "http://")

	revoker, err := gw.NewRevoker(gw.RevokerConfig{
		CoreURL: "https://core.test:4433/api/v1", MTLSCertFile: pki.AdminCertFile, MTLSKeyFile: pki.AdminKeyFile,
	})
	if err != nil {
		t.Fatalf("revoker: %v", err)
	}
	connReg := gw.NewConnRegistry()
	taskReg := gw.NewTaskRegistry()

	g := NewGateway(&Config{
		Listeners: []ListenerConfig{{
			Name: "h3", Listen: "127.0.0.1:0", Protocol: ProtocolH3, TLS: &gw.TLSConfig{CertFile: pki.ServerCertFile, KeyFile: pki.ServerKeyFile},
			Routes: []RouteConfig{{Path: "/*", Target: hostport}},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	g.revoker = revoker
	g.connRegistry = connReg
	g.taskRegistry = taskReg
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()

	ql, ok := g.listeners["h3"].(*QUICListener)
	if !ok {
		t.Fatalf("listener h3 is %T, want *QUICListener", g.listeners["h3"])
	}
	if ql.revoker != revoker {
		t.Error("revoker not wired to QUIC listener")
	}
	if ql.connRegistry != connReg {
		t.Error("connRegistry not wired to QUIC listener")
	}
	if ql.taskRegistry != taskReg {
		t.Error("taskRegistry not wired to QUIC listener")
	}
}

// atomicAddInt64 test helper: performs atomic increment/decrement on q.conns.
func atomicAddInt64(p *int64, delta int64) int64 {
	return atomic.AddInt64(p, delta)
}

// newTestAudit returns an audit logger writing to a temp file + a read-back function.
// Read-back uses polling: AuditLogger flushes asynchronously via channel/loop, so we must wait for writes.
func newTestAudit(t *testing.T) (*gw.AuditLogger, func() []gw.AuditEntry) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "audit.jsonl")
	al, err := gw.NewAuditLogger(f, nil, 0, 0)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	read := func() []gw.AuditEntry {
		var out []gw.AuditEntry
		for i := 0; i < 50; i++ {
			out = out[:0]
			data, err := os.ReadFile(f)
			if err != nil {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				if line == "" {
					continue
				}
				var signed gw.SignedAuditEntry
				if json.Unmarshal([]byte(line), &signed) == nil {
					out = append(out, signed.Entry)
				}
			}
			if len(out) > 0 {
				return out
			}
			time.Sleep(10 * time.Millisecond)
		}
		return out
	}
	return al, read
}

var (
	_ = slog.Logger{}
	_ = io.Discard
	_ = sync.Mutex{}
	_ = time.Second
)
