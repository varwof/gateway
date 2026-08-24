// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package httpgw

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

func TestDeriveRequiredCaps(t *testing.T) {
	tests := []struct {
		prefix string
		method string
		want   string
	}{
		{"varwof/demo-mysql-v1", "GET", "varwof/demo-mysql-v1:SELECT:*"},
		{"varwof/demo-mysql-v1", "POST", "varwof/demo-mysql-v1:INSERT:*"},
		{"varwof/demo-mysql-v1", "PUT", "varwof/demo-mysql-v1:UPDATE:*"},
		{"varwof/demo-mysql-v1", "DELETE", "varwof/demo-mysql-v1:DELETE:*"},
		{"varwof/demo-mysql-v1", "GET", "varwof/demo-mysql-v1:SELECT:*"},
		{"varwof/demo-mysql-v1", "POST", "varwof/demo-mysql-v1:INSERT:*"},
		{"varwof/demo-mysql-v1", "DELETE", "varwof/demo-mysql-v1:DELETE:*"},
		{"varwof/core", "GET", "varwof/core:GET:*"},
		{"varwof/core", "DELETE", "varwof/core:DELETE:*"},
		{"cap", "GET", "cap:GET:*"},
	}
	for _, tt := range tests {
		got := deriveRequiredCaps(tt.prefix, tt.method)
		if len(got) != 1 || got[0] != tt.want {
			t.Errorf("deriveRequiredCaps(%q, %q) = %v, want [%s]", tt.prefix, tt.method, got, tt.want)
		}
	}
}

func TestMatchRoute(t *testing.T) {
	apiURL, _ := url.Parse("http://api:8080")
	pubURL, _ := url.Parse("http://pub:8081")
	healthURL, _ := url.Parse("http://health:8082")

	p := &ProxyListener{
		routes: []Route{
			{Path: "/api/*", Target: apiURL, AllowRoles: []string{"gateway:api"}},
			{Path: "/api/public/*", Target: pubURL},
			{Path: "/health", Target: healthURL},
		},
	}

	tests := []struct {
		path    string
		want    string
		wantLen int
	}{
		{"/api/v1/users", "http://api:8080", 4},
		{"/api/public/status", "http://pub:8081", 11},
		{"/health", "http://health:8082", 7},
		{"/other", "", -1},
	}
	for _, tt := range tests {
		r, l := p.matchRoute(tt.path)
		if r == nil {
			if tt.wantLen >= 0 {
				t.Errorf("matchRoute(%q) = nil, want target %s", tt.path, tt.want)
			}
			continue
		}
		got := r.Target.String()
		if got != tt.want {
			t.Errorf("matchRoute(%q) target = %s, want %s", tt.path, got, tt.want)
		}
		if l != tt.wantLen {
			t.Errorf("matchRoute(%q) len = %d, want %d", tt.path, l, tt.wantLen)
		}
	}
}

func TestProxyPlainHTTP(t *testing.T) {
	backendURL, backendClose := startTestBackend(t)
	defer backendClose()

	cfg := ListenerConfig{
		Name:     "test-plain",
		Listen:   "127.0.0.1:0",
		Protocol: ProtocolHTTP2,
		Routes: []RouteConfig{
			{Path: "/*", Target: backendURL},
		},
	}

	audit, _ := gw.NewAuditLogger("", nil, 0, 0)
	p, err := NewProxyListener(cfg, nil, nil, audit, nil, nil, nil, "en", nil, nil)
	if err != nil {
		t.Fatalf("NewProxyListener: %v", err)
	}
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	addr := p.listener.Addr().String()
	resp, err := http.Get("http://" + addr + "/test")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if strings.TrimSpace(string(body)) != "ok" {
		t.Errorf("body = %q, want %q", string(body), "ok")
	}
}

func TestIsWebSocketRequest(t *testing.T) {
	tests := []struct {
		name   string
		header http.Header
		want   bool
	}{
		{"websocket upgrade", http.Header{"Upgrade": {"websocket"}}, true},
		{"WebSocket case", http.Header{"Upgrade": {"WebSocket"}}, true},
		{"no upgrade header", http.Header{}, false},
		{"other upgrade", http.Header{"Upgrade": {"h2c"}}, false},
		{"empty upgrade", http.Header{"Upgrade": {""}}, false},
	}
	for _, tt := range tests {
		r := &http.Request{Header: tt.header}
		got := isWebSocketRequest(r)
		if got != tt.want {
			t.Errorf("%s: isWebSocketRequest = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestWebSocketProxy(t *testing.T) {
	// Start WebSocket backend: accept Upgrade → 101 → echo data
	backendURL, backendClose := startWebSocketEchoBackend(t)
	defer backendClose()

	cfg := ListenerConfig{
		Name:     "test-ws",
		Listen:   "127.0.0.1:0",
		Protocol: ProtocolHTTP2,
		Routes: []RouteConfig{
			{Path: "/ws/*", Target: backendURL},
		},
	}

	audit, _ := gw.NewAuditLogger("", nil, 0, 0)
	p, err := NewProxyListener(cfg, nil, nil, audit, nil, nil, nil, "en", nil, nil)
	if err != nil {
		t.Fatalf("NewProxyListener: %v", err)
	}
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	// Send WebSocket upgrade request through the proxy
	addr := p.listener.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	req := "GET /ws/echo HTTP/1.1\r\n" +
		"Host: " + addr + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}

	// Read response — should receive 101 Switching Protocols
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101 Switching Protocols", resp.StatusCode)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		t.Errorf("Upgrade header = %q, want websocket", resp.Header.Get("Upgrade"))
	}

	// Send test data over the upgraded connection (WebSocket echo)
	payload := []byte("hello websocket!")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	// Read echo
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(reply) != string(payload) {
		t.Errorf("echo mismatch: got %q, want %q", string(reply), string(payload))
	}
}

func TestWebSocketDeniedByRBAC(t *testing.T) {
	backendURL, backendClose := startWebSocketEchoBackend(t)
	defer backendClose()

	cfg := ListenerConfig{
		Name:     "test-ws-rbac",
		Listen:   "127.0.0.1:0",
		Protocol: ProtocolHTTP2,
		Routes: []RouteConfig{
			{Path: "/admin/*", Target: backendURL, AllowRoles: []string{"gateway:admin"}},
		},
	}

	audit, _ := gw.NewAuditLogger("", nil, 0, 0)
	p, err := NewProxyListener(cfg, nil, nil, audit, nil, nil, nil, "en", nil, nil)
	if err != nil {
		t.Fatalf("NewProxyListener: %v", err)
	}
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	// G5: plain mode + allow_roles must fail-closed reject (no longer silently
	// bypass RBAC due to clientCert==nil). WebSocket upgrade request is rejected
	// before the RBAC check.
	addr := p.listener.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	req := "GET /admin/ws HTTP/1.1\r\n" +
		"Host: " + addr + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	conn.Write([]byte(req))

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	// Requests with allow_roles in plain mode must be rejected (no client cert, cannot authorize).
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("plain WS with allow_roles: status = %d, want 403 (fail-closed)", resp.StatusCode)
	}
}

func startTestBackend(t *testing.T) (string, func()) {
	t.Helper()
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("ok\n"))
		}),
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(lis)
	return "http://" + lis.Addr().String(), func() {
		srv.Close()
		time.Sleep(50 * time.Millisecond)
	}
}

// TestProxyRBACFailClosedNoCert verifies G5: a route that requires roles but
// receives no client certificate (plain listener, or unauthenticated mTLS
// client) must be denied with 403 rather than silently forwarded.
func TestProxyRBACFailClosedNoCert(t *testing.T) {
	backendURL, backendClose := startTestBackend(t)
	defer backendClose()

	cfg := ListenerConfig{
		Name:     "test-rbac-failclosed",
		Listen:   "127.0.0.1:0",
		Protocol: ProtocolHTTP2,
		Routes: []RouteConfig{
			{Path: "/admin/*", Target: backendURL, AllowRoles: []string{"gateway:admin"}},
		},
	}

	audit, _ := gw.NewAuditLogger("", nil, 0, 0)
	p, err := NewProxyListener(cfg, nil, nil, audit, nil, nil, nil, "en", nil, nil)
	if err != nil {
		t.Fatalf("NewProxyListener: %v", err)
	}
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	addr := p.listener.Addr().String()
	resp, err := http.Get("http://" + addr + "/admin/secret")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (fail-closed RBAC)", resp.StatusCode)
	}
}

// TestMatchRouteNormalization verifies H4: request paths with "//", "/./",
// "/x/../" variants must not bypass an exact/prefix route and fall through to
// a broader allow-all route.
func TestMatchRouteNormalization(t *testing.T) {
	adminURL, _ := url.Parse("http://admin:8080")
	wildURL, _ := url.Parse("http://wild:8081")

	p := &ProxyListener{
		routes: []Route{
			{Path: "/api/admin", Target: adminURL, AllowRoles: []string{"gateway:admin"}},
			{Path: "/api/*", Target: wildURL},
		},
	}

	// exact match still works
	if r, _ := p.matchRoute("/api/admin"); r == nil || r.Target != adminURL {
		t.Errorf("exact /api/admin should match admin route, got %v", r)
	}
	// "//" variant must still resolve to the admin route, not the wildcard
	if r, _ := p.matchRoute("//api//admin"); r == nil || r.Target != adminURL {
		t.Errorf("//api//admin should normalize to admin route, got %v", r)
	}
	// "/api/./admin" must normalize to /api/admin (admin route), not wildcard
	if r, _ := p.matchRoute("/api/./admin"); r == nil || r.Target != adminURL {
		t.Errorf("/api/./admin should normalize to admin route, got %v", r)
	}
	// other sub-paths hit the wildcard
	if r, _ := p.matchRoute("/api/users"); r == nil || r.Target != wildURL {
		t.Errorf("/api/users should match wildcard, got %v", r)
	}
}

// startWebSocketEchoBackend starts a WebSocket echo backend server.
// Accepts HTTP Upgrade requests, returns 101, then echoes back all received data.
func startWebSocketEchoBackend(t *testing.T) (string, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis.Addr().String()
	go func() {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 4096)
		if _, err := conn.Read(buf); err != nil {
			return
		}

		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
		if _, err := conn.Write([]byte(resp)); err != nil {
			return
		}

		// Echo data (WebSocket echo mode)
		io.Copy(conn, conn)
	}()
	return "http://" + addr, func() { lis.Close() }
}
