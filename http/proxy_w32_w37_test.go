// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package httpgw

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

// TestXForwardedForOverwritten W37: gateway must overwrite X-Forwarded-For to only
// the peer IP, clearing the client-forged chain (previously used append semantics,
// leftmost entries could be spoofed).
func TestXForwardedForOverwritten(t *testing.T) {
	got := make(chan string, 1)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got <- r.Header.Get("X-Forwarded-For")
			w.WriteHeader(200)
		}),
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(lis)
	defer srv.Close()
	backendURL := "http://" + lis.Addr().String()

	cfg := ListenerConfig{
		Name:     "xff",
		Listen:   "127.0.0.1:0",
		Protocol: ProtocolHTTP2,
		Routes:   []RouteConfig{{Path: "/*", Target: backendURL}},
	}
	audit, _ := gw.NewAuditLogger("", nil, 0, 0)
	p, err := NewProxyListener(cfg, nil, nil, audit, nil, nil, nil, "en", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	req, _ := http.NewRequest("GET", "http://"+p.listener.Addr().String()+"/x", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 203.0.113.2")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	select {
	case v := <-got:
		if v == "203.0.113.1, 203.0.113.2" {
			t.Fatalf("client-supplied X-Forwarded-For chain was forwarded unchanged: %q", v)
		}
		if strings.Contains(v, "203.0.113.1") {
			t.Fatalf("client-spoofed IP leaked into X-Forwarded-For: %q", v)
		}
		// Should only contain the peer IP (127.0.0.1).
		if !strings.HasPrefix(v, "127.0.0.1") {
			t.Fatalf("X-Forwarded-For = %q, want only peer IP 127.0.0.1", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("backend did not receive request")
	}
}

// TestReadHeaderTimeoutConfig W32: after configuring read_header_timeout_sec /
// write_timeout_sec, the server fields take effect.
func TestReadHeaderTimeoutConfig(t *testing.T) {
	backendURL, backendClose := startTestBackend(t)
	defer backendClose()

	cfg := ListenerConfig{
		Name:     "timeouts",
		Listen:   "127.0.0.1:0",
		Protocol: ProtocolHTTP2,
		HTTPExt: &gw.HTTPExtra{
			ReadHeaderTimeoutSec: 10,
			WriteTimeoutSec:      60,
		},
		Routes: []RouteConfig{{Path: "/*", Target: backendURL}},
	}
	audit, _ := gw.NewAuditLogger("", nil, 0, 0)
	p, err := NewProxyListener(cfg, nil, nil, audit, nil, nil, nil, "en", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	if p.server == nil {
		t.Fatal("server is nil")
	}
	if p.server.ReadHeaderTimeout != 10*time.Second {
		t.Fatalf("ReadHeaderTimeout = %v, want 10s", p.server.ReadHeaderTimeout)
	}
	if p.server.WriteTimeout != 60*time.Second {
		t.Fatalf("WriteTimeout = %v, want 60s", p.server.WriteTimeout)
	}
}

// TestQUICStateAfterStop W36: after Stop, QUIC state must transition from Running to Stopped.
func TestQUICStateAfterStop(t *testing.T) {
	q := newTestQUIC(ListenerConfig{Name: "q", Listen: "127.0.0.1:0", Protocol: ProtocolQUIC, TLS: &gw.TLSConfig{}})
	// Directly set running to simulate a started state; after Stop it should go back to Stopped.
	q.running.Store(true)
	if q.State() != ProxyRunning {
		t.Fatalf("State after mock start = %v, want Running", q.State())
	}
	if err := q.Stop(); err != nil {
		t.Fatal(err)
	}
	if q.State() != ProxyStopped {
		t.Fatalf("State after Stop = %v, want Stopped (W36)", q.State())
	}
}
