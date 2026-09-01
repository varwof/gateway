// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package httpgw

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	gw "github.com/varwof/gateway-core"
)

func newTestQUIC(cfg ListenerConfig) *QUICListener {
	q := newQUICListener(cfg, nil, nil, nil, nil, make(chan struct{}), NewBundle(), "en", nil)
	q.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	q.tlsCfg = &tls.Config{}
	return q
}

func TestMatchPath(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"", "/", true},
		{"", "/a", false},
		{"/api/*", "/api/", true},
		{"/api/*", "/api/v1", false},
		{"/api/*", "/api//v1", true},
		{"/api/*", "/apix", false},
		{"/api/*", "/", false},
		{"/health", "/health", true},
		{"/health", "/healthx", false},
		{"/health", "/Health", false},
	}
	for _, c := range cases {
		if got := matchPath(c.pattern, c.path); got != c.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestQUICGetters(t *testing.T) {
	q := newTestQUIC(ListenerConfig{Name: "q1", Listen: "127.0.0.1:0", Protocol: ProtocolQUIC, TLS: &gw.TLSConfig{}})
	if q.Name() != "q1" {
		t.Fatalf("Name = %q", q.Name())
	}
	if q.Config().Name != "q1" {
		t.Fatalf("Config = %+v", q.Config())
	}
	if q.State() != ProxyStopped {
		t.Fatalf("State before Start = %v, want Stopped (W36)", q.State())
	}
	if q.Conns() != 0 {
		t.Fatalf("Conns = %d", q.Conns())
	}
	q.active.Add(3)
	if q.Conns() != 3 {
		t.Fatalf("Conns after Add(3) = %d", q.Conns())
	}
	if q.Addr() != nil {
		t.Fatalf("Addr before Start = %v", q.Addr())
	}
	q.SetLogger(nil)
	q.SetPluginRegistry(nil)
}

func TestQUICStartStopTunnel(t *testing.T) {
	pki := setupPKI(t)
	q := newTestQUIC(ListenerConfig{
		Name: "quic", Listen: "127.0.0.1:0", Protocol: ProtocolQUIC,
		TLS: &gw.TLSConfig{CertFile: pki.ServerCertFile, KeyFile: pki.ServerKeyFile},
	})
	if err := q.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if q.Addr() == nil {
		t.Fatal("Addr() nil after Start")
	}
	if err := q.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := q.Stop(); err != nil {
		t.Fatalf("second Stop should be idempotent: %v", err)
	}
}

func TestQUICStartStopH3(t *testing.T) {
	pki := setupPKI(t)
	q := newTestQUIC(ListenerConfig{
		Name: "h3", Listen: "127.0.0.1:0", Protocol: ProtocolH3,
		TLS: &gw.TLSConfig{CertFile: pki.ServerCertFile, KeyFile: pki.ServerKeyFile},
	})
	if err := q.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := q.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestQUICStopNotStarted(t *testing.T) {
	q := newTestQUIC(ListenerConfig{Name: "q", Listen: "127.0.0.1:0", Protocol: ProtocolQUIC, TLS: &gw.TLSConfig{}})
	if err := q.Stop(); err != nil {
		t.Fatalf("Stop on not-started listener: %v", err)
	}
}

func TestQUICStartErrors(t *testing.T) {
	pki := setupPKI(t)

	t.Run("already running", func(t *testing.T) {
		q := newTestQUIC(ListenerConfig{Name: "q", Listen: "127.0.0.1:0", Protocol: ProtocolQUIC, TLS: &gw.TLSConfig{}})
		q.running.Store(true)
		if err := q.Start(); err == nil {
			t.Fatal("expected already-running error")
		}
	})

	t.Run("bad cert", func(t *testing.T) {
		q := newTestQUIC(ListenerConfig{
			Name: "q", Listen: "127.0.0.1:0", Protocol: ProtocolQUIC,
			TLS: &gw.TLSConfig{CertFile: "/nonexistent/c.pem", KeyFile: "/nonexistent/k.pem"},
		})
		if err := q.Start(); err == nil {
			t.Fatal("expected cert load error")
		}
	})

	t.Run("bad CA", func(t *testing.T) {
		q := newTestQUIC(ListenerConfig{
			Name: "q", Listen: "127.0.0.1:0", Protocol: ProtocolQUIC,
			TLS: &gw.TLSConfig{CertFile: pki.ServerCertFile, KeyFile: pki.ServerKeyFile, CACertFile: "/nonexistent/ca.pem"},
		})
		if err := q.Start(); err == nil {
			t.Fatal("expected CA load error")
		}
	})

	t.Run("bad address", func(t *testing.T) {
		q := newTestQUIC(ListenerConfig{
			Name: "q", Listen: "127.0.0.1:notaport", Protocol: ProtocolQUIC,
			TLS: &gw.TLSConfig{CertFile: pki.ServerCertFile, KeyFile: pki.ServerKeyFile},
		})
		if err := q.Start(); err == nil {
			t.Fatal("expected address resolve error")
		}
	})
}

func TestQUICUpdateCertAndGetCert(t *testing.T) {
	cert := &tls.Certificate{}
	q := newTestQUIC(ListenerConfig{Name: "q", Listen: "127.0.0.1:0", Protocol: ProtocolQUIC, TLS: &gw.TLSConfig{}})
	q.UpdateCert(cert)
	got, err := q.getCert(nil)
	if err != nil {
		t.Fatalf("getCert: %v", err)
	}
	if got != cert {
		t.Fatal("getCert returned wrong certificate")
	}

	q2 := newTestQUIC(ListenerConfig{Name: "q2", Listen: "127.0.0.1:0", Protocol: ProtocolQUIC, TLS: &gw.TLSConfig{}})
	if _, err := q2.getCert(nil); err == nil {
		t.Fatal("expected error when no server certificate stored")
	}
}

func TestQUICBackendTransportShared(t *testing.T) {
	q := newTestQUIC(ListenerConfig{Name: "q", Listen: "127.0.0.1:0", Protocol: ProtocolQUIC, TLS: &gw.TLSConfig{}})
	t1 := q.backendTransportShared()
	t2 := q.backendTransportShared()
	if t1 != t2 {
		t.Fatal("backendTransportShared should return the same transport")
	}
}

func TestQUICProxyH3RequestNotFound(t *testing.T) {
	backend, close := startTestBackend(t)
	defer close()
	hostport := strings.TrimPrefix(backend, "http://")

	q := newTestQUIC(ListenerConfig{
		Name: "h3", Protocol: ProtocolH3, TLS: &gw.TLSConfig{},
		Routes: []RouteConfig{{Path: "/echo", Target: hostport}},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/nope", nil)
	q.handleH3Request(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", rr.Code)
	}
}

func TestQUICProxyH3RequestBackend(t *testing.T) {
	backend, close := startTestBackend(t)
	defer close()
	hostport := strings.TrimPrefix(backend, "http://")

	q := newTestQUIC(ListenerConfig{
		Name: "h3", Protocol: ProtocolH3, TLS: &gw.TLSConfig{},
		Routes: []RouteConfig{{Path: "/echo", Target: hostport}},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/echo", nil)
	q.handleH3Request(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s, want 200", rr.Code, rr.Body.String())
	}
}

// TestQUICProxyH3UpstreamRedirectNotFollowed verifies finding 7: the QUIC/H3
// backend client must never follow an upstream redirect, otherwise a
// compromised backend could steer the gateway into issuing follow-up requests
// to internal addresses (SSRF). The 3xx response must be passed through.
func TestQUICProxyH3UpstreamRedirectNotFollowed(t *testing.T) {
	canaryHit := atomic.Bool{}
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect-me" {
			http.Redirect(w, r, "http://127.0.0.1:9/canary", http.StatusFound)
			return
		}
		canaryHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer redirector.Close()

	q := newTestQUIC(ListenerConfig{
		Name: "h3", Protocol: ProtocolH3, TLS: &gw.TLSConfig{},
		Routes: []RouteConfig{{Path: "/redirect-me", Target: redirector.Listener.Addr().String()}},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/redirect-me", nil)
	q.handleH3Request(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("code = %d, want 302 passed through", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc == "" {
		t.Fatal("Location header not passed through")
	}
	if canaryHit.Load() {
		t.Fatal("gateway followed the upstream redirect (SSRF); 3xx must be returned to the client")
	}
}

// TestQUICProxyH3RequestBodyLimited verifies finding 8: an over-limit request
// body must be rejected rather than streamed through to the backend.
func TestQUICProxyH3RequestBodyLimited(t *testing.T) {
	received := atomic.Int64{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		received.Store(n)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	q := newTestQUIC(ListenerConfig{
		Name: "h3", Protocol: ProtocolH3, TLS: &gw.TLSConfig{},
		Routes: []RouteConfig{{Path: "/upload", Target: backend.Listener.Addr().String()}},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://x/upload", strings.NewReader(strings.Repeat("a", int(h3MaxRequestBodyBytes)+1024)))
	req.Header.Set("Content-Type", "application/octet-stream")
	q.handleH3Request(rr, req)

	if got := received.Load(); got > h3MaxRequestBodyBytes {
		t.Fatalf("backend received %d bytes, want <= %d", got, h3MaxRequestBodyBytes)
	}
	if rr.Code != http.StatusBadGateway && rr.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 or 502", rr.Code)
	}
}

func TestQUICProxyH3RequestMTLSDeny(t *testing.T) {
	backend, close := startTestBackend(t)
	defer close()
	hostport := strings.TrimPrefix(backend, "http://")

	cert, _, _ := makeCert(t, "ops-user", []string{"gateway:ops"}, false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)

	q := newTestQUIC(ListenerConfig{
		Name: "h3", Protocol: ProtocolH3, TLS: &gw.TLSConfig{},
		Routes: []RouteConfig{{Path: "/echo", Target: hostport, AllowRoles: []string{"gateway:admin"}}},
	})
	q.tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/echo", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	q.handleH3Request(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rr.Code)
	}
}

func TestQUICProxyH3RequestMTLSGranted(t *testing.T) {
	backend, close := startTestBackend(t)
	defer close()
	hostport := strings.TrimPrefix(backend, "http://")

	tru := true
	cert, _, _ := makeCert(t, "admin-user", []string{"gateway:admin"}, false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)

	q := newTestQUIC(ListenerConfig{
		Name: "h3", Protocol: ProtocolH3, TLS: &gw.TLSConfig{},
		HTTPExt: &gw.HTTPExtra{
			ForwardClientCert:    &tru,
			TLSTermination:       &tru,
			ForwardClientCertDER: &tru,
		},
		Routes: []RouteConfig{{Path: "/echo", Target: hostport, AllowRoles: []string{"gateway:admin"}}},
	})
	q.tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/echo", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	q.handleH3Request(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s, want 200", rr.Code, rr.Body.String())
	}
}

func TestQUICProxyH3RequestDelegatedAgent(t *testing.T) {
	backend, close := startTestBackend(t)
	defer close()
	hostport := strings.TrimPrefix(backend, "http://")

	tru := true
	cert, _, _ := makeCert(t, "agent-1", []string{"Delegated-Agent"}, false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)

	q := newTestQUIC(ListenerConfig{
		Name: "h3", Protocol: ProtocolH3, TLS: &gw.TLSConfig{},
		HTTPExt: &gw.HTTPExtra{
			ForwardClientCertDER: &tru,
		},
		Routes: []RouteConfig{{Path: "/echo", Target: hostport}},
	})
	q.tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/echo", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	q.handleH3Request(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s, want 200", rr.Code, rr.Body.String())
	}
}
