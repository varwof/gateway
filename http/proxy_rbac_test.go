// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package httpgw

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

func newDirectProxy(t *testing.T, cfg ListenerConfig) *ProxyListener {
	t.Helper()
	audit, _ := gw.NewAuditLogger("", nil, 0, 0)
	p, err := NewProxyListener(cfg, nil, nil, audit, nil, make(chan struct{}), NewBundle(), "en", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func startSlowBackend(t *testing.T) (string, func()) {
	t.Helper()
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(300 * time.Millisecond)
			w.Write([]byte("ok\n"))
		}),
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(lis)
	return "http://" + lis.Addr().String(), func() { srv.Close() }
}

func TestProxyHandleRequestMTLSRequired(t *testing.T) {
	p := newDirectProxy(t, ListenerConfig{
		Name: "m", Protocol: ProtocolHTTP2,
		TLS:    &gw.TLSConfig{Mode: gw.TLSModeMTLS},
		Routes: []RouteConfig{{Path: "/api/*", Target: "http://127.0.0.1:1"}},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/api/y", nil)
	p.handleRequest(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rr.Code)
	}
}

func TestProxyHandleRequestNoRoute(t *testing.T) {
	p := newDirectProxy(t, ListenerConfig{
		Name: "n", Protocol: ProtocolHTTP2,
		Routes: []RouteConfig{{Path: "/only/*", Target: "http://127.0.0.1:1"}},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/other", nil)
	p.handleRequest(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", rr.Code)
	}
}

func TestProxyHandleRequestMethodNotAllowed(t *testing.T) {
	p := newDirectProxy(t, ListenerConfig{
		Name: "mm", Protocol: ProtocolHTTP2,
		Routes: []RouteConfig{{Path: "/api/*", Target: "http://127.0.0.1:1", AllowMethods: []string{"GET"}}},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://x/api/y", nil)
	p.handleRequest(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code = %d, want 405", rr.Code)
	}
}

func TestProxyHandleRequestPipelineDeny(t *testing.T) {
	tru := true
	cert, _, _ := makeCert(t, "plain-agent", nil, false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)

	p := newDirectProxy(t, ListenerConfig{
		Name: "pd", Protocol: ProtocolHTTP2,
		TLS: &gw.TLSConfig{Mode: gw.TLSModeMTLS, RequireAIC: &tru},
		Routes: []RouteConfig{{
			Path: "/api/*", Target: "http://127.0.0.1:1",
			CapabilityScheme: "varwof/demo-mysql-v1", CapabilityPrefix: "varwof/demo-mysql-v1",
		}},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/api/y", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	p.handleRequest(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rr.Code)
	}
}

func TestProxyHandleRequestDelegatedAgent(t *testing.T) {
	backend, close := startTestBackend(t)
	defer close()
	tru := true
	cert, _, _ := makeCert(t, "agent-1", []string{"Delegated-Agent"}, false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)

	p := newDirectProxy(t, ListenerConfig{
		Name: "da", Protocol: ProtocolHTTP2,
		TLS:     &gw.TLSConfig{Mode: gw.TLSModeMTLS},
		HTTPExt: &gw.HTTPExtra{ForwardClientCertDER: &tru},
		Routes:  []RouteConfig{{Path: "/api/*", Target: backend}},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/api/y", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	p.handleRequest(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s, want 200", rr.Code, rr.Body.String())
	}
	if req.Header.Get("X-Client-Cert-DER") == "" {
		t.Fatal("expected X-Client-Cert-DER header injection")
	}
	if req.Header.Get("X-Client-Cert-SPKI-Hash") == "" {
		t.Fatal("expected X-Client-Cert-SPKI-Hash header injection")
	}
}

func TestProxyHandleRequestMaxTotalConns(t *testing.T) {
	backend, closeBackend := startSlowBackend(t)
	defer closeBackend()

	// Finding 10: max_total_conns must count live connections, not requests.
	// Under keep-alive a single connection issuing many requests must not
	// bypass the cap, so the limit is enforced on ConnState (connection) level.
	// Use the real HTTP server path (Start) to trigger ConnState New/Closed.
	p := newDirectProxy(t, ListenerConfig{
		Name: "total", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
		TLS:    &gw.TLSConfig{MaxTotalConns: 1},
		Routes: []RouteConfig{{Path: "/api/*", Target: backend}},
	})
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	addr := p.listener.Addr().String()
	statuses := make([]int, 2)
	startCh := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-startCh
			// Each goroutine uses an independent Transport to force a new TCP connection.
			tr := &http.Transport{DisableKeepAlives: true}
			defer tr.CloseIdleConnections()
			resp, err := tr.RoundTrip(httptest.NewRequest("GET", "http://"+addr+fmt.Sprintf("/api/r%d", i), nil))
			if err != nil {
				statuses[i] = http.StatusServiceUnavailable
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
			statuses[i] = resp.StatusCode
		}(i)
	}
	close(startCh)
	wg.Wait()

	has503 := false
	for _, s := range statuses {
		if s == http.StatusServiceUnavailable {
			has503 = true
		}
	}
	if !has503 {
		t.Fatalf("statuses = %v, want at least one 503 (total connection limit)", statuses)
	}
}

// TestProxyKeepAliveSingleConnNotLimited verifies finding 10: a single
// connection issuing multiple sequential requests must NOT be throttled by
// max_total_conns (it counts connections, not requests).
func TestProxyKeepAliveSingleConnNotLimited(t *testing.T) {
	backend, closeBackend := startSlowBackend(t)
	defer closeBackend()

	p := newDirectProxy(t, ListenerConfig{
		Name: "total-keepalive", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
		TLS:    &gw.TLSConfig{MaxTotalConns: 1},
		Routes: []RouteConfig{{Path: "/api/*", Target: backend}},
	})
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	addr := p.listener.Addr().String()
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	for i := 0; i < 5; i++ {
		resp, err := tr.RoundTrip(httptest.NewRequest("GET", "http://"+addr+fmt.Sprintf("/api/k%d", i), nil))
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusServiceUnavailable {
			t.Fatalf("request %d: got 503 on a single keep-alive connection; max_total_conns must count connections, not requests", i)
		}
	}
}

func TestProxyHandleRequestMaxConnsPerIP(t *testing.T) {
	backend, closeBackend := startSlowBackend(t)
	defer closeBackend()

	// W21: per-IP limit counts by underlying TCP connections (ConnState New/Closed),
	// not by requests. Must use real HTTP server path (Start) to trigger ConnState;
	// direct handleRequest calls don't produce underlying connections.
	// Two concurrent real connections (different keep-alive) should have one get 429.
	p := newDirectProxy(t, ListenerConfig{
		Name: "ip", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
		TLS:    &gw.TLSConfig{MaxConnsPerIP: 1},
		Routes: []RouteConfig{{Path: "/api/*", Target: backend}},
	})
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	addr := p.listener.Addr().String()
	statuses := make([]int, 2)
	startCh := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-startCh
			// Each goroutine uses an independent Transport to force a new TCP connection.
			tr := &http.Transport{DisableKeepAlives: true}
			defer tr.CloseIdleConnections()
			resp, err := tr.RoundTrip(httptest.NewRequest("GET", "http://"+addr+fmt.Sprintf("/api/r%d", i), nil))
			if err != nil {
				statuses[i] = http.StatusServiceUnavailable
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
			statuses[i] = resp.StatusCode
		}(i)
	}
	close(startCh)
	wg.Wait()

	has429 := false
	for _, s := range statuses {
		if s == http.StatusTooManyRequests {
			has429 = true
		}
	}
	if !has429 {
		t.Fatalf("statuses = %v, want at least one 429 (per-IP connection limit)", statuses)
	}
}

func TestProxyHandleRequestMaxConnsPerCert(t *testing.T) {
	pki := setupPKI(t)
	backend, close := startSlowBackend(t)
	defer close()

	p := newDirectProxy(t, ListenerConfig{
		Name: "cert", Protocol: ProtocolHTTP2,
		TLS:    &gw.TLSConfig{Mode: gw.TLSModeMTLS, MaxConnsPerCert: 1},
		Routes: []RouteConfig{{Path: "/api/*", Target: backend, AllowRoles: []string{"gateway:admin"}}},
	})
	if revoker, err := gw.NewRevoker(gw.RevokerConfig{
		CoreURL: "https://core.test:4433/api/v1", MTLSCertFile: pki.AdminCertFile, MTLSKeyFile: pki.AdminKeyFile,
	}); err == nil {
		p.revoker = revoker
	}

	statuses := concurrentRequests(t, p, true, "/api/")
	has429 := false
	for _, s := range statuses {
		if s == http.StatusTooManyRequests {
			has429 = true
		}
	}
	if !has429 {
		t.Fatalf("statuses = %v, want at least one 429", statuses)
	}
}

func concurrentRequests(t *testing.T, p *ProxyListener, mtls bool, pathPrefix string) []int {
	t.Helper()
	const n = 2
	statuses := make([]int, n)
	cert, _, _ := makeCert(t, "c-"+strconv.Itoa(int(time.Now().UnixNano())), []string{"gateway:admin"}, false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			rr := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "http://x"+pathPrefix+strconv.Itoa(i), nil)
			if mtls {
				req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
			}
			p.handleRequest(rr, req)
			statuses[i] = rr.Code
		}(i)
	}
	close(start)
	wg.Wait()
	return statuses
}
