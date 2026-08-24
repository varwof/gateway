// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package httpgw

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
	pki "github.com/varwof/types"
)

func TestProxyStartAlreadyRunning(t *testing.T) {
	p := newDirectProxy(t, ListenerConfig{
		Name: "p", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
	})
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()
	if err := p.Start(); err == nil {
		t.Fatal("expected error on second Start")
	}
}

func TestProxyStartListenError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	p := newDirectProxy(t, ListenerConfig{
		Name: "p", Listen: ln.Addr().String(), Protocol: ProtocolHTTP2,
	})
	if err := p.Start(); err == nil {
		t.Fatal("expected listen conflict error")
	}
}

func TestProxyStartTLSModeServerNoCert(t *testing.T) {
	p := newDirectProxy(t, ListenerConfig{
		Name: "p", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
		TLS: &gw.TLSConfig{Mode: gw.TLSModeServer},
	})
	if err := p.Start(); err == nil {
		t.Fatal("expected cert_file required error")
	}
}

func TestProxyStartMTLSBadCA(t *testing.T) {
	pki := setupPKI(t)
	p := newDirectProxy(t, ListenerConfig{
		Name: "m", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
		TLS: &gw.TLSConfig{
			Mode:       gw.TLSModeMTLS,
			CertFile:   pki.ServerCertFile,
			KeyFile:    pki.ServerKeyFile,
			CACertFile: "/nonexistent/ca.pem",
		},
	})
	if err := p.Start(); err == nil {
		t.Fatal("expected MTLSServerConfig error for missing CA")
	}
}

func TestProxyStartTLSModeServer(t *testing.T) {
	pki := setupPKI(t)
	p := newDirectProxy(t, ListenerConfig{
		Name: "srv", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
		TLS: &gw.TLSConfig{
			Mode:           gw.TLSModeServer,
			CertFile:       pki.ServerCertFile,
			KeyFile:        pki.ServerKeyFile,
			IdleTimeoutSec: 5,
		},
	})
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()
}

func TestProxyHandleRequestMethodAllowed(t *testing.T) {
	backend, close := startTestBackend(t)
	defer close()
	p := newDirectProxy(t, ListenerConfig{
		Name: "am", Protocol: ProtocolHTTP2,
		Routes: []RouteConfig{{Path: "/api/*", Target: backend, AllowMethods: []string{"GET"}}},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/api/y", nil)
	p.handleRequest(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s, want 200", rr.Code, rr.Body.String())
	}
}

func capabilityCert(t *testing.T) *x509.Certificate {
	t.Helper()
	return makeExtCert(t, "cap-agent", nil, nil, []pkix.Extension{
		{Id: pki.OIDAIC, Value: marshalTestAIC(t)},
	})
}

func TestProxyCapabilitySchemePrefixDefault(t *testing.T) {
	cert := capabilityCert(t)
	p := newDirectProxy(t, ListenerConfig{
		Name: "cap", Protocol: ProtocolHTTP2,
		TLS: &gw.TLSConfig{Mode: gw.TLSModeMTLS},
		Routes: []RouteConfig{{
			Path: "/api/*", Target: "http://127.0.0.1:1",
			CapabilityScheme: "varwof/demo-mysql-v1",
		}},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/api/y", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	p.handleRequest(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403 (default cap prefix)", rr.Code)
	}
}

func TestProxyCapabilitySchemeMethodMapping(t *testing.T) {
	cert := capabilityCert(t)
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		p := newDirectProxy(t, ListenerConfig{
			Name: "cap", Protocol: ProtocolHTTP2,
			TLS: &gw.TLSConfig{Mode: gw.TLSModeMTLS},
			Routes: []RouteConfig{{
				Path: "/api/*", Target: "http://127.0.0.1:1",
				CapabilityScheme: "varwof/demo-mysql-v1", CapabilityPrefix: "varwof/demo-mysql-v1",
			}},
		})
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(m, "http://x/api/y", nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		p.handleRequest(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("method %s: code = %d, want 403", m, rr.Code)
		}
	}
}

func TestProxyHandleRequestDelegatedAgentGSFull(t *testing.T) {
	backend, close := startTestBackend(t)
	defer close()
	tru := true
	cert := makeExtCert(t, "agent-1", []string{"Delegated-Agent"}, []string{"Acme"}, []pkix.Extension{
		{Id: pki.OIDAIC, Value: marshalTestAIC(t)},
		{Id: pki.OIDGatewaySession, Value: marshalTestGS(t, 1)},
	})

	p := newDirectProxy(t, ListenerConfig{
		Name: "gs", Protocol: ProtocolHTTP2,
		TLS: &gw.TLSConfig{
			Mode:            gw.TLSModeMTLS,
			MaxConnsPerCert: 1,
		},
		HTTPExt: &gw.HTTPExtra{
			ForwardClientCert:    &tru,
			TLSTermination:       &tru,
			ForwardClientCertDER: &tru,
		},
		Routes: []RouteConfig{{Path: "/api/*", Target: backend}},
	})

	run := func(cancelCtx bool) {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://x/api/y", nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		req.RemoteAddr = "127.0.0.1:50000"
		if cancelCtx {
			ctx, cancel := context.WithCancel(context.Background())
			req = req.WithContext(ctx)
			p.handleRequest(rr, req)
			cancel()
			time.Sleep(150 * time.Millisecond)
		} else {
			p.handleRequest(rr, req)
			time.Sleep(1300 * time.Millisecond)
		}
		if rr.Code != http.StatusOK {
			t.Fatalf("code = %d, body = %s, want 200", rr.Code, rr.Body.String())
		}
		for _, want := range []string{
			"X-Client-Cert-DER",
			"X-Client-Cert-SPKI-Hash",
			"X-Client-Cert-Serial",
			"X-Client-Cert-Principal",
			"X-Client-Cert-Agent-ID",
			"X-Agent-TTL",
			"X-Forwarded-Client-CN",
			"X-Forwarded-Client-O",
			"X-Forwarded-Client-OU",
			"X-Forwarded-Client-Serial",
			"X-Forwarded-Client-NotAfter",
			"X-AIC-Agent-Id",
			"X-AIC-Principal-Uid",
			"X-AIC-Capabilities",
			"X-AIC-Verified-By",
		} {
			if req.Header.Get(want) == "" {
				t.Errorf("missing header %s", want)
			}
		}
		if req.Header.Get("X-Client-Cert-CN") != "agent-1" {
			t.Errorf("X-Client-Cert-CN = %q, want agent-1", req.Header.Get("X-Client-Cert-CN"))
		}
		if !strings.Contains(req.Header.Get("X-Client-Cert-Principal"), "user@varwof.com") {
			t.Errorf("X-Client-Cert-Principal = %q, want principal uid", req.Header.Get("X-Client-Cert-Principal"))
		}
		if !strings.Contains(req.Header.Get("X-Forwarded-Client-OU"), "Delegated-Agent") {
			t.Errorf("X-Forwarded-Client-OU = %q, want Delegated-Agent", req.Header.Get("X-Forwarded-Client-OU"))
		}
		if !strings.Contains(req.Header.Get("X-AIC-Capabilities"), "gateway:read") {
			t.Errorf("X-AIC-Capabilities = %q, want gateway:read", req.Header.Get("X-AIC-Capabilities"))
		}
		if req.Header.Get("X-GS-Max-Concurrent") != "5" {
			t.Errorf("X-GS-Max-Concurrent = %q, want 5", req.Header.Get("X-GS-Max-Concurrent"))
		}
		if req.Header.Get("X-GS-Hard-Timeout") != "1" {
			t.Errorf("X-GS-Hard-Timeout = %q, want 1", req.Header.Get("X-GS-Hard-Timeout"))
		}
		if !strings.Contains(req.Header.Get("X-AIC-Verified-By"), "1.2.840.10045") {
			t.Errorf("X-AIC-Verified-By = %q, want ECDSA algorithm OID", req.Header.Get("X-AIC-Verified-By"))
		}
	}

	run(true)
	run(false)
}

func TestMatchRouteNormalizationEdgeCases(t *testing.T) {
	backend := "http://127.0.0.1:1"
	p := newDirectProxy(t, ListenerConfig{
		Name: "mr", Protocol: ProtocolHTTP2,
		Routes: []RouteConfig{
			{Path: "/x/y/*", Target: backend},
			{Path: "/x/*", Target: backend},
		},
	})

	if r, _ := p.matchRoute("/x/y/../../z/"); r == nil {
		t.Fatal("expected match via normalized trailing-slash path")
	}
	if r, _ := p.matchRoute("/x..y/"); r != nil {
		t.Fatal("unexpected match for non-boundary path")
	}
	if r, _ := p.matchRoute("//"); r != nil {
		t.Fatal("unexpected match for root-normalized path")
	}
}

func TestServeWebSocketWithClientCert(t *testing.T) {
	cert, _, _ := makeCert(t, "ws-agent", nil, false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	p := newDirectProxy(t, ListenerConfig{Name: "ws", Protocol: ProtocolHTTP2, TLS: &gw.TLSConfig{Mode: gw.TLSModeMTLS}})
	route := &Route{
		Path:   "/ws/*",
		Target: &url.URL{Scheme: "http", Host: "127.0.0.1:1"},
		handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/ws/x", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	p.serveWebSocket(rr, req, route, cert, "/ws/x")
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rr.Code)
	}
}

// TestServeWebSocketNoUpgradeNoAudit W30: when no hijack occurs (upgrade fails /
// backend rejects), ws_connect/ws_close audit must not be recorded, and WS metrics
// must not be accumulated.
func TestServeWebSocketNoUpgradeNoAudit(t *testing.T) {
	audit, entries := newTestAudit(t)
	defer audit.Close()

	cert, _, _ := makeCert(t, "ws-agent", nil, false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	p := newDirectProxy(t, ListenerConfig{Name: "ws", Protocol: ProtocolHTTP2, TLS: &gw.TLSConfig{Mode: gw.TLSModeMTLS}})
	p.audit = audit
	route := &Route{
		Path:   "/ws/*",
		Target: &url.URL{Scheme: "http", Host: "127.0.0.1:1"},
		handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// No hijack — simulate upgrade failure (backend rejection).
			http.Error(w, "upgrade rejected", http.StatusBadGateway)
		}),
	}
	before := WSConnectionsTotal.Count("ws")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/ws/x", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	p.serveWebSocket(rr, req, route, cert, "/ws/x")

	for _, e := range entries() {
		if e.Action == string(gw.ActionWSConnect) || e.Action == string(gw.ActionWSClose) {
			t.Fatalf("ws audit recorded without upgrade: %+v", e)
		}
	}
	if after := WSConnectionsTotal.Count("ws"); after != before {
		t.Fatalf("WSConnectionsTotal changed without upgrade: %d → %d", before, after)
	}
}

// TestWSHijackRecorderFiresOnce W30: wsHijackRecorder fires onHijack once
// when hijack truly succeeds (connected dedup), and passes through the error
// when the underlying writer does not support hijack.
func TestWSHijackRecorderFiresOnce(t *testing.T) {
	// Underlying writer that supports Hijack.
	c := &fakeHijacker{}
	calls := 0
	tw := &wsHijackRecorder{ResponseWriter: c, onHijack: func() { calls++ }}

	if _, _, err := tw.Hijack(); err != nil {
		t.Fatalf("hijack: %v", err)
	}
	if calls != 1 || !tw.connected {
		t.Fatalf("after first hijack: calls=%d connected=%v", calls, tw.connected)
	}
	// Second hijack no longer fires (dedup).
	if _, _, err := tw.Hijack(); err != nil {
		t.Fatalf("second hijack: %v", err)
	}
	if calls != 1 {
		t.Fatalf("onHijack fired %d times, want 1", calls)
	}

	// Underlying writer does not support hijack → error passed through, connected stays false.
	tw2 := &wsHijackRecorder{ResponseWriter: httptest.NewRecorder()}
	if _, _, err := tw2.Hijack(); err == nil {
		t.Fatal("expected error for non-hijackable writer")
	}
	if tw2.connected {
		t.Fatal("connected must stay false when hijack fails")
	}
}

// fakeHijacker implements http.Hijacker + http.ResponseWriter (for testing wsHijackRecorder only).
type fakeHijacker struct{}

func (f *fakeHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, nil
}
func (f *fakeHijacker) Header() http.Header         { return http.Header{} }
func (f *fakeHijacker) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeHijacker) WriteHeader(int)             {}
