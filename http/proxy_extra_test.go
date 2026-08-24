package httpgw

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	gw "github.com/varwof/gateway-core"
)

func TestProxyListenerAccessors(t *testing.T) {
	cfg := ListenerConfig{
		Name: "acc", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
		Routes: []RouteConfig{{Path: "/", Target: "http://127.0.0.1:1"}},
	}
	audit, _ := gw.NewAuditLogger("", nil, 0, 0)
	p, err := NewProxyListener(cfg, nil, nil, audit, nil, make(chan struct{}), NewBundle(), "en", nil, nil)
	if err != nil {
		t.Fatalf("NewProxyListener: %v", err)
	}
	if p.State() != ProxyStopped {
		t.Fatalf("initial State = %v", p.State())
	}
	if p.Name() != "acc" {
		t.Fatalf("Name = %q", p.Name())
	}
	if p.Conns() != 0 {
		t.Fatalf("Conns = %d", p.Conns())
	}
	if p.Config().Name != "acc" {
		t.Fatalf("Config = %+v", p.Config())
	}
	if p.Addr() != nil {
		t.Fatalf("Addr before Start = %v", p.Addr())
	}

	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if p.State() != ProxyRunning {
		t.Fatalf("State after Start = %v", p.State())
	}
	if p.Addr() == nil {
		t.Fatal("Addr nil after Start")
	}
	p.UpdateCert(&tls.Certificate{})

	if err := p.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if p.State() != ProxyStopped {
		t.Fatalf("State after Stop = %v", p.State())
	}
	if err := p.Stop(); err != nil {
		t.Fatalf("second Stop should be idempotent: %v", err)
	}
}

func TestNewProxyListenerErrors(t *testing.T) {
	_, err := NewProxyListener(ListenerConfig{
		Name: "bad", Routes: []RouteConfig{{Target: "%zz"}},
	}, nil, nil, nil, nil, nil, NewBundle(), "en", nil, nil)
	if err == nil {
		t.Fatal("expected target parse error")
	}
}

func TestProxyStartErrors(t *testing.T) {
	t.Run("listen failure", func(t *testing.T) {
		audit, _ := gw.NewAuditLogger("", nil, 0, 0)
		p, err := NewProxyListener(ListenerConfig{
			Name: "x", Listen: "999.999.1.1:0", Protocol: ProtocolHTTP2,
			Routes: []RouteConfig{{Path: "/", Target: "http://127.0.0.1:1"}},
		}, nil, nil, audit, nil, nil, NewBundle(), "en", nil, nil)
		if err != nil {
			t.Fatalf("NewProxyListener: %v", err)
		}
		if err := p.Start(); err == nil {
			t.Fatal("expected listen error")
		}
	})

	t.Run("tls without cert", func(t *testing.T) {
		audit, _ := gw.NewAuditLogger("", nil, 0, 0)
		p, err := NewProxyListener(ListenerConfig{
			Name: "x", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
			TLS:    &gw.TLSConfig{Mode: gw.TLSModeServer},
			Routes: []RouteConfig{{Path: "/", Target: "http://127.0.0.1:1"}},
		}, nil, nil, audit, nil, nil, NewBundle(), "en", nil, nil)
		if err != nil {
			t.Fatalf("NewProxyListener: %v", err)
		}
		if err := p.Start(); err == nil {
			t.Fatal("expected cert_file required error")
		}
	})

	t.Run("mtls bad cert", func(t *testing.T) {
		audit, _ := gw.NewAuditLogger("", nil, 0, 0)
		p, err := NewProxyListener(ListenerConfig{
			Name: "x", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
			TLS:    &gw.TLSConfig{Mode: gw.TLSModeMTLS, CertFile: "/nonexistent/c.pem", KeyFile: "/nonexistent/k.pem"},
			Routes: []RouteConfig{{Path: "/", Target: "http://127.0.0.1:1"}},
		}, nil, nil, audit, nil, nil, NewBundle(), "en", nil, nil)
		if err != nil {
			t.Fatalf("NewProxyListener: %v", err)
		}
		if err := p.Start(); err == nil {
			t.Fatal("expected cert load error")
		}
	})
}

func TestProxyHandleTimestamp(t *testing.T) {
	p := &ProxyListener{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_timestamp", nil)
	p.handleTimestamp(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET code = %d, want 200", rr.Code)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["timestamp"] == nil || m["iso8601"] == nil {
		t.Fatalf("timestamp body = %v", m)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/_timestamp", nil)
	p.handleTimestamp(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST code = %d, want 405", rr.Code)
	}
}

func TestCertSpkiHashHex(t *testing.T) {
	cert, _, _ := makeCert(t, "spki", nil, false, nil, nil, nil)
	h := certSpkiHashHex(cert)
	if len(h) != 64 {
		t.Fatalf("certSpkiHashHex length = %d, want 64", len(h))
	}
}

func TestProxyGetCertNoCert(t *testing.T) {
	audit, _ := gw.NewAuditLogger("", nil, 0, 0)
	p, err := NewProxyListener(ListenerConfig{
		Name: "c", Routes: []RouteConfig{{Path: "/", Target: "http://127.0.0.1:1"}},
	}, nil, nil, audit, nil, nil, NewBundle(), "en", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.getCert(nil); err == nil {
		t.Fatal("expected error when no server certificate stored")
	}
}
