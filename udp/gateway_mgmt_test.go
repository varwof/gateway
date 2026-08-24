package udpgw

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

func TestLoadAuthorizationPolicyPaths(t *testing.T) {
	t.Run("no file configured", func(t *testing.T) {
		g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
		g.loadAuthorizationPolicy()
	})

	t.Run("nonexistent file warns and returns", func(t *testing.T) {
		g := NewGateway(&Config{AuthorizationFile: "/nonexistent/authz.json"}, NewBundle(), "en", nil, nil, nil, nil)
		g.loadAuthorizationPolicy()
	})

	t.Run("listener fallback CA used", func(t *testing.T) {
		dir := t.TempDir()
		pki := setupPKI(t)
		authz := filepath.Join(dir, "authz.json")
		if err := os.WriteFile(authz, []byte(`{"version":1}`), 0644); err != nil {
			t.Fatal(err)
		}
		g := NewGateway(&Config{
			AuthorizationFile: authz,
			Listeners: []ListenerConfig{{
				Name:     "l",
				Listen:   ":1",
				Protocol: ProtocolMTLS,
				TLS:      &gw.TLSConfig{CACertFile: pki.CACertFile},
			}},
		}, NewBundle(), "en", nil, nil, nil, nil)
		g.loadAuthorizationPolicy()
	})
}

func TestGatewayUpdateServerCert(t *testing.T) {
	pki := setupPKI(t)
	q := &QUICProxy{}
	g := &Gateway{listeners: map[string]Listener{"quic": q}}
	cert, err := tls.LoadX509KeyPair(pki.ServerCertFile, pki.ServerKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	g.UpdateServerCert(&cert)
	got, err := q.getCert(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got.Certificate) == 0 {
		t.Fatal("certificate was not updated")
	}
}

func TestGatewayReload(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "reload.json")
	writeListeners(t, cfgPath, "l1")

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	defer g.Stop()

	oldL1 := g.listeners["l1"]
	if oldL1 == nil {
		t.Fatal("l1 not started")
	}

	// Reload with l1 unchanged and a new l2 added.
	writeListeners(t, cfgPath, "l1", "l2")

	if err := g.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := g.listeners["l1"]; got != oldL1 {
		t.Error("unchanged listener l1 should be kept as the same instance")
	}
	if g.listeners["l2"] == nil {
		t.Error("new listener l2 should exist after reload")
	}

	// Reload removing l2.
	writeListeners(t, cfgPath, "l1")
	if err := g.Reload(); err != nil {
		t.Fatalf("Reload(remove): %v", err)
	}
	if g.listeners["l2"] != nil {
		t.Error("removed listener l2 should be gone after reload")
	}
}

func writeListeners(t *testing.T, path string, names ...string) {
	t.Helper()
	var listeners []map[string]interface{}
	for _, name := range names {
		listeners = append(listeners, map[string]interface{}{
			"name": name, "listen": "127.0.0.1:0", "protocol": ProtocolUDP,
		})
	}
	data, _ := json.Marshal(map[string]interface{}{"listeners": listeners})
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayReloadUnchangedListenerStillServes(t *testing.T) {
	// Regression: Reload must not kill an unchanged plain UDP listener
	// (serve loop used to be stopCh-coupled and g.stopCh is closed on reload).
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "reload.json")

	// Echo backend
	echoConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer echoConn.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := echoConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echoConn.WriteTo(buf[:n], addr)
		}
	}()

	writeListeners(t, cfgPath, "l1")
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Listeners[0].Routes = []RouteConfig{{Target: echoConn.LocalAddr().String()}}
	cfg.Save()

	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	defer g.Stop()

	ln := g.listeners["l1"].(*UDPProxy)
	gwAddr := ln.conn.LocalAddr().String()

	// Round trip before reload
	if !udpEcho(t, gwAddr, "before reload") {
		t.Fatal("echo failed before reload")
	}

	writeListeners(t, cfgPath, "l1")
	cfg2, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg2.Listeners[0].Routes = []RouteConfig{{Target: echoConn.LocalAddr().String()}}
	cfg2.Save()

	if err := g.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if !udpEcho(t, gwAddr, "after reload") {
		t.Error("echo failed after reload — unchanged listener was killed")
	}
}

func TestGatewayReloadLoadError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "reload.json")
	writeListeners(t, cfgPath, "l1")
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	os.WriteFile(cfgPath, []byte("{invalid"), 0644)
	if err := g.Reload(); err == nil {
		t.Fatal("expected error for invalid reload config")
	}
}

func TestGatewayReloadWithoutConfigPath(t *testing.T) {
	cfg := &Config{
		configPath: "",
		Listeners: []ListenerConfig{{
			Name: "l1", Listen: "127.0.0.1:0", Protocol: ProtocolUDP,
		}},
	}
	// The Save() fallback writes to /tmp; make sure Reload round-trips it.
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	defer g.Stop()
	if err := g.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if len(g.listeners) != 1 {
		t.Errorf("expected 1 listener, got %d", len(g.listeners))
	}
	os.Remove("/tmp/gateway-udp-" + pidStr() + ".json")
}

func TestHandleManagementHandlers(t *testing.T) {
	t.Run("list listeners", func(t *testing.T) {
		g := &Gateway{listeners: map[string]Listener{
			"l1": &UDPProxy{cfg: ListenerConfig{Name: "l1", Listen: ":1", Protocol: ProtocolUDP}},
		}}
		rec := httptest.NewRecorder()
		g.handleListListeners(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		var body []map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body) != 1 || body[0]["name"] != "l1" || body[0]["tls_mode"] != "plain" {
			t.Errorf("unexpected body: %s", rec.Body.String())
		}
	})

	t.Run("add listener bad json", func(t *testing.T) {
		g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
		rec := httptest.NewRecorder()
		g.handleAddListener(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("add listener conflict", func(t *testing.T) {
		g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
		g.listeners["dup"] = &UDPProxy{cfg: ListenerConfig{Name: "dup"}}
		rec := httptest.NewRecorder()
		body, _ := json.Marshal(ListenerConfig{Name: "dup", Listen: ":1", Protocol: ProtocolUDP})
		g.handleAddListener(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body))))
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409", rec.Code)
		}
	})

	t.Run("add listener success", func(t *testing.T) {
		g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
		rec := httptest.NewRecorder()
		body, _ := json.Marshal(ListenerConfig{Name: "new", Listen: "127.0.0.1:0", Protocol: ProtocolUDP})
		g.handleAddListener(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body))))
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body %s", rec.Code, rec.Body.String())
		}
		if _, ok := g.listeners["new"]; !ok {
			t.Error("listener not added")
		}
		g.Stop()
	})

	t.Run("add listener start error", func(t *testing.T) {
		g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
		rec := httptest.NewRecorder()
		// Invalid listen address triggers a start error.
		body, _ := json.Marshal(ListenerConfig{Name: "bad", Listen: "not-an-addr", Protocol: ProtocolUDP})
		g.handleAddListener(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body))))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500, body %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("remove listener not found", func(t *testing.T) {
		g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
		rec := httptest.NewRecorder()
		g.handleRemoveListener(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/gateway/listeners/nope", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("remove listener success", func(t *testing.T) {
		g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
		g.listeners["gone"] = &UDPProxy{cfg: ListenerConfig{Name: "gone"}}
		rec := httptest.NewRecorder()
		g.handleRemoveListener(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/gateway/listeners/gone", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if _, ok := g.listeners["gone"]; ok {
			t.Error("listener not removed")
		}
	})

	t.Run("crl reload empty", func(t *testing.T) {
		g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
		rec := httptest.NewRecorder()
		g.handleCRLReload(rec, httptest.NewRequest(http.MethodPost, "/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"reloaded":0`) {
			t.Errorf("body = %s", rec.Body.String())
		}
	})
}

func TestWriteJSONHelpers(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusCreated, map[string]string{"ok": "1"})
	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}

	rec = httptest.NewRecorder()
	writeAPIError(rec, http.StatusForbidden, "denied")
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"error":"denied"`) {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestStartManagementErrors(t *testing.T) {
	pki := setupPKI(t)
	t.Run("missing cert file", func(t *testing.T) {
		g := NewGateway(&Config{
			Management: &ManagementConfig{
				Listen: "127.0.0.1:0",
				TLS:    &gw.TLSConfig{CACertFile: pki.CACertFile},
			},
		}, NewBundle(), "en", nil, nil, nil, nil)
		if _, err := g.startManagement(); err == nil {
			t.Fatal("expected error for missing cert")
		}
	})

	t.Run("bad CA file", func(t *testing.T) {
		dir := t.TempDir()
		badCA := filepath.Join(dir, "bad.pem")
		os.WriteFile(badCA, []byte("not a pem"), 0644)
		g := NewGateway(&Config{
			Management: &ManagementConfig{
				Listen: "127.0.0.1:0",
				TLS: &gw.TLSConfig{
					CACertFile: badCA,
					CertFile:   pki.ServerCertFile,
					KeyFile:    pki.ServerKeyFile,
				},
			},
		}, NewBundle(), "en", nil, nil, nil, nil)
		if _, err := g.startManagement(); err == nil {
			t.Fatal("expected error for bad CA")
		}
	})
}

func TestStartManagementWiring(t *testing.T) {
	pki := setupPKI(t)
	g := NewGateway(&Config{
		Management: &ManagementConfig{
			Listen: "127.0.0.1:0",
			TLS: &gw.TLSConfig{
				CACertFile: pki.CACertFile,
				CertFile:   pki.ServerCertFile,
				KeyFile:    pki.ServerKeyFile,
			},
		},
	}, NewBundle(), "en", nil, nil, nil, nil)
	ms, err := g.startManagement()
	if err != nil {
		t.Fatalf("startManagement: %v", err)
	}
	if ms == nil {
		t.Fatal("management server is nil")
	}
	g.Stop()
}

// --- helpers ---

func udpEcho(t *testing.T, addr, msg string) bool {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, mustUDPAddr(t, addr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply := make([]byte, 1500)
	n, _, err := conn.ReadFromUDP(reply)
	if err != nil {
		return false
	}
	return string(reply[:n]) == msg
}

func mustUDPAddr(t *testing.T, addr string) *net.UDPAddr {
	t.Helper()
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("resolve %q: %v", addr, err)
	}
	return ua
}

func pidStr() string {
	return strconv.Itoa(os.Getpid())
}
