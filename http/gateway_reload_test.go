// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package httpgw

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gw "github.com/varwof/gateway-core"
)

func writeConfigFile(t *testing.T, path, listen string) {
	t.Helper()
	backend, close := startTestBackend(t)
	t.Cleanup(close)
	data := fmt.Sprintf(`{"listeners":[{"name":"g1","listen":"%s","protocol":"http2","routes":[{"path":"/*","target":"%s"}]}]}`, listen, backend)
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayReloadReuseAndReplace(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gw.json")
	writeConfigFile(t, cfgPath, "127.0.0.1:0")

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	defer g.Stop()

	old := g.listeners["g1"]

	if err := g.Reload(); err != nil {
		t.Fatalf("reload unchanged: %v", err)
	}
	if g.listeners["g1"] != old {
		t.Fatal("unchanged listener was not reused")
	}

	writeConfigFile(t, cfgPath, "127.0.0.2:0")
	if err := g.Reload(); err != nil {
		t.Fatalf("reload changed: %v", err)
	}
	if g.listeners["g1"] == old {
		t.Fatal("changed listener was not replaced")
	}
}

func TestGatewayReloadConfigPathEmpty(t *testing.T) {
	backend, close := startTestBackend(t)
	defer close()
	g := NewGateway(&Config{
		Listeners: []ListenerConfig{{
			Name: "g1", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
			Routes: []RouteConfig{{Path: "/*", Target: backend}},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	g.cfg.configPath = ""

	if err := g.Reload(); err != nil {
		t.Fatalf("reload with empty configPath: %v", err)
	}
	if _, ok := g.listeners["g1"]; !ok {
		t.Fatal("listener g1 missing after reload")
	}
	os.Remove(g.cfg.configPath)
}

func TestGatewayReloadLoadError(t *testing.T) {
	g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
	g.cfg.configPath = filepath.Join(t.TempDir(), "missing.json")
	if err := g.Reload(); err == nil {
		t.Fatal("expected load config error")
	}
}

func TestGatewayReloadNewListenerError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gw.json")
	writeConfigFile(t, cfgPath, "127.0.0.1:0")
	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte(`{"listeners":[{"name":"b","listen":"127.0.0.1:0","protocol":"http2","routes":[{"path":"/*","target":"%zz"}]}]}`), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	g.cfg.configPath = badPath
	if err := g.Reload(); err == nil {
		t.Fatal("expected create listener error")
	}
}

func TestGatewayReloadStartError(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte(`{"listeners":[{"name":"b","listen":"127.0.0.1:0","protocol":"http2","tls":{"mode":"server"},"routes":[{"path":"/*","target":"http://127.0.0.1:1"}]}]}`), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(badPath)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	g.cfg.configPath = badPath
	if err := g.Reload(); err == nil || !strings.Contains(err.Error(), "start listener") {
		t.Fatalf("expected start listener error, got %v", err)
	}
}

func TestGatewayReloadCRLLoadError(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte(`{"listeners":[{"name":"b","listen":"127.0.0.1:0","protocol":"http2","tls":{"crl_url":"http://127.0.0.1:1/crl.pem","ca_cert_file":"/nonexistent/ca.pem"},"routes":[{"path":"/*","target":"http://127.0.0.1:1"}]}]}`), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(badPath)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	g.cfg.configPath = badPath
	if err := g.Reload(); err == nil || !strings.Contains(err.Error(), "load CA cert") {
		t.Fatalf("expected load CA cert error, got %v", err)
	}
}

func TestGatewayReloadPlugins(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gw.json")
	writeConfigFile(t, cfgPath, "127.0.0.1:0")

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)

	pluginsPath := filepath.Join(dir, "plugins.json")
	data := fmt.Sprintf(`{
		"capability_plugins": {
			"tcp": {"type":"allowlist","config":{"allow":["tunnel:prod"],"default_action":"deny"}}
		},
		"listeners": [{"name":"g1","listen":"127.0.0.1:0","protocol":"http2","routes":[{"path":"/*","target":"http://127.0.0.1:1"}]}]
	}`)
	if err := os.WriteFile(pluginsPath, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	g.cfg.configPath = pluginsPath
	if err := g.Reload(); err != nil {
		t.Fatalf("reload with plugins: %v", err)
	}
	if g.pluginRegistry == nil || g.pluginRegistry.Len() != 1 {
		t.Fatalf("pluginRegistry = %+v, want 1 plugin", g.pluginRegistry)
	}

	badPluginsPath := filepath.Join(dir, "badplugins.json")
	if err := os.WriteFile(badPluginsPath, []byte(`{"capability_plugins":{"x":{"type":"nope"}},"listeners":[]}`), 0644); err != nil {
		t.Fatal(err)
	}
	g.cfg.configPath = badPluginsPath
	if err := g.Reload(); err != nil {
		t.Fatalf("reload with bad plugins: %v", err)
	}
	if g.pluginRegistry == nil {
		t.Fatal("pluginRegistry should not be nil after bad plugin build")
	}
}

func TestGatewayReloadSaveWarn(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gw.json")
	writeConfigFile(t, cfgPath, "127.0.0.1:0")

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	if err := os.Chmod(cfgPath, 0400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(cfgPath, 0644) })

	if err := g.Reload(); err != nil {
		t.Fatalf("reload with save warn: %v", err)
	}
}

func TestGatewayNewListener(t *testing.T) {
	pki := setupPKI(t)
	g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)

	tests := []struct {
		name    string
		cfg     ListenerConfig
		wantErr bool
	}{
		{name: "plain", cfg: ListenerConfig{Name: "p", Listen: ":0", Protocol: ProtocolHTTP2}},
		{name: "server", cfg: ListenerConfig{Name: "s", Listen: ":0", Protocol: ProtocolHTTP2, TLS: &gw.TLSConfig{Mode: gw.TLSModeServer, CertFile: pki.ServerCertFile, KeyFile: pki.ServerKeyFile}}},
		{name: "mtls", cfg: ListenerConfig{Name: "m", Listen: ":0", Protocol: ProtocolHTTP2, TLS: &gw.TLSConfig{Mode: gw.TLSModeMTLS, CertFile: pki.ServerCertFile, KeyFile: pki.ServerKeyFile, CACertFile: pki.CACertFile}}},
		{name: "quic", cfg: ListenerConfig{Name: "q", Listen: "127.0.0.1:0", Protocol: ProtocolQUIC, TLS: &gw.TLSConfig{CertFile: pki.ServerCertFile, KeyFile: pki.ServerKeyFile}}},
		{name: "bad", cfg: ListenerConfig{Name: "b", Listen: ":0", Protocol: "bogus"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := g.newListener(tt.cfg, nil, nil, nil)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("newListener: %v", err)
			}
			if l == nil {
				t.Fatal("nil listener")
			}
			if l.Name() != tt.cfg.Name {
				t.Fatalf("name = %q, want %q", l.Name(), tt.cfg.Name)
			}
		})
	}
}

func TestHandleAddListenerCAError(t *testing.T) {
	g, _ := newTestGateway(t)
	body := `{"name":"ca","listen":"127.0.0.1:0","protocol":"http2","tls":{"crl_url":"http://127.0.0.1:1/crl.pem","ca_cert_file":"/nonexistent/ca.pem"},"routes":[{"path":"/*","target":"http://127.0.0.1:1"}]}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/listeners", strings.NewReader(body))
	g.handleAddListener(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, body = %s, want 500", rr.Code, rr.Body.String())
	}
}

func TestHandleAddListenerNewListenerError(t *testing.T) {
	g, _ := newTestGateway(t)
	body := `{"name":"bad","listen":"127.0.0.1:0","protocol":"http2","routes":[{"path":"/*","target":"%zz"}]}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/listeners", strings.NewReader(body))
	g.handleAddListener(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, body = %s, want 500", rr.Code, rr.Body.String())
	}
}

func TestHandleAddListenerStartError(t *testing.T) {
	g, _ := newTestGateway(t)
	body := `{"name":"srv","listen":"127.0.0.1:0","protocol":"http2","tls":{"mode":"server"},"routes":[{"path":"/*","target":"http://127.0.0.1:1"}]}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/listeners", strings.NewReader(body))
	g.handleAddListener(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, body = %s, want 500", rr.Code, rr.Body.String())
	}
}

// TestGatewayReloadAtomicOnConstructError W26: Reload must be atomic on construct failure -
// old listener is unaffected (still running), g.cfg retains old value.
func TestGatewayReloadAtomicOnConstructError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gw.json")
	writeConfigFile(t, cfgPath, "127.0.0.1:0")

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	defer g.Stop()

	old := g.listeners["g1"]
	oldProxy := old.(*ProxyListener)
	if oldProxy.state.Load() != ProxyRunning {
		t.Fatalf("old listener not running before reload")
	}

	// Construct phase failure: new config contains invalid route target (%zz),
	// LoadConfig's validate only does basic checks; newListener fails when parsing route.
	// At this point the old listener must be preserved.
	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte(`{"listeners":[{"name":"g1","listen":"127.0.0.1:0","protocol":"http2","routes":[{"path":"/*","target":"%zz"}]}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	g.cfg.configPath = badPath
	if err := g.Reload(); err == nil {
		t.Fatal("expected construct error")
	}

	// Old listener must still be the same instance and still running.
	if g.listeners["g1"] != old {
		t.Fatal("old listener was replaced despite construct failure")
	}
	if oldProxy.state.Load() != ProxyRunning {
		t.Fatal("old listener stopped after construct failure")
	}
}

// TestGatewayReloadAuthorizationFileHotReload W26: authorization_file changes take effect
// after SIGHUP reload (previously only loaded once at NewGateway).
// TestHandleAddListenerInvalidTLSMode W23: invalid protocol must return 400, not
// silently degraded to a plaintext listener by NewProxyListener.
func TestHandleAddListenerInvalidTLSMode(t *testing.T) {
	g, _ := newTestGateway(t)
	body := `{"name":"bad","listen":"127.0.0.1:0","protocol":"bogus","routes":[{"path":"/*","target":"http://127.0.0.1:1"}]}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/listeners", strings.NewReader(body))
	g.handleAddListener(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, body = %s, want 400", rr.Code, rr.Body.String())
	}
	if _, exists := g.listeners["bad"]; exists {
		t.Fatal("invalid listener was added")
	}
}

// TestHandleAddListenerValid W23: valid listener (plain + route) successfully added
// via validate + newListener factory, and policy closure is bound.
func TestHandleAddListenerValid(t *testing.T) {
	g, backend := newTestGateway(t)
	body := fmt.Sprintf(`{"name":"new1","listen":"127.0.0.1:0","protocol":"http2","routes":[{"path":"/*","target":%q}]}`, backend)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/listeners", strings.NewReader(body))
	g.handleAddListener(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("code = %d, body = %s, want 201", rr.Code, rr.Body.String())
	}
	l, exists := g.listeners["new1"]
	if !exists {
		t.Fatal("listener not added")
	}
	if l.State() != ProxyRunning {
		t.Fatalf("new listener state = %v, want running", l.State())
	}
}

func TestGatewayReloadAuthorizationFileHotReload(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "authz.json")
	writePolicy := func(role string) {
		body := fmt.Sprintf(`{"version":"1","roles":{"%s":{"display_name":"%s role","grants":["read"]}}}`, role, role)
		if err := os.WriteFile(policyPath, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	writePolicy("admin")

	cfgPath := filepath.Join(dir, "gw.json")
	backend, closeB := startTestBackend(t)
	defer closeB()
	cfgBody := fmt.Sprintf(`{"authorization_file":%q,"listeners":[{"name":"g1","listen":"127.0.0.1:0","protocol":"http2","routes":[{"path":"/*","target":%q}]}]}`, policyPath, backend)
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	defer g.Stop()

	p1 := gw.GetAuthorizationPolicy()
	if p1 == nil {
		t.Fatal("policy not loaded at startup")
	}
	if len(p1.Roles) != 1 || p1.Roles["admin"].DisplayName == "" {
		t.Fatalf("unexpected startup policy roles: %+v", p1.Roles)
	}

	// Change the policy file; reload should pick it up.
	writePolicy("audit")
	if err := g.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	p2 := gw.GetAuthorizationPolicy()
	if p2 == nil {
		t.Fatal("policy lost after reload")
	}
	if len(p2.Roles) != 1 || p2.Roles["admin"].DisplayName != "" {
		t.Fatalf("policy not hot-reloaded: roles=%+v", p2.Roles)
	}
}
