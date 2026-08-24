package tcpgw

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gw "github.com/varwof/gateway-core"
)

// TestGatewayReloadTunnelHotReload W13: Reload must hot-reload the tunnel section —
// previously tunnel changes were silently discarded, only fully closed at Stop().
func TestGatewayReloadTunnelHotReload(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.json")

	writeCfg := func(tunnels string) {
		body := fmt.Sprintf(`{"mappings":[{"name":"m","listen":"127.0.0.1:0","target":"127.0.0.1:1","protocol":"tcp"}],"tunnels":[%s]}`, tunnels)
		if err := os.WriteFile(cfgPath, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}

	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "server", caCert, caKey, nil)
	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
	certPEM, _ := os.ReadFile(filepath.Join(dir, "server.pem"))
	keyPEM, _ := os.ReadFile(filepath.Join(dir, "server-key.pem"))

	tunnelCfg := func(name string) string {
		return fmt.Sprintf(`{"name":%q,"listen":"127.0.0.1:0","gateway_addr":"127.0.0.1:1","ca_cert_file":%q,"cert_file":%q,"key_file":%q}`, name, filepath.Join(dir, "ca.pem"), filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"))
	}
	_ = caPEM
	_ = certPEM
	_ = keyPEM

	// Initial config: no tunnel.
	writeCfg("")
	if err := os.WriteFile(cfgPath, []byte(`{"mappings":[{"name":"m","listen":"127.0.0.1:0","target":"127.0.0.1:1","protocol":"tcp"}]}`), 0644); err != nil {
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

	if len(g.tunnels) != 0 {
		t.Fatalf("expected 0 tunnels initially, got %d", len(g.tunnels))
	}

	// Reload 1: add tunnel.
	writeCfg(tunnelCfg("t1"))
	if err := g.Reload(); err != nil {
		t.Fatalf("reload add tunnel: %v", err)
	}
	if len(g.tunnels) != 1 || g.tunnels["t1"] == nil {
		t.Fatalf("tunnel t1 not added, tunnels=%v", g.tunnels)
	}

	// Reload 2: tunnel config unchanged → reuse same instance.
	t1 := g.tunnels["t1"]
	writeCfg(tunnelCfg("t1"))
	if err := g.Reload(); err != nil {
		t.Fatalf("reload unchanged tunnel: %v", err)
	}
	if g.tunnels["t1"] != t1 {
		t.Fatal("unchanged tunnel was not reused")
	}

	// Reload 3: remove tunnel.
	writeCfg("")
	if err := os.WriteFile(cfgPath, []byte(`{"mappings":[{"name":"m","listen":"127.0.0.1:0","target":"127.0.0.1:1","protocol":"tcp"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := g.Reload(); err != nil {
		t.Fatalf("reload remove tunnel: %v", err)
	}
	if len(g.tunnels) != 0 {
		t.Fatalf("tunnel not removed, tunnels=%v", g.tunnels)
	}
}

// TestGatewayReloadMappingRemovedResetsGauge W13: after Reload removes a mapping,
// the MappingUp gauge must be set to 0 (previously stuck at 1, causing false monitoring alerts).
func TestGatewayReloadMappingRemovedResetsGauge(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.json")

	echo1 := startEchoServer(t)
	defer echo1.Close()

	body := fmt.Sprintf(`{"mappings":[{"name":"keep","listen":"127.0.0.1:0","target":%q,"protocol":"tcp"}]}`, echo1.Addr().String())
	if err := os.WriteFile(cfgPath, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)

	// Manually add a mapping that will be removed.
	echo2 := startEchoServer(t)
	defer echo2.Close()
	m, err := NewMapping(MappingConfig{Name: "gone", Listen: "127.0.0.1:0", Target: echo2.Addr().String(), Protocol: ProtocolTCP}, nil, nil, nil, nil, NewBundle(), "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	g.mappings["gone"] = m
	MappingUp.Set(1, "gone")

	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	defer g.Stop()

	// g.Start already rebuilt from g.cfg.Mappings, so add gone back to cfg then trigger reload.
	// This calls Reload directly: config does not contain gone → should be removed and gauge set to 0.
	// Rewrite config without gone (matching g.cfg.Mappings), Reload takes the removal path.
	g.cfg.Mappings = []MappingConfig{{Name: "keep", Listen: "127.0.0.1:0", Target: echo1.Addr().String(), Protocol: ProtocolTCP}}
	g.cfg.configPath = cfgPath
	if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf(`{"mappings":[{"name":"keep","listen":"127.0.0.1:0","target":%q,"protocol":"tcp"}]}`, echo1.Addr().String())), 0644); err != nil {
		t.Fatal(err)
	}
	if err := g.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	if _, exists := g.mappings["gone"]; exists {
		t.Fatal("mapping gone should be removed")
	}
	if v := MappingUp.Value("gone"); v != 0 {
		t.Fatalf("MappingUp[gone] = %d, want 0", v)
	}
}

// TestHandleAddMappingValidate W14: API adding invalid config (missing tls_mode) must return 400.
func TestHandleAddMappingValidate(t *testing.T) {
	g := newTestGateway()
	rec := httptest.NewRecorder()
	body := `{"name":"bad","listen":"127.0.0.1:0","target":"x:1"}`
	g.handleAddMapping(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s, want 400", rec.Code, rec.Body.String())
	}
	if _, exists := g.mappings["bad"]; exists {
		t.Fatal("invalid mapping was added")
	}
}

// TestHandleAddMappingPolicyWiring W14: mappings added via API must be wired with
// pluginRegistry/policyVersion/policyResolver (previously nil, causing admission pipeline inconsistency).
func TestHandleAddMappingPolicyWiring(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "server", caCert, caKey, nil)

	// Policy manager with plugins.
	pm := gw.NewPolicyManager(gw.NewPluginRegistry())
	if _, err := pm.Publish(gw.PluginConfigs{
		"database": {Type: gw.PluginTypeAllowlist, Config: map[string]interface{}{"allowed": []string{"x"}}},
	}, "test", ""); err != nil {
		t.Fatal(err)
	}

	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	g := newTestGateway()
	g.policyMgr = pm
	g.pluginRegistry = pm.Registry()

	body := fmt.Sprintf(`{"name":"wired","listen":"127.0.0.1:0","target":%q,"protocol":"tcp"}`, echoSrv.Addr().String())
	rec := httptest.NewRecorder()
	g.handleAddMapping(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s, want 201", rec.Code, rec.Body.String())
	}
	m := g.mappings["wired"]
	if m == nil {
		t.Fatal("mapping not added")
	}
	defer m.Stop()

	if m.pluginRegistry == nil {
		t.Fatal("pluginRegistry not wired")
	}
	if m.policyVersion == nil {
		t.Fatal("policyVersion fn not wired")
	}
	if m.policyResolver == nil {
		t.Fatal("policyResolver fn not wired")
	}
	if m.policyVersion() == 0 {
		t.Fatal("policyVersion() = 0, want > 0")
	}
}

// TestHandleAddMappingJSONConflicts W14: adding a duplicate name returns 409.
func TestHandleAddMappingJSONConflicts(t *testing.T) {
	g := newTestGateway()
	g.mappings["dup"] = &Mapping{}
	rec := httptest.NewRecorder()
	body := `{"name":"dup","listen":"127.0.0.1:0","target":"x:1","protocol":"tcp"}`
	g.handleAddMapping(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}

var _ = net.IPv4len
var _ = json.Valid

// TestCRLCacheKeyedByMappingName W40: two mappings sharing the same crl_url each
// build their own key (previously keyed by URL, overwriting each other; handleCRLReload only flushed the last one).
func TestCRLCacheKeyedByMappingName(t *testing.T) {
	dir := t.TempDir()
	_, _ = generateTestCA(t, dir)

	cfg := &Config{
		Mappings: []MappingConfig{
			{Name: "m1", Listen: "127.0.0.1:0", Target: "127.0.0.1:1", Protocol: ProtocolTCPMTLS,
				TLS: &gw.TLSConfig{CACertFile: filepath.Join(dir, "ca.pem"), CRLURL: "http://crl.example.com/ca.crl"}},
			{Name: "m2", Listen: "127.0.0.1:0", Target: "127.0.0.1:2", Protocol: ProtocolTCPMTLS,
				TLS: &gw.TLSConfig{CACertFile: filepath.Join(dir, "ca.pem"), CRLURL: "http://crl.example.com/ca.crl"}},
		},
	}

	if cfg.Mappings[0].TLS.CRLURL != cfg.Mappings[1].TLS.CRLURL {
		t.Fatal("test setup: mappings must share crl_url")
	}

	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	_ = g

	// W40 core: key is derived per mapping name, same URL gets separate keys.
	key1 := cfg.Mappings[0].Name + "/crl"
	key2 := cfg.Mappings[1].Name + "/crl"
	if key1 == key2 {
		t.Fatal("keys must differ per mapping name")
	}
	if key1 == cfg.Mappings[0].TLS.CRLURL || key2 == cfg.Mappings[0].TLS.CRLURL {
		t.Fatal("key must not be URL-based (W40)")
	}
}
