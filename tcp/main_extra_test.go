// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package tcpgw

import (
	"os"
	"path/filepath"
	"testing"

	gw "github.com/varwof/gateway-core"
)

func TestBundleEf(t *testing.T) {
	b := NewBundle()
	if err := b.Ef("en", "gateway.started"); err == nil {
		t.Fatal("expected non-nil error")
	}
	if err := b.Ef("zh", "gateway.started"); err == nil {
		t.Fatal("expected non-nil error for zh")
	}
}

func TestStringSliceFlag(t *testing.T) {
	var f stringSliceFlag
	if f.String() != "" {
		t.Fatalf("empty String() = %q", f.String())
	}
	if err := f.Set("a"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := f.Set("b"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if f.String() != "a,b" {
		t.Fatalf("String() = %q, want a,b", f.String())
	}
}

func TestGatewayStartWithTunnelAndTSAProof(t *testing.T) {
	dir := newTunnelCertDir(t)

	proof := gw.NewTSAProofLogger("", nil, nil, 0)
	g := NewGateway(&Config{
		Tunnels: []TunnelConfig{{
			Name:        "tun1",
			Listen:      "127.0.0.1:0",
			GatewayAddr: "127.0.0.1:1",
			CertFile:    filepath.Join(dir, "client.pem"),
			KeyFile:     filepath.Join(dir, "client.key"),
			CACertFile:  filepath.Join(dir, "ca.pem"),
		}},
	}, NewBundle(), "en", nil, nil, proof, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()
	if _, ok := g.tunnels["tun1"]; !ok {
		t.Fatal("tunnel not registered")
	}
}

func TestGatewayStartWithCRLCache(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "server", caCert, caKey, nil)

	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	g := NewGateway(&Config{
		Mappings: []MappingConfig{{
			Name: "crl", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(),
			Protocol: ProtocolTCPMTLS,
			TLS: &gw.TLSConfig{
				CACertFile: filepath.Join(dir, "ca.pem"),
				CertFile:   filepath.Join(dir, "server.pem"),
				KeyFile:    filepath.Join(dir, "server.key"),
				CRLURL:     "http://127.0.0.1:1/unreachable.crl",
				AllowRoles: []string{"gateway:admin"},
			},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()
	if len(g.crlCaches) != 1 {
		t.Fatalf("crlCaches = %d, want 1", len(g.crlCaches))
	}
}

func TestGatewayStartWithMesh(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "server", caCert, caKey, nil)

	peerDir := newTunnelCertDir(t)

	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	g := NewGateway(&Config{
		MeshListen: "127.0.0.1:0",
		// W01 (2026-08-16): mesh protocol enforces symmetric mTLS.
		MeshServerTLS: &gw.TLSConfig{
			CACertFile: filepath.Join(peerDir, "ca.pem"),
			CertFile:   filepath.Join(peerDir, "server.pem"),
			KeyFile:    filepath.Join(peerDir, "server.key"),
		},
		Peers: []MeshPeerConfig{{
			Name: "p", Addr: "127.0.0.1:1",
			CACertFile: filepath.Join(peerDir, "ca.pem"),
			CertFile:   filepath.Join(peerDir, "client.pem"),
			KeyFile:    filepath.Join(peerDir, "client.key"),
		}},
		Mappings: []MappingConfig{{
			Name: "mesh-m", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(),
			Protocol: ProtocolTCPMesh, MeshPeerName: "p",
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()
	if g.meshListener == nil {
		t.Fatal("mesh listener not started")
	}
	if _, ok := g.mappings["mesh-m"]; !ok {
		t.Fatal("mesh mapping not registered")
	}
}

func TestGatewayStartMeshListenError(t *testing.T) {
	peerDir := newTunnelCertDir(t)
	g := NewGateway(&Config{
		MeshListen: "256.256.256.256:99999",
		Peers: []MeshPeerConfig{{
			Name: "p", Addr: "127.0.0.1:1",
			CACertFile: filepath.Join(peerDir, "ca.pem"),
			CertFile:   filepath.Join(peerDir, "client.pem"),
			KeyFile:    filepath.Join(peerDir, "client.key"),
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err == nil {
		g.Stop()
		t.Fatal("expected mesh listen error")
	}
}

func TestGatewayReloadConfigPathEmpty(t *testing.T) {
	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	cfg := &Config{
		Mappings: []MappingConfig{{
			Name: "r", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(), Protocol: ProtocolTCP,
		}},
	}
	cfg.SetDefaults()
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()

	if err := g.Reload(); err != nil {
		t.Fatalf("Reload with empty configPath: %v", err)
	}
}

func TestGatewayReloadComplex(t *testing.T) {
	dir := t.TempDir()
	echo1 := startEchoServer(t)
	defer echo1.Close()
	echo2 := startEchoServer(t)
	defer echo2.Close()

	configJSON := `{"mappings":[
		{"name":"keep","listen":"127.0.0.1:0","target":"` + echo1.Addr().String() + `","protocol":"tcp"},
		{"name":"remove","listen":"127.0.0.1:0","target":"` + echo1.Addr().String() + `","protocol":"tcp"},
		{"name":"change","listen":"127.0.0.1:0","target":"` + echo1.Addr().String() + `","protocol":"tcp"}
	]}`
	configPath := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(configPath, []byte(configJSON), 0644); err != nil {
		t.Fatal(err)
	}

	g := NewGateway(&Config{
		Mappings: []MappingConfig{
			{Name: "keep", Listen: "127.0.0.1:0", Target: echo1.Addr().String(), Protocol: ProtocolTCP},
			{Name: "remove", Listen: "127.0.0.1:0", Target: echo1.Addr().String(), Protocol: ProtocolTCP},
			{Name: "change", Listen: "127.0.0.1:0", Target: echo1.Addr().String(), Protocol: ProtocolTCP},
		},
	}, NewBundle(), "en", nil, nil, nil, nil)
	g.cfg.configPath = configPath
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()

	oldChange := g.mappings["change"]

	reloadJSON := `{"mappings":[
		{"name":"keep","listen":"127.0.0.1:0","target":"` + echo1.Addr().String() + `","protocol":"tcp"},
		{"name":"change","listen":"127.0.0.1:0","target":"` + echo2.Addr().String() + `","protocol":"tcp"},
		{"name":"added","listen":"127.0.0.1:0","target":"` + echo1.Addr().String() + `","protocol":"tcp"}
	]}`
	if err := os.WriteFile(configPath, []byte(reloadJSON), 0644); err != nil {
		t.Fatal(err)
	}

	if err := g.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if _, ok := g.mappings["keep"]; !ok {
		t.Fatal("keep mapping lost")
	}
	if _, ok := g.mappings["remove"]; ok {
		t.Fatal("remove mapping still present")
	}
	if _, ok := g.mappings["added"]; !ok {
		t.Fatal("added mapping missing")
	}
	newChange := g.mappings["change"]
	if newChange == oldChange {
		t.Fatal("changed mapping should have been restarted")
	}
	if newChange.cfg.Target != echo2.Addr().String() {
		t.Fatalf("change target = %q", newChange.cfg.Target)
	}
}

func TestGatewayReloadPluginRebuild(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(configPath, []byte(`{
		"mappings": [],
		"capability_plugins": {
			"scheme-x": {"type": "allowlist", "config": {"allow": ["SELECT:*"]}}
		}
	}`), 0644); err != nil {
		t.Fatal(err)
	}

	g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
	g.cfg.configPath = configPath
	if err := g.Reload(); err != nil {
		t.Fatalf("Reload with plugins: %v", err)
	}
	if g.pluginRegistry == nil {
		t.Fatal("pluginRegistry should be rebuilt")
	}

	if err := os.WriteFile(configPath, []byte(`{"mappings":[]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := g.Reload(); err != nil {
		t.Fatalf("Reload without plugins: %v", err)
	}
	if g.pluginRegistry == nil {
		t.Fatal("pluginRegistry should remain non-nil (PolicyManager-bound)")
	}
	if g.pluginRegistry.Len() != 0 {
		t.Fatalf("pluginRegistry should be empty when no plugins configured, got %d", g.pluginRegistry.Len())
	}
	if g.policyMgr == nil {
		t.Fatal("policyMgr should exist")
	}
	if g.policyMgr.CurrentVersion() != 2 {
		t.Fatalf("expected 2 published versions (reload x2), got %d", g.policyMgr.CurrentVersion())
	}
}

func TestGatewayReloadBadPlugin(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(configPath, []byte(`{
		"mappings": [],
		"capability_plugins": {
			"scheme-x": {"type": "nope", "config": {}}
		}
	}`), 0644); err != nil {
		t.Fatal(err)
	}

	g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
	g.cfg.configPath = configPath
	if err := g.Reload(); err != nil {
		t.Fatalf("Reload should not fail on bad plugin: %v", err)
	}
}

func TestGatewayLoadAuthorizationPolicyMgmtFallback(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "server", caCert, caKey, nil)

	policy := `{"version":"1.0","roles":{"client":{"display_name":"Client","profiles":["client"],"grants":["connect"]}}}`
	policyPath := filepath.Join(dir, "authz.json")
	if err := os.WriteFile(policyPath, []byte(policy), 0644); err != nil {
		t.Fatal(err)
	}

	g := NewGateway(&Config{
		AuthorizationFile: policyPath,
		Management: &ManagementConfig{
			Listen: "127.0.0.1:0",
			TLS: &gw.TLSConfig{
				CACertFile: filepath.Join(dir, "ca.pem"),
				CertFile:   filepath.Join(dir, "server.pem"),
				KeyFile:    filepath.Join(dir, "server.key"),
			},
		},
	}, NewBundle(), "en", nil, nil, nil, nil)
	g.loadAuthorizationPolicy()
}

func TestGatewayStartTunnelError(t *testing.T) {
	dir := newTunnelCertDir(t)
	g := NewGateway(&Config{
		Tunnels: []TunnelConfig{{
			Name:        "bad-tun",
			Listen:      "127.0.0.1:0",
			GatewayAddr: "127.0.0.1:1",
			CertFile:    filepath.Join(dir, "missing.pem"),
			KeyFile:     filepath.Join(dir, "missing.key"),
			CACertFile:  filepath.Join(dir, "ca.pem"),
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	err := g.Start()
	if err == nil {
		g.Stop()
		t.Fatal("expected tunnel cert load error")
	}
	if !contains(err.Error(), "create tunnel") {
		t.Fatalf("unexpected error: %v", err)
	}
}
