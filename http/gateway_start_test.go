package httpgw

import (
	"testing"

	gw "github.com/varwof/gateway-core"
)

func TestGatewayStartCRL(t *testing.T) {
	pki := setupPKI(t)
	cfg := &Config{
		Listeners: []ListenerConfig{{
			Name: "crl", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
			TLS:    &gw.TLSConfig{CRLURL: "http://127.0.0.1:1/crl.pem", CACertFile: pki.CACertFile},
			Routes: []RouteConfig{{Path: "/", Target: "http://127.0.0.1:1"}},
		}},
	}
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	g.Stop()
}

func TestGatewayStartCRLError(t *testing.T) {
	cfg := &Config{
		Listeners: []ListenerConfig{{
			Name: "crl", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
			TLS:    &gw.TLSConfig{CRLURL: "http://x/crl.pem", CACertFile: "/nonexistent/ca.pem"},
			Routes: []RouteConfig{{Path: "/", Target: "http://127.0.0.1:1"}},
		}},
	}
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err == nil {
		t.Fatal("expected CA load error")
	}
}

func TestNewGatewayWithRevoker(t *testing.T) {
	pki := setupPKI(t)
	cfg := &Config{
		VarwofCore: &gw.RevokerConfig{
			CoreURL:      "https://core.test:4433/api/v1",
			MTLSCertFile: pki.AdminCertFile,
			MTLSKeyFile:  pki.AdminKeyFile,
		},
	}
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	if g.revoker == nil {
		t.Fatal("expected revoker to be built")
	}
}

func TestNewGatewayWithBadRevoker(t *testing.T) {
	cfg := &Config{VarwofCore: &gw.RevokerConfig{}}
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	if g.revoker != nil {
		t.Fatal("revoker should be nil when construction fails")
	}
}

func TestNewGatewayWithPlugins(t *testing.T) {
	cfg := &Config{
		CapabilityPlugins: gw.PluginConfigs{
			"tcp": {
				Type: gw.PluginTypeAllowlist,
				Config: map[string]interface{}{
					"allow":          []string{"tunnel:prod"},
					"default_action": "deny",
				},
			},
		},
	}
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	if g.pluginRegistry == nil || g.pluginRegistry.Len() != 1 {
		t.Fatalf("pluginRegistry = %+v", g.pluginRegistry)
	}
}

func TestNewGatewayWithBadPlugins(t *testing.T) {
	cfg := &Config{
		CapabilityPlugins: gw.PluginConfigs{
			"x": {Type: "not-a-plugin"},
		},
	}
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	if g.pluginRegistry == nil {
		t.Fatal("pluginRegistry should be non-nil even when build fails")
	}
}

func TestNewGatewayWithTSAProof(t *testing.T) {
	tsa := gw.NewTSAClient("https://tsa.test")
	proof := gw.NewTSAProofLogger("/tmp/test-proof.log", tsa, nil, 3600)
	g := NewGateway(&Config{TSAProofFile: "/tmp/test-proof.log"}, NewBundle(), "en", nil, tsa, proof, nil)
	if g.tsaProof != proof {
		t.Fatal("tsaProof not wired through NewGateway")
	}
}
