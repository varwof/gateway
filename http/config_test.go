package httpgw

import (
	"os"
	"path/filepath"
	"testing"

	gw "github.com/varwof/gateway-core"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid mtls",
			cfg: Config{
				Listeners: []ListenerConfig{{
					Name:     "l1",
					Listen:   ":8443",
					Protocol: ProtocolHTTP2,
					TLS:      &gw.TLSConfig{Mode: gw.TLSModeMTLS, CACertFile: "/path/ca.pem", CertFile: "/path/cert.pem", KeyFile: "/path/key.pem"},
					Routes:   []RouteConfig{{Path: "/api/*", Target: "http://127.0.0.1:8080"}},
				}},
			},
			wantErr: false,
		},
		{
			name:    "no listeners",
			cfg:     Config{Listeners: []ListenerConfig{}},
			wantErr: false,
		},
		{
			name: "missing name",
			cfg: Config{
				Listeners: []ListenerConfig{{Listen: ":8443", Protocol: ProtocolHTTP2, Routes: []RouteConfig{{Path: "/", Target: "http://b"}}}},
			},
			wantErr: true,
		},
		{
			name: "missing routes",
			cfg: Config{
				Listeners: []ListenerConfig{{Name: "l1", Listen: ":8443", Protocol: ProtocolHTTP2}},
			},
			wantErr: true,
		},
		{
			name: "mtls missing ca",
			cfg: Config{
				Listeners: []ListenerConfig{{
					Name: "l1", Listen: ":8443", Protocol: ProtocolHTTP2,
					TLS:    &gw.TLSConfig{Mode: gw.TLSModeMTLS},
					Routes: []RouteConfig{{Path: "/", Target: "http://b"}},
				}},
			},
			wantErr: true,
		},
		{
			name: "missing listen",
			cfg: Config{
				Listeners: []ListenerConfig{{Name: "l1", Protocol: ProtocolHTTP2, Routes: []RouteConfig{{Path: "/", Target: "http://b"}}}},
			},
			wantErr: true,
		},
		{
			name: "missing protocol",
			cfg: Config{
				Listeners: []ListenerConfig{{Name: "l1", Listen: ":8443", Routes: []RouteConfig{{Path: "/", Target: "http://b"}}}},
			},
			wantErr: true,
		},
		{
			name: "invalid protocol",
			cfg: Config{
				Listeners: []ListenerConfig{{Name: "l1", Listen: ":8443", Protocol: "bogus", Routes: []RouteConfig{{Path: "/", Target: "http://b"}}}},
			},
			wantErr: true,
		},
		{
			name: "h3 missing cert",
			cfg: Config{
				Listeners: []ListenerConfig{{Name: "l1", Listen: ":8443", Protocol: ProtocolH3, Routes: []RouteConfig{{Path: "/", Target: "http://b"}}}},
			},
			wantErr: true,
		},
		{
			name: "route missing path",
			cfg: Config{
				Listeners: []ListenerConfig{{Name: "l1", Listen: ":8443", Protocol: ProtocolHTTP2, Routes: []RouteConfig{{Target: "http://b"}}}},
			},
			wantErr: true,
		},
		{
			name: "route missing target",
			cfg: Config{
				Listeners: []ListenerConfig{{Name: "l1", Listen: ":8443", Protocol: ProtocolHTTP2, Routes: []RouteConfig{{Path: "/"}}}},
			},
			wantErr: true,
		},
		{
			name: "management missing listen",
			cfg: Config{
				Management: &MgmtConfig{TLS: &gw.TLSConfig{CACertFile: "/p/ca.pem"}},
			},
			wantErr: true,
		},
		{
			name: "management missing ca",
			cfg: Config{
				Management: &MgmtConfig{Listen: ":9443"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.json")

	data := `{
		"listeners": [{
			"name": "l1",
			"listen": ":8443",
			"protocol": "http2",
			"routes": [{"path": "/api/*", "target": "http://127.0.0.1:8080"}]
		}]
	}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Listeners) != 1 || cfg.Listeners[0].Name != "l1" {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

func TestForwardClientCertDEREnabled(t *testing.T) {
	m := &gw.HTTPExtra{}
	if m.ForwardClientCertDEREnabled() {
		t.Fatal("expected disabled when unset")
	}
	var nm *gw.HTTPExtra
	if nm.ForwardClientCertDEREnabled() {
		t.Fatal("expected disabled for nil HTTPExtra")
	}
	f := false
	m = &gw.HTTPExtra{ForwardClientCertDER: &f}
	if m.ForwardClientCertDEREnabled() {
		t.Fatal("expected disabled when false")
	}
	tru := true
	m = &gw.HTTPExtra{ForwardClientCertDER: &tru}
	if !m.ForwardClientCertDEREnabled() {
		t.Fatal("expected enabled when true")
	}
}

func TestBuildListenerFromKVForwardClientCertDER(t *testing.T) {
	lc := buildListenerFromKV(map[string]string{
		"name":                    "l1",
		"listen":                  ":8443",
		"protocol":                "http2",
		"tls-mode":                "mtls",
		"ca-cert":                 "/p/ca.pem",
		"cert":                    "/p/cert.pem",
		"key":                     "/p/key.pem",
		"forward-client-cert-der": "true",
	})
	if !lc.HTTPExt.ForwardClientCertDEREnabled() {
		t.Fatal("expected forward-client-cert-der=true to enable DER passthrough")
	}
}
