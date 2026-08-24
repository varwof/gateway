package tcpgw

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid mapping",
			cfg: Config{
				Mappings: []MappingConfig{
					{
						Name:     "test",
						Listen:   ":8080",
						Target:   "127.0.0.1:3306",
						Protocol: ProtocolTCP,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid mtls mapping",
			cfg: Config{
				Mappings: []MappingConfig{
					{
						Name:     "test-mtls",
						Listen:   ":8081",
						Target:   "127.0.0.1:3306",
						Protocol: ProtocolTCPMTLS,
						TLS: &gw.TLSConfig{
							CACertFile: "/path/to/ca.pem",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing name",
			cfg: Config{
				Mappings: []MappingConfig{
					{
						Listen:   ":8080",
						Target:   "127.0.0.1:3306",
						Protocol: ProtocolTCP,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "missing listen",
			cfg: Config{
				Mappings: []MappingConfig{
					{
						Name:     "test",
						Target:   "127.0.0.1:3306",
						Protocol: ProtocolTCP,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "missing target",
			cfg: Config{
				Mappings: []MappingConfig{
					{
						Name:     "test",
						Listen:   ":8080",
						Protocol: ProtocolTCP,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid protocol",
			cfg: Config{
				Mappings: []MappingConfig{
					{
						Name:     "test",
						Listen:   ":8080",
						Target:   "127.0.0.1:3306",
						Protocol: "invalid",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "mtls missing ca",
			cfg: Config{
				Mappings: []MappingConfig{
					{
						Name:     "test",
						Listen:   ":8080",
						Target:   "127.0.0.1:3306",
						Protocol: ProtocolTCPMTLS,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid tunnel",
			cfg: Config{
				Tunnels: []TunnelConfig{
					{
						Name:        "tun1",
						Listen:      "127.0.0.1:3306",
						GatewayAddr: "gateway.varwof.com:3307",
						CertFile:    "/path/to/cert.pem",
						KeyFile:     "/path/to/key.pem",
						CACertFile:  "/path/to/ca.pem",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "tunnel missing cert",
			cfg: Config{
				Tunnels: []TunnelConfig{
					{
						Name:        "tun1",
						Listen:      "127.0.0.1:3306",
						GatewayAddr: "gateway.varwof.com:3307",
						KeyFile:     "/path/to/key.pem",
						CACertFile:  "/path/to/ca.pem",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid management",
			cfg: Config{
				Management: &ManagementConfig{
					Listen: ":8444",
					TLS: &gw.TLSConfig{
						CACertFile: "/path/to/ca.pem",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "management missing ca",
			cfg: Config{
				Management: &ManagementConfig{
					Listen: ":8444",
				},
			},
			wantErr: true,
		},
		{
			// W01 (2026-08-16): mesh protocol enforces symmetric mTLS.
			name: "mesh_listen without mesh_server_tls rejected",
			cfg: Config{
				MeshListen: "127.0.0.1:9000",
			},
			wantErr: true,
		},
		{
			name: "mesh_listen with incomplete mesh_server_tls rejected",
			cfg: Config{
				MeshListen: "127.0.0.1:9000",
				MeshServerTLS: &gw.TLSConfig{
					CACertFile: "/ca.pem",
				},
			},
			wantErr: true,
		},
		{
			name: "mesh_listen with full mesh_server_tls ok",
			cfg: Config{
				MeshListen: "127.0.0.1:9000",
				MeshServerTLS: &gw.TLSConfig{
					CACertFile: "/ca.pem",
					CertFile:   "/srv.pem",
					KeyFile:    "/srv.key",
				},
			},
			wantErr: false,
		},
		{
			name: "incomplete peer rejected",
			cfg: Config{
				Peers: []MeshPeerConfig{{Name: "p", Addr: "1.2.3.4:9000"}},
			},
			wantErr: true,
		},
		{
			name: "complete peer ok",
			cfg: Config{
				Peers: []MeshPeerConfig{{
					Name: "p", Addr: "1.2.3.4:9000",
					CACertFile: "/ca.pem", CertFile: "/c.pem", KeyFile: "/c.key",
				}},
			},
			wantErr: false,
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
	cfgPath := filepath.Join(dir, "config.json")

	validJSON := `{
		"mappings": [{
			"name": "test",
			"listen": ":8080",
			"target": "127.0.0.1:3306",
			"protocol": "tcp"
		}]
	}`
	if err := os.WriteFile(cfgPath, []byte(validJSON), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if len(cfg.Mappings) != 1 || cfg.Mappings[0].Name != "test" {
		t.Errorf("unexpected config: %+v", cfg)
	}

	invalidJSON := `{"mappings": [{"name": "test"}]}`
	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte(invalidJSON), 0644); err != nil {
		t.Fatal(err)
	}
	_, err = LoadConfig(badPath)
	if err == nil {
		t.Error("expected error for missing fields, got nil")
	}

	_, err = LoadConfig("/nonexistent/config.json")
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

// TestLoadConfigRejectsUnknownFields W41: misspelled fields (e.g. ocsp_url) must
// error immediately rather than be silently ignored.
func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	typoJSON := `{
		"mappings": [{
			"name": "test",
			"listen": ":8080",
			"target": "127.0.0.1:3306",
			"protocol": "tcp",
			"tls": {"ocsp_url": "http://ocsp.example.com/ocsp"}
		}]
	}`
	if err := os.WriteFile(cfgPath, []byte(typoJSON), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(cfgPath)
	if err == nil {
		t.Fatal("expected error for unknown field ocsp_url, got nil (W41)")
	}

	// Valid fields must still load.
	validJSON := `{
		"mappings": [{
			"name": "test",
			"listen": ":8080",
			"target": "127.0.0.1:3306",
			"protocol": "tcp+mtls",
			"tls": {"ca_cert_file": "/ca.pem", "ocsp_cache_ttl_sec": 300, "ocsp_fallback": "deny"}
		}]
	}`
	if err := os.WriteFile(cfgPath, []byte(validJSON), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(cfgPath); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestMappingConfigCRLRefreshDuration(t *testing.T) {
	m := &MappingConfig{}
	d := m.CRLRefreshDuration()
	if d != 5*time.Minute {
		t.Errorf("default should be 5m, got %v", d)
	}

	m.TLS = &gw.TLSConfig{CRLRefreshSec: 60}
	d = m.CRLRefreshDuration()
	if d != 60*time.Second {
		t.Errorf("expected 60s, got %v", d)
	}
}
