package udpgw

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
			name: "valid plain listener",
			cfg: Config{
				Listeners: []ListenerConfig{
					{
						Name:     "test",
						Listen:   ":8080",
						Protocol: ProtocolUDP,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid quic listener",
			cfg: Config{
				Listeners: []ListenerConfig{
					{
						Name:     "quic-ingress",
						Listen:   ":4433",
						Protocol: ProtocolQUIC,
						TLS: &gw.TLSConfig{
							CACertFile: "/path/to/ca.pem",
							CertFile:   "/path/to/cert.pem",
							KeyFile:    "/path/to/key.pem",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid dtls listener",
			cfg: Config{
				Listeners: []ListenerConfig{
					{
						Name:     "dtls-ingress",
						Listen:   ":4434",
						Protocol: ProtocolDTLS,
						TLS: &gw.TLSConfig{
							CertFile: "/path/to/cert.pem",
							KeyFile:  "/path/to/key.pem",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid mtls listener",
			cfg: Config{
				Listeners: []ListenerConfig{
					{
						Name:     "mtls-ingress",
						Listen:   ":4435",
						Protocol: ProtocolMTLS,
						TLS: &gw.TLSConfig{
							CACertFile: "/path/to/ca.pem",
							CertFile:   "/path/to/cert.pem",
							KeyFile:    "/path/to/key.pem",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing name",
			cfg: Config{
				Listeners: []ListenerConfig{
					{
						Listen:   ":8080",
						Protocol: ProtocolUDP,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "missing listen",
			cfg: Config{
				Listeners: []ListenerConfig{
					{
						Name:     "test",
						Protocol: ProtocolUDP,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "dtls missing cert",
			cfg: Config{
				Listeners: []ListenerConfig{
					{
						Name:     "dtls-test",
						Listen:   ":4434",
						Protocol: ProtocolDTLS,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "quic missing cert",
			cfg: Config{
				Listeners: []ListenerConfig{
					{
						Name:     "quic-test",
						Listen:   ":4433",
						Protocol: ProtocolQUIC,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "mtls missing ca",
			cfg: Config{
				Listeners: []ListenerConfig{
					{
						Name:     "mtls-test",
						Listen:   ":4435",
						Protocol: ProtocolMTLS,
						TLS: &gw.TLSConfig{
							CertFile: "/path/to/cert.pem",
							KeyFile:  "/path/to/key.pem",
						},
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
		"listeners": [{
			"name": "test",
			"listen": ":8080",
			"protocol": "udp"
		}]
	}`
	if err := os.WriteFile(cfgPath, []byte(validJSON), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if len(cfg.Listeners) != 1 || cfg.Listeners[0].Name != "test" {
		t.Errorf("unexpected config: %+v", cfg)
	}

	invalidJSON := `{"listeners": [{"listen": ":8080", "protocol": "udp"}]}`
	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte(invalidJSON), 0644); err != nil {
		t.Fatal(err)
	}
	_, err = LoadConfig(badPath)
	if err == nil {
		t.Error("expected error for missing name, got nil")
	}

	_, err = LoadConfig("/nonexistent/config.json")
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "defaults.json")

	json := `{
		"listeners": [{
			"name": "test",
			"listen": ":8080",
			"protocol": ""
		}]
	}`
	if err := os.WriteFile(cfgPath, []byte(json), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if cfg.Listeners[0].Protocol != ProtocolUDP {
		t.Errorf("expected default protocol udp, got %q", cfg.Listeners[0].Protocol)
	}
	if cfg.Listeners[0].ReadTimeoutSec != 30 {
		t.Errorf("expected default read timeout 30, got %d", cfg.Listeners[0].ReadTimeoutSec)
	}
	if cfg.Listeners[0].MaxPacketSize != 65535 {
		t.Errorf("expected default max packet size 65535, got %d", cfg.Listeners[0].MaxPacketSize)
	}
}

func TestTLSConfigHelpers(t *testing.T) {
	t.Run("ReadTimeout default", func(t *testing.T) {
		lc := ListenerConfig{}
		if d := lc.ReadTimeout(); d.Seconds() != 30 {
			t.Errorf("default timeout should be 30s, got %v", d)
		}
	})

	t.Run("ReadTimeout custom", func(t *testing.T) {
		lc := ListenerConfig{TLS: &gw.TLSConfig{IdleTimeoutSec: 60}}
		if d := lc.ReadTimeout(); d.Seconds() != 60 {
			t.Errorf("expected 60s, got %v", d)
		}
	})

	t.Run("AuditMaxSize default", func(t *testing.T) {
		lc := ListenerConfig{}
		if s := lc.AuditMaxSize(); s != 100*1024*1024 {
			t.Errorf("default audit max size should be 100MB, got %d", s)
		}
	})

	t.Run("AuditMaxSize custom", func(t *testing.T) {
		lc := ListenerConfig{TLS: &gw.TLSConfig{AuditMaxSizeMB: 200}}
		if s := lc.AuditMaxSize(); s != 200*1024*1024 {
			t.Errorf("expected 200MB, got %d", s)
		}
	})

	t.Run("AuditMaxBackup default", func(t *testing.T) {
		lc := ListenerConfig{}
		if n := lc.AuditMaxBackupCount(); n != 3 {
			t.Errorf("default backup count should be 3, got %d", n)
		}
	})
}

func TestConfigSave(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "save.json")

	cfg := &Config{
		Locale: "zh",
		Listeners: []ListenerConfig{
			{Name: "test", Listen: ":8080", Protocol: ProtocolUDP},
		},
		configPath: cfgPath,
	}

	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	_, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig() of saved file error = %v", err)
	}
	if loaded.Locale != "zh" {
		t.Errorf("expected locale zh, got %q", loaded.Locale)
	}
	if len(loaded.Listeners) != 1 || loaded.Listeners[0].Name != "test" {
		t.Errorf("unexpected listeners: %+v", loaded.Listeners)
	}
}

func TestConfigSaveRoundTripTLS(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "mtls-roundtrip.json")

	cfg := &Config{
		Listeners: []ListenerConfig{
			{
				Name:     "mtls-test",
				Listen:   ":4435",
				Protocol: ProtocolMTLS,
				TLS: &gw.TLSConfig{
					CACertFile:      "/etc/ca.pem",
					CertFile:        "/etc/cert.pem",
					KeyFile:         "/etc/key.pem",
					CRLURL:          "http://crl.example.com",
					CRLRefreshSec:   300,
					OCSPCacheTTLSec: 60,
					OCSPFallback:    "deny",
					AllowRoles:      []string{"gateway:admin", "gateway:video"},
					MaxConnsPerCert: 5,
				},
				UDPExt: &gw.UDPExtra{
					MaxPktsPerIP: 100,
				},
			},
		},
		configPath: cfgPath,
	}

	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	tlsBlock := loaded.Listeners[0].TLS
	if tlsBlock == nil {
		t.Fatal("TLS config lost after round-trip")
	}
	if tlsBlock.CACertFile != "/etc/ca.pem" {
		t.Errorf("CACertFile = %q, want /etc/ca.pem", tlsBlock.CACertFile)
	}
	if tlsBlock.CRLRefreshSec != 300 {
		t.Errorf("CRLRefreshSec = %d, want 300", tlsBlock.CRLRefreshSec)
	}
	if len(tlsBlock.AllowRoles) != 2 || tlsBlock.AllowRoles[0] != "gateway:admin" {
		t.Errorf("AllowRoles = %v, want [gateway:admin gateway:video]", tlsBlock.AllowRoles)
	}
	if loaded.Listeners[0].UDPExt == nil || loaded.Listeners[0].UDPExt.MaxPktsPerIP != 100 {
		t.Errorf("UDPExt.MaxPktsPerIP = %+v, want 100", loaded.Listeners[0].UDPExt)
	}
}

func TestConfigValidateInvalidMode(t *testing.T) {
	cfg := Config{
		Listeners: []ListenerConfig{
			{Name: "bad", Listen: ":8080", Protocol: "invalid"},
		},
	}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for invalid protocol")
	}
	if err.Error() != "listeners[0] \"bad\": invalid protocol \"invalid\"" {
		t.Errorf("unexpected error: %v", err)
	}
}
