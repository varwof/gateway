// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package udpgw

import (
	"os"
	"strings"
	"testing"

	gw "github.com/varwof/gateway-core"
)

func TestParseKV(t *testing.T) {
	kv := parseKV("name=dns, listen=:5353 ,protocol=udp")
	if kv["name"] != "dns" {
		t.Errorf("name = %q", kv["name"])
	}
	if kv["listen"] != ":5353" {
		t.Errorf("listen = %q", kv["listen"])
	}
	if kv["protocol"] != "udp" {
		t.Errorf("protocol = %q", kv["protocol"])
	}
	if len(parseKV("noequals")) != 0 {
		t.Error("entries without '=' should be skipped")
	}
}

func TestSplitList(t *testing.T) {
	if splitList("") != nil {
		t.Error("empty string should return nil")
	}
	got := splitList("a; b;; c")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestBuildListenerFromKV(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		lc := buildListenerFromKV(parseKV(
			"name=dns,listen=:5353,protocol=udp,read-timeout-sec=10,max-packet-size=4096,routes=1.1.1.1:53;8.8.8.8:53",
		))
		if lc.Name != "dns" || lc.Listen != ":5353" || lc.Protocol != ProtocolUDP {
			t.Errorf("unexpected listener: %+v", lc)
		}
		if lc.ReadTimeoutSec != 10 || lc.MaxPacketSize != 4096 {
			t.Errorf("unexpected timeouts: %+v", lc)
		}
		if lc.TLS != nil {
			t.Error("plain listener should not have TLS config")
		}
		if lc.UDPExt != nil {
			t.Error("plain listener should not have UDPExt config")
		}
		if len(lc.Routes) != 2 || lc.Routes[0].Target != "1.1.1.1:53" {
			t.Errorf("unexpected routes: %+v", lc.Routes)
		}
	})

	t.Run("mtls", func(t *testing.T) {
		lc := buildListenerFromKV(parseKV(
			"name=mtls,listen=:4435,protocol=udp+mtls,ca-cert=/ca.pem,cert=/s.pem,key=/s.key," +
				"allow-roles=gateway:admin;gateway:ops,max-conns-per-cert=4,idle-timeout-sec=60," +
				"disconnect-on-expiry=30,cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,min-tls-version=1.2",
		))
		if lc.TLS == nil {
			t.Fatal("expected TLS config")
		}
		if lc.TLS.CACertFile != "/ca.pem" || lc.TLS.CertFile != "/s.pem" || lc.TLS.KeyFile != "/s.key" {
			t.Errorf("unexpected files: %+v", lc.TLS)
		}
		if len(lc.TLS.AllowRoles) != 2 || lc.TLS.AllowRoles[0] != "gateway:admin" {
			t.Errorf("unexpected roles: %v", lc.TLS.AllowRoles)
		}
		if lc.TLS.MaxConnsPerCert != 4 || lc.TLS.IdleTimeoutSec != 60 {
			t.Errorf("unexpected limits: %+v", lc.TLS)
		}
		if lc.UDPExt == nil || lc.UDPExt.DisconnectOnExpirySec != 30 {
			t.Errorf("disconnect-on-expiry = %+v", lc.UDPExt)
		}
		if len(lc.TLS.CipherSuites) != 1 {
			t.Errorf("cipher suites = %v", lc.TLS.CipherSuites)
		}
		if lc.TLS.MinTLSVersion != "1.2" {
			t.Errorf("min tls version = %q", lc.TLS.MinTLSVersion)
		}
	})

	t.Run("no tls without cert fields", func(t *testing.T) {
		lc := buildListenerFromKV(parseKV("name=x,listen=:1,protocol=udp"))
		if lc.TLS != nil {
			t.Error("TLS should be nil when no cert fields")
		}
		if lc.UDPExt != nil {
			t.Error("UDPExt should be nil when no UDP limit fields")
		}
	})
}

func TestBuildConfigFromCLI(t *testing.T) {
	t.Run("plain listener with management", func(t *testing.T) {
		g := &CLIGlobals{
			MgmtListen: "127.0.0.1:8444",
			MgmtCACert: "/mgmt/ca.pem",
		}
		cfg, err := BuildConfigFromCLI([]string{
			"name=dns,listen=:5353,protocol=udp",
		}, g)
		if err != nil {
			t.Fatalf("BuildConfigFromCLI: %v", err)
		}
		if len(cfg.Listeners) != 1 || cfg.Listeners[0].Name != "dns" {
			t.Fatalf("unexpected listeners: %+v", cfg.Listeners)
		}
		if cfg.Management == nil || cfg.Management.Listen != "127.0.0.1:8444" {
			t.Fatalf("unexpected management: %+v", cfg.Management)
		}
		if cfg.Management.TLS.CACertFile != "/mgmt/ca.pem" {
			t.Errorf("mgmt ca = %q", cfg.Management.TLS.CACertFile)
		}
	})

	t.Run("dtls listener with global overrides", func(t *testing.T) {
		g := &CLIGlobals{
			TSAURL:          "https://tsa.example.com",
			TSACertFile:     "/tsa/cert.pem",
			AuditFile:       "/var/log/audit.json",
			AuditMaxSizeMB:  200,
			AuditMaxBackups: 5,
			CRLRefreshSec:   900,
			OCSPCacheTTLSec: 120,
			OCSPFallback:    "allow",
			TSAProofFile:    "/var/log/proof.json",
		}
		cfg, err := BuildConfigFromCLI([]string{
			"name=dtls,listen=:4434,protocol=dtls,cert=/s.pem,key=/s.key",
		}, g)
		if err != nil {
			t.Fatalf("BuildConfigFromCLI: %v", err)
		}
		tlsBlock := cfg.Listeners[0].TLS
		if tlsBlock == nil {
			t.Fatal("expected TLS config")
		}
		if tlsBlock.TSAURL != "https://tsa.example.com" || tlsBlock.TSACertFile != "/tsa/cert.pem" {
			t.Errorf("tsa overrides missing: %+v", tlsBlock)
		}
		if tlsBlock.AuditFile != "/var/log/audit.json" || tlsBlock.AuditMaxSizeMB != 200 || tlsBlock.AuditMaxBackups != 5 {
			t.Errorf("audit overrides missing: %+v", tlsBlock)
		}
		if tlsBlock.CRLRefreshSec != 900 || tlsBlock.OCSPCacheTTLSec != 120 || tlsBlock.OCSPFallback != "allow" {
			t.Errorf("crl/ocsp overrides missing: %+v", tlsBlock)
		}
		if cfg.TSAProofFile != "/var/log/proof.json" {
			t.Errorf("tsa proof file = %q", cfg.TSAProofFile)
		}
	})

	t.Run("invalid mtls missing ca", func(t *testing.T) {
		_, err := BuildConfigFromCLI([]string{
			"name=mtls,listen=:4435,protocol=udp+mtls,cert=/s.pem,key=/s.key",
		}, &CLIGlobals{})
		if err == nil {
			t.Fatal("expected validation error for mtls without ca_cert_file")
		}
	})

	t.Run("invalid quic missing cert", func(t *testing.T) {
		_, err := BuildConfigFromCLI([]string{
			"name=quic,listen=:4433,protocol=quic",
		}, &CLIGlobals{})
		if err == nil {
			t.Fatal("expected validation error for quic without cert")
		}
	})

	t.Run("empty listener list", func(t *testing.T) {
		cfg, err := BuildConfigFromCLI(nil, &CLIGlobals{})
		if err != nil {
			t.Fatalf("BuildConfigFromCLI: %v", err)
		}
		if len(cfg.Listeners) != 0 {
			t.Errorf("expected 0 listeners, got %d", len(cfg.Listeners))
		}
	})
}

func TestUDPExtDelegationEnabled(t *testing.T) {
	if (&gw.UDPExtra{}).RequireDelegationEnabled() {
		t.Error("nil delegation should be disabled")
	}
	f := false
	if (&gw.UDPExtra{RequireDelegation: &f}).RequireDelegationEnabled() {
		t.Error("false delegation should be disabled")
	}
	tr := true
	if !(&gw.UDPExtra{RequireDelegation: &tr}).RequireDelegationEnabled() {
		t.Error("true delegation should be enabled")
	}
}

func TestTLSDisallowRepresentativeDefault(t *testing.T) {
	// When DisallowRepresentative is nil it falls back to RequireAICEnabled.
	if (&gw.TLSConfig{}).DisallowRepresentativeEnabled() {
		t.Error("nil should default to false")
	}
	tr := true
	if !(&gw.TLSConfig{DisallowRepresentative: &tr}).DisallowRepresentativeEnabled() {
		t.Error("explicit true should be enabled")
	}
	aic := true
	if !(&gw.TLSConfig{RequireAIC: &aic}).DisallowRepresentativeEnabled() {
		t.Error("should fall back to RequireAICEnabled")
	}
}

func TestTLSAuditMaxBackupCountCustom(t *testing.T) {
	if n := (&gw.TLSConfig{AuditMaxBackups: 7}).AuditMaxBackupCount(); n != 7 {
		t.Errorf("AuditMaxBackupCount = %d, want 7", n)
	}
}

func TestConfigSaveNoPath(t *testing.T) {
	cfg := &Config{
		Listeners: []ListenerConfig{{Name: "x", Listen: ":1", Protocol: ProtocolUDP}},
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save(): %v", err)
	}
	// Finding 14: os.CreateTemp generates a high-entropy name (no predictable
	// /tmp path that a local attacker could enumerate/symlink) and opens with
	// O_CREATE|O_EXCL. The saved file must exist and be readable.
	if cfg.configPath == "" {
		t.Fatal("configPath should be set after Save")
	}
	if _, err := os.Stat(cfg.configPath); err != nil {
		t.Fatalf("saved config missing: %v", err)
	}
	os.Remove(cfg.configPath)
}

func TestVersionString(t *testing.T) {
	s := VersionString()
	if !strings.Contains(s, "gateway-udp") {
		t.Errorf("VersionString = %q", s)
	}
}

func TestDefaultConfigPaths(t *testing.T) {
	if dir := DefaultConfigDir(); dir != "/etc/varwof/gateway-udp" {
		t.Errorf("DefaultConfigDir = %q", dir)
	}
	if f := DefaultConfigFile(); f != "/etc/varwof/gateway-udp/gateway-udp.json" {
		t.Errorf("DefaultConfigFile = %q", f)
	}
}

func TestNewGatewayPluginRegistryUDP(t *testing.T) {
	g := NewGateway(&Config{
		CapabilityPlugins: gw.PluginConfigs{
			"scheme-1": {Type: "nonexistent", Config: map[string]interface{}{}},
		},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if g.pluginRegistry == nil {
		t.Fatal("pluginRegistry should be non-nil even with bad plugin")
	}
}

func TestNewGatewayRevokerUDP(t *testing.T) {
	g := NewGateway(&Config{
		VarwofCore: &gw.RevokerConfig{CoreURL: "http://127.0.0.1:1"},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if g.revoker != nil {
		t.Fatal("revoker should be nil for invalid pki-core config")
	}
}

func TestNewGatewayTSAProofUDP(t *testing.T) {
	proof := gw.NewTSAProofLogger("", nil, nil, 0)
	tsa := &gw.TSAClient{}
	g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, tsa, proof)
	if g.auditChain == nil {
		t.Fatal("auditChain should be non-nil")
	}
}
