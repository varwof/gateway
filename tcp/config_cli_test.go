package tcpgw

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

func TestParseKV(t *testing.T) {
	got := parseKV("name=web, listen=:443,target=127.0.0.1:8080,bad-entry")
	want := map[string]string{
		"name":   "web",
		"listen": ":443",
		"target": "127.0.0.1:8080",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseKV() = %v, want %v", got, want)
	}

	empty := parseKV("")
	if len(empty) != 0 {
		t.Fatalf("parseKV(\"\") = %v, want empty", empty)
	}
}

func TestSplitList(t *testing.T) {
	if got := splitList(""); got != nil {
		t.Fatalf("splitList(\"\") = %v, want nil", got)
	}
	if got := splitList("gateway:admin; gateway:ops;  "); !reflect.DeepEqual(got, []string{"gateway:admin", "gateway:ops"}) {
		t.Fatalf("splitList = %v", got)
	}
	if got := splitList("  ;  ;"); len(got) != 0 {
		t.Fatalf("splitList(blank) = %v, want empty", got)
	}
}

func TestParseInt(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"0", 0},
		{"42", 42},
		{"-1", -1},
		{"not-a-number", 0},
	}
	for _, tt := range tests {
		if got := parseInt(tt.in); got != tt.want {
			t.Errorf("parseInt(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestBuildMappingFromKVPlain(t *testing.T) {
	mc := buildMappingFromKV(map[string]string{
		"name": "plain", "listen": "127.0.0.1:9000", "target": "10.0.0.1:22", "protocol": "tcp",
	})
	if mc.Protocol != ProtocolTCP {
		t.Fatalf("Protocol = %q", mc.Protocol)
	}
	if mc.TLS != nil {
		t.Fatalf("expected nil TLS for plain tcp, got %+v", mc.TLS)
	}
}

func TestBuildMappingFromKVMTLS(t *testing.T) {
	mc := buildMappingFromKV(map[string]string{
		"name": "mtls", "listen": ":8443", "target": "127.0.0.1:443",
		"protocol": "tcp+mtls", "ca-cert": "/etc/ca.pem", "cert": "/etc/cert.pem",
		"key": "/etc/key.pem", "crl-url": "http://crl/root.crl",
		"crl-refresh-sec": "300", "ocsp-cache-ttl-sec": "120", "ocsp-fallback": "allow",
		"tsa-url": "http://tsa", "tsa-cert-file": "/etc/tsa.pem",
		"allow-roles": "gateway:admin;gateway:ops", "audit-file": "/var/log/audit.log",
		"max-conns-per-ip": "10", "max-total-conns": "100", "idle-timeout-sec": "60",
		"health-check-sec": "5", "health-check-url": "http://hc",
		"audit-max-size-mb": "50", "audit-max-backups": "5",
		"cipher-suites": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;TLS_AES_128_GCM_SHA256",
		"min-tls-version": "1.2",
		"disconnect-on-expiry": "false",
	})
	if mc.Protocol != ProtocolTCPMTLS || mc.TLS == nil {
		t.Fatalf("expected tcp+mtls with TLS block, got %q %+v", mc.Protocol, mc.TLS)
	}
	if mc.TLS.CACertFile != "/etc/ca.pem" || mc.TLS.CRLRefreshSec != 300 || mc.TLS.OCSPCacheTTLSec != 120 {
		t.Fatalf("TLS fields wrong: %+v", mc.TLS)
	}
	if mc.TLS.OCSPFallback != "allow" || mc.TLS.TSAURL != "http://tsa" {
		t.Fatalf("TLS TSA/OCSP wrong: %+v", mc.TLS)
	}
	if !reflect.DeepEqual(mc.TLS.AllowRoles, []string{"gateway:admin", "gateway:ops"}) {
		t.Fatalf("AllowRoles = %v", mc.TLS.AllowRoles)
	}
	if mc.TLS.MaxConnsPerIP != 10 || mc.TLS.MaxTotalConns != 100 || mc.TLS.IdleTimeoutSec != 60 {
		t.Fatalf("TLS limits wrong: %+v", mc.TLS)
	}
	if mc.TCPExt == nil || mc.TCPExt.HealthCheckSec != 5 || mc.TCPExt.HealthCheckURL != "http://hc" {
		t.Fatalf("TCPExt healthcheck wrong: %+v", mc.TCPExt)
	}
	if mc.TLS.AuditMaxSizeMB != 50 || mc.TLS.AuditMaxBackups != 5 {
		t.Fatalf("TLS audit wrong: %+v", mc.TLS)
	}
	if len(mc.TLS.CipherSuites) != 2 || mc.TLS.MinTLSVersion != "1.2" {
		t.Fatalf("TLS cipher/version wrong: %+v", mc.TLS)
	}
	if mc.TLS.DisconnectOnExpiry == nil || *mc.TLS.DisconnectOnExpiry {
		t.Fatalf("DisconnectOnExpiry should be false, got %+v", mc.TLS.DisconnectOnExpiry)
	}
}

func TestBuildMappingFromKVDisconnectOnExpiryDefault(t *testing.T) {
	mc := buildMappingFromKV(map[string]string{
		"name": "m", "listen": ":1", "target": "x:2", "protocol": "tcp+mtls", "ca-cert": "/c",
	})
	if mc.TLS == nil || mc.TLS.DisconnectOnExpiry != nil {
		t.Fatalf("expected nil DisconnectOnExpiry, got %+v", mc.TLS)
	}
}

func TestBuildTunnelFromKV(t *testing.T) {
	tc := buildTunnelFromKV(map[string]string{
		"name": "t1", "listen": "127.0.0.1:2222", "gateway-addr": "gw:443",
		"cert-file": "/c/cert.pem", "key-file": "/c/key.pem", "ca-cert-file": "/c/ca.pem",
	})
	want := TunnelConfig{
		Name: "t1", Listen: "127.0.0.1:2222", GatewayAddr: "gw:443",
		CertFile: "/c/cert.pem", KeyFile: "/c/key.pem", CACertFile: "/c/ca.pem",
	}
	if tc != want {
		t.Fatalf("buildTunnelFromKV() = %+v, want %+v", tc, want)
	}
}

func TestBuildConfigFromCLI(t *testing.T) {
	g := &CLIGlobals{
		CRLRefreshSec: 400, OCSPCacheTTLSec: 250, OCSPFallback: "deny",
		TSAURL: "http://tsa.example", TSACertFile: "/etc/tsa.pem",
		AuditFile: "/var/log/audit.log", AuditMaxSizeMB: 20, AuditMaxBackups: 4,
	}
	cfg, err := BuildConfigFromCLI([]string{
		"name=web,listen=127.0.0.1:8443,target=10.0.0.1:443,protocol=tcp+mtls,ca-cert=/etc/ca.pem",
	}, []string{
		"name=tun,listen=127.0.0.1:2222,gateway-addr=gw:443,cert-file=/c/c.pem,key-file=/c/k.pem,ca-cert-file=/c/ca.pem",
	}, g)
	if err != nil {
		t.Fatalf("BuildConfigFromCLI: %v", err)
	}
	if len(cfg.Mappings) != 1 || len(cfg.Tunnels) != 1 {
		t.Fatalf("got %d mappings, %d tunnels", len(cfg.Mappings), len(cfg.Tunnels))
	}
	m := cfg.Mappings[0]
	if m.Name != "web" || m.Listen != "127.0.0.1:8443" || m.Target != "10.0.0.1:443" {
		t.Fatalf("mapping = %+v", m)
	}
	if m.TLS == nil {
		t.Fatal("expected TLS block")
	}
	if m.TLS.CRLRefreshSec != 400 || m.TLS.OCSPCacheTTLSec != 250 {
		t.Fatalf("globals not applied: %+v", m.TLS)
	}
	if m.TLS.OCSPFallback != "deny" || m.TLS.TSAURL != "http://tsa.example" || m.TLS.TSACertFile != "/etc/tsa.pem" {
		t.Fatalf("globals not applied: %+v", m.TLS)
	}
	if m.TLS.AuditFile != "/var/log/audit.log" || m.TLS.AuditMaxSizeMB != 20 || m.TLS.AuditMaxBackups != 4 {
		t.Fatalf("audit globals not applied: %+v", m.TLS)
	}
	if cfg.Tunnels[0].Name != "tun" || cfg.Tunnels[0].GatewayAddr != "gw:443" {
		t.Fatalf("tunnel = %+v", cfg.Tunnels[0])
	}
}

func TestBuildConfigFromCLIManagement(t *testing.T) {
	g := &CLIGlobals{
		MgmtListen: "127.0.0.1:8081", MgmtCACert: "/etc/mgmt-ca.pem",
		MgmtCert: "/etc/mgmt-cert.pem", MgmtKey: "/etc/mgmt-key.pem",
		MgmtCRLURL: "http://crl/mgmt.crl", MgmtOCSPFallback: "allow",
	}
	cfg, err := BuildConfigFromCLI(nil, nil, g)
	if err != nil {
		t.Fatalf("BuildConfigFromCLI: %v", err)
	}
	if cfg.Management == nil {
		t.Fatal("expected management config")
	}
	if cfg.Management.Listen != "127.0.0.1:8081" {
		t.Fatalf("listen = %q", cfg.Management.Listen)
	}
	if cfg.Management.TLS == nil ||
		cfg.Management.TLS.CACertFile != "/etc/mgmt-ca.pem" ||
		cfg.Management.TLS.CRLURL != "http://crl/mgmt.crl" ||
		cfg.Management.TLS.OCSPFallback != "allow" {
		t.Fatalf("mgmt TLS = %+v", cfg.Management.TLS)
	}
}

func TestBuildConfigFromCLIValidationError(t *testing.T) {
	if _, err := BuildConfigFromCLI([]string{"name=x,protocol=tcp"}, nil, &CLIGlobals{}); err == nil {
		t.Fatal("expected validation error for missing listen/target")
	}
}

func TestMappingConfigFlagGetters(t *testing.T) {
	tr := true
	fa := false

	// nil TLS/TCPExt blocks fall back to safe defaults.
	m := &MappingConfig{}
	if !m.DisconnectOnExpiryEnabled() {
		t.Error("nil TLS: DisconnectOnExpiryEnabled should default true")
	}
	if m.RequireAICEnabled() || m.DisallowRepresentativeEnabled() || m.RequireUserAuthEnabled() {
		t.Error("nil TLS: auth flags should be false")
	}
	if m.RequireDelegationEnabled() || m.RenewalEnabledOrDefault() {
		t.Error("nil TCPExt: delegation/renewal flags should be false")
	}
	if got := m.RenewalWindow(); got != 2*time.Minute {
		t.Errorf("default RenewalWindow = %v", got)
	}
	if got := m.SessionTimeout(); got != 0 {
		t.Errorf("default SessionTimeout = %v", got)
	}
	if got := m.AuditMaxSize(); got != 100*1024*1024 {
		t.Errorf("default AuditMaxSize = %d", got)
	}
	if got := m.AuditMaxBackupCount(); got != 3 {
		t.Errorf("default AuditMaxBackupCount = %d", got)
	}

	m.TLS = &gw.TLSConfig{}
	m.TLS.DisconnectOnExpiry = &fa
	if m.DisconnectOnExpiryEnabled() {
		t.Error("DisconnectOnExpiryEnabled should be false")
	}
	m.TLS.DisconnectOnExpiry = &tr
	if !m.DisconnectOnExpiryEnabled() {
		t.Error("DisconnectOnExpiryEnabled should be true")
	}

	m.TLS.RequireAIC = &tr
	if !m.RequireAICEnabled() {
		t.Error("RequireAICEnabled should be true")
	}
	if !m.DisallowRepresentativeEnabled() {
		t.Error("DisallowRepresentativeEnabled should fall back to RequireAIC")
	}
	m.TLS.DisallowRepresentative = &fa
	if m.DisallowRepresentativeEnabled() {
		t.Error("DisallowRepresentativeEnabled should be false")
	}

	m.TLS.RequireUserAuth = &tr
	if !m.RequireUserAuthEnabled() {
		t.Error("RequireUserAuthEnabled should be true")
	}

	m.TCPExt = &gw.TCPExtra{RequireDelegation: &tr, RenewalEnabled: &tr, RenewalWindowSec: 90, SessionTimeoutSec: 30}
	if !m.RequireDelegationEnabled() {
		t.Error("RequireDelegationEnabled should be true")
	}
	if !m.RenewalEnabledOrDefault() {
		t.Error("RenewalEnabledOrDefault should be true")
	}
	if got := m.RenewalWindow(); got != 90*time.Second {
		t.Errorf("RenewalWindow = %v", got)
	}
	if got := m.SessionTimeout(); got != 30*time.Second {
		t.Errorf("SessionTimeout = %v", got)
	}

	m.TLS.AuditMaxSizeMB = 7
	if got := m.AuditMaxSize(); got != 7*1024*1024 {
		t.Errorf("AuditMaxSize = %d", got)
	}
	m.TLS.AuditMaxBackups = 9
	if got := m.AuditMaxBackupCount(); got != 9 {
		t.Errorf("AuditMaxBackupCount = %d", got)
	}
}

func TestMappingConfigDurationGetters(t *testing.T) {
	m := &MappingConfig{}
	if got := m.CRLRefreshDuration(); got != 5*time.Minute {
		t.Errorf("CRLRefreshDuration = %v", got)
	}
	if got := m.IdleTimeout(); got != 0 {
		t.Errorf("IdleTimeout = %v", got)
	}
	if got := m.MaxConnectionDuration(); got != 0 {
		t.Errorf("MaxConnectionDuration = %v", got)
	}
	if got := m.HealthCheckInterval(); got != 0 {
		t.Errorf("HealthCheckInterval = %v", got)
	}
	if got := m.DialTimeout(); got != 10*time.Second {
		t.Errorf("DialTimeout = %v", got)
	}

	m.TLS = &gw.TLSConfig{CRLRefreshSec: 60, IdleTimeoutSec: 15}
	m.TCPExt = &gw.TCPExtra{MaxConnectionDurationSec: 600, HealthCheckSec: 3, DialTimeoutSec: 4, ConstraintRecheckSec: 120}
	if got := m.CRLRefreshDuration(); got != 60*time.Second {
		t.Errorf("CRLRefreshDuration = %v", got)
	}
	if got := m.IdleTimeout(); got != 15*time.Second {
		t.Errorf("IdleTimeout = %v", got)
	}
	if got := m.MaxConnectionDuration(); got != 600*time.Second {
		t.Errorf("MaxConnectionDuration = %v", got)
	}
	if got := m.HealthCheckInterval(); got != 3*time.Second {
		t.Errorf("HealthCheckInterval = %v", got)
	}
	if got := m.DialTimeout(); got != 4*time.Second {
		t.Errorf("DialTimeout = %v", got)
	}
	if got := m.ConstraintRecheckInterval(); got != 120*time.Second {
		t.Errorf("ConstraintRecheckInterval = %v", got)
	}
}

func TestConfigSaveAndDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")

	cfg := &Config{
		Mappings: []MappingConfig{{
			Name: "a", Listen: "127.0.0.1:1", Target: "x:2", Protocol: ProtocolTCP,
		}},
		configPath: path,
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved: %v", err)
	}
	var got Config
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal saved: %v", err)
	}
	if len(got.Mappings) != 1 || got.Mappings[0].Name != "a" {
		t.Fatalf("saved config mismatch: %+v", got)
	}
	if got.configPath != "" {
		t.Fatalf("configPath leaked into JSON? %q", got.configPath)
	}
}

func TestConfigSaveDefaultPath(t *testing.T) {
	cfg := &Config{}
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save with empty configPath: %v", err)
	}
	if cfg.configPath == "" {
		t.Fatal("configPath should be set after Save")
	}
	data, err := os.ReadFile(cfg.configPath)
	if err != nil {
		t.Fatalf("read default path %s: %v", cfg.configPath, err)
	}
	var got Config
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

func TestConfigSaveError(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{configPath: filepath.Join(dir, "no", "such", "dir", "cfg.json")}
	if err := cfg.Save(); err == nil {
		t.Fatal("expected Save error for invalid path")
	}
}

func TestSetDefaults(t *testing.T) {
	cfg := &Config{}
	cfg.SetDefaults()
	if cfg.Mappings == nil || cfg.Tunnels == nil {
		t.Fatalf("SetDefaults: mappings=%v tunnels=%v", cfg.Mappings, cfg.Tunnels)
	}
	if len(cfg.Mappings) != 0 || len(cfg.Tunnels) != 0 {
		t.Fatalf("SetDefaults should produce empty non-nil slices")
	}
}

func TestVersionString(t *testing.T) {
	s := VersionString()
	if s == "" {
		t.Fatal("VersionString returned empty")
	}
}

func TestDefaultConfigPaths(t *testing.T) {
	if got := DefaultConfigDir(); got == "" {
		t.Fatal("DefaultConfigDir empty")
	}
	if got := DefaultConfigFile(); got == "" {
		t.Fatal("DefaultConfigFile empty")
	}
}
