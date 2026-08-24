// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package httpgw

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

func TestParseKV(t *testing.T) {
	m := parseKV("a=1, b=2, c")
	if m["a"] != "1" || m["b"] != "2" {
		t.Fatalf("parseKV = %v, want a=1 b=2", m)
	}
	if _, ok := m["c"]; ok {
		t.Fatalf("parseKV should drop entries without '=': %v", m)
	}
	m = parseKV("")
	if len(m) != 0 {
		t.Fatalf("parseKV('') = %v, want empty", m)
	}
}

func TestSplitList(t *testing.T) {
	if got := splitList(""); got != nil {
		t.Fatalf("splitList('') = %v, want nil", got)
	}
	got := splitList("a; b;; c;")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("splitList = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitList = %v, want %v", got, want)
		}
	}
}

func TestParseInt(t *testing.T) {
	if got := parseInt(""); got != 0 {
		t.Fatalf("parseInt('') = %d, want 0", got)
	}
	if got := parseInt("42"); got != 42 {
		t.Fatalf("parseInt('42') = %d, want 42", got)
	}
	if got := parseInt("notnum"); got != 0 {
		t.Fatalf("parseInt('notnum') = %d, want 0", got)
	}
}

func TestBuildListenerFromKV(t *testing.T) {
	lc := buildListenerFromKV(map[string]string{
		"name":                    "l1",
		"listen":                  ":8443",
		"protocol":                "http2",
		"tls-mode":                "mtls",
		"ca-cert":                 "/p/ca.pem",
		"cert":                    "/p/cert.pem",
		"key":                     "/p/key.pem",
		"crl-url":                 "http://crl",
		"crl-refresh-sec":         "30",
		"ocsp-cache-ttl-sec":      "20",
		"ocsp-fallback":           "deny",
		"tsa-url":                 "https://tsa",
		"tsa-cert-file":           "/p/tsa.pem",
		"audit-file":              "/var/log/audit.log",
		"max-conns-per-ip":        "5",
		"max-total-conns":         "100",
		"idle-timeout-sec":        "60",
		"audit-max-size-mb":       "7",
		"audit-max-backups":       "2",
		"cipher-suites":           "TLS_AES_128_GCM_SHA256;TLS_AES_256_GCM_SHA384",
		"min-tls-version":         "1.2",
		"disconnect-on-expiry":    "false",
		"forward-client-cert":     "false",
		"forward-client-cert-der": "true",
		"tls-termination":         "false",
	})
	if lc.TLS == nil {
		t.Fatal("expected TLS config for mtls mode")
	}
	if lc.TLS.CRLRefreshSec != 30 || lc.TLS.OCSPCacheTTLSec != 20 {
		t.Fatalf("ints not parsed: %+v", lc.TLS)
	}
	if lc.TLS.MaxConnsPerIP != 5 || lc.TLS.MaxTotalConns != 100 || lc.TLS.IdleTimeoutSec != 60 {
		t.Fatalf("conn limits not parsed: %+v", lc.TLS)
	}
	if lc.TLS.AuditMaxSizeMB != 7 || lc.TLS.AuditMaxBackups != 2 {
		t.Fatalf("audit limits not parsed: %+v", lc.TLS)
	}
	if len(lc.TLS.CipherSuites) != 2 {
		t.Fatalf("cipher suites = %v", lc.TLS.CipherSuites)
	}
	if lc.TLS.DisconnectOnExpiryEnabled() {
		t.Fatal("disconnect-on-expiry=false not honored")
	}
	if lc.HTTPExt.ForwardClientCertEnabled() {
		t.Fatal("forward-client-cert=false not honored")
	}
	if !lc.HTTPExt.ForwardClientCertDEREnabled() {
		t.Fatal("forward-client-cert-der=true not honored")
	}
	if lc.HTTPExt.TLSTerminationEnabled() {
		t.Fatal("tls-termination=false not honored")
	}
}

func TestBuildListenerFromKVPlain(t *testing.T) {
	lc := buildListenerFromKV(map[string]string{
		"name": "l1", "listen": ":8080", "protocol": "http2", "tls-mode": "plain",
	})
	if lc.TLS != nil {
		t.Fatalf("plain mode should not build TLS config, got %+v", lc.TLS)
	}
}

func TestBuildConfigFromCLI(t *testing.T) {
	g := &CLIGlobals{CRLRefreshSec: 99, OCSPCacheTTLSec: 88, OCSPFallback: "allow", AuditMaxSizeMB: 7, AuditMaxBackups: 4}
	cfg, err := BuildConfigFromCLI(
		[]string{
			"name=l1,listen=:8443,protocol=http2,tls-mode=mtls,ca-cert=/p/ca.pem,cert=/p/c.pem,key=/p/k.pem",
			"name=l2,listen=:9443,protocol=http2,tls-mode=mtls,ca-cert=/p/ca.pem,crl-refresh-sec=30,ocsp-cache-ttl-sec=20,ocsp-fallback=deny,audit-max-size-mb=5,audit-max-backups=2",
		},
		[]string{
			"listener=l1,path=/api/*,target=http://be:8080,allow-roles=gateway:admin;gateway:ops",
			"listener=l2,path=/,target=http://web:3000",
		},
		g,
	)
	if err != nil {
		t.Fatalf("BuildConfigFromCLI: %v", err)
	}
	if len(cfg.Listeners) != 2 {
		t.Fatalf("listeners = %d, want 2", len(cfg.Listeners))
	}
	l1 := cfg.Listeners[0]
	if l1.Name != "l1" || l1.TLS == nil || l1.TLS.CACertFile != "/p/ca.pem" {
		t.Fatalf("l1 = %+v", l1)
	}
	if l1.TLS.CRLRefreshSec != 99 || l1.TLS.OCSPCacheTTLSec != 88 {
		t.Fatalf("l1 should inherit globals: %+v", l1.TLS)
	}
	if l1.TLS.OCSPFallback != "allow" || l1.TLS.AuditMaxSizeMB != 7 || l1.TLS.AuditMaxBackups != 4 {
		t.Fatalf("l1 should inherit globals: %+v", l1.TLS)
	}
	if len(l1.Routes) != 1 || l1.Routes[0].Path != "/api/*" || l1.Routes[0].Target != "http://be:8080" {
		t.Fatalf("l1 routes = %+v", l1.Routes)
	}
	if len(l1.Routes[0].AllowRoles) != 2 {
		t.Fatalf("l1 allow-roles = %v", l1.Routes[0].AllowRoles)
	}
	l2 := cfg.Listeners[1]
	if l2.TLS.CRLRefreshSec != 30 || l2.TLS.OCSPCacheTTLSec != 20 {
		t.Fatalf("l2 should keep explicit values: %+v", l2.TLS)
	}
	if l2.TLS.OCSPFallback != "deny" || l2.TLS.AuditMaxSizeMB != 5 || l2.TLS.AuditMaxBackups != 2 {
		t.Fatalf("l2 explicit values not honored: %+v", l2.TLS)
	}
}

func TestBuildConfigFromCLIErrors(t *testing.T) {
	_, err := BuildConfigFromCLI(
		[]string{"name=l1,listen=:8443,protocol=http2,tls-mode=plain"},
		[]string{"listener=unknown,path=/,target=http://x"},
		&CLIGlobals{},
	)
	if err == nil {
		t.Fatal("expected error for unknown listener reference")
	}

	_, err = BuildConfigFromCLI(
		[]string{"name=l1,listen=:8443,protocol=http2,tls-mode=plain"},
		nil,
		&CLIGlobals{},
	)
	if err == nil {
		t.Fatal("expected validation error for listener without routes")
	}
}

func TestBuildConfigFromCLIMgmt(t *testing.T) {
	cfg, err := BuildConfigFromCLI(nil, nil, &CLIGlobals{
		MgmtListen:       "127.0.0.1:0",
		MgmtCACert:       "/p/ca.pem",
		MgmtCert:         "/p/c.pem",
		MgmtKey:          "/p/k.pem",
		MgmtCRLURL:       "http://crl",
		MgmtOCSPFallback: "deny",
	})
	if err != nil {
		t.Fatalf("BuildConfigFromCLI: %v", err)
	}
	if cfg.Management == nil || cfg.Management.Listen != "127.0.0.1:0" {
		t.Fatalf("management = %+v", cfg.Management)
	}
	if cfg.Management.TLS.CACertFile != "/p/ca.pem" || cfg.Management.TLS.CRLURL != "http://crl" {
		t.Fatalf("management tls = %+v", cfg.Management.TLS)
	}
	if cfg.Management.TLS.OCSPFallback != "deny" {
		t.Fatalf("management ocsp fallback = %q", cfg.Management.TLS.OCSPFallback)
	}
}

func TestMTLSBoolGetters(t *testing.T) {
	var m *gw.TLSConfig
	if !m.DisconnectOnExpiryEnabled() {
		t.Fatal("nil: DisconnectOnExpiryEnabled should default true")
	}
	if m.RequireAICEnabled() {
		t.Fatal("nil: RequireAICEnabled should be false")
	}
	if m.DisallowRepresentativeEnabled() {
		t.Fatal("nil: DisallowRepresentativeEnabled should default to RequireAIC=false")
	}
	if m.RequireUserAuthEnabled() {
		t.Fatal("nil: RequireUserAuthEnabled should be false")
	}
	var h *gw.HTTPExtra
	if !h.ForwardClientCertEnabled() {
		t.Fatal("nil: ForwardClientCertEnabled should default true")
	}
	if !h.TLSTerminationEnabled() {
		t.Fatal("nil: TLSTerminationEnabled should default true")
	}

	f, tru := false, true
	m = &gw.TLSConfig{DisconnectOnExpiry: &f}
	if m.DisconnectOnExpiryEnabled() {
		t.Fatal("DisconnectOnExpiry=false not honored")
	}
	m = &gw.TLSConfig{RequireAIC: &tru}
	if !m.RequireAICEnabled() {
		t.Fatal("RequireAIC=true not honored")
	}
	if !m.DisallowRepresentativeEnabled() {
		t.Fatal("DisallowRepresentative should default to RequireAIC=true")
	}
	m = &gw.TLSConfig{RequireAIC: &tru, DisallowRepresentative: &f}
	if m.DisallowRepresentativeEnabled() {
		t.Fatal("explicit DisallowRepresentative=false not honored")
	}
	m = &gw.TLSConfig{RequireUserAuth: &tru}
	if !m.RequireUserAuthEnabled() {
		t.Fatal("RequireUserAuth=true not honored")
	}
	h = &gw.HTTPExtra{ForwardClientCert: &f}
	if h.ForwardClientCertEnabled() {
		t.Fatal("ForwardClientCert=false not honored")
	}
	h = &gw.HTTPExtra{TLSTermination: &f}
	if h.TLSTerminationEnabled() {
		t.Fatal("TLSTermination=false not honored")
	}
}

func TestMTLSDurationGetters(t *testing.T) {
	m := &gw.TLSConfig{
		CRLRefreshSec:   60,
		AuditMaxSizeMB:  4,
		AuditMaxBackups: 7,
		IdleTimeoutSec:  15,
	}
	if m.CRLRefreshDuration() != time.Minute {
		t.Fatalf("CRLRefreshDuration = %v", m.CRLRefreshDuration())
	}
	if m.AuditMaxSize() != 4*1024*1024 {
		t.Fatalf("AuditMaxSize = %d", m.AuditMaxSize())
	}
	if m.AuditMaxBackupCount() != 7 {
		t.Fatalf("AuditMaxBackupCount = %d", m.AuditMaxBackupCount())
	}
	if m.IdleTimeout() != 15*time.Second {
		t.Fatalf("IdleTimeout = %v", m.IdleTimeout())
	}

	m = &gw.TLSConfig{}
	if m.CRLRefreshDuration() != 5*time.Minute {
		t.Fatalf("default CRLRefreshDuration = %v", m.CRLRefreshDuration())
	}
	if m.AuditMaxSize() != 100*1024*1024 {
		t.Fatalf("default AuditMaxSize = %d", m.AuditMaxSize())
	}
	if m.AuditMaxBackupCount() != 3 {
		t.Fatalf("default AuditMaxBackupCount = %d", m.AuditMaxBackupCount())
	}
	if m.IdleTimeout() != 0 {
		t.Fatalf("default IdleTimeout = %v", m.IdleTimeout())
	}
}

func TestConfigSetDefaults(t *testing.T) {
	c := &Config{}
	c.SetDefaults()
	if c.Listeners == nil {
		t.Fatal("SetDefaults should initialize Listeners")
	}
}

func TestConfigSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	c := &Config{
		configPath: path,
		Listeners: []ListenerConfig{{
			Name: "l1", Listen: ":8443", Protocol: ProtocolHTTP2,
			Routes: []RouteConfig{{Path: "/", Target: "http://b"}},
		}},
	}
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Listeners) != 1 || cfg.Listeners[0].Name != "l1" {
		t.Fatalf("reloaded config = %+v", cfg.Listeners)
	}
}

func TestConfigSaveDefaultPath(t *testing.T) {
	c := &Config{}
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	defer os.Remove(c.configPath)
	if c.configPath == "" {
		t.Fatal("Save should assign a default config path")
	}
}

func TestLoadConfigErrors(t *testing.T) {
	if _, err := LoadConfig("/nonexistent/gateway-http.json"); err == nil {
		t.Fatal("expected error for missing file")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{invalid"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected parse error for invalid JSON")
	}

	bad := filepath.Join(dir, "invalid-cfg.json")
	data := `{"listeners":[{"name":"","listen":":1","protocol":"http2","routes":[{"path":"/","target":"http://b"}]}]}`
	if err := os.WriteFile(bad, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(bad); err == nil {
		t.Fatal("expected validation error for missing listener name")
	}
}
