package httpgw

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	gw "github.com/varwof/gateway-core"
	"github.com/varwof/register/ruleexec"
)

func TestRegisterRulePlugins(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules", "std/database-v1")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rule := `{
		"rule_id": "gw-rule", "version": "1.0.0",
		"scheme": "std/database-v1", "capability": "query:SELECT",
		"params": {"tables": ["customers"], "columns": {"customers": ["id","name"]}, "limit": {"max": 100}},
		"conditions": {"op": "eq", "path": "request.method", "value": "GET"}
	}`
	if err := os.WriteFile(filepath.Join(rulesDir, "v1.0.json"), []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath, cert, err := ruleexec.GenSignerCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	if _, err := ruleexec.PublishRules(filepath.Join(dir, "rules"), outDir, certPath, keyPath); err != nil {
		t.Fatal(err)
	}

	reg := gw.NewPluginRegistry()
	schemes, err := RegisterRulePlugins(reg, outDir, []*x509.Certificate{cert}, nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if len(schemes) != 1 || schemes[0] != "std/database-v1" {
		t.Fatalf("schemes: %v", schemes)
	}

	allow, err := reg.Execute("std/database-v1",
		&gw.Capability{SchemeId: "std/database-v1", CapabilityId: "query:SELECT"},
		&gw.PluginContext{Method: "GET", Target: "query:SELECT"})
	if err != nil || allow.Decision != gw.PluginAllow {
		t.Fatalf("GET should be allowed, got %+v err=%v", allow, err)
	}
	deny, err := reg.Execute("std/database-v1",
		&gw.Capability{SchemeId: "std/database-v1", CapabilityId: "query:SELECT"},
		&gw.PluginContext{Method: "DELETE", Target: "query:SELECT"})
	if err != nil || deny.Decision != gw.PluginDeny {
		t.Fatalf("DELETE should be denied, got %+v err=%v", deny, err)
	}
}
