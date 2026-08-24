package httpgw

import (
	"os"
	"path/filepath"
	"testing"

	gw "github.com/varwof/gateway-core"
	"github.com/varwof/register/ruleexec"
)

// TestHTTPGateway_RuleSchemesOptIn verifies that the default config
// (no rule_schemes) leaves the plugin registry empty (backward compat).
func TestHTTPGateway_RuleSchemesOptIn(t *testing.T) {
	g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
	if g == nil {
		t.Fatal("NewGateway() returned nil")
	}
	if g.pluginRegistry.Len() != 0 {
		t.Fatalf("expected empty plugin registry without rule_schemes, got %d", g.pluginRegistry.Len())
	}
}

// TestHTTPGateway_RuleSchemesEnabled verifies that configuring
// rule_schemes loads the published signed rules into the gateway's
// capability plugin registry, and the plugins evaluate HTTP facts.
func TestHTTPGateway_RuleSchemesEnabled(t *testing.T) {
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
	certPath, keyPath, _, err := ruleexec.GenSignerCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	if _, err := ruleexec.PublishRules(filepath.Join(dir, "rules"), outDir, certPath, keyPath); err != nil {
		t.Fatal(err)
	}

	g := NewGateway(&Config{RuleSchemes: outDir, RuleSignerCert: certPath}, NewBundle(), "en", nil, nil, nil, nil)
	if g == nil {
		t.Fatal("NewGateway() returned nil")
	}
	if g.pluginRegistry.Len() != 1 {
		t.Fatalf("expected 1 rule plugin, got %d", g.pluginRegistry.Len())
	}
	if _, err := g.pluginRegistry.Find("std/database-v1"); err != nil {
		t.Fatalf("scheme not registered: %v", err)
	}

	allow, err := g.pluginRegistry.Execute("std/database-v1",
		&gw.Capability{SchemeId: "std/database-v1", CapabilityId: "query:SELECT"},
		&gw.PluginContext{Method: "GET", Target: "query:SELECT"})
	if err != nil || allow.Decision != gw.PluginAllow {
		t.Fatalf("GET should be allowed, got %+v err=%v", allow, err)
	}
	deny, err := g.pluginRegistry.Execute("std/database-v1",
		&gw.Capability{SchemeId: "std/database-v1", CapabilityId: "query:SELECT"},
		&gw.PluginContext{Method: "DELETE", Target: "query:SELECT"})
	if err != nil || deny.Decision != gw.PluginDeny {
		t.Fatalf("DELETE should be denied, got %+v err=%v", deny, err)
	}
}
