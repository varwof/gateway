package httpgw

import (
	"os"
	"path/filepath"
	"testing"

	gw "github.com/varwof/gateway-core"
)

// TestHTTPGateway_CapabilitySchemesOptIn verifies that the default config with
// empty capability_schemes does not set the global registry (backward compat,
// data plane does not validate capability registration).
func TestHTTPGateway_CapabilitySchemesOptIn(t *testing.T) {
	gw.SetGlobalCapabilityRegistry(nil)
	defer gw.SetGlobalCapabilityRegistry(nil)

	g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
	if g == nil {
		t.Fatal("NewGateway() returned nil")
	}
	if g.capReg != nil {
		t.Fatal("expected no capability registry when capability_schemes unset")
	}
	if got := gw.GetGlobalCapabilityRegistry(); got != nil {
		t.Fatal("expected global registry unset when capability_schemes unset")
	}
}

// TestHTTPGateway_CapabilitySchemesEnabled verifies that after explicitly configuring
// capability_schemes, the global registry is set and data plane capability validation
// takes effect (unregistered capabilities are rejected).
func TestHTTPGateway_CapabilitySchemesEnabled(t *testing.T) {
	gw.SetGlobalCapabilityRegistry(nil)
	defer gw.SetGlobalCapabilityRegistry(nil)

	dir := t.TempDir()
	schemeDir := filepath.Join(dir, "varwof", "core")
	if err := os.MkdirAll(schemeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(schemeDir, "v1.json"), []byte(overrideCoreJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	g := NewGateway(&Config{CapabilitySchemes: dir}, NewBundle(), "en", nil, nil, nil, nil)
	if g == nil {
		t.Fatal("NewGateway() returned nil")
	}
	if g.capReg == nil || !g.capReg.Enabled() {
		t.Fatal("expected capability registry loaded")
	}
	cr := gw.GetGlobalCapabilityRegistry()
	if cr == nil {
		t.Fatal("expected global registry set")
	}
	if err := cr.ValidateCapability("varwof/core:cert:issue"); err != nil {
		t.Errorf("expected registered capability valid: %v", err)
	}
	if err := cr.ValidateCapability("varwof/core:not:registered"); err == nil {
		t.Error("expected unregistered capability to fail")
	}
}

// TestHTTPGateway_ReloadCapabilitySchemes verifies SIGHUP Reload hot-reloads the capability registry.
func TestHTTPGateway_ReloadCapabilitySchemes(t *testing.T) {
	gw.SetGlobalCapabilityRegistry(nil)
	defer gw.SetGlobalCapabilityRegistry(nil)

	dir := t.TempDir()
	schemeDir := filepath.Join(dir, "varwof", "core")
	if err := os.MkdirAll(schemeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(schemeDir, "v1.json"), []byte(overrideCoreJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	g := NewGateway(&Config{CapabilitySchemes: dir}, NewBundle(), "en", nil, nil, nil, nil)
	if g.capReg == nil {
		t.Fatal("expected capability registry loaded on NewGateway")
	}

	// Write a new version: add cap audit:export, verify it takes effect after reload
	updated := `{
  "scheme_id": "varwof/core",
  "version": "2",
  "name": "varwof core (v2)",
  "capabilities": [
    {"id": "cert:issue", "name": "Issue", "summary": "s", "usage": "u", "when_not": "n", "examples": ["e"]},
    {"id": "audit:export", "name": "Export", "summary": "s", "usage": "u", "when_not": "n", "examples": ["e"]}
  ],
  "roles": {
    "admin": {"display_name": "Admin", "grants": ["*"]}
  }
}`
	if err := os.WriteFile(filepath.Join(schemeDir, "v1.json"), []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}

	// Directly call reload logic (bypassing file lock/port binding)
	g.loadCapabilityRegistry(&Config{CapabilitySchemes: dir})
	if err := gw.GetGlobalCapabilityRegistry().ValidateCapability("varwof/core:audit:export"); err != nil {
		t.Errorf("expected reloaded capability valid: %v", err)
	}
}

const overrideCoreJSON = `{
  "scheme_id": "varwof/core",
  "version": "1",
  "name": "varwof core",
  "capabilities": [
    {"id": "cert:issue", "name": "Issue certificate", "summary": "issue", "usage": "u", "when_not": "n", "examples": ["e"]}
  ],
  "roles": {
    "admin": {"display_name": "Admin", "grants": ["*"]}
  }
}`
