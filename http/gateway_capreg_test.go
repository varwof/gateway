// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

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

// TestHTTPGateway_ReloadClearsCapabilitySchemes verifies that after a registry is
// loaded, a reload that unsets capability_schemes disables data-plane capability
// validation instead of leaving the stale registry active.
func TestHTTPGateway_ReloadClearsCapabilitySchemes(t *testing.T) {
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
	if gw.GetGlobalCapabilityRegistry() == nil {
		t.Fatal("expected global registry set")
	}

	// Simulate a reload that removes capability_schemes: the global registry must be cleared.
	g.loadCapabilityRegistry(&Config{})
	if got := gw.GetGlobalCapabilityRegistry(); got != nil {
		t.Fatal("expected global registry cleared when capability_schemes removed on reload")
	}
}

// TestHTTPGateway_ReloadCapabilityRegistryFailClosed verifies that a reload that
// configures capability_schemes but cannot establish any registry (no existing
// registry to keep) returns an error — fail-closed instead of silently running
// with capability validation disabled.
func TestHTTPGateway_ReloadCapabilityRegistryFailClosed(t *testing.T) {
	gw.SetGlobalCapabilityRegistry(nil)
	defer gw.SetGlobalCapabilityRegistry(nil)

	g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
	if g.capReg != nil {
		t.Fatal("expected no capability registry initially")
	}

	err := g.loadCapabilityRegistry(&Config{CapabilitySchemes: "/nonexistent/cap-schemes"})
	if err == nil {
		t.Fatal("expected error when capability_schemes configured but registry cannot be loaded")
	}
	if g.capReg != nil {
		t.Fatal("expected no cached loader after failed load")
	}
	if got := gw.GetGlobalCapabilityRegistry(); got != nil {
		t.Fatal("expected global registry still unset after failed load")
	}
}

// TestHTTPGateway_ReloadCapabilityRegistryKeepsExisting verifies that a reload
// failure with an already-established registry keeps the existing registry
// active (non-blocking hot-reload semantics).
func TestHTTPGateway_ReloadCapabilityRegistryKeepsExisting(t *testing.T) {
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

	// Reload against a broken path: must NOT error (existing registry kept).
	if err := g.loadCapabilityRegistry(&Config{CapabilitySchemes: "/nonexistent/cap-schemes"}); err != nil {
		t.Fatalf("expected nil error when existing registry can be kept, got: %v", err)
	}
	cr := gw.GetGlobalCapabilityRegistry()
	if cr == nil {
		t.Fatal("expected global registry still set after failed reload")
	}
	if err := cr.ValidateCapability("varwof/core:cert:issue"); err != nil {
		t.Errorf("expected existing registry still functional: %v", err)
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
