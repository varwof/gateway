// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package capreg

import (
	"os"
	"path/filepath"
	"testing"
)

// helperDir creates a temp capability data tree with a varwof/core scheme.
func helperDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	coreDir := filepath.Join(dir, "varwof", "core")
	if err := os.MkdirAll(coreDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(coreDir, "v1.json"), []byte(coreJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestLoaderLoad verifies that a capability data directory loads and capabilities can be validated.
func TestLoaderLoad(t *testing.T) {
	dir := helperDir(t)
	l, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !l.Enabled() {
		t.Fatal("expected enabled")
	}
	if len(l.Registry().SchemeIDs()) == 0 {
		t.Fatal("expected loaded schemes")
	}
	if err := l.ValidateCapability("varwof/core:cert:issue"); err != nil {
		t.Errorf("expected registered capability valid: %v", err)
	}
	if err := l.ValidateCapability("varwof/core:no:such:cap"); err == nil {
		t.Error("expected unregistered capability to fail")
	}
}

// TestLoaderOverride verifies disk override priority.
func TestLoaderOverride(t *testing.T) {
	dir := helperDir(t)
	// Override the varwof/core scheme with an extra capability
	coreDir := filepath.Join(dir, "varwof", "core")
	if err := os.WriteFile(filepath.Join(coreDir, "v1.json"), []byte(overrideJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	l, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Base capability should still be valid
	if err := l.ValidateCapability("varwof/core:cert:issue"); err != nil {
		t.Errorf("override lost base capability: %v", err)
	}
	// Override-added capability should be valid
	if err := l.ValidateCapability("varwof/core:audit:export"); err != nil {
		t.Errorf("override capability missing: %v", err)
	}
}

// TestLoaderEmptyDirRejected verifies that an empty dir is rejected.
func TestLoaderEmptyDirRejected(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Fatal("expected error for empty dir")
	}
}

// TestLoaderReloadKeepsOnError verifies that Reload keeps the existing registry on error.
func TestLoaderReloadKeepsOnError(t *testing.T) {
	dir := helperDir(t)
	l, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	before := len(l.Registry().SchemeIDs())
	if err := l.Reload("/nonexistent-dir-xyz"); err == nil {
		t.Fatal("expected Reload error for bad dir")
	}
	after := len(l.Registry().SchemeIDs())
	if before != after {
		t.Fatalf("registry changed on failed reload: %d → %d", before, after)
	}
}

const coreJSON = `{
  "scheme_id": "varwof/core",
  "version": "1",
  "name": "varwof core",
  "capabilities": [
    {"id": "cert:issue", "name": "Issue certificate", "summary": "issue", "usage": "u", "when_not": "n", "examples": ["e"]},
    {"id": "cert:revoke", "name": "Revoke certificate", "summary": "revoke", "usage": "u", "when_not": "n", "examples": ["e"]}
  ],
  "roles": {
    "admin": {"display_name": "Admin", "grants": ["*"]}
  }
}`

const overrideJSON = `{
  "scheme_id": "varwof/core",
  "version": "1",
  "name": "varwof core (override)",
  "capabilities": [
    {"id": "cert:issue", "name": "Issue certificate", "summary": "issue", "usage": "u", "when_not": "n", "examples": ["e"]},
    {"id": "cert:revoke", "name": "Revoke certificate", "summary": "revoke", "usage": "u", "when_not": "n", "examples": ["e"]},
    {"id": "audit:export", "name": "Export audit log", "summary": "export", "usage": "u", "when_not": "n", "examples": ["e"]}
  ],
  "roles": {
    "admin": {"display_name": "Admin", "grants": ["*"]}
  }
}`
