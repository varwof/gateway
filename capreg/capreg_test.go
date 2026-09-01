// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package capreg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/varwof/register"
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

// TestTrustRootVerification verifies capability .p7s signature enforcement:
// signed tree loads, unsigned tree is rejected, tampered file is rejected.
func TestTrustRootVerification(t *testing.T) {
	// Generate a self-signed code-signing CA + leaf via the register sign flow.
	srcDir := helperDir(t)
	src := filepath.Join(srcDir, "varwof", "core", "v1.json")

	caKey, caCert := makeSigningCA(t)
	signFile(t, src, caKey, caCert)

	// Loader with trust root: signed tree passes.
	root := writeCertPEM(t, caCert)
	l, err := New(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.SetTrustRoot(root); err != nil {
		t.Fatal(err)
	}
	if err := l.Reload(srcDir); err != nil {
		t.Fatalf("signed tree should load: %v", err)
	}

	// Unsigned file must fail closed.
	unsigned := t.TempDir()
	os.MkdirAll(filepath.Join(unsigned, "varwof", "core"), 0o755)
	os.WriteFile(filepath.Join(unsigned, "varwof", "core", "v1.json"), []byte(coreJSON), 0o644)
	if err := l.Reload(unsigned); err == nil {
		t.Fatal("unsigned capability must be rejected under a trust root")
	}

	// Tampered file must fail closed.
	tampered := t.TempDir()
	os.MkdirAll(filepath.Join(tampered, "varwof", "core"), 0o755)
	os.WriteFile(filepath.Join(tampered, "varwof", "core", "v1.json"), []byte(coreJSON+"// tampered"), 0o644)
	copyFile(filepath.Join(srcDir, "varwof", "core", "v1.json.p7s"),
		filepath.Join(tampered, "varwof", "core", "v1.json.p7s"))
	if err := l.Reload(tampered); err == nil {
		t.Fatal("tampered capability must be rejected")
	}
}

// ── helpers for signature tests ──

func makeSigningCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "capreg-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func signFile(t *testing.T, capPath string, key *ecdsa.PrivateKey, cert *x509.Certificate) {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "signer.pem")
	keyPath := filepath.Join(dir, "signer.key")
	writePEM(certPath, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(keyPath, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := register.SignCapability(certPath, keyPath, capPath, ""); err != nil {
		t.Fatal(err)
	}
}

func writePEM(path string, block *pem.Block) {
	data := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		panic(err)
	}
}

func writeCertPEM(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	writePEM(path, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return path
}

func copyFile(src, dst string) {
	data, err := os.ReadFile(src)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		panic(err)
	}
}
