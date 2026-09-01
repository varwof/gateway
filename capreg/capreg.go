// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Package capreg provides the shared capability registry loader for all gateways.
//
// The single source of capability specs is the register module (embedded scheme + disk override).
// All three gateways (http/tcp/udp) load via this package and, on successful load, inject
// the instance into the gateway-core package-level registry for the data-plane admission
// pipeline (RunAccessPipeline) phase-one validation that AIC-declared capabilities must be
// registered (fail-closed).
package capreg

import (
	"crypto/x509"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/varwof/register"
)

// Loader loads the capability registry.
// When dir is empty, the embedded scheme is used; when a directory is specified, disk override applies (edit JSON for hot updates).
// When a trust root is set, every capability JSON must carry a valid PKCS#7
// detached signature (.p7s) from that root before it is loaded (supply-chain
// integrity for the registry).
type Loader struct {
	reg        *register.Registry
	trustRoots []*x509.Certificate
}

// New creates a Loader. If dir is empty, only the embedded scheme is used.
func New(dir string) (*Loader, error) {
	l := &Loader{}
	if err := l.Reload(dir); err != nil {
		return nil, err
	}
	return l, nil
}

// SetTrustRoot configures the PEM trust root used to verify capability .p7s
// signatures. Empty path disables signature verification.
func (l *Loader) SetTrustRoot(path string) error {
	if path == "" {
		l.trustRoots = nil
		return nil
	}
	roots, err := register.LoadCertFile(path)
	if err != nil {
		return fmt.Errorf("capreg: load trust root: %w", err)
	}
	l.trustRoots = roots
	return nil
}

// Registry returns the current registry instance.
func (l *Loader) Registry() *register.Registry {
	return l.reg
}

// Reload reloads the registry from a disk directory (capability data tree).
// dir must be non-empty; embedded schemes were removed when the capability
// data split into a separate subproject. On failure, the existing registry
// is kept unchanged.
func (l *Loader) Reload(dir string) error {
	if dir == "" {
		return fmt.Errorf("capreg: capability data directory required (embedded schemes removed)")
	}
	if len(l.trustRoots) > 0 {
		if err := verifySchemeSignatures(dir, l.trustRoots); err != nil {
			return err
		}
	}
	reg, err := register.NewRegistryFromDisk(dir)
	if err != nil {
		return err
	}
	l.reg = reg
	return nil
}

// Enabled reports whether the registry has been loaded.
func (l *Loader) Enabled() bool {
	return l != nil && l.reg != nil
}

// ValidateCapability implements the gw.CapabilityRegistry interface.
// The formatted identifier is "scheme:capability_id".
func (l *Loader) ValidateCapability(formatted string) error {
	if l == nil || l.reg == nil {
		return nil
	}
	_, _, err := l.reg.ValidateCapability(formatted)
	return err
}

// verifySchemeSignatures verifies every capability JSON in the tree against
// its .p7s signature using the configured trust root. Missing or invalid
// signatures fail closed (the existing registry, if any, is kept).
func verifySchemeSignatures(dir string, roots []*x509.Certificate) error {
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		if err := register.VerifyCapabilityPKCS7(path, roots); err != nil {
			return fmt.Errorf("capreg: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
