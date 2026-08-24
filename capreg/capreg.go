// Package capreg provides the shared capability registry loader for all gateways.
//
// The single source of capability specs is the register module (embedded scheme + disk override).
// All three gateways (http/tcp/udp) load via this package and, on successful load, inject
// the instance into the gateway-core package-level registry for the data-plane admission
// pipeline (RunAccessPipeline) phase-one validation that AIC-declared capabilities must be
// registered (fail-closed).
package capreg

import (
	"fmt"

	"github.com/varwof/register"
)

// Loader loads the capability registry.
// When dir is empty, the embedded scheme is used; when a directory is specified, disk override applies (edit JSON for hot updates).
type Loader struct {
	reg *register.Registry
}

// New creates a Loader. If dir is empty, only the embedded scheme is used.
func New(dir string) (*Loader, error) {
	l := &Loader{}
	if err := l.Reload(dir); err != nil {
		return nil, err
	}
	return l, nil
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
