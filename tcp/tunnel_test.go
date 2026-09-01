// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package tcpgw

import (
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestTunnelNew_InvalidConfig(t *testing.T) {
	_, err := NewTunnel(TunnelConfig{Name: "t1"}, nil)
	if err == nil {
		t.Fatal("expected error for empty config")
	}
}

func TestTunnelNew_Success(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "client", caCert, caKey, nil)

	tun, err := NewTunnel(TunnelConfig{
		Name:        "test-tun",
		Listen:      "127.0.0.1:0",
		GatewayAddr: "127.0.0.1:9999",
		CertFile:    filepath.Join(dir, "client.pem"),
		KeyFile:     filepath.Join(dir, "client.key"),
		CACertFile:  filepath.Join(dir, "ca.pem"),
	}, nil)
	if err != nil {
		t.Fatalf("NewTunnel() error = %v", err)
	}
	if tun.Name() != "test-tun" {
		t.Errorf("Name() = %q", tun.Name())
	}
}

func TestTunnelStartStop(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "client", caCert, caKey, nil)

	tun, err := NewTunnel(TunnelConfig{
		Name:        "test-tun",
		Listen:      "127.0.0.1:0",
		GatewayAddr: "127.0.0.1:0",
		CertFile:    filepath.Join(dir, "client.pem"),
		KeyFile:     filepath.Join(dir, "client.key"),
		CACertFile:  filepath.Join(dir, "ca.pem"),
	}, nil)
	if err != nil {
		t.Fatalf("NewTunnel() error = %v", err)
	}

	if err := tun.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if tun.State() != TunnelRunning {
		t.Errorf("expected running, got %v", tun.State())
	}

	tun.Stop()
	if tun.State() != TunnelStopped {
		t.Errorf("expected stopped, got %v", tun.State())
	}
}

func TestTunnelStopIdempotent(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "client", caCert, caKey, nil)

	tun, err := NewTunnel(TunnelConfig{
		Name:        "idempotent",
		Listen:      "127.0.0.1:0",
		GatewayAddr: "127.0.0.1:0",
		CertFile:    filepath.Join(dir, "client.pem"),
		KeyFile:     filepath.Join(dir, "client.key"),
		CACertFile:  filepath.Join(dir, "ca.pem"),
	}, nil)
	if err != nil {
		t.Fatalf("NewTunnel() error = %v", err)
	}

	tun.Start()
	tun.Stop()
	tun.Stop() // second stop should not panic
}

func TestTunnelStartTwice(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "client", caCert, caKey, nil)

	tun, err := NewTunnel(TunnelConfig{
		Name:        "twice",
		Listen:      "127.0.0.1:0",
		GatewayAddr: "127.0.0.1:0",
		CertFile:    filepath.Join(dir, "client.pem"),
		KeyFile:     filepath.Join(dir, "client.key"),
		CACertFile:  filepath.Join(dir, "ca.pem"),
	}, nil)
	if err != nil {
		t.Fatalf("NewTunnel() error = %v", err)
	}

	if err := tun.Start(); err != nil {
		t.Fatalf("first Start() error = %v", err)
	}
	if err := tun.Start(); err == nil {
		t.Fatal("expected error on second Start()")
	}
	tun.Stop()
}

func TestTunnelConnsCounter(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "client", caCert, caKey, nil)

	tun, err := NewTunnel(TunnelConfig{
		Name:        "counter",
		Listen:      "127.0.0.1:0",
		GatewayAddr: "127.0.0.1:0",
		CertFile:    filepath.Join(dir, "client.pem"),
		KeyFile:     filepath.Join(dir, "client.key"),
		CACertFile:  filepath.Join(dir, "ca.pem"),
	}, nil)
	if err != nil {
		t.Fatalf("NewTunnel() error = %v", err)
	}
	if c := tun.Conns(); c != 0 {
		t.Errorf("initial Conns() = %d, want 0", c)
	}

	tun.Start()
	defer tun.Stop()
	time.Sleep(50 * time.Millisecond)
	// no actual connections, Conns should be 0
	if c := tun.Conns(); c != 0 {
		t.Errorf("Conns() after start = %d, want 0", c)
	}
}

// TestTunnelConnectionCap verifies finding 9: the tunnel must refuse to accept
// connections beyond maxTunnelConns so a flood cannot exhaust goroutines /
// file descriptors.
func TestTunnelConnectionCap(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "client", caCert, caKey, nil)

	tun, err := NewTunnel(TunnelConfig{
		Name:        "cap",
		Listen:      "127.0.0.1:0",
		GatewayAddr: "127.0.0.1:0",
		CertFile:    filepath.Join(dir, "client.pem"),
		KeyFile:     filepath.Join(dir, "client.key"),
		CACertFile:  filepath.Join(dir, "ca.pem"),
	}, nil)
	if err != nil {
		t.Fatalf("NewTunnel() error = %v", err)
	}
	if !tun.canAccept() {
		t.Fatal("fresh tunnel must accept connections")
	}
	atomic.StoreInt64(&tun.conns, maxTunnelConns)
	if tun.canAccept() {
		t.Fatal("tunnel accepted a connection beyond maxTunnelConns")
	}
}

// TestJitterInt64 verifies finding 12: reconnect jitter comes from crypto/rand,
// must stay within [0, max), and must produce varied values.
func TestJitterInt64(t *testing.T) {
	if jitterInt64(0) != 0 {
		t.Fatal("jitterInt64(0) must be 0")
	}
	if jitterInt64(-5) != 0 {
		t.Fatal("jitterInt64(negative) must be 0")
	}
	const max = int64(1 << 20)
	seen := map[int64]bool{}
	for i := 0; i < 200; i++ {
		v := jitterInt64(max)
		if v < 0 || v >= max {
			t.Fatalf("jitterInt64(%d) = %d out of range", max, v)
		}
		seen[v] = true
	}
	if len(seen) < 10 {
		t.Fatalf("jitter produced only %d distinct values; want varied output", len(seen))
	}
}
