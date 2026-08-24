package tcpgw

import (
	"path/filepath"
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
