// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package tcpgw

import (
	"net"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

func dialAndCheckRejected(t *testing.T, addr string) bool {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return true
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))

	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err != nil {
		return true
	}
	return false
}

func TestMappingPerIPLimit(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "server", caCert, caKey, nil)

	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	cfg := MappingConfig{
		Name:     "test-ip-limit",
		Listen:   "127.0.0.1:0",
		Target:   echoSrv.Addr().String(),
		Protocol: ProtocolTCP,
		TLS: &gw.TLSConfig{
			MaxConnsPerIP: 2,
		},
	}
	m, err := NewMapping(cfg, nil, nil, nil, nil, nil, "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	addr := m.listener.Addr().String()

	conn1, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()

	conn2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()

	time.Sleep(50 * time.Millisecond)

	if !dialAndCheckRejected(t, addr) {
		t.Error("expected third connection from same IP to be rejected")
	}
}

func TestMappingTotalLimit(t *testing.T) {
	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	cfg := MappingConfig{
		Name:     "test-total-limit",
		Listen:   "127.0.0.1:0",
		Target:   echoSrv.Addr().String(),
		Protocol: ProtocolTCP,
		TLS: &gw.TLSConfig{
			MaxTotalConns: 1,
		},
	}
	m, err := NewMapping(cfg, nil, nil, nil, nil, nil, "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	addr := m.listener.Addr().String()
	conn1, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()

	time.Sleep(50 * time.Millisecond)

	if !dialAndCheckRejected(t, addr) {
		t.Error("expected second connection to be rejected (total limit 1)")
	}
}

func TestMappingHealthCheck(t *testing.T) {
	cfg := MappingConfig{
		Name:     "test-hc",
		Listen:   "127.0.0.1:0",
		Target:   "127.0.0.1:1",
		Protocol: ProtocolTCP,
		TCPExt: &gw.TCPExtra{
			HealthCheckSec: 1,
		},
	}
	m, err := NewMapping(cfg, nil, nil, nil, nil, nil, "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	time.Sleep(1500 * time.Millisecond)

	if m.Healthy() {
		t.Error("expected unhealthy (target 127.0.0.1:1)")
	}
	if m.State() != MappingUnhealthy {
		t.Errorf("expected State=unhealthy, got %s", m.State())
	}
}
