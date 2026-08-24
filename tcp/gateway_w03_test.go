// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package tcpgw

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// TestMappingStopWithIdleConnection verifies W03: Mapping.Stop() must return
// quickly (not block indefinitely) when idle keep-alive connections exist
// (no data, no idle_timeout).
func TestMappingStopWithIdleConnection(t *testing.T) {
	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	m, err := NewMapping(MappingConfig{
		Name: "w03", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(), Protocol: ProtocolTCP,
	}, nil, nil, nil, nil, NewBundle(), "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Establish a connection but keep it idle (no data sent, no close).
	conn, err := net.Dial("tcp", m.listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	waitFor(t, 3*time.Second, func() bool { return m.Conns() == 1 }, "mapping conn to be accepted")

	done := make(chan struct{})
	go func() {
		m.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Mapping.Stop() blocked on idle connection (W03 still broken)")
	}
}

// TestTunnelStopWithIdleConnection verifies W03: Tunnel.Stop() must return
// quickly on idle tunnel connections (previously handleConn had no stopCh select,
// io.Copy would block forever).
func TestTunnelStopWithIdleConnection(t *testing.T) {
	dir := newTunnelCertDir(t)
	gateway := startTLSGateway(t, dir)
	defer gateway.Close()

	listen := fmt.Sprintf("127.0.0.1:%d", freePortTCP(t))
	tun := newTunnelFixture(t, dir, listen, gateway.Addr().String())
	if err := tun.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	conn, err := net.Dial("tcp", listen)
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	defer conn.Close()
	waitFor(t, 3*time.Second, func() bool { return tun.Conns() == 1 }, "tunnel conn to be established")

	done := make(chan struct{})
	go func() {
		tun.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Tunnel.Stop() blocked on idle connection (W03 still broken)")
	}
}

// TestGatewayStopWithIdleConnection verifies W03: gateway-level Stop() (including
// management API call path) returns quickly when idle connections exist, no longer
// deadlocking while holding the lock.
func TestGatewayStopWithIdleConnection(t *testing.T) {
	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	g := NewGateway(&Config{
		Mappings: []MappingConfig{{
			Name: "w03", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(), Protocol: ProtocolTCP,
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	conn, err := net.Dial("tcp", g.mappings["w03"].listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	done := make(chan struct{})
	go func() {
		g.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Gateway.Stop() blocked on idle connection (W03 still broken)")
	}
}
