// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package tcpgw

import (
	"fmt"
	"net"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

// TestIdleConnTimesOutWhenIdle verifies that the idleConn wrapper times out after
// the idle window when truly idle.
func TestIdleConnTimesOutWhenIdle(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	serverConn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	wrapped := &idleConn{Conn: serverConn, idle: 150 * time.Millisecond}
	buf := make([]byte, 1)
	_, err = wrapped.Read(buf)
	if err == nil {
		t.Fatal("idle Read should time out after idle window")
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

// TestMappingIdleTimeoutActiveSurvives integration: mapping with small idle_timeout,
// a continuously active echo connection should survive beyond the idle window
// (previously a one-shot SetDeadline would kill it).
func TestMappingIdleTimeoutActiveSurvives(t *testing.T) {
	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	m, err := NewMapping(MappingConfig{
		Name: "w05-active", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(), Protocol: ProtocolTCP,
		TLS: &gw.TLSConfig{IdleTimeoutSec: 1},
	}, nil, nil, nil, nil, NewBundle(), "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	conn, err := net.Dial("tcp", m.listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Continuous ping-pong for 3.5s (over 3x idle=1s), staying connected proves activity refresh works.
	end := time.Now().Add(3500 * time.Millisecond)
	buf := make([]byte, 64)
	for time.Now().Before(end) {
		if _, err := fmt.Fprintf(conn, "ping\n"); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := conn.Read(buf); err != nil {
			t.Fatalf("read: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestMappingIdleTimeoutDisconnects integration: idle connections are disconnected
// after idle_timeout.
func TestMappingIdleTimeoutDisconnects(t *testing.T) {
	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	m, err := NewMapping(MappingConfig{
		Name: "w05-idle", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(), Protocol: ProtocolTCP,
		TLS: &gw.TLSConfig{IdleTimeoutSec: 1},
	}, nil, nil, nil, nil, NewBundle(), "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	conn, err := net.Dial("tcp", m.listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send no data, wait for idle disconnect.
	start := time.Now()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("idle connection should be disconnected by gateway")
	}
	elapsed := time.Since(start)
	if elapsed < 500*time.Millisecond {
		t.Fatalf("disconnected too early (%v), idle timeout not honored", elapsed)
	}
}
