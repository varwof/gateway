// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package tcpgw

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"path/filepath"
	"testing"
	"time"
)

func TestMeshDialConnSuccess(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "server", caCert, caKey, nil)
	generateTestCert(t, dir, "client", caCert, caKey, nil)

	serverCert, err := tls.LoadX509KeyPair(
		filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"))
	if err != nil {
		t.Fatalf("load server keypair: %v", err)
	}

	target := "127.0.0.1:8080"
	got := make(chan string, 1)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint16(lenBuf[:])
		targetBytes := make([]byte, n)
		if _, err := io.ReadFull(conn, targetBytes); err != nil {
			return
		}
		got <- string(targetBytes)
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		io.Copy(io.Discard, conn)
	}()

	m := NewMesh([]MeshPeerConfig{{
		Name:       "peer1",
		Addr:       ln.Addr().String(),
		CACertFile: filepath.Join(dir, "ca.pem"),
		CertFile:   filepath.Join(dir, "client.pem"),
		KeyFile:    filepath.Join(dir, "client.key"),
	}}, nil)

	p := m.Peer("peer1")
	if p == nil {
		t.Fatal("peer not found")
	}
	conn, err := p.DialConn(target, 5*time.Second)
	if err != nil {
		t.Fatalf("DialConn: %v", err)
	}
	defer conn.Close()

	select {
	case g := <-got:
		if g != target {
			t.Fatalf("peer received target %q, want %q", g, target)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("peer did not receive target")
	}
}

func TestMeshDialConnInvalidConfig(t *testing.T) {
	m := NewMesh([]MeshPeerConfig{{
		Name: "bad", Addr: "127.0.0.1:1",
		CACertFile: "/nonexistent/ca.pem",
		CertFile:   "/nonexistent/cert.pem",
		KeyFile:    "/nonexistent/key.pem",
	}}, nil)
	if p := m.Peer("bad"); p != nil {
		t.Fatalf("expected bad peer to be skipped, got %+v", p)
	}
}

func TestMeshPeerDialConnTimeout(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "client", caCert, caKey, nil)

	m := NewMesh([]MeshPeerConfig{{
		Name:       "unreachable",
		Addr:       "198.51.100.99:8443",
		CACertFile: filepath.Join(dir, "ca.pem"),
		CertFile:   filepath.Join(dir, "client.pem"),
		KeyFile:    filepath.Join(dir, "client.key"),
	}}, nil)
	p := m.Peer("unreachable")
	if p == nil {
		t.Skip("peer skipped")
	}
	start := time.Now()
	conn, err := p.DialConn("127.0.0.1:1", 200*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatal("expected dial error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("dial took %v, timeout not respected", elapsed)
	}
}
