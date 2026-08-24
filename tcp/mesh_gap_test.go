// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package tcpgw

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

func TestMeshTargetMatcherDefaults(t *testing.T) {
	m := newMeshTargetMatcher(nil)

	cases := []struct {
		target string
		allow  bool
	}{
		{"127.0.0.1:8080", true},    // loopback
		{"10.0.0.5:22", true},       // RFC1918 private
		{"192.168.1.100:443", true}, // private
		{"172.16.3.9:80", true},     // private
		{"[::1]:8080", true},        // IPv6 loopback
		{"[fc00::1]:443", true},     // ULA
		{"8.8.8.8:53", false},       // public → rejected
		{"example.com:443", false},  // public domain → rejected
	}
	for _, c := range cases {
		if got := m.Allow(c.target); got != c.allow {
			t.Errorf("Allow(%q) = %v, want %v", c.target, got, c.allow)
		}
	}
}

func TestMeshTargetMatcherExplicit(t *testing.T) {
	m := newMeshTargetMatcher([]string{
		"10.0.0.0/8",
		"203.0.113.7:8080",
		"*.internal.example:443",
		"203.0.113.5:8443",
	})

	cases := []struct {
		target string
		allow  bool
	}{
		{"10.1.2.3:22", true},             // CIDR
		{"203.0.113.7:8080", true},        // exact host:port
		{"203.0.113.5:8443", true},        // exact
		{"db.internal.example:443", true}, // suffix domain
		{"api.internal.example:443", true},
		{"internal.example:443", false}, // bare domain does not match *. suffix
		{"203.0.113.7:443", false},      // same IP different port
		{"203.0.113.99:8443", false},    // not in CIDR allowlist
	}
	for _, c := range cases {
		if got := m.Allow(c.target); got != c.allow {
			t.Errorf("Allow(%q) = %v, want %v", c.target, got, c.allow)
		}
	}
}

// TestMeshListenerRequiresMTLS verifies that after configuring mesh_server_tls
// on the inbound mesh listener, raw TCP (non-TLS handshake) connections are rejected;
// a valid mTLS client can handshake successfully (W01).
func TestMeshListenerRequiresMTLS(t *testing.T) {
	dir := newTunnelCertDir(t)
	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	g := &Gateway{
		stopGuard: gw.NewStopGuard(),
		logger:    slog.Default(),
		cfg: &Config{
			MeshListen: "127.0.0.1:0",
			Peers: []MeshPeerConfig{{
				Name: "peer", Addr: "127.0.0.1:1",
				CACertFile: filepath.Join(dir, "ca.pem"),
				CertFile:   filepath.Join(dir, "client.pem"),
				KeyFile:    filepath.Join(dir, "client.key"),
			}},
			MeshServerTLS: &gw.TLSConfig{
				CACertFile: filepath.Join(dir, "ca.pem"),
				CertFile:   filepath.Join(dir, "server.pem"),
				KeyFile:    filepath.Join(dir, "server.key"),
			},
		},
	}
	g.mesh = NewMesh(g.cfg.Peers, nil)

	if err := g.startMeshListener(); err != nil {
		t.Fatalf("startMeshListener: %v", err)
	}
	defer g.meshListener.Close()
	addr := g.meshListener.Addr().String()

	// Raw TCP: write a fake target header, should be rejected by TLS handshake (connection closed).
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(2 * time.Second))
	writeMeshTarget(raw, echoSrv.Addr().String())
	buf := make([]byte, 1)
	if _, err := raw.Read(buf); err == nil {
		t.Fatal("expected raw (non-TLS) connection to be rejected")
	}

	// Valid mTLS client: handshake + forward to loopback echo succeeds.
	clientCfg, err := gwClientTLSConfigForTest(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	tc, err := tls.Dial("tcp", addr, clientCfg)
	if err != nil {
		t.Fatalf("mTLS dial: %v", err)
	}
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	writeMeshTarget(tc, echoSrv.Addr().String())
	if _, err := tc.Write([]byte("mesh-mtls-ok\n")); err != nil {
		t.Fatalf("write echo: %v", err)
	}
	buf = make([]byte, 32)
	n, err := tc.Read(buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf[:n]) != "mesh-mtls-ok\n" {
		t.Fatalf("echo = %q", string(buf[:n]))
	}
}

func writeMeshTarget(w net.Conn, target string) {
	b := []byte(target)
	hdr := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(hdr[:2], uint16(len(b)))
	copy(hdr[2:], b)
	w.Write(hdr)
}

func gwClientTLSConfigForTest(t *testing.T, dir string) (*tls.Config, error) {
	t.Helper()
	caCert, err := tls.LoadX509KeyPair(filepath.Join(dir, "client.pem"), filepath.Join(dir, "client.key"))
	if err != nil {
		return nil, err
	}
	caPool := x509.NewCertPool()
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no CA certs in %s", filepath.Join(dir, "ca.pem"))
	}
	return &tls.Config{
		Certificates: []tls.Certificate{caCert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}
