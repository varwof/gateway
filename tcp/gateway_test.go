// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package tcpgw

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

func TestTCPGateway_New(t *testing.T) {
	g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
	if g == nil {
		t.Fatal("NewGateway() returned nil")
	}
}

func TestTCPGateway_StartStop(t *testing.T) {
	g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	g.Stop()
}

func TestTCPGateway_StopIdempotent(t *testing.T) {
	g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
	g.Start()
	g.Stop()
	g.Stop()
}

func TestTCPGateway_StartWithPlainMapping(t *testing.T) {
	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	g := NewGateway(&Config{
		Mappings: []MappingConfig{{
			Name: "test", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(), Protocol: ProtocolTCP,
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer g.Stop()

	if _, exists := g.mappings["test"]; !exists {
		t.Fatal("mapping 'test' not found after Start()")
	}
	if g.mappings["test"].State() != MappingRunning {
		t.Fatal("mapping 'test' not running")
	}
}

func TestTCPGateway_ManagementAPI(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "server.test", caCert, caKey, nil)
	generateTestCert(t, dir, "client", caCert, caKey, []string{"gateway:admin"})

	mgmtAddr := fmt.Sprintf("127.0.0.1:%d", freePortTCP(t))

	g := NewGateway(&Config{
		Management: &ManagementConfig{
			Listen: mgmtAddr,
			TLS: &gw.TLSConfig{
				CACertFile: filepath.Join(dir, "ca.pem"),
				CertFile:   filepath.Join(dir, "server.test.pem"),
				KeyFile:    filepath.Join(dir, "server.test.key"),
			},
		},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer g.Stop()
	time.Sleep(100 * time.Millisecond)

	pool := x509.NewCertPool()
	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
	pool.AppendCertsFromPEM(caPEM)

	cliCert, _ := tls.LoadX509KeyPair(filepath.Join(dir, "client.pem"), filepath.Join(dir, "client.key"))
	conn, err := tls.Dial("tcp", mgmtAddr, &tls.Config{
		Certificates:       []tls.Certificate{cliCert},
		RootCAs:            pool,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()

	fmt.Fprint(conn, "GET /api/v1/gateway/health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	body := string(buf[:n])
	if !contains(body, "200 OK") {
		t.Fatalf("expected 200, got: %s", body)
	}
}

func freePortTCP(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

func TestTCPGateway_Reload(t *testing.T) {
	echo1 := startEchoServer(t)
	defer echo1.Close()
	echo2 := startEchoServer(t)
	defer echo2.Close()

	configJSON := fmt.Sprintf(`{
		"mappings": [{
			"name": "primary",
			"listen": "127.0.0.1:0",
			"target": "%s",
			"protocol": "tcp"
		}]
	}`, echo1.Addr().String())

	dir := t.TempDir()
	configPath := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(configPath, []byte(configJSON), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer g.Stop()

	initialAddr := g.mappings["primary"].listener.Addr().String()
	conn, err := net.Dial("tcp", initialAddr)
	if err != nil {
		t.Fatalf("initial dial: %v", err)
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprint(conn, "hello\n")
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "hello\n" {
		t.Fatalf("initial echo: got %q", string(buf[:n]))
	}
	conn.Close()

	reloadJSON := fmt.Sprintf(`{
		"mappings": [{
			"name": "primary",
			"listen": "127.0.0.1:0",
			"target": "%s",
			"protocol": "tcp"
		}]
	}`, echo2.Addr().String())

	if err := os.WriteFile(configPath, []byte(reloadJSON), 0644); err != nil {
		t.Fatal(err)
	}

	if err := g.Reload(); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}

	newAddr := g.mappings["primary"].listener.Addr().String()
	conn2, err := net.Dial("tcp", newAddr)
	if err != nil {
		t.Fatalf("reload dial: %v", err)
	}
	defer conn2.Close()
	conn2.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprint(conn2, "world\n")
	buf2 := make([]byte, 64)
	n2, _ := conn2.Read(buf2)
	if string(buf2[:n2]) != "world\n" {
		t.Fatalf("reload echo: got %q", string(buf2[:n2]))
	}

	// W04: after reload swaps stopCh, the expiry loop must restart (bound to new stopCh).
	// connExpiryStop is a non-blocking stop func (returns once new loop starts),
	// calling it after reload should not hang.
	done := make(chan struct{})
	go func() {
		if g.connExpiryStop != nil {
			g.connExpiryStop()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("connExpiryStop stuck after reload (expiry loop not restarted)")
	}
}

func TestTCPMTLS_DataPlane(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "server", caCert, caKey, nil)
	generateTestCert(t, dir, "admin", caCert, caKey, []string{"gateway:admin"})
	generateTestCert(t, dir, "ops", caCert, caKey, []string{"gateway:ops"})
	generateTestCert(t, dir, "nobody", caCert, caKey, nil)

	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	g := NewGateway(&Config{
		Mappings: []MappingConfig{{
			Name:     "mtls-test",
			Listen:   "127.0.0.1:0",
			Target:   echoSrv.Addr().String(),
			Protocol: ProtocolTCPMTLS,
			TLS: &gw.TLSConfig{
				CACertFile: filepath.Join(dir, "ca.pem"),
				CertFile:   filepath.Join(dir, "server.pem"),
				KeyFile:    filepath.Join(dir, "server.key"),
				AllowRoles: []string{"gateway:admin"},
			},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer g.Stop()
	time.Sleep(50 * time.Millisecond)

	addr := g.mappings["mtls-test"].listener.Addr().String()

	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	tests := []struct {
		name   string
		keyVar string
		wantOK bool
	}{
		{"admin role allowed", "admin", true},
		{"ops role denied", "ops", false},
		{"no role denied", "nobody", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cliCert, err := tls.LoadX509KeyPair(
				filepath.Join(dir, tt.keyVar+".pem"),
				filepath.Join(dir, tt.keyVar+".key"),
			)
			if err != nil {
				t.Fatalf("load client cert: %v", err)
			}
			conn, err := tls.Dial("tcp", addr, &tls.Config{
				Certificates:       []tls.Certificate{cliCert},
				RootCAs:            pool,
				InsecureSkipVerify: true,
			})
			if err != nil {
				if !tt.wantOK {
					return
				}
				t.Fatalf("tls dial: %v", err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(2 * time.Second))

			fmt.Fprint(conn, "hello\n")
			buf := make([]byte, 64)
			n, err := conn.Read(buf)
			if !tt.wantOK {
				if err == nil && n > 0 {
					t.Fatal("expected connection to be rejected but got data")
				}
				return
			}
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(buf[:n]) != "hello\n" {
				t.Errorf("got %q, want %q", string(buf[:n]), "hello\n")
			}
		})
	}
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
