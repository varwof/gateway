package tcpgw

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func newTunnelCertDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "server", caCert, caKey, nil)
	generateTestCert(t, dir, "client", caCert, caKey, nil)
	return dir
}

func newTunnelFixture(t *testing.T, dir, listen, gatewayAddr string) *Tunnel {
	t.Helper()
	tun, err := NewTunnel(TunnelConfig{
		Name:        "fixture",
		Listen:      listen,
		GatewayAddr: gatewayAddr,
		CertFile:    filepath.Join(dir, "client.pem"),
		KeyFile:     filepath.Join(dir, "client.key"),
		CACertFile:  filepath.Join(dir, "ca.pem"),
	}, nil)
	if err != nil {
		t.Fatalf("NewTunnel: %v", err)
	}
	return tun
}

func startTLSGateway(t *testing.T, dir string) net.Listener {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"))
	if err != nil {
		t.Fatalf("load server keypair: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 1024)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					conn.Write(buf[:n])
				}
			}()
		}
	}()
	return ln
}

func TestTunnelHandleConnSuccess(t *testing.T) {
	dir := newTunnelCertDir(t)
	gateway := startTLSGateway(t, dir)
	defer gateway.Close()

	tun := newTunnelFixture(t, dir, "127.0.0.1:0", gateway.Addr().String())
	if err := tun.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer tun.Stop()

	localConn, clientConn := net.Pipe()
	defer localConn.Close()
	defer clientConn.Close()

	done := make(chan struct{})
	tun.wg.Add(1)
	atomic.AddInt64(&tun.conns, 1)
	go func() {
		tun.handleConn(localConn)
		close(done)
	}()

	clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprint(clientConn, "hello\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "hello\n" {
		t.Fatalf("echo = %q", string(buf[:n]))
	}

	clientConn.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleConn did not return after close")
	}
	if tun.Conns() != 0 {
		t.Fatalf("Conns() = %d, want 0", tun.Conns())
	}
}

func TestTunnelHandleConnDialError(t *testing.T) {
	dir := newTunnelCertDir(t)
	tun := newTunnelFixture(t, dir, "127.0.0.1:0", "127.0.0.1:1")
	close(tun.stopCh)

	atomic.StoreInt64(&tun.conns, 1)
	localConn, clientConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	tun.wg.Add(1)
	go func() {
		tun.handleConn(localConn)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handleConn did not return")
	}
	if tun.Conns() != 0 {
		t.Fatalf("Conns() = %d, want 0 after failed dial", tun.Conns())
	}
	if _, err := localConn.Read(make([]byte, 1)); err == nil {
		t.Fatal("localConn should be closed after handleConn")
	}
}

func TestTunnelDialWithRetrySuccess(t *testing.T) {
	dir := newTunnelCertDir(t)
	gateway := startTLSGateway(t, dir)
	defer gateway.Close()

	tun := newTunnelFixture(t, dir, "127.0.0.1:0", gateway.Addr().String())
	conn, err := tun.dialWithRetry()
	if err != nil {
		t.Fatalf("dialWithRetry: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("got %q", buf)
	}
}

func TestTunnelAcceptLoopListenerError(t *testing.T) {
	dir := newTunnelCertDir(t)
	tun := newTunnelFixture(t, dir, "127.0.0.1:0", "127.0.0.1:1")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := ln.(*net.TCPListener).SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		tun.acceptLoop(ln)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	close(tun.stopCh)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("acceptLoop did not stop after listener error")
	}
}

func TestTunnelDialWithRetryStopped(t *testing.T) {
	dir := newTunnelCertDir(t)
	tun := newTunnelFixture(t, dir, "127.0.0.1:0", "127.0.0.1:1")
	close(tun.stopCh)
	conn, err := tun.dialWithRetry()
	if err == nil {
		if conn != nil {
			conn.Close()
		}
		t.Fatal("expected error when stopped")
	}
}

func TestTunnelDialWithRetryStopsDuringBackoff(t *testing.T) {
	dir := newTunnelCertDir(t)
	tun := newTunnelFixture(t, dir, "127.0.0.1:0", "127.0.0.1:1")

	done := make(chan error, 1)
	go func() {
		_, err := tun.dialWithRetry()
		done <- err
	}()

	time.Sleep(1700 * time.Millisecond)
	close(tun.stopCh)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error")
		}
		if err.Error() != "stopped" {
			t.Fatalf("err = %v, want stopped", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dialWithRetry did not stop during backoff")
	}
}

func TestTunnelHandleConnFullEndToEnd(t *testing.T) {
	dir := newTunnelCertDir(t)
	gateway := startTLSGateway(t, dir)
	defer gateway.Close()

	listen := fmt.Sprintf("127.0.0.1:%d", freePortTCP(t))
	tun := newTunnelFixture(t, dir, listen, gateway.Addr().String())
	if err := tun.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer tun.Stop()

	conn, err := net.Dial("tcp", listen)
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprint(conn, "roundtrip\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "roundtrip\n" {
		t.Fatalf("echo = %q", string(buf[:n]))
	}
	conn.Close()
	waitFor(t, 5*time.Second, func() bool {
		return tun.Conns() == 0
	}, "tunnel conn count to return to zero")
}
