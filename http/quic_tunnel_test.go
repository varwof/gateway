// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package httpgw

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	gw "github.com/varwof/gateway-core"
)

func startTunnelBackend(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

type tunnelFixture struct {
	q      *QUICListener
	pool   *x509.CertPool
	addr   string
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
}

func newTunnelFixture(t *testing.T, mut func(*ListenerConfig)) *tunnelFixture {
	t.Helper()
	backendAddr, closeBackend := startTunnelBackend(t)
	t.Cleanup(closeBackend)

	dir := t.TempDir()
	caCert, caKey, caDER := makeCert(t, "TunnelCA", nil, true, nil, nil, nil)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	writePEM(t, filepath.Join(dir, "ca.pem"), "CERTIFICATE", caDER)
	_, srvKey, srvDER := makeCert(t, "tunnel-server", nil, false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, caCert, caKey)
	writePEM(t, filepath.Join(dir, "server.pem"), "CERTIFICATE", srvDER)
	writePEM(t, filepath.Join(dir, "server.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(srvKey))

	cfg := ListenerConfig{
		Name: "tunnel", Listen: "127.0.0.1:0", Protocol: ProtocolQUIC,
		TLS: &gw.TLSConfig{
			CertFile:       filepath.Join(dir, "server.pem"),
			KeyFile:        filepath.Join(dir, "server.key"),
			CACertFile:     filepath.Join(dir, "ca.pem"),
			IdleTimeoutSec: 10,
		},
		Routes: []RouteConfig{{Path: "/", Target: backendAddr, AllowRoles: []string{"gateway:admin"}}},
	}
	if mut != nil {
		mut(&cfg)
	}
	q := newQUICListener(cfg, nil, nil, nil, nil, make(chan struct{}), NewBundle(), "en", nil)
	q.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := q.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { q.Stop() })

	return &tunnelFixture{q: q, pool: pool, addr: q.Addr().String(), caCert: caCert, caKey: caKey}
}

func tunnelClientCert(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, ou []string) tls.Certificate {
	t.Helper()
	cert, key, der := makeCert(t, "tunnel-client", ou, false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, caCert, caKey)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}
}

func dialTunnel(t *testing.T, fx *tunnelFixture, client tls.Certificate) (quic.Connection, quic.Stream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, fx.addr, &tls.Config{
		InsecureSkipVerify: true,
		RootCAs:            fx.pool,
		Certificates:       []tls.Certificate{client},
		NextProtos:         []string{"hq"},
	}, &quic.Config{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	return conn, stream
}

func TestQUICTunnelEcho(t *testing.T) {
	fx := newTunnelFixture(t, nil)

	client := tunnelClientCert(t, fx.caCert, fx.caKey, []string{"gateway:admin"})
	conn, stream := dialTunnel(t, fx, client)
	defer conn.CloseWithError(0, "")

	if _, err := stream.Write([]byte("ping-tunnel")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := stream.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 11)
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "ping-tunnel" {
		t.Fatalf("echo = %q, want %q", buf, "ping-tunnel")
	}
}

func TestQUICTunnelDeniedNoRole(t *testing.T) {
	fx := newTunnelFixture(t, nil)

	client := tunnelClientCert(t, fx.caCert, fx.caKey, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, fx.addr, &tls.Config{
		InsecureSkipVerify: true,
		RootCAs:            fx.pool,
		Certificates:       []tls.Certificate{client},
		NextProtos:         []string{"hq"},
	}, &quic.Config{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "")
	assertTunnelClosed(t, ctx, conn)
}

func assertTunnelClosed(t *testing.T, ctx context.Context, conn quic.Connection) {
	t.Helper()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return
	}
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, rerr := io.Copy(io.Discard, stream); rerr == nil {
		t.Fatal("expected connection to be closed by gateway")
	}
}

func TestQUICTunnelMaxConnsPerIP(t *testing.T) {
	fx := newTunnelFixture(t, func(c *ListenerConfig) {
		c.TLS.MaxConnsPerIP = 1
	})

	client := tunnelClientCert(t, fx.caCert, fx.caKey, []string{"gateway:admin"})
	conn1, stream1 := dialTunnel(t, fx, client)
	defer conn1.CloseWithError(0, "")
	defer stream1.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn2, err := quic.DialAddr(ctx, fx.addr, &tls.Config{
		InsecureSkipVerify: true,
		RootCAs:            fx.pool,
		Certificates:       []tls.Certificate{client},
		NextProtos:         []string{"hq"},
	}, &quic.Config{})
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	defer conn2.CloseWithError(0, "")
	assertTunnelClosed(t, ctx, conn2)
}

func TestQUICTunnelMaxConnsPerCert(t *testing.T) {
	fx := newTunnelFixture(t, func(c *ListenerConfig) {
		c.TLS.MaxConnsPerCert = 1
	})

	client := tunnelClientCert(t, fx.caCert, fx.caKey, []string{"gateway:admin"})
	conn1, stream1 := dialTunnel(t, fx, client)
	defer conn1.CloseWithError(0, "")
	defer stream1.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn2, err := quic.DialAddr(ctx, fx.addr, &tls.Config{
		InsecureSkipVerify: true,
		RootCAs:            fx.pool,
		Certificates:       []tls.Certificate{client},
		NextProtos:         []string{"hq"},
	}, &quic.Config{})
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	defer conn2.CloseWithError(0, "")
	assertTunnelClosed(t, ctx, conn2)
}
