package udpgw

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	gw "github.com/varwof/gateway-core"
)

func TestNewQUICProxy(t *testing.T) {
	q, err := NewQUICProxy(
		ListenerConfig{
			Name:     "quic-test",
			Listen:   "127.0.0.1:0",
			Protocol: ProtocolQUIC,
			TLS:      &gw.TLSConfig{CertFile: "/path/to/cert.pem", KeyFile: "/path/to/key.pem"},
		},
		nil, nil, nil, nil, nil, make(chan struct{}), NewBundle(), "en", nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("NewQUICProxy() error = %v", err)
	}
	if q.Name() != "quic-test" {
		t.Errorf("Name() = %q, want %q", q.Name(), "quic-test")
	}
	if q.ActiveClients() != 0 {
		t.Errorf("ActiveClients() = %d, want 0", q.ActiveClients())
	}
}

func TestQUICProxyStartWithoutCert(t *testing.T) {
	q, err := NewQUICProxy(
		ListenerConfig{
			Name:     "bad-quic",
			Listen:   "127.0.0.1:0",
			Protocol: ProtocolQUIC,
		},
		nil, nil, nil, nil, nil, make(chan struct{}), NewBundle(), "en", nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("NewQUICProxy() error = %v", err)
	}

	if err := q.Start(); err == nil {
		t.Error("expected error for QUIC without cert_file")
	}
}

func TestQUICProxyStartInvalidPath(t *testing.T) {
	q, err := NewQUICProxy(
		ListenerConfig{
			Name:     "bad-cert",
			Listen:   "127.0.0.1:0",
			Protocol: ProtocolQUIC,
			TLS:      &gw.TLSConfig{CertFile: "/nonexistent/cert.pem", KeyFile: "/nonexistent/key.pem"},
		},
		nil, nil, nil, nil, nil, make(chan struct{}), NewBundle(), "en", nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("NewQUICProxy() error = %v", err)
	}

	if err := q.Start(); err == nil {
		t.Error("expected error for QUIC with nonexistent cert")
	}
}

func TestQUICProxySelectTarget(t *testing.T) {
	t.Run("no routes returns empty", func(t *testing.T) {
		target := selectTarget([]RouteConfig{})
		if target != "" {
			t.Errorf("expected empty, got %q", target)
		}
	})

	t.Run("single route returns it", func(t *testing.T) {
		target := selectTarget([]RouteConfig{{Target: "127.0.0.1:9001"}})
		if target != "127.0.0.1:9001" {
			t.Errorf("expected 127.0.0.1:9001, got %q", target)
		}
	})

	t.Run("multiple routes distributes (M4: not always routes[0])", func(t *testing.T) {
		routes := []RouteConfig{{Target: "first"}, {Target: "second"}}
		seen := make(map[string]bool)
		for i := 0; i < 20; i++ {
			seen[selectTarget(routes)] = true
		}
		if len(seen) < 2 {
			t.Errorf("expected distribution across multiple routes, got %v", seen)
		}
	})
}

func TestQUICProxyActiveClientsInitial(t *testing.T) {
	q := &QUICProxy{}
	if n := q.ActiveClients(); n != 0 {
		t.Errorf("ActiveClients() = %d, want 0", n)
	}
}

func TestQUICRBACEnforcement(t *testing.T) {
	pki := setupPKI(t)
	gwAddr := freePort(t)

	q, err := NewQUICProxy(
		ListenerConfig{
			Name:     "quic-rbac",
			Listen:   gwAddr,
			Protocol: ProtocolQUIC,
			TLS: &gw.TLSConfig{
				CACertFile: pki.CACertFile,
				CertFile:   pki.ServerCertFile,
				KeyFile:    pki.ServerKeyFile,
				AllowRoles: []string{"gateway:admin"},
			},
		},
		nil, nil, nil, nil, nil, make(chan struct{}), NewBundle(), "en", nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("NewQUICProxy: %v", err)
	}
	if err := q.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer q.Stop()
	time.Sleep(100 * time.Millisecond)

	t.Run("admin role allowed to open stream", func(t *testing.T) {
		adminCert, err := tls.LoadX509KeyPair(pki.ClientCertFile, pki.ClientKeyFile)
		if err != nil {
			t.Fatal(err)
		}

		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{adminCert},
			RootCAs:      pki.CAPool,
			ServerName:   "server.test",
			NextProtos:   []string{"h3", "hq"},
			MinVersion:   tls.VersionTLS13,
		}

		conn, err := quic.DialAddr(context.Background(), gwAddr, tlsCfg, nil)
		if err != nil {
			t.Fatalf("DialAddr: %v", err)
		}
		defer conn.CloseWithError(0, "done")

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			t.Fatalf("OpenStreamSync should succeed: %v", err)
		}
		stream.Close()
	})

	t.Run("no role rejected", func(t *testing.T) {
		noRoleCert, err := tls.LoadX509KeyPair(pki.NoRoleCertFile, pki.NoRoleKeyFile)
		if err != nil {
			t.Fatal(err)
		}

		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{noRoleCert},
			RootCAs:      pki.CAPool,
			ServerName:   "server.test",
			NextProtos:   []string{"h3", "hq"},
			MinVersion:   tls.VersionTLS13,
		}

		conn, err := quic.DialAddr(context.Background(), gwAddr, tlsCfg, nil)
		if err != nil {
			t.Fatalf("DialAddr should succeed: %v", err)
		}
		defer conn.CloseWithError(0, "done")
		time.Sleep(200 * time.Millisecond)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err = conn.OpenStreamSync(ctx)
		if err == nil {
			t.Error("expected OpenStreamSync to fail (RBAC denied)")
		} else {
			t.Logf("got expected error: %v", err)
		}
	})
}

func TestQUICRoleExtraction(t *testing.T) {
	pki := setupPKI(t)

	adminCert, err := tls.LoadX509KeyPair(pki.ClientCertFile, pki.ClientKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	noRoleCert, err := tls.LoadX509KeyPair(pki.NoRoleCertFile, pki.NoRoleKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	adminParsed, _ := x509.ParseCertificate(adminCert.Certificate[0])
	noRoleParsed, _ := x509.ParseCertificate(noRoleCert.Certificate[0])

	adminRoles := gw.ExtractRoles(adminParsed)
	noRoleRoles := gw.ExtractRoles(noRoleParsed)

	if !gw.CheckRole(adminRoles, []string{"gateway:admin"}) {
		t.Error("expected admin cert to have gateway:admin role")
	}
	if gw.CheckRole(noRoleRoles, []string{"gateway:admin"}) {
		t.Error("expected no-role cert to NOT have gateway:admin role")
	}
}

func TestQUICDataForwarding(t *testing.T) {
	pki := setupPKI(t)

	echoConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoConn.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := echoConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echoConn.WriteTo(buf[:n], addr)
		}
	}()

	gwAddr := freePort(t)

	q, err := NewQUICProxy(
		ListenerConfig{
			Name:           "quic-data",
			Listen:         gwAddr,
			Protocol:       ProtocolQUIC,
			ReadTimeoutSec: 1,
			TLS: &gw.TLSConfig{
				CACertFile: pki.CACertFile,
				CertFile:   pki.ServerCertFile,
				KeyFile:    pki.ServerKeyFile,
				AllowRoles: []string{"gateway:admin"},
			},
			Routes: []RouteConfig{
				{Target: echoConn.LocalAddr().String()},
			},
		},
		nil, nil, nil, nil, nil, make(chan struct{}), NewBundle(), "en", nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("NewQUICProxy: %v", err)
	}
	if err := q.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer q.Stop()
	time.Sleep(100 * time.Millisecond)

	adminCert, err := tls.LoadX509KeyPair(pki.ClientCertFile, pki.ClientKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{adminCert},
		RootCAs:      pki.CAPool,
		ServerName:   "server.test",
		NextProtos:   []string{"h3", "hq"},
		MinVersion:   tls.VersionTLS13,
	}

	conn, err := quic.DialAddr(context.Background(), gwAddr, tlsCfg, nil)
	if err != nil {
		t.Fatalf("DialAddr: %v", err)
	}
	defer conn.CloseWithError(0, "done")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenStreamSync: %v", err)
	}

	msg := "hello quic echo\n"
	if _, err := stream.Write([]byte(msg)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	stream.Close()

	reply := make([]byte, len(msg))
	if _, err := io.ReadFull(stream, reply); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}

	if string(reply) != msg {
		t.Errorf("got %q, want %q", string(reply), msg)
	}
}
