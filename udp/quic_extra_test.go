package udpgw

import (
	"bytes"
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	gw "github.com/varwof/gateway-core"
)

func TestQUICProxyConfig(t *testing.T) {
	cfg := ListenerConfig{Name: "q", Listen: ":1", Protocol: ProtocolQUIC}
	q := &QUICProxy{cfg: cfg}
	got := q.Config()
	if got.Name != cfg.Name || got.Listen != cfg.Listen || got.Protocol != cfg.Protocol {
		t.Errorf("Config() = %+v, want %+v", got, cfg)
	}
}

func TestQUICGetCertNilAndUpdate(t *testing.T) {
	q := &QUICProxy{}
	if c, err := q.getCert(nil); err != nil || c != nil {
		t.Errorf("getCert on fresh proxy = %v, %v; want nil, nil", c, err)
	}
	pki := setupPKI(t)
	cert, err := tls.LoadX509KeyPair(pki.ServerCertFile, pki.ServerKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	q.UpdateCert(&cert)
	got, err := q.getCert(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got.Certificate) == 0 {
		t.Fatal("UpdateCert did not store the certificate")
	}
}

func TestQUICRateLimitedWriter(t *testing.T) {
	t.Run("immediate when tokens available", func(t *testing.T) {
		bucket := gw.NewTokenBucket(100000, 100000)
		var buf bytes.Buffer
		w := &rateLimitedWriter{w: &buf, bucket: bucket}
		if _, err := w.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		if buf.String() != "hello" {
			t.Errorf("buf = %q", buf.String())
		}
	})

	t.Run("blocks until refilled", func(t *testing.T) {
		// WaitN can never exceed burst (refill caps at burst), so model the
		// fixed quic.go behavior where burst >= io.Copy chunk size.
		bucket := gw.NewTokenBucket(10000, 10000)
		var buf bytes.Buffer
		w := &rateLimitedWriter{w: &buf, bucket: bucket}
		if _, err := w.Write(make([]byte, 10000)); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if _, err := w.Write(make([]byte, 10000)); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
			t.Errorf("expected rate-limited write to block, took %v", elapsed)
		}
		if buf.Len() != 20000 {
			t.Errorf("buf.Len() = %d, want 20000", buf.Len())
		}
	})

	t.Run("unlimited rate never blocks", func(t *testing.T) {
		bucket := gw.NewTokenBucket(0, 0)
		var buf bytes.Buffer
		w := &rateLimitedWriter{w: &buf, bucket: bucket}
		start := time.Now()
		if _, err := w.Write(make([]byte, 1024)); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
			t.Errorf("unlimited write took %v", elapsed)
		}
	})
}

func TestQUICHandleConnectionNoClientCert(t *testing.T) {
	pki := setupPKI(t)
	gwAddr := freePort(t)

	// No CACertFile → server does not require a client certificate, so
	// handleConnection takes the clientCert == nil path (pipeline skipped,
	// acceptStream loop + handleStream no-route branch covered).
	q, err := NewQUICProxy(
		ListenerConfig{
			Name:           "quic-nocert",
			Listen:         gwAddr,
			Protocol:       ProtocolQUIC,
			ReadTimeoutSec: 1,
			TLS: &gw.TLSConfig{
				CertFile: pki.ServerCertFile,
				KeyFile:  pki.ServerKeyFile,
			},
		},
		nil, nil, nil, nil, nil, make(chan struct{}), NewBundle(), "en", nil, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Start(); err != nil {
		t.Fatal(err)
	}
	defer q.Stop()
	time.Sleep(100 * time.Millisecond)

	conn, err := quic.DialAddr(context.Background(), gwAddr, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3", "hq"},
		MinVersion:         tls.VersionTLS13,
	}, nil)
	if err != nil {
		t.Fatalf("DialAddr: %v", err)
	}
	defer conn.CloseWithError(0, "done")

	// Multiple streams exercise the acceptStream loop.
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		stream, err := conn.OpenStreamSync(ctx)
		cancel()
		if err != nil {
			t.Fatalf("OpenStreamSync #%d: %v", i, err)
		}
		stream.Close()
	}
}

func TestQUICPerIPLimit(t *testing.T) {
	pki := setupPKI(t)
	gwAddr := freePort(t)
	q, err := NewQUICProxy(
		ListenerConfig{
			Name:     "quic-ip-limit",
			Listen:   gwAddr,
			Protocol: ProtocolQUIC,
			TLS: &gw.TLSConfig{
				CACertFile:    pki.CACertFile,
				CertFile:      pki.ServerCertFile,
				KeyFile:       pki.ServerKeyFile,
				AllowRoles:    []string{"gateway:admin"},
				MaxConnsPerIP: 1,
			},
		},
		nil, nil, nil, nil, nil, make(chan struct{}), NewBundle(), "en", nil, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Start(); err != nil {
		t.Fatal(err)
	}
	defer q.Stop()
	time.Sleep(100 * time.Millisecond)

	adminCert, _ := tls.LoadX509KeyPair(pki.ClientCertFile, pki.ClientKeyFile)
	clientTLS := func() *tls.Config {
		return &tls.Config{
			Certificates: []tls.Certificate{adminCert},
			RootCAs:      pki.CAPool,
			ServerName:   "server.test",
			NextProtos:   []string{"h3", "hq"},
			MinVersion:   tls.VersionTLS13,
		}
	}

	conn1, err := quic.DialAddr(context.Background(), gwAddr, clientTLS(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.CloseWithError(0, "done")
	if _, err := conn1.OpenStreamSync(context.Background()); err != nil {
		t.Fatalf("first conn should be allowed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	conn2, err := quic.DialAddr(context.Background(), gwAddr, clientTLS(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.CloseWithError(0, "done")

	// The deny path in handleConnection closes the server-side connection; the
	// client's OpenStreamSync may still succeed, so assert the connection is
	// torn down instead.
	select {
	case <-conn2.Context().Done():
	case <-time.After(3 * time.Second):
		t.Error("second conn from same IP should be denied by MaxConnsPerIP")
	}
}

func TestQUICPerCertLimit(t *testing.T) {
	pki := setupPKI(t)
	gwAddr := freePort(t)
	q, err := NewQUICProxy(
		ListenerConfig{
			Name:     "quic-cert-limit",
			Listen:   gwAddr,
			Protocol: ProtocolQUIC,
			TLS: &gw.TLSConfig{
				CACertFile:      pki.CACertFile,
				CertFile:        pki.ServerCertFile,
				KeyFile:         pki.ServerKeyFile,
				AllowRoles:      []string{"gateway:admin"},
				MaxConnsPerCert: 1,
			},
		},
		nil, nil, nil, nil, nil, make(chan struct{}), NewBundle(), "en", nil, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Start(); err != nil {
		t.Fatal(err)
	}
	defer q.Stop()
	time.Sleep(100 * time.Millisecond)

	adminCert, _ := tls.LoadX509KeyPair(pki.ClientCertFile, pki.ClientKeyFile)
	clientTLS := func() *tls.Config {
		return &tls.Config{
			Certificates: []tls.Certificate{adminCert},
			RootCAs:      pki.CAPool,
			ServerName:   "server.test",
			NextProtos:   []string{"h3", "hq"},
			MinVersion:   tls.VersionTLS13,
		}
	}

	conn1, err := quic.DialAddr(context.Background(), gwAddr, clientTLS(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.CloseWithError(0, "done")
	if _, err := conn1.OpenStreamSync(context.Background()); err != nil {
		t.Fatalf("first conn should be allowed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	conn2, err := quic.DialAddr(context.Background(), gwAddr, clientTLS(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.CloseWithError(0, "done")

	select {
	case <-conn2.Context().Done():
	case <-time.After(3 * time.Second):
		t.Error("second conn with same cert should be denied by MaxConnsPerCert")
	}
}

func TestQUICMaxTotalConns(t *testing.T) {
	pki := setupPKI(t)
	gwAddr := freePort(t)
	q, err := NewQUICProxy(
		ListenerConfig{
			Name:     "quic-total-limit",
			Listen:   gwAddr,
			Protocol: ProtocolQUIC,
			TLS: &gw.TLSConfig{
				CACertFile:    pki.CACertFile,
				CertFile:      pki.ServerCertFile,
				KeyFile:       pki.ServerKeyFile,
				AllowRoles:    []string{"gateway:admin"},
				MaxTotalConns: 1,
			},
		},
		nil, nil, nil, nil, nil, make(chan struct{}), NewBundle(), "en", nil, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Start(); err != nil {
		t.Fatal(err)
	}
	defer q.Stop()
	time.Sleep(100 * time.Millisecond)

	adminCert, _ := tls.LoadX509KeyPair(pki.ClientCertFile, pki.ClientKeyFile)
	clientTLS := func() *tls.Config {
		return &tls.Config{
			Certificates: []tls.Certificate{adminCert},
			RootCAs:      pki.CAPool,
			ServerName:   "server.test",
			NextProtos:   []string{"h3", "hq"},
			MinVersion:   tls.VersionTLS13,
		}
	}

	conn1, err := quic.DialAddr(context.Background(), gwAddr, clientTLS(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.CloseWithError(0, "done")
	if _, err := conn1.OpenStreamSync(context.Background()); err != nil {
		t.Fatalf("first conn should be allowed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	conn2, err := quic.DialAddr(context.Background(), gwAddr, clientTLS(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.CloseWithError(0, "done")

	select {
	case <-conn2.Context().Done():
	case <-time.After(3 * time.Second):
		t.Error("second conn should be denied by MaxTotalConns")
	}
}
