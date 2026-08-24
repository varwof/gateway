// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package tcpgw

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

func TestMappingServerTLSMode(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "server", caCert, caKey, nil)

	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	m, err := NewMapping(MappingConfig{
		Name: "srv", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(),
		Protocol: ProtocolTCP,
		TLS: &gw.TLSConfig{
			Mode:     gw.TLSModeServer,
			CertFile: filepath.Join(dir, "server.pem"),
			KeyFile:  filepath.Join(dir, "server.key"),
		},
	}, nil, nil, nil, nil, NewBundle(), "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	conn, err := tls.Dial("tcp", m.listener.Addr().String(), &tls.Config{
		RootCAs: pool,
	})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(conn, "hi\n")
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "hi\n" {
		t.Fatalf("echo = %q", string(buf[:n]))
	}
}

func TestMappingServerTLSModeLoadCertError(t *testing.T) {
	dir := t.TempDir()
	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	m, err := NewMapping(MappingConfig{
		Name: "bad", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(),
		Protocol: ProtocolTCP,
		TLS: &gw.TLSConfig{
			Mode:     gw.TLSModeServer,
			CertFile: filepath.Join(dir, "missing.pem"),
			KeyFile:  filepath.Join(dir, "missing.key"),
		},
	}, nil, nil, nil, nil, NewBundle(), "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	if err := m.Start(); err == nil {
		m.Stop()
		t.Fatal("expected cert load error")
	}
}

func TestMappingClientModeUnsupported(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "client", caCert, caKey, nil)

	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	m, err := NewMapping(MappingConfig{
		Name: "cli", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(),
		Protocol: ProtocolTCP,
		TLS: &gw.TLSConfig{
			Mode:       "client",
			CACertFile: filepath.Join(dir, "ca.pem"),
		},
	}, nil, nil, nil, nil, NewBundle(), "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	if err := m.Start(); err == nil {
		m.Stop()
		t.Fatal("expected unsupported tls_mode error for client")
	}
	if m.State() != MappingStopped {
		t.Fatalf("State() = %v, want stopped", m.State())
	}
}

func TestMappingStartTwice(t *testing.T) {
	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	m, err := NewMapping(MappingConfig{
		Name: "twice", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(), Protocol: ProtocolTCP,
	}, nil, nil, nil, nil, NewBundle(), "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()
	if err := m.Start(); err == nil {
		t.Fatal("expected already-running error")
	}
}

func TestMappingHealthCheckFails(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "server", caCert, caKey, nil)

	m, _ := NewMapping(MappingConfig{
		Name: "hc", Listen: "127.0.0.1:0", Target: "127.0.0.1:1",
		Protocol: ProtocolTCPMTLS,
		TLS: &gw.TLSConfig{
			CACertFile: filepath.Join(dir, "ca.pem"),
			CertFile:   filepath.Join(dir, "server.pem"),
			KeyFile:    filepath.Join(dir, "server.key"),
			AllowRoles: []string{"gateway:admin"},
		},
		TCPExt: &gw.TCPExtra{
			HealthCheckSec: 1,
		},
	}, nil, nil, nil, nil, NewBundle(), "en", nil, nil, nil, nil)
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	waitFor(t, 10*time.Second, func() bool {
		return !m.Healthy()
	}, "health check to mark unhealthy")
	if m.State() != MappingUnhealthy {
		t.Fatalf("State() = %v, want unhealthy", m.State())
	}
}

func TestMappingHealthCheckHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "server", caCert, caKey, nil)

	m, _ := NewMapping(MappingConfig{
		Name: "hc-http", Listen: "127.0.0.1:0", Target: "127.0.0.1:1",
		Protocol: ProtocolTCPMTLS,
		TLS: &gw.TLSConfig{
			CACertFile: filepath.Join(dir, "ca.pem"),
			CertFile:   filepath.Join(dir, "server.pem"),
			KeyFile:    filepath.Join(dir, "server.key"),
			AllowRoles: []string{"gateway:admin"},
		},
		TCPExt: &gw.TCPExtra{
			HealthCheckSec: 1,
			HealthCheckURL: srv.URL,
		},
	}, nil, nil, nil, nil, NewBundle(), "en", nil, nil, nil, nil)
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	waitFor(t, 10*time.Second, func() bool {
		return !m.Healthy()
	}, "health check (HTTP 500) to mark unhealthy")

	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer okSrv.Close()
	m.cfg.TCPExt.HealthCheckURL = okSrv.URL

	waitFor(t, 10*time.Second, func() bool {
		return m.Healthy()
	}, "health check to recover after switch to healthy URL")
}

func TestMappingHealthCheckPlain(t *testing.T) {
	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	m, err := NewMapping(MappingConfig{
		Name: "hc-plain", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(),
		Protocol: ProtocolTCP,
	}, nil, nil, nil, nil, NewBundle(), "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	waitFor(t, 5*time.Second, func() bool {
		return m.Healthy()
	}, "health check should not run for plain mapping")
	if m.State() != MappingRunning {
		t.Fatalf("State() = %v, want running", m.State())
	}
}

func TestMappingAcceptAfterStop(t *testing.T) {
	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	m, err := NewMapping(MappingConfig{
		Name: "stop-acc", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(), Protocol: ProtocolTCP,
	}, nil, nil, nil, nil, NewBundle(), "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop again: %v", err)
	}
	if m.State() != MappingStopped {
		t.Fatalf("State() = %v, want stopped", m.State())
	}
}
