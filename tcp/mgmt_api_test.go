// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package tcpgw

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

type mgmtClient struct {
	base string
	hc   *http.Client
}

func newMgmtClient(t *testing.T, addr string, dir string) *mgmtClient {
	t.Helper()
	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(dir, "client.pem"), filepath.Join(dir, "client.key"))
	if err != nil {
		t.Fatalf("load client cert: %v", err)
	}
	return &mgmtClient{
		base: "https://" + addr,
		hc: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates:       []tls.Certificate{cert},
					RootCAs:            pool,
					InsecureSkipVerify: true,
				},
			},
		},
	}
}

func (c *mgmtClient) do(t *testing.T, method, path, body string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		t.Fatalf("do %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestTCPGatewayManagementEndpoints(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "server.test", caCert, caKey, nil)
	generateTestCert(t, dir, "client", caCert, caKey, []string{"gateway:admin", "gateway:ops"})

	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	peerDir := newTunnelCertDir(t)

	mgmtAddr := fmt.Sprintf("127.0.0.1:%d", freePortTCP(t))
	g := NewGateway(&Config{
		Peers: []MeshPeerConfig{{
			Name: "peer1", Addr: "127.0.0.1:1",
			CACertFile: filepath.Join(peerDir, "ca.pem"),
			CertFile:   filepath.Join(peerDir, "client.pem"),
			KeyFile:    filepath.Join(peerDir, "client.key"),
		}},
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
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()

	c := newMgmtClient(t, mgmtAddr, dir)

	code, body := c.do(t, http.MethodGet, "/api/v1/gateway/mappings", "")
	if code != http.StatusOK {
		t.Fatalf("list mappings: %d %s", code, body)
	}

	code, _ = c.do(t, http.MethodPost, "/api/v1/gateway/mappings",
		`{"name":"web","listen":"127.0.0.1:0","target":"`+echoSrv.Addr().String()+`","protocol":"tcp"}`)
	if code != http.StatusCreated {
		t.Fatalf("add mapping: %d", code)
	}

	code, body = c.do(t, http.MethodGet, "/api/v1/gateway/mappings", "")
	if code != http.StatusOK || !strings.Contains(body, `"name":"web"`) {
		t.Fatalf("list after add: %d %s", code, body)
	}

	code, _ = c.do(t, http.MethodDelete, "/api/v1/gateway/mappings/web", "")
	if code != http.StatusOK {
		t.Fatalf("delete mapping: %d", code)
	}

	code, _ = c.do(t, http.MethodDelete, "/api/v1/gateway/mappings/nope", "")
	if code != http.StatusNotFound {
		t.Fatalf("delete missing: %d", code)
	}

	code, body = c.do(t, http.MethodPost, "/api/v1/gateway/reload", "")
	if code != http.StatusOK {
		t.Fatalf("reload: %d %s", code, body)
	}

	code, body = c.do(t, http.MethodPost, "/api/v1/gateway/crl/reload", "")
	if code != http.StatusOK {
		t.Fatalf("crl reload: %d %s", code, body)
	}

	code, body = c.do(t, http.MethodGet, "/api/v1/gateway/peers", "")
	if code != http.StatusOK || !strings.Contains(body, `"name":"peer1"`) {
		t.Fatalf("peers: %d %s", code, body)
	}

	code, _ = c.do(t, http.MethodPost, "/api/v1/gateway/renew", `{}`)
	if code != http.StatusUnauthorized && code != http.StatusServiceUnavailable && code != http.StatusBadRequest {
		t.Fatalf("renew: unexpected %d", code)
	}

	code, _ = c.do(t, http.MethodPost, "/api/v1/gateway/disconnect-agent", `{}`)
	if code > 499 {
		t.Fatalf("disconnect-agent: %d", code)
	}

	code, _ = c.do(t, http.MethodPost, "/api/v1/gateway/disconnect-user", `{}`)
	if code > 499 {
		t.Fatalf("disconnect-user: %d", code)
	}

	code, _ = c.do(t, http.MethodPut, "/api/v1/gateway/mappings", "")
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT mappings should be 405, got %d", code)
	}

	code, _ = c.do(t, http.MethodGet, "/api/v1/gateway/reload", "")
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("GET reload should be 405, got %d", code)
	}
}

func TestTCPGatewayManagementDisconnectEndpoints(t *testing.T) {
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
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()

	c := newMgmtClient(t, mgmtAddr, dir)
	code, body := c.do(t, http.MethodPost, "/api/v1/gateway/disconnect-agent",
		`{"serial":"1"}`)
	if code != http.StatusOK && code != http.StatusBadRequest && code != http.StatusNotFound {
		t.Fatalf("disconnect-agent: %d %s", code, body)
	}
}
