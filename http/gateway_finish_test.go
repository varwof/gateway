package httpgw

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

// mgmtRawRequest performs a raw TLS request against the management listener and
// returns the status line plus a chunk of the response body.
func mgmtRawRequest(t *testing.T, addr string, pki *testPKI, method, path, body string) (string, string) {
	t.Helper()
	cliCert, err := tls.LoadX509KeyPair(pki.AdminCertFile, pki.AdminKeyFile)
	if err != nil {
		t.Fatalf("load admin cert: %v", err)
	}
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates:       []tls.Certificate{cliCert},
		RootCAs:            pki.CAPool,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()

	req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n", method, path)
	if body != "" {
		req += fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)
	} else {
		req += "\r\n"
	}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	return resp.Status, string(buf[:n])
}

func TestGatewayStartCreateListenerError(t *testing.T) {
	g := NewGateway(&Config{
		Listeners: []ListenerConfig{{
			Name: "bad", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
			Routes: []RouteConfig{{Path: "/*", Target: "://bad-target"}},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	err := g.Start()
	if err == nil || !strings.Contains(err.Error(), "create listener") {
		t.Fatalf("Start error = %v, want create listener error", err)
	}
}

func TestGatewayStartListenerStartError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	g := NewGateway(&Config{
		Listeners: []ListenerConfig{{Name: "busy", Listen: ln.Addr().String(), Protocol: ProtocolHTTP2}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	err = g.Start()
	if err == nil || !strings.Contains(err.Error(), "start listener") {
		t.Fatalf("Start error = %v, want start listener error", err)
	}
}

func TestGatewayStartManagementBadCA(t *testing.T) {
	pki := setupPKI(t)
	g := NewGateway(&Config{
		Management: &MgmtConfig{
			Listen: fmt.Sprintf("127.0.0.1:%d", freePortTCP(t)),
			TLS: &gw.TLSConfig{
				CACertFile: "/nonexistent/ca.pem",
				CertFile:   pki.ServerCertFile,
				KeyFile:    pki.ServerKeyFile,
			},
		},
	}, NewBundle(), "en", nil, nil, nil, nil)
	err := g.Start()
	if err == nil || !strings.Contains(err.Error(), "management API") {
		t.Fatalf("Start error = %v, want management API error", err)
	}
}

func TestGatewayAuthorizationFallbackCA(t *testing.T) {
	pki := setupPKI(t)
	cfg := &Config{
		AuthorizationFile: filepath.Join(t.TempDir(), "auth.yaml"),
		Listeners: []ListenerConfig{{
			Name: "l", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
			TLS:    &gw.TLSConfig{Mode: gw.TLSModeMTLS, CACertFile: pki.CACertFile, CertFile: pki.ServerCertFile, KeyFile: pki.ServerKeyFile},
			Routes: []RouteConfig{{Path: "/*", Target: "http://127.0.0.1:1"}},
		}},
	}
	NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
}

func TestGatewayTSAProofStartStop(t *testing.T) {
	proof := gw.NewTSAProofLogger(filepath.Join(t.TempDir(), "proof.log"), nil, nil, 3600)
	g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, proof, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	g.Stop()
}

func TestGatewayManagementEndpoints(t *testing.T) {
	pki := setupPKI(t)
	mgmtAddr := fmt.Sprintf("127.0.0.1:%d", freePortTCP(t))
	g := NewGateway(&Config{
		Management: &MgmtConfig{
			Listen: mgmtAddr,
			TLS:    &gw.TLSConfig{CACertFile: pki.CACertFile, CertFile: pki.ServerCertFile, KeyFile: pki.ServerKeyFile},
		},
	}, NewBundle(), "en", nil, nil, nil, nil)
	g.cfg.configPath = filepath.Join(t.TempDir(), "missing.json")
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()
	time.Sleep(100 * time.Millisecond)

	cases := []struct {
		method string
		path   string
		want   string
	}{
		{"PUT", "/api/v1/gateway/listeners", "405"},
		{"GET", "/api/v1/gateway/listeners/foo", "405"},
		{"GET", "/api/v1/gateway/reload", "405"},
		{"POST", "/api/v1/gateway/reload", "500"},
	}
	for _, tc := range cases {
		status, body := mgmtRawRequest(t, mgmtAddr, pki, tc.method, tc.path, "")
		if !strings.Contains(status, tc.want) {
			t.Errorf("%s %s: status = %s body = %s, want %s", tc.method, tc.path, status, body, tc.want)
		}
	}
}
