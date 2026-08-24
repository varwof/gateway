package httpgw

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	gw "github.com/varwof/gateway-core"
)

func genKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return key
}

func makeCert(t *testing.T, cn string, ous []string, isCA bool, extUsage []x509.ExtKeyUsage, signer *x509.Certificate, signerKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()
	key := genKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn, OrganizationalUnit: ous},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           extUsage,
		DNSNames:              []string{cn},
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	if signer == nil {
		signer = tmpl
		signerKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key, der
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}

type testPKI struct {
	CACertFile                    string
	ServerCertFile, ServerKeyFile string
	AdminCertFile, AdminKeyFile   string
	OpsCertFile, OpsKeyFile       string
	NoRoleCertFile, NoRoleKeyFile string
	CAPool                        *x509.CertPool
}

func setupPKI(t *testing.T) *testPKI {
	t.Helper()
	dir := t.TempDir()
	caCert, caKey, caDER := makeCert(t, "TestCA", nil, true, nil, nil, nil)
	writePEM(t, filepath.Join(dir, "ca.pem"), "CERTIFICATE", caDER)

	_, srvKey, srvDER := makeCert(t, "server.test", nil, false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, caCert, caKey)
	writePEM(t, filepath.Join(dir, "server.pem"), "CERTIFICATE", srvDER)
	writePEM(t, filepath.Join(dir, "server.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(srvKey))

	_, admKey, admDER := makeCert(t, "admin-user", []string{"gateway:admin"}, false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, caCert, caKey)
	writePEM(t, filepath.Join(dir, "admin.pem"), "CERTIFICATE", admDER)
	writePEM(t, filepath.Join(dir, "admin.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(admKey))

	_, opsKey, opsDER := makeCert(t, "ops-user", []string{"gateway:ops"}, false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, caCert, caKey)
	writePEM(t, filepath.Join(dir, "ops.pem"), "CERTIFICATE", opsDER)
	writePEM(t, filepath.Join(dir, "ops.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(opsKey))

	_, norKey, norDER := makeCert(t, "nobody", nil, false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, caCert, caKey)
	writePEM(t, filepath.Join(dir, "norole.pem"), "CERTIFICATE", norDER)
	writePEM(t, filepath.Join(dir, "norole.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(norKey))

	pool := x509.NewCertPool()
	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
	pool.AppendCertsFromPEM(caPEM)
	return &testPKI{
		CACertFile:     filepath.Join(dir, "ca.pem"),
		ServerCertFile: filepath.Join(dir, "server.pem"),
		ServerKeyFile:  filepath.Join(dir, "server.key"),
		AdminCertFile:  filepath.Join(dir, "admin.pem"),
		AdminKeyFile:   filepath.Join(dir, "admin.key"),
		OpsCertFile:    filepath.Join(dir, "ops.pem"),
		OpsKeyFile:     filepath.Join(dir, "ops.key"),
		NoRoleCertFile: filepath.Join(dir, "norole.pem"),
		NoRoleKeyFile:  filepath.Join(dir, "norole.key"),
		CAPool:         pool,
	}
}

// --- Orchestrator tests ---

func TestHTTPGateway_New(t *testing.T) {
	g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
	if g == nil {
		t.Fatal("NewGateway() returned nil")
	}
}

func TestHTTPGateway_StartStop(t *testing.T) {
	g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	g.Stop()
}

func TestHTTPGateway_StopIdempotent(t *testing.T) {
	g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
	g.Start()
	g.Stop()
	g.Stop()
}

func TestHTTPGateway_StartWithPlainListener(t *testing.T) {
	backendAddr, backendClose := startTestBackend(t)
	defer backendClose()

	g := NewGateway(&Config{
		Listeners: []ListenerConfig{{
			Name: "test", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
			Routes: []RouteConfig{{Path: "/*", Target: backendAddr}},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer g.Stop()

	if _, exists := g.listeners["test"]; !exists {
		t.Fatal("listener 'test' not found after Start()")
	}
}

func TestHTTPGateway_ManagementAPI(t *testing.T) {
	pki := setupPKI(t)
	mgmtAddr := fmt.Sprintf("127.0.0.1:%d", freePortTCP(t))

	g := NewGateway(&Config{
		Management: &MgmtConfig{
			Listen: mgmtAddr,
			TLS:    &gw.TLSConfig{CACertFile: pki.CACertFile, CertFile: pki.ServerCertFile, KeyFile: pki.ServerKeyFile},
		},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer g.Stop()
	time.Sleep(100 * time.Millisecond)

	cliCert, _ := tls.LoadX509KeyPair(pki.AdminCertFile, pki.AdminKeyFile)
	conn, err := tls.Dial("tcp", mgmtAddr, &tls.Config{
		Certificates:       []tls.Certificate{cliCert},
		RootCAs:            pki.CAPool,
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

// --- Data plane tests ---

func TestHTTPGateway_DataPlane(t *testing.T) {
	backendAddr, backendClose := startTestBackend(t)
	defer backendClose()

	g := NewGateway(&Config{
		Listeners: []ListenerConfig{{
			Name: "dp", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
			Routes: []RouteConfig{{Path: "/*", Target: backendAddr}},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer g.Stop()

	addr := g.listeners["dp"].Addr().String()
	resp, err := http.Get("http://" + addr + "/hello")
	if err != nil {
		t.Fatalf("http get: %v", err)
	}
	defer resp.Body.Close()
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestHTTPMTLS_HeaderInjection(t *testing.T) {
	pki := setupPKI(t)
	backendURL, backendClose := startTestBackend(t)
	defer backendClose()

	g := NewGateway(&Config{
		Listeners: []ListenerConfig{{
			Name: "mtls-header", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
			TLS: &gw.TLSConfig{
				Mode: gw.TLSModeMTLS, CACertFile: pki.CACertFile, CertFile: pki.ServerCertFile, KeyFile: pki.ServerKeyFile,
			},
			Routes: []RouteConfig{{Path: "/*", Target: backendURL}},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()
	time.Sleep(50 * time.Millisecond)

	addr := g.listeners["mtls-header"].Addr().String()
	cliCert, _ := tls.LoadX509KeyPair(pki.AdminCertFile, pki.AdminKeyFile)
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{cliCert},
		RootCAs:      pki.CAPool, ServerName: "server.test",
	})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()

	fmt.Fprint(conn, "GET /test HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	if !contains(string(buf[:n]), "200 OK") {
		t.Fatal("expected 200 OK")
	}
}

func TestHTTPPathLevelRBAC(t *testing.T) {
	pki := setupPKI(t)
	backendURL, backendClose := startTestBackend(t)
	defer backendClose()

	g := NewGateway(&Config{
		Listeners: []ListenerConfig{{
			Name: "rbac", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
			TLS: &gw.TLSConfig{
				Mode: gw.TLSModeMTLS, CACertFile: pki.CACertFile, CertFile: pki.ServerCertFile, KeyFile: pki.ServerKeyFile,
			},
			Routes: []RouteConfig{
				{Path: "/admin/*", Target: backendURL, AllowRoles: []string{"gateway:admin"}},
				{Path: "/ops/*", Target: backendURL, AllowRoles: []string{"gateway:ops"}},
				{Path: "/public/*", Target: backendURL},
			},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()
	time.Sleep(50 * time.Millisecond)

	addr := g.listeners["rbac"].Addr().String()

	tests := []struct {
		name     string
		certFile string
		keyFile  string
		path     string
		wantOK   bool
	}{
		{"admin->admin", pki.AdminCertFile, pki.AdminKeyFile, "/admin/test", true},
		{"admin->ops", pki.AdminCertFile, pki.AdminKeyFile, "/ops/test", false},
		{"admin->public", pki.AdminCertFile, pki.AdminKeyFile, "/public/test", true},
		{"ops->admin", pki.OpsCertFile, pki.OpsKeyFile, "/admin/test", false},
		{"ops->ops", pki.OpsCertFile, pki.OpsKeyFile, "/ops/test", true},
		{"ops->public", pki.OpsCertFile, pki.OpsKeyFile, "/public/test", true},
		{"norole->public", pki.NoRoleCertFile, pki.NoRoleKeyFile, "/public/test", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cliCert, _ := tls.LoadX509KeyPair(tt.certFile, tt.keyFile)
			conn, err := tls.Dial("tcp", addr, &tls.Config{
				Certificates: []tls.Certificate{cliCert},
				RootCAs:      pki.CAPool, ServerName: "server.test",
			})
			if err != nil {
				if !tt.wantOK {
					return
				}
				t.Fatalf("tls dial: %v", err)
			}
			defer conn.Close()

			fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n", tt.path)
			buf := make([]byte, 4096)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, _ := conn.Read(buf)
			gotOK := contains(string(buf[:n]), "200 OK")
			if gotOK != tt.wantOK {
				t.Fatalf("path=%s: got 200=%v, want 200=%v", tt.path, gotOK, tt.wantOK)
			}
		})
	}
}

func TestHTTPMetricsEndpoint(t *testing.T) {
	pki := setupPKI(t)
	mgmtAddr := fmt.Sprintf("127.0.0.1:%d", freePortTCP(t))

	g := NewGateway(&Config{
		Management: &MgmtConfig{
			Listen: mgmtAddr,
			TLS:    &gw.TLSConfig{CACertFile: pki.CACertFile, CertFile: pki.ServerCertFile, KeyFile: pki.ServerKeyFile},
		},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()
	time.Sleep(100 * time.Millisecond)

	cliCert, _ := tls.LoadX509KeyPair(pki.AdminCertFile, pki.AdminKeyFile)
	conn, err := tls.Dial("tcp", mgmtAddr, &tls.Config{
		Certificates:       []tls.Certificate{cliCert},
		RootCAs:            pki.CAPool,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()

	fmt.Fprint(conn, "GET /api/v1/gateway/metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
	buf := make([]byte, 8192)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	body := string(buf[:n])
	if !contains(body, "200 OK") {
		t.Fatalf("expected 200, got: %s", body)
	}
	if !contains(body, "# HELP") {
		t.Fatal("expected Prometheus metrics")
	}
}

// --- Reload test ---

func TestHTTPGateway_Reload(t *testing.T) {
	backend1, close1 := startTestBackend(t)
	defer close1()
	backend2, close2 := startTestBackend(t)
	defer close2()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "cfg.json")
	initialCfg := fmt.Sprintf(`{"listeners":[{"name":"primary","listen":"127.0.0.1:0","protocol":"http2","routes":[{"path":"/*","target":"%s"}]}]}`, backend1)
	if err := os.WriteFile(configPath, []byte(initialCfg), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()

	addr := g.listeners["primary"].Addr().String()
	resp, err := http.Get("http://" + addr + "/test")
	if err != nil {
		t.Fatalf("initial request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("initial: got %d", resp.StatusCode)
	}

	reloadCfg := fmt.Sprintf(`{"listeners":[{"name":"primary","listen":"127.0.0.1:0","protocol":"http2","routes":[{"path":"/*","target":"%s"}]}]}`, backend2)
	if err := os.WriteFile(configPath, []byte(reloadCfg), 0644); err != nil {
		t.Fatal(err)
	}
	if err := g.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	newAddr := g.listeners["primary"].Addr().String()
	resp2, err := http.Get("http://" + newAddr + "/test")
	if err != nil {
		t.Fatalf("reload request: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("reload: got %d", resp2.StatusCode)
	}
}

// --- H2C backend test ---

func TestHTTPBackend_H2C(t *testing.T) {
	backendAddr, backendClose := startH2CBackend(t)
	defer backendClose()

	g := NewGateway(&Config{
		Listeners: []ListenerConfig{{
			Name: "h2c-test", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
			Routes: []RouteConfig{
				{Path: "/*", Target: "http://" + backendAddr, BackendProtocol: BackendProtoH2C},
			},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()
	time.Sleep(50 * time.Millisecond)

	addr := g.listeners["h2c-test"].Addr().String()
	resp, err := http.Get("http://" + addr + "/hello")
	if err != nil {
		t.Fatalf("http get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "from h2c backend\n" {
		t.Errorf("body = %q, want %q", string(body), "from h2c backend\n")
	}
}

func TestHTTPBackend_H1(t *testing.T) {
	backendAddr, backendClose := startTestBackend(t)
	defer backendClose()

	g := NewGateway(&Config{
		Listeners: []ListenerConfig{{
			Name: "h1-test", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
			Routes: []RouteConfig{
				{Path: "/*", Target: backendAddr, BackendProtocol: BackendProtoH1},
			},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()
	time.Sleep(50 * time.Millisecond)

	addr := g.listeners["h1-test"].Addr().String()
	resp, err := http.Get("http://" + addr + "/test")
	if err != nil {
		t.Fatalf("http get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !contains(string(body), "ok") {
		t.Errorf("body = %q, want containing 'ok'", string(body))
	}
}

// --- gRPC proxy test ---

func TestHTTPGRPCProxy(t *testing.T) {
	grpcBackendAddr, grpcBackendClose := startGRPCBackend(t)
	defer grpcBackendClose()

	g := NewGateway(&Config{
		Listeners: []ListenerConfig{{
			Name: "grpc-test", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
			Routes: []RouteConfig{
				{Path: "/*", Target: "http://" + grpcBackendAddr, BackendProtocol: BackendProtoH2C},
			},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()
	time.Sleep(50 * time.Millisecond)

	addr := g.listeners["grpc-test"].Addr().String()

	t.Run("grpc content-type forwarded via h2c", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "http://"+addr+"/grpc.test.Service/Call", nil)
		req.Header.Set("Content-Type", "application/grpc")
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
		}
		if string(body) != "grpc ok" {
			t.Errorf("body = %q, want %q", string(body), "grpc ok")
		}
	})

	t.Run("non-grpc request through h2c backend works", func(t *testing.T) {
		resp, err := http.Get("http://" + addr + "/test")
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
		}
		if string(body) != "from h2c backend\n" {
			t.Errorf("body = %q, want %q", string(body), "from h2c backend\n")
		}
	})
}

func startGRPCBackend(t *testing.T) (string, func()) {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if ct == "application/grpc" {
			w.Write([]byte("grpc ok"))
		} else if r.ProtoAtLeast(2, 0) {
			w.Write([]byte("from h2c backend\n"))
		} else {
			w.Write([]byte("from h1c backend\n"))
		}
	})
	h2s := &http2.Server{}
	srv := &http.Server{
		Handler: h2c.NewHandler(handler, h2s),
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("grpc backend listen: %v", err)
	}
	go srv.Serve(lis)
	return lis.Addr().String(), func() {
		srv.Close()
		time.Sleep(50 * time.Millisecond)
	}
}

func startH2CBackend(t *testing.T) (string, func()) {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoAtLeast(2, 0) {
			w.Write([]byte("from h2c backend\n"))
		} else {
			w.Write([]byte("from h1c backend\n"))
		}
	})
	h2s := &http2.Server{}
	srv := &http.Server{
		Handler: h2c.NewHandler(handler, h2s),
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("h2c listen: %v", err)
	}
	go srv.Serve(lis)
	return lis.Addr().String(), func() {
		srv.Close()
		time.Sleep(50 * time.Millisecond)
	}
}

// --- Helpers ---

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

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
