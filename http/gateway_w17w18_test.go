package httpgw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

// writePEMFile writes a PEM file (for testing).
func writePEMFile(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	block := &pem.Block{Type: typ, Bytes: der}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
}

// genSelfSignedTLS generates a self-signed CA + server certificate (with SAN),
// returns the CA certificate and tls.Certificate.
// If caCertIn/caKeyIn are provided, they are used to sign the server cert; otherwise a new CA is created.
func genSelfSignedTLS(t *testing.T, cn string, caCertIn *x509.Certificate, caKeyIn *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, tls.Certificate, []byte) {
	t.Helper()
	caCert := caCertIn
	caKey := caKeyIn
	if caCert == nil {
		caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		caTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: cn + "-ca"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}
		caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
		caCert, _ = x509.ParseCertificate(caDER)
	}

	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", cn},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  srvKey,
	}
	return caCert, caKey, cert, certDER
}

// startTLSBackend starts an HTTPS backend, using the given CA to sign the server certificate.
func startTLSBackend(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (string, func()) {
	t.Helper()
	_, _, cert, _ := genSelfSignedTLS(t, "backend", caCert, caKey)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("mTLS backend ok\n"))
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeTLS(lis, "", "")
	return "https://" + lis.Addr().String(), func() {
		srv.Close()
		time.Sleep(50 * time.Millisecond)
	}
}

// TestTransportResponseHeaderTimeout W17: backend transport must have
// ResponseHeaderTimeout, otherwise client requests hang forever if backend hangs after accept.
func TestTransportResponseHeaderTimeout(t *testing.T) {
	cfg := ListenerConfig{Name: "w17", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
		Routes: []RouteConfig{{Path: "/*", Target: "http://127.0.0.1:1"}}}
	p, err := NewProxyListener(cfg, nil, nil, nil, nil, nil, nil, "en", nil, nil)
	if err != nil {
		t.Fatalf("NewProxyListener: %v", err)
	}
	if p.transport.ResponseHeaderTimeout != 30*time.Second {
		t.Fatalf("ResponseHeaderTimeout = %v, want 30s (W17 unbound)", p.transport.ResponseHeaderTimeout)
	}
	// h1 clone preserves it.
	tr := p.transportForProtocol(BackendProtoH1, nil).(*http.Transport)
	if tr.ResponseHeaderTimeout != 30*time.Second {
		t.Fatalf("h1 ResponseHeaderTimeout = %v, want 30s", tr.ResponseHeaderTimeout)
	}
}

// TestUpstreamTLSConfigValid W18: UpstreamTLS parses CA + client certificate successfully.
func TestUpstreamTLSConfigValid(t *testing.T) {
	caCert, _, _, certDER := genSelfSignedTLS(t, "upstream-srv", nil, nil)
	dir := t.TempDir()
	writePEMFile(t, filepath.Join(dir, "ca.pem"), "CERTIFICATE", caCert.Raw)
	writePEMFile(t, filepath.Join(dir, "srv.pem"), "CERTIFICATE", certDER)

	tc, err := upstreamTLSConfig(&UpstreamTLSConfig{
		CACertFile: filepath.Join(dir, "ca.pem"),
		ServerName: "backend",
	}, "backend")
	if err != nil {
		t.Fatalf("upstreamTLSConfig: %v", err)
	}
	if tc == nil {
		t.Fatal("expected non-nil tls.Config")
	}
	if tc.ServerName != "backend" {
		t.Errorf("ServerName = %q, want backend", tc.ServerName)
	}
	if tc.RootCAs == nil {
		t.Error("RootCAs should be set from CA file")
	}
}

// TestUpstreamTLSConfigBadCA W18: missing CA file must return error (fail-fast, not silent).
func TestUpstreamTLSConfigBadCA(t *testing.T) {
	if _, err := upstreamTLSConfig(&UpstreamTLSConfig{
		CACertFile: "/nonexistent/ca.pem",
	}, "backend"); err == nil {
		t.Fatal("expected error for missing CA file")
	}
}

// TestProxyUpstreamMTLS E2E: gateway connects back to HTTPS backend with custom CA
// (W18 documented upstream_mtls), request should return 200.
func TestProxyUpstreamMTLS(t *testing.T) {
	caCert, caKey, _, _ := genSelfSignedTLS(t, "backend", nil, nil)
	backendURL, backendClose := startTLSBackend(t, caCert, caKey)
	defer backendClose()

	dir := t.TempDir()
	writePEMFile(t, filepath.Join(dir, "ca.pem"), "CERTIFICATE", caCert.Raw)

	g := NewGateway(&Config{
		Listeners: []ListenerConfig{{
			Name: "w18", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
			Routes: []RouteConfig{{
				Path: "/*", Target: backendURL,
				UpstreamTLS: &UpstreamTLSConfig{
					CACertFile: filepath.Join(dir, "ca.pem"),
					ServerName: "backend",
				},
			}},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()
	time.Sleep(50 * time.Millisecond)

	addr := g.listeners["w18"].Addr().String()
	resp, err := http.Get("http://" + addr + "/hello")
	if err != nil {
		t.Fatalf("http get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, body)
	}
}

// headerCaptureBackend starts a backend that captures request headers,
// returns the listen address and a result channel.
func headerCaptureBackend(t *testing.T) (string, <-chan http.Header) {
	t.Helper()
	ch := make(chan http.Header, 8)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ch <- r.Header.Clone()
			w.Write([]byte("ok\n"))
		}),
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(lis)
	return "http://" + lis.Addr().String(), ch
}

// TestProxyStripForgedIdentityHeaders W19: on a plain listener, client-forged
// X-Client-Cert-* / X-AIC-* headers must not reach the backend (prevents identity spoofing).
func TestProxyStripForgedIdentityHeaders(t *testing.T) {
	backendURL, ch := headerCaptureBackend(t)
	defer func() { time.Sleep(50 * time.Millisecond) }()

	g := NewGateway(&Config{
		Listeners: []ListenerConfig{{
			Name: "w19", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
			Routes: []RouteConfig{{Path: "/*", Target: backendURL}},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()
	time.Sleep(50 * time.Millisecond)

	addr := g.listeners["w19"].Addr().String()
	req, _ := http.NewRequest("GET", "http://"+addr+"/x", nil)
	req.Header.Set("X-Client-Cert-DER", "Zm9yZ2Vk")
	req.Header.Set("X-Client-Cert-CN", "admin")
	req.Header.Set("X-Client-Cert-Serial", "12345")
	req.Header.Set("X-Agent-TTL", "2099-01-01T00:00:00Z")
	req.Header.Set("X-AIC-Task-Id", "forged-task")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	select {
	case hdr := <-ch:
		for _, h := range []string{
			"X-Client-Cert-DER", "X-Client-Cert-CN", "X-Client-Cert-Serial",
			"X-Agent-TTL", "X-AIC-Task-Id", "X-AIC-Task-Status",
		} {
			if hdr.Get(h) != "" {
				t.Errorf("forged header %q leaked to backend: %q", h, hdr.Get(h))
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("backend never received request")
	}
}

// TestProxyTaskHeadersConsumedNotForwarded W19: under mTLS, X-AIC-Task-* headers are
// consumed by the gateway (task registration) but must not be forwarded to the backend.
// Uses a plain listener to verify stripping; mTLS task consumption is covered by existing task tests.
func TestProxyTaskHeadersNotForwarded(t *testing.T) {
	backendURL, ch := headerCaptureBackend(t)

	g := NewGateway(&Config{
		Listeners: []ListenerConfig{{
			Name: "w19b", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
			Routes: []RouteConfig{{Path: "/*", Target: backendURL}},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()
	time.Sleep(50 * time.Millisecond)

	addr := g.listeners["w19b"].Addr().String()
	req, _ := http.NewRequest("GET", "http://"+addr+"/t", nil)
	req.Header.Set("X-AIC-Task-Id", "task-1")
	req.Header.Set("X-AIC-Task-Status", "completed")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	select {
	case hdr := <-ch:
		if hdr.Get("X-AIC-Task-Id") != "" {
			t.Errorf("X-AIC-Task-Id leaked to backend")
		}
		if hdr.Get("X-AIC-Task-Status") != "" {
			t.Errorf("X-AIC-Task-Status leaked to backend")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("backend never received request")
	}
}

// TestMaxConnsPerIPByConnection W21: max_conns_per_ip counts by underlying TCP
// connections, not requests. A single keep-alive connection sending multiple requests
// should all pass; a second concurrent connection should get 429.
func TestMaxConnsPerIPByConnection(t *testing.T) {
	backendURL, _ := startTestBackend(t)
	defer func() { time.Sleep(50 * time.Millisecond) }()

	one := 1
	g := NewGateway(&Config{
		Listeners: []ListenerConfig{{
			Name: "w21", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
			Routes: []RouteConfig{{Path: "/*", Target: backendURL}},
			TLS: &gw.TLSConfig{
				MaxConnsPerIP: one,
			},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()
	time.Sleep(50 * time.Millisecond)

	addr := g.listeners["w21"].Addr().String()

	// Single connection (keep-alive reuse) sends 5 serial requests - before W21 fix
	// these were counted per-request, so the second request would get 429;
	// after fix, all requests on the same connection should get 200.
	client := &http.Client{Transport: &http.Transport{
		MaxIdleConnsPerHost: 5,
	}}
	allOK := true
	for i := 0; i < 5; i++ {
		resp, err := client.Get("http://" + addr + fmt.Sprintf("/r%d", i))
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			allOK = false
			t.Errorf("request %d on reused conn got %d, want 200 (W21 still counting requests)", i, resp.StatusCode)
		}
	}
	if !allOK {
		return
	}

	// Second concurrent connection should get 429 (per-IP connection limit).
	// Use a separate client to ensure no reuse of the first connection.
	client2 := &http.Client{Transport: &http.Transport{
		MaxIdleConnsPerHost: 0,
		DisableKeepAlives:   true,
	}}
	resp2, err := client2.Get("http://" + addr + "/second")
	if err != nil {
		t.Fatalf("second conn get: %v", err)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Errorf("second concurrent conn got %d, want 429 (per-IP connection limit)", resp2.StatusCode)
	}
}

// TestStatusResponseWriterFlush W20: statusResponseWriter supports Flush
// (SSE/chunked streaming), Flush must delegate to the underlying writer.
func TestStatusResponseWriterFlush(t *testing.T) {
	flushed := make(chan struct{})
	base := &flushRecorder{rec: httptest.NewRecorder(), onFlush: func() { close(flushed) }}
	s := &statusResponseWriter{ResponseWriter: base, status: http.StatusOK}

	s.WriteHeader(http.StatusOK)
	s.Flush()
	select {
	case <-flushed:
	case <-time.After(time.Second):
		t.Fatal("statusResponseWriter.Flush did not reach underlying flusher")
	}
}

// flushRecorder records flush events and can be wrapped by statusResponseWriter.
type flushRecorder struct {
	rec     *httptest.ResponseRecorder
	onFlush func()
}

func (f *flushRecorder) Header() http.Header         { return f.rec.Header() }
func (f *flushRecorder) Write(b []byte) (int, error) { return f.rec.Write(b) }
func (f *flushRecorder) WriteHeader(c int)           { f.rec.WriteHeader(c) }
func (f *flushRecorder) Flush() {
	if f.onFlush != nil {
		f.onFlush()
	}
}

// TestStatusResponseWriterUnwrap W20: Unwrap returns the underlying writer,
// allowing ResponseController to access Flusher/Hijacker.
func TestStatusResponseWriterUnwrap(t *testing.T) {
	base := httptest.NewRecorder()
	s := &statusResponseWriter{ResponseWriter: base, status: http.StatusOK}
	if s.Unwrap() != base {
		t.Fatal("Unwrap should return underlying ResponseWriter")
	}
}
