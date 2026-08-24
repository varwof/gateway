package udpgw

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pion/dtls/v2"
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
	ClientCertFile, ClientKeyFile string
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

	_, cliKey, cliDER := makeCert(t, "alice", []string{"gateway:admin"}, false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, caCert, caKey)
	writePEM(t, filepath.Join(dir, "client.pem"), "CERTIFICATE", cliDER)
	writePEM(t, filepath.Join(dir, "client.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(cliKey))

	_, nopKey, nopDER := makeCert(t, "bob", nil, false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, caCert, caKey)
	writePEM(t, filepath.Join(dir, "norole.pem"), "CERTIFICATE", nopDER)
	writePEM(t, filepath.Join(dir, "norole.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(nopKey))

	pool := x509.NewCertPool()
	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
	pool.AppendCertsFromPEM(caPEM)
	return &testPKI{
		CACertFile:     filepath.Join(dir, "ca.pem"),
		ServerCertFile: filepath.Join(dir, "server.pem"),
		ServerKeyFile:  filepath.Join(dir, "server.key"),
		ClientCertFile: filepath.Join(dir, "client.pem"),
		ClientKeyFile:  filepath.Join(dir, "client.key"),
		NoRoleCertFile: filepath.Join(dir, "norole.pem"),
		NoRoleKeyFile:  filepath.Join(dir, "norole.key"),
		CAPool:         pool,
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	a, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	c, _ := net.ListenUDP("udp", a)
	p := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	return fmt.Sprintf("127.0.0.1:%d", p)
}

// TestDTLSConnect: verify DTLS listener accepts connections.
func TestDTLSConnect(t *testing.T) {
	pki := setupPKI(t)
	gwAddr := freePort(t)
	g := NewGateway(&Config{
		Listeners: []ListenerConfig{{
			Name: "dtls", Listen: gwAddr, Protocol: ProtocolDTLS,
			TLS: &gw.TLSConfig{
				CACertFile: pki.CACertFile, CertFile: pki.ServerCertFile, KeyFile: pki.ServerKeyFile,
			},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer g.Stop()
	time.Sleep(100 * time.Millisecond)

	// G1: DTLS now enforces mutual auth — client must present a certificate.
	cliCert, err := tls.LoadX509KeyPair(pki.ClientCertFile, pki.ClientKeyFile)
	if err != nil {
		t.Fatalf("load client cert: %v", err)
	}
	addr, _ := net.ResolveUDPAddr("udp", gwAddr)
	conn, err := dtls.Dial("udp", addr, &dtls.Config{
		Certificates:       []tls.Certificate{cliCert},
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
}

// TestMTLSRejectNoRole: client without gateway:admin role gets data dropped.
func TestMTLSRejectNoRole(t *testing.T) {
	pki := setupPKI(t)
	gwAddr := freePort(t)
	g := NewGateway(&Config{
		Listeners: []ListenerConfig{{
			Name: "mtls-rbac", Listen: gwAddr, Protocol: ProtocolMTLS,
			TLS: &gw.TLSConfig{
				CACertFile: pki.CACertFile, CertFile: pki.ServerCertFile,
				KeyFile: pki.ServerKeyFile, AllowRoles: []string{"gateway:admin"},
			},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer g.Stop()
	time.Sleep(100 * time.Millisecond)

	noRole, _ := tls.LoadX509KeyPair(pki.NoRoleCertFile, pki.NoRoleKeyFile)
	addr, _ := net.ResolveUDPAddr("udp", gwAddr)
	conn, err := dtls.Dial("udp", addr, &dtls.Config{
		Certificates: []tls.Certificate{noRole},
		RootCAs:      pki.CAPool, ServerName: "server.test",
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	conn.Write([]byte("x"))
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 16)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected timeout (packet dropped), got response")
	}
}

// TestMTLSRejectUnknownCA: client signed by unknown CA should fail handshake.
func TestMTLSRejectUnknownCA(t *testing.T) {
	pki := setupPKI(t)
	gwAddr := freePort(t)
	g := NewGateway(&Config{
		Listeners: []ListenerConfig{{
			Name: "mtls-unknown", Listen: gwAddr, Protocol: ProtocolMTLS,
			TLS: &gw.TLSConfig{
				CACertFile: pki.CACertFile, CertFile: pki.ServerCertFile,
				KeyFile: pki.ServerKeyFile,
			},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer g.Stop()
	time.Sleep(100 * time.Millisecond)

	// Create self-signed client cert (not signed by gateway CA)
	rogueCert, rogueKey, _ := makeCert(t, "evil", nil, false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	rogueTLS := tls.Certificate{
		Certificate: [][]byte{rogueCert.Raw},
		PrivateKey:  rogueKey,
	}
	addr, _ := net.ResolveUDPAddr("udp", gwAddr)
	_, err := dtls.Dial("udp", addr, &dtls.Config{
		Certificates: []tls.Certificate{rogueTLS},
		RootCAs:      pki.CAPool,
		ServerName:   "server.test",
	})
	if err == nil {
		t.Error("expected handshake failure for unknown CA, got nil")
	}
}

// TestManagementAPI: health endpoint responds 200.
func TestManagementAPI(t *testing.T) {
	pki := setupPKI(t)
	gwAddr := freePort(t)
	mgmtAddr := freePort(t)
	g := NewGateway(&Config{
		Listeners: []ListenerConfig{{Name: "mgmt", Listen: gwAddr, Protocol: ProtocolUDP}},
		Management: &ManagementConfig{
			Listen: mgmtAddr,
			TLS:    &gw.TLSConfig{CACertFile: pki.CACertFile, CertFile: pki.ServerCertFile, KeyFile: pki.ServerKeyFile},
		},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer g.Stop()
	time.Sleep(100 * time.Millisecond)

	cliCert, _ := tls.LoadX509KeyPair(pki.ClientCertFile, pki.ClientKeyFile)
	conn, err := tls.Dial("tcp", mgmtAddr, &tls.Config{
		Certificates: []tls.Certificate{cliCert},
		RootCAs:      pki.CAPool, ServerName: "server.test",
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
		t.Errorf("expected 200, got: %s", body)
	}
}

// TestPlainUDPEcho: full data plane echo through plain UDP proxy.
func TestPlainUDPEcho(t *testing.T) {
	// Start echo backend
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
	g := NewGateway(&Config{
		Listeners: []ListenerConfig{{
			Name:     "plain-echo",
			Listen:   gwAddr,
			Protocol: ProtocolUDP,
			Routes:   []RouteConfig{{Target: echoConn.LocalAddr().String()}},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer g.Stop()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mustPort(t, gwAddr)})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello plain udp\n")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply := make([]byte, 1500)
	n, _, err := conn.ReadFromUDP(reply)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(reply[:n]) != string(msg) {
		t.Errorf("got %q, want %q", string(reply[:n]), string(msg))
	}
}

func mustPort(t *testing.T, addr string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("parse addr %q: %v", addr, err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return port
}

// TestDTLSEcho: full data plane echo through DTLS proxy.
func TestDTLSEcho(t *testing.T) {
	pki := setupPKI(t)

	// Start echo backend
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
	g := NewGateway(&Config{
		Listeners: []ListenerConfig{{
			Name:     "dtls-echo",
			Listen:   gwAddr,
			Protocol: ProtocolDTLS,
			TLS: &gw.TLSConfig{
				CACertFile: pki.CACertFile,
				CertFile:   pki.ServerCertFile,
				KeyFile:    pki.ServerKeyFile,
			},
			Routes: []RouteConfig{{Target: echoConn.LocalAddr().String()}},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer g.Stop()

	time.Sleep(100 * time.Millisecond)

	// G1: DTLS enforces mutual auth — client must present a certificate.
	cliCert, err := tls.LoadX509KeyPair(pki.ClientCertFile, pki.ClientKeyFile)
	if err != nil {
		t.Fatalf("load client cert: %v", err)
	}
	addr, _ := net.ResolveUDPAddr("udp", gwAddr)
	conn, err := dtls.Dial("udp", addr, &dtls.Config{
		Certificates:       []tls.Certificate{cliCert},
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	msg := "hello dtls\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply := make([]byte, 1500)
	n, err := conn.Read(reply)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(reply[:n]) != msg {
		t.Errorf("got %q, want %q", string(reply[:n]), msg)
	}
}

// TestConfigValidateEndToEnd: config JSON round-trip with defaults.
func TestConfigValidateEndToEnd(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.json")
	os.WriteFile(p, []byte(`{"listeners":[{"name":"dns","listen":":5353","protocol":"dtls","tls":{"cert_file":"/c.pem","key_file":"/k.pem"},"routes":[{"target":"8.8.8.8:53"}]}]}`), 0644)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listeners[0].Protocol != ProtocolDTLS {
		t.Errorf("mode")
	}
}

// TestGatewayLifecycle: start/stop must not panic.
func TestGatewayLifecycle(t *testing.T) {
	g := NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
	g.Start()
	g.Stop()
	g.Stop()
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
