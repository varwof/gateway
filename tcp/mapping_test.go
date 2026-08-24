package tcpgw

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
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

func TestMappingPlainTCP(t *testing.T) {
	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	cfg := MappingConfig{
		Name:    "test-plain",
		Listen:  "127.0.0.1:0",
		Target:  echoSrv.Addr().String(),
		Protocol: ProtocolTCP,
	}
	m, err := NewMapping(cfg, nil, nil, nil, nil, nil, "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}

	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	conn, err := net.Dial("tcp", m.listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	msg := "hello from mapping test\n"
	if _, err := fmt.Fprint(conn, msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if reply != msg {
		t.Errorf("got %q, want %q", reply, msg)
	}

	if m.State() != MappingRunning {
		t.Errorf("state = %v, want %v", m.State(), MappingRunning)
	}
}

func TestMappingMTLS(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "server", caCert, caKey, nil)
	generateTestCert(t, dir, "client", caCert, caKey, []string{"gateway:mysql-prod"})

	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	cfg := MappingConfig{
		Name:     "test-mtls",
		Listen:   "127.0.0.1:0",
		Target:   echoSrv.Addr().String(),
		Protocol: ProtocolTCPMTLS,
		TLS: &gw.TLSConfig{
			CACertFile: filepath.Join(dir, "ca.pem"),
			CertFile:   filepath.Join(dir, "server.pem"),
			KeyFile:    filepath.Join(dir, "server.key"),
			AllowRoles: []string{"gateway:mysql-prod"},
		},
	}

	m, err := NewMapping(cfg, nil, nil, nil, nil, nil, "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	tlsCfg, err := gw.ClientTLSConfig(
		filepath.Join(dir, "ca.pem"),
		filepath.Join(dir, "client.pem"),
		filepath.Join(dir, "client.key"),
		nil, "",
	)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := tls.Dial("tcp", m.listener.Addr().String(), tlsCfg)
	if err != nil {
		t.Fatalf("TLS Dial: %v", err)
	}
	defer conn.Close()

	msg := "mtls hello\n"
	if _, err := fmt.Fprint(conn, msg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if reply != msg {
		t.Errorf("got %q, want %q", reply, msg)
	}
}

// TestMappingMTLSRequireUserAuthDenied verifies G2: when require_user_auth is
// enabled but no UserCertProvider is wired, and the client presents an AIC with
// a DelegationAuth, the admission pipeline must fail-closed and deny the
// connection (it must not silently allow).
func TestMappingMTLSRequireUserAuthDenied(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "server", caCert, caKey, nil)

	// Construct client certificate with AIC (containing DelegationAuth)
	clientKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	aicExt := gw.AIC{
		Version:      1,
		AgentId:      "req-user-auth-client",
		PrincipalUid: gw.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		DelegationAuthorization: gw.DelegationAuthorization{
			// Empty signature + no Provider → RequireUserAuth should fail-closed reject
			SignatureValue:    []byte{},
			SignatureAlgorithm: gw.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
			Timestamp:         time.Now(),
			Nonce:             make([]byte, 32),
			RequestedLifetime: 3600,
		},
	}
	aicDER, err := asn1.Marshal(aicExt)
	if err != nil {
		t.Fatal(err)
	}
	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "req-user-auth-client", OrganizationalUnit: []string{"gateway:mysql-prod"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1}, Value: aicDER},
		},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(filepath.Join(dir, "client.pem"), "CERTIFICATE", clientDER, t)
	writePEM(filepath.Join(dir, "client.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientKey), t)

	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	requireUserAuth := true
	cfg := MappingConfig{
		Name:    "test-req-user-auth",
		Listen:  "127.0.0.1:0",
		Target:  echoSrv.Addr().String(),
		Protocol: ProtocolTCPMTLS,
		TLS: &gw.TLSConfig{
			CACertFile:      filepath.Join(dir, "ca.pem"),
			CertFile:        filepath.Join(dir, "server.pem"),
			KeyFile:         filepath.Join(dir, "server.key"),
			AllowRoles:      []string{"gateway:mysql-prod"},
			RequireUserAuth: &requireUserAuth,
		},
	}

	m, err := NewMapping(cfg, nil, nil, nil, nil, nil, "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	tlsCfg, err := gw.ClientTLSConfig(
		filepath.Join(dir, "ca.pem"),
		filepath.Join(dir, "client.pem"),
		filepath.Join(dir, "client.key"),
		nil, "",
	)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := tls.Dial("tcp", m.listener.Addr().String(), tlsCfg)
	if err != nil {
		t.Fatalf("TLS Dial: %v", err)
	}
	defer conn.Close()

	msg := "should not echo\n"
	if _, err := fmt.Fprint(conn, msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		t.Fatalf("expected connection denied (no echo), got %q", string(buf[:n]))
	}
}

func TestMappingMTLSRejected(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "server", caCert, caKey, nil)
	wrongCAKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrongCATmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "Wrong CA"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	wrongCADER, _ := x509.CreateCertificate(rand.Reader, wrongCATmpl, wrongCATmpl, &wrongCAKey.PublicKey, wrongCAKey)
	wrongCAPath := filepath.Join(dir, "wrong-ca.pem")
	writePEM(wrongCAPath, "CERTIFICATE", wrongCADER, t)

	wrongClientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "unauthorized"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
	}
	wrongClientKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrongClientDER, _ := x509.CreateCertificate(rand.Reader, wrongClientTmpl, wrongCATmpl, &wrongClientKey.PublicKey, wrongCAKey)
	writePEM(filepath.Join(dir, "wrong-client.pem"), "CERTIFICATE", wrongClientDER, t)
	writePEM(filepath.Join(dir, "wrong-client.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(wrongClientKey), t)

	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	cfg := MappingConfig{
		Name:    "test-reject",
		Listen:  "127.0.0.1:0",
		Target:  echoSrv.Addr().String(),
		Protocol: ProtocolTCPMTLS,
		TLS: &gw.TLSConfig{
			CACertFile: filepath.Join(dir, "ca.pem"),
			CertFile:   filepath.Join(dir, "server.pem"),
			KeyFile:    filepath.Join(dir, "server.key"),
			AllowRoles: []string{"gateway:admin"},
		},
	}

	m, err := NewMapping(cfg, nil, nil, nil, nil, nil, "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	tlsCfg, err := gw.ClientTLSConfig(
		filepath.Join(dir, "wrong-ca.pem"),
		filepath.Join(dir, "wrong-client.pem"),
		filepath.Join(dir, "wrong-client.key"),
		nil, "",
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = tls.Dial("tcp", m.listener.Addr().String(), tlsCfg)
	if err == nil {
		t.Error("expected TLS handshake error for wrong CA")
	}
}

func TestMappingMTLSRevoked(t *testing.T) {
	dir := t.TempDir()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(filepath.Join(dir, "ca.pem"), "CERTIFICATE", caDER, t)
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "server"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(filepath.Join(dir, "server.pem"), "CERTIFICATE", serverDER, t)
	writePEM(filepath.Join(dir, "server.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverKey), t)

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial := big.NewInt(42)
	clientTmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         "revoked-client",
			OrganizationalUnit: []string{"gateway:mysql-prod"},
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(1 * time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(filepath.Join(dir, "client.pem"), "CERTIFICATE", clientDER, t)
	writePEM(filepath.Join(dir, "client.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientKey), t)

	crlTmpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-1 * time.Minute),
		NextUpdate: time.Now().Add(1 * time.Hour),
		RevokedCertificates: []pkix.RevokedCertificate{
			{SerialNumber: serial, RevocationTime: time.Now().Add(-1 * time.Minute)},
		},
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTmpl, caCert, caKey)
	if err != nil {
		t.Fatal(err)
	}
	crlPath := filepath.Join(dir, "test.crl")
	writePEM(crlPath, "X509 CRL", crlDER, t)

	crlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, crlPath)
	}))
	defer crlSrv.Close()

	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	cfg := MappingConfig{
		Name:     "test-crl-revoke",
		Listen:   "127.0.0.1:0",
		Target:   echoSrv.Addr().String(),
		Protocol: ProtocolTCPMTLS,
		TLS: &gw.TLSConfig{
			CACertFile: filepath.Join(dir, "ca.pem"),
			CertFile:   filepath.Join(dir, "server.pem"),
			KeyFile:    filepath.Join(dir, "server.key"),
			CRLURL:     crlSrv.URL,
			AllowRoles: []string{"gateway:mysql-prod"},
		},
	}
	crlCache := gw.NewCRLCache(caCert, crlSrv.URL, 60, nil, "en")
	stopCh := make(chan struct{})
	go crlCache.Start(stopCh)
	defer close(stopCh)

	m, err := NewMapping(cfg, crlCache, nil, nil, nil, nil, "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	time.Sleep(500 * time.Millisecond)

	tlsCfg, err := gw.ClientTLSConfig(
		filepath.Join(dir, "ca.pem"),
		filepath.Join(dir, "client.pem"),
		filepath.Join(dir, "client.key"),
		nil, "",
	)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg.InsecureSkipVerify = true

	conn, err := tls.Dial("tcp", m.listener.Addr().String(), tlsCfg)
	if err != nil {
		t.Fatalf("TLS Dial should succeed: %v", err)
	}
	defer conn.Close()

	err = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err == nil {
		t.Errorf("expected EOF after CRL revocation, got data")
	}
}

func startEchoServer(t *testing.T) net.Listener {
	t.Helper()
	srv, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			conn, err := srv.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					conn.Write([]byte(line))
				}
			}()
		}
	}()
	return srv
}

func generateTestCA(t *testing.T, dir string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(filepath.Join(dir, "ca.pem"), "CERTIFICATE", der, t)
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func generateTestCert(t *testing.T, dir, cn string, caCert *x509.Certificate, caKey *rsa.PrivateKey, ous []string) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         cn,
			OrganizationalUnit: ous,
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(1 * time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(filepath.Join(dir, cn+".pem"), "CERTIFICATE", der, t)
	writePEM(filepath.Join(dir, cn+".key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), t)
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func TestNewMappingError(t *testing.T) {
	cfg := MappingConfig{Name: "bad", Protocol: "unknown"}
	_, err := NewMapping(cfg, nil, nil, nil, nil, nil, "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping should not error on creation: %v", err)
	}
}

func writePEM(path, blockType string, der []byte, t *testing.T) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

func generateTestCertWithGS(t *testing.T, dir, cn string, caCert *x509.Certificate, caKey *rsa.PrivateKey, ous []string, gs *gw.GatewaySessionExtension) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var extraExts []pkix.Extension
	if gs != nil {
		val, err := asn1.Marshal(*gs)
		if err != nil {
			t.Fatal(err)
		}
		gsOid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 5}
		extraExts = append(extraExts, pkix.Extension{
			Id:    gsOid,
			Value: val,
		})
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         cn,
			OrganizationalUnit: ous,
		},
		NotBefore:       time.Now().Add(-1 * time.Hour),
		NotAfter:        time.Now().Add(1 * time.Hour),
		IPAddresses:     []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		ExtraExtensions: extraExts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(filepath.Join(dir, cn+".pem"), "CERTIFICATE", der, t)
	writePEM(filepath.Join(dir, cn+".key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), t)
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func TestMappingMTLSHardTimeout(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	shortTimeout := 3
	gs := &gw.GatewaySessionExtension{
		Version:     1,
		HardTimeout: shortTimeout,
	}
	generateTestCertWithGS(t, dir, "server", caCert, caKey, nil, nil)
	generateTestCertWithGS(t, dir, "client", caCert, caKey, []string{"gateway:mysql-prod"}, gs)

	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	cfg := MappingConfig{
		Name:     "test-hardtimeout",
		Listen:   "127.0.0.1:0",
		Target:   echoSrv.Addr().String(),
		Protocol: ProtocolTCPMTLS,
		TLS: &gw.TLSConfig{
			CACertFile: filepath.Join(dir, "ca.pem"),
			CertFile:   filepath.Join(dir, "server.pem"),
			KeyFile:    filepath.Join(dir, "server.key"),
			AllowRoles: []string{"gateway:mysql-prod"},
		},
	}

	m, err := NewMapping(cfg, nil, nil, nil, nil, nil, "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	tlsCfg, err := gw.ClientTLSConfig(
		filepath.Join(dir, "ca.pem"),
		filepath.Join(dir, "client.pem"),
		filepath.Join(dir, "client.key"),
		nil, "",
	)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := tls.Dial("tcp", m.listener.Addr().String(), tlsCfg)
	if err != nil {
		t.Fatalf("TLS Dial: %v", err)
	}
	defer conn.Close()

	msg := "hello before hard timeout\n"
	if _, err := fmt.Fprint(conn, msg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("Read before timeout: %v", err)
	}
	if reply != msg {
		t.Errorf("got %q, want %q", reply, msg)
	}

	// Wait for HardTimeout (3s) + some margin
	time.Sleep(5 * time.Second)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected connection closed after HardTimeout")
	}
}

func TestMappingMTLSAllowedCIDRsBlock(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	gs := &gw.GatewaySessionExtension{
		Version:      1,
		AllowedCIDRs: []string{"10.0.0.0/8"},
	}
	generateTestCertWithGS(t, dir, "server", caCert, caKey, nil, nil)
	generateTestCertWithGS(t, dir, "client", caCert, caKey, []string{"gateway:mysql-prod"}, gs)

	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	cfg := MappingConfig{
		Name:     "test-cidr-block",
		Listen:   "127.0.0.1:0",
		Target:   echoSrv.Addr().String(),
		Protocol: ProtocolTCPMTLS,
		TLS: &gw.TLSConfig{
			CACertFile: filepath.Join(dir, "ca.pem"),
			CertFile:   filepath.Join(dir, "server.pem"),
			KeyFile:    filepath.Join(dir, "server.key"),
			AllowRoles: []string{"gateway:mysql-prod"},
		},
	}

	m, err := NewMapping(cfg, nil, nil, nil, nil, nil, "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	tlsCfg, err := gw.ClientTLSConfig(
		filepath.Join(dir, "ca.pem"),
		filepath.Join(dir, "client.pem"),
		filepath.Join(dir, "client.key"),
		nil, "",
	)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := tls.Dial("tcp", m.listener.Addr().String(), tlsCfg)
	if err != nil {
		t.Fatalf("TLS Dial: %v", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected connection closed/denied due to CIDR mismatch, got data")
	}
}

func boolPtr(b bool) *bool {
	return &b
}

func TestMappingMTLSAllowedCIDRsAllow(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	gs := &gw.GatewaySessionExtension{
		Version:      1,
		AllowedCIDRs: []string{"127.0.0.1/32"},
	}
	generateTestCertWithGS(t, dir, "server", caCert, caKey, nil, nil)
	generateTestCertWithGS(t, dir, "client", caCert, caKey, []string{"gateway:mysql-prod"}, gs)

	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	cfg := MappingConfig{
		Name:     "test-cidr-allow",
		Listen:   "127.0.0.1:0",
		Target:   echoSrv.Addr().String(),
		Protocol: ProtocolTCPMTLS,
		TLS: &gw.TLSConfig{
			CACertFile: filepath.Join(dir, "ca.pem"),
			CertFile:   filepath.Join(dir, "server.pem"),
			KeyFile:    filepath.Join(dir, "server.key"),
			AllowRoles: []string{"gateway:mysql-prod"},
		},
	}

	m, err := NewMapping(cfg, nil, nil, nil, nil, nil, "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	tlsCfg, err := gw.ClientTLSConfig(
		filepath.Join(dir, "ca.pem"),
		filepath.Join(dir, "client.pem"),
		filepath.Join(dir, "client.key"),
		nil, "",
	)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := tls.Dial("tcp", m.listener.Addr().String(), tlsCfg)
	if err != nil {
		t.Fatalf("TLS Dial: %v", err)
	}
	defer conn.Close()

	msg := "allowed cidr test\n"
	if _, err := fmt.Fprint(conn, msg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if reply != msg {
		t.Errorf("got %q, want %q", reply, msg)
	}
}


