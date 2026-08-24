// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package httpgw

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// startCRLServer starts an httptest server that returns a fixed CRL (with one revoked serial number).
func startCRLServer(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*httptest.Server, *big.Int) {
	t.Helper()
	revoked := big.NewInt(4242)
	// CRL ThisUpdate encoding precision is seconds; reusing the same static CRL
	// across requests triggers CRLCache replay protection after reload if
	// ForceRefresh falls within the same second (thisUpdate not strictly increasing)
	// causing intermittent test failures. Generate a new CRL per request so
	// ThisUpdate monotonically increases.
	var mu sync.Mutex
	lastUpdate := time.Now().Add(-time.Hour)
	crlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		lastUpdate = lastUpdate.Add(1 * time.Second)
		u := lastUpdate
		mu.Unlock()
		crlBytes, err := caCert.CreateCRL(rand.Reader, caKey, []pkix.RevokedCertificate{
			{SerialNumber: revoked, RevocationTime: time.Now()},
		}, u, u.Add(24*time.Hour))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})
		w.Write(crlPEM)
	}))
	t.Cleanup(crlSrv.Close)
	return crlSrv, revoked
}

// TestHTTPReloadRefreshesCRLCache verifies W16: when reload preserves a listener,
// its CRL cache is replaced with a new instance bound to the new stopCh (old cache
// refresh goroutine stops, new cache takes effect).
func TestHTTPReloadRefreshesCRLCache(t *testing.T) {
	backend, backendClose := startTestBackend(t)
	t.Cleanup(backendClose)

	// Self-signed CA and server certificate: CRL must be issued by the same CA
	// referenced in ca_cert_file.
	dir := t.TempDir()
	caCert, caKey := makeTestCA(t)
	writePEM(t, filepath.Join(dir, "ca.pem"), "CERTIFICATE", caCert.Raw)

	srvCert, srvKey, _ := makeCert(t, "server.test", nil, false, nil, caCert, caKey)
	writePEM(t, filepath.Join(dir, "server.pem"), "CERTIFICATE", srvCert.Raw)
	writePEM(t, filepath.Join(dir, "server.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(srvKey))

	crlSrv, _ := startCRLServer(t, caCert, caKey)

	cfgPath := filepath.Join(dir, "gw.json")
	cfgData := `{"listeners":[{
		"name":"g1",
		"listen":"127.0.0.1:0",
		"protocol":"http2",
		"tls":{
			"mode":"mtls",
			"ca_cert_file":"` + filepath.Join(dir, "ca.pem") + `",
			"cert_file":"` + filepath.Join(dir, "server.pem") + `",
			"key_file":"` + filepath.Join(dir, "server.key") + `",
			"crl_url":"` + crlSrv.URL + `",
			"crl_refresh_sec":3600
		},
		"routes":[{"path":"/*","target":"` + backend + `"}]
	}]}`
	if err := os.WriteFile(cfgPath, []byte(cfgData), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	defer g.Stop()

	old, ok := g.listeners["g1"].(*ProxyListener)
	if !ok {
		t.Fatalf("listener g1 is %T, want *ProxyListener", g.listeners["g1"])
	}
	oldCache := old.crlCache.Load()
	if oldCache == nil {
		t.Fatal("initial CRL cache is nil")
	}

	if err := g.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	newL, ok := g.listeners["g1"].(*ProxyListener)
	if !ok {
		t.Fatalf("listener g1 after reload is %T", g.listeners["g1"])
	}
	newCache := newL.crlCache.Load()
	if newCache == nil {
		t.Fatal("CRL cache is nil after reload")
	}
	if newCache == oldCache {
		t.Fatal("CRL cache not replaced on reload (W16 still broken)")
	}
	if err := newCache.ForceRefresh(); err != nil {
		t.Fatalf("new cache ForceRefresh: %v", err)
	}
	// New cache should recognize the revoked serial number (proving valid data plane source).
	revoked, err := newCache.IsRevoked(caCert.Subject.String(), big.NewInt(4242))
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Error("revoked serial 4242 not recognized by new cache")
	}
}

// makeTestCA generates a CA certificate and private key.
func makeTestCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CRL Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}
