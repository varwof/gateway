package httpgw

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

func genLargeAICCertHTTP(t *testing.T, dir, cn string, caCert *x509.Certificate, caKey *rsa.PrivateKey, ous []string, targetBytes int) (certPEM, keyPEM string) {
	t.Helper()
	caps := make([]gw.Capability, 0)
	largeAIC := func(caps []gw.Capability) gw.AIC {
		return gw.AIC{
			Version: 1, AgentId: cn,
			PrincipalUid: gw.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "user@varwof.com", KeyHash: make([]byte, 32), HashAlgo: gw.AlgorithmIdentifier{Algorithm: gw.OIDSHA256}},
			Capabilities: caps,
			DelegationAuthorization: gw.DelegationAuthorization{
				Reason:             gw.Reason{ReasonCode: "TEST", Description: "large AIC test"},
				Nonce:              make([]byte, 32),
				SignatureValue:     []byte{1},
				SignatureAlgorithm: gw.AlgorithmIdentifier{Algorithm: gw.OIDSigECDSAWithSHA256},
				RequestedLifetime:  3600,
			},
		}
	}
	for i := 0; ; i++ {
		verboseCapID := fmt.Sprintf("cap-%0250d", i)
		caps = append(caps, gw.Capability{SchemeId: "test-sch", CapabilityId: verboseCapID})
		ext := largeAIC(caps)
		der, _ := asn1.Marshal(ext)
		if len(der) >= targetBytes {
			break
		}
		if len(caps) >= 256 {
			t.Fatalf("reached 256 cap limit at target %d (got %d)", targetBytes, len(der))
		}
	}
	finalExt := largeAIC(caps)
	extDER, _ := asn1.Marshal(finalExt)
	clientKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, OrganizationalUnit: ous},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1}, Critical: false, Value: extDER},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(%d): %v", targetBytes, err)
	}
	certPath := filepath.Join(dir, cn+".pem")
	keyPath := filepath.Join(dir, cn+".key")
	writePEMHTTP(certPath, "CERTIFICATE", der, t)
	writePEMHTTP(keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientKey), t)
	t.Logf("HTTP test cert: AIC ext %d bytes, cert DER %d bytes, caps %d", len(extDER), len(der), len(caps))
	return certPath, keyPath
}

func writePEMHTTP(path, blockType string, der []byte, t *testing.T) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

func genCAHTTP(t *testing.T, dir string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	writePEMHTTP(filepath.Join(dir, "ca.pem"), "CERTIFICATE", der, t)
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func genServerCertHTTP(t *testing.T, dir string, caCert *x509.Certificate, caKey *rsa.PrivateKey) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "server"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"server"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEMHTTP(filepath.Join(dir, "server.pem"), "CERTIFICATE", der, t)
	writePEMHTTP(filepath.Join(dir, "server.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), t)
}

func TestLargeAIC_HTTP(t *testing.T) {
	targetSizes := []int{4096, 8192, 12288, 16384, 20480}
	for _, targetSize := range targetSizes {
		t.Run(fmt.Sprintf("AIC_%d", targetSize), func(t *testing.T) {
			dir := t.TempDir()
			caCert, caKey := genCAHTTP(t, dir)
			genServerCertHTTP(t, dir, caCert, caKey)
			clientCertFile, clientKeyFile := genLargeAICCertHTTP(t, dir, "large-aic-client", caCert, caKey, []string{"gateway:admin"}, targetSize)

			// HTTP echo backend
			backend := &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Write([]byte("ok\n"))
				}),
			}
			blis, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			go backend.Serve(blis)
			defer backend.Close()

			// Proxy
			cfg := ListenerConfig{
				Name:     "test-large-aic-http",
				Listen:   "127.0.0.1:0",
				Protocol: ProtocolHTTP2,
				Routes:   []RouteConfig{{Path: "/*", Target: "http://" + blis.Addr().String(), AllowRoles: []string{"gateway:admin"}}},
				TLS: &gw.TLSConfig{
					Mode:       gw.TLSModeMTLS,
					CACertFile: filepath.Join(dir, "ca.pem"),
					CertFile:   filepath.Join(dir, "server.pem"),
					KeyFile:    filepath.Join(dir, "server.key"),
				},
			}
			audit, _ := gw.NewAuditLogger("", nil, 0, 0)
			p, err := NewProxyListener(cfg, nil, nil, audit, nil, nil, nil, "en", nil, nil)
			if err != nil {
				t.Fatalf("NewProxyListener: %v", err)
			}
			if err := p.Start(); err != nil {
				t.Fatalf("Start: %v", err)
			}
			defer p.Stop()

			// HTTP client with large AIC client cert
			tlsCfg, err := gw.ClientTLSConfig(
				filepath.Join(dir, "ca.pem"),
				clientCertFile, clientKeyFile, nil, "",
			)
			if err != nil {
				t.Fatalf("ClientTLSConfig: %v", err)
			}
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
			resp, err := client.Get("https://" + p.listener.Addr().String() + "/test")
			if err != nil {
				t.Fatalf("GET failed: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status=%d body=%s", resp.StatusCode, string(body))
			}
			if strings.TrimSpace(string(body)) == "" {
				t.Fatal("empty response body")
			}
		})
	}
}
