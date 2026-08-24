// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package tcpgw

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

// largeAICWithAuth builds an AIC with required KeyHash + DelegationAuthorization.
func largeAICWithAuth(cn string, caps []gw.Capability) gw.AIC {
	return gw.AIC{
		Version: 1,
		AgentId: cn,
		PrincipalUid: gw.PrincipalUid{
			Version:    1,
			Realm:      "varwof",
			Identifier: "user@varwof.com",
			KeyHash:    make([]byte, 32),
			HashAlgo:   gw.AlgorithmIdentifier{Algorithm: gw.OIDSHA256},
		},
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

// targetAICSizes are the target AIC extension sizes in bytes for testing.
var targetAICSizes = []int{4096, 8192, 12288, 16384, 20480}

// genLargeAICCertForTCP generates a client test certificate with a large AIC extension, signed by the CA.
// Returns the certificate PEM path and private key PEM path.
func genLargeAICCertForTCP(t *testing.T, dir, cn string, caCert *x509.Certificate, caKey *rsa.PrivateKey, ous []string, targetBytes int) (certPEM, keyPEM string) {
	t.Helper()

	// Build large AIC extension
	const capIDFmt = "cap-%0250d"
	baseScheme := "test-sch"

	caps := make([]gw.Capability, 0)
	for i := 0; ; i++ {
		caps = append(caps, gw.Capability{
			SchemeId:     baseScheme,
			CapabilityId: fmt.Sprintf(capIDFmt, i),
		})
		ext := largeAICWithAuth(cn, caps)
		der, err := asn1.Marshal(ext)
		if err != nil {
			t.Fatalf("asn1.Marshal failed at cap %d: %v", i, err)
		}
		if len(der) >= targetBytes {
			break
		}
		if i > 2000 {
			t.Fatalf("exceeded 2000 caps at target %d (got %d)", targetBytes, len(der))
		}
	}

	finalExt := largeAICWithAuth(cn, caps)
	extDER, err := asn1.Marshal(finalExt)
	if err != nil {
		t.Fatalf("final asn1.Marshal: %v", err)
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
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
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1}, Critical: false, Value: extDER},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	certPath := filepath.Join(dir, cn+".pem")
	keyPath := filepath.Join(dir, cn+".key")
	writePEM(certPath, "CERTIFICATE", der, t)
	writePEM(keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientKey), t)

	t.Logf("TCP test cert AIC ext: %d bytes, cert DER: %d bytes, caps: %d", len(extDER), len(der), len(caps))
	return certPath, keyPath
}

func TestLargeAIC_TCP(t *testing.T) {
	for _, targetSize := range targetAICSizes {
		t.Run(fmt.Sprintf("AIC_%d", targetSize), func(t *testing.T) {
			dir := t.TempDir()
			caCert, caKey := generateTestCA(t, dir)
			generateTestCert(t, dir, "server", caCert, caKey, nil)
			clientCertFile, clientKeyFile := genLargeAICCertForTCP(t, dir, "large-aic-client", caCert, caKey, []string{"gateway:mysql-prod"}, targetSize)

			echoSrv := startEchoServer(t)
			defer echoSrv.Close()

			cfg := MappingConfig{
				Name:     "test-large-aic",
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
				clientCertFile,
				clientKeyFile,
				nil, "",
			)
			if err != nil {
				t.Fatalf("ClientTLSConfig: %v", err)
			}

			conn, err := tls.Dial("tcp", m.listener.Addr().String(), tlsCfg)
			if err != nil {
				t.Fatalf("tls.Dial failed: %v", err)
			}
			defer conn.Close()

			// Test data send/receive
			testMsg := []byte("hello-large-aic\n")
			if _, err := conn.Write(testMsg); err != nil {
				t.Fatalf("write failed: %v", err)
			}
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("read failed: %v", err)
			}
			if string(buf[:n]) != string(testMsg) {
				t.Fatalf("echo mismatch: got %q, want %q", string(buf[:n]), string(testMsg))
			}
		})
	}
}
