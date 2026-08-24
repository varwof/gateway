// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package udpgw

import (
	"context"
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

	"io"

	"github.com/pion/dtls/v2"
	"github.com/quic-go/quic-go"

	gw "github.com/varwof/gateway-core"
)

func genLargeAICCertUDP(t *testing.T, dir string, caCert *x509.Certificate, caKey *rsa.PrivateKey, cn string, ous []string, targetBytes int) (certPEM, keyPEM string) {
	t.Helper()
	const capIDFmt = "cap-%0250d"
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
	caps := make([]gw.Capability, 0)
	for i := 0; ; i++ {
		caps = append(caps, gw.Capability{SchemeId: "test-sch", CapabilityId: fmt.Sprintf(capIDFmt, i)})
		ext := largeAIC(caps)
		der, _ := asn1.Marshal(ext)
		if len(der) >= targetBytes {
			break
		}
		if i > 2000 {
			t.Fatalf("exceeded 2000 caps at target %d (got %d)", targetBytes, len(der))
		}
	}
	finalExt := largeAIC(caps)
	extDER, _ := asn1.Marshal(finalExt)

	clientKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, OrganizationalUnit: ous},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(2 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{cn},
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
	writePEM(t, certPath, "CERTIFICATE", der)
	writePEM(t, keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientKey))
	t.Logf("UDP test [%s] AIC ext %d bytes, cert DER %d bytes, caps %d", cn, len(extDER), len(der), len(caps))
	return certPath, keyPath
}

func TestLargeAIC_DTLS_Echo(t *testing.T) {
	if testing.Short() {
		t.Skip("skip DTLS large AIC in short mode")
	}
	dir := t.TempDir()

	// Create CA directly (setupPKI doesn't expose CA key)
	caCert, caKey, caDER := makeCert(t, "TestCA", nil, true, nil, nil, nil)
	writePEM(t, filepath.Join(dir, "ca.pem"), "CERTIFICATE", caDER)
	writePEM(t, filepath.Join(dir, "ca.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caKey))

	for _, targetSize := range []int{4096, 8192, 12288, 16384, 20480} {
		t.Run(fmt.Sprintf("AIC_%d", targetSize), func(t *testing.T) {
			clientCertFile, clientKeyFile := genLargeAICCertUDP(t, dir, caCert, caKey, "large-aic-client", []string{"gateway:admin"}, targetSize)

			// Echo backend
			echoConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
			if err != nil {
				t.Fatal(err)
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
					Name:     "dtls-large-aic",
					Listen:   gwAddr,
					Protocol: ProtocolDTLS,
					TLS: &gw.TLSConfig{
						CACertFile: filepath.Join(dir, "ca.pem"),
						CertFile:   filepath.Join(dir, "ca.pem"), // Use CA as server cert for DTLS
						KeyFile:    filepath.Join(dir, "ca.key"),
						AllowRoles: []string{"gateway:admin"},
					},
					Routes: []RouteConfig{{Target: echoConn.LocalAddr().String()}},
				}},
			}, NewBundle(), "en", nil, nil, nil, nil)
			if err := g.Start(); err != nil {
				t.Fatalf("start gateway: %v", err)
			}
			defer g.Stop()
			time.Sleep(100 * time.Millisecond)

			// DTLS client with large AIC cert
			clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
			if err != nil {
				t.Fatal(err)
			}
			addr, _ := net.ResolveUDPAddr("udp", gwAddr)
			conn, err := dtls.Dial("udp", addr, &dtls.Config{
				Certificates:       []tls.Certificate{clientCert},
				InsecureSkipVerify: true,
			})
			if err != nil {
				t.Fatalf("dtls dial failed: %v", err)
			}
			defer conn.Close()

			// Verify data flow
			msg := "hello-dtls-large-aic\n"
			if _, err := conn.Write([]byte(msg)); err != nil {
				t.Fatalf("dtls write: %v", err)
			}
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			reply := make([]byte, 1500)
			n, err := conn.Read(reply)
			if err != nil {
				t.Fatalf("dtls read: %v", err)
			}
			if string(reply[:n]) != msg {
				t.Fatalf("echo mismatch: got %q, want %q", string(reply[:n]), msg)
			}
		})
	}
}

func TestLargeAIC_QUIC_Echo(t *testing.T) {
	if testing.Short() {
		t.Skip("skip QUIC large AIC in short mode")
	}
	dir := t.TempDir()
	caCert, caKey, caDER := makeCert(t, "TestCA", nil, true, nil, nil, nil)
	writePEM(t, filepath.Join(dir, "ca.pem"), "CERTIFICATE", caDER)
	writePEM(t, filepath.Join(dir, "ca.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caKey))

	// Server cert for QUIC (needs DNS name for QUIC)
	_, srvKey, srvDER := makeCert(t, "server.test", nil, false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, caCert, caKey)
	writePEM(t, filepath.Join(dir, "server.pem"), "CERTIFICATE", srvDER)
	writePEM(t, filepath.Join(dir, "server.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(srvKey))

	// QUIC TLS handshake Certificate message has a ~16KB hard-wire limit (Known Gotchas #5),
	// so we only test AIC ≤ 12288B (larger sizes require dual-cert scheme, see dev-docs/aic/08-dual-cert.md).
	for _, targetSize := range []int{4096, 8192, 12288} {
		t.Run(fmt.Sprintf("AIC_%d", targetSize), func(t *testing.T) {
			clientCertFile, clientKeyFile := genLargeAICCertUDP(t, dir, caCert, caKey, "large-aic-client", []string{"gateway:admin"}, targetSize)

			// Echo backend (UDP)
			echoConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
			if err != nil {
				t.Fatal(err)
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
					Name:     "quic-large-aic",
					Listen:   gwAddr,
					Protocol: ProtocolQUIC,
					TLS: &gw.TLSConfig{
						CACertFile: filepath.Join(dir, "ca.pem"),
						CertFile:   filepath.Join(dir, "server.pem"),
						KeyFile:    filepath.Join(dir, "server.key"),
						AllowRoles: []string{"gateway:admin"},
					},
					Routes: []RouteConfig{{Target: echoConn.LocalAddr().String()}},
				}},
			}, NewBundle(), "en", nil, nil, nil, nil)
			if err := g.Start(); err != nil {
				t.Fatalf("start gateway: %v", err)
			}
			defer g.Stop()
			time.Sleep(100 * time.Millisecond)

			// QUIC client with large AIC cert. Bound the dial so a stalled
			// handshake fails this subtest instead of hanging the suite (large
			// client certs can intermittently stall quic-go's handshake).
			clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
			if err != nil {
				t.Fatal(err)
			}
			tlsCfg := &tls.Config{
				Certificates:       []tls.Certificate{clientCert},
				ServerName:         "server.test",
				NextProtos:         []string{"h3", "hq"},
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true,
			}
			dialCtx, dialCancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer dialCancel()
			conn, err := quic.DialAddr(dialCtx, gwAddr, tlsCfg, nil)
			if err != nil {
				t.Fatalf("quic dial failed: %v", err)
			}
			defer conn.CloseWithError(0, "done")

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stream, err := conn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatalf("open stream: %v", err)
			}

			msg := []byte("hello-quic-large-aic")
			if _, err := stream.Write(msg); err != nil {
				t.Fatalf("stream write: %v", err)
			}
			stream.Close()

			reply := make([]byte, 1024)
			n, err := stream.Read(reply)
			if err != nil && err != io.EOF {
				t.Fatalf("stream read: %v", err)
			}
			if string(reply[:n]) != string(msg) {
				t.Fatalf("echo mismatch: got %q, want %q", string(reply[:n]), string(msg))
			}
		})
	}
}
