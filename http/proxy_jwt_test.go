// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package httpgw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
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
	"github.com/varwof/types/aicjwt"
)

func jwtTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "jwt-test-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func jwtTestToken(t *testing.T, ca *x509.Certificate, key *ecdsa.PrivateKey, kid, agentID, realm, principalID string, caps []aicjwt.Capability) string {
	t.Helper()
	hb, err := json.Marshal(map[string]any{"alg": "ES256", "typ": aicjwt.TypOuter, "kid": kid})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	kh, err := aicjwt.SPKIHashPub(&key.PublicKey, "sha-256")
	if err != nil {
		t.Fatal(err)
	}
	outer := aicjwt.OuterClaims{
		Iss: "test-issuer",
		Sub: agentID,
		Aud: []string{"test-aud"},
		Iat: now,
		Exp: now + 3600,
		Jti: "test-jti",
		Cnf: &aicjwt.Cnf{Jkt: "dGVzdA"},
		Aic: &aicjwt.AICClaims{
			Ver:            1,
			Principal:      aicjwt.Principal{Realm: realm, ID: principalID, KeyHash: kh, HashAlg: "sha-256"},
			DelegationMode: aicjwt.ModeAuthorized,
			Capabilities:   caps,
		},
	}
	pb, err := json.Marshal(&outer)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := aicjwt.SignCompact(hb, pb, "ES256", key)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func writeCAFile(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// newJWTProxyListener builds a plain-HTTP ProxyListener whose bearer auth
// trusts the given CA (via TLS.JWTCAFile config loading).
func newJWTProxyListener(t *testing.T, caCert *x509.Certificate) *ProxyListener {
	t.Helper()
	backendURL, backendClose := startTestBackend(t)
	t.Cleanup(backendClose)

	cfg := ListenerConfig{
		Name:     "test-jwt",
		Listen:   "127.0.0.1:0",
		Protocol: ProtocolHTTP2,
		TLS:      &gw.TLSConfig{JWTCAFile: writeCAFile(t, caCert)},
		Routes: []RouteConfig{
			{Path: "/*", Target: backendURL},
		},
	}
	audit, _ := gw.NewAuditLogger("", nil, 0, 0)
	p, err := NewProxyListener(cfg, nil, nil, audit, nil, nil, nil, "en", nil, nil)
	if err != nil {
		t.Fatalf("NewProxyListener: %v", err)
	}
	if p.jwtVerifier == nil {
		t.Fatal("jwtVerifier not loaded from JWTCAFile")
	}
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { p.Stop() })
	return p
}

// newJWTProxyListenerTLS builds a TLS (server-auth) ProxyListener whose bearer
// auth trusts the given CA. The transport is encrypted, so bearer tokens are
// acceptable (finding 6: bearer requires an encrypted transport).
func newJWTProxyListenerTLS(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) *ProxyListener {
	t.Helper()
	backendURL, backendClose := startTestBackend(t)
	t.Cleanup(backendClose)

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "jwt-tls-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"jwt-tls-test"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.pem")
	keyFile := filepath.Join(dir, "server.key")
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	if err := os.WriteFile(certFile, pemCert, 0o644); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := ListenerConfig{
		Name:     "test-jwt-tls",
		Listen:   "127.0.0.1:0",
		Protocol: ProtocolHTTP2,
		TLS: &gw.TLSConfig{
			Mode:      gw.TLSModeServer,
			JWTCAFile: writeCAFile(t, caCert),
			CertFile:  certFile,
			KeyFile:   keyFile,
		},
		Routes: []RouteConfig{
			{Path: "/*", Target: backendURL},
		},
	}
	audit, _ := gw.NewAuditLogger("", nil, 0, 0)
	p, err := NewProxyListener(cfg, nil, nil, audit, nil, nil, nil, "en", nil, nil)
	if err != nil {
		t.Fatalf("NewProxyListener(TLS): %v", err)
	}
	if p.jwtVerifier == nil {
		t.Fatal("jwtVerifier not loaded from JWTCAFile")
	}
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { p.Stop() })
	return p
}

func getBearerTLS(t *testing.T, addr, tok string) (int, string) {
	t.Helper()
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(body))
}

func getBearer(t *testing.T, addr, tok string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(body))
}

func TestProxyBearerAuthValid(t *testing.T) {
	caCert, caKey := jwtTestCA(t)
	p := newJWTProxyListenerTLS(t, caCert, caKey)

	kid, err := aicjwt.SPKIHash(caCert, "sha-256")
	if err != nil {
		t.Fatal(err)
	}
	tok := jwtTestToken(t, caCert, caKey, kid, "agent-a", "r", "principal-a", []aicjwt.Capability{
		{Scheme: "std/database-v1", ID: "SELECT:*"},
	})

	addr := p.listener.Addr().String()
	status, body := getBearerTLS(t, addr, tok)
	if status != http.StatusOK {
		t.Fatalf("valid bearer: status = %d body=%q, want 200", status, body)
	}
	if body != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
}

func TestProxyBearerAuthInvalid(t *testing.T) {
	caCert, caKey := jwtTestCA(t)
	p := newJWTProxyListenerTLS(t, caCert, caKey)

	otherCA, otherKey := jwtTestCA(t)
	kid, _ := aicjwt.SPKIHash(otherCA, "sha-256")
	tok := jwtTestToken(t, otherCA, otherKey, kid, "agent-a", "r", "principal-a", nil)

	addr := p.listener.Addr().String()
	status, body := getBearerTLS(t, addr, tok)
	if status != http.StatusUnauthorized {
		t.Fatalf("invalid bearer: status = %d body=%q, want 401", status, body)
	}
	if !strings.Contains(body, "bearer_invalid") {
		t.Fatalf("body = %q, want bearer_invalid error code", body)
	}
}

func TestProxyBearerAuthMalformed(t *testing.T) {
	caCert, caKey := jwtTestCA(t)
	p := newJWTProxyListenerTLS(t, caCert, caKey)

	addr := p.listener.Addr().String()
	status, body := getBearerTLS(t, addr, "not-a-jwt")
	if status != http.StatusUnauthorized {
		t.Fatalf("malformed bearer: status = %d body=%q, want 401", status, body)
	}
}

// A bearer token presented over a plaintext (unencrypted) transport must be
// rejected (finding 6): the token could have been captured by an
// eavesdropper, so it cannot prove the caller is the token's subject.
func TestProxyBearerAuthRejectedOverPlaintext(t *testing.T) {
	caCert, caKey := jwtTestCA(t)
	p := newJWTProxyListener(t, caCert)

	kid, err := aicjwt.SPKIHash(caCert, "sha-256")
	if err != nil {
		t.Fatal(err)
	}
	tok := jwtTestToken(t, caCert, caKey, kid, "agent-a", "r", "principal-a", nil)

	addr := p.listener.Addr().String()
	status, body := getBearer(t, addr, tok)
	if status != http.StatusUnauthorized {
		t.Fatalf("bearer over plaintext: status = %d body=%q, want 401", status, body)
	}
	if !strings.Contains(body, "bearer_tls_required") {
		t.Fatalf("body = %q, want bearer_tls_required error code", body)
	}
}

// Without a bearer token on a server/none-mode listener, requests are
// forwarded unauthenticated (no auth configured).
func TestProxyBearerAuthAbsent(t *testing.T) {
	caCert, _ := jwtTestCA(t)
	p := newJWTProxyListener(t, caCert)

	addr := p.listener.Addr().String()
	status, _ := getBearer(t, addr, "")
	// Fail-closed: a bearer-configured listener must deny requests without a
	// bearer token, never silently allow anonymous access.
	if status != http.StatusUnauthorized {
		t.Fatalf("no bearer: status = %d, want 401", status)
	}
}
