// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package httpgw

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
	pki "github.com/varwof/types"
)

// delegatedPlaceholderCert mints a self-signed client cert carrying an AIC whose
// DelegationAuthorization is a placeholder: PrincipalUid.KeyHash is all zeros
// (so the peer is not the principal) and the signature does not verify against
// any obtainable principal certificate. It therefore fails the mandatory
// DelegationAuthorization check unless that check is switched off.
func delegatedPlaceholderCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key := genKey(t)
	aic := pki.AIC{
		Version:      1,
		AgentId:      "delegated-agent",
		PrincipalUid: pki.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "user@varwof.com", KeyHash: make([]byte, 32)},
		Capabilities: []pki.Capability{{SchemeId: "http", CapabilityId: "gateway:read"}},
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:             pki.Reason{ReasonCode: "TEST", Description: "delegated placeholder"},
			Timestamp:          time.Now().UTC(),
			RequestedLifetime:  3600,
			Nonce:              make([]byte, 32),
			SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
			SignatureValue:     []byte{1, 2, 3},
		},
	}
	der, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatalf("marshal AIC: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "delegated-agent", OrganizationalUnit: []string{"Delegated-Agent"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(2 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			{Id: pki.OIDAIC, Value: der},
		},
	}
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

// TestProxyDelegationAuthSkipSwitch pins the P0-2 escape hatch: an mTLS
// listener refuses a delegated certificate whose principal certificate cannot
// be obtained (fail-closed default), and admits it only when the listener
// explicitly sets tls.skip_delegation_auth_verification.
func TestProxyDelegationAuthSkipSwitch(t *testing.T) {
	backend, closeBackend := startTestBackend(t)
	defer closeBackend()

	cert := delegatedPlaceholderCert(t)

	run := func(t *testing.T, skip *bool) int {
		t.Helper()
		p := newDirectProxy(t, ListenerConfig{
			Name: "da-skip", Protocol: ProtocolHTTP2,
			TLS: &gw.TLSConfig{
				Mode:                           gw.TLSModeMTLS,
				MaxConnsPerCert:                1,
				SkipDelegationAuthVerification: skip,
			},
			Routes: []RouteConfig{{Path: "/api/*", Target: backend}},
		})
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://x/api/y", nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		req.RemoteAddr = "127.0.0.1:50000"
		p.handleRequest(rr, req)
		return rr.Code
	}

	no := false
	yes := true

	if code := run(t, nil); code != http.StatusForbidden {
		t.Fatalf("default (verify) = %d, want 403 for an unverifiable delegation", code)
	}
	if code := run(t, &no); code != http.StatusForbidden {
		t.Fatalf("explicit false = %d, want 403", code)
	}
	if code := run(t, &yes); code != http.StatusOK {
		t.Fatalf("skip enabled = %d, want 200", code)
	}
}
