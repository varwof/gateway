// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package httpgw

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
	pki "github.com/varwof/types"
)

func marshalTestAIC(t *testing.T) []byte {
	t.Helper()
	aic := pki.AIC{
		Version:      1,
		AgentId:      "agent-h3",
		PrincipalUid: pki.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "user@varwof.com", KeyHash: make([]byte, 32)},
		Capabilities: []pki.Capability{{SchemeId: "http", CapabilityId: "gateway:read"}},
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:             pki.Reason{ReasonCode: "SCHEDULED_MAINTENANCE", Description: "h3 test"},
			Timestamp:          time.Now().UTC(),
			RequestedLifetime:  3600,
			Nonce:              make([]byte, 32),
			SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
			SignatureValue:     []byte{1, 2, 3},
		},
	}
	val, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatalf("marshal AIC: %v", err)
	}
	return val
}

func makeExtCert(t *testing.T, cn string, ous []string, org []string, exts []pkix.Extension) *x509.Certificate {
	t.Helper()
	key := genKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(time.Now().UnixNano()),
		Subject:         pkix.Name{CommonName: cn, OrganizationalUnit: ous, Organization: org},
		NotBefore:       time.Now().Add(-1 * time.Hour),
		NotAfter:        time.Now().Add(2 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func startEchoHeadersBackend(t *testing.T) (string, func()) {
	t.Helper()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range r.Header {
			for _, val := range v {
				fmt.Fprintf(w, "%s: %s\n", k, val)
			}
		}
	})}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(lis)
	return "http://" + lis.Addr().String(), func() { srv.Close() }
}

func TestQUICProxyH3RequestFullHeaders(t *testing.T) {
	backend, close := startEchoHeadersBackend(t)
	defer close()
	hostport := strings.TrimPrefix(backend, "http://")

	tru := true
	cert := makeExtCert(t, "agent-1", []string{"Delegated-Agent"}, []string{"Acme"}, []pkix.Extension{
		{Id: pki.OIDAIC, Value: marshalTestAIC(t)},
	})

	q := newTestQUIC(ListenerConfig{
		Name: "h3", Protocol: ProtocolH3, TLS: &gw.TLSConfig{},
		HTTPExt: &gw.HTTPExtra{ForwardClientCert: &tru, TLSTermination: &tru, ForwardClientCertDER: &tru},
		Routes:  []RouteConfig{{Path: "/echo", Target: hostport}},
	})
	q.tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert

	run := func(cancelCtx bool) *httptest.ResponseRecorder {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://x/echo", nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		req.RemoteAddr = "127.0.0.1:50000"
		if cancelCtx {
			ctx, cancel := context.WithCancel(context.Background())
			req = req.WithContext(ctx)
			q.handleH3Request(rr, req)
			cancel()
			time.Sleep(150 * time.Millisecond)
			return rr
		}
		q.handleH3Request(rr, req)
		return rr
	}

	rr := run(true)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s, want 200", rr.Code, rr.Body.String())
	}
	body := strings.ToLower(rr.Body.String())
	for _, want := range []string{
		"x-client-cert-der: ",
		"x-client-cert-spki-hash: ",
		"x-client-cert-serial: ",
		"x-client-cert-cn: agent-1",
		"x-client-cert-principal: varwof:user@varwof.com:",
		"x-client-cert-agent-id: agent-h3",
		"x-forwarded-client-cn: agent-1",
		"x-forwarded-client-o: acme",
		"x-forwarded-client-ou: delegated-agent",
		"x-forwarded-client-serial: ",
		"x-forwarded-client-notafter: ",
		"x-aic-agent-id: agent-h3",
		"x-aic-principal-uid: varwof:user@varwof.com:",
		"x-aic-capabilities: gateway:read",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing header %q in backend echo:\n%s", want, body)
		}
	}

	// X-Agent-TTL and X-GS-* headers are no longer injected (GS removed).
	if strings.Contains(body, "x-agent-ttl:") {
		t.Errorf("x-agent-ttl should not be set without GS extension")
	}
	if strings.Contains(body, "x-gs-") {
		t.Errorf("x-gs-* headers should not be set (GS removed)")
	}

	rr2 := run(false)
	if rr2.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rr2.Code)
	}
}

func TestQUICProxyH3RequestBackendUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()

	q := newTestQUIC(ListenerConfig{
		Name: "h3", Protocol: ProtocolH3, TLS: &gw.TLSConfig{},
		Routes: []RouteConfig{{Path: "/echo", Target: dead}},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/echo", nil)
	q.handleH3Request(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502", rr.Code)
	}
}

func TestQUICServeAcceptErrorAfterStop(t *testing.T) {
	pki := setupPKI(t)
	q := newTestQUIC(ListenerConfig{
		Name: "quic", Listen: "127.0.0.1:0", Protocol: ProtocolQUIC,
		TLS: &gw.TLSConfig{CertFile: pki.ServerCertFile, KeyFile: pki.ServerKeyFile},
	})
	if err := q.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := q.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	q.serve()
}

func tunnelClientCertExt(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, ou []string, exts []pkix.Extension) tls.Certificate {
	t.Helper()
	key := genKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(time.Now().UnixNano()),
		Subject:         pkix.Name{CommonName: "tunnel-client", OrganizationalUnit: ou},
		NotBefore:       time.Now().Add(-1 * time.Hour),
		NotAfter:        time.Now().Add(2 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}
}

func TestQUICTunnelNoGSMeansNoTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()

	fx := newTunnelFixture(t, func(c *ListenerConfig) {
		c.Routes[0].Target = dead
	})

	client := tunnelClientCertExt(t, fx.caCert, fx.caKey, []string{"gateway:admin"}, nil)
	conn, stream := dialTunnel(t, fx, client)
	defer conn.CloseWithError(0, "")

	if _, err := stream.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.Copy(io.Discard, stream)

	// Without GS, no hard timeout timer; connection should remain open.
	time.Sleep(500 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := conn.OpenStreamSync(ctx); err != nil {
		t.Fatalf("connection should remain open without GS timeout, got: %v", err)
	}
}

func TestQUICTunnelNoTargetClosesStream(t *testing.T) {
	fx := newTunnelFixture(t, func(c *ListenerConfig) {
		c.Routes = nil
	})
	client := tunnelClientCert(t, fx.caCert, fx.caKey, []string{"gateway:admin"})
	conn, stream := dialTunnel(t, fx, client)
	defer conn.CloseWithError(0, "")
	if _, err := stream.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, rerr := io.Copy(io.Discard, stream); rerr != nil {
		t.Fatalf("expected clean EOF after server closed stream, got %v", rerr)
	}
}

func TestQUICStartUDPBusy(t *testing.T) {
	pki := setupPKI(t)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	addr := conn.LocalAddr().String()

	q := newTestQUIC(ListenerConfig{
		Name: "quic", Listen: addr, Protocol: ProtocolQUIC,
		TLS: &gw.TLSConfig{CertFile: pki.ServerCertFile, KeyFile: pki.ServerKeyFile},
	})
	if err := q.Start(); err == nil {
		q.Stop()
		t.Fatal("expected UDP listen conflict error")
	}
}
