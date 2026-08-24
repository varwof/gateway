// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package tcpgw

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

// g3TestEvaluator is a stateful constraint executor for G3 integration tests: it starts rejecting
// after callCount >= callLimit (simulating time-window constraints expiring mid-connection).
type g3TestEvaluator struct {
	callLimit int32
	calls     atomic.Int32
}

func (e *g3TestEvaluator) CapabilityId() string { return "test-g3-expiry" }

func (e *g3TestEvaluator) Evaluate(cap *gw.Capability, ctx *gw.ConstraintContext) error {
	if e.calls.Add(1) > e.callLimit {
		return fmt.Errorf("constraint test-g3-expiry: expired after %d calls", e.callLimit)
	}
	return nil
}

// makeAICClientCertWithConstraint issues an AIC client certificate carrying authorizationConstraints.
func makeAICClientCertWithConstraint(t *testing.T, dir string, caCert *x509.Certificate, caKey *rsa.PrivateKey, constraint gw.Capability) {
	t.Helper()
	clientKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	aic := gw.AIC{
		Version:                  1,
		AgentId:                  "g3-recheck-client",
		PrincipalUid:             gw.PrincipalUid{Version: 1, Realm: "varwof", Identifier: "user@varwof.com", KeyHash: make([]byte, 32)},
		Capabilities:             []gw.Capability{{SchemeId: "http", CapabilityId: "gateway:read"}},
		AuthorizationConstraints: []gw.Capability{constraint},
		DelegationAuthorization: gw.DelegationAuthorization{
			SignatureValue:     []byte{},
			SignatureAlgorithm: gw.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
			Timestamp:          time.Now(),
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			Reason:             gw.Reason{ReasonCode: "TEST", Description: "test"},
		},
	}
	aicDER, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatal(err)
	}
	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "g3-recheck-client", OrganizationalUnit: []string{"gateway:mysql-prod"}},
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
}

// TestMappingG3ConstraintRecheckDisconnect verifies G3: when a constraint expires during a long-lived
// connection, the ConstraintRecheckSec periodic recheck triggers disconnection. Uses a stateful
// constraint (rejects after 3rd recheck) instead of a real time-window to avoid minute-scale waits.
func TestMappingG3ConstraintRecheckDisconnect(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	writePEM(filepath.Join(dir, "ca.pem"), "CERTIFICATE", caCert.Raw, t)
	generateTestCert(t, dir, "server", caCert, caKey, nil)

	// Register stateful constraint executor: allow first (handshake vote), then start rejecting.
	ev := &g3TestEvaluator{callLimit: 3}
	_ = gw.RegisterConstraint(ev)

	makeAICClientCertWithConstraint(t, dir, caCert, caKey, gw.Capability{
		SchemeId: "constraint", CapabilityId: ev.CapabilityId(), Parameters: []byte(`{}`),
	})

	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	recheckSec := 1
	cfg := MappingConfig{
		Name:     "test-g3-recheck",
		Listen:   "127.0.0.1:0",
		Target:   echoSrv.Addr().String(),
		Protocol: ProtocolTCPMTLS,
		TLS: &gw.TLSConfig{
			CACertFile: filepath.Join(dir, "ca.pem"),
			CertFile:   filepath.Join(dir, "server.pem"),
			KeyFile:    filepath.Join(dir, "server.key"),
			AllowRoles: []string{"gateway:mysql-prod"},
		},
		TCPExt: &gw.TCPExtra{
			ConstraintRecheckSec: recheckSec,
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

	// Handshake vote should allow (1st constraint call passes).
	msg := "g3 hello\n"
	if _, err := fmt.Fprint(conn, msg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || reply != msg {
		t.Fatalf("initial exchange failed: reply=%q err=%v", reply, err)
	}

	// Periodic recheck (~1s interval) rejects after 3rd call → connection disconnected.
	waitFor(t, 8*time.Second, func() bool {
		conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		_, err := conn.Write([]byte("probe\n"))
		return err != nil
	}, "mapping connection to be disconnected after constraint recheck violation")
}
