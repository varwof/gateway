// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package tcpgw

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

func newTestGateway() *Gateway {
	return NewGateway(&Config{}, NewBundle(), "en", nil, nil, nil, nil)
}

func TestHandleListMappings(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "server", caCert, caKey, nil)

	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	g := NewGateway(&Config{
		Mappings: []MappingConfig{{
			Name: "m1", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(),
			Protocol: ProtocolTCP,
		}, {
			Name: "m2", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(),
			Protocol: ProtocolTCPMTLS,
			TLS: &gw.TLSConfig{
				CACertFile:    filepath.Join(dir, "ca.pem"),
				CertFile:      filepath.Join(dir, "server.pem"),
				KeyFile:       filepath.Join(dir, "server.key"),
				MaxConnsPerIP: 5, MaxTotalConns: 50,
			},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()

	rec := httptest.NewRecorder()
	g.handleListMappings(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var infos []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &infos); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("got %d mappings", len(infos))
	}
	found := map[string]map[string]interface{}{}
	for _, i := range infos {
		found[i["name"].(string)] = i
	}
	if found["m1"]["tls_mode"] != "plain" {
		t.Fatalf("m1 info wrong: %+v", found["m1"])
	}
	if found["m2"]["per_ip_limit"].(float64) != 5 || found["m2"]["total_limit"].(float64) != 50 {
		t.Fatalf("m2 limits wrong: %+v", found["m2"])
	}
}

func TestHandleAddMapping(t *testing.T) {
	t.Run("bad json", func(t *testing.T) {
		g := newTestGateway()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{"))
		g.handleAddMapping(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("conflict", func(t *testing.T) {
		g := newTestGateway()
		g.mappings["dup"] = &Mapping{}
		rec := httptest.NewRecorder()
		body := `{"name":"dup","listen":"127.0.0.1:0","target":"x:1","protocol":"tcp"}`
		g.handleAddMapping(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409", rec.Code)
		}
	})

	t.Run("success", func(t *testing.T) {
		g := newTestGateway()
		rec := httptest.NewRecorder()
		body := `{"name":"web","listen":"127.0.0.1:0","target":"127.0.0.1:1","protocol":"tcp"}`
		g.handleAddMapping(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body %s", rec.Code, rec.Body.String())
		}
		if _, ok := g.mappings["web"]; !ok {
			t.Fatal("mapping not added")
		}
		defer g.mappings["web"].Stop()
		if len(g.cfg.Mappings) != 1 {
			t.Fatalf("cfg.Mappings len = %d", len(g.cfg.Mappings))
		}
	})

	t.Run("ca load error", func(t *testing.T) {
		g := newTestGateway()
		rec := httptest.NewRecorder()
		body := `{"name":"bad","listen":"127.0.0.1:0","target":"x:1","protocol":"tcp+mtls",
			"tls":{"ca_cert_file":"/nonexistent/ca.pem","crl_url":"http://127.0.0.1:1/x.crl"}}`
		g.handleAddMapping(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500, body %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("save warn", func(t *testing.T) {
		g := newTestGateway()
		g.cfg.configPath = filepath.Join(t.TempDir(), "no", "dir", "cfg.json")
		rec := httptest.NewRecorder()
		body := `{"name":"w","listen":"127.0.0.1:0","target":"127.0.0.1:1","protocol":"tcp"}`
		g.handleAddMapping(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body %s", rec.Code, rec.Body.String())
		}
		if _, ok := g.mappings["w"]; !ok {
			t.Fatal("mapping should still be added despite persist warning")
		}
		defer g.mappings["w"].Stop()
	})
}

func TestHandleRemoveMapping(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		g := newTestGateway()
		rec := httptest.NewRecorder()
		g.handleRemoveMapping(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/gateway/mappings/ghost", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("success", func(t *testing.T) {
		g := newTestGateway()
		echoSrv := startEchoServer(t)
		defer echoSrv.Close()
		m, err := NewMapping(MappingConfig{
			Name: "r", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(), Protocol: ProtocolTCP,
		}, nil, nil, nil, nil, NewBundle(), "en", nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("NewMapping: %v", err)
		}
		if err := m.Start(); err != nil {
			t.Fatalf("Start: %v", err)
		}
		g.mappings["r"] = m
		g.cfg.Mappings = append(g.cfg.Mappings, m.cfg)

		rec := httptest.NewRecorder()
		g.handleRemoveMapping(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/gateway/mappings/r", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body %s", rec.Code, rec.Body.String())
		}
		if _, ok := g.mappings["r"]; ok {
			t.Fatal("mapping not removed")
		}
		if len(g.cfg.Mappings) != 0 {
			t.Fatalf("cfg.Mappings still has entries")
		}
	})

	t.Run("persist fail", func(t *testing.T) {
		g := newTestGateway()
		g.cfg.configPath = filepath.Join(t.TempDir(), "no", "dir", "cfg.json")
		echoSrv := startEchoServer(t)
		defer echoSrv.Close()
		m, err := NewMapping(MappingConfig{
			Name: "p", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(), Protocol: ProtocolTCP,
		}, nil, nil, nil, nil, NewBundle(), "en", nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("NewMapping: %v", err)
		}
		if err := m.Start(); err != nil {
			t.Fatalf("Start: %v", err)
		}
		g.mappings["p"] = m
		g.cfg.Mappings = []MappingConfig{{Name: "p"}}
		rec := httptest.NewRecorder()
		g.handleRemoveMapping(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/gateway/mappings/p", nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500, body %s", rec.Code, rec.Body.String())
		}
		if _, ok := g.mappings["p"]; ok {
			t.Fatal("mapping should be removed despite persist failure")
		}
	})
}

func TestHandleCRLReload(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		g := newTestGateway()
		rec := httptest.NewRecorder()
		g.handleCRLReload(rec, httptest.NewRequest(http.MethodPost, "/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		var body map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body["reloaded"].(float64) != 0 {
			t.Fatalf("reloaded = %v", body["reloaded"])
		}
	})

	t.Run("with errors", func(t *testing.T) {
		dir := t.TempDir()
		caCert, _ := generateTestCA(t, dir)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("not a crl"))
		}))
		defer srv.Close()

		cache := gw.NewCRLCache(caCert, srv.URL, 3600, NewBundle(), "en")
		g := newTestGateway()
		g.crlCaches["t"] = cache

		rec := httptest.NewRecorder()
		g.handleCRLReload(rec, httptest.NewRequest(http.MethodPost, "/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		var body map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body["reloaded"].(float64) != 0 {
			t.Fatalf("reloaded = %v, want 0", body["reloaded"])
		}
		if errs, ok := body["errors"].([]interface{}); !ok || len(errs) == 0 {
			t.Fatalf("expected errors list, got %+v", body["errors"])
		}
	})
}

func TestHandleListPeers(t *testing.T) {
	g := newTestGateway()
	g.cfg.Peers = []MeshPeerConfig{{Name: "p1", Addr: "10.0.0.1:443"}}
	rec := httptest.NewRecorder()
	g.handleListPeers(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var infos []map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &infos); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(infos) != 1 || infos[0]["name"] != "p1" || infos[0]["addr"] != "10.0.0.1:443" {
		t.Fatalf("infos = %+v", infos)
	}
}

func TestHandleConfigReload(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "cfg.json")
		if err := os.WriteFile(path, []byte(`{"mappings":[]}`), 0644); err != nil {
			t.Fatal(err)
		}
		g := newTestGateway()
		g.cfg.configPath = path
		rec := httptest.NewRecorder()
		g.handleConfigReload(rec, httptest.NewRequest(http.MethodPost, "/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("error", func(t *testing.T) {
		g := newTestGateway()
		g.cfg.configPath = filepath.Join(t.TempDir(), "missing.json")
		rec := httptest.NewRecorder()
		g.handleConfigReload(rec, httptest.NewRequest(http.MethodPost, "/", nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})
}

func TestHandleRenew(t *testing.T) {
	peerCert := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkixName("renew-client"),
		DNSNames:     []string{"renew-client.example"},
	}

	newReq := func(method, path, body string) *http.Request {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peerCert}}
		return req
	}

	t.Run("mtls required", func(t *testing.T) {
		g := newTestGateway()
		rec := httptest.NewRecorder()
		g.handleRenew(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("invalid body", func(t *testing.T) {
		g := newTestGateway()
		rec := httptest.NewRecorder()
		g.handleRenew(rec, newReq(http.MethodPost, "/", "{"))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("missing fields", func(t *testing.T) {
		g := newTestGateway()
		rec := httptest.NewRecorder()
		g.handleRenew(rec, newReq(http.MethodPost, "/", `{"serial_hex":""}`))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("invalid pubkey", func(t *testing.T) {
		g := newTestGateway()
		rec := httptest.NewRecorder()
		body := `{"serial_hex":"1","new_pub_key_pem":"not-a-pem"}`
		g.handleRenew(rec, newReq(http.MethodPost, "/", body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("short-lived not configured", func(t *testing.T) {
		g := newTestGateway()
		pem := pubKeyPEM(t)
		body, err := json.Marshal(map[string]string{
			"serial_hex":      "4242",
			"new_pub_key_pem": pem,
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rec := httptest.NewRecorder()
		g.handleRenew(rec, newReq(http.MethodPost, "/", string(body)))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503, body %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("issue client init fails", func(t *testing.T) {
		g := newTestGateway()
		g.cfg.ShortLived = &gw.IssueConfig{}
		pem := pubKeyPEM(t)
		body, err := json.Marshal(map[string]string{
			"serial_hex":      "4242",
			"new_pub_key_pem": pem,
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rec := httptest.NewRecorder()
		g.handleRenew(rec, newReq(http.MethodPost, "/", string(body)))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500, body %s", rec.Code, rec.Body.String())
		}
	})
}

func TestWriteJSONAndAPIError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusCreated, map[string]string{"status": "ok"})
	if rec.Code != http.StatusCreated || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("writeJSON: code=%d ct=%q", rec.Code, rec.Header().Get("Content-Type"))
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("body = %+v", body)
	}

	rec2 := httptest.NewRecorder()
	writeAPIError(rec2, http.StatusBadRequest, "boom")
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("code = %d", rec2.Code)
	}
	if !strings.Contains(rec2.Body.String(), `"error":"boom"`) {
		t.Fatalf("body = %s", rec2.Body.String())
	}
}

func TestParsePublicKeyPEM(t *testing.T) {
	pemStr := pubKeyPEM(t)
	if _, err := parsePublicKeyPEM([]byte(pemStr)); err != nil {
		t.Fatalf("valid key: %v", err)
	}
	if _, err := parsePublicKeyPEM([]byte("garbage")); err == nil {
		t.Fatal("expected error for garbage")
	}
	if _, err := parsePublicKeyPEM([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")); err == nil {
		t.Fatal("expected error for non-public-key PEM")
	}
}

func TestBuildOCSPCache(t *testing.T) {
	if got := buildOCSPCache(nil, NewBundle(), "en"); got != nil {
		t.Fatal("nil mtls should yield nil cache")
	}
	if got := buildOCSPCache(&gw.TLSConfig{}, NewBundle(), "en"); got != nil {
		t.Fatal("zero TTL should yield nil cache")
	}
	c := buildOCSPCache(&gw.TLSConfig{OCSPCacheTTLSec: 300}, NewBundle(), "en")
	if c == nil {
		t.Fatal("expected cache")
	}
	c2 := buildOCSPCache(&gw.TLSConfig{OCSPCacheTTLSec: 60, OCSPFallback: "allow"}, NewBundle(), "en")
	if c2 == nil {
		t.Fatal("expected cache with fallback")
	}
}

func TestGatewayUpdateServerCert(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "server", caCert, caKey, nil)

	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	g := NewGateway(&Config{
		Mappings: []MappingConfig{{
			Name: "u", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(), Protocol: ProtocolTCP,
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()

	m := g.mappings["u"]
	if c, _ := m.getCert(nil); c != nil {
		t.Fatal("expected nil cert before update")
	}

	cert, err := tls.LoadX509KeyPair(
		filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"))
	if err != nil {
		t.Fatalf("load keypair: %v", err)
	}
	g.UpdateServerCert(&cert)
	if c, _ := m.getCert(nil); c == nil {
		t.Fatal("expected cert after update")
	}

	m.UpdateCert(nil)
	if c, _ := m.getCert(nil); c != nil {
		t.Fatal("expected nil cert after UpdateCert(nil)")
	}
}

func TestLoadAuthorizationPolicy(t *testing.T) {
	t.Run("no file configured", func(t *testing.T) {
		g := newTestGateway()
		g.loadAuthorizationPolicy()
	})

	t.Run("build opts error", func(t *testing.T) {
		g := NewGateway(&Config{
			AuthorizationFile: "/etc/authz.json",
			PolicySigning: &gw.PolicySigningConfig{
				Enabled: true,
				CAFile:  filepath.Join(t.TempDir(), "missing-ca.pem"),
			},
		}, NewBundle(), "en", nil, nil, nil, nil)
		g.loadAuthorizationPolicy()
	})

	t.Run("load fail degraded", func(t *testing.T) {
		dir := t.TempDir()
		g := NewGateway(&Config{
			AuthorizationFile: filepath.Join(dir, "missing.json"),
		}, NewBundle(), "en", nil, nil, nil, nil)
		g.loadAuthorizationPolicy()
	})

	t.Run("load success", func(t *testing.T) {
		dir := t.TempDir()
		policy := `{"version":"1.0","roles":{"client":{"display_name":"Client","profiles":["client"],"grants":["connect"]}}}`
		path := filepath.Join(dir, "authz.json")
		if err := os.WriteFile(path, []byte(policy), 0644); err != nil {
			t.Fatal(err)
		}
		g := NewGateway(&Config{AuthorizationFile: path}, NewBundle(), "en", nil, nil, nil, nil)
		g.loadAuthorizationPolicy()
	})
}

func TestStartManagementErrors(t *testing.T) {
	t.Run("missing cert", func(t *testing.T) {
		dir := t.TempDir()
		g := NewGateway(&Config{
			Management: &ManagementConfig{
				Listen: "127.0.0.1:0",
				TLS: &gw.TLSConfig{
					CACertFile: filepath.Join(dir, "ca.pem"),
					CertFile:   filepath.Join(dir, "missing.pem"),
					KeyFile:    filepath.Join(dir, "missing.key"),
				},
			},
		}, NewBundle(), "en", nil, nil, nil, nil)
		if _, err := g.startManagement(); err == nil {
			t.Fatal("expected error for missing cert file")
		}
	})

	t.Run("bad CA", func(t *testing.T) {
		dir := t.TempDir()
		caCert, caKey := generateTestCA(t, dir)
		generateTestCert(t, dir, "server", caCert, caKey, nil)
		badCA := filepath.Join(dir, "bad-ca.pem")
		if err := os.WriteFile(badCA, []byte("garbage"), 0644); err != nil {
			t.Fatal(err)
		}
		g := NewGateway(&Config{
			Management: &ManagementConfig{
				Listen: "127.0.0.1:0",
				TLS: &gw.TLSConfig{
					CACertFile: badCA,
					CertFile:   filepath.Join(dir, "server.pem"),
					KeyFile:    filepath.Join(dir, "server.key"),
				},
			},
		}, NewBundle(), "en", nil, nil, nil, nil)
		if _, err := g.startManagement(); err == nil {
			t.Fatal("expected error for bad CA")
		}
	})
}

func TestNewGatewayPluginRegistry(t *testing.T) {
	g := NewGateway(&Config{
		CapabilityPlugins: gw.PluginConfigs{
			"scheme-1": {Type: "nonexistent", Config: map[string]interface{}{}},
		},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if g.pluginRegistry == nil {
		t.Fatal("pluginRegistry should be non-nil even with bad plugin")
	}
}

func TestNewGatewayRevoker(t *testing.T) {
	g := NewGateway(&Config{
		VarwofCore: &gw.RevokerConfig{CoreURL: "http://127.0.0.1:1"},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if g.revoker != nil {
		t.Fatal("revoker should be nil for unreachable pki-core")
	}
}

func TestNewGatewayTSAProof(t *testing.T) {
	proof := gw.NewTSAProofLogger("", nil, nil, 0)
	tsa := &gw.TSAClient{}
	g := NewGateway(&Config{}, NewBundle(), "en", nil, tsa, proof, nil)
	if g.auditChain == nil {
		t.Fatal("auditChain should be non-nil")
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for: %s", msg)
}
