// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package httpgw

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

func newTestGateway(t *testing.T) (*Gateway, string) {
	t.Helper()
	backend, backendClose := startTestBackend(t)
	t.Cleanup(backendClose)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gw.json")
	cfgData := fmt.Sprintf(`{"listeners":[{"name":"g1","listen":"127.0.0.1:0","protocol":"http2","routes":[{"path":"/*","target":"%s"}]}]}`, backend)
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
	t.Cleanup(g.Stop)
	return g, backend
}

func TestWriteJSON(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSON(rr, http.StatusCreated, map[string]string{"k": "v"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("code = %d, want 201", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q", ct)
	}
	var m map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["k"] != "v" {
		t.Fatalf("body = %v", m)
	}
}

func TestWriteAPIError(t *testing.T) {
	rr := httptest.NewRecorder()
	writeAPIError(rr, http.StatusBadRequest, "boom")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rr.Code)
	}
	var m map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["error"] != "boom" {
		t.Fatalf("body = %v", m)
	}
}

func TestBuildOCSPCache(t *testing.T) {
	if got := buildOCSPCache(nil, nil, "en"); got != nil {
		t.Fatalf("nil TLS should return nil cache, got %v", got)
	}
	if got := buildOCSPCache(&gw.TLSConfig{}, nil, "en"); got != nil {
		t.Fatalf("zero TTL should return nil cache, got %v", got)
	}
	if got := buildOCSPCache(&gw.TLSConfig{OCSPCacheTTLSec: 60}, nil, "en"); got == nil {
		t.Fatal("expected non-nil cache when TTL set")
	}
	if got := buildOCSPCache(&gw.TLSConfig{OCSPCacheTTLSec: 60, OCSPFallback: "allow"}, nil, "en"); got == nil {
		t.Fatal("expected non-nil cache with explicit fallback")
	}
	// W28 (2026-08-16): explicit ocsp_fallback config but no TTL set -> OCSP must still be enabled
	// (old implementation silently returned nil, causing fallback config to disable OCSP entirely).
	if got := buildOCSPCache(&gw.TLSConfig{OCSPFallback: "deny"}, nil, "en"); got == nil {
		t.Fatal("expected non-nil cache when fallback set but TTL unset")
	}
}

func TestLoadAuthorizationPolicy(t *testing.T) {
	dir := t.TempDir()
	authFile := filepath.Join(dir, "authz.json")
	data := []byte(`{"version":"1.0","roles":{"admin":{"grants":["*"]}}}`)
	if err := os.WriteFile(authFile, data, 0644); err != nil {
		t.Fatal(err)
	}
	gw.SetAuthorizationPolicy(nil)
	defer gw.SetAuthorizationPolicy(nil)

	g := NewGateway(&Config{AuthorizationFile: authFile}, NewBundle(), "en", nil, nil, nil, nil)
	if gw.GetAuthorizationPolicy() == nil {
		t.Fatal("expected global authorization policy to be loaded")
	}
	_ = g
}

func TestLoadAuthorizationPolicyBuildOptsError(t *testing.T) {
	dir := t.TempDir()
	authFile := filepath.Join(dir, "authz.json")
	if err := os.WriteFile(authFile, []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		AuthorizationFile: authFile,
		PolicySigning:     &gw.PolicySigningConfig{Enabled: true, CAFile: filepath.Join(dir, "missing-ca.pem")},
	}
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	_ = g
}

func TestLoadAuthorizationPolicyLoadError(t *testing.T) {
	gw.SetAuthorizationPolicy(nil)
	defer gw.SetAuthorizationPolicy(nil)

	cfg := &Config{
		AuthorizationFile: "/nonexistent/authz.json",
		PolicySigning:     &gw.PolicySigningConfig{Require: true, SigSuffix: ".custom"},
	}
	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	_ = g
}

func TestStartManagementError(t *testing.T) {
	g := NewGateway(&Config{
		Management: &MgmtConfig{
			Listen: "127.0.0.1:0",
			TLS:    &gw.TLSConfig{CACertFile: "/x/ca.pem", CertFile: "/x/c.pem", KeyFile: "/x/k.pem"},
		},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err == nil {
		t.Fatal("expected management start error for missing cert files")
	}
	g.Stop()
}

func TestUpdateServerCert(t *testing.T) {
	g, _ := newTestGateway(t)
	g.UpdateServerCert(&tls.Certificate{})
}

func TestHandleListListeners(t *testing.T) {
	g, _ := newTestGateway(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/listeners", nil)
	g.handleListListeners(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", rr.Code, rr.Body.String())
	}
	var infos []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &infos); err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].Name != "g1" {
		t.Fatalf("infos = %+v", infos)
	}
}

func TestHandleAddListener(t *testing.T) {
	g, backend := newTestGateway(t)
	body := fmt.Sprintf(`{"name":"new1","listen":"127.0.0.1:0","protocol":"http2","routes":[{"path":"/*","target":"%s"}]}`, backend)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/listeners", bytes.NewBufferString(body))
	g.handleAddListener(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("add: code = %d, body = %s", rr.Code, rr.Body.String())
	}
	if _, ok := g.listeners["new1"]; !ok {
		t.Fatal("listener new1 not registered after add")
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/gateway/listeners", bytes.NewBufferString(body))
	g.handleAddListener(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("duplicate: code = %d, want 409", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/gateway/listeners", bytes.NewBufferString("not json"))
	g.handleAddListener(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad json: code = %d, want 400", rr.Code)
	}
}

func TestHandleRemoveListener(t *testing.T) {
	g, _ := newTestGateway(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/gateway/listeners/nope", nil)
	g.handleRemoveListener(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("not found: code = %d, want 404", rr.Code)
	}

	audit, _ := gw.NewAuditLogger("", nil, 0, 0)
	fp, err := NewProxyListener(ListenerConfig{
		Name: "foo", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2,
		Routes: []RouteConfig{{Path: "/", Target: "http://127.0.0.1:1"}},
	}, nil, nil, audit, nil, nil, NewBundle(), "en", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	g.listeners["foo"] = fp
	g.cfg.Listeners = append(g.cfg.Listeners, ListenerConfig{Name: "foo", Listen: "127.0.0.1:0", Protocol: ProtocolHTTP2})

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/gateway/listeners/foo", nil)
	g.handleRemoveListener(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("remove: code = %d, body = %s", rr.Code, rr.Body.String())
	}
	if _, ok := g.listeners["foo"]; ok {
		t.Fatal("listener foo still registered after remove")
	}
	for _, lc := range g.cfg.Listeners {
		if lc.Name == "foo" {
			t.Fatal("listener foo still present in cfg.Listeners")
		}
	}
}

func mgmtCall(t *testing.T, pki *testPKI, addr, req string) string {
	t.Helper()
	cliCert, _ := tls.LoadX509KeyPair(pki.AdminCertFile, pki.AdminKeyFile)
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates:       []tls.Certificate{cliCert},
		RootCAs:            pki.CAPool,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 16384)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	return string(buf[:n])
}

func TestManagementAPIFull(t *testing.T) {
	pki := setupPKI(t)
	mgmtAddr := fmt.Sprintf("127.0.0.1:%d", freePortTCP(t))
	backend, backendClose := startTestBackend(t)
	defer backendClose()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "mgmt.json")
	initial := fmt.Sprintf(`{"listeners":[{"name":"m1","listen":"127.0.0.1:0","protocol":"http2","routes":[{"path":"/*","target":"%s"}]}]}`, backend)
	if err := os.WriteFile(cfgPath, []byte(initial), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Management = &MgmtConfig{
		Listen: mgmtAddr,
		TLS:    &gw.TLSConfig{CACertFile: pki.CACertFile, CertFile: pki.ServerCertFile, KeyFile: pki.ServerKeyFile},
	}
	cfg.configPath = cfgPath

	g := NewGateway(cfg, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Stop()
	time.Sleep(150 * time.Millisecond)

	body := mgmtCall(t, pki, mgmtAddr, "GET /api/v1/gateway/listeners HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !contains(body, "200 OK") || !contains(body, "m1") {
		t.Fatalf("GET listeners: %s", body)
	}

	payload := fmt.Sprintf(`{"name":"m2","listen":"127.0.0.1:0","protocol":"http2","routes":[{"path":"/*","target":"%s"}]}`, backend)
	req := "POST /api/v1/gateway/listeners HTTP/1.1\r\nHost: x\r\nContent-Length: " + strconv.Itoa(len(payload)) + "\r\nConnection: close\r\n\r\n" + payload
	body = mgmtCall(t, pki, mgmtAddr, req)
	if !contains(body, "201 Created") {
		t.Fatalf("POST listener: %s", body)
	}

	body = mgmtCall(t, pki, mgmtAddr, "DELETE /api/v1/gateway/listeners/m2 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !contains(body, "200 OK") {
		t.Fatalf("DELETE listener: %s", body)
	}

	body = mgmtCall(t, pki, mgmtAddr, "POST /api/v1/gateway/reload HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !contains(body, "200 OK") {
		t.Fatalf("POST reload: %s", body)
	}
}
