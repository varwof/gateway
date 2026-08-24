package httpgw

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

// TestTaskCompleteSignalRevokes verifies A4: when a request carries
// X-AIC-Task-Status: completed, certificate revocation is triggered immediately ("use-and-revoke").
// Uses a fake pki-core to record revocation calls.
func TestTaskCompleteSignalRevokes(t *testing.T) {
	pki := setupPKI(t)

	// Fake pki-core: records received revocation requests.
	var (
		mu      sync.Mutex
		revoked []string
	)
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/revoke") {
			mu.Lock()
			revoked = append(revoked, r.URL.Path)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer core.Close()

	backend, closeBackend := startSlowBackend(t)
	defer closeBackend()

	p := newDirectProxy(t, ListenerConfig{
		Name: "task", Protocol: ProtocolHTTP2,
		TLS:    &gw.TLSConfig{Mode: gw.TLSModeMTLS},
		Routes: []RouteConfig{{Path: "/api/*", Target: backend, AllowRoles: []string{"gateway:admin"}}},
	})
	revoker, err := gw.NewRevoker(gw.RevokerConfig{
		CoreURL:      core.URL + "/api/v1",
		MTLSCertFile: pki.AdminCertFile, MTLSKeyFile: pki.AdminKeyFile,
		Timeout: 2 * time.Second,
		CAMap:   map[string]string{"task-agent": "test-ca"},
	})
	if err != nil {
		t.Fatalf("build revoker: %v", err)
	}
	p.revoker = revoker
	// Inject shared task registry (simulates Gateway SetTaskRegistry).
	reg := gw.NewTaskRegistry()
	p.taskRegistry = reg

	cert, _, _ := makeCert(t, "task-agent", []string{"gateway:admin"}, false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)

	req := httptest.NewRequest("POST", "http://x/api/task", nil)
	req.Header.Set("X-AIC-Task-Id", "job-42")
	req.Header.Set("X-AIC-Task-Status", "completed")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rr := httptest.NewRecorder()
	p.handleRequest(rr, req)

	if rr.Code != http.StatusOK && rr.Code != http.StatusBadGateway {
		body, _ := io.ReadAll(rr.Body)
		t.Fatalf("expected proxied response, got %d: %s", rr.Code, string(body))
	}

	// Fake core should have received a revocation request.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(revoked)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	n := len(revoked)
	mu.Unlock()
	if n == 0 {
		t.Fatal("expected revoke call to fake pki-core, got none")
	}
	// Task record should have been unregistered.
	if reg.Lookup("job-42") != nil {
		t.Fatal("expected task job-42 unregistered after completion")
	}
}

// TestTaskRegisterHeaderOnly verifies A3: tasks carrying only X-AIC-Task-Id are registered,
// but no revocation is triggered when no completion signal is present.
func TestTaskRegisterHeaderOnly(t *testing.T) {
	pki := setupPKI(t)
	backend, closeBackend := startSlowBackend(t)
	defer closeBackend()

	p := newDirectProxy(t, ListenerConfig{
		Name: "task-reg", Protocol: ProtocolHTTP2,
		TLS:    &gw.TLSConfig{Mode: gw.TLSModeMTLS},
		Routes: []RouteConfig{{Path: "/api/*", Target: backend, AllowRoles: []string{"gateway:admin"}}},
	})
	revoker, err := gw.NewRevoker(gw.RevokerConfig{
		CoreURL:      "https://core.test:4433/api/v1",
		MTLSCertFile: pki.AdminCertFile, MTLSKeyFile: pki.AdminKeyFile,
	})
	if err != nil {
		t.Fatalf("build revoker: %v", err)
	}
	p.revoker = revoker
	reg := gw.NewTaskRegistry()
	p.taskRegistry = reg

	cert, _, _ := makeCert(t, "task-reg-agent", []string{"gateway:admin"}, false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)

	req := httptest.NewRequest("POST", "http://x/api/task", nil)
	req.Header.Set("X-AIC-Task-Id", "job-77")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rr := httptest.NewRecorder()
	p.handleRequest(rr, req)

	if rr.Code != http.StatusOK && rr.Code != http.StatusBadGateway {
		body, _ := io.ReadAll(rr.Body)
		t.Fatalf("expected proxied response, got %d: %s", rr.Code, string(body))
	}
	if rec := reg.Lookup("job-77"); rec == nil {
		t.Fatal("expected task job-77 registered")
	} else if rec.Serial == "" {
		t.Fatalf("expected serial recorded, got %+v", rec)
	}
}
