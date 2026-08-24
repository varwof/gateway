package httpgw

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
	"github.com/varwof/register/ruleexec"
)

// TestRealGatewayMatrixE2E runs the aic-matrix-demo style permission
// matrix under the new rule_schemes stack:
//
//	users (AIC certs issued by the varwof client) x HTTP methods
//
// zhangsan: GET only | lisi: GET/POST/PUT | wangwu: GET/POST/PUT/DELETE.
// The gateway derives the required capability from the HTTP method
// (CapabilityScheme/CapabilityPrefix), so a method whose capability is
// missing from the agent's AIC is denied (403) while allowed methods
// reach the backend (non-403).
func TestRealGatewayMatrixE2E(t *testing.T) {
	dsn := os.Getenv("MYSQL_DSN")
	if dsn == "" {
		t.Skip("set MYSQL_DSN")
	}
	matrixDir := os.Getenv("E2E_MATRIX_DIR")
	if matrixDir == "" {
		matrixDir = "/tmp/aic-e2e-pki/certs"
	}
	if _, err := os.Stat(filepath.Join(matrixDir, "zhangsan-agent.pem")); err != nil {
		t.Skipf("matrix AIC certs not found in %s (run setup-e2e-pki.sh)", matrixDir)
	}
	repo := filepath.Clean(filepath.Join("..", ".."))
	mysqlBin := filepath.Join(repo, "demo", "mysql-api", "mysql-api")
	if _, err := os.Stat(mysqlBin); err != nil {
		t.Skipf("mysql-api binary not found: %s", mysqlBin)
	}
	tlsCA := "/tmp/aic-e2e-pki/tls/certs/ca.pem"
	serverCert := "/tmp/aic-e2e-pki/api-e2e.pem"
	serverKey := "/tmp/aic-e2e-pki/api-e2e.key"
	for _, f := range []string{tlsCA, serverCert, serverKey} {
		if _, err := os.Stat(f); err != nil {
			t.Skipf("e2e pki file not found: %s", f)
		}
	}

	// ---- backend ----
	backendPort := freePortTCP(t)
	cfgPath := filepath.Join(t.TempDir(), "mysql.json")
	_ = os.WriteFile(cfgPath, []byte(fmt.Sprintf(`{"listen":"127.0.0.1:%d","dsn":%q}`, backendPort, dsn)), 0o600)
	cmd := exec.Command(mysqlBin, "-config", cfgPath)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("start mysql-api: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	waitHTTP(t, fmt.Sprintf("http://127.0.0.1:%d/api/tables", backendPort), 15*time.Second)

	// ---- permissive path-gate rule (capability enforcement is at the
	// pipeline via CapabilityScheme method mapping) ----
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules", "std/database-v1")
	_ = os.MkdirAll(rulesDir, 0o755)
	rule := `{
		"rule_id": "matrix-db", "version": "1.0.0",
		"scheme": "std/database-v1", "capability": "GET:*",
		"params": {"tables": ["employees"], "columns": {"employees": ["id","name","department"]}, "limit": {"max": 50}},
		"conditions": {"op": "contains", "path": "request.path", "value": "/api/tables/employees"}
	}`
	_ = os.WriteFile(filepath.Join(rulesDir, "v1.0.json"), []byte(rule), 0o644)
	signerCert, signerKey, _, err := ruleexec.GenSignerCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	if _, err := ruleexec.PublishRules(filepath.Join(dir, "rules"), outDir, signerCert, signerKey); err != nil {
		t.Fatal(err)
	}

	// ---- gateway with method -> capability mapping ----
	gwPort := freePortTCP(t)
	g := NewGateway(&Config{
		RuleSchemes:    outDir,
		RuleSignerCert: signerCert,
		Listeners: []ListenerConfig{{
			Name: "matrix", Listen: fmt.Sprintf("127.0.0.1:%d", gwPort), Protocol: ProtocolHTTP2,
			TLS: &gw.TLSConfig{
				Mode:       gw.TLSModeMTLS,
				CACertFile: tlsCA,
				CertFile:   serverCert,
				KeyFile:    serverKey,
			},
			Routes: []RouteConfig{{
				Path:             "/*",
				Target:           fmt.Sprintf("http://127.0.0.1:%d", backendPort),
				CapabilityScheme: "std/database-v1",
				CapabilityPrefix: "std/database-v1",
			}},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("gateway start: %v", err)
	}
	defer g.Stop()

	// ---- mTLS client factory ----
	pool := x509.NewCertPool()
	caPEM, _ := os.ReadFile(tlsCA)
	pool.AppendCertsFromPEM(caPEM)
	newClient := func(certFile, keyFile string) *http.Client {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      pool,
			Certificates: []tls.Certificate{cert},
			ServerName:   "e2e.varwof.test",
		}}}
	}
	base := fmt.Sprintf("https://127.0.0.1:%d", gwPort)
	path := "/api/tables/employees/rows"

	// user -> methods allowed
	matrix := map[string]map[string]bool{
		"zhangsan": {"GET": true, "POST": false, "PUT": false, "DELETE": false},
		"lisi":     {"GET": true, "POST": true, "PUT": true, "DELETE": false},
		"wangwu":   {"GET": true, "POST": true, "PUT": true, "DELETE": true},
	}
	for user, methods := range matrix {
		client := newClient(filepath.Join(matrixDir, user+"-agent.pem"), filepath.Join(matrixDir, user+"-agent.key"))
		for method, wantAllow := range methods {
			code, body := e2eRequest(t, client, base, method, path)
			if wantAllow {
				if code == http.StatusForbidden {
					t.Errorf("%s %s: expected allow, got 403 (%s)", user, method, body)
				}
			} else if code != http.StatusForbidden {
				t.Errorf("%s %s: expected deny(403), got %d (%s)", user, method, code, body)
			}
		}
	}
}
