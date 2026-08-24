package httpgw

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
	"github.com/varwof/register/ruleexec"
)

// TestRealGatewayE2E runs the full process chain with the varwof-client
// issued AIC certificate:
//
//	mTLS client (AIC cert) -> real HTTP gateway (rule_schemes) -> mysql-api -> MySQL
//
// Prerequisites (skip otherwise):
//   - MYSQL_DSN (running MariaDB with the mysql-api schema)
//   - AIC cert/key issued by the varwof client
//     (E2E_AIC_CERT / E2E_AIC_KEY, default /tmp/e2e-certs/e2e-agent.{pem,key})
//   - the mysql-api binary (demo/mysql-api/mysql-api)
//
// The rule gates: GET /api/tables/employees/rows allowed; DELETE denied;
// /api/tables/orders/rows denied (path condition).
func TestRealGatewayE2E(t *testing.T) {
	dsn := os.Getenv("MYSQL_DSN")
	if dsn == "" {
		t.Skip("set MYSQL_DSN")
	}
	aicCert := os.Getenv("E2E_AIC_CERT")
	if aicCert == "" {
		aicCert = "/tmp/aic-e2e-pki/certs/zhangsan-agent.pem"
	}
	aicKey := os.Getenv("E2E_AIC_KEY")
	if aicKey == "" {
		aicKey = "/tmp/aic-e2e-pki/certs/zhangsan-agent.key"
	}
	if _, err := os.Stat(aicCert); err != nil {
		t.Skipf("AIC cert not found: %s", aicCert)
	}
	repo := filepath.Clean(filepath.Join("..", ".."))
	mysqlBin := filepath.Join(repo, "demo", "mysql-api", "mysql-api")
	if _, err := os.Stat(mysqlBin); err != nil {
		t.Skipf("mysql-api binary not found: %s", mysqlBin)
	}
	tlsCA := os.Getenv("E2E_TLS_CA")
	if tlsCA == "" {
		tlsCA = "/tmp/aic-e2e-pki/tls/certs/ca.pem" // issuer CA of the AIC cert
	}
	if _, err := os.Stat(tlsCA); err != nil {
		t.Skipf("e2e TLS CA not found: %s", tlsCA)
	}
	serverCert := os.Getenv("E2E_SERVER_CERT")
	if serverCert == "" {
		serverCert = "/tmp/aic-e2e-pki/api-e2e.pem"
	}
	serverKey := os.Getenv("E2E_SERVER_KEY")
	if serverKey == "" {
		serverKey = "/tmp/aic-e2e-pki/api-e2e.key"
	}
	if _, err := os.Stat(serverCert); err != nil {
		t.Skipf("e2e server cert not found: %s", serverCert)
	}

	// ---- 1) start mysql-api backend ----
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

	// ---- 2) publish rule (employees, method GET + path gate) ----
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules", "std/database-v1")
	_ = os.MkdirAll(rulesDir, 0o755)
	rule := `{
		"rule_id": "e2e-db", "version": "1.0.0",
		"scheme": "std/database-v1", "capability": "query:SELECT",
		"params": {"tables": ["employees"], "columns": {"employees": ["id","name","department"]},
			"filter_columns": {"employees": ["department"]},
			"row_filter": {"employees": {"column": "department", "op": "=", "value": "Engineering"}},
			"limit": {"max": 50}},
		"conditions": {"op": "and", "items": [
			{"op": "eq", "path": "request.method", "value": "GET"},
			{"op": "contains", "path": "request.path", "value": "/api/tables/employees"}
		]}
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

	// ---- 3) start real gateway with rule_schemes ----
	gwPort := freePortTCP(t)
	g := NewGateway(&Config{
		RuleSchemes:    outDir,
		RuleSignerCert: signerCert,
		Listeners: []ListenerConfig{{
			Name: "e2e", Listen: fmt.Sprintf("127.0.0.1:%d", gwPort), Protocol: ProtocolHTTP2,
			TLS: &gw.TLSConfig{
				Mode:       gw.TLSModeMTLS,
				CACertFile: tlsCA,
				CertFile:   serverCert,
				KeyFile:    serverKey,
			},
			Routes: []RouteConfig{{Path: "/*", Target: fmt.Sprintf("http://127.0.0.1:%d", backendPort)}},
		}},
	}, NewBundle(), "en", nil, nil, nil, nil)
	if err := g.Start(); err != nil {
		t.Fatalf("gateway start: %v", err)
	}
	defer g.Stop()

	// ---- 4) mTLS client with the AIC cert ----
	pool := x509.NewCertPool()
	caPEM, _ := os.ReadFile(tlsCA)
	pool.AppendCertsFromPEM(caPEM)
	cert, err := tls.LoadX509KeyPair(aicCert, aicKey)
	if err != nil {
		t.Fatalf("load AIC keypair: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		ServerName:   "e2e.varwof.test",
	}}}
	base := fmt.Sprintf("https://127.0.0.1:%d", gwPort)

	// allowed: GET employees rows -> proxied to mysql-api
	code, body := e2eRequest(t, client, base, "GET", "/api/tables/employees/rows")
	if code != http.StatusOK {
		t.Fatalf("GET employees: status %d body=%s", code, body)
	}
	if !strings.Contains(body, "id") {
		t.Fatalf("GET employees: expected mysql-api rows JSON, got %s", body)
	}

	// denied: DELETE (rule method condition)
	code, _ = e2eRequest(t, client, base, "DELETE", "/api/tables/employees/rows")
	if code != http.StatusForbidden {
		t.Fatalf("DELETE should be 403, got %d", code)
	}

	// denied: orders table (rule path condition)
	code, _ = e2eRequest(t, client, base, "GET", "/api/tables/orders/rows")
	if code != http.StatusForbidden {
		t.Fatalf("orders should be 403, got %d", code)
	}
}

func e2eRequest(t *testing.T, client *http.Client, base, method, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func waitHTTP(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("backend not ready: %s", url)
}

var _ = json.Marshal
