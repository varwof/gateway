package httpgw

import (
	"net/http/httptest"
	"testing"
)

func TestHTTPFactsFor(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/tables/customers/rows?tenant=org-a", nil)
	r.Header.Set("X-Role", "readonly")
	f := httpFactsFor(r)
	if f.Method != "GET" || f.Path != "/api/tables/customers/rows" {
		t.Fatalf("method/path wrong: %+v", f)
	}
	if len(f.Query["tenant"]) != 1 || f.Query["tenant"][0] != "org-a" {
		t.Fatalf("query wrong: %+v", f.Query)
	}
	if f.Headers["X-Role"] != "readonly" {
		t.Fatalf("headers wrong: %+v", f.Headers)
	}
}
