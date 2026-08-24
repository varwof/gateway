package httpgw

import "testing"

func TestBundleNilAndArgs(t *testing.T) {
	var b *Bundle
	key := "http.access_denied"
	if got := b.T("en", key, "x"); got != key+"%!(EXTRA string=x)" {
		t.Fatalf("nil bundle with args = %q, want Sprintf-formatted key", got)
	}
	bb := NewBundle()
	known := "listener.listening"
	if got := bb.T("en", known, "arg"); got == "" {
		t.Fatal("expected formatted translation for known key")
	}
	if got := bb.T("xx", known, "arg"); got == "" {
		t.Fatal("expected en fallback translation for unknown lang")
	}
}
