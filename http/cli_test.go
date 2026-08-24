package httpgw

import (
	"runtime"
	"strings"
	"testing"
)

func TestStringSliceFlag(t *testing.T) {
	var f stringSliceFlag
	if f.String() != "" {
		t.Fatalf("empty String() = %q", f.String())
	}
	if err := f.Set("a"); err != nil {
		t.Fatal(err)
	}
	if err := f.Set("b"); err != nil {
		t.Fatal(err)
	}
	if f.String() != "a,b" {
		t.Fatalf("String() = %q, want a,b", f.String())
	}
	if len(f.values) != 2 {
		t.Fatalf("values = %v", f.values)
	}
}

func TestVersionString(t *testing.T) {
	s := VersionString()
	if !strings.Contains(s, "gateway-http") {
		t.Fatalf("VersionString = %q", s)
	}
	if !strings.Contains(s, version) {
		t.Fatalf("VersionString = %q, want version %q", s, version)
	}
	if !strings.Contains(s, runtime.GOOS) || !strings.Contains(s, runtime.GOARCH) {
		t.Fatalf("VersionString = %q, want GOOS/GOARCH", s)
	}
}

func TestUsage(t *testing.T) {
	usage()
}

func TestDefaultConfigPaths(t *testing.T) {
	dir := DefaultConfigDir()
	if dir == "" {
		t.Fatal("DefaultConfigDir empty")
	}
	file := DefaultConfigFile()
	if file == "" || !strings.Contains(file, "gateway-http.json") {
		t.Fatalf("DefaultConfigFile = %q", file)
	}
	if !strings.HasPrefix(file, dir) {
		t.Fatalf("DefaultConfigFile %q not under dir %q", file, dir)
	}
}
