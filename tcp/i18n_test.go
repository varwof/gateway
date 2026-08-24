// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package tcpgw

import (
	"fmt"
	"testing"
)

func TestNewBundle(t *testing.T) {
	b := NewBundle()
	if b == nil {
		t.Fatal("NewBundle() returned nil")
	}
	if _, ok := b.data["en"]; !ok {
		t.Fatal("en locale not loaded")
	}
	if _, ok := b.data["zh"]; !ok {
		t.Fatal("zh locale not loaded")
	}
	if len(b.data["en"]) == 0 {
		t.Fatal("en locale empty")
	}
	if len(b.data["en"]) != len(b.data["zh"]) {
		t.Fatalf("key count mismatch: en=%d zh=%d",
			len(b.data["en"]), len(b.data["zh"]))
	}
}

func TestBundle_T(t *testing.T) {
	b := NewBundle()

	got := b.T("en", "gateway.started")
	if got != "gateway-tcp server started" {
		t.Fatalf("expected 'gateway-tcp server started', got %q", got)
	}

	got = b.T("zh", "gateway.started")
	if got != "gateway-tcp 服务已启动" {
		t.Fatalf("expected 'gateway-tcp 服务已启动', got %q", got)
	}
}

func TestBundle_Fallback(t *testing.T) {
	b := NewBundle()

	got := b.T("en", "nonexistent.key")
	if got != "nonexistent.key" {
		t.Fatalf("expected 'nonexistent.key', got %q", got)
	}

	got = b.T("fr", "gateway.started")
	if got != "gateway-tcp server started" {
		t.Fatalf("expected fallback to en, got %q", got)
	}
}

func TestBundle_Format(t *testing.T) {
	b := NewBundle()

	tmpl := b.T("en", "err.config_not_found")
	got := fmt.Sprintf(tmpl, "/etc/config.json")
	if got != "config file not found at /etc/config.json" {
		t.Fatalf("expected formatted string, got %q", got)
	}
}

func TestDetectLang(t *testing.T) {
	tests := []struct {
		cli    string
		cfg    string
		env    string
		expect string
	}{
		{"zh", "", "", "zh"},
		{"", "zh", "", "zh"},
		{"", "", "zh_CN.UTF-8", "zh"},
		{"en", "zh", "zh_CN.UTF-8", "en"},
		{"", "", "en_US.UTF-8", "en"},
		{"", "", "", "en"},
		{"", "fr", "", "en"},
	}
	for _, tt := range tests {
		got := DetectLang(tt.cli, tt.cfg, tt.env)
		if got != tt.expect {
			t.Errorf("DetectLang(%q,%q,%q) = %q, want %q",
				tt.cli, tt.cfg, tt.env, got, tt.expect)
		}
	}
}
