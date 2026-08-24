// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package udpgw

import (
	"testing"
)

func TestNewBundle(t *testing.T) {
	b := NewBundle()
	if b == nil {
		t.Fatal("NewBundle() returned nil")
	}

	// Should have en and zh translations
	en := b.T("en", "gateway.started")
	if en != "UDP gateway started" {
		t.Errorf("en gateway.started = %q, want %q", en, "UDP gateway started")
	}

	zh := b.T("zh", "gateway.started")
	if zh != "UDP 网关已启动" {
		t.Errorf("zh gateway.started = %q, want %q", zh, "UDP 网关已启动")
	}
}

func TestBundleWithArgs(t *testing.T) {
	b := NewBundle()

	key := "listener.listening"
	msg := b.T("en", key, "test", ":8080", "plain")
	if msg != `listener "test" listening on :8080 [plain]` {
		t.Errorf("with args = %q", msg)
	}
}

func TestBundleFallback(t *testing.T) {
	b := NewBundle()

	// Missing key returns the key itself
	msg := b.T("en", "nonexistent.key")
	if msg != "nonexistent.key" {
		t.Errorf("expected raw key, got %q", msg)
	}
}

func TestBundleMissingLang(t *testing.T) {
	b := NewBundle()

	// Missing lang falls back to English
	msg := b.T("fr", "gateway.started")
	if msg != "UDP gateway started" {
		t.Errorf("expected English fallback, got %q", msg)
	}
}

func TestBundleNil(t *testing.T) {
	var b *Bundle

	msg := b.T("en", "gateway.started")
	if msg != "gateway.started" {
		t.Errorf("expected raw key for nil bundle, got %q", msg)
	}

	msg = b.T("en", "test %s", "arg")
	if msg != "test arg" {
		t.Errorf("expected formatted string for nil bundle, got %q", msg)
	}
}

func TestDetectLang(t *testing.T) {
	tests := []struct {
		name     string
		cliLang  string
		cfgLang  string
		envLang  string
		expected string
	}{
		{"CLI zh", "zh", "", "", "zh"},
		{"CLI zh_CN", "zh_CN", "", "", "zh"},
		{"CLI en", "en", "", "", "en"},
		{"cfg locale zh", "", "zh", "", "zh"},
		{"env zh", "", "", "zh_CN.UTF-8", "zh"},
		{"env en", "", "", "en_US", "en"},
		{"default en", "", "", "", "en"},
		{"priority: CLI over cfg", "en", "zh", "", "en"},
		{"priority: cfg over env", "", "zh", "en_US", "zh"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectLang(tt.cliLang, tt.cfgLang, tt.envLang)
			if got != tt.expected {
				t.Errorf("DetectLang(%q, %q, %q) = %q, want %q",
					tt.cliLang, tt.cfgLang, tt.envLang, got, tt.expected)
			}
		})
	}
}
