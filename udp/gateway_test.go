package udpgw

import (
	"testing"

	gw "github.com/varwof/gateway-core"
)

func TestNewGateway(t *testing.T) {
	g := NewGateway(
		&Config{},
		NewBundle(),
		"en",
		nil, nil, nil, nil,
	)
	if g == nil {
		t.Fatal("NewGateway() returned nil")
	}
	if len(g.listeners) != 0 {
		t.Errorf("expected 0 listeners, got %d", len(g.listeners))
	}
}

func TestGatewayStartEmpty(t *testing.T) {
	g := NewGateway(
		&Config{},
		NewBundle(),
		"en",
		nil, nil, nil, nil,
	)

	if err := g.Start(); err != nil {
		t.Fatalf("Start() with empty config error = %v", err)
	}
	g.Stop()
}

func TestGatewayStartWithPlainListener(t *testing.T) {
	g := NewGateway(
		&Config{
			Listeners: []ListenerConfig{
				{
					Name:     "test",
					Listen:   "127.0.0.1:0",
					Protocol: ProtocolUDP,
				},
			},
		},
		NewBundle(),
		"en",
		nil, nil, nil, nil,
	)

	if err := g.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if _, exists := g.listeners["test"]; !exists {
		t.Error("listener 'test' not found after Start()")
	}

	g.Stop()
}

func TestNewListener(t *testing.T) {
	t.Run("plain mode", func(t *testing.T) {
		ln, err := newListener(
			ListenerConfig{
				Name:     "test-plain",
				Listen:   "127.0.0.1:0",
				Protocol: ProtocolUDP,
			},
			nil, nil, nil, nil, nil, make(chan struct{}), NewBundle(), "en", nil, nil, nil,
		)
		if err != nil {
			t.Fatalf("newListener() error = %v", err)
		}
		if _, ok := ln.(*UDPProxy); !ok {
			t.Errorf("expected *UDPProxy, got %T", ln)
		}
		if ln.Name() != "test-plain" {
			t.Errorf("Name() = %q", ln.Name())
		}
	})

	t.Run("quic mode", func(t *testing.T) {
		ln, err := newListener(
			ListenerConfig{
				Name:     "test-quic",
				Listen:   "127.0.0.1:0",
				Protocol: ProtocolQUIC,
				TLS:      &gw.TLSConfig{CertFile: "/path/to/cert.pem", KeyFile: "/path/to/key.pem"},
			},
			nil, nil, nil, nil, nil, make(chan struct{}), NewBundle(), "en", nil, nil, nil,
		)
		if err != nil {
			t.Fatalf("newListener() error = %v", err)
		}
		if _, ok := ln.(*QUICProxy); !ok {
			t.Errorf("expected *QUICProxy, got %T", ln)
		}
	})
}

func TestConfigsEqual(t *testing.T) {
	a := ListenerConfig{Name: "test", Listen: ":8080", Protocol: ProtocolUDP}
	b := ListenerConfig{Name: "test", Listen: ":8080", Protocol: ProtocolUDP}
	c := ListenerConfig{Name: "test", Listen: ":9090", Protocol: ProtocolUDP}

	if !configsEqual(a, b) {
		t.Error("identical configs should be equal")
	}
	if configsEqual(a, c) {
		t.Error("different configs should not be equal")
	}
}

func TestBuildOCSPCache(t *testing.T) {
	t.Run("nil tls returns nil", func(t *testing.T) {
		if cache := buildOCSPCache(nil, NewBundle(), "en"); cache != nil {
			t.Error("expected nil for nil TLS config")
		}
	})

	t.Run("zero TTL returns nil", func(t *testing.T) {
		cache := buildOCSPCache(&gw.TLSConfig{}, NewBundle(), "en")
		if cache != nil {
			t.Error("expected nil for zero TTL")
		}
	})

	t.Run("valid config returns cache", func(t *testing.T) {
		cache := buildOCSPCache(
			&gw.TLSConfig{
				OCSPCacheTTLSec: 60,
				OCSPFallback:    "deny",
			},
			NewBundle(), "en",
		)
		if cache == nil {
			t.Error("expected non-nil cache")
		}
	})
}

func TestParseInt(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"", 0},
		{"0", 0},
		{"42", 42},
		{"-1", 0},
		{"abc", 0},
	}
	for _, tt := range tests {
		got := parseInt(tt.input)
		if got != tt.want {
			t.Errorf("parseInt(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestGatewayMetricsInitialized(t *testing.T) {
	// Ensure gateway metrics are registered via init() — just verify they're non-nil
	if PacketsTotal == nil {
		t.Error("PacketsTotal not initialized")
	}
	if PacketDroppedTotal == nil {
		t.Error("PacketDroppedTotal not initialized")
	}
	if ConnectionsAccepted == nil {
		t.Error("ConnectionsAccepted not initialized")
	}
}
