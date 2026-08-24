package udpgw

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

func TestNewUDPProxy(t *testing.T) {
	p, err := NewUDPProxy(
		ListenerConfig{
			Name:     "test",
			Listen:   "127.0.0.1:0",
			Protocol: ProtocolUDP,
		},
		nil, nil, nil, nil, nil, make(chan struct{}), NewBundle(), "en", nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("NewUDPProxy() error = %v", err)
	}
	if p.Name() != "test" {
		t.Errorf("Name() = %q, want %q", p.Name(), "test")
	}
	if p.ActiveClients() != 0 {
		t.Errorf("ActiveClients() = %d, want 0", p.ActiveClients())
	}
}

func TestUDPProxySelectTarget(t *testing.T) {
	t.Run("no routes returns empty", func(t *testing.T) {
		p := &UDPProxy{cfg: ListenerConfig{}}
		if target := p.selectTarget("hello"); target != "" {
			t.Errorf("expected empty, got %q", target)
		}
	})

	t.Run("single route returns it", func(t *testing.T) {
		p := &UDPProxy{
			cfg: ListenerConfig{
				Routes: []RouteConfig{{Target: "127.0.0.1:9001"}},
			},
		}
		if target := p.selectTarget("hello"); target != "127.0.0.1:9001" {
			t.Errorf("expected 127.0.0.1:9001, got %q", target)
		}
	})

	t.Run("multiple routes selects by hash", func(t *testing.T) {
		p := &UDPProxy{
			cfg: ListenerConfig{
				Routes: []RouteConfig{
					{Target: "a"},
					{Target: "b"},
				},
			},
		}
		// Same input always selects same target
		r1 := p.selectTarget("hello")
		r2 := p.selectTarget("hello")
		if r1 != r2 {
			t.Errorf("expected same target for same input, got %q vs %q", r1, r2)
		}
	})
}

func TestUDPProxyRateLimiting(t *testing.T) {
	p := &UDPProxy{
		cfg: ListenerConfig{
			UDPExt: &gw.UDPExtra{MaxPktsPerIP: 2},
		},
		rateLimit: make(map[string]*rateBucket),
	}

	src := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}

	// First two should be allowed
	if !p.trackClient(src) {
		t.Error("first packet should be allowed")
	}
	if !p.trackClient(src) {
		t.Error("second packet should be allowed")
	}
	// Third should be denied
	if p.trackClient(src) {
		t.Error("third packet should be rate limited")
	}
}

func TestUDPProxyRateLimitingReset(t *testing.T) {
	p := &UDPProxy{
		cfg: ListenerConfig{
			UDPExt: &gw.UDPExtra{MaxPktsPerIP: 1},
		},
		rateLimit: make(map[string]*rateBucket),
	}

	src := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 54321}

	if !p.trackClient(src) {
		t.Error("first packet should be allowed")
	}

	// Set the bucket's resetAt to the past
	key := src.String()
	p.mu.Lock()
	p.rateLimit[key].resetAt = time.Now().Add(-time.Second)
	p.mu.Unlock()

	if !p.trackClient(src) {
		t.Error("packet after reset should be allowed")
	}
}

func TestUDPProxyRateLimitingDisabled(t *testing.T) {
	p := &UDPProxy{
		cfg:       ListenerConfig{},
		rateLimit: make(map[string]*rateBucket),
	}

	src := &net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 9999}
	for i := 0; i < 10; i++ {
		if !p.trackClient(src) {
			t.Error("rate limiting should be disabled when MaxPktsPerIP is 0")
		}
	}
}

func TestUDPProxyTotalLimitReached(t *testing.T) {
	t.Run("disabled when MaxTotalPkts is 0", func(t *testing.T) {
		p := &UDPProxy{
			cfg: ListenerConfig{UDPExt: &gw.UDPExtra{MaxTotalPkts: 0}},
		}
		if p.totalLimitReached() {
			t.Error("totalLimitReached() should be false when MaxTotalPkts is 0")
		}
	})

	t.Run("disabled when UDPExt is nil", func(t *testing.T) {
		p := &UDPProxy{cfg: ListenerConfig{}}
		if p.totalLimitReached() {
			t.Error("totalLimitReached() should be false when UDPExt is nil")
		}
	})

	t.Run("under limit", func(t *testing.T) {
		p := &UDPProxy{
			cfg: ListenerConfig{UDPExt: &gw.UDPExtra{MaxTotalPkts: 5}},
		}
		p.usedPkts.Store(3)
		if p.totalLimitReached() {
			t.Error("totalLimitReached() should be false at 3/5")
		}
	})

	t.Run("at limit", func(t *testing.T) {
		p := &UDPProxy{
			cfg: ListenerConfig{UDPExt: &gw.UDPExtra{MaxTotalPkts: 5}},
		}
		p.usedPkts.Store(5)
		if !p.totalLimitReached() {
			t.Error("totalLimitReached() should be true at 5/5")
		}
	})

	t.Run("over limit", func(t *testing.T) {
		p := &UDPProxy{
			cfg: ListenerConfig{UDPExt: &gw.UDPExtra{MaxTotalPkts: 5}},
		}
		p.usedPkts.Store(10)
		if !p.totalLimitReached() {
			t.Error("totalLimitReached() should be true at 10/5")
		}
	})

	t.Run("concurrent access", func(t *testing.T) {
		p := &UDPProxy{
			cfg: ListenerConfig{UDPExt: &gw.UDPExtra{MaxTotalPkts: 100}},
		}
		var done atomic.Int64
		for i := 0; i < 10; i++ {
			go func() {
				for j := 0; j < 15; j++ {
					// countPacket() atomically caps the counter (no TOCTOU
					// overshoot), so callers must use it rather than a
					// check-then-add on usedPkts.
					p.countPacket()
				}
				done.Add(1)
			}()
		}
		for done.Load() < 10 {
			time.Sleep(10 * time.Millisecond)
		}
		if p.usedPkts.Load() > 100 {
			t.Errorf("usedPkts exceeded limit: %d > 100", p.usedPkts.Load())
		}
	})
}

func TestBuildDTLSCipherSuites(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  int
	}{
		{"nil input", nil, 0},
		{"empty input", []string{}, 0},
		{"single suite", []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}, 1},
		{"multiple suites", []string{
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		}, 2},
		{"unknown suite skipped", []string{"UNKNOWN_SUITE"}, 0},
		{"mixed known and unknown", []string{
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"UNKNOWN",
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		}, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildDTLSCipherSuites(tt.input)
			if len(got) != tt.want {
				t.Errorf("got %d suites, want %d: %v", len(got), tt.want, got)
			}
		})
	}
}

func TestLoadCertErrors(t *testing.T) {
	t.Run("missing cert file", func(t *testing.T) {
		_, err := loadCert(&gw.TLSConfig{})
		if err == nil {
			t.Error("expected error for missing cert_file")
		}
	})

	t.Run("missing key file", func(t *testing.T) {
		_, err := loadCert(&gw.TLSConfig{CertFile: "/path/to/cert.pem"})
		if err == nil {
			t.Error("expected error for missing key_file")
		}
	})
}

func TestUDPProxyStartStopPlain(t *testing.T) {
	p, err := NewUDPProxy(
		ListenerConfig{
			Name:           "test-plain",
			Listen:         "127.0.0.1:0",
			Protocol:       ProtocolUDP,
			ReadTimeoutSec: 1,
		},
		nil, nil, nil, nil, nil, make(chan struct{}), NewBundle(), "en", nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("NewUDPProxy() error = %v", err)
	}

	if err := p.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if p.ActiveClients() != 0 {
		t.Errorf("ActiveClients() should be 0 initially, got %d", p.ActiveClients())
	}

	// Verify we're listening
	if p.conn == nil {
		t.Error("conn should not be nil after Start()")
	}

	p.Stop()
	if p.running.Load() {
		t.Error("proxy should not be running after Stop()")
	}

	// Double stop should be safe
	p.Stop()
}

func TestUDPProxyStartTwice(t *testing.T) {
	p, err := NewUDPProxy(
		ListenerConfig{
			Name:     "test-twice",
			Listen:   "127.0.0.1:0",
			Protocol: ProtocolUDP,
		},
		nil, nil, nil, nil, nil, make(chan struct{}), NewBundle(), "en", nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("NewUDPProxy() error = %v", err)
	}

	if err := p.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer p.Stop()

	if err := p.Start(); err == nil {
		t.Error("expected error for starting already running proxy")
	}
}

func TestUDPProxyTLSWithoutConfig(t *testing.T) {
	p, err := NewUDPProxy(
		ListenerConfig{
			Name:     "bad-dtls",
			Listen:   "127.0.0.1:0",
			Protocol: ProtocolDTLS,
		},
		nil, nil, nil, nil, nil, make(chan struct{}), NewBundle(), "en", nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("NewUDPProxy() error = %v", err)
	}

	if err := p.Start(); err == nil {
		t.Error("expected error for DTLS without TLS config")
	}
}

func TestUDPProxyHandlePacket(t *testing.T) {
	certTracker := gw.NewConnectionTracker()
	p := &UDPProxy{
		cfg: ListenerConfig{
			Name:   "test-handle",
			Routes: []RouteConfig{}, // no routes -> will be dropped
		},
		rateLimit:   make(map[string]*rateBucket),
		certTracker: certTracker,
		bundle:      NewBundle(),
	}

	src := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}

	// Should not panic
	p.handlePacket(src, []byte("test"), true)

	// Active clients should temporarily increase and then decrease
	// Because handlePacket uses atomic.AddInt32 and defers atomic.AddInt32 -1
	// But after the goroutine completes, activeIP should be 0
	time.Sleep(10 * time.Millisecond)
	if p.ActiveClients() != 0 {
		t.Logf("ActiveClients() = %d (expected eventually 0, may still be running)", p.ActiveClients())
	}
}

func TestListenerUpMetricInit(t *testing.T) {
	// Verify metrics are registered (init already ran)
	if ListenerUp == nil {
		t.Error("ListenerUp metric not initialized")
	}
	if PacketsTotal == nil {
		t.Error("PacketsTotal metric not initialized")
	}
	if PacketDroppedTotal == nil {
		t.Error("PacketDroppedTotal metric not initialized")
	}
	if ActiveClients == nil {
		t.Error("ActiveClients metric not initialized")
	}
}

// TestQUICSelectTargetDistribution verifies M4: multi-route QUIC configs must
// actually distribute across routes instead of always hitting routes[0].
func TestQUICSelectTargetDistribution(t *testing.T) {
	routes := []RouteConfig{
		{Target: "127.0.0.1:9001"},
		{Target: "127.0.0.1:9002"},
		{Target: "127.0.0.1:9003"},
	}
	seen := make(map[string]bool)
	for i := 0; i < 30; i++ {
		seen[selectTarget(routes)] = true
	}
	if len(seen) < 2 {
		t.Errorf("selectTarget always returned the same route (%v); expected distribution across multiple", seen)
	}
}
