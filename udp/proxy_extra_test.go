package udpgw

import (
	"net"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

func TestUDPProxyConfig(t *testing.T) {
	cfg := ListenerConfig{Name: "l", Listen: ":1", Protocol: ProtocolUDP}
	p := &UDPProxy{cfg: cfg}
	got := p.Config()
	if got.Name != cfg.Name || got.Listen != cfg.Listen || got.Protocol != cfg.Protocol {
		t.Errorf("Config() = %+v, want %+v", got, cfg)
	}
}

func TestUDPProxyHandlePacketEcho(t *testing.T) {
	echoConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer echoConn.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := echoConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echoConn.WriteTo(buf[:n], addr)
		}
	}()

	gwConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer gwConn.Close()

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	p := &UDPProxy{
		cfg: ListenerConfig{
			Name:           "handle",
			MaxPacketSize:  65535,
			Routes:         []RouteConfig{{Target: echoConn.LocalAddr().String()}},
			ReadTimeoutSec: 5,
		},
		rateLimit:   make(map[string]*rateBucket),
		certTracker: gw.NewConnectionTracker(),
		bundle:      NewBundle(),
		conn:        gwConn,
	}

	src := client.LocalAddr().(*net.UDPAddr)
	msg := []byte("hello via handlePacket\n")
	p.handlePacket(src, msg, true)

	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply := make([]byte, 1500)
	n, _, err := client.ReadFromUDP(reply)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(reply[:n]) != string(msg) {
		t.Errorf("got %q, want %q", string(reply[:n]), string(msg))
	}
}

func TestUDPProxyHandlePacketAllowedFalse(t *testing.T) {
	p := &UDPProxy{
		cfg:       ListenerConfig{Name: "h"},
		rateLimit: make(map[string]*rateBucket),
	}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1}
	p.handlePacket(src, []byte("x"), false)
}

func TestUDPProxyHandlePacketNoRoute(t *testing.T) {
	p := &UDPProxy{
		cfg:         ListenerConfig{Name: "h", MaxPacketSize: 1500},
		rateLimit:   make(map[string]*rateBucket),
		certTracker: gw.NewConnectionTracker(),
		bundle:      NewBundle(),
	}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1}
	p.handlePacket(src, []byte("x"), true)
	if p.ActiveClients() != 0 {
		t.Errorf("ActiveClients = %d, want 0 after drop", p.ActiveClients())
	}
}

func TestUDPProxyServeStopsWhenNotRunning(t *testing.T) {
	// Regression: serve() must exit when Stop() sets running=false even if
	// stopCh was already closed elsewhere (e.g. by Reload teardown).
	p, err := NewUDPProxy(
		ListenerConfig{
			Name:           "serve",
			Listen:         "127.0.0.1:0",
			Protocol:       ProtocolUDP,
			ReadTimeoutSec: 1,
		},
		nil, nil, nil, nil, nil, make(chan struct{}), NewBundle(), "en", nil, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	p.Stop()
	// If serve() were still stopCh-coupled and the test's channel were open it
	// would keep running; here it must have returned via the running check.
	if p.running.Load() {
		t.Error("proxy still marked running after Stop()")
	}
}

func TestUDPProxyStartTwiceResolveError(t *testing.T) {
	p, err := NewUDPProxy(
		ListenerConfig{
			Name:     "bad",
			Listen:   "999.999.999.999:1",
			Protocol: ProtocolUDP,
		},
		nil, nil, nil, nil, nil, make(chan struct{}), NewBundle(), "en", nil, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(); err == nil {
		t.Fatal("expected resolve error")
	}
	if p.running.Load() {
		t.Error("running should be false after failed Start")
	}
}

func TestUDPProxyStartBadCACert(t *testing.T) {
	p, err := NewUDPProxy(
		ListenerConfig{
			Name:     "dtls",
			Listen:   "127.0.0.1:0",
			Protocol: ProtocolDTLS,
			TLS: &gw.TLSConfig{
				CACertFile: "/nonexistent/ca.pem",
				CertFile:   "/nonexistent/cert.pem",
				KeyFile:    "/nonexistent/key.pem",
			},
		},
		nil, nil, nil, nil, nil, make(chan struct{}), NewBundle(), "en", nil, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(); err == nil {
		t.Fatal("expected load cert error")
	}
}
