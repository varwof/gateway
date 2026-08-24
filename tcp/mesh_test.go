package tcpgw

import (
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	gw "github.com/varwof/gateway-core"
)

func TestNewMesh(t *testing.T) {
	m := NewMesh(nil, nil)
	if m == nil {
		t.Fatal("expected non-nil mesh")
	}
	if len(m.Peers()) != 0 {
		t.Fatal("expected empty peers")
	}
}

func TestNewMeshEmptyPeers(t *testing.T) {
	m := NewMesh([]MeshPeerConfig{}, nil)
	if m == nil {
		t.Fatal("expected non-nil mesh")
	}
	if len(m.Peers()) != 0 {
		t.Fatal("expected empty peers")
	}
}

func TestMeshPeerNotFound(t *testing.T) {
	m := NewMesh(nil, nil)
	p := m.Peer("nonexistent")
	if p != nil {
		t.Fatal("expected nil peer")
	}
}

func TestMeshPeerNameList(t *testing.T) {
	m := NewMesh([]MeshPeerConfig{}, nil)
	names := m.Peers()
	if names == nil {
		t.Fatal("expected empty slice, not nil")
	}
}

func TestMeshPeerConfigDefaults(t *testing.T) {
	// Verify the MeshPeerConfig struct fields
	cfg := MeshPeerConfig{
		Name:       "test-peer",
		Addr:       "10.0.0.1:8443",
		CACertFile: "/etc/ca.pem",
		CertFile:   "/etc/cert.pem",
		KeyFile:    "/etc/key.pem",
	}
	if cfg.Name != "test-peer" {
		t.Fatal("name mismatch")
	}
}

func TestNewMeshWithInvalidPeer(t *testing.T) {
	m := NewMesh([]MeshPeerConfig{
		{
			Name: "bad-peer",
			Addr: "127.0.0.1:1",
			// No cert files — ClientTLSConfig will return error but mesh should skip
		},
	}, nil)
	if m == nil {
		t.Fatal("expected non-nil mesh")
	}
	// Bad peer should be skipped
	if p := m.Peer("bad-peer"); p != nil {
		t.Fatal("expected bad-peer to be skipped")
	}
}

func TestMeshPeerDialTimeout(t *testing.T) {
	// This tests that DialConn with a non-routable address gets a timeout
	// rather than hanging forever
	m := NewMesh([]MeshPeerConfig{
		{
			Name:       "timeout-peer",
			Addr:       "198.51.100.1:8443",
			CACertFile: "testdata/ca-cert.pem",
			CertFile:   "testdata/client-cert.pem",
			KeyFile:    "testdata/client-key.pem",
		},
	}, nil)

	peer := m.Peer("timeout-peer")
	if peer == nil {
		t.Skip("peer skipped due to missing cert files")
	}

	conn, err := peer.DialConn("127.0.0.1:8080", 100*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatal("expected dial to fail")
	}
}

func TestHandlePeerRequestInvalidTargetLength(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan bool, 1)
	go func() {
		HandlePeerRequest(server, nil)
		done <- true
	}()

	// Send invalid zero-length target
	client.Write([]byte{0x00, 0x00})
	<-done
}

func TestHandlePeerRequestTooLongTarget(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan bool, 1)
	go func() {
		HandlePeerRequest(server, nil)
		done <- true
	}()

	// Send too-long target length (5000 > 4096)
	header := []byte{0x13, 0x88} // 5000
	client.Write(header)
	<-done
}

func TestHandlePeerRequestPartialTarget(t *testing.T) {
	server, client := net.Pipe()

	done := make(chan bool, 1)
	go func() {
		HandlePeerRequest(server, nil)
		done <- true
	}()

	// Send valid length but partial content, then close writer
	client.Write([]byte{0x00, 0x05}) // length 5
	client.Write([]byte("ab"))       // only 2 bytes
	client.Close()
	<-done
}

func TestHandlePeerRequestUnreachableTarget(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan bool, 1)
	go func() {
		HandlePeerRequest(server, nil)
		done <- true
	}()

	target := "198.51.100.99:9999"
	header := make([]byte, 2+len(target))
	header[0] = byte(len(target) >> 8)
	header[1] = byte(len(target))
	copy(header[2:], target)
	client.Write(header)

	select {
	case <-done:
	case <-time.After(12 * time.Second):
		t.Fatal("HandlePeerRequest did not return within timeout")
	}
}

func TestStartMeshListenerNoMesh(t *testing.T) {
	g := &Gateway{
		mesh:      nil,
		stopGuard: gw.NewStopGuard(),
		logger:    slog.Default(),
	}
	err := g.startMeshListener()
	if err != nil {
		t.Fatalf("expected no error: %v", err)
	}
}

func TestStartMeshListenerNoListen(t *testing.T) {
	g := &Gateway{
		mesh:      NewMesh(nil, nil),
		cfg:       &Config{},
		stopGuard: gw.NewStopGuard(),
		logger:    slog.Default(),
	}
	err := g.startMeshListener()
	if err != nil {
		t.Fatalf("expected no error: %v", err)
	}
}

func TestStartMeshListenerValid(t *testing.T) {
	dir := newTunnelCertDir(t)
	g := &Gateway{
		mesh: NewMesh(nil, nil),
		cfg: &Config{
			MeshListen: "127.0.0.1:0",
			// W01 (2026-08-16): Mesh protocol enforces symmetric mTLS — inbound must
		// configure full mesh_server_tls, otherwise startup is rejected (old behavior
		// silently listens in plaintext = cross-node forwarding guaranteed to fail + SSRF vector).
			MeshServerTLS: &gw.TLSConfig{
				CACertFile: filepath.Join(dir, "ca.pem"),
				CertFile:   filepath.Join(dir, "server.pem"),
				KeyFile:    filepath.Join(dir, "server.key"),
			},
		},
		stopGuard: gw.NewStopGuard(),
		logger:    slog.Default(),
	}
	err := g.startMeshListener()
	if err != nil {
		t.Fatalf("expected no error: %v", err)
	}
	if g.meshListener == nil {
		t.Fatal("expected mesh listener to be created")
	}
	g.meshListener.Close()
}

// TestStartMeshListenerRejectsPlaintext W01: MeshListen without mesh_server_tls
// must fail on startup (plaintext listening forbidden).
func TestStartMeshListenerRejectsPlaintext(t *testing.T) {
	g := &Gateway{
		mesh:      NewMesh(nil, nil),
		cfg:       &Config{MeshListen: "127.0.0.1:0"},
		stopGuard: gw.NewStopGuard(),
		logger:    slog.Default(),
	}
	if err := g.startMeshListener(); err == nil {
		t.Fatal("expected error: mesh_listen without mesh_server_tls must be rejected")
	}
}

func TestHandlePeerRequestProxiesTraffic(t *testing.T) {
	// Set up a local TCP echo server as the "backend"
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoListener.Close()

	echoAddr := echoListener.Addr().String()
	go func() {
		conn, err := echoListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		conn.Write(buf[:n])
	}()

	// Set up the peer request handler
	peerServer, peerClient := net.Pipe()
	defer peerServer.Close()
	defer peerClient.Close()

	go HandlePeerRequest(peerServer, slog.Default())

	// Send target address
	targetBytes := []byte(echoAddr)
	header := make([]byte, 2+len(targetBytes))
	header[0] = byte(len(targetBytes) >> 8)
	header[1] = byte(len(targetBytes))
	copy(header[2:], targetBytes)
	if _, err := peerClient.Write(header); err != nil {
		t.Fatal(err)
	}

	// Now we should be able to send data to "peer" and get it back
	time.Sleep(100 * time.Millisecond) // let the handler connect
	msg := []byte("hello mesh")
	if _, err := peerClient.Write(msg); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(msg))
	peerClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := peerClient.Read(reply)
	if err != nil {
		t.Fatal("expected echo reply, got:", err)
	}
	if string(reply[:n]) != string(msg) {
		t.Fatalf("expected %q, got %q", msg, reply[:n])
	}
}

func TestMeshTLSModeInConfigValidate(t *testing.T) {
	cfg := &Config{
		Mappings: []MappingConfig{
			{
				Name:         "mesh-test",
				Listen:       "127.0.0.1:0",
				Target:       "127.0.0.1:8080",
				Protocol:     ProtocolTCPMesh,
				MeshPeerName: "peer1",
			},
		},
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("expected valid: %v", err)
	}
}

func TestMeshTLSModeMissingPeer(t *testing.T) {
	cfg := &Config{
		Mappings: []MappingConfig{
			{
				Name:     "mesh-bad",
				Listen:   "127.0.0.1:0",
				Target:   "127.0.0.1:8080",
				Protocol: ProtocolTCPMesh,
			},
		},
	}
	if err := cfg.validate(); err == nil {
		t.Fatal("expected validation error for missing mesh_peer")
	}
}

func TestMeshSetOnMapping(t *testing.T) {
	m := NewMesh(nil, nil)
	mapping := &Mapping{}
	mapping.SetMesh(m)
	if mapping.mesh != m {
		t.Fatal("expected mesh to be set")
	}
}

func TestMeshHandleConnNoPeer(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	m := NewMesh(nil, nil)
	mapping := &Mapping{
		cfg:    MappingConfig{MeshPeerName: "nonexistent"},
		mesh:   m,
		logger: slog.Default(),
		stopCh: make(chan struct{}),
	}

	done := make(chan bool, 1)
	go func() {
		mapping.handleMesh(server, 0)
		done <- true
	}()

	// handleMesh should return without error (peer not found)
	<-done
}

func TestMeshConnMetricsRegistration(t *testing.T) {
	// Verify metrics symbols are accessible
	if MeshRequestsReceived == nil {
		t.Fatal("MeshRequestsReceived not initialized")
	}
	if MeshConnectionsActive == nil {
		t.Fatal("MeshConnectionsActive not initialized")
	}
	if MeshDialErrors == nil {
		t.Fatal("MeshDialErrors not initialized")
	}
}
