package tcpgw

import (
	"crypto/tls"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func startMeshPeer(t *testing.T, dir string, target string) net.Listener {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"))
	if err != nil {
		t.Fatalf("load peer keypair: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("peer tls listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go HandlePeerRequest(conn, nil)
		}
	}()
	return ln
}

func TestMappingMeshFullPath(t *testing.T) {
	peerDir := newTunnelCertDir(t)

	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	peer := startMeshPeer(t, peerDir, echoSrv.Addr().String())
	defer peer.Close()

	mesh := NewMesh([]MeshPeerConfig{{
		Name:       "peer1",
		Addr:       peer.Addr().String(),
		CACertFile: filepath.Join(peerDir, "ca.pem"),
		CertFile:   filepath.Join(peerDir, "client.pem"),
		KeyFile:    filepath.Join(peerDir, "client.key"),
	}}, nil)

	m, err := NewMapping(MappingConfig{
		Name: "mesh", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(),
		Protocol: ProtocolTCPMesh, MeshPeerName: "peer1",
	}, nil, nil, nil, nil, NewBundle(), "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	m.SetMesh(mesh)
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	conn, err := net.Dial("tcp", m.listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(conn, "mesh-echo\n")
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "mesh-echo\n" {
		t.Fatalf("echo = %q", string(buf[:n]))
	}
}

func TestMappingMeshDialPeerFails(t *testing.T) {
	peerDir := newTunnelCertDir(t)

	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	mesh := NewMesh([]MeshPeerConfig{{
		Name:       "down",
		Addr:       "127.0.0.1:1",
		CACertFile: filepath.Join(peerDir, "ca.pem"),
		CertFile:   filepath.Join(peerDir, "client.pem"),
		KeyFile:    filepath.Join(peerDir, "client.key"),
	}}, nil)

	m, err := NewMapping(MappingConfig{
		Name: "mesh-down", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(),
		Protocol: ProtocolTCPMesh, MeshPeerName: "down",
	}, nil, nil, nil, nil, NewBundle(), "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	m.SetMesh(mesh)
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	conn, err := net.Dial("tcp", m.listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("x\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected connection to be closed when peer is down")
	}
}

func TestMappingMeshPeerNotFound(t *testing.T) {
	peerDir := newTunnelCertDir(t)

	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	mesh := NewMesh([]MeshPeerConfig{{
		Name:       "other",
		Addr:       "127.0.0.1:1",
		CACertFile: filepath.Join(peerDir, "ca.pem"),
		CertFile:   filepath.Join(peerDir, "client.pem"),
		KeyFile:    filepath.Join(peerDir, "client.key"),
	}}, nil)

	m, err := NewMapping(MappingConfig{
		Name: "mesh-nope", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(),
		Protocol: ProtocolTCPMesh, MeshPeerName: "ghost",
	}, nil, nil, nil, nil, NewBundle(), "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	m.SetMesh(mesh)
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	conn, err := net.Dial("tcp", m.listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("x\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected connection to be closed when peer not found")
	}
}

func TestMappingMeshSetMeshNil(t *testing.T) {
	echoSrv := startEchoServer(t)
	defer echoSrv.Close()

	m, err := NewMapping(MappingConfig{
		Name: "mesh-nil", Listen: "127.0.0.1:0", Target: echoSrv.Addr().String(),
		Protocol: ProtocolTCPMesh, MeshPeerName: "x",
	}, nil, nil, nil, nil, NewBundle(), "en", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewMapping: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	conn, err := net.Dial("tcp", m.listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("x\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected connection closed when mesh is nil")
	}
}
