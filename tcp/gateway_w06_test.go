package tcpgw

import (
	"io"
	"net"
	"testing"
	"time"
)

// startHalfCloseBackend starts a backend server that "returns a response only after
// reading to EOF": the client finishes sending (FIN/CloseWrite), but the backend
// can still return a complete response — verifying that the gateway half-close
// forwarding does not truncate (W06).
func startHalfCloseBackend(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				body, err := io.ReadAll(c)
				if err != nil {
					return
				}
				// Simulate backend processing + response (client has half-closed write, should still receive).
				c.Write(append([]byte("RESP:"), body...))
			}(conn)
		}
	}()
	return ln
}

// TestMappingHalfCloseNoTruncation verifies W06: client sends a request then
// CloseWrite (half-close), backend reads EOF and returns response, response must
// not be truncated by the gateway (before fix, full close tore down the connection
// and dropped the response).
func TestMappingHalfCloseNoTruncation(t *testing.T) {
	backend := startHalfCloseBackend(t)
	defer backend.Close()

	m, err := NewMapping(MappingConfig{
		Name: "w06-halfclose", Listen: "127.0.0.1:0", Target: backend.Addr().String(), Protocol: ProtocolTCP,
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

	// Send request and half-close write direction (simulating "request done but still expecting response" protocol).
	if _, err := conn.Write([]byte("hello-request")); err != nil {
		t.Fatalf("write: %v", err)
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatal("expected *net.TCPConn")
	}
	if err := tcp.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	// Client should still receive the complete response (not truncated by gateway).
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v (W06 truncation?)", err)
	}
	if string(body) != "RESP:hello-request" {
		t.Fatalf("got %q, want %q", body, "RESP:hello-request")
	}
}

// TestHalfCloseWriteSemantics verifies that halfCloseWrite on *net.TCPConn is a
// half-close (peer can still write responses), not a full close.
func TestHalfCloseWriteSemantics(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverDone := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- ""
			return
		}
		defer conn.Close()
		body, _ := io.ReadAll(conn)
		// After half-close, peer can still read our data (read direction not closed).
		conn.Write([]byte("after-eof:" + string(body)))
		serverDone <- "served"
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	halfCloseWrite(conn) // Half-close write: peer reads EOF, but read direction still open.

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read after half-close: %v", err)
	}
	if string(buf[:n]) != "after-eof:data" {
		t.Fatalf("got %q", buf[:n])
	}
}

// TestIdleConnCloseWriteDelegation verifies that idleConn.CloseWrite delegates
// to the underlying *net.TCPConn (W06 half-close still works under W05 wrapping).
func TestIdleConnCloseWriteDelegation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		conn.Write([]byte("pong"))
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	wrapped := &idleConn{Conn: conn, idle: time.Minute}
	if _, err := wrapped.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := wrapped.CloseWrite(); err != nil {
		t.Fatalf("idleConn.CloseWrite: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read after idleConn half-close: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("got %q", buf)
	}
}
