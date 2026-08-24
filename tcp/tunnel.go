// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package tcpgw

import (
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	gw "github.com/varwof/gateway-core"
)

// tunnelDialTimeout is the tunnel dial-to-gateway timeout (W08: tls.Dial originally had no timeout;
// black-hole peers would block for minutes; explicit 10s).
const tunnelDialTimeout = 10 * time.Second

// TunnelState represents the running state of a TCP tunnel.
type TunnelState string

const (
	// TunnelStopped indicates the tunnel has stopped.
	TunnelStopped TunnelState = "stopped"
	// TunnelRunning indicates the tunnel is running.
	TunnelRunning TunnelState = "running"
	// TunnelFailed indicates the tunnel failed to start.
	TunnelFailed TunnelState = "failed"
)

// Tunnel is a TCP tunnel instance that connects to the gateway via mTLS.
type Tunnel struct {
	cfg    TunnelConfig
	tlsCfg *tls.Config
	logger *slog.Logger
	state  atomic.Value
	mu     sync.Mutex
	stopCh chan struct{}
	wg     sync.WaitGroup
	conns  int64
}

// NewTunnel creates a TCP tunnel instance.
func NewTunnel(cfg TunnelConfig, logger *slog.Logger) (*Tunnel, error) {
	if logger == nil {
		logger = slog.Default()
	}
	tlsCfg, err := gw.ClientTLSConfig(cfg.CACertFile, cfg.CertFile, cfg.KeyFile, nil, "")
	if err != nil {
		return nil, fmt.Errorf("tunnel %q: %w", cfg.Name, err)
	}
	t := &Tunnel{
		cfg:    cfg,
		tlsCfg: tlsCfg,
		logger: logger,
		stopCh: make(chan struct{}),
	}
	t.state.Store(TunnelStopped)
	return t, nil
}

// Start starts TCP tunnel listening.
func (t *Tunnel) Start() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.state.Load().(TunnelState) == TunnelRunning {
		return fmt.Errorf("tunnel %q already running", t.cfg.Name)
	}

	local, err := net.Listen("tcp", t.cfg.Listen)
	if err != nil {
		t.state.Store(TunnelFailed)
		return fmt.Errorf("tunnel %q listen %s: %w", t.cfg.Name, t.cfg.Listen, err)
	}

	t.state.Store(TunnelRunning)
	t.logger.Info("tunnel listening", "name", t.cfg.Name, "listen", t.cfg.Listen, "gateway", t.cfg.GatewayAddr)

	go t.acceptLoop(local)
	return nil
}

// Stop stops the TCP tunnel (idempotent).
func (t *Tunnel) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.state.Load().(TunnelState) == TunnelStopped {
		return nil
	}

	close(t.stopCh)
	t.wg.Wait()
	t.state.Store(TunnelStopped)
	return nil
}

// State returns the current tunnel state.
func (t *Tunnel) State() TunnelState {
	return t.state.Load().(TunnelState)
}

// Conns returns the current active tunnel connection count.
func (t *Tunnel) Conns() int64 {
	return atomic.LoadInt64(&t.conns)
}

// Name returns the tunnel name.
func (t *Tunnel) Name() string {
	return t.cfg.Name
}

func (t *Tunnel) acceptLoop(local net.Listener) {
	defer local.Close()

	for {
		localConn, err := local.Accept()
		if err != nil {
			select {
			case <-t.stopCh:
				return
			default:
			}
			t.logger.Warn("tunnel accept error", "name", t.cfg.Name, "error", err)
			// W12 (2026-08-16): Accept error backoff, prevent hot loop.
			select {
			case <-time.After(acceptErrorBackoff):
			case <-t.stopCh:
				return
			}
			continue
		}
		// W10 (2026-08-16): Enable keepalive on accepted connections.
		enableTCPKeepAlive(localConn)

		// W03: wg.Add runs inside t.mu and re-checks stopCh — Stop() holds t.mu and calls wg.Wait(),
		// avoiding Add∥Wait race (concurrent Add with Wait when WaitGroup counter is 0 is undefined behavior);
		// and Stop closes(stopCh) inside the lock, so re-checking prevents orphaned connections.
		t.mu.Lock()
		select {
		case <-t.stopCh:
			t.mu.Unlock()
			localConn.Close()
			return
		default:
		}
		t.wg.Add(1)
		t.mu.Unlock()

		atomic.AddInt64(&t.conns, 1)
		go t.handleConn(localConn)
	}
}

func (t *Tunnel) handleConn(localConn net.Conn) {
	defer func() {
		localConn.Close()
		t.wg.Done()
		atomic.AddInt64(&t.conns, -1)
	}()

	gwConn, err := t.dialWithRetry()
	if err != nil {
		t.logger.Error("tunnel dial gateway failed", "name", t.cfg.Name, "gateway", t.cfg.GatewayAddr, "error", err)
		return
	}
	defer gwConn.Close()

	// W03: Stop() must force-disconnect the tunnel, otherwise idle connections make io.Copy block
	// forever and t.wg.Wait() hang indefinitely. dialWithRetry already respects stopCh; here we
	// cover already-established connections.
	tunnelWatch := make(chan struct{})
	defer close(tunnelWatch)
	go func() {
		select {
		case <-t.stopCh:
			localConn.Close()
			gwConn.Close()
		case <-tunnelWatch:
		}
	}()

	done := make(chan struct{}, 2)
	// W06: Half-close (CloseWrite) instead of full close, avoiding truncation of remaining peer response.
	// W09 (2026-08-16): Wait for both directions to finish — previously a single `<-done`, when the
	// first direction finished, the defer Close killed the second direction's io.Copy, losing in-flight
	// data; mapping/mesh both wait for both directions; tunnel is now consistent.
	go func() {
		io.Copy(gwConn, localConn)
		halfCloseWrite(gwConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(localConn, gwConn)
		halfCloseWrite(localConn)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func (t *Tunnel) dialWithRetry() (net.Conn, error) {
	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second

	for {
		// W08 (2026-08-16): tls.Dial had no dial timeout — black-hole peers (dropping packets without
		// sending RST) would block until the TCP kernel timeout (several minutes). Switched to
		// DialWithDialer with a 10s timeout (same default as Mapping.dialTimeout).
		d := &net.Dialer{Timeout: tunnelDialTimeout}
		conn, err := tls.DialWithDialer(d, "tcp", t.cfg.GatewayAddr, t.tlsCfg)
		if err == nil {
			return conn, nil
		}

		select {
		case <-t.stopCh:
			return nil, fmt.Errorf("stopped")
		default:
		}

		t.logger.Warn("tunnel dial failed, retrying", "name", t.cfg.Name, "backoff", backoff, "error", err)

		// Note (2026-08-16): time.After leaks — the timer cannot be reclaimed before it fires,
		// leaking one timer up to 30s per retry. Switched to a stoppable Timer.
		timer := time.NewTimer(backoff + time.Duration(rand.Int63n(int64(backoff/2))))
		select {
		case <-timer.C:
		case <-t.stopCh:
			timer.Stop()
			return nil, fmt.Errorf("stopped")
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
