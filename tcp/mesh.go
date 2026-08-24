// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package tcpgw

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	gw "github.com/varwof/gateway-core"
)

// meshMatcher is the package-level target matcher used by proxyPeerToBackend for
// DNS rebinding prevention. Set by Gateway.Start() after loading mesh config.
var meshMatcher *meshTargetMatcher

// isLinkLocalOrMetadata returns true for link-local, loopback, and cloud metadata IPs.
func isLinkLocalOrMetadata(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// Cloud metadata endpoints: 169.254.169.254 (AWS/GCP/Azure)
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 169 && ip4[1] == 254 {
		return true
	}
	return false
}

// maxMeshTargetLen is the maximum length of a mesh forwarding target address (W38: named constant replacing magic number 4096).
const maxMeshTargetLen = 4096

type meshPeer struct {
	cfg    MeshPeerConfig
	tlsCfg *tls.Config
	mu     sync.Mutex
	conn   net.Conn
	logger *slog.Logger
}

// Mesh is a Mesh peer network instance that manages inter-node connections.
type Mesh struct {
	peers  map[string]*meshPeer
	logger *slog.Logger
}

// NewMesh creates a Mesh peer network instance.
func NewMesh(peers []MeshPeerConfig, logger *slog.Logger) *Mesh {
	if logger == nil {
		logger = slog.Default()
	}
	m := &Mesh{
		peers:  make(map[string]*meshPeer),
		logger: logger,
	}
	for _, p := range peers {
		tlsCfg, err := gw.ClientTLSConfig(p.CACertFile, p.CertFile, p.KeyFile, nil, "")
		if err != nil {
			logger.Warn("mesh: failed to build peer TLS config, skipping", "peer", p.Name, "error", err)
			continue
		}
		m.peers[p.Name] = &meshPeer{
			cfg:    p,
			tlsCfg: tlsCfg,
			logger: logger.With("peer", p.Name),
		}
	}
	return m
}

// Peer returns the peer node with the given name.
func (m *Mesh) Peer(name string) *meshPeer {
	return m.peers[name]
}

// Peers returns the list of all peer node names.
func (m *Mesh) Peers() []string {
	names := make([]string, 0, len(m.peers))
	for n := range m.peers {
		names = append(names, n)
	}
	return names
}

// DialConn establishes an mTLS connection to the peer and sends the target address.
// Returns the connected net.Conn which proxies bidirectionally with the caller.
func (p *meshPeer) DialConn(target string, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", p.cfg.Addr, p.tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("dial peer %s: %w", p.cfg.Name, err)
	}

	targetBytes := []byte(target)
	header := make([]byte, 2+len(targetBytes))
	binary.BigEndian.PutUint16(header[:2], uint16(len(targetBytes)))
	copy(header[2:], targetBytes)

	if _, err := conn.Write(header); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send target to peer: %w", err)
	}

	return conn, nil
}

// handleMeshPeerRequest handles inbound mesh forwarding requests and performs
// target allowlist validation (anti-SSRF, W02). target is the host:port the peer requests to dial.
func handleMeshPeerRequest(peerConn net.Conn, allowed *meshTargetMatcher, logger *slog.Logger) {
	if allowed == nil {
		allowed = newMeshTargetMatcher(nil)
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(peerConn, lenBuf[:]); err != nil {
		logger.Warn("peer: failed to read target length", "error", err)
		peerConn.Close()
		return
	}
	targetLen := binary.BigEndian.Uint16(lenBuf[:])
	if targetLen == 0 || targetLen > maxMeshTargetLen {
		logger.Warn("peer: invalid target length", "length", targetLen)
		peerConn.Close()
		return
	}

	targetBytes := make([]byte, targetLen)
	if _, err := io.ReadFull(peerConn, targetBytes); err != nil {
		logger.Warn("peer: failed to read target", "error", err)
		peerConn.Close()
		return
	}
	target := string(targetBytes)

	if !allowed.Allow(target) {
		logger.Warn("peer: target not allowed", "target", target)
		MeshTargetRejected.Inc()
		peerConn.Close()
		return
	}

	proxyPeerToBackend(peerConn, target, logger)
}

// meshTargetMatcher determines whether a mesh forwarding target is in the allowed set.
type meshTargetMatcher struct {
	exact map[string]bool
	subs  []string // "*.internal.example" suffix domains
	cidrs []*net.IPNet
}

func newMeshTargetMatcher(entries []string) *meshTargetMatcher {
	m := &meshTargetMatcher{exact: make(map[string]bool)}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			if _, ipnet, err := net.ParseCIDR(e); err == nil {
				m.cidrs = append(m.cidrs, ipnet)
			}
			continue
		}
		if strings.HasPrefix(e, "*.") {
			sub := e[2:]
			if _, _, err := net.SplitHostPort(sub); err == nil {
				if h, _, e2 := net.SplitHostPort(sub); e2 == nil {
					sub = h
				}
			}
			m.subs = append(m.subs, sub)
			continue
		}
		m.exact[e] = true
	}
	return m
}

// Allow determines whether the target (host:port or plain host) is allowed to be forwarded.
func (m *meshTargetMatcher) Allow(target string) bool {
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}

	// Exact host:port or host match.
	if m.exact[target] || m.exact[host] {
		return true
	}
	// Suffix domain match.
	for _, sub := range m.subs {
		if strings.HasSuffix(host, "."+sub) {
			return true
		}
	}
	// CIDR match (only for IP targets).
	if ip := net.ParseIP(host); ip != nil {
		for _, c := range m.cidrs {
			if c.Contains(ip) {
				return true
			}
		}
		// When no explicit CIDR, default allow loopback and private networks, blocking public SSRF.
		if len(m.cidrs) == 0 && m.isPrivate(ip) {
			return true
		}
	}
	return false
}

func (m *meshTargetMatcher) isPrivate(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// 169.254.0.0/16 link-local, 10/8, 172.16/12, 192.168/16
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
	}
	// IPv6 ULA fc00::/7 and link-local fe80::/10
	if v6 := ip.To16(); v6 != nil && ip.To4() == nil {
		if v6[0]&0xfe == 0xfc {
			return true
		}
		if v6[0] == 0xfe && v6[1]&0xc0 == 0x80 {
			return true
		}
	}
	return false
}

// HandlePeerRequest reads a target address from a peer connection,
// connects to the target, and proxies bidirectionally.
func HandlePeerRequest(peerConn net.Conn, logger *slog.Logger) {
	defer peerConn.Close()

	if logger == nil {
		logger = slog.Default()
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(peerConn, lenBuf[:]); err != nil {
		logger.Warn("peer: failed to read target length", "error", err)
		return
	}
	targetLen := binary.BigEndian.Uint16(lenBuf[:])
	if targetLen == 0 || targetLen > maxMeshTargetLen {
		logger.Warn("peer: invalid target length", "length", targetLen)
		return
	}

	targetBytes := make([]byte, targetLen)
	if _, err := io.ReadFull(peerConn, targetBytes); err != nil {
		logger.Warn("peer: failed to read target", "error", err)
		return
	}
	target := string(targetBytes)

	logger.Info("peer: forwarding request", "target", target)
	proxyPeerToBackend(peerConn, target, logger)
}

// proxyPeerToBackend dials the backend target and proxies bidirectionally with peerConn.
// H8 fix: resolve DNS first and validate resolved IPs against the mesh target matcher
// to prevent DNS rebinding attacks (hostname resolves to safe IP during validation,
// then re-resolves to metadata address during dial).
func proxyPeerToBackend(peerConn net.Conn, target string, logger *slog.Logger) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		port = "443"
	}

	// Resolve DNS and validate each resolved IP against the mesh matcher.
	resolver := net.DefaultResolver
	ips, err := resolver.LookupIPAddr(context.Background(), host)
	if err != nil || len(ips) == 0 {
		logger.Warn("peer: DNS resolution failed", "target", target, "error", err)
		return
	}

	// Validate resolved IPs against the mesh target matcher (DNS rebinding prevention).
	if meshMatcher != nil {
		for _, ip := range ips {
			if !meshMatcher.Allow(ip.IP.String()) {
				logger.Warn("peer: resolved IP rejected by mesh policy", "target", target, "ip", ip.IP)
				return
			}
		}
	} else {
		// No matcher configured: block link-local/metadata addresses.
		for _, ip := range ips {
			if isLinkLocalOrMetadata(ip.IP) {
				logger.Warn("peer: resolved IP is link-local/metadata, blocking", "target", target, "ip", ip.IP)
				return
			}
		}
	}

	// Dial the first resolved IP directly (no re-resolution).
	addr := net.JoinHostPort(ips[0].IP.String(), port)
	backend, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		logger.Warn("peer: dial target failed", "target", target, "addr", addr, "error", err)
		return
	}
	defer backend.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(backend, peerConn)
		backend.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(peerConn, backend)
		peerConn.Close()
	}()
	wg.Wait()
}

func (g *Gateway) startMeshListener() error {
	mesh := g.mesh
	if mesh == nil {
		return nil
	}

	listen := g.cfg.MeshListen
	if listen == "" {
		g.logger.Info("mesh: no mesh_listen configured, acting as leaf node only")
		return nil
	}

	var tlsCfg *tls.Config
	if g.cfg.MeshServerTLS != nil && g.cfg.MeshServerTLS.CertFile != "" {
		cert, err := gw.LoadCert(g.cfg.MeshServerTLS.CertFile, g.cfg.MeshServerTLS.KeyFile)
		if err != nil {
			return fmt.Errorf("mesh server cert: %w", err)
		}
		tlsCfg, err = gw.MTLSServerConfig(g.cfg.MeshServerTLS.CACertFile, cert,
			g.cfg.MeshServerTLS.CipherSuites, g.cfg.MeshServerTLS.MinTLSVersion)
		if err != nil {
			return fmt.Errorf("mesh server TLS config: %w", err)
		}
	}
	// W01 (2026-08-16): Mesh protocol requires symmetric mTLS — inbound must never fall back to plaintext.
	// Programmatic APIs may bypass validate(); here we defensively emit a hard error rather than silently
	// listening in plaintext.
	if tlsCfg == nil {
		return fmt.Errorf("mesh_listen configured but mesh_server_tls incomplete (mesh protocol is mTLS-only)")
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("mesh listener: %w", err)
	}
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}

	allowed := newMeshTargetMatcher(g.cfg.MeshAllowedTargets)
	meshMatcher = allowed // H8 fix: set package-level matcher for DNS rebinding prevention

	g.meshListener = ln
	g.logger.Info("mesh listener started", "listen", listen, "mtls", tlsCfg != nil)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if g.stopGuard.IsStopped() {
					return
				}
				g.logger.Warn("mesh listener accept error", "error", err)
				// W12 (2026-08-16): Accept error backoff, prevent hot loop.
				select {
				case <-time.After(acceptErrorBackoff):
				case <-g.stopCh:
					return
				}
				continue
			}
			// W10 (2026-08-16): Enable keepalive on accepted connections.
			enableTCPKeepAlive(conn)
			MeshRequestsReceived.Inc()
			go handleMeshPeerRequest(conn, allowed, g.logger.With("mesh", "incoming"))
		}
	}()

	return nil
}
