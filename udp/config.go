// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package udpgw

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	gw "github.com/varwof/gateway-core"
)

// Protocol values for ListenerConfig.Protocol (transport + security semantics).
const (
	// ProtocolUDP is plaintext UDP packet forwarding (no TLS), or UDP with an
	// explicit tls.mode (server/mtls) set in the TLS block.
	ProtocolUDP = gw.ProtocolUDP
	// ProtocolDTLS is DTLS transport (server-auth by default, or tls.mode).
	ProtocolDTLS = gw.ProtocolDTLS
	// ProtocolMTLS is DTLS transport with mutual TLS (requires the TLS block).
	ProtocolMTLS = "udp+mtls"
	// ProtocolQUIC is QUIC transport (built-in TLS 1.3, mTLS via tls block).
	ProtocolQUIC = gw.ProtocolQUIC
)

// Config is the UDP gateway main configuration.
type Config struct {
	// Locale internationalization language code (zh/en).
	Locale string `json:"locale,omitempty"`
	// Listeners UDP listener configuration list.
	Listeners []ListenerConfig `json:"listeners"`
	// Management management API configuration.
	Management *ManagementConfig `json:"management,omitempty"`
	// VarwofCore Varwof Core service connection configuration.
	VarwofCore *gw.RevokerConfig `json:"varwof_core,omitempty"`
	// ShortLived short-lived certificate auto-issuance configuration.
	ShortLived *gw.IssueConfig `json:"short_lived,omitempty"`
	// CapabilityPlugins capability plugin configuration (JSON).
	CapabilityPlugins gw.PluginConfigs `json:"capability_plugins,omitempty"`
	// AuthorizationFile authorization policy file path (authz.json).
	AuthorizationFile string `json:"authorization_file,omitempty"`
	// CapabilitySchemes capability registration directory path (register spec).
	// Empty string uses embedded scheme; specified directory means disk override (edit JSON for hot-reload of policy).
	// When enabled, data plane verifies that AIC-declared capabilities must be registered.
	CapabilitySchemes string `json:"capability_schemes,omitempty"`
	// PolicySigning authorization policy file signature verification configuration.
	PolicySigning *gw.PolicySigningConfig `json:"policy_signing,omitempty"`
	// AuditIndexFile audit FTS index file path. When set, enables
	// GET /api/v1/gateway/audit/search full-text search endpoint.
	AuditIndexFile string `json:"audit_index_file,omitempty"`
	// RiskMonitor high-risk agent automated disposition rules. When set, enables
	// "behavior violation → disconnect + revocation" reactive closure.
	RiskMonitor *gw.RiskMonitorConfig `json:"risk_monitor,omitempty"`
	// ChainPeers cross-gateway audit chain reference peer endpoints. Each entry is a peer gateway's
	// management API base URL (e.g. https://gw2:9443). The gateway periodically pulls the peer's
	// GET /api/v1/gateway/audit/chain chain head and writes it to the local ChainRefStore,
	// forming a cross-gateway audit evidence DAG (no consensus ordering required).
	ChainPeers []gw.ChainPeerConfig `json:"chain_peers,omitempty"`
	// TSAProofFile TSA audit proof output file path.
	TSAProofFile string `json:"tsa_proof_file,omitempty"`
	// TSAProofIntervalSec TSA audit proof generation interval (seconds).
	TSAProofIntervalSec int `json:"tsa_proof_interval_sec,omitempty"`
	configPath          string
}

// Save persists the configuration to a JSON file.
func (c *Config) Save() error {
	if c.configPath == "" {
		rnd, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
		c.configPath = fmt.Sprintf("/tmp/gateway-udp-%d-%x.json", os.Getpid(), rnd.Uint64())
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(c.configPath, data, 0600)
}

// ListenerConfig defines a single UDP listener.
type ListenerConfig struct {
	// Name listener name (unique identifier).
	Name string `json:"name"`
	// Listen listen address (e.g. :5353).
	Listen string `json:"listen"`

	// Protocol is the transport+application protocol: udp, dtls, udp+mtls, quic.
	Protocol string `json:"protocol"`
	// TLS is the unified TLS configuration block.
	TLS *gw.TLSConfig `json:"tls,omitempty"`
	// UDPExt holds UDP-specific extension fields (packet limits, rate limiting, etc.).
	UDPExt *gw.UDPExtra `json:"udp_ext,omitempty"`

	// Routes routing rules (UDP destination forwarding).
	Routes []RouteConfig `json:"routes,omitempty"`
	// ReadTimeoutSec read timeout (seconds).
	ReadTimeoutSec int `json:"read_timeout_sec,omitempty"`
	// MaxPacketSize maximum UDP packet size (bytes).
	MaxPacketSize int `json:"max_packet_size,omitempty"`
}

// effectiveMode maps the protocol (+ optional TLS block) to the concrete TLS
// authentication mode driving the data plane: none / server / mtls.
// Returns "" for unknown protocols (rejected by validate).
func (l ListenerConfig) effectiveMode() string {
	switch l.Protocol {
	case ProtocolMTLS:
		return gw.TLSModeMTLS
	case ProtocolQUIC:
		if l.TLS != nil && l.TLS.Mode != "" {
			return l.TLS.Mode
		}
		return gw.TLSModeMTLS
	case ProtocolDTLS:
		if l.TLS != nil && l.TLS.Mode != "" {
			return l.TLS.Mode
		}
		return gw.TLSModeServer
	case ProtocolUDP:
		if l.TLS != nil && l.TLS.Mode != "" {
			return l.TLS.Mode
		}
		return gw.TLSModeNone
	}
	return ""
}

// DisplayTLSMode returns the effective TLS mode for API display purposes.
// gw.TLSModeNone is rendered as "plain" to match the historical tls_mode vocabulary.
func (l ListenerConfig) DisplayTLSMode() string {
	mode := l.effectiveMode()
	if mode == gw.TLSModeNone {
		return "plain"
	}
	return mode
}

// ReadTimeout returns the read/idle timeout duration (default 30 seconds).
func (l *ListenerConfig) ReadTimeout() time.Duration {
	if l.TLS == nil || l.TLS.IdleTimeoutSec <= 0 {
		return 30 * time.Second
	}
	return time.Duration(l.TLS.IdleTimeoutSec) * time.Second
}

// DisconnectOnExpiryEnabled returns whether to auto-disconnect on certificate expiry.
func (l *ListenerConfig) DisconnectOnExpiryEnabled() bool {
	if l.UDPExt != nil {
		return l.UDPExt.DisconnectOnExpiryEnabled()
	}
	return false
}

// RequireAICEnabled returns whether to require the client to hold an AIC certificate.
func (l *ListenerConfig) RequireAICEnabled() bool {
	return l.TLS.RequireAICEnabled()
}

// DisallowRepresentativeEnabled returns whether delegated-agent mode is disallowed.
func (l *ListenerConfig) DisallowRepresentativeEnabled() bool {
	return l.TLS.DisallowRepresentativeEnabled()
}

// RequireUserAuthEnabled returns whether user authentication is required.
func (l *ListenerConfig) RequireUserAuthEnabled() bool {
	return l.TLS.RequireUserAuthEnabled()
}

// RequireDelegationEnabled returns whether dual-certificate delegation mode is required.
func (l *ListenerConfig) RequireDelegationEnabled() bool {
	if l.UDPExt != nil {
		return l.UDPExt.RequireDelegationEnabled()
	}
	return false
}

// MaxPktsPerIP returns the max packets per IP per second (0=unlimited).
func (l *ListenerConfig) MaxPktsPerIP() int {
	if l.UDPExt != nil {
		return l.UDPExt.MaxPktsPerIP
	}
	return 0
}

// MaxTotalPkts returns the global max total packet count (0=unlimited).
func (l *ListenerConfig) MaxTotalPkts() int {
	if l.UDPExt != nil {
		return l.UDPExt.MaxTotalPkts
	}
	return 0
}

// ConnectionBPS returns the per-connection byte-level rate limit in bps (0=unlimited).
func (l *ListenerConfig) ConnectionBPS() int64 {
	if l.UDPExt != nil {
		return l.UDPExt.ConnectionBPS
	}
	return 0
}

// ConnectionBurst returns the token bucket burst capacity in bytes.
func (l *ListenerConfig) ConnectionBurst() int64 {
	if l.UDPExt != nil {
		return l.UDPExt.ConnectionBurst
	}
	return 0
}

// MaxConnsPerIP returns the max connections per IP (0=unlimited).
func (l *ListenerConfig) MaxConnsPerIP() int {
	if l.TLS != nil {
		return l.TLS.MaxConnsPerIP
	}
	return 0
}

// MaxConnsPerCert returns the max connections per certificate (0=unlimited).
func (l *ListenerConfig) MaxConnsPerCert() int {
	if l.TLS != nil {
		return l.TLS.MaxConnsPerCert
	}
	return 0
}

// MaxTotalConns returns the global max connections (0=unlimited).
func (l *ListenerConfig) MaxTotalConns() int {
	if l.TLS != nil {
		return l.TLS.MaxTotalConns
	}
	return 0
}

// AllowRoles returns the list of allowed RBAC roles.
func (l *ListenerConfig) AllowRoles() []string {
	if l.TLS != nil {
		return l.TLS.AllowRoles
	}
	return nil
}

// AuditFile returns the audit log file path.
func (l *ListenerConfig) AuditFile() string {
	if l.TLS != nil {
		return l.TLS.AuditFile
	}
	return ""
}

// IdleTimeout returns the idle timeout duration (0=unlimited).
func (l *ListenerConfig) IdleTimeout() time.Duration {
	return l.TLS.IdleTimeout()
}

// CRLRefreshDuration returns the CRL cache refresh interval (default 5 minutes).
func (l *ListenerConfig) CRLRefreshDuration() time.Duration {
	return l.TLS.CRLRefreshDuration()
}

// OCSPCacheTTL returns the OCSP cache TTL (default 5 minutes).
func (l *ListenerConfig) OCSPCacheTTL() time.Duration {
	if l.TLS != nil && l.TLS.OCSPCacheTTLSec > 0 {
		return time.Duration(l.TLS.OCSPCacheTTLSec) * time.Second
	}
	return 5 * time.Minute
}

// OCSPFallback returns the OCSP degradation policy (deny/allow).
func (l *ListenerConfig) OCSPFallback() string {
	if l.TLS != nil {
		return l.TLS.OCSPFallback
	}
	return ""
}

// TSAURL returns the TSA timestamp service URL.
func (l *ListenerConfig) TSAURL() string {
	if l.TLS != nil {
		return l.TLS.TSAURL
	}
	return ""
}

// TSACertFile returns the TSA certificate file path.
func (l *ListenerConfig) TSACertFile() string {
	if l.TLS != nil {
		return l.TLS.TSACertFile
	}
	return ""
}

// AuditMaxSize returns the max audit log file size (default 100MB).
func (l *ListenerConfig) AuditMaxSize() int64 {
	return l.TLS.AuditMaxSize()
}

// AuditMaxBackupCount returns the max number of audit log backup files (default 3).
func (l *ListenerConfig) AuditMaxBackupCount() int {
	return l.TLS.AuditMaxBackupCount()
}

// RequiredCapabilities returns the list of required capabilities.
func (l *ListenerConfig) RequiredCapabilities() []string {
	if l.TLS != nil {
		return l.TLS.RequiredCapabilities
	}
	return nil
}

// CapabilityScheme returns the capability scheme ID.
func (l *ListenerConfig) CapabilityScheme() string {
	if l.TLS != nil {
		return l.TLS.CapabilityScheme
	}
	return ""
}

// CipherSuites returns the list of TLS cipher suites.
func (l *ListenerConfig) CipherSuites() []string {
	if l.TLS != nil {
		return l.TLS.CipherSuites
	}
	return nil
}

// MinTLSVersion returns the minimum TLS version.
func (l *ListenerConfig) MinTLSVersion() string {
	if l.TLS != nil {
		return l.TLS.MinTLSVersion
	}
	return ""
}

// RouteConfig defines a UDP routing rule.
type RouteConfig struct {
	// Target backend target address.
	Target string `json:"target"`
	// AllowRoles allowed roles list.
	AllowRoles []string `json:"allow_roles,omitempty"`
}

// ManagementConfig is the management API configuration.
type ManagementConfig struct {
	// Listen management API listen address.
	Listen string `json:"listen"`
	// TLS management API mTLS configuration.
	TLS *gw.TLSConfig `json:"tls"`
}

// SetDefaults applies default values for unset config fields.
func (c *Config) SetDefaults() {
	if c.Listeners == nil {
		c.Listeners = []ListenerConfig{}
	}
	for i, l := range c.Listeners {
		if l.Protocol == "" {
			c.Listeners[i].Protocol = ProtocolUDP
		}
		if l.ReadTimeoutSec <= 0 {
			c.Listeners[i].ReadTimeoutSec = 30
		}
		if l.MaxPacketSize <= 0 {
			c.Listeners[i].MaxPacketSize = 65535
		}
	}
}

// LoadConfig loads configuration from a JSON file and performs validation.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(data))
	// W41 (2026-08-16): Reject unknown fields — typos were previously silently ignored.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.configPath = path
	if cfg.Listeners == nil {
		cfg.Listeners = []ListenerConfig{}
	}

	cfg.SetDefaults()

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
}

// --- CLI mode helpers ---

// CLIGlobals is the CLI global parameter overrides.
type CLIGlobals struct {
	// TSAURL CLI override: TSA service URL.
	TSAURL string
	// TSACertFile CLI override: TSA certificate file.
	TSACertFile string
	// TSAProofFile CLI override: TSA audit proof file.
	TSAProofFile string
	// TSAProofIntervalSec CLI override: TSA audit proof generation interval (seconds).
	TSAProofIntervalSec int
	// AuditFile CLI override: audit log file.
	AuditFile string
	// AuditMaxSizeMB CLI override: audit log file size (MB).
	AuditMaxSizeMB int
	// AuditMaxBackups CLI override: audit log backup count.
	AuditMaxBackups int
	// MgmtListen CLI override: management API listen address.
	MgmtListen string
	// MgmtCACert CLI override: management API CA certificate.
	MgmtCACert string
	// MgmtCert CLI override: management API client certificate.
	MgmtCert string
	// MgmtKey CLI override: management API client private key.
	MgmtKey string
	// MgmtCRLURL CLI override: management API CRL URL.
	MgmtCRLURL string
	// MgmtOCSPFallback CLI override: management API OCSP fallback policy.
	MgmtOCSPFallback string
	// CRLRefreshSec CLI override: CRL refresh interval (seconds).
	CRLRefreshSec int
	// OCSPCacheTTLSec CLI override: OCSP cache TTL (seconds).
	OCSPCacheTTLSec int
	// OCSPFallback CLI override: OCSP fallback policy.
	OCSPFallback string
}

func parseKV(s string) map[string]string {
	r := make(map[string]string)
	for _, p := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		r[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return r
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ";")
	r := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			r = append(r, p)
		}
	}
	return r
}

func buildListenerFromKV(kv map[string]string) ListenerConfig {
	lc := ListenerConfig{
		Name:           kv["name"],
		Listen:         kv["listen"],
		Protocol:       kv["protocol"],
		ReadTimeoutSec: parseInt(kv["read-timeout-sec"]),
		MaxPacketSize:  parseInt(kv["max-packet-size"]),
	}
	if lc.Protocol == "" {
		lc.Protocol = ProtocolUDP
	}
	tlsBlock := &gw.TLSConfig{
		CACertFile:      kv["ca-cert"],
		CertFile:        kv["cert"],
		KeyFile:         kv["key"],
		CRLURL:          kv["crl-url"],
		CRLRefreshSec:   parseInt(kv["crl-refresh-sec"]),
		OCSPCacheTTLSec: parseInt(kv["ocsp-cache-ttl-sec"]),
		OCSPFallback:    kv["ocsp-fallback"],
		TSAURL:          kv["tsa-url"],
		TSACertFile:     kv["tsa-cert-file"],
		AllowRoles:      splitList(kv["allow-roles"]),
		AuditFile:       kv["audit-file"],
		MaxConnsPerCert: parseInt(kv["max-conns-per-cert"]),
		MaxConnsPerIP:   parseInt(kv["max-conns-per-ip"]),
		IdleTimeoutSec:  parseInt(kv["idle-timeout-sec"]),
		AuditMaxSizeMB:  parseInt(kv["audit-max-size-mb"]),
		AuditMaxBackups: parseInt(kv["audit-max-backups"]),
		CipherSuites:    splitList(kv["cipher-suites"]),
		MinTLSVersion:   kv["min-tls-version"],
	}
	if tlsBlock.CACertFile != "" || tlsBlock.CertFile != "" || tlsBlock.KeyFile != "" ||
		tlsBlock.CRLURL != "" || tlsBlock.CRLRefreshSec > 0 || tlsBlock.OCSPCacheTTLSec > 0 ||
		tlsBlock.OCSPFallback != "" || tlsBlock.TSAURL != "" || tlsBlock.TSACertFile != "" ||
		tlsBlock.AuditFile != "" || tlsBlock.MaxConnsPerCert > 0 || tlsBlock.MaxConnsPerIP > 0 ||
		tlsBlock.IdleTimeoutSec > 0 || tlsBlock.AuditMaxSizeMB > 0 || tlsBlock.AuditMaxBackups > 0 ||
		tlsBlock.CipherSuites != nil || tlsBlock.MinTLSVersion != "" {
		lc.TLS = tlsBlock
	}
	udpExt := &gw.UDPExtra{
		MaxPktsPerIP:          parseInt(kv["max-pkts-per-ip"]),
		MaxTotalPkts:          parseInt(kv["max-total-pkts"]),
		ConnectionBPS:         int64(parseInt(kv["connection-bps"])),
		ConnectionBurst:       int64(parseInt(kv["connection-burst"])),
		DisconnectOnExpirySec: parseInt(kv["disconnect-on-expiry"]),
	}
	if udpExt.MaxPktsPerIP > 0 || udpExt.MaxTotalPkts > 0 || udpExt.ConnectionBPS > 0 ||
		udpExt.ConnectionBurst > 0 || udpExt.DisconnectOnExpirySec > 0 {
		lc.UDPExt = udpExt
	}
	if routes := kv["routes"]; routes != "" {
		for _, t := range splitList(routes) {
			lc.Routes = append(lc.Routes, RouteConfig{Target: t})
		}
	}
	return lc
}

// BuildConfigFromCLI builds configuration from CLI parameters, overriding global defaults.
func BuildConfigFromCLI(listenerKVs []string, g *CLIGlobals) (*Config, error) {
	cfg := &Config{
		Listeners: make([]ListenerConfig, 0, len(listenerKVs)),
	}
	for _, kv := range listenerKVs {
		lc := buildListenerFromKV(parseKV(kv))
		if lc.TLS != nil {
			if lc.TLS.TSAURL == "" {
				lc.TLS.TSAURL = g.TSAURL
			}
			if lc.TLS.TSACertFile == "" {
				lc.TLS.TSACertFile = g.TSACertFile
			}
			if lc.TLS.AuditFile == "" {
				lc.TLS.AuditFile = g.AuditFile
			}
			if lc.TLS.AuditMaxSizeMB <= 0 {
				lc.TLS.AuditMaxSizeMB = g.AuditMaxSizeMB
			}
			if lc.TLS.AuditMaxBackups <= 0 {
				lc.TLS.AuditMaxBackups = g.AuditMaxBackups
			}
			if lc.TLS.CRLRefreshSec <= 0 {
				lc.TLS.CRLRefreshSec = g.CRLRefreshSec
			}
			if lc.TLS.OCSPCacheTTLSec <= 0 {
				lc.TLS.OCSPCacheTTLSec = g.OCSPCacheTTLSec
			}
			if lc.TLS.OCSPFallback == "" {
				lc.TLS.OCSPFallback = g.OCSPFallback
			}
		}
		cfg.Listeners = append(cfg.Listeners, lc)
	}
	if g.TSAProofFile != "" {
		cfg.TSAProofFile = g.TSAProofFile
	}
	if g.TSAProofIntervalSec > 0 {
		cfg.TSAProofIntervalSec = g.TSAProofIntervalSec
	}
	if g.MgmtListen != "" {
		cfg.Management = &ManagementConfig{
			Listen: g.MgmtListen,
			TLS: &gw.TLSConfig{
				CACertFile:   g.MgmtCACert,
				CertFile:     g.MgmtCert,
				KeyFile:      g.MgmtKey,
				CRLURL:       g.MgmtCRLURL,
				OCSPFallback: g.MgmtOCSPFallback,
			},
		}
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	for i, l := range c.Listeners {
		if l.Name == "" {
			return fmt.Errorf("listeners[%d]: name required", i)
		}
		if l.Listen == "" {
			return fmt.Errorf("listeners[%d] %q: listen required", i, l.Name)
		}
		switch l.Protocol {
		case ProtocolUDP, ProtocolDTLS, ProtocolMTLS, ProtocolQUIC:
		default:
			return fmt.Errorf("listeners[%d] %q: invalid protocol %q", i, l.Name, l.Protocol)
		}
		switch l.Protocol {
		case ProtocolDTLS:
			if l.TLS == nil {
				return fmt.Errorf("listeners[%d] %q: tls config required for %s mode", i, l.Name, l.Protocol)
			}
			if l.TLS.CertFile == "" {
				return fmt.Errorf("listeners[%d] %q: tls.cert_file required for %s mode", i, l.Name, l.Protocol)
			}
			if l.TLS.KeyFile == "" {
				return fmt.Errorf("listeners[%d] %q: tls.key_file required for %s mode", i, l.Name, l.Protocol)
			}
		case ProtocolMTLS:
			if l.TLS == nil {
				return fmt.Errorf("listeners[%d] %q: tls config required for %s mode", i, l.Name, l.Protocol)
			}
			if l.TLS.CertFile == "" {
				return fmt.Errorf("listeners[%d] %q: tls.cert_file required for %s mode", i, l.Name, l.Protocol)
			}
			if l.TLS.KeyFile == "" {
				return fmt.Errorf("listeners[%d] %q: tls.key_file required for %s mode", i, l.Name, l.Protocol)
			}
			if l.TLS.CACertFile == "" {
				return fmt.Errorf("listeners[%d] %q: tls.ca_cert_file required for %s mode", i, l.Name, l.Protocol)
			}
		case ProtocolQUIC:
			if l.TLS == nil || l.TLS.CertFile == "" {
				return fmt.Errorf("listeners[%d] %q: tls.cert_file required for quic mode", i, l.Name)
			}
			if l.TLS.CACertFile == "" {
				return fmt.Errorf("listeners[%d] %q: tls.ca_cert_file required for quic mode (mTLS mandatory)", i, l.Name)
			}
		}
	}

	if c.Management != nil {
		if c.Management.Listen == "" {
			return fmt.Errorf("management.listen required")
		}
		if c.Management.TLS == nil {
			return fmt.Errorf("management.tls config required")
		}
		if c.Management.TLS.CACertFile == "" {
			return fmt.Errorf("management.tls.ca_cert_file required")
		}
	}

	return nil
}
