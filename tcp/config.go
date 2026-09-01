// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package tcpgw

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	gw "github.com/varwof/gateway-core"
)

// Protocol values for MappingConfig.Protocol (transport + security semantics).
const (
	// ProtocolTCP is plaintext TCP transport (no TLS), or TCP with an explicit
	// tls.mode (server/mtls) set in the TLS block.
	ProtocolTCP = gw.ProtocolTCP
	// ProtocolTCPMTLS is TCP transport with mutual TLS (requires the TLS block).
	ProtocolTCPMTLS = "tcp+mtls"
	// ProtocolTCPMesh is TCP transport forwarded via a Mesh peer node
	// (mTLS-only, requires mesh_peer).
	ProtocolTCPMesh = "tcp+mesh"
)

// Config is the TCP gateway main configuration.
type Config struct {
	// Locale is the internationalization language code (zh/en).
	Locale string `json:"locale,omitempty"`
	// Peers is the list of Mesh mode peer node addresses.
	Peers []MeshPeerConfig `json:"peers,omitempty"`
	// MeshListen is the Mesh mode listen address.
	MeshListen string `json:"mesh_listen,omitempty"`
	// MeshServerTLS is the inbound Mesh server mTLS config. Must be provided
	// when MeshListen is configured: cert_file/key_file are this node's Mesh
	// server certificate, ca_cert_file is for verifying peer client certificates.
	// Defaults to rejecting by default port/plaintext (SSRF protection).
	MeshServerTLS *gw.TLSConfig `json:"mesh_server_tls,omitempty"`
	// MeshAllowedTargets is the inbound Mesh forwarding target allowlist.
	// When empty, only loopback and RFC1918 private network targets are allowed
	// (anti-SSRF); entries like "10.0.0.5:8080" or "192.168.1.0/24" or
	// "*.internal.example:443" can be appended.
	MeshAllowedTargets []string `json:"mesh_allowed_targets,omitempty"`
	// Mappings is the TCP port mapping list.
	Mappings []MappingConfig `json:"mappings"`
	// Tunnels is the TCP tunnel configuration list.
	Tunnels []TunnelConfig `json:"tunnels,omitempty"`
	// Management is the management API configuration.
	Management *ManagementConfig `json:"management,omitempty"`
	// TSAProofFile is the TSA audit proof output file path.
	TSAProofFile string `json:"tsa_proof_file,omitempty"`
	// TSAProofIntervalSec is the TSA audit proof generation interval (seconds).
	TSAProofIntervalSec int `json:"tsa_proof_interval_sec,omitempty"`
	// VarwofCore is the Varwof Core service connection configuration.
	VarwofCore *gw.RevokerConfig `json:"varwof_core,omitempty"`
	// ShortLived is the short-lived certificate auto-issuance configuration.
	ShortLived *gw.IssueConfig `json:"short_lived,omitempty"`
	// CapabilityPlugins is the capability plugin configuration (JSON).
	CapabilityPlugins gw.PluginConfigs `json:"capability_plugins,omitempty"`
	// AuthorizationFile is the authorization policy file path (authz.json).
	AuthorizationFile string `json:"authorization_file,omitempty"`
	// CapabilitySchemes is the capability registration directory path (register spec).
	// When empty, uses the embedded scheme; when a directory is specified, disk override
	// (editing JSON hot-updates the policy). When enabled, data plane validation requires
	// AIC-declared capabilities to be registered.
	CapabilitySchemes string `json:"capability_schemes,omitempty"`
	// PolicySigning is the authorization policy file signature verification configuration.
	PolicySigning *gw.PolicySigningConfig `json:"policy_signing,omitempty"`
	// AuditIndexFile is the audit FTS index file path. When set, enables the
	// GET /api/v1/gateway/audit/search full-text search endpoint.
	AuditIndexFile string `json:"audit_index_file,omitempty"`
	// RiskMonitor is the high-risk agent automatic disposition rule. When set, enables
	// the "behavior violation → disconnect + revoke" reactive closed loop.
	RiskMonitor *gw.RiskMonitorConfig `json:"risk_monitor,omitempty"`
	// ChainPeers is the cross-gateway audit chain reference peer endpoints. Each item
	// is a peer gateway's management API base URL (e.g. https://gw2:9443). The gateway
	// periodically pulls the peer's GET /api/v1/gateway/audit/chain chain head and writes
	// it to the local ChainRefStore, forming a cross-gateway audit evidence DAG (no consensus ordering).
	ChainPeers []gw.ChainPeerConfig `json:"chain_peers,omitempty"`
	configPath string
}

// Save persists the configuration to a JSON file.
func (c *Config) Save() error {
	if c.configPath == "" {
		// Finding 14: use os.CreateTemp instead of a predictable /tmp path with
		// a 32-bit random suffix. CreateTemp picks a high-entropy name and
		// opens with O_CREATE|O_EXCL (no symlink race), and the file is
		// created with 0600 perms. A predictable filename would let a local
		// attacker pre-create a symlink to clobber or redirect the saved
		// config.
		f, err := os.CreateTemp("", "gateway-tcp-*.json")
		if err != nil {
			return fmt.Errorf("create temp config: %w", err)
		}
		c.configPath = f.Name()
		if err := f.Close(); err != nil {
			return fmt.Errorf("close temp config: %w", err)
		}
		// os.WriteFile below re-opens and overwrites; keep the file
		// restricted to the owner.
		_ = os.Chmod(c.configPath, 0o600)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(c.configPath, data, 0600)
}

// MappingConfig defines a single TCP port mapping.
type MappingConfig struct {
	// Name is the mapping name (unique identifier).
	Name string `json:"name"`
	// Listen is the listen address (e.g. :8443).
	Listen string `json:"listen"`
	// Target is the backend target address (e.g. 127.0.0.1:8080).
	Target string `json:"target"`

	// ── Protocol & TLS (unified format) ──
	// Protocol is the transport+security protocol: tcp (plaintext, or TLS via
	// tls.mode), tcp+mtls, tcp+mesh.
	Protocol string `json:"protocol"`
	// TLS is the unified TLS configuration block.
	TLS *gw.TLSConfig `json:"tls,omitempty"`
	// TCPExt holds TCP-specific extension fields (timeouts, health checks, etc.).
	TCPExt *gw.TCPExtra `json:"tcp_ext,omitempty"`

	// MeshPeerName is the Mesh mode peer node name.
	MeshPeerName string `json:"mesh_peer,omitempty"`
}

// effectiveMode maps the protocol (+ optional TLS block) to the concrete TLS
// authentication mode driving the data plane: none / server / mtls / mesh.
// Returns "" for unknown protocols (rejected by validate).
func (m *MappingConfig) effectiveMode() string {
	switch m.Protocol {
	case ProtocolTCPMesh:
		return "mesh"
	case ProtocolTCPMTLS:
		return gw.TLSModeMTLS
	case ProtocolTCP:
		if m.TLS != nil && m.TLS.Mode != "" {
			return m.TLS.Mode
		}
		return gw.TLSModeNone
	}
	return ""
}

// DisplayTLSMode returns the effective TLS mode for API display purposes.
// gw.TLSModeNone is rendered as "plain" to match the historical tls_mode vocabulary.
func (m *MappingConfig) DisplayTLSMode() string {
	mode := m.effectiveMode()
	if mode == gw.TLSModeNone {
		return "plain"
	}
	return mode
}

// DisconnectOnExpiryEnabled returns whether to auto-disconnect on certificate expiry.
func (m *MappingConfig) DisconnectOnExpiryEnabled() bool {
	return m.TLS.DisconnectOnExpiryEnabled()
}

// RequireAICEnabled returns whether to require the client to hold an AIC certificate.
func (m *MappingConfig) RequireAICEnabled() bool {
	return m.TLS.RequireAICEnabled()
}

// RequireDelegationEnabled returns whether dual-certificate delegation mode is required.
func (m *MappingConfig) RequireDelegationEnabled() bool {
	if m.TCPExt != nil {
		return m.TCPExt.RequireDelegationEnabled()
	}
	return false
}

// MaxConnsPerIP returns the max connections per IP (0=unlimited).
func (m *MappingConfig) MaxConnsPerIP() int {
	if m.TLS != nil {
		return m.TLS.MaxConnsPerIP
	}
	return 0
}

// MaxConnsPerCert returns the max connections per certificate (0=unlimited).
func (m *MappingConfig) MaxConnsPerCert() int {
	if m.TLS != nil {
		return m.TLS.MaxConnsPerCert
	}
	return 0
}

// MaxTotalConns returns the global max connections (0=unlimited).
func (m *MappingConfig) MaxTotalConns() int {
	if m.TLS != nil {
		return m.TLS.MaxTotalConns
	}
	return 0
}

// AllowRoles returns the list of allowed RBAC roles.
func (m *MappingConfig) AllowRoles() []string {
	if m.TLS != nil {
		return m.TLS.AllowRoles
	}
	return nil
}

// AuditFile returns the audit log file path.
func (m *MappingConfig) AuditFile() string {
	if m.TLS != nil {
		return m.TLS.AuditFile
	}
	return ""
}

// IdleTimeout returns the idle timeout duration (0=unlimited).
func (m *MappingConfig) IdleTimeout() time.Duration {
	return m.TLS.IdleTimeout()
}

// CRLRefreshDuration returns the CRL cache refresh interval (default 5 minutes).
func (m *MappingConfig) CRLRefreshDuration() time.Duration {
	return m.TLS.CRLRefreshDuration()
}

// OCSPCacheTTL returns the OCSP cache TTL (default 5 minutes).
func (m *MappingConfig) OCSPCacheTTL() time.Duration {
	if m.TLS != nil && m.TLS.OCSPCacheTTLSec > 0 {
		return time.Duration(m.TLS.OCSPCacheTTLSec) * time.Second
	}
	return 5 * time.Minute
}

// OCSPFallback returns the OCSP degradation policy (deny/allow).
func (m *MappingConfig) OCSPFallback() string {
	if m.TLS != nil {
		return m.TLS.OCSPFallback
	}
	return ""
}

// TSAURL returns the TSA timestamp service URL.
func (m *MappingConfig) TSAURL() string {
	if m.TLS != nil {
		return m.TLS.TSAURL
	}
	return ""
}

// TSACertFile returns the TSA certificate file path.
func (m *MappingConfig) TSACertFile() string {
	if m.TLS != nil {
		return m.TLS.TSACertFile
	}
	return ""
}

// HealthCheckInterval returns the backend health check interval (0=no check).
func (m *MappingConfig) HealthCheckInterval() time.Duration {
	if m.TCPExt != nil {
		return m.TCPExt.HealthCheckInterval()
	}
	return 0
}

// HealthCheckURL returns the health check URL.
func (m *MappingConfig) HealthCheckURL() string {
	if m.TCPExt != nil {
		return m.TCPExt.HealthCheckURL
	}
	return ""
}

// DialTimeout returns the backend dial timeout (default 10s).
func (m *MappingConfig) DialTimeout() time.Duration {
	if m.TCPExt != nil {
		return m.TCPExt.DialTimeout()
	}
	return 10 * time.Second
}

// MaxConnectionDuration returns the max connection duration (0=unlimited).
func (m *MappingConfig) MaxConnectionDuration() time.Duration {
	if m.TCPExt != nil {
		return m.TCPExt.MaxConnectionDuration()
	}
	return 0
}

// SessionTimeout returns the session validity period (0=unlimited).
func (m *MappingConfig) SessionTimeout() time.Duration {
	if m.TCPExt != nil {
		return m.TCPExt.SessionTimeout()
	}
	return 0
}

// ConstraintRecheckInterval returns the periodic recheck interval for constraints (0=disabled).
func (m *MappingConfig) ConstraintRecheckInterval() time.Duration {
	if m.TCPExt != nil {
		return m.TCPExt.ConstraintRecheckInterval()
	}
	return 0
}

// RenewalEnabledOrDefault returns whether auto-renewal is enabled (default false).
func (m *MappingConfig) RenewalEnabledOrDefault() bool {
	if m.TCPExt != nil {
		return m.TCPExt.RenewalEnabledOrDefault()
	}
	return false
}

// RenewalWindow returns the renewal advance window (default 2 minutes).
func (m *MappingConfig) RenewalWindow() time.Duration {
	if m.TCPExt != nil {
		return m.TCPExt.RenewalWindow()
	}
	return 2 * time.Minute
}

// AuditMaxSize returns the max audit log file size (default 100MB).
func (m *MappingConfig) AuditMaxSize() int64 {
	return m.TLS.AuditMaxSize()
}

// AuditMaxBackupCount returns the max number of audit log backup files (default 3).
func (m *MappingConfig) AuditMaxBackupCount() int {
	return m.TLS.AuditMaxBackupCount()
}

// RequiredCapabilities returns the list of required capabilities.
func (m *MappingConfig) RequiredCapabilities() []string {
	if m.TLS != nil {
		return m.TLS.RequiredCapabilities
	}
	return nil
}

// CapabilityScheme returns the capability scheme ID.
func (m *MappingConfig) CapabilityScheme() string {
	if m.TLS != nil {
		return m.TLS.CapabilityScheme
	}
	return ""
}

// RequireUserAuthEnabled returns whether user authentication is required.
func (m *MappingConfig) RequireUserAuthEnabled() bool {
	return m.TLS.RequireUserAuthEnabled()
}

// DisallowRepresentativeEnabled returns whether the delegation proxy mode is disabled.
func (m *MappingConfig) DisallowRepresentativeEnabled() bool {
	return m.TLS.DisallowRepresentativeEnabled()
}

// CipherSuites returns the list of TLS cipher suites.
func (m *MappingConfig) CipherSuites() []string {
	if m.TLS != nil {
		return m.TLS.CipherSuites
	}
	return nil
}

// MinTLSVersion returns the minimum TLS version.
func (m *MappingConfig) MinTLSVersion() string {
	if m.TLS != nil {
		return m.TLS.MinTLSVersion
	}
	return ""
}

// ManagementConfig is the management API configuration.
type ManagementConfig struct {
	// Listen is the management API listen address.
	Listen string `json:"listen"`
	// TLS is the management API mTLS configuration.
	TLS *gw.TLSConfig `json:"tls"`
}

// MeshPeerConfig is the Mesh peer node configuration.
type MeshPeerConfig struct {
	// Name is the peer node name.
	Name string `json:"name"`
	// Addr is the peer node address.
	Addr string `json:"addr"`
	// CACertFile is the peer node CA certificate.
	CACertFile string `json:"ca_cert_file"`
	// CertFile is the client certificate.
	CertFile string `json:"cert_file"`
	// KeyFile is the client private key.
	KeyFile string `json:"key_file"`
}

// TunnelConfig is the TCP tunnel configuration.
type TunnelConfig struct {
	// Name is the tunnel name (unique identifier).
	Name string `json:"name"`
	// Listen is the tunnel listen address.
	Listen string `json:"listen"`
	// GatewayAddr is the gateway address (tunnel connection target).
	GatewayAddr string `json:"gateway_addr"`
	// CertFile is the mTLS client certificate.
	CertFile string `json:"cert_file"`
	// KeyFile is the mTLS client private key.
	KeyFile string `json:"key_file"`
	// CACertFile is the CA certificate file.
	CACertFile string `json:"ca_cert_file"`
}

// SetDefaults applies default values for unset config fields.
func (c *Config) SetDefaults() {
	if c.Mappings == nil {
		c.Mappings = []MappingConfig{}
	}
	if c.Tunnels == nil {
		c.Tunnels = []TunnelConfig{}
	}
}

// LoadConfig loads configuration from a JSON file and performs validation.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	dec := json.NewDecoder(strings.NewReader(string(data)))
	// W41 (2026-08-16): Reject unknown fields — typos (e.g. ocsp_url / max_conns)
	// were previously silently ignored, causing config to have no effect with no warning.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.configPath = path
	cfg.SetDefaults()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	for i, m := range c.Mappings {
		if m.Name == "" {
			return fmt.Errorf("mappings[%d]: name required", i)
		}
		if m.Listen == "" {
			return fmt.Errorf("mappings[%d] %q: listen required", i, m.Name)
		}
		if m.Target == "" {
			return fmt.Errorf("mappings[%d] %q: target required", i, m.Name)
		}
		// Validate protocol/tls mode
		effectiveMode := m.effectiveMode()
		if effectiveMode == "" {
			return fmt.Errorf("mappings[%d] %q: protocol required (tcp | tcp+mtls | tcp+mesh)", i, m.Name)
		}
		switch effectiveMode {
		case gw.TLSModeNone, gw.TLSModeServer, gw.TLSModeMTLS, "mesh":
		default:
			return fmt.Errorf("mappings[%d] %q: invalid tls mode %q (use protocol tcp with tls.mode server/mtls, or tcp+mtls/tcp+mesh)", i, m.Name, effectiveMode)
		}
		if effectiveMode == "mesh" && m.MeshPeerName == "" {
			return fmt.Errorf("mappings[%d] %q: mesh_peer required for mesh protocol", i, m.Name)
		}
		if effectiveMode == gw.TLSModeMTLS {
			t := m.TLS
			if t == nil {
				return fmt.Errorf("mappings[%d] %q: tls config required for tcp+mtls", i, m.Name)
			}
			if t.CACertFile == "" {
				return fmt.Errorf("mappings[%d] %q: tls.ca_cert_file required", i, m.Name)
			}
			if len(t.AllowRoles) == 0 {
				slog.Warn("mapping uses mTLS with empty allow_roles — all valid mTLS clients will be accepted", "name", m.Name)
			}
		}
	}

	for i, t := range c.Tunnels {
		if t.Name == "" {
			return fmt.Errorf("tunnels[%d]: name required", i)
		}
		if t.Listen == "" {
			return fmt.Errorf("tunnels[%d] %q: listen required", i, t.Name)
		}
		if t.GatewayAddr == "" {
			return fmt.Errorf("tunnels[%d] %q: gateway_addr required", i, t.Name)
		}
		if t.CertFile == "" {
			return fmt.Errorf("tunnels[%d] %q: cert_file required", i, t.Name)
		}
		if t.KeyFile == "" {
			return fmt.Errorf("tunnels[%d] %q: key_file required", i, t.Name)
		}
		if t.CACertFile == "" {
			return fmt.Errorf("tunnels[%d] %q: ca_cert_file required", i, t.Name)
		}
	}

	if c.Management != nil {
		if c.Management.Listen == "" {
			return errors.New("management.listen required")
		}
		if c.Management.TLS == nil {
			return errors.New("management.tls config required")
		}
		if c.Management.TLS.CACertFile == "" {
			return errors.New("management.tls.ca_cert_file required")
		}
	}

	// W01 (2026-08-16): Mesh protocol requires symmetric mTLS. Outbound DialConn always sends TLS
	// ClientHello; inbound, if MeshServerTLS lacks cert, it silently falls back to plaintext listener —
	// a valid peer's ClientHello (0x16 0x03) gets parsed as target length 5635>4096 and rejected
	// (cross-node forwarding silently fails), and plaintext listening exposes an SSRF surface. Here we
	// turn "silent corruption" into a hard config error: configuring MeshListen requires complete inbound mTLS.
	if c.MeshListen != "" {
		if c.MeshServerTLS == nil {
			return errors.New("mesh_listen requires mesh_server_tls (mesh protocol is mTLS-only)")
		}
		if c.MeshServerTLS.CertFile == "" || c.MeshServerTLS.KeyFile == "" || c.MeshServerTLS.CACertFile == "" {
			return errors.New("mesh_server_tls requires cert_file, key_file and ca_cert_file (mesh protocol is mTLS-only)")
		}
	}
	// When peers are configured, they must be complete; otherwise NewMesh silently skips that peer,
	// and mesh forwarding connections will always fail to dial with no error.
	for i, p := range c.Peers {
		if p.Name == "" || p.Addr == "" {
			return fmt.Errorf("peers[%d]: name and addr required", i)
		}
		if p.CACertFile == "" || p.CertFile == "" || p.KeyFile == "" {
			return fmt.Errorf("peers[%d] %q: ca_cert_file, cert_file and key_file required", i, p.Name)
		}
	}

	return nil
}

// --- CLI mode helpers ---

// CLIGlobals is the CLI global parameter overrides.
type CLIGlobals struct {
	// CRLRefreshSec CLI override: CRL refresh interval (seconds).
	CRLRefreshSec int
	// OCSPCacheTTLSec CLI override: OCSP cache TTL (seconds).
	OCSPCacheTTLSec int
	// OCSPFallback CLI override: OCSP degradation policy.
	OCSPFallback string
	// TSAURL CLI override: TSA service URL.
	TSAURL string
	// TSACertFile CLI override: TSA certificate file.
	TSACertFile string
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
	// MgmtOCSPFallback CLI override: management API OCSP degradation policy.
	MgmtOCSPFallback string
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

func parseInt(s string) int {
	if s == "" {
		return 0
	}
	n, _ := strconv.Atoi(s)
	return n
}

func buildMappingFromKV(kv map[string]string) MappingConfig {
	mc := MappingConfig{
		Name:     kv["name"],
		Listen:   kv["listen"],
		Target:   kv["target"],
		Protocol: kv["protocol"],
	}
	if mc.Protocol == ProtocolTCPMTLS {
		mc.TLS = &gw.TLSConfig{
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
			MaxConnsPerIP:   parseInt(kv["max-conns-per-ip"]),
			MaxTotalConns:   parseInt(kv["max-total-conns"]),
			IdleTimeoutSec:  parseInt(kv["idle-timeout-sec"]),
			AuditMaxSizeMB:  parseInt(kv["audit-max-size-mb"]),
			AuditMaxBackups: parseInt(kv["audit-max-backups"]),
			CipherSuites:    splitList(kv["cipher-suites"]),
			MinTLSVersion:   kv["min-tls-version"],
		}
		if v := kv["disconnect-on-expiry"]; v == "false" {
			f := false
			mc.TLS.DisconnectOnExpiry = &f
		}
		mc.TCPExt = &gw.TCPExtra{
			HealthCheckSec: parseInt(kv["health-check-sec"]),
			DialTimeoutSec: parseInt(kv["dial-timeout-sec"]),
			HealthCheckURL: kv["health-check-url"],
		}
	}
	return mc
}

func buildTunnelFromKV(kv map[string]string) TunnelConfig {
	return TunnelConfig{
		Name:        kv["name"],
		Listen:      kv["listen"],
		GatewayAddr: kv["gateway-addr"],
		CertFile:    kv["cert-file"],
		KeyFile:     kv["key-file"],
		CACertFile:  kv["ca-cert-file"],
	}
}

// BuildConfigFromCLI builds configuration from CLI parameters, overriding global defaults.
func BuildConfigFromCLI(maps, tunnels []string, g *CLIGlobals) (*Config, error) {
	cfg := &Config{
		Mappings: make([]MappingConfig, 0, len(maps)),
		Tunnels:  make([]TunnelConfig, 0, len(tunnels)),
	}
	for _, m := range maps {
		kv := parseKV(m)
		mc := buildMappingFromKV(kv)
		if mc.TLS != nil {
			if mc.TLS.CRLRefreshSec <= 0 {
				mc.TLS.CRLRefreshSec = g.CRLRefreshSec
			}
			if mc.TLS.OCSPCacheTTLSec <= 0 {
				mc.TLS.OCSPCacheTTLSec = g.OCSPCacheTTLSec
			}
			if mc.TLS.OCSPFallback == "" {
				mc.TLS.OCSPFallback = g.OCSPFallback
			}
			if mc.TLS.TSAURL == "" {
				mc.TLS.TSAURL = g.TSAURL
			}
			if mc.TLS.TSACertFile == "" {
				mc.TLS.TSACertFile = g.TSACertFile
			}
			if mc.TLS.AuditFile == "" {
				mc.TLS.AuditFile = g.AuditFile
			}
			if mc.TLS.AuditMaxSizeMB <= 0 {
				mc.TLS.AuditMaxSizeMB = g.AuditMaxSizeMB
			}
			if mc.TLS.AuditMaxBackups <= 0 {
				mc.TLS.AuditMaxBackups = g.AuditMaxBackups
			}
		}
		cfg.Mappings = append(cfg.Mappings, mc)
	}
	for _, t := range tunnels {
		cfg.Tunnels = append(cfg.Tunnels, buildTunnelFromKV(parseKV(t)))
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
