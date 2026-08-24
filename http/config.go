package httpgw

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"strconv"
	"strings"

	gw "github.com/varwof/gateway-core"
)

// Protocol values for ListenerConfig.Protocol (transport + application semantics).
// These replace the legacy tls_mode field which mixed transport and TLS semantics;
// the TLS authentication mode is carried by the TLS block's Mode field.
const (
	// ProtocolHTTP1 is HTTP/1.1.
	ProtocolHTTP1 = gw.ProtocolHTTP1
	// ProtocolHTTP2 is HTTP/2 (TLS).
	ProtocolHTTP2 = gw.ProtocolHTTP2
	// ProtocolH2C is HTTP/2 cleartext (no TLS).
	ProtocolH2C = gw.ProtocolH2C
	// ProtocolGRPC is gRPC (HTTP/2 + protobuf).
	ProtocolGRPC = gw.ProtocolGRPC
	// ProtocolWS is WebSocket (HTTP upgrade).
	ProtocolWS = gw.ProtocolWS
	// ProtocolWSS is WebSocket over TLS.
	ProtocolWSS = gw.ProtocolWSS
	// ProtocolH3 is HTTP/3 (QUIC transport, built-in TLS 1.3).
	ProtocolH3 = gw.ProtocolH3
	// ProtocolQUIC is the QUIC raw stream tunnel mode (TLS 1.3).
	ProtocolQUIC = gw.ProtocolQUIC
)

// Config is the HTTP gateway main configuration.
type Config struct {
	// Locale is the internationalization language code (zh/en).
	Locale string `json:"locale,omitempty"`
	// Listeners is the HTTP listener configuration list.
	Listeners []ListenerConfig `json:"listeners"`
	// Management is the management API configuration.
	Management *MgmtConfig `json:"management,omitempty"`
	// TSAProofFile is the TSA audit proof output file path.
	TSAProofFile string `json:"tsa_proof_file,omitempty"`
	// TSAProofIntervalSec is the TSA audit proof generation interval in seconds.
	TSAProofIntervalSec int `json:"tsa_proof_interval_sec,omitempty"`
	// VarwofCore is the Varwof Core service connection configuration.
	VarwofCore *gw.RevokerConfig `json:"varwof_core,omitempty"`
	// ShortLived is the short-lived certificate auto-issuance configuration.
	ShortLived *gw.IssueConfig `json:"short_lived,omitempty"`
	// CapabilityPlugins is the capability plugin configuration (JSON).
	CapabilityPlugins gw.PluginConfigs `json:"capability_plugins,omitempty"`
	// CapabilityFile is the capability engine configuration file path.
	CapabilityFile string `json:"capability_file,omitempty"`
	// AuthorizationFile is the authorization policy file path (authz.json).
	AuthorizationFile string `json:"authorization_file,omitempty"`
	// RuleSchemes is the published rule directory (register ruleexec
	// publisher output: <dir>/<scheme>/default.json + .p7s). When set,
	// signed rules are loaded as capability plugins at startup and on
	// reload (same opt-in style as capability_schemes).
	RuleSchemes string `json:"rule_schemes,omitempty"`
	// RuleSignerCert is the trust anchor PEM (certificate chain) for
	// rule PKCS#7 signatures. Required when RuleSchemes is set.
	RuleSignerCert string `json:"rule_signer_cert,omitempty"`
	// CapabilitySchemes is the capability registry directory path (register spec).
	// Empty uses the embedded scheme; specified directory enables disk override (modifying JSON
	// hot-updates the policy). Once enabled, data plane verification requires AIC-declared
	// capabilities to be registered.
	CapabilitySchemes string `json:"capability_schemes,omitempty"`
	// PolicySigning is the authorization policy file signature verification configuration.
	PolicySigning *gw.PolicySigningConfig `json:"policy_signing,omitempty"`
	// AuditIndexFile is the audit FTS index file path. When set, enables the
	// GET /api/v1/gateway/audit/search full-text search endpoint.
	AuditIndexFile string `json:"audit_index_file,omitempty"`
	// RiskMonitor is the high-risk agent automatic remediation rules. When set, enables the
	// "behavioral violation -> disconnect + revoke" reactive closed-loop.
	RiskMonitor *gw.RiskMonitorConfig `json:"risk_monitor,omitempty"`
	// ChainPeers is the cross-gateway audit chain reference peer endpoints. Each entry is a
	// peer gateway's management API base URL (e.g. https://gw2:9443). The gateway periodically
	// fetches the peer's GET /api/v1/gateway/audit/chain chain head and writes it to the local
	// ChainRefStore, forming a cross-gateway audit evidence DAG (consensus-free ordering).
	ChainPeers []gw.ChainPeerConfig `json:"chain_peers,omitempty"`
	configPath string
}

// ListenerConfig defines a single HTTP listener.
type ListenerConfig struct {
	// Name is the listener name (unique identifier).
	Name string `json:"name"`
	// Listen is the listen address (e.g. :8443).
	Listen string `json:"listen"`

	// Protocol is the transport+application protocol: http1, http2, h2c, grpc, ws, wss, h3, quic.
	Protocol string `json:"protocol,omitempty"`
	// TLS is the unified TLS configuration block. The Mode field selects the
	// authentication mode (none / server / mtls); TLS is required for h3/quic
	// (cert_file) and for mtls listeners (ca_cert_file).
	TLS *gw.TLSConfig `json:"tls,omitempty"`
	// HTTPExt holds HTTP-specific extension fields (timeouts, client cert forwarding, etc.).
	HTTPExt *gw.HTTPExtra `json:"http_ext,omitempty"`

	// Routes is the routing rule list.
	Routes []RouteConfig `json:"routes"`
}

// effectiveMode maps the protocol (+ optional TLS block) to the concrete TLS
// authentication mode driving the data plane: none / server / mtls.
// Returns "" for unknown protocols (rejected by validate).
func (l ListenerConfig) effectiveMode() string {
	mode := ""
	if l.TLS != nil {
		mode = l.TLS.Mode
	}
	switch l.Protocol {
	case ProtocolH3, ProtocolQUIC:
		// QUIC/H3 transport always runs TLS 1.3; derive the auth mode from the TLS block.
		if mode == "" {
			if l.TLS != nil && l.TLS.CACertFile != "" {
				return gw.TLSModeMTLS
			}
			return gw.TLSModeServer
		}
		return mode
	case ProtocolHTTP2, ProtocolGRPC, ProtocolWSS, ProtocolHTTP1, ProtocolH2C, ProtocolWS:
		// TLS-capable protocols: TLS only when the TLS block explicitly sets a mode.
		if mode == "" {
			return gw.TLSModeNone
		}
		return mode
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

// RouteConfig defines a single HTTP routing rule.
type RouteConfig struct {
	// Path is the URL path prefix, supports * and ** wildcards.
	Path string `json:"path"`
	// Target is the backend target address (http:// / https:// / unix:).
	Target string `json:"target"`
	// AllowMethods is the list of allowed HTTP methods.
	AllowMethods []string `json:"allow_methods,omitempty"`
	// AllowRoles is the list of allowed roles.
	AllowRoles []string `json:"allow_roles,omitempty"`
	// BackendProtocol is the backend protocol: h1 (HTTP/1.1) / h2c (HTTP/2 cleartext).
	BackendProtocol string `json:"backend_protocol,omitempty"`
	// RequiredCapabilities is the list of capabilities the client must have.
	RequiredCapabilities []string `json:"required_capabilities,omitempty"`
	// CapabilityScheme is the capability scheme ID.
	CapabilityScheme string `json:"capability_scheme,omitempty"`
	// CapabilityPrefix is the capability ID prefix match.
	CapabilityPrefix string `json:"capability_prefix,omitempty"`
	// UpstreamTLS is the backend reverse-connect mTLS configuration (W18). When set, HTTPS backends
	// use a custom CA to verify the peer and carry the gateway client certificate (mutual authentication),
	// no longer validating against system roots.
	UpstreamTLS *UpstreamTLSConfig `json:"upstream_tls,omitempty"`
}

// UpstreamTLSConfig is the backend reverse-connect TLS/mTLS configuration (W18: documented as upstream_mtls).
type UpstreamTLSConfig struct {
	// CACertFile is the backend CA certificate file path. Leave empty to validate against system roots (when only a certificate is needed).
	CACertFile string `json:"ca_cert_file,omitempty"`
	// CertFile is the gateway-side client certificate file path (when the backend requires mutual authentication).
	CertFile string `json:"cert_file,omitempty"`
	// KeyFile is the gateway-side client private key file path.
	KeyFile string `json:"key_file,omitempty"`
	// ServerName overrides SNI/host verification. Leave empty to use the target host.
	ServerName string `json:"server_name,omitempty"`
	// InsecureSkipVerify when set to true skips backend certificate verification
	// (testing/self-signed intranet only, should not be enabled in production).
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
}

const (
	// BackendProtoH1 is the HTTP/1.1 backend protocol.
	BackendProtoH1 = "h1"
	// BackendProtoH2 is the HTTP/2 backend protocol.
	BackendProtoH2 = "h2"
	// BackendProtoH2C is the HTTP/2 cleartext backend protocol.
	BackendProtoH2C = "h2c"
)

// MgmtConfig is the management API configuration.
type MgmtConfig struct {
	// Listen is the management API listen address.
	Listen string `json:"listen"`
	// TLS is the management API mTLS configuration.
	TLS *gw.TLSConfig `json:"tls"`
}

// SetDefaults applies default values for unset config fields.
func (c *Config) SetDefaults() {
	if c.Listeners == nil {
		c.Listeners = []ListenerConfig{}
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
	// W41 (2026-08-16): Reject unknown fields -- typos were previously silently ignored.
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

// Save persists the configuration to a JSON file.
func (c *Config) Save() error {
	if c.configPath == "" {
		rnd, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
		c.configPath = fmt.Sprintf("/tmp/gateway-http-%d-%x.json", os.Getpid(), rnd.Uint64())
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(c.configPath, data, 0600)
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
		case ProtocolHTTP1, ProtocolHTTP2, ProtocolH2C, ProtocolGRPC, ProtocolWS, ProtocolWSS, ProtocolH3, ProtocolQUIC:
		case "":
			return fmt.Errorf("listeners[%d] %q: protocol required", i, l.Name)
		default:
			return fmt.Errorf("listeners[%d] %q: invalid protocol %q", i, l.Name, l.Protocol)
		}
		mode := l.effectiveMode()
		switch mode {
		case gw.TLSModeNone, gw.TLSModeServer, gw.TLSModeMTLS:
		default:
			return fmt.Errorf("listeners[%d] %q: invalid tls mode %q", i, l.Name, mode)
		}
		switch mode {
		case gw.TLSModeMTLS:
			t := l.TLS
			if t == nil || t.CACertFile == "" {
				return fmt.Errorf("listeners[%d] %q: tls.ca_cert_file required", i, l.Name)
			}
			for _, r := range l.Routes {
				if len(r.AllowRoles) == 0 {
					slog.Warn("listener route uses mTLS with empty allow_roles", "listener", l.Name, "path", r.Path)
				}
			}
		case gw.TLSModeServer:
			// Server mode requires cert_file/key_file; enforced at Start so that
			// per-listener TLS setup surfaces the exact error.
		}
		if l.Protocol == ProtocolH3 || l.Protocol == ProtocolQUIC {
			t := l.TLS
			if t == nil || t.CertFile == "" {
				return fmt.Errorf("listeners[%d] %q: cert_file required for %s protocol", i, l.Name, l.Protocol)
			}
			if t == nil || t.CACertFile == "" {
				return fmt.Errorf("listeners[%d] %q: ca_cert_file required for %s protocol (mTLS mandatory)", i, l.Name, l.Protocol)
			}
		}
		if len(l.Routes) == 0 {
			return fmt.Errorf("listeners[%d] %q: at least one route required", i, l.Name)
		}
		for j, r := range l.Routes {
			if r.Path == "" {
				return fmt.Errorf("listeners[%d].routes[%d]: path required", i, j)
			}
			if r.Target == "" {
				return fmt.Errorf("listeners[%d].routes[%d]: target required", i, j)
			}
		}
	}

	if c.Management != nil {
		if c.Management.Listen == "" {
			return errors.New("management.listen required")
		}
		if c.Management.TLS == nil || c.Management.TLS.CACertFile == "" {
			return errors.New("management.tls.ca_cert_file required")
		}
	}

	return nil
}

// --- CLI mode helpers ---

// CLIGlobals is the CLI global parameter overrides.
type CLIGlobals struct {
	// CRLRefreshSec CLI override: CRL refresh interval in seconds.
	CRLRefreshSec int
	// OCSPCacheTTLSec CLI override: OCSP cache TTL in seconds.
	OCSPCacheTTLSec int
	// OCSPFallback CLI override: OCSP fallback policy.
	OCSPFallback string
	// TSAURL CLI override: TSA service URL.
	TSAURL string
	// TSACertFile CLI override: TSA certificate file.
	TSACertFile string
	// AuditFile CLI override: audit log file.
	AuditFile string
	// AuditMaxSizeMB CLI override: audit log file size in MB.
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

func buildListenerFromKV(kv map[string]string) ListenerConfig {
	lc := ListenerConfig{
		Name:     kv["name"],
		Listen:   kv["listen"],
		Protocol: kv["protocol"],
	}
	if lc.Protocol == "" {
		lc.Protocol = ProtocolHTTP2
	}
	mode := kv["tls-mode"]
	if mode == "" {
		if t := kv["tls"]; t != "" {
			mode = t
		}
	}
	if mode != "" && mode != gw.TLSModeNone && mode != "plain" {
		lc.TLS = &gw.TLSConfig{
			Mode:            mode,
			CACertFile:      kv["ca-cert"],
			CertFile:        kv["cert"],
			KeyFile:         kv["key"],
			CRLURL:          kv["crl-url"],
			CRLRefreshSec:   parseInt(kv["crl-refresh-sec"]),
			OCSPCacheTTLSec: parseInt(kv["ocsp-cache-ttl-sec"]),
			OCSPFallback:    kv["ocsp-fallback"],
			TSAURL:          kv["tsa-url"],
			TSACertFile:     kv["tsa-cert-file"],
			AuditFile:       kv["audit-file"],
			MaxConnsPerIP:   parseInt(kv["max-conns-per-ip"]),
			MaxConnsPerCert: parseInt(kv["max-conns-per-cert"]),
			MaxTotalConns:   parseInt(kv["max-total-conns"]),
			IdleTimeoutSec:  parseInt(kv["idle-timeout-sec"]),
			AuditMaxSizeMB:  parseInt(kv["audit-max-size-mb"]),
			AuditMaxBackups: parseInt(kv["audit-max-backups"]),
			CipherSuites:    splitList(kv["cipher-suites"]),
			MinTLSVersion:   kv["min-tls-version"],
		}
		if v := kv["disconnect-on-expiry"]; v == "false" {
			f := false
			lc.TLS.DisconnectOnExpiry = &f
		}
		if v := kv["require-aic"]; v == "true" {
			b := true
			lc.TLS.RequireAIC = &b
		}
	}
	lc.HTTPExt = &gw.HTTPExtra{
		ReadHeaderTimeoutSec: parseInt(kv["read-header-timeout-sec"]),
		WriteTimeoutSec:      parseInt(kv["write-timeout-sec"]),
	}
	if v := kv["forward-client-cert"]; v == "false" {
		f := false
		lc.HTTPExt.ForwardClientCert = &f
	}
	if v := kv["forward-client-cert-der"]; v == "true" {
		f := true
		lc.HTTPExt.ForwardClientCertDER = &f
	}
	if v := kv["tls-termination"]; v == "false" {
		f := false
		lc.HTTPExt.TLSTermination = &f
	}
	return lc
}

// BuildConfigFromCLI builds configuration from CLI parameters, overriding global defaults.
func BuildConfigFromCLI(listeners, routes []string, g *CLIGlobals) (*Config, error) {
	cfg := &Config{
		Listeners: make([]ListenerConfig, 0, len(listeners)),
	}
	listenerIdx := make(map[string]int)

	for _, l := range listeners {
		kv := parseKV(l)
		lc := buildListenerFromKV(kv)
		if lc.TLS != nil {
			if lc.TLS.CRLRefreshSec <= 0 {
				lc.TLS.CRLRefreshSec = g.CRLRefreshSec
			}
			if lc.TLS.OCSPCacheTTLSec <= 0 {
				lc.TLS.OCSPCacheTTLSec = g.OCSPCacheTTLSec
			}
			if lc.TLS.OCSPFallback == "" {
				lc.TLS.OCSPFallback = g.OCSPFallback
			}
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
		}
		listenerIdx[lc.Name] = len(cfg.Listeners)
		cfg.Listeners = append(cfg.Listeners, lc)
	}

	for _, r := range routes {
		kv := parseKV(r)
		rc := RouteConfig{
			Path:       kv["path"],
			Target:     kv["target"],
			AllowRoles: splitList(kv["allow-roles"]),
		}
		ln := kv["listener"]
		idx, ok := listenerIdx[ln]
		if !ok {
			return nil, fmt.Errorf("route references unknown listener %q", ln)
		}
		cfg.Listeners[idx].Routes = append(cfg.Listeners[idx].Routes, rc)
	}

	if g.MgmtListen != "" {
		cfg.Management = &MgmtConfig{
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
