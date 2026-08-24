package tcpgw

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	gw "github.com/varwof/gateway-core"
)

type stringSliceFlag struct {
	values []string
}

// String returns a comma-separated string of the flag values.
func (s *stringSliceFlag) String() string {
	return strings.Join(s.values, ",")
}

// Set appends a flag value.
func (s *stringSliceFlag) Set(value string) error {
	s.values = append(s.values, value)
	return nil
}

func RunCLI() {
	if len(os.Args) < 2 {
		serverUsage()
		return
	}

	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "tunnel":
		runTunnel(os.Args[2:])
	case "audit":
		runAudit(os.Args[2:])
	case "--version", "-v", "version":
		fmt.Println(VersionString())
	case "--help", "-h", "help":
		topUsage()
	default:
		runServer(os.Args[1:])
	}
}

func topUsage() {
	fmt.Printf(`gateway-tcp — zero-trust TCP security gateway

Usage:
  gateway-tcp [--config <file> | --map <kv>...] [flags]
  gateway-tcp tunnel [--config <file> | --tunnel <kv>...] [flags]
  gateway-tcp audit --entry <file> [--tsa-url <url>]

Default subcommand is "server".

Use "gateway-tcp server --help" for server flags.
Use "gateway-tcp tunnel --help" for tunnel flags.
Use "gateway-tcp audit --help" for audit flags.

Examples:
  gateway-tcp --config %[1]s
  gateway-tcp --map name=web,listen=:8443,target=web:8080,protocol=tcp+mtls,ca-cert=ca.pem
  gateway-tcp tunnel --config %[1]s
  gateway-tcp audit --entry audit-line.json --tsa-url http://tsa:3180/tsa
`, DefaultConfigFile())
}

func serverUsage() {
	fmt.Printf(`gateway-tcp server [flags]

Flags:
  -c, --config <file>       server config file (JSON) (default: %[1]s)
  -l, --lang <lang>         language (zh/en)
  -m, --map <kv>            mapping definition (key=value,key=value...) — repeatable
  -t, --tunnel <kv>         tunnel definition (key=value,key=value...) — repeatable
      --crl-refresh-sec <n>   global CRL refresh interval in seconds (default: 300)
      --ocsp-cache-ttl-sec <n> global OCSP cache TTL in seconds (default: 300)
      --ocsp-fallback <s>     global OCSP fallback policy (allow|deny|crl) (default: allow)
      --tsa-url <url>         TSA server URL
      --tsa-cert-file <path>  TSA certificate file
      --audit-file <path>     audit log file path
      --audit-max-size-mb <n> audit max size in MB (default: 100)
      --audit-max-backups <n> audit max backup count (default: 3)
      --management-listen <addr> management API listen address
      --mgmt-ca-cert <path>   management API CA cert file
      --mgmt-cert <path>      management API server cert file
      --mgmt-key <path>       management API server key file
      --mgmt-crl-url <url>    management API CRL URL
      --mgmt-ocsp-fallback <s> management API OCSP fallback (default: allow)

Map key=value format:
  name=<name>,listen=<addr>,target=<addr>,
  protocol=<tcp|tcp+mtls|tcp+mesh>,
  ca-cert=<path>,cert=<path>,key=<path>,
  allow-roles=<role>[;<role>...],
  crl-url=<url>,crl-refresh-sec=<n>,
  ocsp-cache-ttl-sec=<n>,ocsp-fallback=<s>,
  tsa-url=<url>,audit-file=<path>,
  max-conns-per-ip=<n>,max-total-conns=<n>,
  idle-timeout-sec=<n>,health-check-sec=<n>,
  health-check-url=<url>,disconnect-on-expiry=<bool>,
  cipher-suites=<suite>[;<suite>...],min-tls-version=<ver>,
  audit-max-size-mb=<n>,audit-max-backups=<n>

Examples:
  gateway-tcp server --config %[1]s
  gateway-tcp -m name=web,listen=:8443,target=web:8080,protocol=tcp+mtls,ca-cert=ca.pem
  gateway-tcp -m name=web,... -m name=api,... --tsa-url http://tsa:3180/tsa
`, DefaultConfigFile())
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	cfgDefault := DefaultConfigFile()

	configPath := fs.String("config", "", "server config file (JSON)")
	fs.StringVar(configPath, "c", "", "shorthand for --config")

	langFlag := fs.String("lang", "", "language (zh/en)")
	fs.StringVar(langFlag, "l", "", "shorthand for --lang")

	maps := &stringSliceFlag{}
	fs.Var(maps, "listener", "mapping definition (key=value,...) — repeatable, alias for --map")
	fs.Var(maps, "map", "mapping definition (key=value,...) — repeatable")
	fs.Var(maps, "m", "shorthand for --map")
	fs.Var(maps, "L", "shorthand for --listener")

	tunnels := &stringSliceFlag{}
	fs.Var(tunnels, "tunnel", "tunnel definition (key=value,...) — repeatable")
	fs.Var(tunnels, "t", "shorthand for --tunnel")

	crlRefreshSec := fs.Int("crl-refresh-sec", 300, "global CRL refresh interval (seconds)")
	ocspCacheTTL := fs.Int("ocsp-cache-ttl-sec", 300, "global OCSP cache TTL (seconds)")
	ocspFallback := fs.String("ocsp-fallback", "allow", "global OCSP fallback (allow|deny|crl)")
	tsaURL := fs.String("tsa-url", "", "TSA server URL")
	tsaCertFile := fs.String("tsa-cert-file", "", "TSA certificate file")
	auditFile := fs.String("audit-file", "", "audit log file path")
	auditMaxSizeMB := fs.Int("audit-max-size-mb", 100, "audit max size (MB)")
	auditMaxBackups := fs.Int("audit-max-backups", 3, "audit max backup count")
	mgmtListen := fs.String("management-listen", "", "management API listen address")
	mgmtCACert := fs.String("mgmt-ca-cert", "", "management CA cert file")
	mgmtCert := fs.String("mgmt-cert", "", "management server cert file")
	mgmtKey := fs.String("mgmt-key", "", "management server key file")
	mgmtCRLURL := fs.String("mgmt-crl-url", "", "management CRL URL")
	mgmtOCSPFallback := fs.String("mgmt-ocsp-fallback", "allow", "management OCSP fallback")

	fs.Usage = func() {
		serverUsage()
	}
	fs.Parse(args)

	bundle := NewBundle()
	lang := DetectLang(*langFlag, "", os.Getenv("LANG"))
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	hasConfig := *configPath != ""
	hasCLI := len(maps.values) > 0 || len(tunnels.values) > 0

	if hasConfig && hasCLI {
		logger.Error("config and map are mutually exclusive")
		os.Exit(1)
	}

	var cfg *Config
	var err error

	if hasCLI {
		cfg, err = BuildConfigFromCLI(maps.values, tunnels.values, &CLIGlobals{
			CRLRefreshSec:   *crlRefreshSec,
			OCSPCacheTTLSec: *ocspCacheTTL,
			OCSPFallback:    *ocspFallback,
			TSAURL:          *tsaURL,
			TSACertFile:     *tsaCertFile,
			AuditFile:       *auditFile,
			AuditMaxSizeMB:  *auditMaxSizeMB,
			AuditMaxBackups: *auditMaxBackups,
			MgmtListen:      *mgmtListen,
			MgmtCACert:      *mgmtCACert,
			MgmtCert:        *mgmtCert,
			MgmtKey:         *mgmtKey,
			MgmtCRLURL:      *mgmtCRLURL,
			MgmtOCSPFallback: *mgmtOCSPFallback,
		})
		if err != nil {
			logger.Error("failed to build config from CLI", "error", err)
			os.Exit(1)
		}
		startGateway(cfg, bundle, lang, logger)
		return
	}

	if *configPath == "" {
		*configPath = cfgDefault
	}
	if _, err := os.Stat(*configPath); err != nil {
		logger.Error(bundle.T(lang, "err.config_not_found"), "path", *configPath)
		logger.Error(bundle.T(lang, "cli.help_config"))
		os.Exit(1)
	}

	cfg, err = LoadConfig(*configPath)
	if err != nil {
		logger.Error(bundle.T(lang, "err.load_config"), "error", err)
		os.Exit(1)
	}
	startGateway(cfg, bundle, lang, logger)
}

func startGateway(cfg *Config, bundle *Bundle, lang string, logger *slog.Logger) {
	var err error
	var tsaClient *gw.TSAClient
	var auditLogger *gw.AuditLogger

	for _, m := range cfg.Mappings {
		if m.TLS == nil {
			continue
		}
		if m.TLS.TSAURL != "" && tsaClient == nil {
			tsaClient = gw.NewTSAClient(m.TLS.TSAURL)
			if tsaClient != nil && m.TLS.TSACertFile != "" {
				if err := tsaClient.SetCACert(m.TLS.TSACertFile); err != nil {
					logger.Warn("load TSA CA cert", "error", err)
				}
			}
		}
		if m.TLS.AuditFile != "" && auditLogger == nil {
			if err := gw.ArchiveAuditFile(m.TLS.AuditFile); err != nil {
				logger.Warn("archive audit file", "error", err)
			}
			auditLogger, err = gw.NewAuditLogger(
				m.TLS.AuditFile, tsaClient,
				m.AuditMaxSize(), m.AuditMaxBackupCount(),
			)
			if err != nil {
				logger.Error(bundle.T(lang, "err.load_config"), "error", err)
				os.Exit(1)
			}
		}
	}

	var tsaProofLogger *gw.TSAProofLogger
	if cfg.TSAProofFile != "" && tsaClient != nil {
		tsaProofLogger = gw.NewTSAProofLogger(cfg.TSAProofFile, tsaClient, nil, cfg.TSAProofIntervalSec)
	}

	var shortResult *gw.AutoIssueResult
	if cfg.ShortLived != nil {
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "unknown"
		}
		cn := "gateway-tcp-" + hostname
		shortResult, err = gw.AutoIssueCert(cfg.ShortLived, cn, "")
		if err != nil {
			logger.Error("auto-issue cert", "error", err)
			os.Exit(1)
		}
		logger.Info("short-lived cert issued", "cn", shortResult.CN, "serial", shortResult.Result.SerialNumber)

		for i := range cfg.Mappings {
			if cfg.Mappings[i].TLS != nil {
				cfg.Mappings[i].TLS.CertFile = shortResult.CertFile
				cfg.Mappings[i].TLS.KeyFile = shortResult.KeyFile
			}
		}
		for i := range cfg.Tunnels {
			cfg.Tunnels[i].CertFile = shortResult.CertFile
			cfg.Tunnels[i].KeyFile = shortResult.KeyFile
		}
		if cfg.Management != nil && cfg.Management.TLS != nil {
			cfg.Management.TLS.CertFile = shortResult.CertFile
			cfg.Management.TLS.KeyFile = shortResult.KeyFile
		}
	}

	g := NewGateway(cfg, bundle, lang, auditLogger, tsaClient, tsaProofLogger, logger)
	if err := g.Start(); err != nil {
		logger.Error(bundle.T(lang, "err.load_config"), "error", err)
		if auditLogger != nil {
			auditLogger.Close()
		}
		os.Exit(1)
	}

	logger.Info(bundle.T(lang, "gateway.started"))

	if shortResult != nil {
		issueCfg := *cfg.ShortLived
		certFile := shortResult.CertFile
		keyFile := shortResult.KeyFile
		go func() {
			ticker := time.NewTicker(issueCfg.RenewalInterval())
			defer ticker.Stop()
			for {
				select {
				case <-g.renewalCh:
					return
				case <-ticker.C:
					tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
					if err != nil || tlsCert.Leaf == nil {
						continue
					}
					if !gw.NeedRenewPct(tlsCert.Leaf, 0) {
						continue
					}
					client, err := gw.NewIssueClient(issueCfg)
					if err != nil {
						continue
					}
					result, err := client.Issue(&gw.IssueRequest{
						CA:       issueCfg.DefaultCA,
						CN:       shortResult.CN,
						Validity: 10,
						Profile:  "tls-server",
					})
					if err != nil {
						continue
					}
					os.WriteFile(certFile, []byte(result.CertPEM), 0644)
					os.WriteFile(keyFile, []byte(result.KeyPEM), 0600)
					newCert, err := tls.X509KeyPair([]byte(result.CertPEM), []byte(result.KeyPEM))
					if err != nil {
						continue
					}
					g.UpdateServerCert(&newCert)
					logger.Info("short-lived cert renewed", "serial", result.SerialNumber)
				}
			}
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	gw.RegisterReloadSignal(sigCh)

	for {
		sig := <-sigCh
		if gw.IsReloadSignal(sig) {
			logger.Info(bundle.T(lang, "gateway.reloading"))
			if err := g.Reload(); err != nil {
				logger.Error(bundle.T(lang, "err.reload"), "error", err)
			}
			continue
		}
		break
	}

	logger.Info(bundle.T(lang, "gateway.shutting_down"))
	g.Stop()
	if auditLogger != nil {
		auditLogger.Close()
	}
}

func runTunnel(args []string) {
	fs := flag.NewFlagSet("tunnel", flag.ExitOnError)
	cfgDefault := DefaultConfigFile()

	configPath := fs.String("config", "", "tunnel config file (JSON)")
	fs.StringVar(configPath, "c", "", "shorthand for --config")

	langFlag := fs.String("lang", "", "language (zh/en)")
	fs.StringVar(langFlag, "l", "", "shorthand for --lang")

	maps := &stringSliceFlag{}
	fs.Var(maps, "map", "tunnel definition (key=value,...) — repeatable")
	fs.Var(maps, "m", "shorthand for --map")

	fs.Parse(args)

	bundle := NewBundle()
	lang := DetectLang(*langFlag, "", os.Getenv("LANG"))
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	hasConfig := *configPath != ""
	hasCLI := len(maps.values) > 0

	if hasConfig && hasCLI {
		logger.Error("config and map are mutually exclusive")
		os.Exit(1)
	}

	var cfg *Config
	var err error

	if hasCLI {
		cfg, err = BuildConfigFromCLI(nil, maps.values, &CLIGlobals{})
		if err != nil {
			logger.Error("failed to build config from CLI", "error", err)
			os.Exit(1)
		}
	} else {
		if *configPath == "" {
			*configPath = cfgDefault
		}
		if _, err := os.Stat(*configPath); err != nil {
			logger.Error(bundle.T(lang, "err.config_not_found"), "path", *configPath)
			logger.Error(bundle.T(lang, "cli.help_config"))
			os.Exit(1)
		}
		cfg, err = LoadConfig(*configPath)
		if err != nil {
			logger.Error(bundle.T(lang, "err.load_config"), "error", err)
			os.Exit(1)
		}
	}

	tsaClient := gw.NewTSAClient("")
	gw := NewGateway(cfg, bundle, lang, nil, tsaClient, nil, logger)
	if err := gw.Start(); err != nil {
		logger.Error(bundle.T(lang, "err.load_config"), "error", err)
		os.Exit(1)
	}

	logger.Info(bundle.T(lang, "tunnel.started"))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Info(bundle.T(lang, "gateway.shutting_down"))
	gw.Stop()
}

func runAudit(args []string) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	entryFile := fs.String("entry", "", "audit entry JSON file to verify")
	tsaURL := fs.String("tsa-url", "", "TSA server URL")
	langFlag := fs.String("lang", "", "language (zh/en)")
	fs.StringVar(langFlag, "l", "", "shorthand for --lang")

	fs.Parse(args)

	bundle := NewBundle()
	lang := DetectLang(*langFlag, "", os.Getenv("LANG"))
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *entryFile == "" {
		logger.Error(bundle.T(lang, "err.entry_required"))
		os.Exit(1)
	}

	data, err := os.ReadFile(*entryFile)
	if err != nil {
		logger.Error(bundle.T(lang, "err.load_config"), "error", err)
		os.Exit(1)
	}

	if *tsaURL != "" {
		tsaClient := gw.NewTSAClient(*tsaURL)
		if err := gw.VerifyAuditEntry(data, tsaClient); err != nil {
			logger.Error(bundle.T(lang, "err.verify_failed"), "error", err)
			os.Exit(1)
		}
	} else {
		if err := gw.VerifyAuditEntry(data, nil); err != nil {
			logger.Error(bundle.T(lang, "err.verify_failed"), "error", err)
			os.Exit(1)
		}
	}

	logger.Info(bundle.T(lang, "audit.entry_verified"))
}
