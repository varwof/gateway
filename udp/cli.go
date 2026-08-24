package udpgw

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

// String returns a comma-separated flag value string.
func (s *stringSliceFlag) String() string {
	return strings.Join(s.values, ",")
}

// Set appends a flag value.
func (s *stringSliceFlag) Set(value string) error {
	s.values = append(s.values, value)
	return nil
}

func usage() {
	fmt.Printf(`gateway-udp — zero-trust UDP/DTLS/QUIC security gateway

Usage:
  gateway-udp [--config <file> | --listener <kv>...] [flags]

Flags:
  -c, --config <file>          config file path (JSON)
  -l, --lang <lang>            language (zh/en)
  -L, --listener <kv>          listener definition (key=value,...) — repeatable
      --tsa-url <url>          TSA server URL
      --tsa-cert-file <path>   TSA certificate file
      --tsa-proof-file <path>  TSA proof log file
      --tsa-proof-interval-sec <n> TSA proof interval in seconds
      --audit-file <path>      audit log file
      --audit-max-size-mb <n>  audit max size in MB (default: 100)
      --audit-max-backups <n>  audit max backup count (default: 3)
      --management-listen <addr> management API listen address
      --mgmt-ca-cert <path>    management API CA cert
      --mgmt-cert <path>       management API server cert
      --mgmt-key <path>        management API server key
      --mgmt-crl-url <url>     management API CRL URL
      --mgmt-ocsp-fallback <s> management API OCSP fallback (allow/deny)
      --crl-refresh-sec <n>    CRL refresh interval in seconds (default: 300)
      --ocsp-cache-ttl-sec <n> OCSP cache TTL in seconds (default: 300)
      --ocsp-fallback <s>      OCSP fallback policy (allow/deny)

Listener key=value format:
  name=<name>,listen=<addr>,protocol=<udp|dtls|udp+mtls|quic>,
  ca-cert=<path>,cert=<path>,key=<path>,
  routes=<target>[;<target>...],
  allow-roles=<role>[;<role>...],
  crl-url=<url>,crl-refresh-sec=<n>,
  ocsp-cache-ttl-sec=<n>,ocsp-fallback=<s>,
  tsa-url=<url>,audit-file=<path>,
  max-pkts-per-ip=<n>,max-conns-per-cert=<n>,
  max-total-pkts=<n>,idle-timeout-sec=<n>,
  max-packet-size=<n>,read-timeout-sec=<n>,
  disconnect-on-expiry=<n>,cipher-suites=<s>[;<s>...],
  min-tls-version=<s>

Examples:
  gateway-udp --config %[1]s
  gateway-udp -L name=dns,listen=:5353,protocol=dtls,cert=/etc/cert.pem,key=/etc/key.pem,routes=8.8.8.8:53
  gateway-udp -L name=quic,listen=:4433,protocol=quic,cert=/etc/cert.pem,key=/etc/key.pem
`, DefaultConfigFile())
}

func RunCLI() {
	configPath := flag.String("config", "", "config file path")
	flag.StringVar(configPath, "c", "", "shorthand for --config")

	langFlag := flag.String("lang", "", "language (zh/en)")
	flag.StringVar(langFlag, "l", "", "shorthand for --lang")

	listeners := &stringSliceFlag{}
	flag.Var(listeners, "listener", "listener definition (key=value,...) — repeatable")
	flag.Var(listeners, "L", "shorthand for --listener")

	tsaURL := flag.String("tsa-url", "", "TSA server URL")
	tsaCertFile := flag.String("tsa-cert-file", "", "TSA certificate file")
	tsaProofFile := flag.String("tsa-proof-file", "", "TSA proof log file")
	tsaProofIntervalSec := flag.Int("tsa-proof-interval-sec", 0, "TSA proof interval in seconds")
	auditFile := flag.String("audit-file", "", "audit log file")
	auditMaxSizeMB := flag.Int("audit-max-size-mb", 100, "audit max size (MB)")
	auditMaxBackups := flag.Int("audit-max-backups", 3, "audit max backup count")
	mgmtListen := flag.String("management-listen", "", "management API listen address")
	mgmtCACert := flag.String("mgmt-ca-cert", "", "management CA cert")
	mgmtCert := flag.String("mgmt-cert", "", "management server cert")
	mgmtKey := flag.String("mgmt-key", "", "management server key")
	mgmtCRLURL := flag.String("mgmt-crl-url", "", "management API CRL URL")
	mgmtOCSPFallback := flag.String("mgmt-ocsp-fallback", "", "management API OCSP fallback (allow/deny)")
	crlRefreshSec := flag.Int("crl-refresh-sec", 300, "CRL refresh interval in seconds (default: 300)")
	ocspCacheTTLSec := flag.Int("ocsp-cache-ttl-sec", 300, "OCSP cache TTL in seconds (default: 300)")
	ocspFallback := flag.String("ocsp-fallback", "", "OCSP fallback policy (allow/deny)")
	showVersion := flag.Bool("version", false, "show version")
	flag.BoolVar(showVersion, "v", false, "shorthand for --version")
	showHelp := flag.Bool("help", false, "show usage")
	flag.BoolVar(showHelp, "h", false, "shorthand for --help")

	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Println(VersionString())
		return
	}

	if *showHelp {
		flag.Usage()
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	bundle := NewBundle()
	envLang := os.Getenv("LC_ALL")
	if envLang == "" {
		envLang = os.Getenv("LANG")
	}
	lang := DetectLang(*langFlag, "", envLang)

	hasConfig := *configPath != ""
	hasCLI := len(listeners.values) > 0

	if hasConfig && hasCLI {
		logger.Error(bundle.T(lang, "err.config_not_found"), "detail", "--config and --listener are mutually exclusive")
		os.Exit(1)
	}

	var cfg *Config
	var err error

	if hasCLI {
		cfg, err = BuildConfigFromCLI(listeners.values, &CLIGlobals{
			TSAURL:              *tsaURL,
			TSACertFile:         *tsaCertFile,
			TSAProofFile:        *tsaProofFile,
			TSAProofIntervalSec: *tsaProofIntervalSec,
			AuditFile:           *auditFile,
			AuditMaxSizeMB:      *auditMaxSizeMB,
			AuditMaxBackups:     *auditMaxBackups,
			MgmtListen:          *mgmtListen,
			MgmtCACert:          *mgmtCACert,
			MgmtCert:            *mgmtCert,
			MgmtKey:             *mgmtKey,
			MgmtCRLURL:          *mgmtCRLURL,
			MgmtOCSPFallback:    *mgmtOCSPFallback,
			CRLRefreshSec:       *crlRefreshSec,
			OCSPCacheTTLSec:     *ocspCacheTTLSec,
			OCSPFallback:        *ocspFallback,
		})
		if err != nil {
			logger.Error(bundle.T(lang, "err.load_config"), "error", err)
			os.Exit(1)
		}
	} else {
		path := *configPath
		if path == "" {
			path = DefaultConfigFile()
		}
		if _, err := os.Stat(path); err != nil {
			logger.Error(bundle.T(lang, "err.config_not_found"), "path", path)
			logger.Error(bundle.T(lang, "cli.help_config"))
			os.Exit(1)
		}
		cfg, err = LoadConfig(path)
		if err != nil {
			logger.Error(bundle.T(lang, "err.load_config"), "error", err)
			os.Exit(1)
		}
	}

	lang = DetectLang(*langFlag, cfg.Locale, envLang)

	var tsaClient *gw.TSAClient
	for _, l := range cfg.Listeners {
		if l.TLS != nil && l.TLS.TSAURL != "" {
			tsaClient = gw.NewTSAClient(l.TLS.TSAURL)
			if l.TLS.TSACertFile != "" {
				if err := tsaClient.SetCACert(l.TLS.TSACertFile); err != nil {
					logger.Error("TSA cert", "error", err)
					os.Exit(1)
				}
			}
			break
		}
	}

	var audit *gw.AuditLogger
	for _, l := range cfg.Listeners {
		if l.TLS != nil && l.TLS.AuditFile != "" {
			a, err := gw.NewAuditLogger(l.TLS.AuditFile, tsaClient, l.TLS.AuditMaxSize(), l.TLS.AuditMaxBackupCount())
			if err != nil {
				logger.Error("audit init", "error", err)
				os.Exit(1)
			}
			audit = a
			break
		}
	}

	var tsaProof *gw.TSAProofLogger
	if cfg.TSAProofFile != "" && tsaClient != nil {
		tsaProof = gw.NewTSAProofLogger(cfg.TSAProofFile, tsaClient, nil, cfg.TSAProofIntervalSec)
	}

	var shortResult *gw.AutoIssueResult
	if cfg.ShortLived != nil {
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "unknown"
		}
		cn := "gateway-udp-" + hostname
		shortResult, err = gw.AutoIssueCert(cfg.ShortLived, cn, "")
		if err != nil {
			logger.Error("auto-issue cert", "error", err)
			os.Exit(1)
		}
		logger.Info("short-lived cert issued", "cn", shortResult.CN, "serial", shortResult.Result.SerialNumber)

		for i := range cfg.Listeners {
			if cfg.Listeners[i].TLS != nil {
				cfg.Listeners[i].TLS.CertFile = shortResult.CertFile
				cfg.Listeners[i].TLS.KeyFile = shortResult.KeyFile
			}
		}
		if cfg.Management != nil && cfg.Management.TLS != nil {
			cfg.Management.TLS.CertFile = shortResult.CertFile
			cfg.Management.TLS.KeyFile = shortResult.KeyFile
		}
	}

	gateway := NewGateway(cfg, bundle, lang, logger, audit, tsaClient, tsaProof)

	if err := gateway.Start(); err != nil {
		logger.Error("start", "error", err)
		os.Exit(1)
	}

	logger.Info(bundle.T(lang, "gateway.started"))

	if shortResult != nil {
		issueCfg := *cfg.ShortLived
		certFile := shortResult.CertFile
		keyFile := shortResult.KeyFile
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-gateway.renewalCh:
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
					gateway.UpdateServerCert(&newCert)
					logger.Info("short-lived cert renewed", "serial", result.SerialNumber)
				}
			}
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		sig := <-sigCh
		switch sig {
		case syscall.SIGHUP:
			logger.Info(bundle.T(lang, "gateway.reloading"))
			if err := gateway.Reload(); err != nil {
				logger.Error(bundle.T(lang, "err.reload"), "error", err)
			}
		default:
			logger.Info(bundle.T(lang, "gateway.shutting_down"))
			gateway.Stop()
			return
		}
	}
}
