// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package httpgw

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

// String returns a comma-separated string of flag values.
func (s *stringSliceFlag) String() string {
	return strings.Join(s.values, ",")
}

// Set appends a flag value.
func (s *stringSliceFlag) Set(value string) error {
	s.values = append(s.values, value)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}

	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "--version", "-v", "version":
		fmt.Println(VersionString())
	case "--help", "-h", "help":
		usage()
	default:
		runServer(os.Args[1:])
	}
}

func usage() {
	fmt.Printf(`gateway-http — zero-trust HTTP reverse proxy

Usage:
  gateway-http [--config <file> | --listener <kv>... --route <kv>...] [flags]

Default subcommand is "server".

Flags:
  -c, --config <file>           config file (JSON) (default: %[1]s)
  -l, --lang <lang>             language (zh/en)
  -L, --listener <kv>           listener definition (key=value,...) — repeatable
  -r, --route <kv>              route definition (key=value,...) — repeatable
      --crl-refresh-sec <n>       global CRL refresh interval in seconds (default: 300)
      --ocsp-cache-ttl-sec <n>    global OCSP cache TTL in seconds (default: 300)
      --ocsp-fallback <s>         global OCSP fallback policy (allow|deny|crl) (default: deny)
      --tsa-url <url>             TSA server URL
      --tsa-cert-file <path>      TSA certificate file
      --audit-file <path>         audit log file path
      --audit-max-size-mb <n>     audit max size in MB (default: 100)
      --audit-max-backups <n>     audit max backup count (default: 3)
      --management-listen <addr>  management API listen address
      --mgmt-ca-cert <path>       management API CA cert file
      --mgmt-cert <path>          management API server cert file
      --mgmt-key <path>           management API server key file
      --mgmt-crl-url <url>        management API CRL URL
      --mgmt-ocsp-fallback <s>    management API OCSP fallback (default: deny)

Listener key=value format:
  name=<name>,listen=<addr>,protocol=<protocol>,
  ca-cert=<path>,cert=<path>,key=<path>,
  crl-url=<url>,crl-refresh-sec=<n>,
  ocsp-cache-ttl-sec=<n>,ocsp-fallback=<s>,
  tsa-url=<url>,audit-file=<path>,
  max-conns-per-ip=<n>,max-total-conns=<n>,
  idle-timeout-sec=<n>,
  read-header-timeout-sec=<n>,write-timeout-sec=<n>,
  disconnect-on-expiry=<bool>,forward-client-cert=<bool>,
  cipher-suites=<suite>[;<suite>...],min-tls-version=<ver>,
  audit-max-size-mb=<n>,audit-max-backups=<n>

Route key=value format:
  listener=<name>,path=<path>,target=<addr>[,allow-roles=<role>[;<role>...]]

Examples:
  gateway-http --config %[1]s
  gateway-http -L name=api,listen=:443,protocol=http2,tls-mode=mtls,ca-cert=ca.pem,cert=cert.pem,key=key.pem -r listener=api,path=/api/v1,target=be:8080,allow-roles=gateway:admin -r listener=api,path=/,target=web:3000
`, DefaultConfigFile())
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfgDefault := DefaultConfigFile()

	configPath := fs.String("config", "", "config file (JSON)")
	fs.StringVar(configPath, "c", "", "shorthand for --config")

	langFlag := fs.String("lang", "", "language (zh/en)")
	fs.StringVar(langFlag, "l", "", "shorthand for --lang")

	listeners := &stringSliceFlag{}
	fs.Var(listeners, "listener", "listener definition (key=value,...) — repeatable")
	fs.Var(listeners, "L", "shorthand for --listener")

	routes := &stringSliceFlag{}
	fs.Var(routes, "route", "route definition (key=value,...) — repeatable")
	fs.Var(routes, "r", "shorthand for --route")

	crlRefreshSec := fs.Int("crl-refresh-sec", 300, "global CRL refresh interval (seconds)")
	ocspCacheTTL := fs.Int("ocsp-cache-ttl-sec", 300, "global OCSP cache TTL (seconds)")
	ocspFallback := fs.String("ocsp-fallback", "deny", "global OCSP fallback (allow|deny|crl)")
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
	mgmtOCSPFallback := fs.String("mgmt-ocsp-fallback", "deny", "management OCSP fallback")

	fs.Usage = func() {
		usage()
	}
	fs.Parse(args)

	bundle := NewBundle()
	lang := DetectLang(*langFlag, "", os.Getenv("LANG"))

	hasConfig := *configPath != ""
	hasCLI := len(listeners.values) > 0 || len(routes.values) > 0

	if hasConfig && hasCLI {
		logger.Error("--config and --listener/--route are mutually exclusive")
		os.Exit(1)
	}

	var cfg *Config
	var err error

	if hasCLI {
		cfg, err = BuildConfigFromCLI(listeners.values, routes.values, &CLIGlobals{
			CRLRefreshSec:    *crlRefreshSec,
			OCSPCacheTTLSec:  *ocspCacheTTL,
			OCSPFallback:     *ocspFallback,
			TSAURL:           *tsaURL,
			TSACertFile:      *tsaCertFile,
			AuditFile:        *auditFile,
			AuditMaxSizeMB:   *auditMaxSizeMB,
			AuditMaxBackups:  *auditMaxBackups,
			MgmtListen:       *mgmtListen,
			MgmtCACert:       *mgmtCACert,
			MgmtCert:         *mgmtCert,
			MgmtKey:          *mgmtKey,
			MgmtCRLURL:       *mgmtCRLURL,
			MgmtOCSPFallback: *mgmtOCSPFallback,
		})
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
			logger.Info(bundle.T(lang, "cli.help_config"))
			os.Exit(1)
		}
		cfg, err = LoadConfig(*configPath)
		if err != nil {
			logger.Error(bundle.T(lang, "err.load_config"), "error", err)
			os.Exit(1)
		}
	}

	var tsaClient *gw.TSAClient
	var firstTSAURL string
	for _, l := range cfg.Listeners {
		if l.TLS == nil {
			continue
		}
		if l.TLS.TSAURL == "" {
			continue
		}
		if tsaClient == nil {
			firstTSAURL = l.TLS.TSAURL
			tsaClient = gw.NewTSAClient(l.TLS.TSAURL)
			if tsaClient != nil && l.TLS.TSACertFile != "" {
				if err := tsaClient.SetCACert(l.TLS.TSACertFile); err != nil {
					logger.Warn("load TSA CA cert failed", "error", err)
				}
			}
		} else if l.TLS.TSAURL != firstTSAURL {
			// W35 (2026-08-16): TSA is a gateway-level shared service; subsequent listener's
			// tsa_url is ignored -- consistent with the shared audit_file warning, avoiding silence.
			logger.Warn("listener tsa_url ignored, using shared TSA",
				"listener", l.Name,
				"tsa_url", l.TLS.TSAURL,
				"shared_url", firstTSAURL)
		}
	}

	var auditLogger *gw.AuditLogger
	// shared audit: all listeners write to the same file (set by the first listener with audit_file)
	var firstAuditFile string
	if len(cfg.Listeners) > 0 && cfg.Listeners[0].TLS != nil {
		firstAuditFile = cfg.Listeners[0].TLS.AuditFile
	}
	for _, l := range cfg.Listeners {
		if l.TLS == nil || l.TLS.AuditFile == "" {
			continue
		}
		if auditLogger == nil {
			// startup archive: rename old audit file so API only queries the current session
			if err := gw.ArchiveAuditFile(l.TLS.AuditFile); err != nil {
				logger.Warn("archive audit file failed", "error", err)
			}
			auditLogger, err = gw.NewAuditLogger(
				l.TLS.AuditFile, tsaClient,
				l.TLS.AuditMaxSize(), l.TLS.AuditMaxBackupCount(),
			)
			if err != nil {
				logger.Error(bundle.T(lang, "err.load_config"), "error", err)
				os.Exit(1)
			}
		} else if l.TLS.AuditFile != "" && l.TLS.AuditFile != firstAuditFile {
			logger.Warn("listener audit_file ignored, using shared file",
				"listener", l.Name,
				"audit_file", l.TLS.AuditFile,
				"shared_file", firstAuditFile)
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
		cn := "gateway-http-" + hostname
		shortResult, err = gw.AutoIssueCert(cfg.ShortLived, cn, "")
		if err != nil {
			logger.Error("auto-issue cert failed", "error", err)
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
			ticker := time.NewTicker(cfg.ShortLived.RenewalInterval())
			defer ticker.Stop()
			for {
				select {
				case <-g.RenewalCh:
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
