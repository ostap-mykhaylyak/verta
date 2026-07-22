// Command verta is an enterprise secure mail server.
//
// The command line follows one rule: the service verbs — start, stop,
// reload, restart — are bare words, because that is how a service is
// managed; every other action is a --flag, so a diagnostic or a
// one-shot task can never be taken for a service command.
//
//	verta start   [--config path] [--pidfile path] [--socket path]
//	verta stop    [--pidfile path]
//	verta reload  [--pidfile path]
//	verta restart [--config path] [--pidfile path] [--socket path]
//
//	verta --init
//	verta --purge [--yes]
//	verta --status [--json] [--socket path]
//	verta --check-config [--config path]
//	verta --hash-password
//	verta --generate-dkim [--selector s] [--dir d] <domain>
//	verta --audit | --security-check | --container-check [--config path]
//	verta --version
package main

import (
	"bufio"
	stdtls "crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ostap-mykhaylyak/verta/internal/antispam"
	"github.com/ostap-mykhaylyak/verta/internal/antivirus"
	"github.com/ostap-mykhaylyak/verta/internal/api"
	"github.com/ostap-mykhaylyak/verta/internal/auth"
	"github.com/ostap-mykhaylyak/verta/internal/blacklist"
	"github.com/ostap-mykhaylyak/verta/internal/bootstrap"
	"github.com/ostap-mykhaylyak/verta/internal/checks"
	"github.com/ostap-mykhaylyak/verta/internal/config"
	"github.com/ostap-mykhaylyak/verta/internal/container"
	"github.com/ostap-mykhaylyak/verta/internal/dkim"
	"github.com/ostap-mykhaylyak/verta/internal/egress"
	"github.com/ostap-mykhaylyak/verta/internal/imap"
	"github.com/ostap-mykhaylyak/verta/internal/logging"
	"github.com/ostap-mykhaylyak/verta/internal/mailauth"
	"github.com/ostap-mykhaylyak/verta/internal/maildir"
	"github.com/ostap-mykhaylyak/verta/internal/pace"
	"github.com/ostap-mykhaylyak/verta/internal/paths"
	"github.com/ostap-mykhaylyak/verta/internal/pop3"
	"github.com/ostap-mykhaylyak/verta/internal/proc"
	"github.com/ostap-mykhaylyak/verta/internal/queue"
	"github.com/ostap-mykhaylyak/verta/internal/ratelimit"
	"github.com/ostap-mykhaylyak/verta/internal/reputation"
	"github.com/ostap-mykhaylyak/verta/internal/routing"
	"github.com/ostap-mykhaylyak/verta/internal/smtp"
	"github.com/ostap-mykhaylyak/verta/internal/srs"
	"github.com/ostap-mykhaylyak/verta/internal/stats"
	kstatus "github.com/ostap-mykhaylyak/verta/internal/status"
	"github.com/ostap-mykhaylyak/verta/internal/storage"
	ktls "github.com/ostap-mykhaylyak/verta/internal/tls"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

// certRefreshInterval bounds how stale an on-disk renewed certificate
// can stay unloaded without a SIGHUP: certbot renews in place, verta
// re-reads on this interval and on every reload.
const certRefreshInterval = 12 * time.Hour

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}

	// Command convention: the service verbs — start, stop, reload,
	// restart — are bare words, because that is how an operator and
	// systemd drive the service. Everything else is a --flag, so a
	// diagnostic or one-shot action can never be mistaken for one of
	// them. normalizeCommand enforces this and gives a targeted error
	// for the two easy mistakes (a -- on a service verb, or a missing
	// -- on the rest).
	args := os.Args[2:]
	cmd, err := normalizeCommand(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "verta:", err)
		fmt.Fprintln(os.Stderr)
		usage(os.Stderr)
		os.Exit(2)
	}

	switch cmd {
	case "start":
		fs := flag.NewFlagSet("start", flag.ExitOnError)
		cfgPath := fs.String("config", paths.ConfigFile, "config file")
		pidfile := fs.String("pidfile", paths.Pidfile, "pidfile path")
		sock := fs.String("socket", paths.Socket, "control socket for `verta --status`")
		fs.Parse(args)
		fatalIf(runDaemon(*cfgPath, *pidfile, *sock))

	case "stop":
		fs := flag.NewFlagSet("stop", flag.ExitOnError)
		pidfile := fs.String("pidfile", paths.Pidfile, "pidfile path")
		fs.Parse(args)
		fatalIf(proc.Stop(*pidfile))

	case "reload":
		fs := flag.NewFlagSet("reload", flag.ExitOnError)
		pidfile := fs.String("pidfile", paths.Pidfile, "pidfile path")
		fs.Parse(args)
		fatalIf(proc.Reload(*pidfile))

	case "restart":
		// Stop the running daemon, wait for it to release the
		// listening sockets, then become the new foreground daemon.
		// Under systemd use `systemctl restart verta` instead; this is
		// for running the service by hand.
		fs := flag.NewFlagSet("restart", flag.ExitOnError)
		cfgPath := fs.String("config", paths.ConfigFile, "config file")
		pidfile := fs.String("pidfile", paths.Pidfile, "pidfile path")
		sock := fs.String("socket", paths.Socket, "control socket for `verta --status`")
		fs.Parse(args)
		fatalIf(proc.StopAndWait(*pidfile, 30*time.Second))
		fatalIf(runDaemon(*cfgPath, *pidfile, *sock))

	case "check-config":
		fs := flag.NewFlagSet("check-config", flag.ExitOnError)
		cfgPath := fs.String("config", paths.ConfigFile, "config file")
		fs.Parse(args)
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "config error:", err)
			os.Exit(1)
		}
		for _, w := range cfg.Warnings {
			fmt.Println("warning:", w)
		}
		fmt.Printf("%s: config OK\n", *cfgPath)
		fmt.Printf("domains: %d from %s\n", len(cfg.Domains), cfg.DomainsDir)
		for _, d := range cfg.Domains {
			n := 0
			for _, u := range cfg.Users {
				if strings.HasSuffix(u.Email, "@"+d.Name) {
					n++
				}
			}
			storage := d.Storage.Type
			if storage == "" {
				storage = config.StorageVirtual
			}
			fmt.Printf("  %-30s %-12s %d mailbox(es)\n", d.Name, storage, n)
		}

	case "init":
		fatalIf(bootstrap.Init(version, os.Stdout))

	case "purge":
		fs := flag.NewFlagSet("purge", flag.ExitOnError)
		assumeYes := fs.Bool("yes", false, "skip the confirmation prompt")
		fs.Parse(args)
		fatalIf(bootstrap.Purge(*assumeYes, os.Stdin, os.Stdout))

	case "status":
		fs := flag.NewFlagSet("status", flag.ExitOnError)
		sock := fs.String("socket", paths.Socket, "control socket")
		asJSON := fs.Bool("json", false, "machine-readable output")
		fs.Parse(args)
		rep, err := kstatus.Query(*sock)
		fatalIf(err)
		if *asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			fatalIf(enc.Encode(rep))
			return
		}
		rep.Print(os.Stdout)

	case "version":
		fmt.Println("verta", version)

	case "hash-password":
		// Read from stdin (not argv: passwords must not land in the
		// shell history or the process list).
		fmt.Fprint(os.Stderr, "password: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			fatalIf(err)
		}
		pw := strings.TrimRight(line, "\r\n")
		if pw == "" {
			fatalIf(fmt.Errorf("empty password"))
		}
		h, err := auth.HashArgon2id(pw)
		fatalIf(err)
		fmt.Println(h)

	case "generate-dkim":
		fs := flag.NewFlagSet("generate-dkim", flag.ExitOnError)
		selector := fs.String("selector", dkim.DefaultSelector, "DKIM selector")
		dir := fs.String("dir", paths.DKIMDir, "key directory")
		fs.Parse(args)
		if fs.NArg() != 1 {
			fatalIf(fmt.Errorf("usage: verta --generate-dkim [--selector s] [--dir d] <domain>"))
		}
		domain := strings.ToLower(fs.Arg(0))
		name, value, err := dkim.Generate(*dir, domain, *selector)
		if err != nil {
			// An existing key is re-displayed, not overwritten.
			if n, v, terr := dkim.NewStore(*dir).TXTRecord(domain, *selector); terr == nil {
				fmt.Fprintln(os.Stderr, "verta:", err)
				fmt.Printf("\nExisting DNS record:\n\n%s. IN TXT %q\n", n, v)
				return
			}
			fatalIf(err)
		}
		fmt.Printf("DKIM key generated for %s (selector %s).\n\nPublish this DNS record:\n\n%s. IN TXT %q\n",
			domain, *selector, name, value)

	case "security-check", "audit", "container-check":
		fs := flag.NewFlagSet(cmd, flag.ExitOnError)
		cfgPath := fs.String("config", paths.ConfigFile, "config file")
		probeHost := fs.String("host", "", "address to probe instead of server.hostname (security-check)")
		fs.Parse(args)

		cfg, err := config.Load(*cfgPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "config error:", err)
			os.Exit(1)
		}
		var report *checks.Report
		var title string
		switch cmd {
		case "security-check":
			report, title = checks.SecurityCheck(cfg, *probeHost), "verta security check"
		case "audit":
			report, title = checks.Audit(cfg, *cfgPath), "verta configuration audit"
		default:
			report, title = checks.ContainerCheck(cfg), "verta container check"
		}
		report.Print(os.Stdout, title)
		os.Exit(report.ExitCode())

	default:
		// Unreachable: normalizeCommand has already rejected anything
		// not handled above. Kept as a guard against a new case being
		// added to one table but not the switch.
		fmt.Fprintf(os.Stderr, "verta: unhandled command %q\n", cmd)
		os.Exit(2)
	}
}

// serviceVerbs are driven as bare words, the way an operator and
// systemd manage a service.
var serviceVerbs = map[string]bool{
	"start": true, "stop": true, "reload": true, "restart": true,
}

// flagCommands are the diagnostic and one-shot actions. They take a
// leading --, so they can never be confused with a service verb.
var flagCommands = map[string]bool{
	"init": true, "purge": true, "status": true, "check-config": true,
	"version": true, "hash-password": true, "generate-dkim": true,
	"audit": true, "security-check": true, "container-check": true,
}

// normalizeCommand maps the word the user typed to its internal name,
// enforcing the convention and explaining the two common mistakes:
// a -- on a service verb, or a missing -- on everything else.
func normalizeCommand(cmd string) (string, error) {
	if bare, ok := strings.CutPrefix(cmd, "--"); ok {
		switch {
		case flagCommands[bare]:
			return bare, nil
		case serviceVerbs[bare]:
			return "", fmt.Errorf("service commands take no leading --: use %q, not %q", bare, cmd)
		default:
			return "", fmt.Errorf("unknown command %q", cmd)
		}
	}
	switch {
	case serviceVerbs[cmd]:
		return cmd, nil
	case flagCommands[cmd]:
		return "", fmt.Errorf("this command takes a leading --: use %q, not %q", "--"+cmd, cmd)
	default:
		return "", fmt.Errorf("unknown command %q", cmd)
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `verta - enterprise secure mail server

Service (bare verbs, no dashes):
  start          run the daemon in the foreground (what systemd does)
  stop           signal the running daemon to shut down
  reload         reload configuration, domains and certificates
  restart        stop the running daemon, then start it again

Setup (--flags):
  --init           create the layout, default config and systemd unit
  --purge          remove config, domains, logs and state (asks first)

Everything else (--flags):
  --status         show the running daemon's state (--json for machine)
  --check-config   validate the configuration and exit
  --hash-password  read a password from stdin, print its argon2id hash
  --generate-dkim  create a domain's DKIM key, print the DNS record
  --version        print version and exit

Diagnostics (--flags, exit 1 when a check fails):
  --audit           inspect the local configuration and filesystem, no network
  --security-check  probe the live deployment: relay, TLS, DNS, rDNS, blacklists
  --container-check verify the public identity of a containerized deployment
`)
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "verta:", err)
		os.Exit(1)
	}
}

func runDaemon(cfgPath, pidfile, sockPath string) (err error) {
	// First execution without a config: auto-provision the default
	// layout from the embedded skel, warn on stderr and keep going.
	if cfgPath == paths.ConfigFile {
		if _, statErr := os.Stat(cfgPath); os.IsNotExist(statErr) {
			fmt.Fprintln(os.Stderr, "verta: no config found, provisioning default layout")
			if err := bootstrap.EnsureLayout(os.Stderr); err != nil {
				return err
			}
		}
	}

	mgr, err := config.NewManager(cfgPath)
	if err != nil {
		return err
	}
	cfg := mgr.Get()

	logs, err := logging.Open(cfg.Log.Dir)
	if err != nil {
		return err
	}
	defer logs.Close()
	// Surface a fatal startup error in the service log too, not only
	// on stderr — otherwise a crash loop is invisible to anyone
	// reading verta.log. Runs before logs.Close.
	defer func() {
		if err != nil {
			logs.Service.Error("fatal error, exiting", "error", err.Error())
		}
	}()

	logs.Service.Info("starting", "version", version, "config", cfgPath, "pid", os.Getpid())
	for _, w := range cfg.Warnings {
		logs.Service.Warn("config warning", "warning", w)
	}

	// Public identity: nothing verta writes may carry the container's
	// own name, including the host part of Maildir filenames.
	maildir.SetHostname(cfg.Server.Hostname)
	if leaks, why := container.LeaksContainerName(cfg.Server.Hostname); leaks {
		logs.Service.Warn("server.hostname is not a public mail hostname",
			"hostname", cfg.Server.Hostname, "reason", why)
	}
	if rt := container.Detect(); rt != container.RuntimeNone {
		logs.Service.Info("container runtime detected",
			"runtime", string(rt), "container_mode", cfg.Container.Enabled)
		if !cfg.Container.Enabled {
			logs.Service.Warn("running in a container without container mode: internal addresses may reach outgoing mail",
				"runtime", string(rt))
		}
	}

	if err := proc.WritePidfile(pidfile); err != nil {
		// Not fatal: under systemd the MAINPID is known anyway, and in
		// development /run may not exist.
		logs.Service.Warn("pidfile not written", "path", pidfile, "error", err.Error())
	} else {
		defer proc.RemovePidfile(pidfile)
	}

	store, warns := ktls.New(tlsParams(cfg))
	for _, w := range warns {
		logs.Service.Warn("tls warning", "warning", w)
	}
	logs.Service.Info("tls certificates loaded",
		"domains", store.Loaded(), "min_version", cfg.TLS.MinVersion)

	counters := &stats.Counters{}
	started := time.Now()

	// --- authentication (survives reloads: lookup reads mgr.Get()) ---
	authr := auth.New(
		func(email string) (string, bool) { return mgr.Get().PasswordHashFor(email) },
		cfg.Auth.MaxFailures, time.Duration(cfg.Auth.LockoutMinutes)*time.Minute)

	dkimStore := dkim.NewStore(cfg.DKIM.Dir)

	// --- blacklists (DNSBL for IPs, URIBL for body links) ---
	var bl *blacklist.Checker
	if cfg.Blacklist.IsEnabled() {
		bl = blacklist.New(cfg.Blacklist.DNSBL, cfg.Blacklist.URIBL,
			time.Duration(cfg.Blacklist.CacheMinutes)*time.Minute)
		logs.Service.Info("blacklists enabled",
			"dnsbl", len(cfg.Blacklist.DNSBL), "uribl", len(cfg.Blacklist.URIBL),
			"reject_listed", cfg.Blacklist.RejectListed)
	}

	// --- antivirus ---
	var scanner antispam.Scanner
	if cfg.Antivirus.Enabled {
		av := antivirus.New(cfg.Antivirus.Socket,
			time.Duration(cfg.Antivirus.TimeoutSeconds)*time.Second)
		if err := av.Ping(); err != nil {
			// Not fatal: clamd may still be starting. Scans will
			// error until it answers, and reject_on_error decides
			// what that means for the mail.
			logs.Service.Warn("clamav not reachable at startup",
				"socket", cfg.Antivirus.Socket, "error", err.Error())
		} else {
			logs.Service.Info("antivirus enabled", "socket", cfg.Antivirus.Socket)
		}
		scanner = av
	}

	// --- antispam ---
	var spamEngine *antispam.Engine
	var bayes *antispam.Bayes
	if cfg.Antispam.IsEnabled() {
		var err error
		bayes, err = antispam.NewBayes(cfg.Antispam.BayesFile)
		if err != nil {
			logs.Service.Warn("bayes corpus not loaded, starting empty",
				"file", cfg.Antispam.BayesFile, "error", err.Error())
			bayes, _ = antispam.NewBayes("")
		}
		spamEngine = &antispam.Engine{Bayes: bayes, Scanner: scanner}
		if bl != nil {
			spamEngine.URIBL = bl
		}
		ham, spam := bayes.Trained()
		logs.Service.Info("antispam enabled",
			"bayes_ham", ham, "bayes_spam", spam, "bayes_ready", bayes.Ready(),
			"tag", cfg.Antispam.TagScore, "quarantine", cfg.Antispam.QuarantineScore,
			"reject", cfg.Antispam.RejectScore)
	}

	// --- reputation ---
	var rep *reputation.Store
	if cfg.Reputation.IsEnabled() {
		var err error
		rep, err = reputation.Open(cfg.Reputation.File)
		if err != nil {
			logs.Service.Warn("reputation store not loaded, starting empty",
				"file", cfg.Reputation.File, "error", err.Error())
			rep, _ = reputation.Open("")
		}
		logs.Service.Info("reputation enabled",
			"file", cfg.Reputation.File, "warmup", cfg.Reputation.WarmUp.Enabled)
	}
	warmUp := func(cfg *config.Config) reputation.WarmUp {
		w := cfg.Reputation.WarmUp
		return reputation.WarmUp{Enabled: w.Enabled, Day1: w.Day1, Day7: w.Day7, Full: w.FullPerDay}
	}

	// --- outbound queue + scheduler ---
	q, err := queue.Open(cfg.Queue.Dir)
	if err != nil {
		return err
	}
	transport := &queue.SMTPTransport{Hostname: cfg.Server.Hostname}
	bounceFn := func(e *queue.Envelope, reason string) {
		// A hard bounce is reputation-relevant: it is the clearest
		// signal that a sender is mailing addresses it should not.
		if rep != nil && e.From != "" {
			rep.Record("user:"+e.From, reputation.EventBounce)
			if _, domain, ok := storage.Split(e.From); ok {
				rep.Record("domain:"+domain, reputation.EventBounce)
			}
		}
		data := queue.BuildBounce(mgr.Get().Server.Hostname, e, reason)
		if data == nil {
			return // null reverse-path: never bounce a bounce
		}
		mb, ok := storage.Resolve(mgr.Get(), e.From)
		if !ok {
			logs.Service.Warn("bounce dropped: sender not local",
				"event", "bounce_dropped", "queue_id", e.ID, "from", e.From)
			return
		}
		full := append([]byte("Return-Path: <>\r\n"), data...)
		if _, err := maildir.Deliver(mb.Dir, full, mb.UID, mb.GID); err != nil {
			logs.Service.Error("bounce delivery failed",
				"queue_id", e.ID, "from", e.From, "error", err.Error())
		}
	}
	sched := queue.NewScheduler(q, transport, bounceFn, cfg.Queue.MaxAttempts, logs.Service)
	sched.SetCounters(counters)
	// Outbound source selection: per-mailbox / per-domain pins, then the
	// rotation pool.
	if sel := egressSelector(cfg, logs.Service); sel != nil {
		sched.SetEgress(sel)
		logs.Service.Info("outbound IP selection enabled",
			"event", "egress", "strategy", cfg.Egress.Strategy, "addresses", len(cfg.Egress.Addresses))
	}
	if th := pace.New(cfg.ThrottleConfig()); th != nil {
		sched.SetThrottle(th)
		logs.Service.Info("outbound pacing enabled", "event", "throttle_config")
	}
	schedStop := make(chan struct{})
	go sched.Run(schedStop)
	logs.Service.Info("outbound queue open", "dir", cfg.Queue.Dir, "pending", q.Size())

	// --- state persistence: the learned corpus and the scores are
	// flushed periodically and on shutdown, so a crash loses at most
	// one interval of learning rather than everything. ---
	stateStop := make(chan struct{})
	saveState := func() {
		if bayes != nil {
			if err := bayes.Save(); err != nil {
				logs.Service.Error("bayes save failed", "error", err.Error())
			}
		}
		if rep != nil {
			if err := rep.Save(); err != nil {
				logs.Service.Error("reputation save failed", "error", err.Error())
			}
		}
	}
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-stateStop:
				return
			case <-t.C:
				saveState()
			}
		}
	}()

	backend := smtp.Backend{
		IsLocalDomain: func(d string) bool { return mgr.Get().HasDomain(d) },
		Route: func(email string) (routing.Plan, bool) {
			cfg := mgr.Get()
			p := routing.Resolve(cfg, cfg.Forwarding.SRSSecret, email)
			return p, p.Found
		},
		Store: func(mb storage.Mailbox, from, folder string, seen, flagged bool, msg []byte) error {
			dir := mb.Dir
			if folder != "" {
				dir = filepath.Join(dir, "."+folder) // Maildir++ subfolder (".Spam", ".Newsletters", ...)
			}
			var flags maildir.Flags
			if seen {
				flags = flags.Add(maildir.FlagSeen)
			}
			if flagged {
				flags = flags.Add(maildir.FlagFlagged)
			}
			full := append([]byte("Return-Path: <"+from+">\r\n"), msg...)
			_, err := maildir.DeliverWithFlags(dir, full, flags, mb.UID, mb.GID)
			return err
		},
		Forward: func(from, forwardDomain, rcpt string, msg []byte) error {
			sender := from
			if secret := mgr.Get().Forwarding.SRSSecret; secret != "" && from != "" {
				sender = srs.Forward(secret, forwardDomain, from)
			}
			return q.Enqueue(sender, rcpt, msg)
		},
		Postmaster: func() string {
			if doms := mgr.Get().Domains; len(doms) > 0 {
				return "postmaster@" + doms[0].Name
			}
			return ""
		},
		Authenticate: authr.Verify,
		Enqueue:      q.Enqueue,
		Screen: func(ip, helo, from string, data []byte) smtp.ScreenResult {
			cfg := mgr.Get()
			var out smtp.ScreenResult
			var auth antispam.Auth

			// --- SPF / DKIM / DMARC ---
			if cfg.MailAuth.IsEnabled() {
				checker := mailauth.New(cfg.Server.Hostname, cfg.MailAuth.IsEnforced())
				res := checker.Check(net.ParseIP(ip), helo, from, data)
				logs.Service.Info("mail authentication",
					"event", "mail_auth", "protocol", "smtp", "ip", ip, "from", from,
					"spf", res.SPF, "dkim", res.DKIM, "dmarc", res.DMARC)
				out.AuthResults = res.AuthResults
				out.Reason = res.Reason
				auth = antispam.Auth{
					SPFPass:   res.SPF == "pass",
					DKIMPass:  res.DKIM == "pass",
					DMARCPass: res.DMARC == "pass",
				}
				switch res.Action {
				case mailauth.Reject:
					out.Action = smtp.ScreenReject
					return out // a DMARC reject settles it, no need to score
				case mailauth.Quarantine:
					out.Action = smtp.ScreenQuarantine
				}
			}

			// --- DNSBL on the connecting IP ---
			if bl != nil && cfg.Blacklist.RejectListed {
				if listed, zones := bl.ListedIP(ip); listed {
					logs.Service.Warn("connection from blacklisted ip",
						"event", "blacklist_hit", "protocol", "smtp", "ip", ip,
						"zones", zones, "action", "reject")
					out.Action = smtp.ScreenReject
					out.Reason = fmt.Sprintf("your IP is listed on %s", strings.Join(zones, ", "))
					return out
				}
			}

			// --- antispam scoring ---
			if spamEngine != nil {
				v := spamEngine.Check(data, auth)
				out.SpamHeader = v.Header(cfg.Antispam.TagScore)
				logs.Service.Info("message scored",
					"event", "spam_score", "protocol", "smtp", "ip", ip, "from", from,
					"score", v.Score, "bayes", v.Bayes, "rules", v.Rules, "virus", v.Virus)

				switch {
				case v.Virus != "":
					// Malware is never delivered, not even quarantined.
					out.Action = smtp.ScreenReject
					out.Reason = fmt.Sprintf("message contains %s", v.Virus)
					return out
				case v.BadAttachment != "" && cfg.Antispam.RejectsExecutables():
					out.Action = smtp.ScreenReject
					out.Reason = fmt.Sprintf("executable attachment refused: %s", v.BadAttachment)
					return out
				case v.Score >= cfg.Antispam.RejectScore:
					out.Action = smtp.ScreenReject
					out.Reason = fmt.Sprintf("message rejected, spam score %.1f", v.Score)
					return out
				case v.Score >= cfg.Antispam.QuarantineScore:
					out.Action = smtp.ScreenQuarantine
					if out.Reason == "" {
						out.Reason = fmt.Sprintf("spam score %.1f", v.Score)
					}
				}
			}
			return out
		},
		MaySend: func(user, domain string) (bool, string) {
			if rep == nil {
				return true, ""
			}
			if rep.Blocked("user:" + user) {
				return false, "sending temporarily suspended, contact your administrator"
			}
			if rep.Blocked("domain:" + domain) {
				return false, "domain sending temporarily suspended"
			}
			if ok, limit := rep.AllowSend("domain:"+domain, warmUp(mgr.Get())); !ok {
				return false, fmt.Sprintf("daily sending limit reached (%d), try again tomorrow", limit)
			}
			return true, ""
		},
		Sent: func(user, domain string) {
			if rep == nil {
				return
			}
			rep.Record("user:"+user, reputation.EventDelivered)
			rep.Record("domain:"+domain, reputation.EventDelivered)
		},
		Sign: func(fromDomain string, msg []byte) ([]byte, error) {
			cfg := mgr.Get()
			sel := cfg.DKIMSelectorFor(fromDomain)
			signer, ok := dkimStore.Signer(fromDomain, sel)
			if !ok {
				return msg, nil // no key: send unsigned
			}
			return dkim.Sign(msg, fromDomain, sel, signer)
		},
	}

	// --- listeners ---
	// TLS-requiring listeners (submission, IMAP, POP3, the API) are only
	// bound once a certificate is loaded: verta never exposes
	// authentication in the clear. Such a listener may be skipped at
	// startup and become possible later — when the operator installs the
	// certificate and reloads, or when certbot renews it. Binding is
	// therefore idempotent and re-run on every reload and certificate
	// refresh, not only at startup; before this, a listener skipped at
	// startup stayed down until a full restart.
	limits := newLimits(cfg)

	type running struct {
		srv      *smtp.Server
		mode     smtp.Mode
		implicit bool
	}
	type imapRunning struct {
		srv      *imap.Server
		implicit bool
	}
	type pop3Running struct {
		srv      *pop3.Server
		implicit bool
	}
	var (
		servers     []running
		imapServers []imapRunning
		pop3Servers []pop3Running
		apiSrv      *api.Server
	)

	// bound records which named listeners are up (name -> address). It is
	// touched only on the daemon's main goroutine: startup, then the
	// reload/refresh cases of the select loop. liveListeners publishes it
	// to the status goroutine without a lock.
	bound := map[string]string{}
	var liveListeners atomic.Pointer[[]kstatus.Listener]
	publishListeners := func() {
		var out []kstatus.Listener
		for _, n := range []string{"smtp", "submission", "smtps", "imap", "imaps", "pop3", "pop3s", "api"} {
			if addr, ok := bound[n]; ok {
				out = append(out, kstatus.Listener{Protocol: n, Address: addr})
			}
		}
		liveListeners.Store(&out)
	}

	// Mail access (IMAP and POP3) authenticates the same accounts as
	// submission and resolves the mailbox through the same storage rules.
	accessAuth := func(email, password, ip string) (string, error) {
		if err := authr.Verify(email, password, ip); err != nil {
			return "", err
		}
		mb, ok := storage.Resolve(mgr.Get(), strings.ToLower(email))
		if !ok {
			return "", fmt.Errorf("no mailbox for %s", email)
		}
		return mb.Dir, nil
	}

	// ensureListeners binds every configured listener that should be up
	// but is not yet, leaving already-bound ones untouched. Bind errors
	// are returned so startup can treat them as fatal (a crash loop is
	// visible) while a reload only logs them.
	ensureListeners := func(cfg *config.Config, lim limitSet) []error {
		var errs []error

		for _, sp := range []struct {
			name     string
			addr     string
			mode     smtp.Mode
			implicit bool
		}{
			{"smtp", cfg.Listeners.SMTP.Address, smtp.ModeInbound, false},
			{"submission", cfg.Listeners.Submission.Address, smtp.ModeSubmission, false},
			{"smtps", cfg.Listeners.SMTPS.Address, smtp.ModeSubmission, true},
		} {
			if sp.addr == "" || bound[sp.name] != "" {
				continue
			}
			if sp.mode == smtp.ModeSubmission && len(store.Loaded()) == 0 {
				logs.Service.Warn("submission listener not started: no TLS certificate loaded",
					"protocol", sp.name, "address", sp.addr)
				continue
			}
			ln, err := net.Listen("tcp", sp.addr)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s listener %s: %w", sp.name, sp.addr, err))
				continue
			}
			if sp.implicit {
				ln = stdtls.NewListener(ln, store.Config())
			}
			srv := smtp.New(smtpSettings(cfg, store, sp.mode, sp.implicit, lim, counters), backend, cfg.Server.Workers, logs.Service)
			go func(name string, srv *smtp.Server, ln net.Listener) {
				if err := srv.Serve(ln); err != nil {
					logs.Service.Error("smtp server failed", "protocol", name, "error", err.Error())
				}
			}(sp.name, srv, ln)
			servers = append(servers, running{srv, sp.mode, sp.implicit})
			bound[sp.name] = sp.addr
			logs.Service.Info("listening", "protocol", sp.name, "address", sp.addr)
		}

		for _, sp := range []struct {
			name     string
			addr     string
			implicit bool
		}{
			{"imap", cfg.Listeners.IMAP.Address, false},
			{"imaps", cfg.Listeners.IMAPS.Address, true},
		} {
			if sp.addr == "" || bound[sp.name] != "" {
				continue
			}
			if len(store.Loaded()) == 0 {
				logs.Service.Warn("imap listener not started: no TLS certificate loaded",
					"protocol", sp.name, "address", sp.addr)
				continue
			}
			ln, err := net.Listen("tcp", sp.addr)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s listener %s: %w", sp.name, sp.addr, err))
				continue
			}
			if sp.implicit {
				ln = stdtls.NewListener(ln, store.Config())
			}
			srv := imap.New(imapSettings(cfg, store, sp.implicit),
				imap.Backend{Authenticate: accessAuth}, cfg.Server.Workers, logs.Service)
			go func(name string, srv *imap.Server, ln net.Listener) {
				if err := srv.Serve(ln); err != nil {
					logs.Service.Error("imap server failed", "protocol", name, "error", err.Error())
				}
			}(sp.name, srv, ln)
			imapServers = append(imapServers, imapRunning{srv, sp.implicit})
			bound[sp.name] = sp.addr
			logs.Service.Info("listening", "protocol", sp.name, "address", sp.addr)
		}

		for _, sp := range []struct {
			name     string
			addr     string
			implicit bool
		}{
			{"pop3", cfg.Listeners.POP3.Address, false},
			{"pop3s", cfg.Listeners.POP3S.Address, true},
		} {
			if sp.addr == "" || bound[sp.name] != "" {
				continue
			}
			if len(store.Loaded()) == 0 {
				logs.Service.Warn("pop3 listener not started: no TLS certificate loaded",
					"protocol", sp.name, "address", sp.addr)
				continue
			}
			ln, err := net.Listen("tcp", sp.addr)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s listener %s: %w", sp.name, sp.addr, err))
				continue
			}
			if sp.implicit {
				ln = stdtls.NewListener(ln, store.Config())
			}
			srv := pop3.New(pop3Settings(cfg, store, sp.implicit),
				pop3.Backend{Authenticate: accessAuth}, cfg.Server.Workers, logs.Service)
			go func(name string, srv *pop3.Server, ln net.Listener) {
				if err := srv.Serve(ln); err != nil {
					logs.Service.Error("pop3 server failed", "protocol", name, "error", err.Error())
				}
			}(sp.name, srv, ln)
			pop3Servers = append(pop3Servers, pop3Running{srv, sp.implicit})
			bound[sp.name] = sp.addr
			logs.Service.Info("listening", "protocol", sp.name, "address", sp.addr)
		}

		// Administrative API (HTTPS, static API keys only).
		if cfg.API.Enabled && bound["api"] == "" {
			if len(store.Loaded()) == 0 {
				logs.Service.Warn("api not started: no TLS certificate loaded", "address", cfg.API.Address)
			} else {
				srv := api.New(cfg.API.Address, cfg.API.Keys, api.Deps{
					Config:     mgr.Get,
					Reload:     mgr.Reload,
					QueueSize:  q.Size,
					Reputation: rep,
					Version:    version,
					Started:    started,
				}, logs.Service)
				ln, err := net.Listen("tcp", cfg.API.Address)
				if err != nil {
					errs = append(errs, fmt.Errorf("api listener %s: %w", cfg.API.Address, err))
				} else {
					apiSrv = srv
					go func() {
						if err := srv.Serve(stdtls.NewListener(ln, store.Config())); err != nil {
							logs.Service.Error("api server failed", "error", err.Error())
						}
					}()
					bound["api"] = cfg.API.Address
					logs.Service.Info("listening", "protocol", "api", "address", cfg.API.Address, "keys", len(cfg.API.Keys))
				}
			}
		}

		publishListeners()
		return errs
	}

	// Bind everything possible now. A bind failure at startup (e.g. port
	// 25 already in use) is fatal, so the problem is visible instead of a
	// silently missing listener; the same failure on a later reload is
	// only logged.
	if errs := ensureListeners(cfg, limits); len(errs) > 0 {
		return errs[0]
	}

	updateAll := func(cfg *config.Config, lim limitSet) {
		for _, r := range servers {
			r.srv.Update(smtpSettings(cfg, store, r.mode, r.implicit, lim, counters))
		}
		for _, r := range imapServers {
			r.srv.Update(imapSettings(cfg, store, r.implicit))
		}
		for _, r := range pop3Servers {
			r.srv.Update(pop3Settings(cfg, store, r.implicit))
		}
	}

	// --- control socket for `verta --status` ---
	statusStop := make(chan struct{})
	buildStatus := func() kstatus.Report {
		cfg := mgr.Get()
		var domains []kstatus.DomainInfo
		for _, d := range cfg.Domains {
			n := 0
			for _, u := range cfg.Users {
				if strings.HasSuffix(u.Email, "@"+d.Name) {
					n++
				}
			}
			st := d.Storage.Type
			if st == "" {
				st = config.StorageVirtual
			}
			_, hasKey := dkimStore.Signer(d.Name, cfg.DKIMSelectorFor(d.Name))
			domains = append(domains, kstatus.DomainInfo{
				Name: d.Name, Storage: st, Mailboxes: n, DKIM: hasKey,
			})
		}
		// The listeners actually bound, not merely configured: a
		// TLS-requiring listener that could not start (no certificate)
		// must not be reported as up, or status hides the real problem.
		var lst []kstatus.Listener
		if p := liveListeners.Load(); p != nil {
			lst = *p
		}
		return kstatus.Build(version, cfg.Server.Hostname, started, domains,
			len(cfg.Users), lst, store.Loaded(), q.Size(), counters,
			cfg.Warnings, mgr.LastError())
	}
	if err := kstatus.Serve(sockPath, buildStatus, statusStop); err != nil {
		// Not fatal: the mail server works without the status socket,
		// and /run may not exist in a development checkout.
		logs.Service.Warn("status socket unavailable", "error", err.Error())
	} else {
		logs.Service.Info("status socket ready", "path", sockPath)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGTERM, os.Interrupt)
	refresh := time.NewTicker(certRefreshInterval)
	defer refresh.Stop()

	logs.Service.Info("ready", "hostname", cfg.Server.Hostname)
	for {
		select {
		case <-refresh.C:
			for _, w := range store.Reload(tlsParams(mgr.Get())) {
				logs.Service.Warn("tls warning", "warning", w)
			}
			// A certificate may have appeared (certbot renewal, or a
			// fresh install): update the STARTTLS offer on running
			// listeners, and bring up any that were waiting for it.
			// Limiters are kept, so quotas are not reset by the refresh.
			updateAll(mgr.Get(), limits)
			for _, err := range ensureListeners(mgr.Get(), limits) {
				logs.Service.Error("listener not started", "error", err.Error())
			}

		case s := <-sigs:
			switch s {
			case syscall.SIGHUP:
				logs.Service.Info("reload requested")
				if err := logs.Reopen(); err != nil {
					logs.Service.Error("log reopen failed", "error", err.Error())
				}
				if err := mgr.Reload(); err != nil {
					logs.Service.Error("config reload failed, keeping previous config", "error", err.Error())
					continue
				}
				cfg := mgr.Get()
				for _, w := range cfg.Warnings {
					logs.Service.Warn("config warning", "warning", w)
				}
				for _, w := range store.Reload(tlsParams(cfg)) {
					logs.Service.Warn("tls warning", "warning", w)
				}
				limits = newLimits(cfg)
				updateAll(cfg, limits)
				// Bring up listeners that became possible now that the
				// certificate is loaded — the whole point of this fix,
				// so `verta reload` after installing a certificate no
				// longer needs a `verta restart` to open the mail-access
				// ports.
				for _, err := range ensureListeners(cfg, limits) {
					logs.Service.Error("listener not started", "error", err.Error())
				}
				logs.Service.Info("reload complete",
					"domains", len(cfg.Domains), "tls_loaded", store.Loaded(),
					"listeners", len(*liveListeners.Load()))

			default: // SIGTERM, Interrupt
				logs.Service.Info("shutdown requested", "signal", s.String())
				close(schedStop)
				close(stateStop)
				close(statusStop)
				saveState()
				if apiSrv != nil {
					apiSrv.Shutdown(5 * time.Second)
				}
				for _, r := range servers {
					r.srv.Shutdown(30 * time.Second)
				}
				for _, r := range imapServers {
					r.srv.Shutdown(30 * time.Second)
				}
				for _, r := range pop3Servers {
					r.srv.Shutdown(30 * time.Second)
				}
				logs.Service.Info("stopped", "queued", q.Size())
				return nil
			}
		}
	}
}

// limitSet holds the shared limiter instances: they live across
// settings updates so quotas are not reset by a periodic refresh.
type limitSet struct {
	in  *ratelimit.Inbound
	out *ratelimit.Outbound
	gov *ratelimit.Governor
}

// egressPool builds the outbound source-IP pool from config, or nil when
// none is configured. An address without a public address is skipped.
func egressPool(cfg *config.Config) *egress.Pool {
	var addrs []egress.Address
	for _, a := range cfg.Egress.Addresses {
		if a.Address == "" {
			continue
		}
		addrs = append(addrs, egress.Address{
			Public:  a.Address,
			HELO:    a.HELO,
			Bind:    a.Bind,
			Domains: a.Domains,
		})
	}
	return egress.New(cfg.Egress.Strategy, addrs)
}

// egressSelector resolves the outbound source per envelope: a mailbox
// pinned to an IP wins, then its domain, then the rotation pool's
// strategy. Returns nil when neither pins nor a pool are configured. A
// pin to an IP absent from the pool is logged and ignored.
func egressSelector(cfg *config.Config, log *slog.Logger) func(from, dest string) (bind, helo string) {
	pool := egressPool(cfg)
	mailboxPin := map[string]string{}
	domainPin := map[string]string{}
	for _, u := range cfg.Users {
		if u.Outbound != nil && u.Outbound.EgressIP != "" {
			mailboxPin[strings.ToLower(u.Email)] = u.Outbound.EgressIP
		}
	}
	for _, d := range cfg.Domains {
		if d.Outbound.EgressIP != "" {
			domainPin[d.Name] = d.Outbound.EgressIP
		}
	}
	if pool == nil && len(mailboxPin) == 0 && len(domainPin) == 0 {
		return nil
	}
	pin := func(ip string) (egress.Source, bool) {
		s, ok := pool.ByAddress(ip)
		if !ok {
			log.Warn("egress pin references an IP not in egress.addresses",
				"event", "egress_config", "ip", ip)
		}
		return s, ok
	}
	return func(from, dest string) (bind, helo string) {
		if ip := mailboxPin[strings.ToLower(from)]; ip != "" {
			if s, ok := pin(ip); ok {
				return s.Bind, s.HELO
			}
		}
		if _, sdom, ok := storage.Split(from); ok {
			if ip := domainPin[sdom]; ip != "" {
				if s, ok := pin(ip); ok {
					return s.Bind, s.HELO
				}
			}
		}
		s := pool.Select(from, dest)
		return s.Bind, s.HELO
	}
}

// newLimits builds the limiters from the current config (fresh
// instances on SIGHUP reload, since the rates may have changed).
func newLimits(cfg *config.Config) limitSet {
	var l limitSet
	if in := cfg.RateLimit.Inbound; in.IsEnabled() {
		l.in = ratelimit.NewInbound(
			in.IP.ConnectionsPerMinute, in.IP.MessagesPerMinute, in.IP.RecipientsPerMinute)
	}
	if out := cfg.RateLimit.Outbound; out.IsEnabled() {
		l.out = ratelimit.NewOutbound(out.User.MessagesPerHour, out.User.RecipientsPerHour)
	}
	l.gov = ratelimit.NewGovernor(cfg.GovernorRules())
	return l
}

// smtpSettings maps the current config onto one SMTP listener.
// STARTTLS is offered only when at least one certificate actually
// loaded.
func smtpSettings(cfg *config.Config, store *ktls.Store, mode smtp.Mode, implicit bool, lim limitSet, counters *stats.Counters) smtp.Settings {
	set := smtp.Settings{
		Hostname:      cfg.Server.Hostname,
		MaxSize:       cfg.SMTP.MaxSize,
		MaxRecipients: cfg.SMTP.MaxRecipients,
		Mode:          mode,
		ImplicitTLS:   implicit,
		Limits:        lim.in,
		OutLimits:     lim.out,
		Governor:      lim.gov,
		Stats:         counters,
		Identity: container.Identity{
			Enabled:    cfg.Container.Enabled,
			Hostname:   cfg.Server.Hostname,
			PublicIP:   cfg.Container.PublicIP,
			InternalIP: cfg.Container.InternalIP,
		},
	}
	if !implicit && len(store.Loaded()) > 0 {
		set.TLS = store.Config()
	}
	return set
}

// imapSettings maps the config onto one IMAP listener.
func imapSettings(cfg *config.Config, store *ktls.Store, implicit bool) imap.Settings {
	set := imap.Settings{
		Hostname:    cfg.Server.Hostname,
		ImplicitTLS: implicit,
		MaxSize:     cfg.SMTP.MaxSize,
	}
	if !implicit && len(store.Loaded()) > 0 {
		set.TLS = store.Config()
	}
	return set
}

// pop3Settings maps the config onto one POP3 listener.
func pop3Settings(cfg *config.Config, store *ktls.Store, implicit bool) pop3.Settings {
	set := pop3.Settings{
		Hostname:    cfg.Server.Hostname,
		ImplicitTLS: implicit,
	}
	if !implicit && len(store.Loaded()) > 0 {
		set.TLS = store.Config()
	}
	return set
}

func tlsParams(cfg *config.Config) ktls.Params {
	return ktls.Params{
		CertRoot:       cfg.TLS.CertRoot,
		Hostname:       cfg.Server.Hostname,
		Domains:        cfg.DomainNames(),
		MinVersion:     cfg.TLS.MinVersion,
		ExpiryWarnDays: cfg.TLS.ExpiryWarnDays,
	}
}
