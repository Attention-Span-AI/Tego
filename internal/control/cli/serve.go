// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/internal/control/web"
	"github.com/attention-span-ai/tego/internal/handoff"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/profilesrc"
	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/internal/setup"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// serve's command: the dashboard (docs/DASHBOARD.md), a web view of a ledger root on loopback that also answers
// asks and stops runs, as tego approve, deny and stop do.
func init() { register(cmdServe) }

func cmdServe() Command {
	return Command{
		Name:    "serve",
		Summary: "start the local dashboard", // handoff.Nouns' line, held equal by TestHandoffNounsMatchControlCommands
		Usage:   "[--addr 127.0.0.1:8484] [--ledger DIR] [--open] [--preview]",
		// The dashboard holds the sign-in token, the CSRF and acknowledgement keys and, while a form handles it, a Vault
		// value; mainWith makes the process undumpable before this runs (ADR 0100 (7), amended 2026-11-22).
		HoldsSecrets: true,
		Run: func(ctx context.Context, args []string, stdout, stderr io.Writer) int {
			fs := flag.NewFlagSet(handoff.Name+" serve", flag.ContinueOnError)
			fs.SetOutput(stderr)
			fs.Usage = func() { // tego serve hands off here, so -h names the command a person typed
				fmt.Fprintln(fs.Output(), "usage: tego serve [--addr 127.0.0.1:8484] [--ledger DIR] [--open] [--preview]")
				fmt.Fprintln(fs.Output())
				fs.PrintDefaults()
			}
			addr := fs.String("addr", "127.0.0.1:8484", "loopback address and port to listen on, such as [::1]:8484 (port 0 picks one)")
			ledger := fs.String("ledger", "", "ledger root to read (default: the ledger_root tego writes runs to)")
			open := fs.Bool("open", false, "open the dashboard, signed in, in the browser ($BROWSER, else xdg-open) once it listens")
			preview := fs.Bool("preview", false, "also list the preview pages in the nav")
			if err := fs.Parse(args); err != nil {
				if err == flag.ErrHelp {
					return identity.ExitOK
				}
				return exits[codeUsage]
			}
			if fs.NArg() != 0 {
				diag(stderr, handoff.Name+" serve: takes no arguments", codeUsage, "run "+handoff.Name+" serve --addr 127.0.0.1:8484")
				return exits[codeUsage]
			}
			if os.Getenv("TEGO_HOST_KIND") == "windows" {
				// A dashboard of its own here prints a 127.0.0.1 link that reaches WSL's forwarding from Windows, which
				// the peer check refuses. The dashboard on Windows is tego dashboard's, opened through the Windows
				// command's relay (docs/adr/0123-dashboard-threat-model.md, "A browser on Windows").
				fmt.Fprintln(stderr, "tego serve: on Windows the dashboard opens with tego dashboard; in Tego's Linux shell, type exit, then run: tego dashboard")
				return identity.ExitFinding
			}
			listen, err := loopbackAddr(*addr)
			if err != nil {
				diag(stderr, handoff.Name+" serve: "+err.Error(), codeUsage, "use --addr 127.0.0.1:<port>")
				return exits[codeUsage]
			}
			// One snapshot supplies the report, served root, anchor and every current-rule check.
			mr := loadMachineReport(config.TrustWarn)
			addrSet := false
			fs.Visit(func(f *flag.Flag) {
				if f.Name == "addr" {
					addrSet = true
				}
			})
			if !addrSet && mr.err == nil && mr.m.ServePort.Value != 0 && mr.m.ServePort.Source.Layer != config.LayerBuiltin {
				listen = net.JoinHostPort("127.0.0.1", strconv.Itoa(mr.m.ServePort.Value))
			}
			root := *ledger
			if root == "" {
				if mr.err != nil {
					diag(stderr, handoff.Name+" serve: machine config: "+mr.err.Error(), codeIO, "check the configuration file")
					return exits[codeIO]
				}
				if root, err = reportLedgerRoot(mr); err != nil {
					diag(stderr, handoff.Name+" serve: ledger root: "+err.Error(), codeIO, "pass --ledger DIR")
					return exits[codeIO]
				}
			}
			var machine *config.Machine
			if mr.err == nil {
				machine = mr.m
			}
			root, scope, err := setup.DashboardScope(machine, root)
			if err != nil {
				diag(stderr, handoff.Name+" serve: dashboard identity: "+err.Error(), codeIO, "check the configuration and ledger folder")
				return exits[codeIO]
			}
			ln, err := net.Listen("tcp", listen)
			if err != nil {
				diag(stderr, handoff.Name+" serve: listen: "+err.Error(), codeIO, "pick another port with --addr 127.0.0.1:<port>")
				return exits[codeIO]
			}
			defer func() { _ = ln.Close() }()
			// The chain anchor the run page and the overview verify against; unknown leaves every chain unchecked.
			anchor, anchorErr := reportAnchorPath(mr)
			// The machine config the Rules page compiles each run's contract against; unreadable shows them uncompiled.
			rs := ruleService(root, anchor, machine, mr.secure)
			at := ln.Addr().(*net.TCPAddr) // the links name the address listened on: 127.0.0.1, another 127.x.y.z, or ::1
			srv, err := web.New(web.Config{Ledger: root, Anchor: anchor, Host: at.IP.String(), Port: at.Port, Machine: machine,
				Profiles: profilesrc.Chain(machine), Rules: rs, Setup: rs, Preview: *preview, SeverityFile: severityFile(),
				Guide: guideInputs(machine, root, anchor)})
			if err != nil {
				diag(stderr, handoff.Name+" serve: "+err.Error(), codeIO, "report this build")
				return exits[codeIO]
			}
			go srv.Prewarm(ctx) // read the ledger and check the chains now, so the first page is already warm
			// Line 1 stays byte for byte: launch_test, open_test and the e2e suites read the URL from it. What it serves
			// follows on stderr, so "the dashboard shows another ledger" is visible at a glance.
			if _, err := fmt.Fprintf(stdout, "Tego dashboard: %s\n", srv.URL()); err != nil {
				return exits[codeIO]
			}
			// The program this dashboard runs, by the SHA-256 of its own bytes (handoff.ProgramLine), is the first line on
			// stderr, which the unit's log holds beside stdout: tego dashboard and tego start reuse the dashboard when the
			// program they would start has the same bytes. Not read: no line, and no later tego reuses this dashboard.
			if sum, err := handoff.SelfSum(); err == nil {
				_, _ = io.WriteString(stderr, handoff.ProgramLine(sum))
			}
			// The dashboard is non-dumpable, so a scan of this user's processes cannot read its program file. It holds a lock
			// the scan can prove (runlock.HoldDashboard), as a launcher does for its run, so the scan names it and does not
			// count it as a program it cannot read. A dashboard that cannot take the lock (another one holds it, or the
			// folder is not writable) serves all the same and stays among the unreadable programs.
			if home := dashboardLockHome(machine); home != "" {
				if lock, err := runlock.HoldDashboard(home); err != nil {
					_, _ = fmt.Fprintf(stderr, "%s serve: a scan of your processes will count this dashboard among the programs it cannot read: %v\n", handoff.Name, err)
				} else {
					defer func() { _ = lock.Close() }()
				}
			}
			writeServeFacts(stderr, serveFacts{root: root, flagLedger: *ledger != "", machine: mr, anchor: anchor, anchorErr: anchorErr})
			if *open {
				// The listener is up (a connection waits in its queue until Serve runs), so the page is there when the
				// browser asks. Never a reason to stop: without an opener the person has the URL printed above. The
				// opener gets a one-time code, not the token: a browser keeps its arguments in a process list for as
				// long as it runs (web/opencode.go).
				if err := openURL(srv.OpenURL(), os.Getenv("BROWSER")); err != nil {
					_, _ = fmt.Fprintf(stderr, "%s serve: --open: %v; open the URL above\n", handoff.Name, err)
				}
			}
			if err := web.Serve(ctx, ln, dashboardIdentity(srv, srv.URL(), scope)); err != nil {
				diag(stderr, handoff.Name+" serve: "+err.Error(), codeIO, "start it again")
				return exits[codeIO]
			}
			return identity.ExitOK
		},
	}
}

// machineLockHome is the home the dashboard's lock lives under: the machine's, else the account's; "" holds no lock.
func machineLockHome(m *config.Machine) string {
	if m != nil && m.Home != "" {
		return m.Home
	}
	h, _ := os.UserHomeDir()
	return h
}

// dashboardLockHome is machineLockHome in the product. A variable so a binary built with -tags tegotesthooks keeps the
// lock where its tests say (dashboardlock_testhook.go), as it keeps the chain anchor, and a test of this package's own
// keeps none in the developer's home (TestMain).
var dashboardLockHome = machineLockHome

// loopbackAddr accepts only a loopback IP and a port: 127.0.0.0/8 (localhost read as 127.0.0.1) or ::1. The peer
// check reads an IPv6 client's socket in /proc/net/tcp6 and the governed check asks sock_diag in AF_INET6, so [::1]
// is held as 127.0.0.1 is (web/peer.go, web/governed.go).
func loopbackAddr(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("--addr %q: %w", addr, err)
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("--addr %q: the dashboard listens on a loopback address only", addr)
	}
	return net.JoinHostPort(ip.String(), port), nil
}

// anchorPath resolves the chain anchor the dashboard checks runs against. It is a variable so a binary built with
// the tegotesthooks tag (anchor_testhook.go) reads the anchor its tests name, as tego's own test build does.
var anchorPath = machineAnchorPath

// machineAnchorPath is the chain anchor `tego events <run> --verify` checks against: ledger.AnchorPath, the rule
// tego's own launcher anchors by (internal/runtime's AnchorPath, which this package may not import,
// TestControlLinksNoEngine, calls it too), over the invoking user's passwd home: its ~/.tego/chain.log, or for an
// account with no home the chain.log beside the machine's ledger root, resolved as serve resolves the root it shows.
func machineAnchorPath(m *config.Machine, secure bool) (string, error) {
	return ledger.AnchorPath(m.Home, func() (string, error) { return ledgerRootOf(m, secure) })
}

func reportLedgerRoot(r machineReport) (string, error) {
	if r.err != nil {
		return "", r.err
	}
	if r.m == nil {
		return "", errors.New("machine config could not be read")
	}
	return ledgerRootOf(r.m, r.secure)
}

func reportAnchorPath(r machineReport) (string, error) {
	if r.err != nil {
		return "", r.err
	}
	if r.m == nil {
		return "", errors.New("machine config could not be read")
	}
	return anchorPath(r.m, r.secure)
}

// machineReport retains one config snapshot and every diagnostic, including unknown layer reasons.
type machineReport struct {
	m      *config.Machine
	secure bool
	diags  []config.Diagnostic
	err    error
}

var loadMachineSnapshot = config.LoadSources

// loadMachineReport resolves and loads one invoking-user snapshot, retaining its diagnostics.
func loadMachineReport(mode config.TrustMode) machineReport {
	uid, _ := config.InvokingUID()
	secure, err := config.DetectSecureExec()
	if err != nil {
		return machineReport{err: err}
	}
	src, home, diags := config.Resolve(uid, secure)
	m, more, err := loadMachineSnapshot(src, home, uid, mode)
	return machineReport{m: m, secure: secure, diags: append(diags, more...), err: err}
}

// serveFacts is what serve says about what it serves, after the URL line.
type serveFacts struct {
	root       string
	flagLedger bool
	machine    machineReport
	anchor     string
	anchorErr  error
}

// writeServeFacts prints, on w, the ledger root with where it came from and how many runs it holds, the chain
// anchor runs are checked against (or why there is none), and the machine config's diagnostics, so a dashboard
// showing a fallback ledger after a failed layer is visible at start, with the UNKNOWN baseline
// and its cause. Read pages and stop remain useful; permission changes require a known config.
func writeServeFacts(w io.Writer, f serveFacts) {
	_, _ = fmt.Fprintf(w, "  ledger: %s (from %s), %s\n", record.Printable(f.root), ledgerOrigin(f), runCount(f.root))
	if f.anchorErr != nil {
		_, _ = fmt.Fprintf(w, "  chains: no anchor found (%s); runs show as unverified\n", record.Printable(f.anchorErr.Error()))
	} else {
		_, _ = fmt.Fprintf(w, "  chains: checked against %s\n", record.Printable(f.anchor))
	}
	for _, d := range f.machine.diags {
		_, _ = fmt.Fprintf(w, "  config: %s\n", record.Printable(d.String()))
	}
	if f.machine.err != nil {
		_, _ = fmt.Fprintf(w, "  config: baseline UNKNOWN: it could not be read: %s\n", record.Printable(f.machine.err.Error()))
	}
}

// ledgerOrigin names where the served ledger root came from: --ledger, the layer file that set ledger_root
// ($TEGO_CONFIG named as such), or the built-in default.
func ledgerOrigin(f serveFacts) string {
	if f.flagLedger {
		return "--ledger"
	}
	if f.machine.m == nil {
		return "default"
	}
	src := f.machine.m.LedgerRoot.Source
	switch {
	case src.Layer == config.LayerBuiltin || src.File == "":
		return "default"
	case src.Layer == config.LayerEnvFile:
		// The settings file is a place and is named; a value that is not an absolute clean path is not echoed
		// (pkg/spec/identity envtext.go, rules (b) and (c)).
		if !identity.EnvPlace(src.File) {
			return config.EnvConfigVar + " (not an absolute clean path; " + identity.EnvInspect(config.EnvConfigVar) + ")"
		}
		return config.EnvConfigVar + " " + record.Printable(src.File)
	default:
		return record.Printable(src.File)
	}
}

// runCount says how many runs root holds: its directories named r-*, as the ledger names a run (RUN-IDENTITY.md).
func runCount(root string) string {
	entries, err := os.ReadDir(root)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "0 runs (the folder does not exist yet)"
	case err != nil:
		return "runs unknown (" + err.Error() + ")"
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "r-") {
			n++
		}
	}
	if n == 1 {
		return "1 run"
	}
	return strconv.Itoa(n) + " runs"
}

// ledgerRootOf is m's ledger_root, a leading ~/ expanded.
func ledgerRootOf(m *config.Machine, secure bool) (string, error) {
	root := m.LedgerRoot.Value
	if strings.HasPrefix(root, "~/") {
		h := m.Home
		if h == "" && !secure {
			h, _ = os.UserHomeDir()
		}
		if h == "" {
			return "", fmt.Errorf("ledger_root %q needs a home directory", root)
		}
		root = filepath.Join(h, root[2:])
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("ledger_root %q is not absolute", root)
	}
	return root, nil
}

// severityFile is where the dashboard keeps the person's own severity rules: tego's folder under the user's config
// directory; "" (no Severity page) when there is none.
func severityFile() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "tego", "severity.json")
}

// dashboardIdentity proves to the local CLI that a listener owns the private sign-in token without receiving it.
// It grants no dashboard access. Ordinary requests still pass through the dashboard's existing checks.
func dashboardIdentity(next http.Handler, link, scope string) http.Handler {
	u, err := url.Parse(link)
	if err != nil {
		return next
	}
	token := u.Query().Get("t")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_tego/identity" {
			next.ServeHTTP(w, r)
			return
		}
		nonce := r.URL.Query().Get("challenge")
		_, err := hex.DecodeString(nonce)
		if token == "" || r.Method != http.MethodGet || r.Host != u.Host || len(nonce) != 64 || err != nil {
			http.Error(w, "invalid dashboard challenge", http.StatusBadRequest)
			return
		}
		mac := hmac.New(sha256.New, []byte(token))
		_, _ = mac.Write([]byte("tego-dashboard-v1\n" + nonce + "\n" + scope))
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, hex.EncodeToString(mac.Sum(nil)))
	})
}
