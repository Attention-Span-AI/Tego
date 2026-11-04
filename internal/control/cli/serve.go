// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/internal/control/web"
	"github.com/attention-span-ai/tego/internal/handoff"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/profilesrc"
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
		Run: func(ctx context.Context, args []string, stdout, stderr io.Writer) int {
			fs := flag.NewFlagSet(handoff.Name+" serve", flag.ContinueOnError)
			fs.SetOutput(stderr)
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
			listen, err := loopbackAddr(*addr)
			if err != nil {
				diag(stderr, handoff.Name+" serve: "+err.Error(), codeUsage, "use --addr 127.0.0.1:<port>")
				return exits[codeUsage]
			}
			// The machine config, read once for the startup lines: what it said is printed, never dropped.
			mr := loadMachineReport()
			if why, code := mr.envSkip(); why != "" && *ledger == "" {
				// $TEGO_CONFIG names the ledger the person meant; serving the default one instead shows other runs
				// under a calm page, so serve refuses to start (CO-P5). --ledger says which ledger outright.
				fix := "create the file or fix what does not parse"
				if code == config.CodeUntrusted {
					fix = "make the file yours, mode 600, in a folder only you can write"
				}
				diag(stderr, fmt.Sprintf("%s serve: %s %s was skipped (%s), so the dashboard would show the default "+
					"ledger, not that file's", handoff.Name, config.EnvConfigVar, record.Printable(mr.envFile), record.Printable(why)),
					code, fix+", or unset "+config.EnvConfigVar+", or name the ledger with --ledger DIR")
				return exits[codeIO]
			}
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
				if root, err = machineLedgerRoot(); err != nil {
					diag(stderr, handoff.Name+" serve: ledger root: "+err.Error(), codeIO, "pass --ledger DIR")
					return exits[codeIO]
				}
			}
			if root, err = filepath.Abs(root); err != nil {
				diag(stderr, handoff.Name+" serve: ledger root: "+err.Error(), codeUsage, "pass --ledger DIR")
				return exits[codeUsage]
			}
			ln, err := net.Listen("tcp", listen)
			if err != nil {
				diag(stderr, handoff.Name+" serve: listen: "+err.Error(), codeIO, "pick another port with --addr 127.0.0.1:<port>")
				return exits[codeIO]
			}
			defer func() { _ = ln.Close() }()
			// The chain anchor the run page and the overview verify against; unknown leaves every chain unchecked.
			anchor, anchorErr := anchorPath()
			// The machine config the Rules page compiles each run's contract against; unreadable shows them uncompiled.
			var machine *config.Machine
			if mr.err == nil {
				machine = mr.m
			}
			rs := ruleService(root, anchor, machine)
			at := ln.Addr().(*net.TCPAddr) // the links name the address listened on: 127.0.0.1, another 127.x.y.z, or ::1
			srv, err := web.New(web.Config{Ledger: root, Anchor: anchor, Host: at.IP.String(), Port: at.Port, Machine: machine,
				Profiles: profilesrc.Chain(machine), Rules: rs, Setup: rs, Preview: *preview, SeverityFile: severityFile()})
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
			if err := web.Serve(ctx, ln, srv); err != nil {
				diag(stderr, handoff.Name+" serve: "+err.Error(), codeIO, "start it again")
				return exits[codeIO]
			}
			return identity.ExitOK
		},
	}
}

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

// machineLedgerRoot is the ledger_root tego writes runs to: the machine config's (TEGO_CONFIG, the layer files),
// with a leading ~/ expanded against the passwd home, as tego's own runtime.LedgerRoot does.
func machineLedgerRoot() (string, error) {
	m, secure, err := loadMachine()
	if err != nil {
		return "", err
	}
	return ledgerRootOf(m, secure)
}

// anchorPath resolves the chain anchor the dashboard checks runs against. It is a variable so a binary built with
// the tegotesthooks tag (anchor_testhook.go) reads the anchor its tests name, as tego's own test build does.
var anchorPath = machineAnchorPath

// machineAnchorPath is the chain anchor `tego events <run> --verify` checks against: ledger.AnchorPath, the rule
// tego's own launcher anchors by (internal/runtime's AnchorPath, which this package may not import,
// TestControlLinksNoEngine, calls it too), over the invoking user's passwd home: its ~/.tego/chain.log, or for an
// account with no home the chain.log beside the machine's ledger root, resolved as serve resolves the root it shows.
func machineAnchorPath() (string, error) {
	m, secure, err := loadMachine()
	if err != nil {
		return "", err
	}
	return ledger.AnchorPath(m.Home, func() (string, error) { return ledgerRootOf(m, secure) })
}

// loadMachine is the machine config as tego loads it (TEGO_CONFIG, the layer files), and whether this is AT_SECURE.
func loadMachine() (*config.Machine, bool, error) {
	r := loadMachineReport()
	if r.err != nil {
		return nil, false, r.err
	}
	return r.m, r.secure, nil
}

// machineReport is one load of the machine config with what the load said about it: the layer $TEGO_CONFIG named
// (envFile, "" when unset or AT_SECURE) and every diagnostic, so serve can print them instead of dropping them.
type machineReport struct {
	m       *config.Machine
	secure  bool
	envFile string
	diags   []config.Diagnostic
	err     error
}

// loadMachineReport loads the machine config as loadMachine does, keeping the diagnostics.
func loadMachineReport() machineReport {
	uid, _ := config.InvokingUID()
	secure, err := config.DetectSecureExec()
	if err != nil {
		return machineReport{err: err}
	}
	src, home, diags := config.Resolve(uid, secure)
	m, more, err := config.LoadSources(src, home, uid, config.TrustWarn)
	return machineReport{m: m, secure: secure, envFile: src.EnvFile, diags: append(diags, more...), err: err}
}

// envSkipped says why the $TEGO_CONFIG layer was skipped, or "" when it was read (or none was named). In TrustWarn
// mode a missing, untrusted or invalid layer is a warning on that file whose fix ends "The layer was skipped."
// (pkg/spec/config skipOrAbort and demote); the first such message is the reason.
func (r machineReport) envSkipped() string {
	if r.envFile == "" {
		return ""
	}
	if r.err != nil {
		return r.err.Error()
	}
	for _, d := range r.diags {
		if d.File == r.envFile && strings.Contains(d.Fix, "The layer was skipped") {
			return d.Message
		}
	}
	return ""
}

// envSkip is envSkipped with the skipped layer's reason code: config-untrusted for a file that failed the trust
// check, config-invalid otherwise (a missing file, one that does not parse).
func (r machineReport) envSkip() (why, code string) {
	why = r.envSkipped()
	if why == "" {
		return "", ""
	}
	code = config.CodeInvalid
	if r.err != nil {
		code = config.CodeUntrusted
	}
	for _, d := range r.diags {
		if d.File == r.envFile && strings.Contains(d.Fix, "The layer was skipped") && d.Code != "" {
			code = d.Code
			break
		}
	}
	return why, code
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
// showing another ledger than the one meant is visible at start. A skipped $TEGO_CONFIG without --ledger never gets
// here: serve refuses it before it listens (envSkip). It never changes serve's exit code: the dashboard of the ledger
// it names is still useful.
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
