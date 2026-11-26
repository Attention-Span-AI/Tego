// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/handoff"
	"github.com/attention-span-ai/tego/internal/setup"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func init() { register(cmdDashboard) }

// cmdDashboard is `tego dashboard`: the one dashboard, a user unit that tego start starts too. One already running is
// offered first (open it, or start a new one, which signs out its tabs); with no terminal it is reused. On a Mac
// (including legacy TEGO_ON_MAC), the host command opens its link. On Windows the link is never printed: from
// Windows its 127.0.0.1 address reaches WSL's own forwarding, which the dashboard refuses; the Windows tego command
// opens the dashboard through its relay instead (docs/adr/0123-dashboard-threat-model.md, "A browser on Windows"),
// and a shell inside Tego's Linux is told to run it there. On Linux the link is printed.
// shortcut: no browser is opened on Linux; tego serve --open does that for a dashboard of its own.
func cmdDashboard() Command {
	return Command{
		Name:    "dashboard",
		Summary: "open the dashboard in your browser",
		Usage:   "",
		Flags:   func(*flag.FlagSet) {},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 0 {
				message(stderr, "", 0, 0, "tego dashboard: takes no arguments", codeUsage)
				return identity.ExitUsage
			}
			host := setupHost()
			m, cds, err := loadMachine(config.TrustWarn)
			writeConfigDiagnostics(stderr, cds)
			if err != nil {
				message(stderr, "", 0, 0, "tego dashboard: machine config: "+err.Error(), config.CodeUntrusted)
				return identity.ExitError
			}
			g := newWalk(os.Stdin, stdout, guideInteractive(stdout))
			g.col = colTop
			// shown is how a link is printed here: on Windows not at all (see above).
			shown := func(u string) string {
				if host == hostWindows {
					return ""
				}
				return ": " + u
			}
			u, current := dashboardAt(m.Home)
			// A dashboard that answers needs no start; one that has to be started needs the user's manager and its bus.
			if !(u != "" && current) {
				if p := classifyUserBus(userBusProbe()); p.found() {
					writeUserBusProblem(g, p)
					return identity.ExitError
				}
			}
			switch {
			case u != "" && current:
				g.ok("The dashboard is already running" + shown(u))
				if !g.tty {
					break
				}
				pick, err := g.chooseOne("Open it, or start a new one?", []choice{
					{name: "Open it", desc: "Tabs already open stay signed in", recommended: true},
					{name: "Start a new one", desc: "Stops this one; its open tabs are signed out"},
				})
				if err != nil {
					return identity.ExitFinding // left the question: nothing changed
				}
				if pick == 1 {
					if u = restartDashboard(ctx, m.Home); u == "" {
						return dashboardFailed(g, m.Home)
					}
					g.ok("Started a new dashboard" + shown(u))
				}
			case u != "":
				if u = restartDashboard(ctx, m.Home); u == "" {
					return dashboardFailed(g, m.Home)
				}
				if why := unreadableProgram(); why != "" {
					g.ok("Started the dashboard again: " + why + shown(u))
				} else {
					g.ok("Started the dashboard again, on the updated tego" + shown(u))
				}
			default:
				if u = guideDashboard(ctx, m.Home); u == "" {
					return dashboardFailed(g, m.Home)
				}
				g.ok("Started the dashboard" + shown(u))
			}
			switch {
			case host == hostLinux:
				g.line("%s  %sOpen the link above in your browser.%s", colTop, g.dim, g.offEsc)
			case host == hostWindows && !windowsNative():
				// A shell inside Tego's Linux cannot start a Windows browser.
				g.line("%s  %sTo open it in your browser, type exit, then run tego dashboard in Windows%s", colTop, g.dim, g.offEsc)
			}
			return identity.ExitOK
		},
	}
}

// windowsNative reports whether the Windows tego command ran this command (the guest entry says so), which opens
// the dashboard in the person's browser when it returns.
func windowsNative() bool { return os.Getenv("TEGO_WINDOWS_NATIVE") == "1" }

// restartDashboard stops the running dashboard and starts a new one: with its log emptied, guideDashboard finds no
// dashboard to reuse.
func restartDashboard(ctx context.Context, home string) string {
	if err := replaceGuideFile(home, ".tego/dashboard.log", nil, 0o600); err != nil {
		return ""
	}
	return guideDashboard(ctx, home)
}

func dashboardFailed(g *walk, home string) int {
	if windowsNative() {
		// The log is inside Tego's Linux, where a Windows person cannot open ~/.tego/dashboard.log: name the command that
		// reads it from Windows, and show its last lines (their sign-in links hidden) so the reason is often on screen.
		g.bad(`The dashboard didn't start. Its log is inside Tego's Linux; to read it, run: tego shell -c "tail -n 40 ~/.tego/dashboard.log"`)
		for _, l := range dashboardLogTail(home, dashboardLogLines) {
			g.detail("  " + l)
		}
		return identity.ExitError
	}
	g.bad("The dashboard didn't start. Its log: " + tildeHome(dashboardLog(home), home))
	return identity.ExitError
}

// dashboardLogLines is how many of the log's last lines a Windows person is shown when the dashboard did not start.
const dashboardLogLines = 6

// dashboardLogTail is the last n non-empty lines of the dashboard's log, each at most 160 characters with control
// characters removed, and with the dashboard's sign-in token hidden wherever it appears (a link, or any "t=<token>"):
// the token signs a browser in, so it is never printed. An unreadable or empty log gives none.
func dashboardLogTail(home string, n int) []string {
	b, err := readGuideFile(home, ".tego/dashboard.log")
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.Map(func(r rune) rune {
			if r < ' ' || r == 0x7f {
				return -1 // strings.Map drops the rune: not an exit code (I9)
			}
			return r
		}, l)
		if l = strings.TrimSpace(logToken.ReplaceAllString(l, "${1}t=(hidden)")); l == "" {
			continue
		}
		if r := []rune(l); len(r) > 160 {
			l = string(r[:160]) + "…"
		}
		out = append(out, l)
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}

// logToken is a sign-in token in a line of the dashboard's log: the value of a t= parameter, in a link (?t=, &t=), at the
// start of a line, after a space, a comma, a semicolon or in a fragment (#t=).
var logToken = regexp.MustCompile(`(^|[?&#\s,;])t=[0-9A-Za-z._~-]+`)

// dashboardLink is the sign-in link tego serve prints when it starts.
var dashboardLink = regexp.MustCompile(`http://(127\.0\.0\.1:[0-9]+)/\?t=[0-9a-f]+`)

// dashboardLog is where tego start's dashboard writes what tego serve prints.
func dashboardLog(home string) string { return filepath.Join(home, ".tego", "dashboard.log") }

// runningDashboard is the link of the dashboard tego start left running, when it runs this tego; "" otherwise.
func runningDashboard(home string) string {
	if u, current := dashboardAt(home); current {
		return u
	}
	return ""
}

// dashboardAt is the link of the dashboard tego start left running, "" when none answers at its address, and whether
// it runs the program a dashboard started now would run. That is decided by content: the log carries the SHA-256 of
// the bytes the dashboard runs (written by the dashboard itself from /proc/self/exe, handoff.ProgramLine), and the
// program tego would start is tego-control with the hash this build pinned. The same bytes are the same program
// whatever the inode, the memfd the handoff copied them into or the modification time; the file attributes the earlier
// identity compared (device, inode, size, times) named another memfd on every launch, so it never matched. A log with no such
// line is from a tego before it, so not this one. The listener must prove possession of the private sign-in token
// before a link is reused or printed.
func dashboardAt(home string) (string, bool) { return dashboardWithin(home, 300*time.Millisecond) }

// dashboardWithin is dashboardAt with the identity probe's time limit: the Windows relay's Linux end, which checks
// a dashboard already serving pages, allows it longer (dashboard_relay.go).
func dashboardWithin(home string, limit time.Duration) (string, bool) {
	b, err := readGuideFile(home, ".tego/dashboard.log")
	if err != nil {
		return "", false
	}
	m := dashboardLink.FindSubmatch(b)
	if m == nil {
		return "", false
	}
	if !probeDashboardWithin(string(m[0]), limit) {
		return "", false
	}
	// A program that cannot be named is no proof: the dashboard is not reused unchecked.
	want, ok := thisProgram()
	started, recorded := handoff.RecordedProgram(b)
	return string(m[0]), ok && recorded && started == want
}

// unreadableProgram says why a dashboard that answers is not reused when the program a new one would run cannot be
// named, else "".
func unreadableProgram() string {
	if _, ok := thisProgram(); ok {
		return ""
	}
	return "this tego has no pinned tego-control to compare the running dashboard with"
}

// thisProgram is the SHA-256 of the program a dashboard started now would run: tego-control, whose bytes the handoff
// verifies against the hash this build pinned before it runs anything. When this build pins none (it hands off
// nothing) the dashboard is not reused (unreadableProgram says why). A variable so a test names another program.
var thisProgram = handoff.PinnedSum

// probeDashboard sends a fresh challenge, never the sign-in token, to a listener that has not yet been trusted.
func probeDashboard(link string) bool { return probeDashboardWithin(link, 300*time.Millisecond) }

func probeDashboardWithin(link string, limit time.Duration) bool {
	_, _, scope, err := dashboardConfiguration()
	if err != nil {
		return false
	}
	u, err := url.Parse(link)
	if err != nil {
		return false
	}
	token := u.Query().Get("t")
	if token == "" {
		return false
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return false
	}
	challenge := hex.EncodeToString(nonce[:])
	u.Path, u.RawQuery = "/_tego/identity", "challenge="+challenge
	client := &http.Client{Timeout: limit, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("dashboard probe redirects are refused") }}
	defer client.CloseIdleConnections()
	resp, err := client.Get(u.String())
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	proof, err := io.ReadAll(io.LimitReader(resp.Body, 257))
	if err != nil || len(proof) != 64 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write([]byte("tego-dashboard-v1\n" + challenge + "\n" + scope))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal(proof, []byte(expected))
}

// dashboardConfiguration names the shell's intended ledger and loaded effective machine configuration.
// It is passed to the unit and authenticated in the reuse probe, so the user manager cannot select a different one.
func dashboardConfiguration() (root, file, scope string, err error) {
	m, _, err := loadMachine(config.TrustWarn)
	if err != nil {
		return "", "", "", err
	}
	if !m.BaselineKnown() {
		return "", "", "", errors.New("cannot authenticate dashboard configuration: a machine configuration layer is unknown; fix the configuration before opening its link")
	}
	root, err = ledgerRootOf(m)
	if err != nil {
		return "", "", "", err
	}
	file = os.Getenv(config.EnvConfigVar)
	if file != "" {
		file, err = filepath.Abs(file)
		if err != nil {
			return "", "", "", err
		}

	}
	root, scope, err = setup.DashboardScope(m, root)
	return root, file, scope, err
}
