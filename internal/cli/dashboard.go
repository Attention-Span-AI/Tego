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
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func init() { register(cmdDashboard) }

// cmdDashboard is `tego dashboard`: the one dashboard, a user unit that tego start starts too. One already running is
// offered first (open it, or start a new one, which signs out its tabs); with no terminal it is reused. On a Mac
// (TEGO_ON_MAC) the tego command on the Mac opens the link in the Mac's browser; elsewhere the link is printed.
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
			m, cds, err := loadMachine(config.TrustWarn)
			writeConfigDiagnostics(stderr, cds)
			if err != nil {
				message(stderr, "", 0, 0, "tego dashboard: machine config: "+err.Error(), config.CodeUntrusted)
				return identity.ExitError
			}
			g := newWalk(os.Stdin, stdout, guideInteractive(stdout))
			g.col = colTop
			u, current := dashboardAt(m.Home)
			switch {
			case u != "" && current:
				g.ok("The dashboard is already running: " + u)
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
					if u = restartDashboard(m.Home); u == "" {
						return dashboardFailed(g, m.Home)
					}
					g.ok("Started a new dashboard: " + u)
				}
			case u != "":
				if u = restartDashboard(m.Home); u == "" {
					return dashboardFailed(g, m.Home)
				}
				g.ok("Started the dashboard again, on the updated tego: " + u)
			default:
				if u = guideDashboard(m.Home); u == "" {
					return dashboardFailed(g, m.Home)
				}
				g.ok("Started the dashboard: " + u)
			}
			if os.Getenv("TEGO_ON_MAC") != "1" {
				g.line("%s  %sOpen the link above in your browser.%s", colTop, g.dim, g.offEsc)
			}
			return identity.ExitOK
		},
	}
}

// restartDashboard stops the running dashboard and starts a new one: with its log emptied, guideDashboard finds no
// dashboard to reuse.
func restartDashboard(home string) string {
	if err := replaceGuideFile(home, ".tego/dashboard.log", nil, 0o600); err != nil {
		return ""
	}
	return guideDashboard(home)
}

func dashboardFailed(g *walk, home string) int {
	g.bad("The dashboard didn't start. Its log: " + tildeHome(dashboardLog(home), home))
	return identity.ExitError
}

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
// it runs this tego: false when tego was updated after it started (its log is older than this program).
// The listener must prove possession of the private sign-in token before a link is reused or printed.
func dashboardAt(home string) (string, bool) {
	log := dashboardLog(home)
	fi, err := os.Lstat(log)
	if err != nil {
		return "", false
	}
	b, err := readGuideFile(home, ".tego/dashboard.log")
	if err != nil {
		return "", false
	}
	m := dashboardLink.FindSubmatch(b)
	if m == nil {
		return "", false
	}
	if !probeDashboard(string(m[0])) {
		return "", false
	}
	current := true
	if self, err := os.Executable(); err == nil {
		if si, err := os.Stat(self); err == nil && si.ModTime().After(fi.ModTime()) {
			current = false
		}
	}
	return string(m[0]), current
}

// probeDashboard sends a fresh challenge, never the sign-in token, to a listener that has not yet been trusted.
func probeDashboard(link string) bool {
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
	client := &http.Client{Timeout: 300 * time.Millisecond, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("dashboard probe redirects are refused") }}
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

// dashboardConfiguration names the shell's intended ledger and config, including that file's current contents.
// It is passed to the unit and authenticated in the reuse probe, so the user manager cannot select a different one.
func dashboardConfiguration() (root, file, scope string, err error) {
	m, _, err := loadMachine(config.TrustWarn)
	if err != nil {
		return "", "", "", err
	}
	root, err = ledgerRootOf(m)
	if err != nil {
		return "", "", "", err
	}
	file = os.Getenv(config.EnvConfigVar)
	var data []byte
	if file != "" {
		file, err = filepath.Abs(file)
		if err != nil {
			return "", "", "", err
		}
		data, err = os.ReadFile(file)
		if err != nil {
			return "", "", "", err
		}
	}
	sum := sha256.Sum256([]byte(root + "\x00" + file + "\x00" + string(data)))
	return root, file, hex.EncodeToString(sum[:]), nil
}
