// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// dirs is a directory probe that answers from a fixed set, so the rules are tested without the
// machine's own /home.
func dirs(existing ...string) func(string) bool {
	return func(p string) bool {
		for _, e := range existing {
			if p == e {
				return true
			}
		}
		return false
	}
}

// TestAnchorPathIsTheUsersNotTheLedgerRoots is CHAIN-ANCHOR-PATH: the anchor is ~/.tego/chain.log of
// the invoking user (P0-DESIGN §3.3) whatever ledger_root says. It used to be <ledger_root>/../chain.log,
// which on the documented server setting put every user's anchor in one shared /var/lib/tego/chain.log.
func TestAnchorPathIsTheUsersNotTheLedgerRoots(t *testing.T) {
	m := config.Builtin()
	m.Home = "/home/u"
	m.LedgerRoot = config.Setting[string]{Value: "/var/lib/tego/runs"}
	got, err := anchorPath(m, notSecure, func() (string, error) { return "/home/env", nil }, dirs("/home/u"))
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join("/home/u", ".tego", ledger.ChainLogFile); got != want {
		t.Fatalf("anchor %q, want %q", got, want)
	}
}

// TestAnchorPathWithoutAHome: an account with no home — no passwd entry, or a passwd home that does not
// exist (a service account's /nonexistent) — anchors beside its ledger root, the one place its runs
// already write, and does so whether or not the process is AT_SECURE: the file-capability launcher, the
// plain binary and `events --verify` must all name one file. $HOME is never read for it (R21), and the
// home itself is never created.
func TestAnchorPathWithoutAHome(t *testing.T) {
	attacker := func() (string, error) { return "/tmp/attacker", nil }
	for _, home := range []string{"", "/nonexistent"} {
		m := config.Builtin()
		m.Home = home
		m.LedgerRoot = config.Setting[string]{Value: "/srv/tego/runs"}
		for name, secure := range map[string]func() (bool, error){"plain": notSecure, "AT_SECURE": isSecure, "unreadable auxv": failedAuxv} {
			got, err := anchorPath(m, secure, attacker, dirs("/home/u"))
			if err != nil || got != "/srv/tego/"+ledger.ChainLogFile {
				t.Fatalf("home %q, %s: %q %v, want the chain.log beside /srv/tego/runs", home, name, got, err)
			}
		}
	}
}

// TestAnchorPathHomeRules: with no passwd home and a "~/" ledger_root, the anchor sits beside the ledger
// root that $HOME expands — only when not AT_SECURE; a secure process refuses rather than let $HOME
// choose where it appends (R21), which is the same condition that refuses the ledger root (case 37).
//
// Also pins runtime-launch.md E37: no passwd home and a ~/ ledger_root: ErrAnchorHome under AT_SECURE only.
func TestAnchorPathHomeRules(t *testing.T) {
	m := config.Builtin()
	m.Home = ""
	attacker := func() (string, error) { return "/tmp/attacker", nil }
	for name, secure := range map[string]func() (bool, error){"AT_SECURE": isSecure, "unreadable auxv": failedAuxv} {
		_, err := anchorPath(m, secure, attacker, dirs())
		if !errors.Is(err, ErrAnchorHome) || !errors.Is(err, ErrLedgerRootHome) || strings.Contains(err.Error(), "/tmp/attacker") {
			t.Fatalf("%s: err = %v, want ErrAnchorHome without the refused $HOME", name, err)
		}
	}
	got, err := anchorPath(m, notSecure, func() (string, error) { return "/home/container", nil }, dirs())
	if err != nil || got != filepath.Join("/home/container", ".tego", ledger.ChainLogFile) {
		t.Fatalf("not secure: %q %v", got, err)
	}
	if _, err := anchorPath(m, notSecure, func() (string, error) { return "relative", nil }, dirs()); !errors.Is(err, ErrAnchorHome) {
		t.Fatalf("a relative home: %v, want ErrAnchorHome", err)
	}
	if _, err := anchorPath(nil, notSecure, attacker, dirs()); !errors.Is(err, ErrDeps) {
		t.Fatalf("nil machine: %v", err)
	}
}

// TestRunnerAnchorPath: the launcher appends to Deps.AnchorPath when the CLI names one, and only
// otherwise to the ledger's default beside the root.
func TestRunnerAnchorPath(t *testing.T) {
	r := &runner{dir: "/l/runs/r-1"}
	if got := r.anchorFile(); got != ledger.DefaultAnchorPath("/l/runs/r-1") {
		t.Fatalf("default %q", got)
	}
	r.deps.AnchorPath = "/home/u/.tego/chain.log"
	if got := r.anchorFile(); got != "/home/u/.tego/chain.log" {
		t.Fatalf("named %q", got)
	}
}

// TestSweepAnchorsWhereTheLauncherDoes: an orphan the sweep ends is anchored in the chain.log
// WithSweepAnchor names, the same file a run that ended normally uses, so `events --verify` finds it.
func TestSweepAnchorsWhereTheLauncherDoes(t *testing.T) {
	root := t.TempDir()
	const orphan = "r-00000000-000000000000a-orphan"
	startedRun(t, root, orphan)
	anchor := filepath.Join(t.TempDir(), ".tego", ledger.ChainLogFile)
	res, err := Sweep(context.Background(), root, KeepForever, WithSweepManager(nil), WithSweepAnchor(anchor))
	if err != nil || res.Orphaned != 1 {
		t.Fatalf("Sweep: %+v %v", res, err)
	}
	r, err := ledger.OpenReader(filepath.Join(root, orphan))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	rep, err := r.Verify(context.Background(), ledger.NewFileChainAnchor(anchor))
	if err != nil || !rep.Anchored || !rep.Ended {
		t.Fatalf("the swept run is not anchored in %s: %+v %v", anchor, rep, err)
	}
}

// TestSweepAnchorIsTheOwners: on a shared ledger root, a run another account owns is anchored where that
// account's own launcher would have anchored it — its ~/.tego/chain.log, or beside the root when it has
// no home — not in the sweeper's chain.log, where its owner's `events --verify` never looks. A run the
// sweeper owns, or root owns in a root-owned ledger root, stays in the sweeper's own anchor; a
// root-owned run directory in another account's ledger root is that account's.
func TestSweepAnchorIsTheOwners(t *testing.T) {
	const root = "/srv/tego/runs"
	owners := map[string]int{
		root:                    0,
		root + "/r-mine":        1000,
		root + "/r-theirs":      1001,
		root + "/r-homeless":    1002,
		root + "/r-root":        0,
		"/home/v/.tego/runs":    1001,
		"/home/v/.tego/runs/rr": 0,
	}
	a := &sweepAnchor{
		root: root, own: "/home/me/.tego/chain.log", self: 1000,
		homeOf: func(uid int) string {
			return map[int]string{1000: "/home/me", 1001: "/home/v", 1002: "/nonexistent"}[uid]
		},
		uidOf: func(_ sys.Lender, p string) (int, bool) { uid, ok := owners[p]; return uid, ok },
		isDir: dirs("/home/me", "/home/v"),
	}
	for run, want := range map[string]string{
		"r-mine":     "/home/me/.tego/chain.log",
		"r-theirs":   "/home/v/.tego/chain.log",
		"r-homeless": "/srv/tego/chain.log",
		"r-root":     "/home/me/.tego/chain.log",
		"r-gone":     "/home/me/.tego/chain.log",
	} {
		if got := a.pathFor(run); got != want {
			t.Errorf("%s: anchored in %q, want %q", run, got, want)
		}
	}
	a.root = "/home/v/.tego/runs"
	if got := a.pathFor("rr"); got != "/home/v/.tego/chain.log" {
		t.Errorf("a root-owned run in v's ledger root: anchored in %q, want v's", got)
	}
}

// Even while the configured path names a decoy, a sweeper chooses the anchor from the actual run's
// ownership. The ownership probe is injected so this regression needs no chown privileges.
func TestSweepAnchorOwnershipUsesHeldRoot(t *testing.T) {
	for _, tc := range []struct {
		name, runOwner, rootOwner string
		hasHome                   bool
	}{
		{"run owner", "1001", "0", true},
		{"root-owned run inherits ledger owner", "0", "1001", true},
		{"no-home anchor stays beside declared root", "1001", "0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			root, decoy := filepath.Join(base, "runs"), filepath.Join(base, "decoy")
			const run = "r-00000000-000000000000a-orphan"
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			startedRun(t, root, run)
			if err := os.MkdirAll(filepath.Join(decoy, run), 0o700); err != nil {
				t.Fatal(err)
			}
			for path, owner := range map[string]string{
				filepath.Join(root, "owner"): tc.rootOwner, filepath.Join(root, run, "owner"): tc.runOwner,
				filepath.Join(decoy, "owner"): "1002", filepath.Join(decoy, run, "owner"): "1002",
			} {
				if err := os.WriteFile(path, []byte(owner), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			own := filepath.Join(base, "mine", ledger.ChainLogFile)
			realHome, decoyHome := filepath.Join(base, "real-home"), filepath.Join(base, "decoy-home")
			a := newSweepAnchor(root, own)
			a.self = 1000
			a.uidOf = func(at sys.Lender, name string) (int, bool) {
				if at == nil {
					t.Fatalf("ownership of %s read by path, not under the held root", name)
				}
				var b []byte
				err := at.Borrow(func(n int) error {
					var err error
					b, err = os.ReadFile(fmt.Sprintf("/proc/self/fd/%d/%s/owner", n, name))
					return err
				})
				if err != nil {
					return 0, false
				}
				n, err := strconv.Atoi(string(b))
				return n, err == nil
			}
			a.homeOf = func(uid int) string {
				if !tc.hasHome {
					return ""
				}
				if uid == 1001 {
					return realHome
				}
				return decoyHome
			}
			a.isDir = func(string) bool { return true }
			var boundAnchor *sweepAnchor
			bind := ledger.WithBoundWriterOptions(func(bound sys.Lender) []ledger.Option {
				boundAnchor = a.boundTo(bound)
				if err := os.Rename(root, root+".held"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(decoy, root); err != nil {
					t.Fatal(err)
				}
				return []ledger.Option{ledger.WithAnchor(boundAnchor)}
			})
			rep, err := ledger.GC(context.Background(), root, KeepForever, false, bind)
			if err != nil || len(rep.Errors) != 0 || len(rep.Swept) != 1 {
				t.Fatalf("GC: %+v %v", rep, err)
			}
			want := filepath.Join(realHome, StateDir, ledger.ChainLogFile)
			if !tc.hasHome {
				want = filepath.Join(base, ledger.ChainLogFile)
			}
			if _, ok, err := ledger.NewFileChainAnchor(want).Head(run); err != nil || !ok {
				t.Fatalf("expected anchor %s: found=%v err=%v", want, ok, err)
			}
			if _, err := os.Stat(filepath.Join(decoyHome, StateDir, ledger.ChainLogFile)); !os.IsNotExist(err) {
				t.Fatalf("decoy anchor touched: %v", err)
			}
			if _, err := os.Stat(own); !os.IsNotExist(err) {
				t.Fatalf("sweeper's own anchor touched: %v", err)
			}
		})
	}
}
