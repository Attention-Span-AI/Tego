// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// SUDO_UID may select config discovery's owner, but must not move an implicit
// library compile's credential, IPC or anchor protection away from the real uid.
func TestCompileImplicitHomeKeepsRealUIDUnderSudo(t *testing.T) {
	f := newFixture(t)
	rootHome := f.home
	otherHome := filepath.Join(f.root, "other-home")
	rootAnchor := filepath.Join(rootHome, ".tego", "chain.log")
	for _, home := range []string{rootHome, otherHome} {
		if err := os.MkdirAll(filepath.Join(home, ".tego"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.file(rootAnchor, "", 0o600)
	secret := filepath.Join(rootHome, ".ssh", "id_ed25519")
	f.file(secret, "root secret", 0o600)
	m := *f.machine
	m.LedgerRoot.Value = filepath.Join(f.root, "ledger") // neither home selects the protected ledger
	saved := currentUser
	t.Cleanup(func() { currentUser = saved })
	realUID := 0
	passwdHome := rootHome
	var lookedUp []int
	currentUser = compilerUserLookup(func() (*user.User, error) {
		return &user.User{Uid: "0", HomeDir: rootHome}, nil
	}, func() int { return realUID }, func(uid int) (*user.User, error) {
		lookedUp = append(lookedUp, uid)
		return &user.User{Uid: strconv.Itoa(uid), HomeDir: passwdHome}, nil
	})
	t.Setenv("SUDO_UID", "4242")
	t.Setenv("HOME", otherHome)
	t.Setenv("USER", "other")
	// Clear only the fixture's default WithHome: exercise the production cached
	// resolver and defaults/compile passes with controlled identity providers.
	opts := f.opts(WithHome(""))
	c := f.load("version: 0\nname: real-uid\ncommand: [python]\n")
	rt, ds, err := Compile(c, &m, opts...)
	if err != nil {
		t.Fatalf("implicit real-uid compile: %v\n%s", err, render(ds))
	}
	if len(lookedUp) != 1 || lookedUp[0] != 0 || rt.Home != rootHome {
		t.Fatalf("implicit home %q from lookups %v, want real uid 0 home %q", rt.Home, lookedUp, rootHome)
	}
	for _, path := range []string{secret, rootAnchor} {
		for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup} {
			if got := rt.Evaluate(Action{Kind: ActionFSRead, Path: path}, tier); got.Verdict != VerdictRefused {
				t.Errorf("tier %s reading real uid's %s = %+v, want refused", tier, path, got)
			}
		}
	}
	if got := rt.BuiltinUnixRule(filepath.Join(rootHome, ".screen", "session")); got != BuiltinHostIPC {
		t.Errorf("real uid's screen socket rule = %q, want %q", got, BuiltinHostIPC)
	}
	if got := rt.BuiltinUnixRule(filepath.Join(rootHome, ".tego", "api.sock")); got != BuiltinTegoSurface {
		t.Errorf("real uid's Tego socket rule = %q, want %q", got, BuiltinTegoSurface)
	}
	c = f.load("version: 0\nname: real-uid\ncommand: [python]\nfs:\n  write: [\"" + rootAnchor + "\"]\n")
	rt, ds, err = Compile(c, &m, opts...)
	if rt != nil || !errors.Is(err, ErrContractOverlap) || !strings.Contains(render(ds), "the chain anchor "+rootAnchor) {
		t.Fatalf("implicit root anchor grant: %v\n%s; want actual root-anchor refusal", err, render(ds))
	}
	if len(lookedUp) != 1 {
		t.Fatalf("implicit anchor compile lookups = %v, want the established real-uid lookup", lookedUp)
	}
	// Like the release's user.Current cache, later passwd or real-uid changes
	// must not move the original home's protections on repeated library calls.
	for _, change := range []string{"passwd home", "real uid"} {
		passwdHome = otherHome
		if change == "real uid" {
			realUID = 4242
		}
		rt, ds, err = Compile(c, &m, opts...)
		if rt != nil || !errors.Is(err, ErrContractOverlap) || !strings.Contains(render(ds), "the chain anchor "+rootAnchor) || len(lookedUp) != 1 {
			t.Fatalf("after %s change: table %v, lookups %v, error %v\n%s; want original root-anchor refusal", change, rt, lookedUp, err, render(ds))
		}
	}
	// A deliberate nonempty override is the release's existing library API.
	// It establishes that selecting the other home really changes this grant's
	// outcome, while proving that explicit context bypasses all default lookup.
	for _, tc := range []struct {
		home   string
		refuse bool
	}{{rootHome, true}, {otherHome, false}} {
		rt, ds, err = Compile(c, &m, append(opts, WithHome(tc.home))...)
		if tc.refuse {
			if rt != nil || !errors.Is(err, ErrContractOverlap) || !strings.Contains(render(ds), "the chain anchor "+rootAnchor) {
				t.Fatalf("explicit root anchor grant: %v\n%s; want refusal", err, render(ds))
			}
		} else if err != nil || rt.Home != otherHome {
			t.Fatalf("explicit other-home control: %v\n%s; want other-home success", err, render(ds))
		}
		if len(lookedUp) != 1 {
			t.Fatalf("explicit WithHome consulted passwd: %v", lookedUp)
		}
	}
}

func TestCompilerUserLookupPreservesReleaseCache(t *testing.T) {
	cause := errors.New("first process-user lookup failed")
	for _, tc := range []struct {
		name            string
		cached, trusted *user.User
		currentErr      error
		lookupErr       error
		wantErr         bool
		wantLookup      int
	}{
		{name: "cached-error", currentErr: cause, wantErr: true},
		{name: "cached-old-uid", cached: &user.User{Uid: "4242", HomeDir: "/old"}, wantErr: true},
		{name: "passwd-moved-before-first-compile", cached: &user.User{Uid: "0", HomeDir: "/old"}, trusted: &user.User{Uid: "0", HomeDir: "/new"}, wantErr: true, wantLookup: 1},
		{name: "environment-fallback", cached: &user.User{Uid: "0", HomeDir: "/from-env"}, lookupErr: user.UnknownUserIdError(0), wantErr: true, wantLookup: 1},
		{name: "trusted-wrong-uid", cached: &user.User{Uid: "0", HomeDir: "/root"}, trusted: &user.User{Uid: "4242", HomeDir: "/root"}, wantErr: true, wantLookup: 1},
		{name: "empty-home-stays-empty", cached: &user.User{Uid: "0"}, trusted: &user.User{Uid: "0"}, wantLookup: 1},
		{name: "agreed-home", cached: &user.User{Uid: "0", HomeDir: "/root"}, trusted: &user.User{Uid: "0", HomeDir: "/root"}, wantLookup: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			currentCalls, lookupCalls := 0, 0
			resolve := compilerUserLookup(func() (*user.User, error) {
				currentCalls++
				if currentCalls > 1 {
					return &user.User{Uid: "0", HomeDir: "/retry-success"}, nil
				}
				return tc.cached, tc.currentErr
			}, func() int { return 0 }, func(int) (*user.User, error) {
				lookupCalls++
				return tc.trusted, tc.lookupErr
			})
			for range 2 {
				u, err := resolve()
				if (err != nil) != tc.wantErr {
					t.Fatalf("resolve = %v, %v; want error %t", u, err, tc.wantErr)
				}
				if tc.currentErr != nil && !errors.Is(err, cause) {
					t.Fatalf("cached first error = %v, want original cause", err)
				}
				if !tc.wantErr && (u.Uid != tc.cached.Uid || u.HomeDir != tc.cached.HomeDir) {
					t.Fatalf("resolve = %+v, want cached %+v", u, tc.cached)
				}
			}
			if currentCalls != 1 || lookupCalls != tc.wantLookup {
				t.Fatalf("current/lookup calls = %d/%d, want 1/%d", currentCalls, lookupCalls, tc.wantLookup)
			}
		})
	}
}

// Implicit homes must be established from passwd, even for home-independent
// contracts. USER/HOME cannot replace the lookup; a library's WithHome can.
// Inject the lookup result so the test needs neither root nor changes to passwd.
func TestCompileNumericIdentity(t *testing.T) {
	saved := currentUser
	t.Cleanup(func() { currentUser = saved })
	for _, tc := range []struct {
		name, username, home string
		entry                *user.User
	}{
		{name: "no-passwd-no-env"},
		{name: "no-passwd-user", username: "container"},
		{name: "no-passwd-home", home: "/untrusted-home"},
		{name: "no-passwd-user-home", username: "container", home: "/untrusted-home"},
		{name: "empty-passwd-home", entry: &user.User{Uid: "1234", Username: "container"}},
		{name: "root", entry: &user.User{Uid: "0", Username: "root", HomeDir: "/root"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("USER", tc.username)
			t.Setenv("HOME", tc.home)
			if tc.username == "" {
				if err := os.Unsetenv("USER"); err != nil {
					t.Fatal(err)
				}
			}
			if tc.home == "" {
				if err := os.Unsetenv("HOME"); err != nil {
					t.Fatal(err)
				}
			}
			currentUser = func() (*user.User, error) {
				if tc.entry != nil {
					return tc.entry, nil
				}
				return nil, user.UnknownUserIdError(1234)
			}
			dir := t.TempDir()
			c, _, err := LoadBytes(filepath.Join(dir, "agent.yaml"), []byte("version: 0\nname: numeric\ncommand: [/bin/true]\n"), nil)
			if err != nil {
				t.Fatal(err)
			}
			m := config.Builtin()
			m.LedgerRoot.Value = filepath.Join(dir, "runs")
			rt, ds, err := Compile(c, m, WithCwd(dir), Offline())
			if tc.entry == nil || tc.entry.HomeDir == "" {
				if err == nil || rt != nil {
					t.Fatalf("compile without an established home = %v, %v; want refusal", rt, err)
				}
				if tc.entry == nil {
					var unknown user.UnknownUserIdError
					if !errors.As(err, &unknown) {
						t.Fatalf("compile error = %v, want the passwd lookup error", err)
					}
				} else if !strings.Contains(err.Error(), tc.entry.Uid) || !strings.Contains(err.Error(), "WithHome") {
					t.Fatalf("compile error = %v, want uid and WithHome advice", err)
				}
			} else if err != nil || rt.Home != tc.entry.HomeDir {
				t.Fatalf("known-home compile = %v, %v, %v; want home %q", rt, ds, err, tc.entry.HomeDir)
			}
			home := t.TempDir()
			rt, ds, err = Compile(c, m, WithCwd(dir), WithHome(home), Offline())
			if err != nil || rt.Home != home {
				t.Fatalf("explicit-home compile = %v, %v, %v; want home %q", rt, ds, err, home)
			}
		})
	}
}

func TestCompileNoHomePaths(t *testing.T) {
	saved := currentUser
	t.Cleanup(func() { currentUser = saved })
	currentUser = func() (*user.User, error) { return nil, user.UnknownUserIdError(1234) }
	dir := t.TempDir()
	home := t.TempDir()
	anchor := filepath.Join(home, ".tego", "chain.log")
	if err := os.MkdirAll(filepath.Dir(anchor), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(anchor, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	m := config.Builtin()
	m.LedgerRoot.Value = filepath.Join(dir, "state", "runs")
	if err := os.Mkdir(filepath.Dir(m.LedgerRoot.Value), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body        string
		wantExplicitError bool
	}{
		{name: "work-write", body: "fs:\n  write: [./output]\n"},
		{name: "explicit-home", body: "fs:\n  write: [~/output]\n"},
		{name: "anchor-write", body: "fs:\n  write: [" + anchor + "]\n", wantExplicitError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, err := LoadBytes(filepath.Join(dir, "agent.yaml"), []byte("version: 0\nname: numeric\ncommand: [/bin/true]\n"+tc.body), nil)
			if err != nil {
				t.Fatal(err)
			}
			rt, _, err := Compile(c, m, WithCwd(dir), Offline())
			var unknown user.UnknownUserIdError
			if rt != nil || !errors.As(err, &unknown) {
				t.Fatalf("compile without an implicit home = %v, %v; want the passwd lookup refusal", rt, err)
			}
			rt, ds, err := Compile(c, m, WithCwd(dir), WithHome(home), Offline())
			if (err != nil) != tc.wantExplicitError {
				t.Fatalf("compile with explicit home: %v", err)
			}
			if tc.name == "anchor-write" {
				if !errors.Is(err, ErrContractOverlap) {
					t.Fatalf("anchor write: %v, want ErrContractOverlap", err)
				}
				var found bool
				for _, d := range ds {
					if d.IsError() && d.Code == CodeContradiction && strings.Contains(d.Message, "the chain anchor") {
						found = true
					}
				}
				if !found {
					t.Fatalf("missing anchor-specific refusal: %v", ds)
				}
			}
			if err != nil {
				if !strings.Contains(render(ds), "the chain anchor "+anchor) {
					t.Fatalf("compile refusal = %v, %v; want the actual chain anchor", err, ds)
				}
				return
			}
			for _, rules := range [][]FSRule{rt.FS, rt.DenyWrite} {
				for _, r := range rules {
					if !filepath.IsAbs(r.Path) {
						t.Errorf("invented relative builtin path: %+v", r)
					}
				}
			}
			for _, p := range append(rt.Builtins.TegoDirs, rt.Builtins.IPCDirs...) {
				if !filepath.IsAbs(p) {
					t.Errorf("relative protected path %q", p)
				}
			}
		})
	}
}
