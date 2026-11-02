// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/profilesrc"
	"github.com/attention-span-ai/tego/internal/setup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestCompileParity: the dashboard compiles a contract as tego compiles a run of it, over the six cases that broke
// rule writes from the dashboard: a contract that extends a profile (F2), a tier-auto
// contract with fs.ask_read compiled at the run's tier (F3), a program named by its basename that only the run's
// exec directories hold (F17), a pinned tier, an entry the compiler refuses, and a write entry over the chain anchor
// (R10, the anchor the service is given); and a write entry over tego's runtime parent under XDG_RUNTIME_DIR (R10a,
// the runtime directories the launcher checks).
func TestCompileParity(t *testing.T) {
	dir := t.TempDir()
	proj := filepath.Join(dir, "proj")
	profiles := filepath.Join(dir, "profiles")
	bin := filepath.Join(dir, "bin")
	anchorDir := filepath.Join(dir, "anchor")
	runtimeParent := filepath.Join(dir, "xdg", agent.RuntimeDirName)
	for _, d := range []string{proj, filepath.Join(proj, "docs"), filepath.Join(profiles, "base"), bin, anchorDir, runtimeParent} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", filepath.Dir(runtimeParent))
	writeFile(t, filepath.Join(profiles, "base", "mini.yaml"), "net:\n  allow: [\"api.example.com:443\"]\n")
	if err := os.WriteFile(filepath.Join(bin, "mytool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := config.Builtin()
	m.Profiles.Value = profiles
	m.Home = filepath.Join(dir, "home")
	s := &Service{Ledger: filepath.Join(dir, "ledger"), Machine: m, PATH: "/usr/bin:/bin", Anchor: filepath.Join(anchorDir, "chain.log")}
	contract := filepath.Join(proj, "agent.yaml")
	head := "version: 0\nname: parity\ncommand: [\"sh\"]\n"
	cases := []struct {
		name, text string
		cc         CheckContext
		ok         bool
		want       string
	}{
		{"extends a profile", head + "extends: base/mini\nexec:\n  allow: [sh]\n", CheckContext{Tier: "landlock"}, true, ""},
		{"auto with ask_read at the run's tier", head + "tier: auto\nexec:\n  allow: [sh]\nfs:\n  ask_read: [\"./docs/\"]\n",
			CheckContext{Tier: "landlock"}, true, ""},
		{"auto with ask_read and no run tier (F3 as it was)", head + "tier: auto\nexec:\n  allow: [sh]\nfs:\n  ask_read: [\"./docs/\"]\n",
			CheckContext{}, false, "ask_read"},
		{"basename on the run's exec dirs", head + "exec:\n  allow: [sh, mytool]\n", CheckContext{Tier: "landlock", ExecDirs: bin}, true, ""},
		{"basename on no PATH", head + "exec:\n  allow: [sh, mytool]\n", CheckContext{Tier: "landlock"}, false, "mytool"},
		{"pinned tier", head + "tier: landlock\nexec:\n  allow: [sh]\n", CheckContext{Tier: "landlock"}, true, ""},
		{"a broken entry", head + "exec:\n  allow: [sh, no-such-program-tego-parity]\n", CheckContext{Tier: "landlock"}, false,
			"no-such-program-tego-parity"},
		{"a write over the chain anchor", head + "exec:\n  allow: [sh]\nfs:\n  write: [\"" + anchorDir + "/\"]\n",
			CheckContext{Tier: "landlock"}, false, "chain"},
		{"a write over tego's runtime parent", head + "exec:\n  allow: [sh]\nfs:\n  write: [\"" + runtimeParent + "/\"]\n",
			CheckContext{Tier: "landlock"}, false, "runtime directory"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cc := c.cc
			cc.Contract, cc.Cwd = contract, proj
			_, err := s.compile(context.Background(), cc, []byte(c.text))
			if (err == nil) != c.ok || err != nil && !strings.Contains(err.Error(), c.want) {
				t.Fatalf("compile: %v (want ok %v, %q)", err, c.ok, c.want)
			}
		})
	}
	// F2 as it was: the profile is not found without the machine's profile sources.
	if _, _, err := agent.LoadBytes(contract, []byte(cases[0].text), &agent.ProfileChain{}); err == nil {
		t.Error("an empty profile chain resolved base/mini: the extends case proves nothing")
	}
	if _, _, err := agent.LoadBytes(contract, []byte(cases[0].text), profilesrc.Chain(m)); err != nil {
		t.Errorf("profilesrc.Chain: %v", err)
	}
}

// TestTheRuleServiceNamesTheLaunchersRuntimeDirs: the dashboard compiles a change of a run's contract, and a new
// contract, with config.RuntimeDirBases, the runtime directories `tego rule` compiles with and the launcher checks
// before it makes anything (agent-contract.md R10a), whatever the environment says. The service kept its own copy of
// the launcher's list, which tego-control may not link; had the two drifted, the dashboard would have refused a
// change tego runs, or written a contract the next run refuses.
func TestTheRuleServiceNamesTheLaunchersRuntimeDirs(t *testing.T) {
	dir := t.TempDir()
	xdg := filepath.Join(dir, "xdg")
	if err := os.MkdirAll(filepath.Join(xdg, agent.RuntimeDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	m := config.Builtin()
	m.Home = filepath.Join(dir, "home")
	s := &Service{Ledger: filepath.Join(dir, "ledger"), Machine: m, PATH: "/usr/bin:/bin"}
	uid, _ := config.InvokingUID()
	logind := filepath.Join(config.LogindRuntimeRoot, strconv.Itoa(uid))
	for _, x := range []string{"", "relative/dir", logind, logind + "/", xdg} {
		t.Setenv("XDG_RUNTIME_DIR", x)
		if got, want := s.nextrunContext(CheckContext{}).RuntimeDirs, config.RuntimeDirBases(); !slices.Equal(got, want) {
			t.Errorf("XDG_RUNTIME_DIR=%q: the rule service compiles with %q, the launcher checks %q", x, got, want)
		}
	}
	// "Set up a new agent" compiles with the same list: a write over tego's runtime parent under XDG_RUNTIME_DIR is
	// refused, as tego compile refuses it.
	t.Setenv("XDG_RUNTIME_DIR", xdg)
	text := "version: 0\nname: rt\ncommand: [\"sh\"]\nexec:\n  allow: [sh]\nfs:\n  write: [\"" +
		filepath.Join(xdg, agent.RuntimeDirName) + "/\"]\n"
	ds, ok := setup.Check([]byte(text), dir, *s.newEnv())
	if ok || !slices.ContainsFunc(ds, func(d agent.Diagnostic) bool {
		return d.Code == agent.CodeContradiction && strings.Contains(d.Message, "runtime directory")
	}) {
		t.Fatalf("a new contract that writes over tego's runtime parent compiled (ok %v): %+v", ok, ds)
	}
}
