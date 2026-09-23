// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestCodexIsRoutedThroughItsOwnCodexHome is E22's Codex half (capture-derive.md R19b): Codex ignores
// OPENAI_BASE_URL and reads openai_base_url only from the config.toml under CODEX_HOME, so a run whose
// forwarder has an openai listener writes that file into its runtime directory — tego's key first, the
// user's own config.toml after it — and points CODEX_HOME at it. No run wrote it before, so Codex under
// capture: forwarder sent its calls around the forwarder.
func TestCodexIsRoutedThroughItsOwnCodexHome(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root launcher writes no CODEX_HOME: its runtime directory is not the agent's")
	}
	const base = "http://127.0.0.1:41001/v1"
	userHome := t.TempDir()
	user := "model = \"gpt-5\"\n[profiles.fast]\nmodel = \"m\"\n"
	if err := os.WriteFile(filepath.Join(userHome, "config.toml"), []byte(user), 0o600); err != nil {
		t.Fatal(err)
	}
	runnerWith := func(rt *agent.RuleTable, vars map[string]string) *runner {
		return &runner{
			id:  "r-00000000-000000000000a-aaaaaa",
			rt:  rt,
			log: slog.New(slog.DiscardHandler),
			deps: Deps{
				Capture: []source.Source{&fakeLoopback{name: "forwarder", vars: vars}},
				Environ: []string{"HOME=/nonexistent", identity.EnvCodexHome + "=" + userHome},
			},
		}
	}
	runner := func(vars map[string]string) *runner { return runnerWith(&agent.RuleTable{}, vars) }

	t.Run("an openai listener", func(t *testing.T) {
		t.Setenv("XDG_RUNTIME_DIR", privateTempDir(t))
		r := runner(map[string]string{envOpenAIBaseURL: base, "OPENAI_API_BASE": base})
		if err := r.createRuntimeDir(); err != nil {
			t.Fatal(err)
		}
		vars := r.forwarderVars()
		home := vars[identity.EnvCodexHome]
		if home != filepath.Join(r.runtimeDir, codexHomeName) {
			t.Fatalf("CODEX_HOME = %q, want the run's own under %s", home, r.runtimeDir)
		}
		got, err := os.ReadFile(filepath.Join(home, codexConfigFile))
		if err != nil {
			t.Fatal(err)
		}
		if want := string(identity.CodexConfig(base, []byte(user))); string(got) != want {
			t.Fatalf("config.toml =\n%s\nwant\n%s", got, want)
		}
		for path, want := range map[string]os.FileMode{home: 0o700, filepath.Join(home, codexConfigFile): 0o600} {
			if st, err := os.Stat(path); err != nil || st.Mode().Perm() != want {
				t.Errorf("%s: %v %v, want mode %o", path, st, err, want)
			}
		}
		if vars[envOpenAIBaseURL] != base {
			t.Errorf("the listener's own variables were lost: %v", vars)
		}
	})

	// The user's file is the one the agent's own environment names — the launcher's with the contract's
	// env rules applied — not the launcher's: a contract that sets or denies CODEX_HOME points Codex at
	// another config.toml, and the launcher's CODEX_HOME copied a file Codex would never have read.
	t.Run("a contract that sets or denies CODEX_HOME", func(t *testing.T) {
		setHome := t.TempDir()
		fromSet := "model = \"from-the-contract\"\n"
		if err := os.WriteFile(filepath.Join(setHome, codexConfigFile), []byte(fromSet), 0o600); err != nil {
			t.Fatal(err)
		}
		home := t.TempDir()
		if err := os.Mkdir(filepath.Join(home, ".codex"), 0o700); err != nil {
			t.Fatal(err)
		}
		fromHome := "model = \"from-home\"\n"
		if err := os.WriteFile(filepath.Join(home, ".codex", codexConfigFile), []byte(fromHome), 0o600); err != nil {
			t.Fatal(err)
		}
		for name, c := range map[string]struct {
			rt   *agent.RuleTable
			want string
		}{
			"set":             {&agent.RuleTable{Set: map[string]string{identity.EnvCodexHome: setHome}}, fromSet},
			"denied":          {&agent.RuleTable{Deny: []string{identity.EnvCodexHome}, Set: map[string]string{"HOME": home}}, fromHome},
			"not in the pass": {&agent.RuleTable{Env: []string{"PATH"}, Set: map[string]string{"HOME": home}}, fromHome},
		} {
			t.Run(name, func(t *testing.T) {
				t.Setenv("XDG_RUNTIME_DIR", privateTempDir(t))
				r := runnerWith(c.rt, map[string]string{envOpenAIBaseURL: base})
				if err := r.createRuntimeDir(); err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(filepath.Join(r.forwarderVars()[identity.EnvCodexHome], codexConfigFile))
				if err != nil {
					t.Fatal(err)
				}
				if want := string(identity.CodexConfig(base, []byte(c.want))); string(got) != want {
					t.Fatalf("config.toml =\n%s\nwant the agent's own user file after tego's key:\n%s", got, want)
				}
			})
		}
	})

	t.Run("no openai listener", func(t *testing.T) {
		t.Setenv("XDG_RUNTIME_DIR", privateTempDir(t))
		r := runner(map[string]string{identity.EnvAnthropicBaseURL: "http://127.0.0.1:41002"})
		if err := r.createRuntimeDir(); err != nil {
			t.Fatal(err)
		}
		if home, ok := r.forwarderVars()[identity.EnvCodexHome]; ok {
			t.Fatalf("CODEX_HOME = %q for a run with nothing for Codex to reach", home)
		}
		if _, err := os.Stat(filepath.Join(r.runtimeDir, codexHomeName)); !os.IsNotExist(err) {
			t.Fatalf("a codex home was written: %v", err)
		}
	})

	// R19b's refusal (Codex POC F2): with no runtime directory the launcher made none and routed nothing, and said
	// nothing; Codex then failed for want of a state directory it could write. The launch is refused, naming the fix.
	for _, xdg := range []string{"", "relative/dir"} {
		t.Run("no runtime directory "+xdg, func(t *testing.T) {
			t.Setenv("XDG_RUNTIME_DIR", xdg)
			r := runner(map[string]string{envOpenAIBaseURL: base})
			err := r.createRuntimeDir()
			if !errors.Is(err, ErrNoRuntimeDir) || !strings.Contains(err.Error(), "XDG_RUNTIME_DIR") || !strings.Contains(err.Error(), "models list") {
				t.Fatalf("err = %v, want ErrNoRuntimeDir naming XDG_RUNTIME_DIR and the fix", err)
			}
			if home, ok := r.forwarderVars()[identity.EnvCodexHome]; ok {
				t.Fatalf("CODEX_HOME = %q with no runtime directory to hold it", home)
			}
		})
	}
	t.Run("no runtime directory and no openai listener", func(t *testing.T) {
		t.Setenv("XDG_RUNTIME_DIR", "")
		r := runner(map[string]string{identity.EnvAnthropicBaseURL: "http://127.0.0.1:41002"})
		if err := r.createRuntimeDir(); err != nil {
			t.Fatalf("a run with nothing for Codex to reach failed for a directory only Codex uses: %v", err)
		}
	})
}

// TestTheRunGrantsItsOwnCodexHome is agent-contract.md R10a (Codex POC F2): the run's CODEX_HOME,
// $XDG_RUNTIME_DIR/tego/<run id>/codex, which no contract can name, is a write grant the run makes on its own
// authority for exactly that directory, named fs.codex_home[<path>], listed in run_start's runtime_grants, and
// recognised as a runtime rule (drift does not count it). The compiled table is not mutated.
func TestTheRunGrantsItsOwnCodexHome(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root launcher writes no CODEX_HOME")
	}
	xdg := privateTempDir(t)
	t.Setenv("XDG_RUNTIME_DIR", xdg)
	compiled := &agent.RuleTable{FS: []agent.FSRule{{Path: "/work", Kind: agent.FSWrite, Raw: "/work"}}}
	r := &runner{
		id: "r-00000000-000000000000a-aaaaaa", rt: compiled, log: slog.New(slog.DiscardHandler),
		deps: Deps{Capture: []source.Source{&fakeLoopback{name: "forwarder", vars: map[string]string{envOpenAIBaseURL: "http://127.0.0.1:41001/v1"}}},
			Environ: []string{"HOME=/nonexistent"}},
	}
	if err := r.createRuntimeDir(); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(xdg, "tego", "r-00000000-000000000000a-aaaaaa", codexHomeName)
	if len(compiled.FS) != 1 {
		t.Fatalf("the compiled table was mutated: %+v", compiled.FS)
	}
	var grants []agent.FSRule
	for _, f := range r.rt.FS {
		if f.Runtime != "" {
			grants = append(grants, f)
		}
	}
	if len(grants) != 1 || grants[0].Path != home || grants[0].Kind != agent.FSWrite || grants[0].Access != agent.AccessWriteSet {
		t.Fatalf("runtime grants %+v, want one write grant on %s", grants, home)
	}
	// The grant carries the directory's identity, which the backend compares with what it opens.
	var st syscall.Stat_t
	if err := syscall.Lstat(home, &st); err != nil {
		t.Fatal(err)
	}
	if grants[0].RuntimeDev != uint64(st.Dev) || grants[0].RuntimeIno != st.Ino {
		t.Fatalf("the grant's identity %d:%d, want the directory's %d:%d", grants[0].RuntimeDev, grants[0].RuntimeIno, st.Dev, st.Ino)
	}
	name := grants[0].RuleName()
	if name != "fs.codex_home["+home+"]" || !agent.IsRuntimeRule(name) {
		t.Fatalf("rule name %q (runtime=%v), want fs.codex_home[%s], a runtime rule", name, agent.IsRuntimeRule(name), home)
	}
	if got := runtimeGrants(r.rt); !slices.Equal(got, []string{name}) {
		t.Fatalf("runtime_grants = %q, want [%s]", got, name)
	}
	// Exactly the run's own directory: a write to its parent, or to another run's, is not under the grant.
	for _, p := range []string{filepath.Join(home, "state.sqlite"), filepath.Join(home, "sessions", "s.jsonl")} {
		if !agent.Covers(grants[0].Path, p) {
			t.Errorf("%s is not under the grant", p)
		}
	}
	for _, p := range []string{filepath.Join(xdg, "tego", "r-00000000-000000000000b-bbbbbb", codexHomeName, "config.toml"),
		filepath.Join(xdg, "tego", "r-00000000-000000000000a-aaaaaa", "last-refusal.json")} {
		if agent.Covers(grants[0].Path, p) {
			t.Errorf("%s is under the grant", p)
		}
	}
}

// TestARunRefusesAWriteEntryOverTheRuntimeParent is R10a's launcher half: a table whose write or ask entry covers
// $XDG_RUNTIME_DIR/tego, or lies inside it (another run's directory), is refused before the run makes anything
// there, whatever compile was told. It runs at every euid: the launcher checks the parents before its root return,
// and a root launcher makes no directory to refuse after.
func TestARunRefusesAWriteEntryOverTheRuntimeParent(t *testing.T) {
	xdg := privateTempDir(t)
	t.Setenv("XDG_RUNTIME_DIR", xdg)
	parent := filepath.Join(xdg, "tego")
	for name, rule := range map[string]agent.FSRule{
		"the parent":         {Path: parent + "/", Kind: agent.FSWrite},
		"its ancestor":       {Path: xdg, Kind: agent.FSWrite},
		"another run's":      {Path: filepath.Join(parent, "r-00000000-000000000000b-bbbbbb"), Kind: agent.FSWrite},
		"an ask scope there": {Path: parent, Kind: agent.FSAsk},
	} {
		t.Run(name, func(t *testing.T) {
			rt := &agent.RuleTable{FS: []agent.FSRule{rule}}
			if rule.Kind == agent.FSAsk {
				rt = &agent.RuleTable{FSAsk: []agent.FSRule{rule}}
			}
			r := &runner{id: "r-00000000-000000000000a-aaaaaa", rt: rt, log: slog.New(slog.DiscardHandler)}
			err := r.createRuntimeDir()
			if !errors.Is(err, ErrRuntimeDirWritable) {
				t.Fatalf("err = %v, want ErrRuntimeDirWritable", err)
			}
			if r.runtimeDir != "" {
				t.Fatalf("the run made its directory %s before refusing", r.runtimeDir)
			}
		})
	}
	t.Run("a sibling under XDG_RUNTIME_DIR", func(t *testing.T) {
		rt := &agent.RuleTable{FS: []agent.FSRule{{Path: filepath.Join(xdg, "cc-socks"), Kind: agent.FSWrite}}}
		r := &runner{id: "r-00000000-000000000000a-aaaaaa", rt: rt, log: slog.New(slog.DiscardHandler)}
		if err := r.createRuntimeDir(); err != nil {
			t.Fatalf("a write entry beside tego's directory was refused: %v", err)
		}
	})
}

// noPasswdUID is a uid no passwd database on a test machine holds, so the passwd fallback finds no home.
const noPasswdUID = 1<<31 - 7

// TestUserCodexConfig: the user's file is the one Codex itself would have read — under the inherited
// CODEX_HOME, else ~/.codex — and a missing one is nothing to copy. A symlink or a FIFO in its place is
// refused rather than followed or waited on.
func TestUserCodexConfig(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".codex", codexConfigFile), []byte("model = \"a\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := userCodexConfig([]string{"HOME=" + home}, noPasswdUID); err != nil || string(b) != "model = \"a\"\n" {
		t.Fatalf("~/.codex: %q %v", b, err)
	}
	// An empty CODEX_HOME is unset to Codex, which then reads ~/.codex.
	if b, err := userCodexConfig([]string{identity.EnvCodexHome + "=", "HOME=" + home}, noPasswdUID); err != nil || string(b) != "model = \"a\"\n" {
		t.Fatalf("an empty CODEX_HOME: %q %v, want ~/.codex's", b, err)
	}
	// With no HOME, Codex takes the passwd home; a uid with no passwd entry has none, and nothing is copied.
	if b, err := userCodexConfig(nil, noPasswdUID); err != nil || b != nil {
		t.Fatalf("no HOME and no passwd home: %q %v, want nothing", b, err)
	}
	other := t.TempDir()
	if b, err := userCodexConfig([]string{"HOME=" + home, identity.EnvCodexHome + "=" + other}, noPasswdUID); err != nil || b != nil {
		t.Fatalf("an inherited CODEX_HOME with no config.toml: %q %v, want nothing", b, err)
	}
	if err := os.Symlink(filepath.Join(home, ".codex", codexConfigFile), filepath.Join(other, codexConfigFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := userCodexConfig([]string{identity.EnvCodexHome + "=" + other}, noPasswdUID); err == nil {
		t.Fatal("a symlinked config.toml was followed")
	}
	fifo := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(fifo, codexConfigFile), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := userCodexConfig([]string{identity.EnvCodexHome + "=" + fifo}, noPasswdUID); err == nil {
		t.Fatal("a FIFO was read as a config.toml")
	}
}
