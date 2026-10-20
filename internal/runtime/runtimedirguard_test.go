// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"crypto/sha256"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// fakeLogind points logindRuntimeRoot into a temporary directory for the test and returns the invoking user's
// directory under it, /run/user/<uid> as the test sees it.
func fakeLogind(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	old := logindRuntimeRoot
	logindRuntimeRoot = root
	t.Cleanup(func() { logindRuntimeRoot = old })
	uid, _ := config.InvokingUID()
	dir := filepath.Join(root, strconv.Itoa(uid))
	if err := os.MkdirAll(filepath.Join(dir, agent.RuntimeDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestRuntimeDirBases is R10a's list of the parents every launch protects: the invoking user's logind directory
// whatever the environment says, and XDG_RUNTIME_DIR when it is absolute and names another.
func TestRuntimeDirBases(t *testing.T) {
	logind := fakeLogind(t)
	other := t.TempDir()
	for _, tc := range []struct {
		xdg  string
		want []string
	}{
		{"", []string{logind}},
		{"relative/dir", []string{logind}},
		{logind, []string{logind}},
		{logind + "/", []string{logind}},
		{other, []string{logind, other}},
	} {
		t.Setenv("XDG_RUNTIME_DIR", tc.xdg)
		if got := RuntimeDirBases(); !slices.Equal(got, tc.want) {
			t.Errorf("XDG_RUNTIME_DIR=%q: RuntimeDirBases() = %q, want %q", tc.xdg, got, tc.want)
		}
	}
}

// TestARunRefusesTheLogindRuntimeParentWithoutXDG: the launcher checked only $XDG_RUNTIME_DIR/tego,
// and only after its returns for a root launcher and for an unset variable, so under plain sudo (which resets the
// variable), cron or ssh without pam_systemd a write entry over /run/user/<uid>/tego ran and rewrote another run's
// CODEX_HOME and refusal mirror there. The logind directory is checked at every euid, whatever the environment says;
// this test runs unprivileged and, in the root suites, as root.
func TestARunRefusesTheLogindRuntimeParentWithoutXDG(t *testing.T) {
	logind := fakeLogind(t)
	parent := filepath.Join(logind, agent.RuntimeDirName)
	custom := t.TempDir()
	for _, xdg := range []string{"", "relative", custom} {
		t.Run("XDG_RUNTIME_DIR="+xdg, func(t *testing.T) {
			t.Setenv("XDG_RUNTIME_DIR", xdg)
			for name, rule := range map[string]agent.FSRule{
				"the parent":        {Path: parent + "/", Kind: agent.FSWrite},
				"the logind dir":    {Path: logind, Kind: agent.FSWrite},
				"another run's dir": {Path: filepath.Join(parent, "r-00000000-000000000000b-bbbbbb"), Kind: agent.FSWrite},
			} {
				r := &runner{id: "r-00000000-000000000000a-aaaaaa", rt: &agent.RuleTable{FS: []agent.FSRule{rule}}, log: slog.New(slog.DiscardHandler)}
				if err := r.createRuntimeDir(); !errors.Is(err, ErrRuntimeDirWritable) {
					t.Fatalf("%s: err = %v, want ErrRuntimeDirWritable", name, err)
				}
				if r.runtimeDir != "" {
					t.Fatalf("%s: the run made %s before refusing", name, r.runtimeDir)
				}
			}
		})
	}
	t.Run("an entry beside it", func(t *testing.T) {
		t.Setenv("XDG_RUNTIME_DIR", "")
		r := &runner{id: "r-00000000-000000000000a-aaaaaa", log: slog.New(slog.DiscardHandler),
			rt: &agent.RuleTable{FS: []agent.FSRule{{Path: filepath.Join(logind, "cc-socks"), Kind: agent.FSWrite}}}}
		if err := r.createRuntimeDir(); err != nil {
			t.Fatalf("a write entry beside tego's directory was refused: %v", err)
		}
	})
}

// TestARunRefusesARuntimeDirectoryAnotherUserCouldSwap: the CODEX_HOME grant is
// opened by path at Prepare, so whoever can rename an entry on that path can move it. XDG_RUNTIME_DIR writable by
// others without the sticky bit, $XDG_RUNTIME_DIR/tego as a link or writable by group or others, are refused before
// the run makes its directory; a sticky world-writable XDG_RUNTIME_DIR (only an entry's owner may rename it) and a
// private one are not.
func TestARunRefusesARuntimeDirectoryAnotherUserCouldSwap(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root launcher makes no runtime directory")
	}
	fakeLogind(t)
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, xdg string)
		ok    bool
	}{
		{"a private XDG_RUNTIME_DIR", func(*testing.T, string) {}, true},
		{"a sticky world-writable XDG_RUNTIME_DIR", func(t *testing.T, xdg string) { chmod(t, xdg, 0o777|os.ModeSticky) }, true},
		{"a world-writable XDG_RUNTIME_DIR", func(t *testing.T, xdg string) { chmod(t, xdg, 0o777) }, false},
		{"a group-writable tego directory", func(t *testing.T, xdg string) {
			if err := os.Mkdir(filepath.Join(xdg, agent.RuntimeDirName), 0o700); err != nil {
				t.Fatal(err)
			}
			chmod(t, filepath.Join(xdg, agent.RuntimeDirName), 0o770)
		}, false},
		{"tego's directory a link", func(t *testing.T, xdg string) {
			if err := os.Symlink(t.TempDir(), filepath.Join(xdg, agent.RuntimeDirName)); err != nil {
				t.Fatal(err)
			}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			xdg := privateTempDir(t)
			t.Setenv("XDG_RUNTIME_DIR", xdg)
			tc.setup(t, xdg)
			r := codexRunner(&agent.RuleTable{})
			err := r.createRuntimeDir()
			if tc.ok {
				if err != nil || r.codexHome == "" {
					t.Fatalf("createRuntimeDir = %v (CODEX_HOME %q), want a CODEX_HOME", err, r.codexHome)
				}
				return
			}
			if !errors.Is(err, ErrRuntimeDirUnsafe) || r.codexHome != "" {
				t.Fatalf("createRuntimeDir = %v (CODEX_HOME %q), want ErrRuntimeDirUnsafe and none", err, r.codexHome)
			}
			// A run with no openai listener goes on without a runtime directory, as with no XDG_RUNTIME_DIR.
			plain := &runner{id: "r-00000000-000000000000b-bbbbbb", rt: &agent.RuleTable{}, log: slog.New(slog.DiscardHandler)}
			if err := plain.createRuntimeDir(); err != nil || plain.runtimeDir != "" {
				t.Fatalf("a run with no openai listener: %v, runtime directory %q; want none and no error", err, plain.runtimeDir)
			}
		})
	}
}

// privateTempDir is t.TempDir made 0700: XDG_RUNTIME_DIR must be writable by no one else (privateRuntimeDirs), and a
// umask of 002 leaves t.TempDir group-writable.
func privateTempDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	chmod(t, d, 0o700)
	return d
}

func chmod(t *testing.T, p string, m os.FileMode) {
	t.Helper()
	if err := os.Chmod(p, m); err != nil {
		t.Fatal(err)
	}
}

// codexRunner is a runner whose forwarder has an openai listener, so it writes a CODEX_HOME.
func codexRunner(rt *agent.RuleTable) *runner {
	return &runner{
		id: "r-00000000-000000000000a-aaaaaa", rt: rt, log: slog.New(slog.DiscardHandler),
		deps: Deps{Capture: []source.Source{&fakeLoopback{name: "forwarder", vars: map[string]string{envOpenAIBaseURL: "http://127.0.0.1:41001/v1"}}},
			Environ: []string{"HOME=/nonexistent"}},
	}
}

// TestTheCodexHomeGrantNeedsTheDirectoryTheRunMade: grantCodexHome resolved the CODEX_HOME
// path and granted whatever it led to. A process able to write the run's directory could swap codex/ for a link
// (into the ledger, say) or for another directory between writeCodexHome and the grant. The grant now requires the
// path, unfollowed, and its resolved spelling to be the directory writeCodexHome made.
func TestTheCodexHomeGrantNeedsTheDirectoryTheRunMade(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root launcher writes no CODEX_HOME")
	}
	for _, swap := range []string{"a link", "another directory"} {
		t.Run(swap, func(t *testing.T) {
			r := codexRunner(&agent.RuleTable{})
			r.runtimeDir = filepath.Join(t.TempDir(), "tego", string(r.id))
			if err := os.MkdirAll(r.runtimeDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := r.writeCodexHome(); err != nil {
				t.Fatal(err)
			}
			if r.codexHome == "" {
				t.Fatal("no CODEX_HOME written")
			}
			if err := os.Rename(r.codexHome, r.codexHome+".moved"); err != nil {
				t.Fatal(err)
			}
			elsewhere := t.TempDir()
			var err error
			if swap == "a link" {
				err = os.Symlink(elsewhere, r.codexHome)
			} else {
				err = os.Mkdir(r.codexHome, 0o700)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := r.grantCodexHome(); err == nil || !strings.Contains(err.Error(), "no longer the directory") {
				t.Fatalf("grantCodexHome = %v, want a refusal of the swapped directory", err)
			}
			for _, f := range r.rt.FS {
				if f.Runtime != "" {
					t.Fatalf("a grant was added: %+v", f)
				}
			}
		})
	}
	t.Run("unswapped", func(t *testing.T) {
		r := codexRunner(&agent.RuleTable{})
		r.runtimeDir = filepath.Join(t.TempDir(), "tego", string(r.id))
		if err := os.MkdirAll(r.runtimeDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := r.writeCodexHome(); err != nil {
			t.Fatal(err)
		}
		if err := r.grantCodexHome(); err != nil {
			t.Fatal(err)
		}
	})
}

// TestTheCodexHomeGrantRefusesAnExecDirectoryOverIt: compile's exec-writable check sees only the
// declared write entries, so an exec.allow directory over $XDG_RUNTIME_DIR compiled without a word and the agent
// ran a binary it copied into its CODEX_HOME while the exec list refused the real one. A run whose CODEX_HOME grant
// an allowed or asked exec directory covers is refused; a deny-list entry, a file entry and a directory elsewhere
// are not.
func TestTheCodexHomeGrantRefusesAnExecDirectoryOverIt(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root launcher writes no CODEX_HOME")
	}
	fakeLogind(t)
	xdg := privateTempDir(t)
	link := filepath.Join(t.TempDir(), "rt")
	if err := os.Symlink(xdg, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", xdg)
	refused := map[string]agent.ExecRule{
		"exec.allow over XDG_RUNTIME_DIR": {Path: xdg, IsDir: true, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow},
		"exec.allow over the parent":      {Path: filepath.Join(xdg, "tego") + "/", IsDir: true, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow},
		"exec.ask over it":                {Path: xdg, IsDir: true, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAsk},
		"through a link":                  {Path: link, Resolved: xdg, IsDir: true, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow},
	}
	for name, rule := range refused {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { _ = os.RemoveAll(filepath.Join(xdg, agent.RuntimeDirName)) })
			r := codexRunner(&agent.RuleTable{Exec: []agent.ExecRule{rule}})
			err := r.createRuntimeDir()
			if !errors.Is(err, ErrCodexHomeExecutable) || !strings.Contains(err.Error(), "contradiction") {
				t.Fatalf("err = %v, want ErrCodexHomeExecutable naming a contradiction", err)
			}
		})
	}
	for name, rule := range map[string]agent.ExecRule{
		"a directory elsewhere": {Path: t.TempDir(), IsDir: true, Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow},
		"a deny-list entry":     {Path: xdg, IsDir: true, Source: agent.ExecSourceAllow, Verdict: agent.VerdictRefused},
		"a file entry":          {Path: "/usr/bin/cp", Source: agent.ExecSourceAllow, Verdict: agent.VerdictAllow},
	} {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { _ = os.RemoveAll(filepath.Join(xdg, agent.RuntimeDirName)) })
			r := codexRunner(&agent.RuleTable{Exec: []agent.ExecRule{rule}})
			if err := r.createRuntimeDir(); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
}

// TestARunWithAnUnroutedCodexSaysSo: a root launcher writes no CODEX_HOME, so a run with an openai
// listener runs with Codex unrouted, and said so only in tego's own log. It writes gap what=capture
// why=codex-unrouted binary=codex after run_start; a run whose CODEX_HOME was written, or with no openai listener,
// writes none.
func TestARunWithAnUnroutedCodexSaysSo(t *testing.T) {
	for _, tc := range []struct {
		name      string
		codexHome string
		vars      map[string]string
		want      bool
	}{
		{"an openai listener and no CODEX_HOME", "", map[string]string{envOpenAIBaseURL: "http://127.0.0.1:41001/v1"}, true},
		{"a CODEX_HOME written", "/run/user/1/tego/r/codex", map[string]string{envOpenAIBaseURL: "http://127.0.0.1:41001/v1"}, false},
		{"no openai listener", "", map[string]string{"ANTHROPIC_BASE_URL": "http://127.0.0.1:41002"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRunner(Deps{Capture: []source.Source{&fakeLoopback{name: "forwarder", vars: tc.vars}}})
			r.codexHome = tc.codexHome
			r.rt = &agent.RuleTable{}
			r.queue = NewQueue(8)
			r.emitCodexUnroutedGap()
			r.queue.Close()
			var got []record.GapPayload
			for ev := range r.queue.C() {
				var p record.GapPayload
				if ev.Kind != record.KindGap || ev.DecodePayload(&p) != nil {
					t.Fatalf("queued %s", ev.Kind)
				}
				got = append(got, p)
			}
			var want []record.GapPayload
			if tc.want {
				want = []record.GapPayload{{What: record.GapCapture, Why: GapCodexUnrouted, Binary: "codex"}}
			}
			if !slices.Equal(got, want) {
				t.Fatalf("gaps %+v, want %+v", got, want)
			}
		})
	}
}

// TestRunStartCarriesTheRuntimeGrants: run_start lists every grant the run
// made on its own authority (agent-contract.md R10a) at record_minor 11 (MinorRuntimeGrants), from the real writeRunStart.
func TestRunStartCarriesTheRuntimeGrants(t *testing.T) {
	const id = "r-00000000-000000000000a-grants"
	dir := filepath.Join(t.TempDir(), id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "grants"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	home := "/run/user/1000/tego/" + id + "/codex"
	r := newTestRunner(Deps{Enforce: tierBackend{tier: backend.TierLandlock}})
	r.writer = w
	r.rt = &agent.RuleTable{
		FS: []agent.FSRule{
			{Path: "/work", Kind: agent.FSWrite, Raw: "/work"},
			{Path: home, Kind: agent.FSWrite, Access: agent.AccessWriteSet, Runtime: agent.CodexHomeGrant},
		},
		Net: []agent.NetRule{{Raw: "127.0.0.1:41001", Runtime: agent.CaptureGrant}},
	}
	if err := r.writeRunStart(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	evs := events(t, dir)
	if len(evs) == 0 || evs[0].Kind != record.KindRunStart {
		t.Fatalf("no run_start: %+v", evs)
	}
	var p record.RunStartPayload
	if err := evs[0].DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	want := runtimeGrants(r.rt)
	if len(want) != 2 || !slices.Equal(p.RuntimeGrants, want) || p.RecordMinor < record.MinorRuntimeGrants {
		t.Fatalf("run_start.runtime_grants = %q at record_minor %d, want %q at %d or later", p.RuntimeGrants, p.RecordMinor, want, record.MinorRuntimeGrants)
	}
	if !slices.Contains(p.RuntimeGrants, "fs.codex_home["+home+"]") {
		t.Fatalf("run_start.runtime_grants = %q holds no fs.codex_home grant", p.RuntimeGrants)
	}
}

// TestRunStartCarriesTheContractSource: run_start names the contract file the launching user named, by path or by
// a registry name (agent-contract.md R26), at record_minor 13 (MinorContractSource), from the real writeRunStart; a
// run with no source (a generated contract) writes none.
func TestRunStartCarriesTheContractSource(t *testing.T) {
	for _, src := range []*record.ContractSource{
		{Path: "/p/.tego/agents/retriever.yaml", Name: "retriever", Registry: "project"}, {Path: "/p/agent.yaml"}, nil,
	} {
		const id = "r-00000000-000000000000a-source"
		dir := filepath.Join(t.TempDir(), id)
		w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "retriever"}, ledger.WithAnchor(nopAnchor{}))
		if err != nil {
			t.Fatal(err)
		}
		r := newTestRunner(Deps{Enforce: tierBackend{tier: backend.TierLandlock}, ContractSource: src})
		r.writer = w
		r.rt = &agent.RuleTable{ContractPath: "/elsewhere/contract.yaml"}
		if err := r.writeRunStart(); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
			t.Fatal(err)
		}
		evs := events(t, dir)
		var p record.RunStartPayload
		if len(evs) == 0 || evs[0].DecodePayload(&p) != nil {
			t.Fatalf("no run_start: %+v", evs)
		}
		if p.RecordMinor < record.MinorContractSource || !reflect.DeepEqual(p.ContractSource, src) {
			t.Fatalf("run_start.contract_source = %+v at record_minor %d, want %+v at %d or later", p.ContractSource, p.RecordMinor, src, record.MinorContractSource)
		}
	}
}

// TestRunStartListsTheProfiles: run_start.profiles lists the profiles the contract merged, in merge order, with each
// one's source and sha256 (ADR 0066 D6), at record_minor 15 (MinorProfiles), from the real writeRunStart of a run and
// of an adoption, byte for byte; a contract that extends nothing writes none.
func TestRunStartListsTheProfiles(t *testing.T) {
	if string(agent.ProfileBuiltin) != record.ProfileSourceBuiltin || string(agent.ProfileDir) != record.ProfileSourceDir {
		t.Fatalf("agent's profile kinds %q %q are not the record's %q %q", agent.ProfileBuiltin, agent.ProfileDir,
			record.ProfileSourceBuiltin, record.ProfileSourceDir)
	}
	used := []agent.ProfileUse{
		{Name: "tego/python", Source: agent.ProfileBuiltin, SHA256: sha256.Sum256([]byte("python"))},
		{Name: "team", Source: agent.ProfileDir, SHA256: sha256.Sum256([]byte("team"))},
	}
	const golden = `"profiles":[{"name":"tego/python","source":"builtin","sha256":"11a4a60b518bf24989d481468076e5d5982884626aed9faeb35b8576fcd223e1"},` +
		`{"name":"team","source":"dir","sha256":"ca8b22d0db83a22db163b560b3e4e51527e533d31d067b614a0c33c4d2df8432"}]`
	for _, tc := range []struct {
		name     string
		profiles []agent.ProfileUse
		adopt    bool
	}{{"run", used, false}, {"adoption", used, true}, {"no extends", nil, false}} {
		t.Run(tc.name, func(t *testing.T) {
			const id = "r-00000000-000000000000a-profil"
			dir := filepath.Join(t.TempDir(), id)
			w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "retriever"}, ledger.WithAnchor(nopAnchor{}))
			if err != nil {
				t.Fatal(err)
			}
			r := newTestRunner(Deps{Enforce: tierBackend{tier: backend.TierLandlock}})
			r.writer = w
			r.rt = &agent.RuleTable{ContractPath: "/elsewhere/contract.yaml", Profiles: tc.profiles}
			if tc.adopt {
				a := &adoption{r: r, spec: AdoptSpec{Root: adopt.Process{PID: os.Getpid(), Argv: []string{"agent"}}}, env: adopt.Env{Proc: adopt.NewFS("")}}
				err = a.writeRunStart()
			} else {
				err = r.writeRunStart()
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
				t.Fatal(err)
			}
			line, err := os.ReadFile(filepath.Join(dir, ledger.EventsFile))
			if err != nil {
				t.Fatal(err)
			}
			first, _, _ := strings.Cut(string(line), "\n")
			var p record.RunStartPayload
			if evs := events(t, dir); len(evs) == 0 || evs[0].DecodePayload(&p) != nil || p.RecordMinor < record.MinorProfiles {
				t.Fatalf("no run_start at record_minor %d or later: %s", record.MinorProfiles, first)
			}
			if tc.profiles == nil {
				if strings.Contains(first, `"profiles"`) {
					t.Fatalf("a contract that extends nothing wrote profiles: %s", first)
				}
				return
			}
			if !strings.Contains(first, golden) {
				t.Fatalf("run_start does not carry\n%s\nin\n%s", golden, first)
			}
		})
	}
}

// TestRunStartCarriesHarnessAndProfiles: a run whose contract extends a profile and whose launcher provisioned a
// harness writes both run_start fields from the one writeRunStart (record_minor 14's harness, ADR 0062, and 15's
// profiles, ADR 0066 D6, merged into one payload by two packages), byte for byte, at record_minor 15 or later.
func TestRunStartCarriesHarnessAndProfiles(t *testing.T) {
	const id = "r-00000000-000000000000a-harpro"
	dir := filepath.Join(t.TempDir(), id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "retriever"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	r := newTestRunner(Deps{Enforce: tierBackend{tier: backend.TierLandlock}})
	r.writer = w
	r.rt = &agent.RuleTable{ContractPath: "/elsewhere/contract.yaml", Profiles: []agent.ProfileUse{
		{Name: "team", Source: agent.ProfileDir, SHA256: sha256.Sum256([]byte("team"))},
	}}
	r.harness.start = &record.HarnessStart{Name: "claude-code", Why: record.HarnessWhyNoProvisioner}
	if err := r.writeRunStart(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	line, err := os.ReadFile(filepath.Join(dir, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	first, _, _ := strings.Cut(string(line), "\n")
	var p record.RunStartPayload
	if evs := events(t, dir); len(evs) == 0 || evs[0].DecodePayload(&p) != nil {
		t.Fatalf("no run_start: %s", first)
	}
	if p.RecordMinor < record.MinorProfiles || p.RecordMinor < record.MinorHarness {
		t.Fatalf("run_start at record_minor %d, want %d or later", p.RecordMinor, record.MinorProfiles)
	}
	if !reflect.DeepEqual(p.Harness, r.harness.start) || len(p.Profiles) != 1 || p.Profiles[0].Name != "team" {
		t.Fatalf("run_start harness %+v profiles %+v, want %+v and team", p.Harness, p.Profiles, r.harness.start)
	}
	for _, want := range []string{
		`"harness":{"name":"claude-code","provisioned":false,"why":"no-provisioner"}`,
		`"profiles":[{"name":"team","source":"dir","sha256":"ca8b22d0db83a22db163b560b3e4e51527e533d31d067b614a0c33c4d2df8432"}]`,
	} {
		if !strings.Contains(first, want) {
			t.Fatalf("run_start does not carry\n%s\nin\n%s", want, first)
		}
	}
}
