// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// newProject makes an empty project folder beside the fixture's.
func (f *fixture) newProject(t *testing.T, name string) string {
	t.Helper()
	d := filepath.Join(f.dir, name)
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestNewPlanAndCreate: a preset form previews a contract that extends the presets, says its rules in sentences and
// writes nothing; Create writes it once, journals it, and the bounded set then holds it with no run, so DescribeNew
// and a change can name it; a second Create is refused and the file is untouched.
func TestNewPlanAndCreate(t *testing.T) {
	f := newFixture(t)
	dir := f.newProject(t, "My Project")
	req := NewReq{Dir: dir, Presets: []string{"no-secrets", "no-prod"}, Hosts: []string{"api.example.com:443", " "}, Command: "sh"}
	p, err := f.s.PlanNew(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !p.OK || len(p.Problems) > 0 {
		t.Fatalf("plan not OK: %+v", p)
	}
	if p.Name != "my-project" || p.File != filepath.Join(dir, "agent.yaml") || p.Base != rulefile.Sum(p.Text) {
		t.Fatalf("plan = name %q file %q", p.Name, p.File)
	}
	for _, want := range []string{"tego/no-secrets", "tego/no-prod", "api.example.com:443", "my-project"} {
		if !strings.Contains(string(p.Text), want) {
			t.Errorf("the draft lacks %q:\n%s", want, p.Text)
		}
	}
	if len(p.Groups) == 0 || !slices.ContainsFunc(p.Groups, func(g NewGroup) bool { return g.ID == "network" && len(g.Rules) > 0 }) {
		t.Errorf("no network sentences: %+v", p.Groups)
	}
	if !slices.ContainsFunc(p.Groups, func(g NewGroup) bool {
		return g.ID == "never-read" && slices.ContainsFunc(g.Rules, func(r NewRule) bool {
			return r.Effect == "deny" && strings.Contains(r.Sentence, "~/.ssh")
		}) && slices.ContainsFunc(g.Rules, func(r NewRule) bool { return strings.Contains(r.Sentence, "~/.aws") })
	}) {
		t.Errorf("the preview does not list the built-in secret refusals under Never reads: %+v", p.Groups)
	}
	if _, err := os.Stat(p.File); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("PlanNew wrote the file")
	}

	c, err := f.s.CreateNew(context.Background(), req, p.Base)
	if err != nil {
		t.Fatal(err)
	}
	if c.ID == "" || c.Path != p.File || c.Ref != refOf(p.File) {
		t.Fatalf("created = %+v", c)
	}
	if b, err := os.ReadFile(p.File); err != nil || string(b) != string(p.Text) {
		t.Fatalf("file = %q, %v", b, err)
	}
	es, _ := rulefile.ReadJournal(f.ledger)
	if len(es) != 1 || es[0].Op != rulefile.OpCreate || es[0].Via != Via || !strings.Contains(es[0].Summary, "no-secrets") {
		t.Fatalf("journal = %+v", es)
	}
	cs, err := f.s.Contracts()
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(cs, func(r ContractRef) bool { return r.Ref == c.Ref })
	if i < 0 || cs[i].Runs != 0 || !cs[i].Writable || cs[i].Agent != "my-project" {
		t.Fatalf("the new contract is not in the set as writable with no run: %+v", cs)
	}
	hs, err := f.s.History(c.Ref)
	if err != nil || len(hs) != 1 || hs[0].Op != rulefile.OpCreate || hs[0].Current {
		t.Fatalf("history of the new contract = %+v, %v: a create is listed and is not Current (Revert refuses it)", hs, err)
	}
	d, err := f.s.DescribeNew(context.Background(), c.Ref)
	if err != nil || !d.OK || d.Name != "my-project" || len(d.Groups) == 0 {
		t.Fatalf("DescribeNew = %+v, %v", d, err)
	}
	if _, err := f.s.DescribeNew(context.Background(), refOf(f.contract)); !errors.Is(err, ErrNoContract) {
		t.Errorf("DescribeNew of a contract with runs = %v", err)
	}
	cp, err := f.s.PlanChange(context.Background(), ChangeReq{Ref: c.Ref, Base: cs[i].Base, Edits: []Edit{{"add", "fs.deny_read", "./secret/"}}})
	if err != nil || cp.Err != "" {
		t.Fatalf("a change of the new contract: %+v, %v", cp, err)
	}

	if _, err := f.s.CreateNew(context.Background(), req, p.Base); !errors.Is(err, ErrRefused) {
		t.Fatalf("a second Create = %v, want ErrRefused", err)
	}
	again, _ := f.s.PlanNew(context.Background(), req)
	if !again.Exists || again.OK {
		t.Fatalf("a plan over an existing file = %+v", again)
	}
}

// TestNewRefusals: the project folder must be an existing directory of this user's, given as a full path or ~/, not
// writable by others, and not tego's own; the name must be an agent id; a preset is required; a stale base writes
// nothing and makes no folder.
func TestNewRefusals(t *testing.T) {
	f := newFixture(t)
	file := filepath.Join(f.dir, "a-file")
	writeFile(t, file, "x")
	open := f.newProject(t, "open")
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	tegoHome := filepath.Join(f.s.Home, ".tego", "p")
	if err := os.MkdirAll(tegoHome, 0o700); err != nil {
		t.Fatal(err)
	}
	inLedger := filepath.Join(f.ledger, "proj")
	if err := os.Mkdir(inLedger, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.dir, "to-ledger")
	if err := os.Symlink(f.ledger, link); err != nil {
		t.Fatal(err)
	}
	ok := f.newProject(t, "ok")
	for _, tc := range []struct {
		name string
		req  NewReq
		want string
	}{
		{"empty", NewReq{Presets: []string{"no-secrets"}}, "Type the project folder"},
		{"relative", NewReq{Dir: "proj", Presets: []string{"no-secrets"}}, "full path"},
		{"missing", NewReq{Dir: filepath.Join(f.dir, "nope"), Presets: []string{"no-secrets"}}, "does not exist"},
		{"file", NewReq{Dir: file, Presets: []string{"no-secrets"}}, "not a folder"},
		{"world-writable", NewReq{Dir: open, Presets: []string{"no-secrets"}}, "writable by every user"},
		{"tego home", NewReq{Dir: tegoHome, Presets: []string{"no-secrets"}}, "tego's own folder"},
		{"ledger", NewReq{Dir: inLedger, Presets: []string{"no-secrets"}}, "tego's own folder"},
		{"link to the ledger", NewReq{Dir: link, Presets: []string{"no-secrets"}}, "tego's own folder"},
		{"bad name", NewReq{Dir: ok, Name: "Bad Name", Presets: []string{"no-secrets"}}, "not an agent id"},
		{"no preset", NewReq{Dir: ok}, "Pick at least one preset"},
		{"unknown preset", NewReq{Dir: ok, Presets: []string{"yolo"}}, "unknown preset"},
		{"repo-only-writes with no folder", NewReq{Dir: ok, Presets: []string{"repo-only-writes"}}, "needs the folders"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := f.s.PlanNew(context.Background(), tc.req)
			if err != nil {
				t.Fatal(err)
			}
			if p.OK || !slices.ContainsFunc(p.Problems, func(s string) bool { return strings.Contains(strings.ToLower(s), strings.ToLower(tc.want)) }) {
				t.Fatalf("problems = %q, want one with %q", p.Problems, tc.want)
			}
			if _, err := f.s.CreateNew(context.Background(), tc.req, p.Base); !errors.Is(err, ErrRefused) {
				t.Fatalf("CreateNew = %v, want ErrRefused", err)
			}
		})
	}
	// ~/ is the invoking user's home.
	home := filepath.Join(f.s.Home, "work")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if p, _ := f.s.PlanNew(context.Background(), NewReq{Dir: "~/work", Presets: []string{"no-secrets"}}); p.Dir != home || !p.OK {
		t.Fatalf("~/work = %+v", p)
	}
	// A stale base: nothing written, no folder made.
	req := NewReq{Dir: ok, Presets: []string{"repo-only-writes"}, Writes: []string{"src/"}}
	if _, err := f.s.CreateNew(context.Background(), req, strings.Repeat("0", 64)); !errors.Is(err, ErrStale) {
		t.Fatalf("stale base = %v", err)
	}
	if ents, _ := os.ReadDir(ok); len(ents) != 0 {
		t.Fatalf("a refused create left %v", ents)
	}
	// A test compiler that refuses: not OK, nothing written.
	p, _ := f.s.PlanNew(context.Background(), NewReq{Dir: ok, Presets: []string{"no-secrets"}, Command: "broken"})
	if p.OK || len(p.Diagnostics) == 0 {
		t.Fatalf("a contract that does not compile = %+v", p)
	}
	if _, err := f.s.CreateNew(context.Background(), NewReq{Dir: ok, Presets: []string{"no-secrets"}, Command: "broken"}, p.Base); !errors.Is(err, ErrRefused) {
		t.Fatalf("CreateNew of a contract that does not compile = %v", err)
	}
}

// TestNewRealCompile: with the machine config and no test compiler, the draft compiles as tego compile --offline
// would: a command on the dashboard's PATH compiles, Create makes the preset's folders and writes; a command that is
// on no PATH is compile's error and nothing is written.
func TestNewRealCompile(t *testing.T) {
	f := newFixture(t)
	f.s.Compile = nil
	m := config.Builtin()
	m.Home = f.s.Home
	f.s.Machine = m
	bin := filepath.Join(f.dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "fakeagent"), []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	f.s.PATH = bin + ":/usr/bin:/bin"
	dir := f.newProject(t, "real")
	req := NewReq{Dir: dir, Name: "real", Presets: []string{"no-secrets", "repo-only-writes"}, Writes: []string{"src/"}, Command: "fakeagent --go"}
	p, err := f.s.PlanNew(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !p.OK {
		t.Fatalf("plan = %+v", p)
	}
	if !slices.Contains(p.MakeDirs, "src/") {
		t.Errorf("MakeDirs = %q", p.MakeDirs)
	}
	c, err := f.s.CreateNew(context.Background(), req, p.Base)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "src")); err != nil || !fi.IsDir() || !slices.Contains(c.Made, "src") {
		t.Fatalf("src/ not made: %v, made %q", err, c.Made)
	}

	other := f.newProject(t, "nopath")
	bad := NewReq{Dir: other, Name: "x", Presets: []string{"no-secrets"}, Command: "no-such-agent-anywhere"}
	p, _ = f.s.PlanNew(context.Background(), bad)
	if p.OK || !slices.ContainsFunc(p.Diagnostics, func(s string) bool { return strings.HasPrefix(s, "error:") }) {
		t.Fatalf("a command on no PATH = %+v", p)
	}
	if _, err := f.s.CreateNew(context.Background(), bad, p.Base); !errors.Is(err, ErrRefused) {
		t.Fatalf("CreateNew = %v", err)
	}
	if _, err := os.Stat(filepath.Join(other, "agent.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a contract that does not compile was written")
	}

	f.s.Machine = nil
	if p, _ := f.s.PlanNew(context.Background(), NewReq{Dir: other, Presets: []string{"no-secrets"}}); p.OK {
		t.Fatal("no machine config, and the plan is OK")
	}
}

// TestNewFromRunUnderANameYAMLReadsAsAnother: an agent id may be all digits or a word YAML reads as a bool or a null,
// and name is a string (R3), so the drafted contract writes it quoted, as tego init does: written plain it does not
// load, and the dashboard refuses a name its own form accepts. (This fixture's compiler always answers OK, so the
// test loads the draft itself.)
func TestNewFromRunUnderANameYAMLReadsAsAnother(t *testing.T) {
	f := newFixture(t)
	const run = "r-aaaaaaaa-0000000000001-learnx"
	f.writeRun(t, run, f.contract, 9)
	for _, name := range []string{"2024", "true", "null", "1e3"} {
		t.Run(name, func(t *testing.T) {
			p, err := f.s.PlanNew(context.Background(), NewReq{Dir: f.newProject(t, "n"+name), Name: name, FromRun: run})
			if err != nil {
				t.Fatal(err)
			}
			if !p.OK || len(p.Problems) > 0 {
				t.Fatalf("plan = %+v\n%s", p, p.Text)
			}
			c, ds, err := agent.LoadBytes(p.File, p.Text, nil)
			if err != nil || c.Name != name {
				t.Fatalf("the drafted contract does not load as %q: %v %v\n%s", name, err, ds, p.Text)
			}
		})
	}
}

// TestNewFromRun: "Start from a run" drafts the run's least-privilege proposal under the form's name.
func TestNewFromRun(t *testing.T) {
	f := newFixture(t)
	dir := f.newProject(t, "fromrun")
	const run = "r-aaaaaaaa-0000000000001-learnx"
	f.writeRun(t, run, f.contract, 9)
	p, err := f.s.PlanNew(context.Background(), NewReq{Dir: dir, Name: "learned", FromRun: run})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Problems) > 0 || !strings.Contains(string(p.Text), "\nname: \"learned\"\n") || p.FromRun != run {
		t.Fatalf("plan = %+v\n%s", p, p.Text)
	}
	if p, _ := f.s.PlanNew(context.Background(), NewReq{Dir: dir, FromRun: "../../etc"}); len(p.Problems) == 0 {
		t.Fatal("a bad run id drafted something")
	}
	if p, _ := f.s.PlanNew(context.Background(), NewReq{Dir: dir, FromRun: "r-zzzz-9999-none"}); len(p.Problems) == 0 {
		t.Fatal("a missing run drafted something")
	}
}

// TestNewSymlinkedProjectListedOnce: a project reached through a symlink is created at its resolved path; once a run
// records the contract by the symlinked path, the bounded set lists it once, as run, not also as "not run yet".
func TestNewSymlinkedProjectListedOnce(t *testing.T) {
	f := newFixture(t)
	realDir := f.newProject(t, "real-proj")
	link := filepath.Join(f.dir, "link-proj")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	req := NewReq{Dir: link, Presets: []string{"no-secrets"}, Command: "sh"}
	p, err := f.s.PlanNew(context.Background(), req)
	if err != nil || !p.OK {
		t.Fatalf("plan = %+v, %v", p, err)
	}
	c, err := f.s.CreateNew(context.Background(), req, p.Base)
	if err != nil {
		t.Fatal(err)
	}
	f.writeRun(t, "r-aaaa-0009-rules", filepath.Join(link, "agent.yaml"), 9)
	cs, err := f.s.Contracts()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range cs {
		if r.Ref == c.Ref {
			n++
			if r.Runs != 1 {
				t.Errorf("the symlinked project's contract has %d runs, want 1", r.Runs)
			}
		}
	}
	if n != 1 {
		t.Fatalf("the symlinked project's contract is listed %d times: %+v", n, cs)
	}
}

// TestNewAskReadSaysWhatItCosts: Ask before reading pins the whole policy to tier landlock, so the plan says so; with
// Adjustable, which writes tier cgroup, the plan says these reads are blocked without asking. A draft with neither says
// nothing.
func TestNewAskReadSaysWhatItCosts(t *testing.T) {
	f := newFixture(t)
	dir := f.newProject(t, "ask-proj")
	base := NewReq{Dir: dir, Presets: []string{"no-secrets"}, Command: "sh"}

	p, err := f.s.PlanNew(context.Background(), base)
	if err != nil || p.Protection != "" {
		t.Fatalf("a plain draft: %q, %v", p.Protection, err)
	}
	ask := base
	ask.AskRead = []string{"./notes/"}
	p, err = f.s.PlanNew(context.Background(), ask)
	if err != nil || p.Protection != askReadBasic || !strings.Contains(string(p.Text), "tier: landlock") {
		t.Fatalf("Ask before reading: %q, %v\n%s", p.Protection, err, p.Text)
	}
	adj := ask
	adj.LiveMode = NewLiveAdjustable
	p, err = f.s.PlanNew(context.Background(), adj)
	if err != nil || p.Protection != askReadAdjustable || !strings.Contains(string(p.Text), "tier: cgroup") {
		t.Fatalf("with Adjustable: %q, %v\n%s", p.Protection, err, p.Text)
	}
}

// TestNewAgentPolicyCompiles: a policy made on the dashboard for an interactive agent compiles with the real compiler,
// under all three presets, on a machine that has the agent.
func TestNewAgentPolicyCompiles(t *testing.T) {
	for _, command := range []string{"claude", "codex --no-daemon"} {
		f := newFixture(t)
		f.s.Compile = nil
		m := config.Builtin()
		m.Home = f.s.Home
		f.s.Machine = m
		bin := filepath.Join(f.dir, "bin")
		if err := os.Mkdir(bin, 0o700); err != nil {
			t.Fatal(err)
		}
		agent, _, _ := strings.Cut(command, " ")
		if err := os.WriteFile(filepath.Join(bin, agent), []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		f.s.PATH = bin + ":/usr/bin:/bin"
		req := NewReq{Dir: f.newProject(t, "agent-proj"), Name: "agent", Presets: []string{"no-secrets", "no-prod", "repo-only-writes"},
			Writes: []string{"src/"}, Command: command}
		p, err := f.s.PlanNew(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if !p.OK || !strings.Contains(string(p.Text), `"/dev/tty"`) {
			t.Errorf("%s: OK %v, problems %v, diagnostics %v\n%s", command, p.OK, p.Problems, p.Diagnostics, p.Text)
		}
	}
}
