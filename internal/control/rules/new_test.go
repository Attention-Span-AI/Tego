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

	"gopkg.in/yaml.v3"

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

// TestNewRefusesALinkWhereAFolderIsMade: a symbolic link in the project folder where Create must make a folder (a .tego
// linked out of the project, as an agent that may write the project could leave it) refuses Create, naming the link:
// no folder is made where it leads, the folder made before it is removed, and no agent.yaml is written.
func TestNewRefusesALinkWhereAFolderIsMade(t *testing.T) {
	f := newFixture(t)
	dir := f.newProject(t, "linked")
	outside := f.newProject(t, "outside")
	link := filepath.Join(dir, ".tego")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	req := NewReq{Dir: dir, Presets: []string{"repo-only-writes"}, Writes: []string{"src/"}, Command: "sh"}
	p, err := f.s.PlanNew(context.Background(), req)
	if err != nil || !p.OK || !slices.Equal(p.MakeDirs, []string{"src/", ".tego/tmp/"}) {
		t.Fatalf("plan = %+v, %v", p, err)
	}
	if _, err := f.s.CreateNew(context.Background(), req, p.Base); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), link+" is a symbolic link") {
		t.Fatalf("CreateNew through a link = %v", err)
	}
	if es, _ := os.ReadDir(outside); len(es) > 0 {
		t.Errorf("a folder was made where the link leads: %v", es)
	}
	for _, name := range []string{"src", NewFile} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			t.Errorf("%s is left in the project", name)
		}
	}
}

// swapThenFail is a Writer whose Create stands in for an agent.yaml write that fails after swap ran: a process of the
// same uid swapping a folder of the project between the making of the plan's folders and that write.
type swapThenFail struct {
	Writer
	swap func()
}

func (w swapThenFail) Create(context.Context, string, []byte, rulefile.Change) (*rulefile.Entry, error) {
	w.swap()
	return nil, errors.New("refused after the swap")
}

// TestNewRemovesNoFolderThroughALink: when agent.yaml's write fails after the plan's folders were made, CreateNew
// removes them beneath the project folder (setup.Remove). A .tego swapped meanwhile for a link to a folder holding an
// empty tmp/ leaves that tmp/ where it is, which a removal by path took, and src/, still a folder of the project,
// goes.
func TestNewRemovesNoFolderThroughALink(t *testing.T) {
	f := newFixture(t)
	dir := f.newProject(t, "swapped")
	outside := f.newProject(t, "outside")
	if err := os.Mkdir(filepath.Join(outside, "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	req := NewReq{Dir: dir, Presets: []string{"repo-only-writes"}, Writes: []string{"src/"}, Command: "sh"}
	p, err := f.s.PlanNew(context.Background(), req)
	if err != nil || !p.OK || !slices.Equal(p.MakeDirs, []string{"src/", ".tego/tmp/"}) {
		t.Fatalf("plan = %+v, %v", p, err)
	}
	tego := filepath.Join(p.Dir, ".tego")
	f.s.Writer = swapThenFail{Writer: localWriter{f.s.guard()}, swap: func() {
		if err := os.Rename(tego, tego+".moved"); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(outside, tego); err != nil {
			t.Error(err)
		}
	}}
	if _, err := f.s.CreateNew(context.Background(), req, p.Base); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "refused after the swap") {
		t.Fatalf("CreateNew = %v", err)
	}
	if fi, err := os.Lstat(filepath.Join(outside, "tmp")); err != nil || !fi.IsDir() {
		t.Errorf("the empty tmp/ where the swapped-in link leads was removed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(p.Dir, "src")); err == nil {
		t.Error("src/, made for the contract, is left in the project")
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

// TestRenamedSetsTheNameKey: "Start from a run" names the proposal through its YAML tree, not by the first line that
// starts with name:. Only the top-level key's value changes, so a comment on its line stays, a name: line inside
// another value is left alone, a key spelled another way is found, and every other byte is kept; a name over two
// lines is set by writing the tree out, its comments kept. Text with no top-level name comes back as it was.
func TestRenamedSetsTheNameKey(t *testing.T) {
	for _, tc := range []struct{ why, in, want string }{
		{"a comment on the name line",
			"# name: the header's own words\nversion: 0\nname: learned-x  # name: from the run's agent\ncommand: [sh]\n",
			"# name: the header's own words\nversion: 0\nname: \"fresh\"  # name: from the run's agent\ncommand: [sh]\n"},
		{"a name: line inside the command, before the key",
			"version: 0\ncommand: [\"sh\", \"-c\", \"echo a\nname: b\"]\nname: learned-x\n",
			"version: 0\ncommand: [\"sh\", \"-c\", \"echo a\nname: b\"]\nname: \"fresh\"\n"},
		{"a quoted key", "version: 0\n\"name\" : 'learned-x'\n", "version: 0\n\"name\" : \"fresh\"\n"},
		{"carriage returns", "version: 0\r\nname: learned-x # c\r\n", "version: 0\r\nname: \"fresh\" # c\r\n"},
		{"no name", "version: 0\ncommand: [sh]\n", "version: 0\ncommand: [sh]\n"},
	} {
		if got := string(renamed([]byte(tc.in), "fresh")); got != tc.want {
			t.Errorf("%s: renamed =\n%q\nwant\n%q", tc.why, got, tc.want)
		}
	}
	got := renamed([]byte("version: 0\n# the agent\nname: learned\n  x\ncommand: [sh]\n"), "fresh")
	var c struct {
		Name    string
		Command []string
	}
	if err := yaml.Unmarshal(got, &c); err != nil || c.Name != "fresh" || !slices.Equal(c.Command, []string{"sh"}) ||
		!strings.Contains(string(got), "# the agent") {
		t.Errorf("a name over two lines: %v %+v\n%s", err, c, got)
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

// TestBuiltInSecretRulesFollowFamilies: the preview's Never reads rows group the built-in list by each row's family
// (agent.BuiltInDenyReadFamily), not by its spelling: ~/.ssh is in the SSH keys row, every login row is in the logins
// row and no other row is, and the browser profiles are one row that names the browsers, not their folders.
func TestBuiltInSecretRulesFollowFamilies(t *testing.T) {
	const sshRow, loginRow, browserRow = "Never reads your SSH keys", "Never reads cloud, registry and git logins", "Never reads browser profiles"
	named := map[string][]string{} // a row's lead -> what its parentheses name
	for _, r := range builtInSecretRules() {
		if lead, rest, ok := strings.Cut(r.Sentence, " ("); ok {
			inside, _, _ := strings.Cut(rest, ")")
			named[lead] = strings.Split(inside, ", ")
		}
	}
	if len(named) != 3 || len(named[sshRow]) == 0 || len(named[loginRow]) == 0 || len(named[browserRow]) == 0 {
		t.Fatalf("the rows that name paths or browsers are %q, want the SSH keys, logins and browser profiles rows", named)
	}
	logins := 0
	for _, rel := range agent.BuiltInDenyRead() {
		want := "" // a browser profile is named by its browser, in no row by its folder
		switch f := agent.BuiltInDenyReadFamily(rel); f {
		case agent.SecretSSHKeys:
			want = sshRow
		case agent.SecretLogins:
			want, logins = loginRow, logins+1
		case agent.SecretBrowsers:
		default:
			t.Errorf("~/%s has family %q, which this page has no row for", rel, f)
		}
		for lead, items := range named {
			if in := slices.Contains(items, "~/"+rel); in != (lead == want) {
				t.Errorf("~/%s named in the %q row: %v", rel, lead, in)
			}
		}
	}
	if len(named[loginRow]) != logins {
		t.Errorf("the logins row names %d paths, want the %d login rows once each", len(named[loginRow]), logins)
	}
}
