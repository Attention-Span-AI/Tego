// SPDX-License-Identifier: Apache-2.0

package inforce

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestProgramEntriesTakeTheirFilesNames: a program entry's rule key is the name a run's lines give the file it
// resolved to, and its covers are the file's other rules and its own spelling's name, so every entry that resolved to
// one file counts that file's lines (rulesview's TestIntegrationRuleKeysAreARunsKeys holds them to a real run). An
// entry that resolves to the path an earlier one did (env after the command, bin/cat after cat, git diff after git
// status) is that rule; a link to a file is a rule of its own, named after the file's first; an entry with words is
// its program's rule; a quoted path is named without its quotes; the run command reached by a link is named after the
// command's file. The fixture's programs are #!/bin/sh scripts, so the command's file covers the /bin/sh its #! line
// was granted.
func TestProgramEntriesTakeTheirFilesNames(t *testing.T) {
	f := newFixture(t)
	link := filepath.Join(f.root, "alt", "cat")
	runLink := filepath.Join(f.root, "alt", "env")
	tool := filepath.Join(f.root, "my tools", "tool")
	for _, d := range []string{filepath.Dir(link), filepath.Dir(tool)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	for l, target := range map[string]string{link: filepath.Join(f.bin, "cat"), runLink: filepath.Join(f.bin, "env")} {
		if err := os.Symlink(target, l); err != nil {
			t.Fatal(err)
		}
	}
	env, cat := filepath.Join(f.bin, "env"), filepath.Join(f.bin, "cat")
	text := fmt.Sprintf("version: 0\nname: names\ncommand: [%q, \"agent.sh\"]\nexec:\n  allow: [env, cat, %q, %q, \"git status\", \"git diff\", %q]\n",
		env, cat, link, "'"+tool+"'")
	cp := filepath.Join(f.proj, "agent.yaml")
	if err := os.WriteFile(cp, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _, err := agent.LoadBytes(cp, []byte(text), nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	rt, _, err := agent.Compile(c, config.Builtin(), agent.WithPATH(f.bin), agent.WithCwd(f.proj), agent.WithHome(f.home),
		agent.Offline(), agent.WithRunCommand(runLink))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	v := Of(rt, backend.TierLandlock, "")

	// Every key a program row carries is a rule's name, one a run's line can carry, or an exec.allow entry's own
	// spelling, which a run on another PATH can give its lines (TestProgramKeysHoldOnAnotherPATH).
	names := map[string]bool{}
	for _, r := range rt.Exec {
		names[r.RuleName()] = true
	}
	for _, r := range v.Group(GroupPrograms).Rules {
		for _, k := range append([]string{r.RuleKey}, r.Covers...) {
			own := r.Key == "exec.allow" && k == ruleKey(kExecAllow, r.Entry)
			if k != "" && r.Key != "exec.deny" && r.Key != "exec.ask" && !names[k] && !own {
				t.Errorf("%s %q carries %s, which no rule of the table is named", r.Key, r.Entry, k)
			}
		}
	}
	want := []struct {
		key, entry, ruleKey string
		covers              []string
	}{
		{"exec.allow", "env", "exec[" + env + "]", []string{"exec[" + runLink + "]", "exec[/bin/sh]", "exec[env]"}},
		{"exec.allow", "cat", "exec[cat]", []string{"exec[" + link + "]"}},
		{"exec.allow", cat, "exec[cat]", []string{"exec[" + link + "]", "exec[" + cat + "]"}},
		{"exec.allow", link, "exec[cat]", []string{"exec[" + link + "]"}},
		{"exec.allow", "git status", "exec[git]", nil},
		{"exec.allow", "git diff", "exec[git]", nil},
		{"exec.allow", "'" + tool + "'", "exec[" + tool + "]", nil},
		{"run-command", runLink, "exec[" + env + "]", []string{"exec[" + runLink + "]", "exec[/bin/sh]"}},
	}
	for _, w := range want {
		r := findRule(t, &v, w.key, w.entry)
		if r.RuleKey != w.ruleKey || !slices.Equal(r.Covers, w.covers) {
			t.Errorf("%s %q: key %s covers %v, want %s %v", w.key, w.entry, r.RuleKey, r.Covers, w.ruleKey, w.covers)
		}
	}
	// The command resolved to the rule env's entry did, so a row of its own would only say that entry again.
	for _, r := range v.Rules() {
		if r.Key == "command" {
			t.Errorf("the command is listed beside the exec.allow entry that resolved to its rule: %+v", r)
		}
	}

	// A line counts for every entry of its file.
	v.Count(slices.Values([]string{"exec[cat]", "exec[" + link + "]", "exec[git]", "exec[" + env + "]"}))
	for _, w := range []struct {
		key, entry string
		hits       int
	}{
		{"exec.allow", "cat", 2}, {"exec.allow", cat, 2}, {"exec.allow", link, 2}, {"exec.allow", "git status", 1},
		{"exec.allow", "git diff", 1}, {"exec.allow", "env", 1}, {"run-command", runLink, 1}, {"exec.allow", "'" + tool + "'", 0},
	} {
		if r := findRule(t, &v, w.key, w.entry); r.Hits != w.hits {
			t.Errorf("%s %q: %d hits, want %d", w.key, w.entry, r.Hits, w.hits)
		}
	}

	// Read from the text alone, an entry with words is named by its program and a quoted path without its quotes.
	declaredKeys(t, text, cp, map[string]string{"git status": "exec[git]", "git diff": "exec[git]", "'" + tool + "'": "exec[" + tool + "]", cat: "exec[" + cat + "]"})
}

// TestProgramKeysHoldOnAnotherPATH: the dashboard compiles a run's contract on its own PATH, which need not be the
// run's (rulesview's loadCopy), so a bare name can resolve to another file there than in the run. Whichever of the two
// resolves it to the file a path entry names, every name the run's lines carry (the first rule of each file of the
// run's table) is still a key or a cover of the view built from the dashboard's table. Here the run found cat in its
// own directory and kept the path entry <bin>/cat as a rule of its own, which the dashboard merges into cat's.
func TestProgramKeysHoldOnAnotherPATH(t *testing.T) {
	f := newFixture(t)
	mine := filepath.Join(f.root, "mine")
	if err := os.MkdirAll(mine, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mine, "cat"), []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	text := fmt.Sprintf("version: 0\nname: paths\ncommand: [\"bash\", \"agent.sh\"]\nexec:\n  allow: [bash, cat, %q]\n", filepath.Join(f.bin, "cat"))
	cp := filepath.Join(f.proj, "agent.yaml")
	c, _, err := agent.LoadBytes(cp, []byte(text), nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	compile := func(path string) *agent.RuleTable {
		t.Helper()
		rt, _, err := agent.Compile(c, config.Builtin(), agent.WithPATH(path), agent.WithCwd(f.proj), agent.WithHome(f.home), agent.Offline())
		if err != nil {
			t.Fatalf("compile on %s: %v", path, err)
		}
		return rt
	}
	for _, p := range []struct{ run, dashboard string }{{mine + ":" + f.bin, f.bin}, {f.bin, mine + ":" + f.bin}} {
		run, dash := compile(p.run), compile(p.dashboard)
		v := Of(dash, backend.TierLandlock, "")
		listed := map[string]bool{}
		for _, r := range v.Rules() {
			for _, k := range append([]string{r.RuleKey}, r.Covers...) {
				listed[k] = true
			}
		}
		for _, same := range newExecNames(run).byFile {
			if name := run.Exec[same[0]].RuleName(); !listed[name] {
				t.Errorf("run on %s, dashboard on %s: the run's lines for %s carry %s, which the view does not list:\n%s",
					p.run, p.dashboard, run.Exec[same[0]].Path, name, render(&v, f.root))
			}
		}
	}
}

// TestCommandRowStaysBesideAnEntryWithWords: an entry with words for the command's program compiles to the command's
// rule, but the command is granted with any words (ADR 0048 (1)), which the entry does not say, so the command keeps
// its own row; both count the program's lines.
func TestCommandRowStaysBesideAnEntryWithWords(t *testing.T) {
	f := newFixture(t)
	text := "version: 0\nname: words\ncommand: [\"git\", \"log\"]\nexec:\n  allow: [bash, \"git status\"]\n"
	v := Of(f.compile(t, text, nil), backend.TierLandlock, "")
	d, err := Declared([]byte(text), "agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]*View{"compiled": &v, "declared": &d} {
		v.Count(slices.Values([]string{"exec[git]"}))
		for _, key := range []string{"command", "exec.allow"} {
			entry := map[string]string{"command": "git", "exec.allow": "git status"}[key]
			if r := findRule(t, v, key, entry); r.RuleKey != "exec[git]" || r.Hits != 1 {
				t.Errorf("%s: %s %q has key %s and %d hits, want exec[git] and 1", name, key, entry, r.RuleKey, r.Hits)
			}
		}
	}
}

// TestToolEntriesCoverItsHelperImages: compile grants a tool's helper images as rules of their own (git's exec-path
// git and the dashed helpers its entries' closures run, Source helper:git), and git re-runs itself from there (an
// allowed git commit runs <exec-path>/git maintenance, a line named after that rule), so every exec.allow entry of the
// tool covers them and a line of one counts for each such entry; an entry of another program covers none.
func TestToolEntriesCoverItsHelperImages(t *testing.T) {
	f := newFixture(t)
	core := filepath.Join(f.root, "lib", "git-core") // beside the fixture's bin/git, where compile looks (helperDir)
	if err := os.MkdirAll(core, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"git", "git-remote-https"} {
		if err := os.WriteFile(filepath.Join(core, n), []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	gitCore, remote := "exec["+filepath.Join(core, "git")+"]", "exec["+filepath.Join(core, "git-remote-https")+"]"
	for _, allow := range []string{`[bash, "git commit", "git fetch"]`, `[bash, git]`} {
		rt := f.compile(t, "version: 0\nname: helpers\ncommand: [\"bash\", \"agent.sh\"]\nexec:\n  allow: "+allow+"\n", nil)
		granted := map[string]bool{}
		for _, r := range rt.Exec {
			if fromSource(r.Source, agent.ExecSourceHelper+":git") {
				granted[r.RuleName()] = true
			}
		}
		if !granted[gitCore] || !granted[remote] {
			t.Fatalf("%s: compile granted the helper images %v, want %s and %s", allow, granted, gitCore, remote)
		}
		v := Of(rt, backend.TierLandlock, "")
		v.Count(slices.Values([]string{gitCore, remote, "exec[git]", "exec[bash]"}))
		for _, r := range v.Group(GroupPrograms).Rules {
			want, hits := []string{gitCore, remote}, 3
			if r.Entry == "bash" {
				// The command's rule, a #!/bin/sh script in the fixture, which compile grants /bin/sh.
				want, hits = []string{"exec[/bin/sh]"}, 1
			}
			if r.Key != "exec.allow" {
				continue
			}
			if !slices.Equal(r.Covers, want) || r.Hits != hits {
				t.Errorf("%s: %q covers %v with %d hits, want %v and %d", allow, r.Entry, r.Covers, r.Hits, want, hits)
			}
		}
	}
}

// TestScriptCommandCoversItsInterpreters: compile grants a script command the interpreter its #! line names and env's
// argument (Source interpreter:<script>), and an agent that runs one of them again writes a line named after that
// rule, so the command's row covers them, and so does an exec.allow entry that resolved to the command's rule and
// stands for it.
func TestScriptCommandCoversItsInterpreters(t *testing.T) {
	f := newFixture(t)
	env := filepath.Join(f.bin, "env")
	if err := os.WriteFile(filepath.Join(f.proj, "agent.sh"), []byte("#!"+env+" python3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	want := []string{"exec[" + env + "]", "exec[python3]"}
	for _, c := range []struct{ allow, key string }{{"[cat]", "command"}, {"[cat, ./agent.sh]", "exec.allow"}} {
		rt := f.compile(t, "version: 0\nname: script\ncommand: [\"./agent.sh\"]\nexec:\n  allow: "+c.allow+"\n", nil)
		v := Of(rt, backend.TierLandlock, "")
		v.Count(slices.Values([]string{"exec[python3]", "exec[" + env + "]", "exec[./agent.sh]", "exec[cat]"}))
		if r := findRule(t, &v, c.key, "./agent.sh"); r.RuleKey != "exec[./agent.sh]" || !slices.Equal(r.Covers, want) || r.Hits != 3 {
			t.Errorf("%s: the %s row of the script: key %s covers %v hits %d, want exec[./agent.sh] %v 3", c.allow, c.key, r.RuleKey, r.Covers, r.Hits, want)
		}
		if r := findRule(t, &v, "exec.allow", "cat"); len(r.Covers) != 0 || r.Hits != 1 {
			t.Errorf("%s: cat covers %v with %d hits, want none and 1", c.allow, r.Covers, r.Hits)
		}
	}
}

// TestEntryWordsAreReadAsCompileReadsThem: an exec.allow entry is a command pattern, whose words tego checks (best
// effort where the table has command rules), exactly when compile reads it as one (execmatch.IsPattern): a quoted
// path with a space is one word, a program the kernel enforces, and a tab separates words as a space does.
func TestEntryWordsAreReadAsCompileReadsThem(t *testing.T) {
	f := newFixture(t)
	tool := filepath.Join(f.root, "my tools", "tool")
	if err := os.MkdirAll(filepath.Dir(tool), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	quoted := "'" + tool + "'"
	rt := f.compile(t, fmt.Sprintf("version: 0\nname: words\ncommand: [\"bash\", \"agent.sh\"]\ntier: landlock\nexec:\n  allow: [bash, %q, \"git\\tstatus\"]\n", quoted), nil)
	v := Of(rt, backend.TierLandlock, "")
	if r := findRule(t, &v, "exec.allow", quoted); !r.Enforced || r.EnforcedText != textKernel || r.Sentence != "Can run tool" {
		t.Errorf("a quoted path with a space is one program the kernel enforces: %+v", r)
	}
	if r := findRule(t, &v, "exec.allow", "git\tstatus"); r.Enforced || r.EnforcedText != textTegoCommands || r.State != StateBestEffort ||
		r.RuleKey != "exec[git]" {
		t.Errorf("a pattern split by a tab is a command rule, best effort at tier landlock: %+v", r)
	}
}

// TestCommandKeyIsItsSpelling: a run names the command's rule as the command is written, so the command's row is keyed
// exec[<command as written>] in a view built from text as in a compiled one, and is left out of both beside an
// exec.allow entry that names the command the same way.
func TestCommandKeyIsItsSpelling(t *testing.T) {
	f := newFixture(t)
	if err := os.WriteFile(filepath.Join(f.proj, "agent.sh"), []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	bash := filepath.Join(f.bin, "bash")
	for _, c := range []struct {
		command, allow string
		row            bool
	}{
		{bash, "[cat]", true}, {"./agent.sh", "[cat]", true}, {"bash", "[cat]", true},
		{bash, fmt.Sprintf("[%q, cat]", bash), false}, {"./agent.sh", "[./agent.sh, cat]", false},
	} {
		text := fmt.Sprintf("version: 0\nname: cmd\ncommand: [%q, \"x\"]\nexec:\n  allow: %s\n", c.command, c.allow)
		d, err := Declared([]byte(text), "agent.yaml")
		if err != nil {
			t.Fatal(err)
		}
		compiled := Of(f.compile(t, text, nil), backend.TierLandlock, "")
		for name, v := range map[string]*View{"declared": &d, "compiled": &compiled} {
			var rows []Rule
			for _, r := range v.Rules() {
				if r.Key == "command" {
					rows = append(rows, r)
				}
			}
			switch {
			case !c.row && len(rows) != 0:
				t.Errorf("%s, %s %s: the command is listed beside the entry that names it: %+v", name, c.command, c.allow, rows)
			case c.row && (len(rows) != 1 || rows[0].RuleKey != "exec["+c.command+"]"):
				t.Errorf("%s, %s %s: the command's row is %+v, want one keyed exec[%s]", name, c.command, c.allow, rows, c.command)
			}
		}
	}
}

// TestFencedAllowRuleKeepsItsEntrysKey: a live fence entry that takes out an exec.deny name and names an exec.allow
// entry's path marks that entry's rule as the fence's (pkg/spec/agent liveExecMark), named live.fence[exec:<path>]. Its
// lines are the fence's refusals and lifts, so the entry's "Can run" row keeps its own key and counts none of them.
func TestFencedAllowRuleKeepsItsEntrysKey(t *testing.T) {
	f := newFixture(t)
	cat := filepath.Join(f.bin, "cat")
	rt := f.compile(t, "version: 0\nname: fence\ncommand: [python3, agent.py]\ntier: cgroup\nfs:\n  write: [out/]\n"+
		"exec:\n  allow: [python3, "+cat+"]\n  deny: [cat]\nenv: {pass: [PATH, HOME]}\n"+
		"live:\n  mode: adjustable\n  fence:\n    exec: ["+cat+"]\n", nil)
	fence := agent.LiveFenceRule(agent.LiveKindExec, cat)
	marked := false
	for _, r := range rt.Exec {
		marked = marked || r.Path == cat && r.Fence && fromSource(r.Source, agent.ExecSourceAllow) && r.RuleName() == fence
	}
	if !marked {
		t.Fatalf("compile did not mark the exec.allow rule of %s as the fence's: %+v", cat, rt.Exec)
	}
	v := Of(rt, backend.TierCgroup, "")
	v.Count(slices.Values([]string{fence, fence}))
	if r := findRule(t, &v, "exec.allow", cat); r.RuleKey != "exec["+cat+"]" || len(r.Covers) != 0 || r.Hits != 0 {
		t.Errorf("the fenced entry's row: key %s covers %v hits %d, want its own key exec[%s] and no hits", r.RuleKey, r.Covers, r.Hits, cat)
	}
}

// declaredKeys holds the rule key of each exec.allow entry of text, read as text alone, to want.
func declaredKeys(t *testing.T, text, path string, want map[string]string) {
	t.Helper()
	d, err := Declared([]byte(text), path)
	if err != nil {
		t.Fatal(err)
	}
	for entry, key := range want {
		if r := findRule(t, &d, "exec.allow", entry); r.RuleKey != key || len(r.Covers) != 0 {
			t.Errorf("declared %q: key %s covers %v, want %s", entry, r.RuleKey, r.Covers, key)
		}
	}
}
