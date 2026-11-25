// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/inforce"
	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// sourceText is the rules file a fixture run names: comments and blank lines put its entries on other lines than
// the canonical copy's, so a test tells source positions from copy positions.
const sourceText = `# the demo agent
version: 0
name: demo
command: [sh]
capture: off

# where it may write
fs:
  write:
    - ./out/
    - ./tmp/
exec:
  allow: [sh, git]
`

// fixture is one run under a ledger root: its rules file, its copy, its ledger.
type fixture struct {
	root, proj, home, run, dir, source string
	started                            time.Time
	lines                              bytes.Buffer
	seq                                int
	m                                  *config.Machine
}

// newFixture writes the rules file and a run of it that started an hour ago, holding only run_start.
func newFixture(t testing.TB, run string) *fixture { return newFixtureWith(t, run, sourceText, "") }

// newFixtureWith is newFixture with the rules file's text and extra run_start fields (`,"key":value` pairs) given.
func newFixtureWith(t testing.TB, run, text, startExtra string) *fixture {
	t.Helper()
	base := t.TempDir()
	f := &fixture{root: filepath.Join(base, "ledger"), proj: filepath.Join(base, "proj"), home: filepath.Join(base, "home"), run: run}
	f.dir = filepath.Join(f.root, run)
	f.source = filepath.Join(f.proj, "agent.yaml")
	for _, d := range []string{f.dir, filepath.Join(f.proj, "out"), filepath.Join(f.proj, "tmp"), f.home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(f.source, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	c, _, err := agent.LoadBytes(f.source, []byte(text), &agent.ProfileChain{})
	if err != nil {
		t.Fatal(err)
	}
	canon, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sum, _ := c.Hash()
	if err := os.WriteFile(filepath.Join(f.dir, "contract.yaml"), canon, 0o644); err != nil {
		t.Fatal(err)
	}
	f.started = time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	f.add(fmt.Sprintf(`"kind":"run_start","source":"supervisor","tier":"landlock","command":["sh"],"cwd":"%s","contract_hash":"%s","contract_source":{"path":"%s"}%s`,
		f.proj, hex.EncodeToString(sum[:]), f.source, startExtra))
	f.m = &config.Machine{Home: f.home}
	f.m.LedgerRoot.Value = f.root
	return f
}

// add appends one ledger line with rest after the common fields.
func (f *fixture) add(rest string) {
	fmt.Fprintf(&f.lines, `{"v":1,"seq":%d,"id":"%064x","prev":"","ts":"%s","mono_ns":%d,"run":"%s","agent":"demo","pid":10,"tid":10,"cgroup":1,%s}`+"\n",
		f.seq, f.seq+1, f.started.Add(time.Duration(f.seq)*time.Millisecond).Format(time.RFC3339Nano), f.seq+1, f.run, rest)
	f.seq++
}

// inForce writes the ledger and reads the view.
func (f *fixture) inForce(t *testing.T) *InForceView {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "events.jsonl"), f.lines.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	v := InForce(context.Background(), f.root, f.run, Options{Machine: f.m})
	if v.Err != "" {
		t.Fatalf("InForce: %s", v.Err)
	}
	return v
}

// rule is the view's rule of key and entry.
func rule(t *testing.T, v *InForceView, key, entry string) inforce.Rule {
	t.Helper()
	for _, r := range v.View.Rules() {
		if r.Key == key && r.Entry == entry {
			return r
		}
	}
	t.Fatalf("no rule %s %s in the view:\n%s", key, entry, v.View.Text())
	return inforce.Rule{}
}

// lineOf is the 1-based line of text that holds needle.
func lineOf(t *testing.T, text, needle string) int {
	t.Helper()
	for i, l := range strings.Split(text, "\n") {
		if strings.Contains(l, needle) {
			return i + 1
		}
	}
	t.Fatalf("%q not in\n%s", needle, text)
	return 0
}

// TestInForceGroupsHitsAndSourcePositions: an unchanged rules file gives the view its positions (lines of the real
// file, not of the canonical copy), the groups hold the entries, each line counts once for its rule, and nothing is
// pending.
func TestInForceGroupsHitsAndSourcePositions(t *testing.T) {
	f := newFixture(t, "r-aaaaaaaa-0000000000010-groups")
	f.add(`"kind":"fs","source":"landlock","rule":"fs.write[./out/]","verdict":"allow","op":"write","path":"/x/out/a"`)
	f.add(`"kind":"fs","source":"landlock","rule":"fs.write[./out/]","verdict":"allow","op":"write","path":"/x/out/b"`)
	f.add(`"kind":"exec","source":"seccomp","rule":"exec[git]","verdict":"allow","authority":"rule","argv":["git"],"exec_id":"x/10/1","path":"/usr/bin/git"`)
	f.add(`"kind":"net","source":"supervisor","rule":"unmatched","verdict":"refused","authority":"rule","attribution":{"confidence":"unattributed","method":"none"},"dst":"203.0.113.9:443","proto":"tcp"`)
	v := f.inForce(t)
	if v.Positions != PositionsSource || v.PositionsWhy != "" {
		t.Fatalf("positions %q (%s), want the source's", v.Positions, v.PositionsWhy)
	}
	if !v.View.Compiled || v.View.Tier != "landlock" {
		t.Errorf("compiled %v tier %q, want a landlock compile", v.View.Compiled, v.View.Tier)
	}
	out := rule(t, v, "fs.write", "./out/")
	if out.Group != inforce.GroupChange || out.Hits != 2 {
		t.Errorf("fs.write ./out/: group %q hits %d, want change and 2", out.Group, out.Hits)
	}
	if want := lineOf(t, sourceText, "- ./out/"); out.Source.File != f.source || out.Source.Line != want {
		t.Errorf("fs.write ./out/ at %s:%d, want %s:%d", out.Source.File, out.Source.Line, f.source, want)
	}
	if git := rule(t, v, "exec.allow", "git"); git.Hits != 1 || git.Group != inforce.GroupPrograms {
		t.Errorf("exec.allow git: group %q hits %d, want programs and 1", git.Group, git.Hits)
	}
	if rule(t, v, "fs.write", "./tmp/").Hits != 0 {
		t.Error("an unused entry has hits")
	}
	if v.View.Unmatched != 1 {
		t.Errorf("unmatched %d, want 1", v.View.Unmatched)
	}
	if v.Lines != 5 || v.Ended || !v.Started.Equal(f.started) {
		t.Errorf("lines %d ended %v started %v, want 5, false, %v", v.Lines, v.Ended, v.Started, f.started)
	}
	if v.Pending != nil {
		t.Errorf("pending %+v for an unchanged rules file", v.Pending)
	}
	if v.Contract.Table == "" || v.Contract.Text == "" {
		t.Error("the copy's text and compile table are missing (the page's details)")
	}
}

// TestInForceDefaultHits: each line no rule named counts on the default of the group that decided it (an exec line on
// the programs', a net line on the network's), whether the ledger is read or the read model's run is handed in; a file
// line counts in the run's total alone.
func TestInForceDefaultHits(t *testing.T) {
	f := newFixture(t, "r-aaaaaaaa-0000000000017-dhits1")
	attr := `"attribution":{"confidence":"unattributed","method":"none"}`
	f.add(`"kind":"exec","source":"seccomp","rule":"unmatched","verdict":"refused","authority":"rule",` + attr + `,"argv":["curl"],"exec_id":"x/10/3","path":"/usr/bin/curl"`)
	for range 2 {
		f.add(`"kind":"net","source":"supervisor","rule":"unmatched","verdict":"allow",` + attr + `,"dst":"203.0.113.9:443","proto":"tcp"`)
	}
	f.add(`"kind":"fs","source":"seccomp","rule":"unmatched","verdict":"observed",` + attr + `,"op":"open","path":"/etc/hosts"`)
	f.add(`"kind":"exec","source":"seccomp","rule":"exec[git]","verdict":"allow","authority":"rule",` + attr + `,"argv":["git"],"exec_id":"x/10/4","path":"/usr/bin/git"`)
	scanned := f.inForce(t)
	r, err := ledgerview.Open(f.root).Run(f.run)
	if err != nil {
		t.Fatal(err)
	}
	cached := InForce(context.Background(), f.root, f.run, Options{Machine: f.m, Run: r})
	for name, v := range map[string]*InForceView{"ledger": scanned, "read model": cached} {
		want := map[string]int{inforce.GroupPrograms: 1, inforce.GroupNetwork: 2}
		for _, g := range v.View.Groups {
			if g.DefaultHits != want[g.ID] {
				t.Errorf("%s: %s default hits %d, want %d", name, g.ID, g.DefaultHits, want[g.ID])
			}
		}
		if v.View.Unmatched != 4 {
			t.Errorf("%s: unmatched %d, want 4", name, v.View.Unmatched)
		}
	}
}

// TestInForceCopyPositionsAfterTheSourceChanged: the rules file was edited by hand after the run started, so its
// lines no longer hold the run's rules: positions name the run's copy, the rules shown are the run's, and Pending
// says the file was edited.
func TestInForceCopyPositionsAfterTheSourceChanged(t *testing.T) {
	f := newFixture(t, "r-aaaaaaaa-0000000000011-edited")
	if err := os.WriteFile(f.source, []byte(strings.Replace(sourceText, "    - ./tmp/\n", "", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	v := f.inForce(t)
	if v.Positions != PositionsCopy || !strings.Contains(v.PositionsWhy, "no longer loads to the rules this run ran") {
		t.Fatalf("positions %q (%s), want the copy's because the file no longer loads to the run's rules", v.Positions, v.PositionsWhy)
	}
	tmp := rule(t, v, "fs.write", "./tmp/") // the run's rule, gone from the file
	copyText := v.Contract.Text
	if want := lineOf(t, copyText, "- ./tmp/"); tmp.Source.File != v.CopyPath || tmp.Source.Line != want {
		t.Errorf("fs.write ./tmp/ at %s:%d, want the copy %s:%d", tmp.Source.File, tmp.Source.Line, v.CopyPath, want)
	}
	if v.Pending == nil || v.Pending.Edited.IsZero() || len(v.Pending.Changes) != 0 {
		t.Fatalf("pending %+v, want an edit outside the journal", v.Pending)
	}
}

// TestInForcePendingFromTheJournal: a change written through rulefile after the run started is pending with its
// sentences, not an unexplained edit; undoing it brings the file back to the run's rules and nothing is pending.
func TestInForcePendingFromTheJournal(t *testing.T) {
	f := newFixture(t, "r-aaaaaaaa-0000000000012-jrnlpd")
	g := rulefile.DefaultGuard(f.root)
	cur, err := rulefile.Read(f.source, g)
	if err != nil {
		t.Fatal(err)
	}
	next := strings.Replace(sourceText, "  allow: [sh, git]\n", "  allow: [sh]\n", 1)
	_, err = rulefile.Replace(context.Background(), g, f.source, cur.SHA256, []byte(next), rulefile.Change{
		Via: "dashboard", Run: f.run, Line: 3, Summary: "remove git from the programs",
		Sentences: []string{"May run git → Can never run git"}, Direction: "narrows"})
	if err != nil {
		t.Fatal(err)
	}
	v := f.inForce(t)
	if v.Pending == nil || len(v.Pending.Changes) != 1 {
		t.Fatalf("pending %+v, want the one journaled change", v.Pending)
	}
	ch := v.Pending.Changes[0]
	if ch.Summary != "remove git from the programs" || len(ch.Sentences) != 1 || ch.Via != "dashboard" {
		t.Errorf("change %+v, want the journal's summary, sentence and via", ch)
	}
	if !v.Pending.Edited.IsZero() {
		t.Errorf("edited %v: the journal accounts for the change", v.Pending.Edited)
	}
	if rule(t, v, "exec.allow", "git").Source.File != v.CopyPath {
		t.Error("the run's git rule does not point at the copy after the file changed")
	}
	if _, err := rulefile.Undo(context.Background(), g, f.source, rulefile.RevertOptions{Change: rulefile.Change{Via: "dashboard"}}); err != nil {
		t.Fatal(err)
	}
	v = f.inForce(t)
	if v.Pending != nil || v.Positions != PositionsSource {
		t.Errorf("after undo: pending %+v positions %q, want none and the source's", v.Pending, v.Positions)
	}
}

// TestInForcePendingAfterAnUndo: a change undone since the run started is no longer pending, and neither is the undo
// that undid it; an undo of a change made before the run started is pending, said as what it undid, never as the
// journal's raw summary.
func TestInForcePendingAfterAnUndo(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, "r-aaaaaaaa-0000000000013-undopd")
	g := rulefile.DefaultGuard(f.root)
	write := func(old, next, summary, sentence string) *rulefile.Entry {
		t.Helper()
		cur, err := rulefile.Read(f.source, g)
		if err != nil {
			t.Fatal(err)
		}
		e, err := rulefile.Replace(ctx, g, f.source, cur.SHA256, []byte(strings.Replace(string(cur.Text), old, next, 1)),
			rulefile.Change{Via: "dashboard", Summary: summary, Sentences: []string{sentence}, Direction: "narrows"})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	undo := func() {
		t.Helper()
		if _, err := rulefile.Undo(ctx, g, f.source, rulefile.RevertOptions{Change: rulefile.Change{Via: "dashboard"}}); err != nil {
			t.Fatal(err)
		}
	}
	// Two changes after the start, the second undone: only the first is pending.
	write("  allow: [sh, git]\n", "  allow: [sh]\n", "exec.allow -= git", "Can run git → Cannot run git")
	write("    - ./tmp/\n", "", "fs.write -= ./tmp/", "Can change ./tmp/ → Cannot change ./tmp/")
	undo()
	v := f.inForce(t)
	if v.Pending == nil || len(v.Pending.Changes) != 1 || v.Pending.Changes[0].Summary != "exec.allow -= git" {
		t.Fatalf("pending %+v, want only the change that stands", v.Pending)
	}

	// A run that started after a change ran its text; undoing that change is pending, in words.
	f = newFixture(t, "r-aaaaaaaa-0000000000014-undopr")
	g = rulefile.DefaultGuard(f.root)
	a := write("  allow: [sh, git]\n", "  allow: [sh]\n", "exec.allow -= git", "Can run git → Cannot run git")
	ranText, err := os.ReadFile(f.source)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := agent.LoadBytes(f.source, ranText, &agent.ProfileChain{})
	if err != nil {
		t.Fatal(err)
	}
	canon, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sum, _ := c.Hash()
	if err := os.WriteFile(filepath.Join(f.dir, "contract.yaml"), canon, 0o644); err != nil {
		t.Fatal(err)
	}
	f.lines.Reset()
	f.seq, f.started = 0, a.At.Add(time.Millisecond)
	f.add(fmt.Sprintf(`"kind":"run_start","source":"supervisor","tier":"landlock","command":["sh"],"cwd":"%s","contract_hash":"%s","contract_source":{"path":"%s"}%s`,
		f.proj, hex.EncodeToString(sum[:]), f.source, ""))
	if v := f.inForce(t); v.Pending != nil {
		t.Fatalf("pending %+v before the undo: the run ran the file as it is", v.Pending)
	}
	time.Sleep(5 * time.Millisecond)
	undo()
	v = f.inForce(t)
	if v.Pending == nil || len(v.Pending.Changes) != 1 {
		t.Fatalf("pending %+v, want the undo", v.Pending)
	}
	if ch := v.Pending.Changes[0]; ch.Summary != "Undid: Cannot run git" || len(ch.Sentences) != 0 || ch.Op != rulefile.OpRevert {
		t.Errorf("the undo reads %q (sentences %q), want Undid: Cannot run git", ch.Summary, ch.Sentences)
	}
}

// TestUndoWords: an undo is said from the change it undid; an undo of an undo puts that change back; a change the
// journal holds no sentences for is "an earlier change".
func TestUndoWords(t *testing.T) {
	byID := map[string]rulefile.Entry{
		"c1": {ID: "c1", Op: rulefile.OpChange, Sentences: []string{"Asks you before it reads ./confidential/ → Can never read ./confidential/", "(nothing) → Cannot run curl"}},
		"r1": {ID: "r1", Op: rulefile.OpRevert, Reverts: "c1"},
		"r2": {ID: "r2", Op: rulefile.OpRevert, Reverts: "r1"},
		"c0": {ID: "c0", Op: rulefile.OpChange, Summary: "fs.ask_read -= ./x/"},
		"r0": {ID: "r0", Op: rulefile.OpRevert, Reverts: "c0"},
	}
	for id, want := range map[string]string{
		"r1": "Undid: Can never read ./confidential/; Cannot run curl",
		"r2": "Redid: Can never read ./confidential/; Cannot run curl",
		"r0": "Undid an earlier change",
	} {
		if got := UndoWords(byID[id], byID); got != want {
			t.Errorf("UndoWords(%s) = %q, want %q", id, got, want)
		}
	}
	if got := UndoWords(rulefile.Entry{Op: rulefile.OpRevert, Reverts: "gone"}, byID); got != "Undid an earlier change" {
		t.Errorf("an undo of an entry the journal lost: %q", got)
	}
}

// TestInForceLiveBlocks: a running run's live block is in the live group with the hits of its refusals; once the
// run has ended its blocks leave the group, with a note that they refuse nothing now.
func TestInForceLiveBlocks(t *testing.T) {
	f := newFixture(t, "r-aaaaaaaa-0000000000013-liveb1")
	_, err := liveblock.Update(context.Background(), f.dir, f.run, func(o *liveblock.Overlay) (bool, error) {
		_, ok, err := o.Add(liveblock.KindExec, "/usr/bin/curl", "uid:1000 pid:42 dashboard", time.Now())
		return ok, err
	})
	if err != nil {
		t.Fatal(err)
	}
	confirm(f, "exec", "/usr/bin/curl", 1) // the launcher put it in force, then refused under it
	f.add(`"kind":"exec","source":"seccomp","rule":"live.block[exec:/usr/bin/curl]","verdict":"refused","authority":"rule","argv":["curl"],"exec_id":"x/10/2","path":"/usr/bin/curl"`)
	v := f.inForce(t)
	live := v.View.Group(inforce.GroupLive)
	if v.LiveBlocks != 1 || live == nil || len(live.Rules) != 1 {
		t.Fatalf("live blocks %d, group %+v, want the one block", v.LiveBlocks, live)
	}
	if r := live.Rules[0]; r.RuleKey != "live.block[exec:/usr/bin/curl]" || r.Hits != 1 || !strings.Contains(r.Source.Origin, "dashboard") {
		t.Errorf("live rule %+v, want its rule key, one hit and its writer", r)
	}
	f.add(`"kind":"run_end","source":"supervisor","reason":"exited","exit_code":0`)
	v = f.inForce(t)
	if !v.Ended || len(v.View.Group(inforce.GroupLive).Rules) != 0 || v.LiveBlocks != 1 {
		t.Errorf("ended %v live rules %d blocks %d, want an ended run with no live rule", v.Ended, len(v.View.Group(inforce.GroupLive).Rules), v.LiveBlocks)
	}
	if !strings.Contains(strings.Join(v.View.Notes, " "), "The run has ended, so its live block refuses nothing now.") {
		t.Errorf("notes %q, want the ended run's live blocks named", v.View.Notes)
	}
}

// TestInForceDeclaredWhenItDoesNotCompile: the programs the rules name are on no PATH here and the run's ledger
// names none, so the contract does not compile today; the view is read from the unchanged rules file's text, with
// no enforcement claim, and still counts hits.
func TestInForceDeclaredWhenItDoesNotCompile(t *testing.T) {
	f := newFixture(t, "r-aaaaaaaa-0000000000014-nocomp")
	f.add(`"kind":"fs","source":"landlock","rule":"fs.write[./out/]","verdict":"allow","op":"write","path":"/x/out/a"`)
	t.Setenv("PATH", t.TempDir())
	v := f.inForce(t)
	if v.View.Compiled || v.Contract.Err == "" {
		t.Fatalf("compiled %v err %q, want a view from the text", v.View.Compiled, v.Contract.Err)
	}
	r := rule(t, v, "fs.write", "./out/")
	if r.Hits != 1 || r.State != inforce.StateNone {
		t.Errorf("fs.write ./out/: hits %d state %q, want 1 and no claim", r.Hits, r.State)
	}
	if v.Positions != PositionsSource || r.Source.File != f.source {
		t.Errorf("positions %q at %s, want the unchanged source", v.Positions, r.Source.File)
	}
}

// TestInForceRefusesABadRun: a run id from a request never names a path.
func TestInForceRefusesABadRun(t *testing.T) {
	for _, run := range []string{"../etc", "", "r-x/../../y"} {
		v := InForce(context.Background(), t.TempDir(), run, Options{})
		if v.Err == "" || len(v.View.Groups) == 0 {
			t.Errorf("run %q: err %q groups %d, want refused with an empty view", run, v.Err, len(v.View.Groups))
		}
	}
}

// TestContractsFromRuns: distinct rules files, the newest run's first, counted with their live runs. No file is at
// any of these paths, so each is gone.
func TestContractsFromRuns(t *testing.T) {
	t0 := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	s := &ledgerview.Snapshot{Runs: []*ledgerview.Run{
		{ID: "r-3", Agent: "codex", Contract: "/p/b.yaml", Start: t0.Add(3 * time.Hour), Live: true},
		{ID: "r-2", Agent: "claude", Contract: "/p/a.yaml", Start: t0.Add(2 * time.Hour)},
		{ID: "r-1b", Agent: "", Contract: "", Start: t0.Add(90 * time.Minute)},
		{ID: "r-1", Agent: "codex-old", Contract: "/p/./b.yaml", Start: t0.Add(time.Hour)},
		{ID: "r-0", Agent: "x", Contract: "relative.yaml", Start: t0},
	}}
	got := ContractsFromRuns(s)
	want := []ContractRun{
		{Path: "/p/b.yaml", Gone: true, Agent: "codex", Newest: "r-3", NewestStart: t0.Add(3 * time.Hour), Runs: 2, Live: 1},
		{Path: "/p/a.yaml", Gone: true, Agent: "claude", Newest: "r-2", NewestStart: t0.Add(2 * time.Hour), Runs: 1},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("ContractsFromRuns =\n%+v\nwant\n%+v", got, want)
	}
	if ContractsFromRuns(nil) != nil {
		t.Error("a nil snapshot lists contracts")
	}
}

// TestContractsFromRunsMarksAGoneFile: a rules file still at its path is not gone, also through a linked folder; one
// removed since its runs is, and so is one under a folder that is a file now. A folder this user may not search says
// nothing either way, so its file is not called gone.
func TestContractsFromRunsMarksAGoneFile(t *testing.T) {
	base := t.TempDir()
	proj := filepath.Join(base, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(proj, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "flat"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "agent.yaml"), []byte("version: 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(base, "locked")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	gone := map[string]bool{
		filepath.Join(proj, "agent.yaml"):         false,
		filepath.Join(base, "link", "agent.yaml"): false,
		filepath.Join(proj, "removed.yaml"):       true,
		filepath.Join(base, "flat", "agent.yaml"): true,
	}
	if os.Geteuid() != 0 { // root searches a folder whatever its mode says
		if err := os.Chmod(locked, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o755) }) // so TempDir can remove it
		gone[filepath.Join(locked, "agent.yaml")] = false
	}
	s := &ledgerview.Snapshot{}
	for p := range gone {
		s.Runs = append(s.Runs, &ledgerview.Run{ID: "r-" + filepath.Base(filepath.Dir(p)), Contract: p})
	}
	got := ContractsFromRuns(s)
	if len(got) != len(gone) {
		t.Fatalf("ContractsFromRuns = %+v, want one entry per path", got)
	}
	for _, c := range got {
		if c.Gone != gone[c.Path] {
			t.Errorf("%s: gone %v, want %v", c.Path, c.Gone, gone[c.Path])
		}
	}
}

// TestRunListsReadsTheCopyAsLoadDoes: RunLists follows no link at contract.yaml and takes no path from a bad run id
// (F20).
func TestRunListsReadsTheCopyAsLoadDoes(t *testing.T) {
	root := t.TempDir()
	run := "r-aaaaaaaa-0000000000015-lists1"
	if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "other.yaml")
	if err := os.WriteFile(outside, []byte("exec:\n  allow: [curl]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(root, run, "contract.yaml")
	if err := os.Symlink(outside, copyPath); err != nil {
		t.Fatal(err)
	}
	if l := RunLists(root, run); l.OK {
		t.Errorf("RunLists followed a symlinked copy: %+v", l)
	}
	if err := os.Remove(copyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, []byte("exec:\n  allow: [git]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if l := RunLists(root, run); !l.OK || len(l.Exec) != 1 || l.Exec[0] != "git" {
		t.Errorf("RunLists = %+v, want the copy's exec list", l)
	}
	if l := RunLists(filepath.Join(root, run), ".."); l.OK {
		t.Error("RunLists read a path from a bad run id")
	}
}

// bigRun is a fixture run of n lines of the mix a long Codex session writes: file reads and writes, execs, connects,
// model lines with no rule.
func bigRun(tb testing.TB, n int) *fixture {
	tb.Helper()
	f := newFixture(tb, "r-aaaaaaaa-0000000000016-bigrun")
	for i := 1; f.seq < n; i++ {
		switch i % 5 {
		case 0:
			f.add(`"kind":"fs","source":"landlock","rule":"fs.write[./out/]","verdict":"allow","authority":"rule","attribution":{"confidence":"unattributed","method":"none"},"op":"write","path":"/home/u/proj/out/file.txt"`)
		case 1:
			f.add(`"kind":"fs","source":"seccomp","rule":"fs.read","verdict":"allow","authority":"rule","attribution":{"confidence":"unattributed","method":"none"},"op":"open","path":"/usr/lib/x86_64-linux-gnu/libc.so.6"`)
		case 2:
			f.add(`"kind":"net","source":"supervisor","rule":"unmatched","verdict":"refused","authority":"rule","reason":"net-not-allowed","attribution":{"confidence":"unattributed","method":"none"},"dst":"203.0.113.9:443","proto":"tcp"`)
		case 3:
			f.add(`"kind":"exec","source":"seccomp","rule":"exec[git]","verdict":"allow","authority":"rule","argv":["git","status","--porcelain"],"exec_id":"x/10/1","path":"/usr/bin/git"`)
		default:
			f.add(`"kind":"ssl_request","source":"capture","attribution":{"confidence":"exact","method":"pid"},"host":"chatgpt.com","method":"POST","path":"/backend-api/codex/responses","bytes":48211`)
		}
	}
	return f
}

// inForceTarget is the CPU time the Rules page's refresh was designed for: one InForce over a 55k-line run the
// dashboard's read model holds (the page always has the run there), the page rendering on every refresh. It was
// measured at 60 to 70 ms on the reference box on 2026-10-27, when the read ran in the calling process. Since the read
// runs in a worker process (inforce.go's remoteView: two exchanges and a worker's start for each) it has cost 40 to 60
// ms of CPU in the caller and its workers together with the run's findings taken from the read model, which is what the
// page's refresh is; it cost 450 to 550 ms before the caller sent the findings to the worker, each of two exchanges
// then scanning the whole ledger in a process that lives for that exchange alone. Budget mode prints TARGET-MISS above it.
const inForceTarget = 150 * time.Millisecond

// The CPU time of the process tree (the caller's and its worker's) over which the read fails, for each of the two reads
// of a 55k-line run. In budget mode, where the machine is quiet, the limit is a figure of the reference box: warm (the
// page: the run's findings from the read model) measures 40 to 60 ms there, cold (`tego rules`, which has no read model
// and scans the whole ledger once, in the caller) 210 to 280 ms with the box loaded to 8 to 10 and a floor of about
// 150 ms of that in the scan itself (record.Strings over each line, which checks the line is valid JSON and reads its
// members) and 40 ms in the two worker processes' start and compile. The limits are 1.8 times the cold and 5 times the
// warm figures, the worst of the loaded measurements. The ceiling is the unit gate's, where the read runs beside other
// work: a busy machine slows CPU work by a lower clock and a busy sibling hyperthread (beside 8 busy loops and a box loaded to 9 the read measured 82 ms warm and
// 423 ms cold, 1.5 and 1.8 times its figures; 20 busy loops made the old read 3.5 times its cost), so each ceiling is
// 2 to 3.5 times that. Either fails a read that does several times the work it does now, on any machine.
const (
	inForceLimitCold   = 500 * time.Millisecond
	inForceLimitWarm   = 300 * time.Millisecond
	inForceCeilingCold = 1500 * time.Millisecond
	inForceCeilingWarm = 600 * time.Millisecond
)

// inForceWallBound is the loose bound on the wall clock of the same read: far over what it takes (0.15 to 0.3 s cold,
// 30 to 50 ms warm on the box) on purpose, so that it fails a wait (a sleep, a lock, a pipe that is never
// answered, a timeout run to its end) on any machine and not the machine's ordinary load. A busy machine also
// stretches the wall clock (1.15 s beside 8 busy loops, 2 s beside 20, before the read was cut), by waits for a CPU that
// its CPU time keeps out, so the bound holds only where the wall clock is also over twice the CPU time: a wait is wall
// clock the work does not account for.
const inForceWallBound = time.Second

// inForceCostRatio is the most the 55k-line read may cost over the 11k-line one, in CPU time, cold. Five times the lines
// is five times the cost at the most (the workers' start-up is the same for both, so the ratio reads about 2.5), and one
// more for the run's own spread. inForceWarmRatio is the same for the read from the read model, whose cost does not
// depend on the run's lines at all (it reads run_start and takes the rest from memory): it reads about 1.
//
// inForceWarmOverCold is the most the read from the read model may cost of the read with none, in the same measurement:
// it measures 0.2 and it costs the whole when the read scans the ledger as the other does. Both sides run on the same
// machine, so the figure is the machine's load alike, which the CPU limits cannot be (a loaded box makes the page's
// 55 ms 200 ms, and the page's old 490 ms fits the ceiling that allows that).
const (
	inForceCostRatio    = 6.0
	inForceWarmRatio    = 3.0
	inForceWarmOverCold = 0.5
)

// TestInForceLongRunIsFast: a 55k-line run reads in a time the Rules page can refresh in, and what the read costs grows
// with the run's size and no faster. InForce does its work in a worker process, which a short launcher starts and
// leaves (so it is nobody's child), and which the calling thread's clock, the unit gate's usual figure
// (testutil.MinOfThread), never sees: the first form of this test read 3.9 ms of CPU for a read that takes 450 ms, and
// the one before it held the wall clock to the 150 ms budget on a hosted runner with other tenants (261 and 332 ms,
// with the CPU time flat). The read is made twice a run, as the two callers make it: warm, with the run as the dashboard's
// read model holds it (Options.Run: the Rules page, every refresh), and cold, with none (`tego rules`). Each bound is
// for one fault and none for the machine's load:
//   - CPU time of the process tree, the caller's and its worker's (testutil.MinOfTree, the fastest of five reads of each
//     run, interleaved), at most the limit of its read in budget mode and the ceiling in the unit gate: the work the read
//     does, which a scan that does more of it, a second scan, or a read that copies more, exceeds (the page's read made
//     two scans of the ledger in two worker processes, 450 to 550 ms, until the caller took one scan or the read model's
//     findings and sent them on). A busy machine slows CPU work by a lower clock and a busy sibling hyperthread, not by
//     the waits for a CPU, so the ceiling keeps the room for that.
//   - The same figure of the 55k-line run over an 11k-line run, at most inForceCostRatio cold and inForceWarmRatio warm:
//     a scan that is quadratic in the run (a rescan for every line, a lookup that walks what it has seen) costs 25 times
//     and fails on any machine, however slow, since both sides run on it alike; a warm read that scans the ledger
//     again is cold's ratio, over the warm bound.
//   - The warm figure over the cold figure of the 55k-line run, at most inForceWarmOverCold: the read model's findings
//     must be what the page's read is made from (it scanned the ledger twice, as the read with none does, while the
//     findings stayed in the caller), whatever the machine's load.
//   - The wall clock of each 55k-line read, at most inForceWallBound unless it is under twice the CPU time: a read that
//     waits (a sleep, a lock, a worker that is slow to answer) fails it, and the message gives the machine's load, the
//     other reading of it. No budget is read on the wall clock, because a wall clock beside other tenants has no bound
//     the code controls.
//
// In budget mode (testutil.BudgetsEnv, scripts/timing-budgets.sh, which runs it alone) the same bounds hold, three
// reads a side instead of five, and a warm CPU time over inForceTarget prints TARGET-MISS; the race detector's slowdown
// and -short skip it.
func TestInForceLongRunIsFast(t *testing.T) {
	if raceEnabled || testing.Short() {
		t.Skip("timing under -race or -short says nothing")
	}
	mode := testutil.TimingMode(t)
	big, small := bigRun(t, 55000), bigRun(t, 11000)
	held := map[*fixture]*ledgerview.Run{}
	for _, tc := range []struct {
		f     *fixture
		lines int
	}{{big, 55000}, {small, 11000}} {
		v := tc.f.inForce(t) // warm the page cache as a dashboard's earlier reads have
		if hits := rule(t, v, "exec.allow", "git").Hits; v.Lines != tc.lines || hits != tc.lines/5 {
			t.Fatalf("%d lines: read %d lines, git hits %d, want %d and %d", tc.lines, v.Lines, hits, tc.lines, tc.lines/5)
		}
		r, err := ledgerview.Open(tc.f.root).Run(tc.f.run)
		if err != nil {
			t.Fatal(err)
		}
		held[tc.f] = r
		if w := InForce(context.Background(), tc.f.root, tc.f.run, Options{Machine: tc.f.m, Run: r}); w.Err != "" || w.Lines != tc.lines {
			t.Fatalf("%d lines, from the read model: err %q, lines %d", tc.lines, w.Err, w.Lines) // also fills its memo, as the page's first view does
		}
	}
	read := func(f *fixture, lines int, warm bool) func() {
		o := Options{Machine: f.m}
		if warm {
			o.Run = held[f]
		}
		return func() {
			if got := InForce(context.Background(), f.root, f.run, o); got.Err != "" || got.Lines != lines {
				t.Errorf("timed InForce (read model %v): err %q, lines %d, want none and %d", warm, got.Err, got.Lines, lines)
			}
		}
	}
	rounds := 5
	if mode.Budgets() {
		rounds = 3
	}
	// Interleaved, the order rotated: a change in the machine's load over the measurement is on every run alike.
	fig := testutil.MinOfTree(rounds, read(big, 55000, false), read(small, 11000, false), read(big, 55000, true), read(small, 11000, true))
	cold, coldSmall, warm, warmSmall := fig[0], fig[1], fig[2], fig[3]
	ratio := func(b, s testutil.TreeFigure) float64 { return float64(b.CPU) / float64(max(s.CPU, time.Millisecond)) }
	coldRatio, warmRatio := ratio(cold, coldSmall), ratio(warm, warmSmall)
	suffix := ""
	if mode.Budgets() {
		suffix = ", budget mode"
	}
	t.Logf("InForce over a 55k-line run, from the read model (the Rules page): %v of CPU time (the caller's and its worker's; target %v), %v of wall clock; the 11k-line run %v, ratio %.2f (limit %.1f%s)",
		warm.CPU, inForceTarget, warm.Wall, warmSmall.CPU, warmRatio, inForceWarmRatio, suffix)
	t.Logf("InForce over a 55k-line run, with none (`tego rules`): %v of CPU time, %v of wall clock; the 11k-line run %v, ratio %.2f (limit %.1f%s)",
		cold.CPU, cold.Wall, coldSmall.CPU, coldRatio, inForceCostRatio, suffix)
	if mode.Budgets() && warm.CPU > inForceTarget {
		t.Logf("TARGET-MISS: InForce over a 55k-line run %v of CPU time > %v (the Rules page renders on every refresh)", warm.CPU, inForceTarget)
	}
	limitCold, limitWarm := inForceCeilingCold, inForceCeilingWarm
	if mode.Budgets() {
		limitCold, limitWarm = inForceLimitCold, inForceLimitWarm
	}
	if warm.CPU > limitWarm {
		t.Errorf("InForce over a 55k-line run from the read model: %v of CPU time of the caller and its worker, over the %v limit", warm.CPU, limitWarm)
	}
	if cold.CPU > limitCold {
		t.Errorf("InForce over a 55k-line run with no read model: %v of CPU time of the caller and its worker, over the %v limit", cold.CPU, limitCold)
	}
	if float64(warm.CPU) > inForceWarmOverCold*float64(cold.CPU) {
		t.Errorf("InForce from the read model costs %v of CPU time over a 55k-line run, over %.0f%% of the %v the read with none costs: the read model's findings are not what the page's view is made from", warm.CPU, inForceWarmOverCold*100, cold.CPU)
	}
	if coldRatio > inForceCostRatio {
		t.Errorf("InForce costs %.1f times as much CPU time over 55k lines (%v) as over 11k (%v), more than %.0f: the read grows faster than the run", coldRatio, cold.CPU, coldSmall.CPU, inForceCostRatio)
	}
	if warmRatio > inForceWarmRatio {
		t.Errorf("InForce from the read model costs %.1f times as much CPU time over 55k lines (%v) as over 11k (%v), more than %.0f: it reads the ledger again", warmRatio, warm.CPU, warmSmall.CPU, inForceWarmRatio)
	}
	for name, b := range map[string]testutil.TreeFigure{"from the read model": warm, "with no read model": cold} {
		if b.Wall > inForceWallBound && b.Wall > 2*b.CPU {
			load, _ := os.ReadFile("/proc/loadavg")
			t.Errorf("InForce over a 55k-line run %s took %v of wall clock for %v of CPU time, over the %v bound and over twice its CPU time: the read waits on something, or the machine is loaded beyond what a wait of this size says (load average %s)", name, b.Wall, b.CPU, inForceWallBound, strings.TrimSpace(string(load)))
		}
	}
}

// BenchmarkInForce55k is InForce over a 55k-line run.
func BenchmarkInForce55k(b *testing.B) {
	f := bigRun(b, 55000)
	if err := os.WriteFile(filepath.Join(f.dir, "events.jsonl"), f.lines.Bytes(), 0o644); err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		_ = InForce(context.Background(), f.root, f.run, Options{Machine: f.m})
	}
}
