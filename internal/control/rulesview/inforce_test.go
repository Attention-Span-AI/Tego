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
func newFixture(t testing.TB, run string) *fixture {
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
	if err := os.WriteFile(f.source, []byte(sourceText), 0o644); err != nil {
		t.Fatal(err)
	}
	c, _, err := agent.LoadBytes(f.source, []byte(sourceText), &agent.ProfileChain{})
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
	f.add(fmt.Sprintf(`"kind":"run_start","source":"supervisor","tier":"landlock","command":["sh"],"cwd":"%s","contract_hash":"%s","contract_source":{"path":"%s"}`,
		f.proj, hex.EncodeToString(sum[:]), f.source))
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
	f.add(fmt.Sprintf(`"kind":"run_start","source":"supervisor","tier":"landlock","command":["sh"],"cwd":"%s","contract_hash":"%s","contract_source":{"path":"%s"}`,
		f.proj, hex.EncodeToString(sum[:]), f.source))
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

// TestCommonFields: the fast read of a line's kind and rule agrees with the decoder, and gives up (so the caller
// decodes) on an escape; a rule key inside the payload is not the line's rule.
func TestCommonFields(t *testing.T) {
	for _, tc := range []struct {
		line, kind, rule string
		ok               bool
	}{
		{`{"v":1,"kind":"fs","source":"landlock","rule":"fs.write[./out/]","verdict":"allow"}`, "fs", "fs.write[./out/]", true},
		{`{"v":1,"kind":"ssl_request","source":"capture","attribution":{"rule":"x"},"host":"a"}`, "ssl_request", "", true},
		{`{"v":1,"kind":"run_start","source":"s","ask_read_relaxes":[{"rule":"fs.ask_read[x]"}]}`, "run_start", "", true},
		{`{"v":1,"kind":"fs","rule":"fs.write[./a\"b/]"}`, "", "", false},
		{`{"v":1,"seq":2}`, "", "", false},
		{``, "", "", false},
	} {
		k, r, ok := commonFields([]byte(tc.line))
		if string(k) != tc.kind || string(r) != tc.rule || ok != tc.ok {
			t.Errorf("commonFields(%s) = %q %q %v, want %q %q %v", tc.line, k, r, ok, tc.kind, tc.rule, tc.ok)
		}
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

// inForceBudget55k is the budget of one InForce over a 55k-line run read from disk (no read model, so the whole
// ledger is scanned): the Rules page renders on every refresh. Measured about 60 ms on the reference
// box, 70 ms on 2026-10-27.
const inForceBudget55k = 150 * time.Millisecond

// TestInForceLongRunIsFast: a 55k-line run reads in under 150 ms. In budget mode (testutil.BudgetsEnv, set by
// scripts/timing-budgets.sh, which runs it alone) the figure is the fastest of three reads on the wall clock, held to
// the budget as the test always held it; in the unit gate, which also runs beside the integration suites, it is the
// fastest of five reads in the thread's own time (testutil.MinOfThread: InForce runs on the calling goroutine), held to
// testutil.CeilingFactor times the budget and its wall clock to testutil.WallCeilingFactor times it
// (docs/BENCHMARKS.md, "Timing budgets in the test suites"). The wall clock alone failed there: beside the integration
// suites the box has more runnable threads than CPUs, and the fastest of three reads still waited for a CPU and ran on
// a busy core (213 and 228 ms on 2026-10-27, 70 ms alone). A scan that grew with the run's size squared, or a read
// that waited on anything, still fails the ceiling. The race detector's slowdown skips it.
func TestInForceLongRunIsFast(t *testing.T) {
	if raceEnabled || testing.Short() {
		t.Skip("timing under -race or -short says nothing")
	}
	mode := testutil.TimingMode(t)
	f := bigRun(t, 55000)
	v := f.inForce(t) // warm the page cache as a dashboard's earlier reads have
	if v.Lines != 55000 || rule(t, v, "exec.allow", "git").Hits != 11000 {
		t.Fatalf("lines %d git hits %d, want 55000 and 11000", v.Lines, rule(t, v, "exec.allow", "git").Hits)
	}
	rounds := 5
	if mode.Budgets() {
		rounds = 3
	}
	var got *InForceView
	m := mode.Measure(rounds, func() { got = InForce(context.Background(), f.root, f.run, Options{Machine: f.m}) })
	if got.Err != "" || got.Lines != 55000 {
		t.Fatalf("timed InForce: err %q, lines %d, want none and 55000", got.Err, got.Lines)
	}
	mode.Judge(t, testutil.Budget{Name: "InForce over a 55k-line run", Limit: inForceBudget55k,
		Spec: "the Rules page renders on every refresh"}, m[0])
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
