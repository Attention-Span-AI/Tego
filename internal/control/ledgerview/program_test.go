// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// TestProgramOf: each line's program follows the line page's rule. A process runs its own program after an exec
// the kernel let through, its parent's while every exec it made was refused, and nothing known when it made no exec
// (a pid that forked without exec, the launcher); an exec of /proc/self/exe keeps the program the process ran.
func TestProgramOf(t *testing.T) {
	x, seqs := codexShaped(t)
	self := x.exec(800, 11, "200/6", false, "/proc/self/exe", "--codex-run-as-process-setup")
	x.lines[self] = replaceOnce(t, x.lines[self], `"path":"/usr/bin/exe"`, `"path":"/proc/self/exe"`)
	r := x.write(t)
	for name, want := range map[string]string{
		"start": "", "codex": "codex", "bash": "bash", "curl": "curl", "net": "curl",
		"awk": "", "lsb": "codex", "lsbread": "codex", "forked": "",
	} {
		if got := ProgramOf(r, seqs[name]); got != want {
			t.Errorf("%s (line %d): program %q, want %q", name, seqs[name], got, want)
		}
	}
	if got := ProgramOf(r, self); got != "codex" {
		t.Errorf("/proc/self/exe: program %q, want codex (the parent's program, started again)", got)
	}
	if got := ProgramOf(r, 999); got != "" {
		t.Errorf("a line the run does not hold: %q", got)
	}
}

func replaceOnce(t *testing.T, s, old, repl string) string {
	t.Helper()
	for i := 0; i+len(old) <= len(s); i++ {
		if s[i:i+len(old)] == old {
			return s[:i] + repl + s[i+len(old):]
		}
	}
	t.Fatalf("%q not in %q", old, s)
	return s
}

// TestProgramsGrowWithTheRun: a live run that gains lines continues its program index (the processes it knew keep
// their programs), and a replaced events file starts it over.
func TestProgramsGrowWithTheRun(t *testing.T) {
	x, seqs := codexShaped(t)
	writeRun(t, x.root, x.run, x.lines...)
	st := Open(x.root)
	r1, err := st.Run(x.run)
	if err != nil {
		t.Fatal(err)
	}
	if got := ProgramOf(r1, seqs["net"]); got != "curl" {
		t.Fatalf("before: %q", got)
	}
	more := x.add(400, `"kind":"fs","source":"seccomp","rule":"unmatched","verdict":"allow","authority":"rule","op":"open","flags":0,"path":"/tmp/x"`)
	f, err := os.OpenFile(filepath.Join(x.root, x.run, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(x.lines[more]); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	r2, err := st.Run(x.run)
	if err != nil {
		t.Fatal(err)
	}
	if len(r2.AllEvents()) != len(r1.AllEvents())+1 {
		t.Fatalf("the run did not grow: %d then %d lines", len(r1.AllEvents()), len(r2.AllEvents()))
	}
	if got := ProgramOf(r2, more); got != "curl" {
		t.Errorf("the appended line of pid 400: %q, want curl", got)
	}
	if _, of := r1.progs(); len(of) != len(r1.AllEvents()) {
		t.Errorf("the older version sees %d programs for %d lines", len(of), len(r1.AllEvents()))
	}
	// Replaced by a run where pid 400 started nothing: the index starts over.
	writeRun(t, x.root, x.run, x.lines[0], x.lines[seqs["net"]])
	r3, err := st.Run(x.run)
	if err != nil {
		t.Fatal(err)
	}
	if got := ProgramOf(r3, seqs["net"]); got != "" {
		t.Errorf("after the file was replaced: %q, want none", got)
	}
}

// TestQueryPrograms: prog: matches the program a line's process ran, -prog: leaves it out, rows carry it, and the
// Program facet's counts are what prog: would match.
func TestQueryPrograms(t *testing.T) {
	x, _ := codexShaped(t)
	r := x.write(t)
	s := &Snapshot{Runs: []*Run{r}}
	count := func(q string) int {
		t.Helper()
		f, _, err := ParseQuery(q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return s.Query(f).Matched
	}
	if n := count("prog:curl"); n != 2 {
		t.Errorf("prog:curl: %d lines, want 2 (its exec and its connection)", n)
	}
	if n := count("prog:CODEX"); n != 3 {
		t.Errorf("prog:codex: %d lines, want 3 (its exec, the refused lsb_release and its read)", n)
	}
	all := count("")
	if n := count("-prog:codex"); n != all-3 {
		t.Errorf("-prog:codex: %d lines, want %d", n, all-3)
	}
	pg := s.Query(Filter{Facets: true})
	for _, v := range pg.Facets.Program.Values {
		if n := count("prog:" + v.Value); n != v.Count {
			t.Errorf("Program facet %s: %d, but prog:%s matches %d", v.Value, v.Count, v.Value, n)
		}
	}
	if len(pg.Facets.Program.Values) != 3 {
		t.Errorf("Program facet %+v, want codex, bash and curl", pg.Facets.Program.Values)
	}
	for _, row := range pg.Rows {
		if want := ProgramOf(r, row.Seq); row.Program != want {
			t.Errorf("row %d: program %q, want %q", row.Seq, row.Program, want)
		}
	}
	f, toks, err := ParseQuery("prog:curl -prog:bash")
	if err != nil || len(f.Programs) != 1 || len(f.Not.Programs) != 1 || FormatQuery(toks) != "prog:curl -prog:bash" {
		t.Errorf("parse: %+v %v %v", f, toks, err)
	}
}

// TestGroup: the groups hold every matched line once, a process group is a pid and its program, target and rule
// groups gather across runs, and a cached run's groups answer the same again.
func TestGroup(t *testing.T) {
	_, s := queryFixture(t)
	matched := s.Query(Filter{}).Matched
	for _, by := range []string{GroupProcess, GroupTarget, GroupRule, GroupSeverity} {
		g := s.Group(Filter{}, by, 0, nil)
		sum := g.Keyless
		for _, row := range g.Rows {
			sum += row.Lines
		}
		if sum != matched || g.Matched != matched {
			t.Errorf("%s: groups hold %d lines (Matched %d), the search %d", by, sum, g.Matched, matched)
		}
		if g.Total != len(g.Rows) {
			t.Errorf("%s: total %d rows %d", by, g.Total, len(g.Rows))
		}
		again := s.Group(Filter{}, by, 0, nil)
		if len(again.Rows) != len(g.Rows) || again.Rows[0] != g.Rows[0] {
			t.Errorf("%s: a second call differs", by)
		}
	}
	rules := s.Group(Filter{}, GroupRule, 0, nil)
	var deny *GroupRow
	for i := range rules.Rows {
		if rules.Rows[i].Rule == "net.deny[chatgpt.com]" {
			deny = &rules.Rows[i]
		}
	}
	if deny == nil || deny.Lines != 2 || deny.Refused != 2 || deny.Run != "" {
		t.Errorf("net.deny group %+v, want 2 refused lines across both runs", deny)
	}
	procs := s.Group(Filter{Runs: []string{qRunA}}, GroupProcess, 0, nil)
	for _, row := range procs.Rows {
		if row.PID == 101 && (row.Program != "" || row.Lines != 2 || row.Run != qRunA) {
			// pid 101's exec line names no exec_id, so its program is not known.
			t.Errorf("pid 101: %+v", row)
		}
	}
	if top := s.Group(Filter{}, GroupTarget, 1, nil); len(top.Rows) != 1 || top.Total < 2 {
		t.Errorf("limit 1: %d rows of %d", len(top.Rows), top.Total)
	}
	if g := s.Group(Filter{}, "nonsense", 0, nil); len(g.Rows) != 0 {
		t.Errorf("unknown grouping: %+v", g)
	}
}

// TestGroupSeverity: the severity groups read High to Allowed, whatever their sizes, and every refused line is in a
// blocked severity.
func TestGroupSeverity(t *testing.T) {
	_, s := queryFixture(t)
	g := s.Group(Filter{}, GroupSeverity, 0, nil)
	last, refused := -1, 0
	for _, row := range g.Rows {
		i := slices.Index(sevOrder, row.Severity)
		if i < 0 || i <= last {
			t.Fatalf("group %q out of order in %+v", row.Severity, g.Rows)
		}
		last = i
		if slices.Contains(sevOrder[4:], row.Severity) {
			if row.Refused != 0 {
				t.Errorf("group %s holds %d refused lines", row.Severity, row.Refused)
			}
			continue
		}
		refused += row.Refused
	}
	if want := s.Query(Filter{Verdicts: []string{"refused"}}).Matched; refused != want {
		t.Errorf("blocked severities hold %d refused lines, the search %d", refused, want)
	}
}

// TestGroupSeverityObservedIsNotAllowed: a watched run's key read and send are Observed: nothing allowed them.
func TestGroupSeverityObservedIsNotAllowed(t *testing.T) {
	root, id := t.TempDir(), "r-aaaa-0011-watchd"
	t0 := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	writeRun(t, root, id,
		line(id, "agent", 0, t0, "run_start", `"tier":"observe","command":["agent"],"cwd":"/w/proj"`),
		line(id, "agent", 1, t0.Add(time.Second), "fs", `"rule":"unmatched","verdict":"observed","op":"open","path":"/w/home/.ssh/id_rsa"`),
		line(id, "agent", 2, t0.Add(2*time.Second), "net", `"rule":"unmatched","verdict":"observed","dst":"198.51.100.7:443","proto":"tcp"`),
		line(id, "agent", 3, t0.Add(3*time.Second), "fs", `"rule":"fs.read[./]","verdict":"allow","op":"open","path":"/w/proj/main.go"`))
	snap, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, row := range snap.Group(Filter{}, GroupSeverity, 0, nil).Rows {
		got[row.Severity] = row.Lines
	}
	if got["Observed"] != 2 || got["Allowed"] != 1 || got["Recorded"] != 1 {
		t.Errorf("groups %v: want the key read and the send Observed, main.go Allowed, the run_start line Recorded", got)
	}
}

// TestGroupSeverityAllowedIsAllowed: Allowed holds what a rule allowed, and nothing else. A person's no, a gap in the
// record and the end of a run were all in it.
func TestGroupSeverityAllowedIsAllowed(t *testing.T) {
	root, id := t.TempDir(), "r-aaaa-0012-groupx"
	t0 := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	writeRun(t, root, id,
		line(id, "agent", 0, t0, "run_start", `"tier":"landlock","command":["agent"],"cwd":"/w/proj"`),
		line(id, "agent", 1, t0.Add(time.Second), "fs", `"rule":"fs.ask[/w/proj/held/]","verdict":"ask","op":"open","path":"/w/proj/held/a"`),
		line(id, "agent", 2, t0.Add(time.Second), "ask", `"ask_id":"q-1","ask_rule":"fs.ask[/w/proj/held/]","hold":"open","op":"write","target":"/w/proj/held/a"`),
		line(id, "agent", 3, t0.Add(2*time.Second), "answer", `"ask_id":"q-1","approved":false,"by":"uid:1000 pid:42","after_s":1.0,"answer_reason":"ask-denied"`),
		line(id, "agent", 4, t0.Add(3*time.Second), "gap", `"what":"fs","why":"overflow"`),
		line(id, "agent", 5, t0.Add(4*time.Second), "fs", `"rule":"fs.read[./]","verdict":"allow","op":"open","path":"/w/proj/main.go"`),
		line(id, "agent", 6, t0.Add(5*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	snap, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, row := range snap.Group(Filter{}, GroupSeverity, 0, nil).Rows {
		got[row.Severity] = row.Lines
	}
	want := map[string]int{"Asked": 2, "Answered": 1, "Allowed": 1, "Recorded": 3}
	if !maps.Equal(got, want) {
		t.Errorf("groups %v, want %v", got, want)
	}
}

// TestGroupSeverityReadsThePagesSignal: By severity reads a run's Signal under the Sensitive the pages use: the contract
// entry that makes a path a secret makes it High here too, and the read lands on the page's cache slot, not over it.
func TestGroupSeverityReadsThePagesSignal(t *testing.T) {
	root, id := t.TempDir(), "r-aaaa-0012-sensit"
	t0 := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	writeRun(t, root, id,
		line(id, "agent", 0, t0, "run_start", `"tier":"landlock","command":["agent"],"cwd":"/w/proj"`),
		line(id, "agent", 1, t0.Add(time.Second), "refused", `"rule":"unmatched","reason":"write-outside-contract","op":"open","target":"/w/vault/plan.md"`))
	snap, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	r := snap.Find(id)
	sens := Sensitive{Entries: []string{"/w/vault/"}, Cwd: r.Cwd}
	own := Signal(r, sens)
	if own.High != 1 {
		t.Fatalf("the page's Signal: %d High, want the contract's secret", own.High)
	}
	before := signalComputes.Load()
	rows := snap.Group(Filter{}, GroupSeverity, 0, func(*Run) Sensitive { return sens }).Rows
	if len(rows) == 0 || rows[0].Severity != "High" || rows[0].Refused != 1 {
		t.Errorf("By severity %+v: want the refusal High", rows)
	}
	if n := signalComputes.Load() - before; n != 0 {
		t.Errorf("By severity computed %d Signals: it replaced the page's cache slot", n)
	}
}

// TestSeverityOfEveryRefusedLine: a refused line that is not background has a blocked severity, whether it is the
// action's own line or its mirror.
func TestSeverityOfEveryRefusedLine(t *testing.T) {
	_, s := queryFixture(t)
	for _, r := range s.Runs {
		sig := Signal(r, Sensitive{Cwd: r.Cwd})
		evs := r.AllEvents()
		for i := range evs {
			e := &evs[i]
			if e.Refused() && e.Kind == "refused" && sig.IsBackground(e) != (sig.SeverityOf(e) == SevRoutine) {
				t.Errorf("%s line %d (%s %s): background %v, severity %v", r.ID, e.Seq, e.Op, e.Target, sig.IsBackground(e), sig.SeverityOf(e))
			}
			if e.Refused() && !sig.IsBackground(e) && sig.SeverityOf(e) == SevRoutine {
				t.Errorf("%s line %d (%s %s %s) is not background yet reads Routine", r.ID, e.Seq, e.Kind, e.Op, e.Target)
			}
		}
	}
}
