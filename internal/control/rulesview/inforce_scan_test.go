// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// pageFacts is what the Rules page shows of a run that comes from reading its ledger, as text with the run's folders
// and start time named by placeholders: the lines read, whether the run ended, each group's default hits, each rule's
// key, entry, effect and hits, the notes and the ended-live rules. It leaves out what the compile and the machine
// decide (sentences, enforcement words), which a ledger scan does not move.
func pageFacts(f *fixture, v *InForceView) string {
	var b strings.Builder
	started := v.Started.Format(time.RFC3339Nano)
	if v.Started.Equal(f.started) {
		started = "<the fixture's start>"
	}
	fmt.Fprintf(&b, "run %s\nerr %q\nlines %d ended %v positions %s (%s)\nstarted %s\n", v.Run, v.Err, v.Lines, v.Ended, v.Positions, v.PositionsWhy, started)
	for _, g := range v.View.Groups {
		fmt.Fprintf(&b, "group %s default_kind=%q default_hits=%d\n", g.ID, g.DefaultKind, g.DefaultHits)
		for _, r := range g.Rules {
			fmt.Fprintf(&b, "  rule %s | %s | %s | %v | hits %d\n", r.Key, r.Entry, r.RuleKey, r.Effect, r.Hits)
		}
	}
	for _, n := range v.View.Notes {
		fmt.Fprintf(&b, "note %s\n", n)
	}
	for _, r := range v.EndedLive {
		fmt.Fprintf(&b, "ended-live %s hits %d\n", r.RuleKey, r.Hits)
	}
	s := b.String()
	for from, to := range map[string]string{f.root: "<ledger>", f.proj: "<proj>", f.home: "<home>"} {
		s = strings.ReplaceAll(s, from, to)
	}
	return s
}

// TestInForcePageOfALongRunIsUnchanged pins what the Rules page shows of a seeded 55,000-line run (bigRun, read through
// the worker as the page reads it) to testdata/inforce_55k_page.txt, written by the code before the page's read was cut
// to one scan: the cost of the page may fall, what it says may not move. TEGO_UPDATE_GOLDEN=1 rewrites the file.
// The page gained one row after that first writing, in the always-on group: the standard-devices allow rule
// (`builtin.standard_devices`, hits 0), because a contract with an fs: section may now write the five standard device
// files and says so. The golden holds that row; every other line is as the code before the change wrote it.
func TestInForcePageOfALongRunIsUnchanged(t *testing.T) {
	f := bigRun(t, 55000)
	got := pageFacts(f, f.inForce(t))
	golden := filepath.Join("testdata", "inforce_55k_page.txt")
	if os.Getenv("TEGO_UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("the page of the seeded 55k-line run changed:\n%s", firstDifference(string(want), got))
	}
}

func firstDifference(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < max(len(w), len(g)); i++ {
		var a, b string
		if i < len(w) {
			a = w[i]
		}
		if i < len(g) {
			b = g[i]
		}
		if a != b {
			return fmt.Sprintf("line %d\n  was: %s\n  now: %s", i+1, a, b)
		}
	}
	return "(no difference)"
}

// oddRun is bigRun's mix with the exec lines a scan must read as the full decode would: programs in several folders,
// a folder met again after a line the full decode refuses, a relative program, a number for a program, a program that
// is not UTF-8, a line without its common fields, an unreadable line, and a run_end.
func oddRun(t testing.TB) *fixture {
	t.Helper()
	f := bigRun(t, 3000)
	exec := func(path string) {
		f.add(`"kind":"exec","source":"seccomp","rule":"exec[x]","verdict":"allow","authority":"rule","argv":["x"],"exec_id":"x/10/1","path":` + path)
	}
	exec(`"/opt/py/bin/python3"`)
	exec(`"/usr/local/bin/tool"`)
	exec(`"bin/relative"`)
	exec(`42`)
	exec("\"/opt/\xff/bad\"")
	exec(`"/opt/py/bin/again"`)
	// An exec line the full decode refuses (no mono_ns) from a folder not listed yet, then one from a listed folder.
	fmt.Fprintf(&f.lines, `{"v":1,"seq":%d,"kind":"exec","rule":"exec[y]","verdict":"allow","path":"/srv/refused/bin/y"}`+"\n", f.seq)
	fmt.Fprintf(&f.lines, `{"v":1,"seq":%d,"kind":"exec","rule":"exec[y]","verdict":"allow","path":"/opt/py/bin/y"}`+"\n", f.seq+1)
	f.seq += 2
	f.lines.WriteString("this is no record\n")
	f.add(`"kind":"exec","source":"seccomp","rule":"exec[git]","verdict":"allow","authority":"rule","command_rule":"git status","command_list":"allow","argv":["git","status"],"exec_id":"x/10/3","path":"/usr/bin/git"`)
	f.add(`"kind":"run_end","source":"supervisor","reason":"exited","exit_code":0`)
	return f
}

// referenceExecDirs is what the scan's exec folders were before it skipped the decode of a line from a folder it had
// listed: every exec line of the first maxExecScan is decoded in full.
func referenceExecDirs(t testing.TB, dir string) []string {
	t.Helper()
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	sc := &runScan{}
	seen := map[string]bool{}
	n, lines := 0, 0
	for line, err := range r.Lines() {
		if err != nil {
			t.Fatal(err)
		}
		lines++
		if lines == 1 {
			continue
		}
		f, err := record.Strings(line, keyKind)
		if err != nil || record.Kind(f[0]) != record.KindExec || n >= maxExecScan {
			continue
		}
		n++
		sc.addExec(line, seen)
	}
	return sc.execDirs
}

// TestScanSkipsTheDecodeOfListedFoldersAndKeepsTheFolders: an exec line from a folder already listed is not decoded, and
// the folders are the ones the full decode of every line finds, in the same order, on a run with lines the full decode
// refuses, programs that are not paths or not UTF-8 and more than maxExecScan exec lines.
func TestScanSkipsTheDecodeOfListedFoldersAndKeepsTheFolders(t *testing.T) {
	for name, build := range map[string]func(testing.TB) *fixture{
		"odd run": oddRun,
		"past the bound": func(tb testing.TB) *fixture {
			f := oddRun(tb)
			for i := 0; i < maxExecScan; i++ {
				f.add(`"kind":"exec","source":"seccomp","rule":"exec[x]","verdict":"allow","authority":"rule","argv":["x"],"exec_id":"x/10/1","path":"/usr/bin/git"`)
			}
			f.add(`"kind":"exec","source":"seccomp","rule":"exec[x]","verdict":"allow","authority":"rule","argv":["x"],"exec_id":"x/10/1","path":"/after/the/bound/prog"`)
			return f
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := build(t)
			if err := os.WriteFile(filepath.Join(f.dir, "events.jsonl"), f.lines.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
			sc, err := scanRun(context.Background(), f.dir)
			if err != nil {
				t.Fatal(err)
			}
			want := referenceExecDirs(t, f.dir)
			if !slices.Equal(sc.execDirs, want) {
				t.Errorf("exec folders %q, want %q (every exec line decoded in full)", sc.execDirs, want)
			}
			if !slices.Contains(sc.execDirs, "/opt/py/bin") || !slices.Contains(sc.execDirs, "/usr/local/bin") || slices.Contains(sc.execDirs, "/srv/refused/bin") {
				t.Errorf("exec folders %q: the fixture no longer holds the cases the test is for", sc.execDirs)
			}
		})
	}
}

// TestInForceViewIsTheSameWhoeverScans: the view of a run is the same whether the worker scans the ledger (what every
// view did, twice), the calling process does and sends the scan with the request (what the page does), or the call
// is made in one process: the scan crosses the pipe as it was found, run_start and all.
func TestInForceViewIsTheSameWhoeverScans(t *testing.T) {
	f := oddRun(t)
	if err := os.WriteFile(filepath.Join(f.dir, "events.jsonl"), f.lines.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, o := context.Background(), Options{Machine: f.m}
	// The worker's own scan, in both exchanges, as InForce asked before the caller scanned.
	copyReply, err := viewCall(ctx, "inforce-copy", f.root, f.run, "", "", o)
	if err != nil {
		t.Fatal(err)
	}
	workers, err := viewCall(ctx, "inforce", f.root, f.run, "", "", o)
	if err != nil {
		t.Fatal(err)
	}
	if copyReply.InForce.Lines != workers.InForce.Lines {
		t.Fatalf("the two exchanges read %d and %d lines", copyReply.InForce.Lines, workers.InForce.Lines)
	}
	want := pageFacts(f, workers.InForce)
	if n := strings.Count(f.lines.String(), "\n"); workers.InForce.Err != "" || workers.InForce.Lines != n || !workers.InForce.Ended {
		t.Fatalf("the worker's own view: err %q, lines %d (want %d), ended %v", workers.InForce.Err, workers.InForce.Lines, n, workers.InForce.Ended)
	}
	if got := pageFacts(f, InForce(ctx, f.root, f.run, o)); got != want {
		t.Errorf("the view with the caller's scan differs from the worker's own:\n%s", firstDifference(want, got))
	}
	if got := pageFacts(f, inForce(ctx, f.root, f.run, o)); got != want {
		t.Errorf("the view made in one process differs from the worker's own:\n%s", firstDifference(want, got))
	}
}

// TestInForceViewOfTheReadModelsRunIsTheSame: the view made from the read model's findings is the one the worker's own
// scan gives, on a run whose lines the read model takes as a scan does (it leaves out the lines a decode refuses, so
// the odd run is not one).
func TestInForceViewOfTheReadModelsRunIsTheSame(t *testing.T) {
	f := bigRun(t, 3000)
	f.add(`"kind":"run_end","source":"supervisor","reason":"exited","exit_code":0`)
	if err := os.WriteFile(filepath.Join(f.dir, "events.jsonl"), f.lines.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, o := context.Background(), Options{Machine: f.m}
	worker, err := viewCall(ctx, "inforce", f.root, f.run, "", "", o)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ledgerview.Open(f.root).Run(f.run)
	if err != nil {
		t.Fatal(err)
	}
	o.Run = r
	want, got := pageFacts(f, worker.InForce), pageFacts(f, InForce(ctx, f.root, f.run, o))
	if got != want || !worker.InForce.Ended || worker.InForce.Lines != f.seq {
		t.Errorf("the view of the read model's run differs from the worker's own (lines %d, ended %v):\n%s", worker.InForce.Lines, worker.InForce.Ended, firstDifference(want, got))
	}
}

// TestInForceOfAnUnreadableRunSaysWhatItDid: a name that is no run's, and a run whose ledger is missing, give the same
// view they gave when the worker did the reading.
func TestInForceOfAnUnreadableRunSaysWhatItDid(t *testing.T) {
	f := bigRun(t, 20)
	ctx, o := context.Background(), Options{Machine: f.m}
	if v := InForce(ctx, f.root, "../escape", o); v.Err != "not a run id" || v.CopyPath != "" || len(v.View.Notes) != 1 || v.View.Notes[0] != "Not a run id." {
		t.Errorf("a name that is no run: err %q, copy %q, notes %q", v.Err, v.CopyPath, v.View.Notes)
	}
	v := InForce(ctx, f.root, "r-bbbbbbbb-0000000000001-nolins", o) // no folder at all
	if v.Err == "" || v.CopyPath != filepath.Join(f.root, "r-bbbbbbbb-0000000000001-nolins", ledger.ContractFile) || len(v.View.Notes) != 1 || v.View.Notes[0] != "The run's record could not be read." {
		t.Errorf("a run with no ledger: err %q, copy %q, notes %q", v.Err, v.CopyPath, v.View.Notes)
	}
	worker, err := viewCall(ctx, "inforce", f.root, "r-bbbbbbbb-0000000000001-nolins", "", "", o)
	if err != nil {
		t.Fatal(err)
	}
	if worker.InForce.Err != v.Err || worker.InForce.CopyPath != v.CopyPath || !slices.Equal(worker.InForce.View.Notes, v.View.Notes) {
		t.Errorf("the worker's own view of a run with no ledger: err %q copy %q notes %q; the caller's: err %q copy %q notes %q",
			worker.InForce.Err, worker.InForce.CopyPath, worker.InForce.View.Notes, v.Err, v.CopyPath, v.View.Notes)
	}
}

// TestInForceThroughTheWorkerTakesTheReadModelsFindings: the page's view of a run the read model holds is made from the
// read model's findings (kept per run version in the calling process, a worker being a new process for each exchange):
// the ledger on disk is not read again, so a ledger changed behind the read model's back shows the read model's run,
// and two views of one version scan once.
func TestInForceThroughTheWorkerTakesTheReadModelsFindings(t *testing.T) {
	f := bigRun(t, 500)
	events := filepath.Join(f.dir, "events.jsonl")
	if err := os.WriteFile(events, f.lines.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := ledgerview.Open(f.root).Run(f.run)
	if err != nil {
		t.Fatal(err)
	}
	reads := func() int {
		scanMu.Lock()
		defer scanMu.Unlock()
		return scanReads
	}
	before := reads()
	o := Options{Machine: f.m, Run: r}
	a := InForce(context.Background(), f.root, f.run, o)
	if a.Err != "" || a.Lines != 500 || rule(t, a, "exec.allow", "git").Hits != 100 {
		t.Fatalf("first view: err %q, lines %d, git hits %d", a.Err, a.Lines, rule(t, a, "exec.allow", "git").Hits)
	}
	// Behind the read model's back: the ledger is replaced by a shorter run.
	short := bigRun(t, 50)
	if err := os.WriteFile(events, short.lines.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	b := InForce(context.Background(), f.root, f.run, o)
	if b.Err != "" || b.Lines != 500 || rule(t, b, "exec.allow", "git").Hits != 100 {
		t.Errorf("second view after the ledger changed: err %q, lines %d, git hits %d; want the read model's 500 and 100", b.Err, b.Lines, rule(t, b, "exec.allow", "git").Hits)
	}
	if n := reads() - before; n != 1 {
		t.Errorf("two views of one run version scanned it %d times, want 1", n)
	}
}
