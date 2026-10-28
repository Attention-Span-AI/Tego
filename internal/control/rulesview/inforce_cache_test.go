// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// TestInForceScanIsKeptPerRunVersion: the Rules page asked twice for the same version of a run scans its ledger once
// and shows the same hits; after the run gains a line it scans again and the new line counts.
func TestInForceScanIsKeptPerRunVersion(t *testing.T) {
	f := bigRun(t, 500)
	write := func() {
		if err := os.WriteFile(filepath.Join(f.dir, "events.jsonl"), f.lines.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write()
	store := ledgerview.Open(f.root)
	view := func() *InForceView {
		t.Helper()
		r, err := store.Run(f.run)
		if err != nil {
			t.Fatal(err)
		}
		v := InForce(context.Background(), f.root, f.run, Options{Machine: f.m, Run: r})
		if v.Err != "" {
			t.Fatal(v.Err)
		}
		return v
	}
	reads := func() int {
		scanMu.Lock()
		defer scanMu.Unlock()
		return scanReads
	}
	before := reads()
	a, b := view(), view()
	if n := reads() - before; n != 1 {
		t.Errorf("two views of one run version scanned it %d times, want 1", n)
	}
	if ga, gb := rule(t, a, "exec.allow", "git").Hits, rule(t, b, "exec.allow", "git").Hits; ga != gb || ga != 100 {
		t.Errorf("git hits %d then %d, want 100 both times", ga, gb)
	}
	f.add(`"kind":"exec","source":"seccomp","rule":"exec[git]","verdict":"allow","authority":"rule","argv":["git","log"],"exec_id":"x/10/2","path":"/usr/bin/git"`)
	write()
	c := view()
	if n := reads() - before; n != 2 {
		t.Errorf("the run after one more line was scanned %d times in all, want 2", n)
	}
	if got := rule(t, c, "exec.allow", "git").Hits; got != 101 || c.Lines != 501 {
		t.Errorf("after one more line: git hits %d, lines %d; want 101 and 501", got, c.Lines)
	}
}

// BenchmarkInForceWarm55k is the Rules page's InForce over a 55k-line run the read model holds (Options.Run), asked
// again with nothing changed, as an open /rules tab asks on every live update.
func BenchmarkInForceWarm55k(b *testing.B) {
	f := bigRun(b, 55000)
	if err := os.WriteFile(filepath.Join(f.dir, "events.jsonl"), f.lines.Bytes(), 0o644); err != nil {
		b.Fatal(err)
	}
	r, err := ledgerview.Open(f.root).Run(f.run)
	if err != nil {
		b.Fatal(err)
	}
	o := Options{Machine: f.m, Run: r}
	_ = InForce(context.Background(), f.root, f.run, o)
	for b.Loop() {
		_ = InForce(context.Background(), f.root, f.run, o)
	}
}
