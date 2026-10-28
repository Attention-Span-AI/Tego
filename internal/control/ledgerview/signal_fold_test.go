// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/secretpath"
)

// sameSignal fails t when got is not want, the one-pass reference (refSignal), field for field. The reference keeps
// each destination's group indices, which the cached result drops once its post-pass read them.
func sameSignal(t *testing.T, what string, got, want *RunSignal) {
	t.Helper()
	for i := range want.Outbound {
		want.Outbound[i].groups = nil
	}
	if reflect.DeepEqual(got, want) {
		return
	}
	t.Fatalf("%s: the incremental Signal differs from the one pass\n got: %+v\nwant: %+v", what, got, want)
}

// TestSignalFoldEqualsOnePass: on randomized runs read a few lines at a time, as a live run's page reads it, the
// Signal folded from the lines each version gained equals the one-pass code it replaced, version after version:
// the same secrets, destinations, asks, groups and verdict inputs, in the same order. Between versions the run's
// state moves too (live, lost, ended, asks open), and an older version is asked for after a newer one.
func TestSignalFoldEqualsOnePass(t *testing.T) {
	folds := signalFolds.Load()
	for seed := range 24 {
		rng := rand.New(rand.NewPCG(uint64(seed), 7))
		id := fmt.Sprintf("r-aaaa-%04d-foldxx", seed)
		root := t.TempDir()
		n := 50 + rng.IntN(1500)
		vocab := 3 + rng.IntN(40)
		step := time.Duration(50+rng.IntN(3000)) * time.Millisecond
		ls := agentLines(id, 0, n, vocab, step, rng)
		ended := rng.IntN(2) == 0
		if ended {
			ls = append(ls, line(id, "codex", n, time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC), "run_end", `"reason":"exit","exit_code":0`))
		}
		writeRun(t, root, id, ls...)
		full, err := LoadRun(root, id)
		if err != nil {
			t.Fatal(err)
		}
		evs := full.Events
		sens := Sensitive{Cwd: "/home/u/proj"}
		if rng.IntN(3) > 0 {
			sens.Entries = []string{"/home/u/.ssh/", "./confidential/", "~/.aws/", "/home/u/proj/src/f1*.go"}
		}
		var rev uint64
		version := func(k int, live bool) *Run {
			rev++
			r := replay(id, evs[:k], false, nil)
			r.Live, r.Rev = live && !r.Ended, rev
			return r
		}
		k := 0
		for k < len(evs) {
			k = min(len(evs), k+1+rng.IntN(1+rng.IntN(60)))
			live := k < len(evs) || !ended
			r := version(k, live && rng.IntN(8) > 0)
			sameSignal(t, fmt.Sprintf("seed %d, %d of %d lines, live %v", seed, k, len(evs), r.Live), Signal(r, sens), refSignal(r, sens))
			if rng.IntN(10) == 0 && k > 2 {
				old := version(1+rng.IntN(k-1), true)
				sameSignal(t, fmt.Sprintf("seed %d, an older version of %d lines", seed, old.Lines), Signal(old, sens), refSignal(old, sens))
			}
			if rng.IntN(12) == 0 {
				other := Sensitive{Cwd: "/elsewhere"}
				sameSignal(t, fmt.Sprintf("seed %d, other entries", seed), Signal(r, other), refSignal(r, other))
			}
		}
	}
	if signalFolds.Load() == folds {
		t.Fatal("no Signal was folded from a run's new lines: the test did not reach the incremental path")
	}
}

// TestSignalFoldAcrossStoreAppends: the same through the Store, as the dashboard reads a live run whose file grows:
// each version's Signal equals the one pass, and a version only folds the lines it gained.
func TestSignalFoldAcrossStoreAppends(t *testing.T) {
	root, id := t.TempDir(), "r-aaaa-0042-storex"
	rng := rand.New(rand.NewPCG(42, 42))
	writeRun(t, root, id, agentLines(id, 0, 400, 12, 400*time.Millisecond, rng)...)
	markLive(t, root, id, true)
	s := Open(root)
	sens := Sensitive{Entries: []string{"/home/u/.ssh/", "./confidential/"}, Cwd: "/home/u/proj"}
	seq := 400
	for i := range 30 {
		r, err := s.Run(id)
		if err != nil {
			t.Fatal(err)
		}
		before := signalFolds.Load()
		sameSignal(t, fmt.Sprintf("append %d", i), Signal(r, sens), refSignal(r, sens))
		if i > 0 && signalFolds.Load() != before+1 {
			t.Fatalf("append %d: the new version was not folded from its new lines", i)
		}
		ls := agentLines(id, seq, 1+rng.IntN(20), 12, 400*time.Millisecond, rng)
		seq += len(ls)
		appendLines(t, root, id, ls...)
	}
	markLive(t, root, id, false)
	r, err := s.Run(id)
	if err != nil {
		t.Fatal(err)
	}
	sameSignal(t, "lost", Signal(r, sens), refSignal(r, sens))
}

// TestSecretMarkAndEntries: the compiled contract entries match a path as the one-pass code did, and the mark a line
// gets when the Store takes it says for each of its paths what secretpath.Is says: one path, a rename's two, a target
// holding " → " twice (left unmarked, read by name), a refused line, an ask, and a line no Store took.
func TestSecretMarkAndEntries(t *testing.T) {
	names := []string{"/home/u/.ssh/id_rsa", "/home/u/.ssh/id_rsa.pub", "/home/u/proj/.env", "/home/u/proj/src/f12.go",
		"/home/u/proj/src/f2.go", "/home/u/proj/confidential/plan.md", "/home/u/proj/confidentialx", "/etc/ssl/certs/a.pem",
		"/home/u/.aws/credentials", "/home/u/proj/confidential", "", "relative/.env", "/home/u/.config/gh/token"}
	senses := []Sensitive{
		{},
		{Cwd: "/home/u/proj"},
		{Entries: []string{"./confidential/", "/home/u/.ssh/"}, Cwd: "/home/u/proj"},
		{Entries: []string{"./confidential/"}, Cwd: ""},
		{Entries: []string{"~/.aws/", "/home/u/proj/src/f1*.go", "/home/u/proj/confidential"}, Cwd: "/home/u/proj"},
		{Entries: []string{"./confidential/"}, Cwd: "/other"},
	}
	for _, s := range senses {
		m := compileSensitive(s)
		for _, p := range names {
			wantEntry, wantUnder := refUnder(s, p)
			if entry, under := m.under(p); entry != wantEntry || under != wantUnder {
				t.Errorf("%+v %q: (%q, %v), want (%q, %v)", s, p, entry, under, wantEntry, wantUnder)
			}
			if got, ok := s.under(p); got != wantEntry || ok != wantUnder {
				t.Errorf("Sensitive.under(%q) = %q, %v; want %q, %v", p, got, ok, wantEntry, wantUnder)
			}
		}
	}
	for _, a := range names {
		for _, b := range names {
			for _, e := range []Event{
				{Kind: "fs", Target: a},
				{Kind: "fs", Target: a + " → " + b},
				{Kind: "fs", Target: a + " → " + b + " → " + a},
				{Kind: "refused", Target: a},
				{Kind: "ask", askTarget: a},
			} {
				// Signal reads a file line's paths with paths (two at most), Compare with strings.Split.
				splits := [][]string{{a}}
				if e.Kind == "fs" {
					splits = [][]string{paths(e.Target), strings.Split(e.Target, " → ")}
				}
				for _, marked := range []bool{false, true} {
					if marked {
						markSecret(&e)
					}
					for _, parts := range splits {
						for i, p := range parts {
							if got := e.secretPart(i, p); got != secretpath.Is(p) {
								t.Errorf("%s %q part %d %q (marked %v): %v, want %v", e.Kind, e.Target, i, p, marked, got, !got)
							}
						}
					}
				}
			}
		}
	}
}

// TestSignalConcurrentVersions: viewers asking for a live run's Signal at once, each holding some version of it (a
// newer one, an older one a slower request still holds), each get that version's Signal, and a result they keep is
// never changed by the folds that follow (run with -race).
func TestSignalConcurrentVersions(t *testing.T) {
	rng := rand.New(rand.NewPCG(5, 5))
	id := "r-aaaa-0055-concur"
	root := t.TempDir()
	writeRun(t, root, id, agentLines(id, 0, 1200, 9, 300*time.Millisecond, rng)...)
	full, err := LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	sens := Sensitive{Entries: []string{"/home/u/.ssh/"}, Cwd: "/home/u/proj"}
	var versions []*Run
	var want []*RunSignal
	for k := 100; k <= len(full.Events); k += 50 {
		r := replay(id, full.Events[:k], false, nil)
		r.Live, r.Rev = true, uint64(k)
		w := refSignal(r, sens)
		for i := range w.Outbound {
			w.Outbound[i].groups = nil
		}
		versions, want = append(versions, r), append(want, w)
	}
	pick := func(g, i int) int { return max(min(len(versions)-1, i+g%3-1), 0) } // a version behind, the same, ahead
	var wg sync.WaitGroup
	got := make([][]*RunSignal, 8)
	for g := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range versions {
				got[g] = append(got[g], Signal(versions[pick(g, i)], sens))
			}
		}()
	}
	wg.Wait()
	for g := range got {
		for i, sig := range got[g] {
			if v := pick(g, i); !reflect.DeepEqual(sig, want[v]) {
				t.Fatalf("viewer %d, version of %d lines: the Signal differs from the one pass", g, versions[v].Lines)
			}
		}
	}
}
