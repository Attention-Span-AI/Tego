// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The cold start (store.go, bring): runs decoded outside the Store's mutex, in parallel; LoadNow that waits for no
// one; the chain checks that no longer hold a page (chain.go). Run these with -race.

// referenceRun is run id of root as a fresh, single-threaded read of its whole file gives it.
func referenceRun(t *testing.T, root, id string) *Run {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, id, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var evs []Event
	for _, l := range strings.SplitAfter(string(b), "\n") {
		if !strings.HasSuffix(l, "\n") || len(l) == 1 {
			continue
		}
		ev, _, ok := decodeLine([]byte(l[:len(l)-1]))
		if !ok {
			t.Fatalf("%s: a line of the fixture does not decode: %q", id, l)
		}
		markSecret(&ev)
		evs = append(evs, ev)
	}
	return replay(id, evs, false, nil)
}

// sameSummary fails when got and want differ in anything a page counts.
func sameSummary(t *testing.T, how string, got, want *Run) {
	t.Helper()
	if got.Lines != want.Lines || got.Refusals != want.Refusals || got.Asks != want.Asks || got.Bad != want.Bad ||
		got.LastSeq != want.LastSeq || !got.Start.Equal(want.Start) || !got.End.Equal(want.End) ||
		got.Ended != want.Ended || len(got.AllEvents()) != len(want.Events) || !reflect.DeepEqual(got.Kinds, want.Kinds) ||
		len(got.Pending) != len(want.Pending) {
		t.Fatalf("%s %s: lines %d refusals %d asks %d bad %d last %d kinds %v pending %d; want %d %d %d %d %d %v %d",
			how, got.ID, got.Lines, got.Refusals, got.Asks, got.Bad, got.LastSeq, got.Kinds, len(got.Pending),
			want.Lines, want.Refusals, want.Asks, want.Bad, want.LastSeq, want.Kinds, len(want.Pending))
	}
}

// checkResident fails when the Store's resident estimate is not the sum of its resident runs' bytes: a run read in
// parallel must be counted once, never twice or not at all.
func checkResident(t *testing.T, s *Store) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var sum int64
	for _, st := range s.runs {
		if st.reading != nil {
			t.Fatalf("%s is still claimed after every request returned", st.id)
		}
		if st.resident {
			sum += st.bytes
		}
	}
	if sum != s.resident {
		t.Fatalf("resident estimate %d, the runs hold %d", s.resident, sum)
	}
}

// TestColdParallelReads: many requests open a cold Store at once (Load, LoadRun, LoadNow); every run is read once
// into the same summary a single-threaded read gives, and nothing is counted twice.
func TestColdParallelReads(t *testing.T) {
	root := randomLedger(t, 21, 12, 400)
	ids := make([]string, 12)
	want := map[string]*Run{}
	for i := range ids {
		ids[i] = fmt.Sprintf("r-aaaa-%04d-randxx", i)
		want[ids[i]] = referenceRun(t, root, ids[i])
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for g := range 9 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			switch g % 3 {
			case 0:
				s, err := Load(root)
				if err != nil || s.Partial || len(s.Runs) != len(ids) {
					t.Errorf("Load: %d runs, partial %v, %v", len(s.Runs), s.Partial, err)
					return
				}
				for _, r := range s.Runs {
					sameSummary(t, "Load", r, want[r.ID])
				}
			case 1:
				id := ids[g%len(ids)]
				r, err := LoadRun(root, id)
				if err != nil {
					t.Error(err)
					return
				}
				sameSummary(t, "LoadRun", r, want[id])
			default:
				s, err := LoadNow(root)
				if err != nil {
					t.Error(err)
					return
				}
				for _, r := range s.Runs { // a run LoadNow shows is whole: published only once read to the end
					sameSummary(t, "LoadNow", r, want[r.ID])
				}
				if len(s.Runs) < len(ids) && !s.Partial {
					t.Errorf("LoadNow left out %d runs without saying Partial", len(ids)-len(s.Runs))
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	checkResident(t, Open(root))
	s, err := Load(root)
	if err != nil || s.Partial || len(s.Runs) != len(ids) {
		t.Fatalf("after: %d runs, partial %v, %v", len(s.Runs), s.Partial, err)
	}
}

// claimRun marks run id of root as being read by someone else, as bring does, and returns the release.
func claimRun(t *testing.T, root, id string) func() {
	t.Helper()
	s := Open(root)
	s.mu.Lock()
	st := s.state(id)
	if st.reading != nil {
		s.mu.Unlock()
		t.Fatalf("%s already claimed", id)
	}
	st.reading = make(chan struct{})
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		close(st.reading)
		st.reading = nil
		s.mu.Unlock()
	}
}

// TestLoadNowDoesNotWait: while a run is being read, LoadNow answers at once with what was last published (a run
// never read is left out) and says Partial; Load waits for the read and then has the new lines.
func TestLoadNowDoesNotWait(t *testing.T) {
	root := randomLedger(t, 22, 3, 50)
	a, b := "r-aaaa-0000-randxx", "r-aaaa-0001-randxx"
	if _, err := Load(root); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	appendLines(t, root, a, line(a, "x", 50, t0, "exec", `"verdict":"allow","argv":["git"]`))
	release := claimRun(t, root, a)
	writeRun(t, root, "r-aaaa-0009-newxxx", line("r-aaaa-0009-newxxx", "x", 0, t0, "run_start", ""))
	releaseNew := claimRun(t, root, "r-aaaa-0009-newxxx")

	done := make(chan *Snapshot, 1)
	go func() {
		s, _ := LoadNow(root)
		done <- s
	}()
	var now *Snapshot
	select {
	case now = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("LoadNow waited for a run another request is reading")
	}
	if !now.Partial || now.Find(a) == nil || now.Find(a).Lines != 50 || now.Find("r-aaaa-0009-newxxx") != nil ||
		now.Find(b) == nil {
		t.Fatalf("LoadNow during a read: partial %v, %v", now.Partial, now.Runs)
	}

	full := make(chan *Snapshot, 1)
	go func() {
		s, _ := Load(root)
		full <- s
	}()
	select {
	case s := <-full:
		t.Fatalf("Load answered while a run it needs was being read: %d runs", len(s.Runs))
	case <-time.After(100 * time.Millisecond):
	}
	release()
	releaseNew()
	select {
	case s := <-full:
		if s.Partial || s.Find(a).Lines != 51 || s.Find("r-aaaa-0009-newxxx") == nil || s.Rev <= now.Rev {
			t.Fatalf("Load after the read: partial %v, %d lines, rev %d after %d", s.Partial, s.Find(a).Lines, s.Rev, now.Rev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Load did not finish once the read was released")
	}
	checkResident(t, Open(root))
}

// TestLoadNowHandsOffBigReads: LoadNow does not decode a large append itself; it shows the run as it was, and a
// background read publishes it and moves the revision.
func TestLoadNowHandsOffBigReads(t *testing.T) {
	root := randomLedger(t, 23, 2, 20)
	id := "r-aaaa-0000-randxx"
	s0, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	pad := strings.Repeat("p", 500)
	var ls []string
	for j := 20; j < 20+nowaitBytes/400; j++ {
		ls = append(ls, line(id, "x", j, t0, "exec", `"verdict":"allow","argv":["`+pad+`"]`))
	}
	appendLines(t, root, id, ls...)
	s1, err := LoadNow(root)
	if err != nil {
		t.Fatal(err)
	}
	if !s1.Partial || s1.Find(id).Lines != 20 {
		t.Fatalf("LoadNow after a %d-line append: partial %v, %d lines", len(ls), s1.Partial, s1.Find(id).Lines)
	}
	deadline := time.Now().Add(10 * time.Second)
	for Open(root).Rev() == s0.Rev {
		if time.Now().After(deadline) {
			t.Fatal("the background read never published")
		}
		time.Sleep(5 * time.Millisecond)
	}
	s2, err := LoadNow(root)
	if err != nil || s2.Partial || s2.Find(id).Lines != 20+len(ls) {
		t.Fatalf("after the background read: partial %v, %d lines, %v", s2.Partial, s2.Find(id).Lines, err)
	}
	sameSummary(t, "after", s2.Find(id), referenceRun(t, root, id))
}

// chainRun writes an ended run with a valid chain anchored in anchor.
func chainRun(t *testing.T, root, anchor, id string) {
	t.Helper()
	w, err := ledger.Open(filepath.Join(root, id), record.RunRef{ID: id, Agent: "cold-test"},
		ledger.WithAnchor(ledger.NewFileChainAnchor(anchor)))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{LauncherPID: 1, LauncherStartNS: 1, TegoVersion: "0.1.0-dev",
		Tier: "landlock", Capture: "off", Kernel: "6.17.0", ContractHash: strings.Repeat("7a", 32), StopGrace: "10s",
		Command: []string{"sh"}, Cwd: "/p"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: "exit"}); err != nil {
		t.Fatal(err)
	}
}

// waitNoFlight waits until no chain check of dir is running.
func waitNoFlight(t *testing.T, dir string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		busy := false
		chainMu.Lock()
		for k := range chainFlights {
			if k.dir == dir {
				busy = true
			}
		}
		chainMu.Unlock()
		if !busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("a chain check never ended")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestChainStaleVerdictRecheckedInBackground: once a verdict's ten minutes ran out, the page gets it at once while
// the run is checked again; an anchor edited in place (same file, same size) is caught by that check, which moves the
// revision so open pages redraw, and the next look says broken.
func TestChainStaleVerdictRecheckedInBackground(t *testing.T) {
	dir := t.TempDir()
	root, anchor := filepath.Join(dir, "runs"), filepath.Join(dir, "chain.log")
	id := "r-3f9c2a1b-0dllq06ts7401-c4chex"
	chainRun(t, root, anchor, id)
	r, err := LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if c := VerifyRun(context.Background(), root, id, anchor, r); !c.Verified() {
		t.Fatalf("chain: %+v", c)
	}
	b, err := os.ReadFile(anchor)
	if err != nil {
		t.Fatal(err)
	}
	i := strings.LastIndex(string(b), "\n") - 1 // the head's last hex digit
	flip := byte('0')
	if b[i] == '0' {
		flip = '1'
	}
	b[i] = flip
	if err := os.WriteFile(anchor, b, 0o600); err != nil { // in place: the same inode and size
		t.Fatal(err)
	}
	chainMu.Lock()
	for k, e := range chainVerdicts {
		if k.dir == filepath.Join(root, id) {
			e.at = time.Now().Add(-2 * chainTTL)
			chainVerdicts[k] = e
		}
	}
	chainMu.Unlock()
	rev := Open(root).Rev()
	if c := VerifyRun(context.Background(), root, id, anchor, r); !c.Verified() {
		t.Fatalf("past its time, the kept verdict is shown while the run is checked again; got %+v", c)
	}
	waitNoFlight(t, filepath.Join(root, id))
	if Open(root).Rev() == rev {
		t.Fatal("the check found another verdict but the revision did not move")
	}
	if c := VerifyRun(context.Background(), root, id, anchor, r); !c.Broken() {
		t.Fatalf("after the background check: %+v, want broken", c)
	}
}

// TestChainVerifyingIsShared: a run whose check is already running is "verifying" on the overview, which does not
// wait; the run page waits for that same check instead of hashing again.
func TestChainVerifyingIsShared(t *testing.T) {
	dir := t.TempDir()
	root, anchor := filepath.Join(dir, "runs"), filepath.Join(dir, "chain.log")
	id := "r-3f9c2a1b-0dllq06ts7402-c4chex"
	chainRun(t, root, anchor, id)
	snap, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	k, why := chainKeyOf(root, id, anchor, snap.Find(id))
	if why != nil || k.dir == "" {
		t.Fatalf("not cacheable: %v", why)
	}
	chainMu.Lock()
	f := startFlight(k.cacheKey())
	chainMu.Unlock()
	if lc := VerifySnapshot(context.Background(), snap, anchor); lc.Verifying != 1 || lc.Checked != 0 || lc.Broken != nil {
		t.Fatalf("overview during a check: %+v", lc)
	}
	got := make(chan Chain, 1)
	go func() { got <- VerifyRun(context.Background(), root, id, anchor, snap.Find(id)) }()
	select {
	case c := <-got:
		t.Fatalf("the run page did not wait for the running check: %+v", c)
	case <-time.After(50 * time.Millisecond):
	}
	n := chainVerifies.Load()
	land(k.cacheKey(), k.anchorSize, f, verifyNow(context.Background(), k.dir, id, anchor))
	if c := <-got; !c.Verified() {
		t.Fatalf("the waiting run page: %+v", c)
	}
	if lc := VerifySnapshot(context.Background(), snap, anchor); lc.Checked != 1 || lc.Verifying != 0 {
		t.Fatalf("overview after the check: %+v", lc)
	}
	if d := chainVerifies.Load() - n; d != 0 {
		t.Fatalf("%d more checks after the shared one", d)
	}
}

// TestPrewarmChain: the start-up check leaves every run the overview checks with a kept verdict, and moves the
// revision once.
func TestPrewarmChain(t *testing.T) {
	dir := t.TempDir()
	root, anchor := filepath.Join(dir, "runs"), filepath.Join(dir, "chain.log")
	for i := range 3 {
		chainRun(t, root, anchor, fmt.Sprintf("r-3f9c2a1b-0dllq06ts750%d-c4chex", i))
	}
	snap, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	rev := Open(root).Rev()
	<-PrewarmChain(context.Background(), snap, anchor)
	if Open(root).Rev() == rev {
		t.Fatal("the revision did not move after the start-up check")
	}
	n := chainVerifies.Load()
	if lc := VerifySnapshot(context.Background(), snap, anchor); lc.Checked != 3 || lc.Verifying != 0 {
		t.Fatalf("overview after the start-up check: %+v", lc)
	}
	if d := chainVerifies.Load() - n; d != 0 {
		t.Fatalf("the overview checked %d runs again", d)
	}
	rev = Open(root).Rev()
	<-PrewarmChain(context.Background(), snap, anchor) // nothing left to check
	if Open(root).Rev() != rev {
		t.Fatal("a start-up check with nothing to do moved the revision")
	}
}
