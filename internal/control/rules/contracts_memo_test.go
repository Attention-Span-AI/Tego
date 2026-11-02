// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/rulefile"
)

// countingWriter is the local writer, counting its guarded reads.
type countingWriter struct {
	Writer
	reads map[string]int
}

func (w *countingWriter) Read(path string) (*rulefile.File, error) {
	w.reads[path]++
	return w.Writer.Read(path)
}

// TestContractsReadOncePerVersion: Contracts reads each contract through the guards once while the file and its
// folder stay the same, and again after a rewrite, an edit in place of the same size, or a folder made unsafe.
func TestContractsReadOncePerVersion(t *testing.T) {
	f := newFixture(t)
	w := &countingWriter{Writer: localWriter{f.s.guard()}, reads: map[string]int{}}
	f.s.Writer = w
	first := f.ref(t, f.contract)
	f.ref(t, f.contract)
	if w.reads[f.contract] != 1 || w.reads[f.other] != 1 {
		t.Fatalf("two listings read %v, want each contract once", w.reads)
	}
	if !first.Writable || first.Base != rulefile.Sum([]byte(baseText)) || first.Agent != "tester" {
		t.Fatalf("first listing: %+v", first)
	}

	// A rewrite through a rename (as rulefile writes): a new inode.
	tmp := f.contract + ".new"
	writeFile(t, tmp, strings.Replace(baseText, "name: tester", "name: renamed", 1))
	if err := os.Rename(tmp, f.contract); err != nil {
		t.Fatal(err)
	}
	if got := f.ref(t, f.contract); got.Agent != "renamed" || w.reads[f.contract] != 2 || w.reads[f.other] != 1 {
		t.Fatalf("after a rename: %+v, reads %v", got, w.reads)
	}

	// An edit in place with the same size: the change time moves.
	same := strings.Replace(baseText, "name: tester", "name: tested", 1)
	time.Sleep(10 * time.Millisecond)
	writeFile(t, f.contract, same)
	got := f.ref(t, f.contract)
	if got.Base != rulefile.Sum([]byte(same)) || w.reads[f.contract] != 3 {
		t.Fatalf("after an edit in place: base %s, reads %v; want the new text's base", got.Base, w.reads)
	}

	// The folder made writable by others: the guard refuses, and the listing says so at once.
	if err := os.Chmod(f.proj, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(f.proj, 0o700) })
	if got := f.ref(t, f.contract); got.Writable || got.Why == "" || got.Agent != "agent" {
		t.Fatalf("an unsafe folder: %+v, want not writable with a reason and the file's name", got)
	}
}

// keyOf is the ledger root dir's key and the later of its modification and change times (rootKey).
func keyOf(t *testing.T, dir string) (string, time.Time) {
	t.Helper()
	d, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	key, changed, ok := rootKey(d)
	if !ok {
		t.Fatalf("%s has no key", dir)
	}
	return key, changed
}

// mustStarts is s.starts, failing t on an error or an empty listing.
func mustStarts(t *testing.T, s *Service) []start {
	t.Helper()
	sts, err := s.starts()
	if err != nil || len(sts) == 0 {
		t.Fatalf("starts: %d runs, err %v", len(sts), err)
	}
	return sts
}

// TestStartsKeptWhileRootUnchanged: the root's listing is kept while its key stays the same, and Contracts over the
// kept listing equals Contracts of a service that never listed the root, after a new run, a removed run, a run whose
// first line comes after the listing and a run that starts running.
func TestStartsKeptWhileRootUnchanged(t *testing.T) {
	f := newFixture(t)
	later := time.Now().Add(time.Hour)
	f.s.clock = func() time.Time { return later } // every listing comes an hour after the root last changed
	same := func(step string) {
		t.Helper()
		got, err := f.s.Contracts()
		if err != nil {
			t.Fatal(err)
		}
		want, err := (&Service{Ledger: f.ledger, Home: f.s.Home, live: f.s.live}).Contracts()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: the kept listing gives %+v, a new service %+v", step, got, want)
		}
	}
	if a, b := mustStarts(t, f.s), mustStarts(t, f.s); &a[0] != &b[0] || len(a) != 4 {
		t.Fatalf("the root was listed again with nothing changed (%d runs)", len(b))
	}
	same("unchanged")

	const runN, runP = "r-aaaa-0005-rules", "r-aaaa-0006-rules"
	f.writeRun(t, runN, f.other, 4)
	if sts := mustStarts(t, f.s); len(sts) != 5 || sts[0].Run != runN {
		t.Fatalf("after a new run: %d runs, newest %s; want 5 and %s", len(sts), sts[0].Run, runN)
	}
	same("a new run")

	if err := os.RemoveAll(filepath.Join(f.ledger, runB)); err != nil {
		t.Fatal(err)
	}
	if got := f.ref(t, f.other); got.Runs != 1 || got.LastRun != runN {
		t.Fatalf("after a removed run: %+v, want only %s", got, runN)
	}
	same("a removed run")

	// A run directory whose first line is not written yet is left out, and read again on every call: its run_start
	// lands in its own directory and leaves the root's key as it was.
	if err := os.Mkdir(filepath.Join(f.ledger, runP), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(f.ledger, runP, ledger.EventsFile), "")
	if sts := mustStarts(t, f.s); slices.ContainsFunc(sts, func(st start) bool { return st.Run == runP }) {
		t.Fatalf("a run without its first line is listed: %+v", sts)
	}
	key, _ := keyOf(t, f.ledger)
	f.writeRun(t, runP, f.contract, 6)
	if now, _ := keyOf(t, f.ledger); now != key {
		t.Fatalf("writing a run's first line moved the root's key (%s, was %s): the case is not tested", now, key)
	}
	if got := f.ref(t, f.contract); got.Runs != 3 || got.LastRun != runP {
		t.Fatalf("after %s wrote its first line: %+v, want 3 runs, the newest %s", runP, got, runP)
	}
	same("a first line after the listing")

	f.live[runP] = true
	if got := f.ref(t, f.contract).Live; !slices.Equal(got, []string{runP}) {
		t.Fatalf("a run that started running: live %v, want [%s]", got, runP)
	}
	same("a run that started running")
}

// TestStartsNotKeptWhileRootSettles: a listing made within listingSettle of the root's last change is not kept, as a
// run directory made in the same tick of the file times could leave the key as it was; once the root has been
// unchanged that long, the next listing is.
func TestStartsNotKeptWhileRootSettles(t *testing.T) {
	f := newFixture(t)
	_, changed := keyOf(t, f.ledger)
	f.s.clock = func() time.Time { return changed.Add(listingSettle / 2) }
	if a, b := mustStarts(t, f.s), mustStarts(t, f.s); &a[0] == &b[0] {
		t.Fatal("a listing made right after the root changed was kept")
	}
	f.s.clock = func() time.Time { return changed.Add(2 * listingSettle) }
	if a, b := mustStarts(t, f.s), mustStarts(t, f.s); &a[0] != &b[0] {
		t.Fatal("a listing of a settled root was not kept")
	}
}

// TestStartsConcurrent: Contracts called from several requests at once while runs start keeps one consistent
// listing (the race detector checks the kept listing is shared safely), and ends as a new service sees the root.
func TestStartsConcurrent(t *testing.T) {
	f := newFixture(t)
	later := time.Now().Add(time.Hour)
	f.s.clock = func() time.Time { return later }
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 50 {
				if _, err := f.s.Contracts(); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	for i := range 10 {
		f.writeRun(t, fmt.Sprintf("r-bbbb-%04d-rules", i), f.contract, 10+i)
	}
	wg.Wait()
	got, err := f.s.Contracts()
	if err != nil {
		t.Fatal(err)
	}
	want, err := (&Service{Ledger: f.ledger, Home: f.s.Home, live: f.s.live}).Contracts()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) || f.ref(t, f.contract).Runs != 12 {
		t.Fatalf("after concurrent listings: %+v, a new service %+v; want 12 runs of %s", got, want, f.contract)
	}
}

// TestContractsProbeOnlyListedRuns: a run holds its lock only while the live index lists it, so the listing probes
// listed runs only: a held lock of an unlisted run is not live, the same lock listed is.
func TestContractsProbeOnlyListedRuns(t *testing.T) {
	f := newFixture(t)
	f.s.live = nil // the real probe
	lock, err := os.OpenFile(filepath.Join(f.ledger, runA, ledger.LockFile), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if got := f.ref(t, f.contract).Live; len(got) != 0 {
		t.Errorf("no live index: live %v, want none probed", got)
	}
	if err := os.MkdirAll(filepath.Join(f.ledger, ledger.LiveDir), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{runA, runA2} { // runA2 is listed but holds no lock
		writeFile(t, filepath.Join(f.ledger, ledger.LiveDir, id), "")
	}
	if got := f.ref(t, f.contract).Live; !slices.Equal(got, []string{runA}) {
		t.Errorf("runA listed and locked, runA2 listed only: live %v, want [%s]", got, runA)
	}
}
