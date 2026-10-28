// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
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
