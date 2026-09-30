// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/reason"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestAnchorAppendRepairsATornTail: an anchor line torn by a full disk or a crash is cut before the next
// append, so the next line starts on a line boundary. Glued onto the fragment, it made a malformed line
// that failed Head for every run in the file, earlier ones included (E28).
//
// Also pins record-ledger.md E28: an append to a chain.log with a torn tail repairs it.
func TestAnchorAppendRepairsATornTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".tego", ChainLogFile)
	a := NewFileChainAnchor(path)
	if err := a.Append(testRef.ID, strings.Repeat("ab", 32)); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(runID(fixedStart.Add(time.Minute), "zz9zz9") + " " + strings.Repeat("ef", 3)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	third := runID(fixedStart.Add(2*time.Minute), "yy8yy8")
	if err := a.Append(third, strings.Repeat("cd", 32)); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := a.Head(testRef.ID); err != nil || !ok {
		t.Errorf("Head(the run anchored before the tear) = ok %v, err %v", ok, err)
	}
	if _, ok, err := a.Head(third); err != nil || !ok {
		t.Errorf("Head(the run anchored after the tear) = ok %v, err %v", ok, err)
	}
}

// TestStateOfAnEmptyRunWithAHeldLockIsRunning: a Writer between its flock and its first open of
// events.jsonl owns a directory with no ledger yet. State asks the lock, as everywhere (I7), so gc keeps it.
func TestStateOfAnEmptyRunWithAHeldLockIsRunning(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	id := runID(time.Now().Add(-2*time.Second), "d4e5f6")
	if err := MakeRunDir(root, id); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(root, id, LockFile), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if st, err := NewRunRepository(root).State(context.Background(), id); err != nil || st != StateRunning {
		t.Fatalf("State = %s, %v; want running while the lock is held", st, err)
	}
	rep, err := GC(context.Background(), root, time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Deleted) != 0 {
		t.Fatalf("gc deleted %v, a run directory whose lock a live Writer holds", rep.Deleted)
	}
}

// TestGCKeepsARunThatStartedAfterItsStateWasRead: gc decides on State and then removes; a launcher that
// opens the directory in between (a run between MakeRunDir and its first line reads empty) must keep it.
// gc now removes only under the run's own lock. The WithNow hook runs between the two.
func TestGCKeepsARunThatStartedAfterItsStateWasRead(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	id := runID(time.Now().Add(-2*time.Second), "a1b2c3")
	ref := record.RunRef{ID: id, Agent: "retriever"}
	if err := MakeRunDir(root, id); err != nil {
		t.Fatal(err)
	}
	anchor := &memAnchor{}
	var w *Writer
	now := func() time.Time {
		if w == nil {
			var err error
			if w, err = Open(filepath.Join(root, id), ref, WithFreshRunDir(), WithAnchor(anchor)); err != nil {
				t.Fatalf("launcher Open: %v", err)
			}
			if err := w.WriteRunStart(startPayload()); err != nil {
				t.Fatal(err)
			}
		}
		return time.Now()
	}
	if _, err := GC(context.Background(), root, time.Second, false, WithNow(now)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := VerifyRunDir(context.Background(), filepath.Join(root, id), anchor); errors.Is(err, ErrLedgerMissing) {
		t.Fatal("gc removed a live run's record")
	}
}

// TestGCAgesOutALostRunItCannotSweep: a lost run whose chain resume refuses (one damaged line before an
// intact last one) is reported on every pass and still removed once it is past retention (E22). gc used to
// return before the age check, so the directory stayed forever and failed the same way on every pass.
func TestGCAgesOutALostRunItCannotSweep(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 3)
	w.release()
	w.closeDirs()
	p := filepath.Join(dir, EventsFile)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(b, []byte("\n"))
	lines[1] = bytes.Replace(lines[1], []byte(`"why":"e0"`), []byte(`"why":"e9"`), 1) // one byte changed
	if err := os.WriteFile(p, bytes.Join(lines, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := GC(context.Background(), filepath.Dir(dir), time.Hour, false,
		WithNow(func() time.Time { return fixedStart.Add(365 * 24 * time.Hour) }))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Errors[testRef.ID] == nil {
		t.Error("the failed sweep was not reported")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("a year past retention the run directory is still there (%v)", err)
	}
}

// TestAFIFOInTheRunDirectoryHangsNothing: a FIFO planted as lock or events.jsonl held the reader's open, and
// with it gc, status and the sweep every `tego run` does before it starts. Readers open non-blocking and take
// only a regular file.
func TestAFIFOInTheRunDirectoryHangsNothing(t *testing.T) {
	for _, name := range []string{LockFile, EventsFile} {
		t.Run(name, func(t *testing.T) {
			w, dir, _ := openTestWriter(t)
			startRun(t, w, 1)
			w.release() // the launcher died: a lost run
			w.closeDirs()
			p := filepath.Join(dir, name)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				_, _ = GC(context.Background(), filepath.Dir(dir), time.Hour, true)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				// Release the stuck open before failing, so the test binary does not hang with it.
				if f, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
					_ = f.Close()
				}
				t.Fatalf("gc blocked on a FIFO named %s", name)
			}
		})
	}
}

// TestLastRefusalIsMirroredWhereTheRunCanReadIt: the ledger root is read-denied to the agent (agent-contract
// R6a), so last-refusal.json is written into the run's runtime directory as well, and a link there is refused
// rather than followed.
func TestLastRefusalIsMirroredWhereTheRunCanReadIt(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 1)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	if err := w.MirrorLastRefusal(link); err == nil {
		t.Fatal("MirrorLastRefusal followed a symbolic link")
	}
	mirror := t.TempDir()
	if err := w.MirrorLastRefusal(mirror); err != nil {
		t.Fatal(err)
	}
	e := &record.Event{Kind: record.KindRefused, Source: record.SourceSupervisor, PID: 1, TID: 1,
		Rule: "fs.write[./out]", Reason: record.ReasonWriteOutsideContract}
	if err := e.SetPayload(record.RefusedPayload{Op: "open", Target: "/etc/x", Reason: record.ReasonWriteOutsideContract, Rule: "fs.write[./out]"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(e); err != nil {
		t.Fatal(err)
	}
	want := record.RefusedPayload{Op: "open", Target: "/etc/x", Reason: record.ReasonWriteOutsideContract, Rule: "fs.write[./out]"}
	one := func(f *reason.File) bool { return f.Refusals == 1 }
	f, inDir := waitReason(t, dir, one)
	if got := legacy(t, inDir); got != want || f.Seq != 2 || f.Run != testRef.ID { // run_start, a gap, the refusal
		t.Fatalf("run directory %s, want %+v", inDir, want)
	}
	if _, inMirror := waitReason(t, mirror, one); !bytes.Equal(inMirror, inDir) {
		t.Fatalf("mirror %s, want the run directory's bytes %s", inMirror, inDir)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
}

// TestARunThatDiedBeforeRunStartHasItsCgroupSwept: a launcher killed between opening its ledger and writing run_start
// left an empty ledger and a cgroup scope nothing removed, since the sweep ended only runs with a run_start. The hook
// now runs for such a run too, with the agent its contract copy names; a run with no contract copy had no cgroup yet
// and is not touched.
func TestARunThatDiedBeforeRunStartHasItsCgroupSwept(t *testing.T) {
	for _, withContract := range []bool{true, false} {
		t.Run(fmt.Sprintf("contract=%v", withContract), func(t *testing.T) {
			opts := []Option{}
			if withContract {
				opts = append(opts, WithContract([]byte("version: 0\nname: early-agent\ncommand: [\"/bin/true\"]\n")))
			}
			w, dir, _ := openTestWriter(t, opts...)
			w.release() // killed before run_start: no line, lock free
			w.closeDirs()
			var swept []record.RunRef
			hook := WithSweepHook(func(_ context.Context, _ sys.Lender, run record.RunRef) error { swept = append(swept, run); return nil })
			for _, pass := range []func() error{
				func() error { _, err := GC(context.Background(), filepath.Dir(dir), keepAll, false, hook); return err },
				func() error {
					if err := MarkLive(filepath.Dir(dir), testRef.ID); err != nil {
						return err
					}
					_, err := SweepLive(context.Background(), filepath.Dir(dir), hook)
					return err
				},
			} {
				swept = nil
				if err := pass(); err != nil {
					t.Fatal(err)
				}
				if withContract && (len(swept) != 1 || swept[0].Agent != "early-agent" || swept[0].ID != testRef.ID) {
					t.Errorf("hook calls %+v, want one for early-agent's run", swept)
				}
				if !withContract && len(swept) != 0 {
					t.Errorf("hook ran %+v for a run with no contract copy, which had no cgroup yet", swept)
				}
			}
		})
	}
}

// TestCloseSyncsTheRunDirectoryAndTheLedgerRoot: Close fsynced events.jsonl and the blobs, never the directory
// entries that name them: the run directory, which holds events.jsonl, and the ledger root, which holds the run
// directory. A file's fsync persists a new entry on the common filesystems in practice, and POSIX does not promise
// it.
func TestCloseSyncsTheRunDirectoryAndTheLedgerRoot(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	if err := w.WriteRunStart(startPayload()); err != nil {
		t.Fatal(err)
	}
	var synced []string
	prev := fsyncDir
	fsyncDir = func(d *sys.FD) error {
		var p string
		_ = d.ProcPath(func(path string) error { p, _ = os.Readlink(path); return nil })
		synced = append(synced, p)
		return prev(d)
	}
	t.Cleanup(func() { fsyncDir = prev })
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	want := []string{dir, filepath.Dir(dir)}
	if len(synced) != 2 || synced[0] != want[0] || synced[1] != want[1] {
		t.Fatalf("Close synced %v, want %v", synced, want)
	}
}

// TestOpenSweepsTheTempFilesOfADeadWriter: writeFileAt's temp files, left by a writer that died between
// creating one and renaming it, were never removed. The next Open, under the run's lock, removes them.
func TestOpenSweepsTheTempFilesOfADeadWriter(t *testing.T) {
	w, dir, _ := openTestWriter(t, WithContract([]byte("version: 0\nname: a\ncommand: [x]\n")))
	if err := w.WriteRunStart(startPayload()); err != nil {
		t.Fatal(err)
	}
	w.release() // died without run_end
	w.closeDirs()
	for _, name := range []string{".contract.yaml.123", ".last-refusal.json.456"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	again, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = again.Close(record.RunEndPayload{Reason: record.RunEndOrphaned}) })
	for _, name := range []string{".contract.yaml.123", ".last-refusal.json.456"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s survived the reopen: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ContractFile)); err != nil {
		t.Errorf("the contract copy itself went: %v", err)
	}
}

// TestAFreshRunWaitsOutAProbesHold: gc's and stop's liveness probes take the run's flock for an instant, and one that
// landed between a fresh run's lock-file open and its flock refused the brand-new run with ErrRunLocked. A fresh run
// retries for freshLockWait; a resumed one, where a holder is a live launcher, still fails at once.
func TestAFreshRunWaitsOutAProbesHold(t *testing.T) {
	probe := func(path string) {
		f, err := os.Open(path)
		if err != nil {
			t.Error(err)
			return
		}
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Error(err)
		}
		go func() {
			time.Sleep(5 * time.Millisecond)
			_ = f.Close()
		}()
	}
	prev := lockOpened
	lockOpened = probe
	t.Cleanup(func() { lockOpened = prev })

	root := filepath.Join(t.TempDir(), "runs")
	if err := MakeDirs(root); err != nil {
		t.Fatal(err)
	}
	if err := MakeRunDir(root, testRef.ID); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, testRef.ID)
	w, err := Open(dir, testRef, WithAnchor(&memAnchor{}), WithFreshRunDir())
	if err != nil {
		t.Fatalf("a fresh run met a probe's hold: %v", err)
	}
	if err := w.WriteRunStart(startPayload()); err != nil {
		t.Fatal(err)
	}
	w.release()
	w.closeDirs()
	if _, err := Open(dir, testRef, WithAnchor(&memAnchor{})); !errors.Is(err, ErrRunLocked) {
		t.Fatalf("a resumed run under a probe's hold: %v, want ErrRunLocked at once", err)
	}
}
