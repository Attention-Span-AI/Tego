// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/reason"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestOpenCreatesRunDirectory(t *testing.T) {
	w, dir, _ := openTestWriter(t, WithContract([]byte("name: retriever\n")))
	defer w.Close(record.RunEndPayload{Reason: record.RunEndExit})
	if got := fileMode(t, dir); got != 0o700 {
		t.Errorf("run dir mode %o, want 0700", got)
	}
	for _, f := range []string{EventsFile, LockFile, ContractFile} {
		if got := fileMode(t, filepath.Join(dir, f)); got != 0o600 {
			t.Errorf("%s mode %o, want 0600", f, got)
		}
	}
	if got := fileMode(t, filepath.Join(dir, BlobsDir)); got != 0o700 {
		t.Errorf("blobs mode %o, want 0700", got)
	}
	if w.Seq() != 0 || w.Head() != "" || w.Ref() != testRef || w.Dir() != dir {
		t.Errorf("fresh writer: seq %d head %q", w.Seq(), w.Head())
	}
	if st, err := os.Stat(filepath.Join(dir, EventsFile)); err != nil || st.Size() != 0 {
		t.Errorf("no line written yet: %v %d", err, st.Size())
	}
	// The events file is the only open of that path and carries O_APPEND (I1).
	if fl, err := fcntlFlags(w.events); err != nil || fl&syscall.O_APPEND == 0 {
		t.Errorf("events fd flags %#x err %v: O_APPEND missing", fl, err)
	}
}

func fcntlFlags(f *os.File) (int, error) {
	fl, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_GETFL, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(fl), nil
}

// TestOpenWithExistingFilesMakesNothing: under WithExistingFiles a run directory missing any of the Writer's files is
// os.ErrNotExist with nothing made, whichever is missing, and one that has them all resumes.
func TestOpenWithExistingFilesMakesNothing(t *testing.T) {
	for _, missing := range []string{LockFile, EventsFile, BlobsDir} {
		t.Run(missing, func(t *testing.T) {
			w, dir, _ := openTestWriter(t)
			if err := w.Abandon(); err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(filepath.Join(dir, missing)); err != nil {
				t.Fatal(err)
			}
			if w, err := Open(dir, testRef, WithExistingFiles(), WithAnchor(&memAnchor{})); !errors.Is(err, os.ErrNotExist) {
				if err == nil {
					_ = w.Abandon()
				}
				t.Fatalf("Open with %s missing = %v, want os.ErrNotExist", missing, err)
			}
			if _, err := os.Lstat(filepath.Join(dir, missing)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("Open made %s: %v", missing, err)
			}
		})
	}
	w, dir, _ := openTestWriter(t)
	if err := w.Abandon(); err != nil {
		t.Fatal(err)
	}
	w, err := Open(dir, testRef, WithExistingFiles(), WithAnchor(&memAnchor{}))
	if err != nil {
		t.Fatalf("Open with every file there: %v", err)
	}
	if err := w.Abandon(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRejectsBadRef(t *testing.T) {
	for _, ref := range []record.RunRef{{ID: "run-1", Agent: "a"}, {ID: testRef.ID, Agent: "Bad Agent"}} {
		if _, err := Open(t.TempDir(), ref); !errors.Is(err, ErrBadRunRef) {
			t.Errorf("%+v: err = %v, want ErrBadRunRef", ref, err)
		}
	}
}

// Also pins record-ledger.md E24: a second Open of the same run is ErrRunLocked.
func TestOpenTwiceIsRunLocked(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	defer w.Close(record.RunEndPayload{Reason: record.RunEndExit})
	_, err := Open(dir, testRef)
	if !errors.Is(err, ErrRunLocked) {
		t.Fatalf("second Open: %v, want ErrRunLocked", err)
	}
	if s := stateOf(t, dir); s != StateRunning {
		t.Fatalf("state %s, want running", s)
	}
}

// Also pins record-ledger.md R13: run_end carries no head of its own; the chain anchor gets the run's final
// event id.
func TestAppendStampsAndChains(t *testing.T) {
	w, dir, anchor := openTestWriter(t)
	startRun(t, w, 3)
	e := fsEvent("/home/u/proj/out/a.txt", nil)
	e.Run, e.Agent, e.Seq, e.ID = "bogus", "bogus", 99, "bogus" // overwritten unconditionally
	if err := w.Append(e); err != nil {
		t.Fatal(err)
	}
	if e.Run != testRef.ID || e.Agent != testRef.Agent || e.Seq != 4 || !record.IsID(e.ID) || e.Prev == "" {
		t.Fatalf("stamped event: %+v", e)
	}
	if e.TS.Location() != time.UTC || e.TS.Before(fixedStart) || e.MonoNS <= 5_000_000_000 {
		t.Fatalf("clock stamping: ts %v mono %d", e.TS, e.MonoNS)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit, ExitCode: 0,
		Supervisor: record.Supervisor{Notifications: 7, HeldMS: 2}}); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rep := verify(t, dir, anchor)
	if rep.Lines != 6 || !rep.Started || !rep.Ended || !rep.Anchored || rep.Head != w.Head() {
		t.Fatalf("verify report %+v, head %s", rep, w.Head())
	}
	events := readAll(t, dir)
	for i, ev := range events {
		if ev.Seq != uint64(i) {
			t.Errorf("seq %d at line %d", ev.Seq, i)
		}
		if i > 0 && ev.MonoNS <= events[i-1].MonoNS {
			t.Errorf("mono_ns not increasing at %d", i)
		}
	}
	var end record.RunEndPayload
	if last := events[len(events)-1]; last.Kind != record.KindRunEnd || last.DecodePayload(&end) != nil ||
		end.Reason != "exit" || end.Supervisor.Notifications != 7 || end.Head != "" {
		t.Fatalf("run_end: %+v %+v", events[len(events)-1], end)
	}
	if h, ok, _ := anchor.Head(testRef.ID); !ok || h != w.Head() {
		t.Fatalf("anchor head %q ok %v, want %q", h, ok, w.Head())
	}
}

// Also pins record-ledger.md E3, E26: a non-existent Kind errors before a byte is written; Blob after Close
// is ErrClosed.
func TestAppendOrderingRules(t *testing.T) {
	w, _, _ := openTestWriter(t)
	if err := w.Append(gapEvent("early")); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("append before run_start: %v", err)
	}
	startRun(t, w, 0)
	if err := w.WriteRunStart(startPayload()); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("second run_start: %v", err)
	}
	end := &record.Event{Kind: record.KindRunEnd, Source: record.SourceSupervisor}
	_ = end.SetPayload(record.RunEndPayload{Reason: "exit"})
	if err := w.Append(end); !errors.Is(err, record.ErrInvalidEvent) {
		t.Fatalf("run_end through Append: %v", err)
	}
	bad := gapEvent("x")
	bad.Kind = "nope"
	if err := w.Append(bad); !errors.Is(err, record.ErrInvalidEvent) {
		t.Fatalf("invalid kind: %v", err)
	}
	if w.Seq() != 1 {
		t.Fatalf("failed appends must not consume seq: %d", w.Seq())
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); !errors.Is(err, ErrAlreadyClosed) {
		t.Fatalf("second Close: %v", err)
	}
	if err := w.Append(gapEvent("late")); !errors.Is(err, ErrClosed) {
		t.Fatalf("append after Close: %v", err)
	}
	if _, err := w.Blob([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("blob after Close: %v", err)
	}
}

func TestAppendConcurrentIsGapless(t *testing.T) {
	w, dir, anchor := openTestWriter(t)
	startRun(t, w, 0)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if err := w.Append(fsEvent("/home/u/proj/out/f", nil)); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	if rep := verify(t, dir, anchor); rep.Lines != 402 {
		t.Fatalf("lines %d, want 402", rep.Lines)
	}
}

// partialWriter simulates the kernel: it writes the first n bytes of a write to f, then fails with err.
type partialWriter struct {
	f   *os.File
	n   int
	err error
}

func (p partialWriter) Write(b []byte) (int, error) {
	if p.n >= len(b) {
		return p.f.Write(b)
	}
	n, _ := p.f.Write(b[:p.n])
	return n, p.err
}

// TestAppendWriteFailures: a write that fails before any byte loses its line only. One that leaves part of a
// line on disk (ENOSPC or EIO mid-write, a short write) has the partial bytes cut back, so the next line
// starts on a line boundary and the run's record goes on to run_end (E6). Only when that cut fails is the
// Writer torn for the rest of the run, and the run then reads as lost.
//
// Also pins record-ledger.md E5, E7: a short write with no error is ErrShortWrite; ENOSPC leaves the prior
// line intact.
func TestAppendWriteFailures(t *testing.T) {
	tests := []struct {
		name    string
		n       int
		err     error
		want    error
		cutFail bool
	}{
		{"enospc before any byte", 0, syscall.ENOSPC, syscall.ENOSPC, false},
		{"enospc mid-line", 10, syscall.ENOSPC, syscall.ENOSPC, false},
		{"short write no error", 10, io.ErrShortWrite, ErrShortWrite, false},
		{"enospc mid-line, and the cut fails", 10, syscall.ENOSPC, syscall.ENOSPC, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, dir, anchor := openTestWriter(t)
			startRun(t, w, 1)
			if tc.cutFail {
				w.truncate = func(int64) error { return syscall.EIO }
			}
			w.out = partialWriter{w.events, tc.n, tc.err}
			if err := w.Append(gapEvent("fail")); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			w.out = w.events
			err := w.Append(gapEvent("after"))
			if tc.cutFail != errors.Is(err, ErrTorn) {
				t.Fatalf("torn = %v after the write failure, err = %v", tc.cutFail, err)
			}
			cerr := w.Close(record.RunEndPayload{Reason: record.RunEndExit})
			if tc.cutFail {
				if !errors.Is(cerr, ErrTorn) {
					t.Fatalf("Close after an uncut partial line: %v", cerr)
				}
				if s := stateOf(t, dir); s != StateLost {
					t.Fatalf("a torn run reads as %s, want lost", s)
				}
				if _, err := Open(dir, testRef); err != nil {
					t.Fatalf("lock must be released after a failed Close: %v", err)
				}
				return
			}
			if cerr != nil {
				t.Fatalf("Close: %v", cerr)
			}
			if s := stateOf(t, dir); s != StateEnded {
				t.Fatalf("state %s, want ended: the partial line was cut and the record went on", s)
			}
			verify(t, dir, anchor)
		})
	}
}

func TestCloseAnchorFailureIsDistinct(t *testing.T) {
	w, dir, anchor := openTestWriter(t)
	startRun(t, w, 1)
	anchor.fail = errors.New("chain.log: permission denied")
	err := w.Close(record.RunEndPayload{Reason: record.RunEndExit})
	if !errors.Is(err, ErrAnchorWrite) || errors.Is(err, ErrTorn) {
		t.Fatalf("Close: %v, want ErrAnchorWrite", err)
	}
	if s := stateOf(t, dir); s != StateEnded {
		t.Fatalf("run is durable and ended without its anchor: %s", s)
	}
	if _, err := Open(dir, testRef); !errors.Is(err, ErrRunEnded) {
		t.Fatalf("lock released, run ended: %v", err)
	}
	r, _ := OpenReader(dir)
	defer r.Close()
	// E29: "run fine, anchor missing" is its own answer, distinct from a chain that is broken.
	if _, err := r.Verify(context.Background(), anchor); !errors.Is(err, ErrAnchorMissing) || errors.Is(err, ErrCorruptChain) {
		t.Fatalf("verify against a missing anchor: %v, want ErrAnchorMissing", err)
	}
	if rep, err := r.Verify(context.Background(), nil); err != nil || !rep.Ended {
		t.Fatalf("verify without anchor: %+v %v", rep, err)
	}
}

// Also pins record-ledger.md R17: the refused line and last-refusal.json are how a refusal's reason is
// recorded. The file's top level is the refusal as it was before v1 (op, target, reason, rule), and v1 adds the
// line's seq, ts and pid, the run, the sentence, the count and the recent list (ADR 0061).
func TestRefusedWritesLastRefusal(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 0)
	e := &record.Event{Kind: record.KindRefused, Source: record.SourceLandlock, PID: 5, TID: 5}
	_ = e.SetPayload(record.RefusedPayload{Op: "open", Target: "/home/u/.ssh/id_ed25519",
		Reason: record.ReasonReadDenied, Rule: "fs.deny_read[~/.ssh]"})
	if err := w.Append(e); err != nil {
		t.Fatal(err)
	}
	want := record.RefusedPayload{Op: "open", Target: "/home/u/.ssh/id_ed25519", Reason: record.ReasonReadDenied,
		Rule: "fs.deny_read[~/.ssh]"}
	f, b := waitReason(t, dir, func(f *reason.File) bool { return f.Refusals == 1 })
	if got := legacy(t, b); got != want {
		t.Fatalf("last-refusal.json read as before v1 = %+v, want %+v (%s)", got, want, b)
	}
	_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
	line := readAll(t, dir)[1]
	if f.V != reason.Version || f.Run != testRef.ID || f.Seq != line.Seq || f.Seq != 1 || !f.TS.Equal(line.TS) ||
		f.PID != 5 || f.Refusals != 1 || len(f.Recent) != 1 {
		t.Fatalf("v1 keys: %+v, the refused line seq %d ts %v", f, line.Seq, line.TS)
	}
	if f.Text != reason.Text(want.Reason, want.Op, want.Target, want.Rule) || f.Recent[0].Text != f.Text {
		t.Errorf("text %q", f.Text)
	}
	if got := fileMode(t, filepath.Join(dir, LastRefusalFile)); got != 0o600 {
		t.Errorf("mode %o", got)
	}
}

// TestLastRefusalIsRewrittenNotAppended pins one of the two exceptions to append-only storage that §3's storage
// table calls out by name: "one of the two files in the run dir that ARE overwritten" (the other is the activity
// sidecar). A second refusal leaves one whole file behind: its top level is only the second refusal, and the
// first is an entry of the recent list (ADR 0061), not bytes left over from the first file.
func TestLastRefusalIsRewrittenNotAppended(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 0)
	first := &record.Event{Kind: record.KindRefused, Source: record.SourceLandlock, PID: 5, TID: 5}
	_ = first.SetPayload(record.RefusedPayload{Op: "open", Target: "/home/u/.ssh/id_ed25519",
		Reason: record.ReasonReadDenied, Rule: "fs.deny_read[~/.ssh]"})
	if err := w.Append(first); err != nil {
		t.Fatal(err)
	}
	// The first is on disk before the second is appended, so the second is a rewrite, not a coalesced write.
	waitReason(t, dir, func(f *reason.File) bool { return f.Refusals == 1 })
	second := &record.Event{Kind: record.KindRefused, Source: record.SourceSupervisor, PID: 6, TID: 6}
	_ = second.SetPayload(record.RefusedPayload{Op: "connect", Target: "93.184.216.34:443",
		Reason: record.ReasonNetNotAllowed, Rule: "unmatched"})
	if err := w.Append(second); err != nil {
		t.Fatal(err)
	}
	want := record.RefusedPayload{Op: "connect", Target: "93.184.216.34:443", Reason: record.ReasonNetNotAllowed, Rule: "unmatched"}
	f, b := waitReason(t, dir, func(f *reason.File) bool { return f.Refusals == 2 })
	if got := legacy(t, b); got != want {
		t.Fatalf("last-refusal.json's top level = %+v, want it rewritten to only the second refusal: %+v", got, want)
	}
	if len(f.Recent) != 2 || f.Recent[0].Target != "/home/u/.ssh/id_ed25519" || f.Recent[0].Seq != 1 ||
		f.Recent[1].Target != want.Target || f.Recent[1].Seq != 2 || f.Seq != 2 {
		t.Fatalf("recent %+v", f.Recent)
	}
	_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
}

// waitReason reads last-refusal.json in dir until it decodes as a reason file ok accepts or a second has passed,
// and returns what it decoded and read last: the file is written off Append's path, within refusalWindow
// (lastRefusal).
func waitReason(t *testing.T, dir string, ok func(*reason.File) bool) (*reason.File, []byte) {
	t.Helper()
	var b []byte
	for deadline := time.Now().Add(time.Second); ; time.Sleep(time.Millisecond) {
		b, _ = os.ReadFile(filepath.Join(dir, LastRefusalFile))
		f, err := reason.Decode(bytes.NewReader(b))
		if err == nil && ok(f) {
			return f, b
		}
		if time.Now().After(deadline) {
			t.Fatalf("last-refusal.json in %s: %v: %s", dir, err, b)
		}
	}
}

// legacy is the file as a reader of its pre-v1 shape, a RefusedPayload, reads it.
func legacy(t *testing.T, b []byte) record.RefusedPayload {
	t.Helper()
	var p record.RefusedPayload
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return p
}

// refusedEvent is a refused line whose target is target.
func refusedEvent(target string) *record.Event {
	e := &record.Event{Kind: record.KindRefused, Source: record.SourceLandlock, PID: 5, TID: 5,
		Reason: record.ReasonReadDenied, Rule: "fs.deny_read[~/.ssh]"}
	_ = e.SetPayload(record.RefusedPayload{Op: "open", Target: target})
	return e
}

// TestLastRefusalIsCoalescedOffTheAppendPath: every refused line rewrote
// last-refusal.json (create, write, rename, twice with the mirror) on the pipeline goroutine under the
// Writer's lock, so an agent choosing its refusal rate cut the ledger's throughput 3.7x. A flood of refusals
// now costs at most one write per refusalWindow, the file ends as the latest refusal while the Writer is
// open, Close writes the latest one, and nothing is written after Close. The mirror holds the same bytes.
func TestLastRefusalIsCoalescedOffTheAppendPath(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 0)
	mirror := t.TempDir()
	if err := w.MirrorLastRefusal(mirror); err != nil {
		t.Fatal(err)
	}
	const n = 2000
	t0 := time.Now()
	for i := range n {
		if err := w.Append(refusedEvent(fmt.Sprintf("/t/%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(t0)
	last := fmt.Sprintf("/t/%d", n-1)
	for _, d := range []string{dir, mirror} {
		_, b := waitReason(t, d, func(f *reason.File) bool { return f.Refusals == n })
		if got := legacy(t, b); got.Target != last || got.Reason != record.ReasonReadDenied || got.Rule != "fs.deny_read[~/.ssh]" {
			t.Fatalf("while open, %s holds %+v, want the latest refusal %s", d, got, last)
		}
	}
	w.refusal.fileMu.Lock()
	writes := w.refusal.writes
	w.refusal.fileMu.Unlock()
	// One write at once, then at most one per window while the flood lasted, and the trailing one.
	if limit := 2 + int(elapsed/refusalWindow) + 1; writes > limit {
		t.Errorf("%d refusals in %v wrote the file %d times, want at most %d", n, elapsed, writes, limit)
	}
	t.Logf("%d refusals in %v: %d writes", n, elapsed, writes)

	// Close writes what is pending at once, not a window later.
	final := refusedEvent("/t/final")
	if err := w.Append(final); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	inDir, _ := os.ReadFile(filepath.Join(dir, LastRefusalFile))
	inMirror, _ := os.ReadFile(filepath.Join(mirror, LastRefusalFile))
	if !bytes.Equal(inDir, inMirror) {
		t.Errorf("the mirror holds other bytes than the run directory:\n%s\n%s", inMirror, inDir)
	}
	f, err := reason.Decode(bytes.NewReader(inDir))
	if err != nil {
		t.Fatalf("after Close: %v: %s", err, inDir)
	}
	if f.Target != "/t/final" || f.Refusals != n+1 || len(f.Recent) != reason.RingSize ||
		f.Recent[0].Target != fmt.Sprintf("/t/%d", n+1-reason.RingSize) || f.Recent[reason.RingSize-1].Target != "/t/final" {
		t.Errorf("after Close: target %s, %d refusals, recent %s .. %s", f.Target, f.Refusals, f.Recent[0].Target,
			f.Recent[len(f.Recent)-1].Target)
	}
	w.refusal.fileMu.Lock()
	writes = w.refusal.writes
	w.refusal.fileMu.Unlock()
	time.Sleep(3 * refusalWindow)
	w.refusal.fileMu.Lock()
	defer w.refusal.fileMu.Unlock()
	if w.refusal.writes != writes {
		t.Errorf("last-refusal.json written %d times after Close", w.refusal.writes-writes)
	}
}

// TestOpenContractCopyIsBestEffort pins §4 Open's contract-copy step: "best-effort, never fatal." A path Open
// cannot write contract.yaml onto (here, something already occupying it that a file can't replace) must not
// stop the run from opening, and must not touch what is already there.
func TestOpenContractCopyIsBestEffort(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runs", testRef.ID)
	if err := os.MkdirAll(filepath.Join(dir, ContractFile), 0o700); err != nil { // contract.yaml is a directory
		t.Fatal(err)
	}
	w, err := Open(dir, testRef, WithAnchor(&memAnchor{}), WithContract([]byte("name: retriever\n")))
	if err != nil {
		t.Fatalf("Open must succeed even when the contract copy cannot land: %v", err)
	}
	defer func() { _ = w.Close(record.RunEndPayload{Reason: record.RunEndExit}) }()
	fi, err := os.Stat(filepath.Join(dir, ContractFile))
	if err != nil || !fi.IsDir() {
		t.Fatalf("the occupied path must be left alone: stat err %v, isDir %v", err, fi != nil && fi.IsDir())
	}
}

// backwardClock hands Append a wall clock that steps backward after its first reading, the NTP correction R7
// describes (E9): "ts... may move backward... no code may use it to order events." mono_ns still advances so
// nothing about seq assignment depends on the wall clock's direction.
type backwardClock struct {
	mono uint64
	n    int
	base time.Time
}

func (c *backwardClock) Now() time.Time {
	c.n++
	c.mono++
	if c.n == 1 {
		return c.base
	}
	return c.base.Add(-time.Hour)
}
func (c *backwardClock) Mono() uint64 { return c.mono }

// TestAppendAcceptsNonMonotonicWallClock pins R7: a run must not fail, and seq must stay the sole, gapless
// ordering key (I4), even when the injected wall clock itself goes backward mid-run.
//
// Also pins record-ledger.md and runtime-launch.md E9 and E19: a wall clock stepped backward does not
// misorder events or stop mono_ns.
func TestAppendAcceptsNonMonotonicWallClock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), testRef.ID)
	clk := &backwardClock{base: fixedStart}
	w, err := Open(dir, testRef, WithClock(clk), WithAnchor(&memAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	startRun(t, w, 3) // run_start's ts, then three lines whose ts has stepped an hour into the past
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatalf("a backward-stepping wall clock must not fail a run: %v", err)
	}
	events := readAll(t, dir)
	if len(events) != 5 {
		t.Fatalf("lines %d, want 5", len(events))
	}
	for i, e := range events {
		if e.Seq != uint64(i) {
			t.Fatalf("seq %d at line %d: seq, not ts, must be what orders the run", e.Seq, i)
		}
	}
	if !events[0].TS.After(events[1].TS) {
		t.Fatalf("clock fixture must actually step backward for this test to mean anything: %v then %v",
			events[0].TS, events[1].TS)
	}
}

// countingWriter counts Write calls and forwards every byte to the real file underneath, so I5 -- "no line is
// assembled via multiple partial writes" -- can be pinned without disturbing what actually reaches disk.
type countingWriter struct {
	calls int
	to    io.Writer
}

func (c *countingWriter) Write(b []byte) (int, error) {
	c.calls++
	return c.to.Write(b)
}

// TestAppendIssuesExactlyOneWriteCall pins R4/I5: Append builds the whole line in one buffer and issues one
// write(2) -- the property the torn-line-tolerant reader depends on for its atomicity argument.
//
// Also pins record-ledger.md I5: one write(2) per Append.
func TestAppendIssuesExactlyOneWriteCall(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 0)
	cw := &countingWriter{to: w.events}
	w.out = cw
	if err := w.Append(gapEvent("one-write")); err != nil {
		t.Fatal(err)
	}
	if cw.calls != 1 {
		t.Fatalf("Append issued %d Write calls, want exactly 1", cw.calls)
	}
	w.out = w.events
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	if got := len(readAll(t, dir)); got != 3 {
		t.Fatalf("lines %d, want 3 (run_start, gap, run_end)", got)
	}
}

// TestCloseReleasesLockWhenRunEndAppendFails covers §4 Close's own error path distinctly from
// TestAppendWriteFailures's uncut case, which tears the writer before Close is ever invoked: here the
// run_end Append inside Close is the very first write to fail. "An Append failure during Close is returned
// but the lock/fds are still released" must hold for this first-failure path too, not only the already-torn one.
func TestCloseReleasesLockWhenRunEndAppendFails(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 0)
	w.out = partialWriter{w.events, 0, syscall.ENOSPC} // fails before a single byte of run_end lands: not torn, just lost
	err := w.Close(record.RunEndPayload{Reason: record.RunEndError, Detail: "disk full"})
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("Close err = %v, want it to surface the run_end write failure", err)
	}
	if errors.Is(err, ErrTorn) {
		t.Fatalf("zero bytes of run_end reached disk, so this must not read as a torn write: %v", err)
	}
	w2, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	if err != nil {
		t.Fatalf("the lock must be free after a failed Close: %v", err)
	}
	_ = w2.Close(record.RunEndPayload{Reason: record.RunEndExit})
}

// TestCloseReleasesLockOnFsyncFailure pins §7's "fsync failure at Close (EIO)" row. A second, independent
// descriptor on the same events.jsonl carries the real run_end write through to disk (an fsync failure is not a
// write failure: the doc is explicit that the line "exists in the page cache and likely on disk, but not
// durability-confirmed"), while w.events -- the descriptor Sync is called on -- is closed out from under it, so
// the sync call itself fails the way an EIO would. Close must still release the lock and surface the error.
func TestCloseReleasesLockOnFsyncFailure(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 0)
	second, err := os.OpenFile(filepath.Join(dir, EventsFile), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	w.out = second
	if err := w.events.Close(); err != nil {
		t.Fatal(err)
	}
	err = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
	if err == nil || !strings.Contains(err.Error(), "fsync") {
		t.Fatalf("Close err = %v, want an fsync failure", err)
	}
	if errors.Is(err, ErrAnchorWrite) {
		t.Fatalf("this must read as a sync failure, not an anchor failure: %v", err)
	}
	_ = second.Close()
	if _, err := Open(dir, testRef, WithAnchor(&memAnchor{})); !errors.Is(err, ErrRunEnded) {
		t.Fatalf("the run_end line landed and the lock must be free: %v", err)
	}
}

func TestResumeAfterTornTail(t *testing.T) {
	w, dir, anchor := openTestWriter(t)
	startRun(t, w, 2)
	head := w.Head()
	// Simulate death mid-write: half a line lands on disk and the lock is released without run_end.
	tearTail(t, w)
	w.release()
	if s := stateOf(t, dir); s != StateLost {
		t.Fatalf("state %s, want lost", s)
	}
	clk := newStepClock(fixedStart.Add(time.Hour), 9_000_000_000, time.Millisecond)
	w2, err := Open(dir, testRef, WithClock(clk), WithAnchor(anchor))
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if w2.Seq() != 4 || w2.Head() == head {
		t.Fatalf("resumed writer: seq %d (want 4: 3 lines + gap), head changed %v", w2.Seq(), w2.Head() != head)
	}
	if err := w2.Close(record.RunEndPayload{Reason: record.RunEndOrphaned}); err != nil {
		t.Fatal(err)
	}
	events := readAll(t, dir)
	var gap record.GapPayload
	if len(events) != 6 || events[3].Kind != record.KindGap || events[3].DecodePayload(&gap) != nil ||
		gap.What != record.GapRecord || gap.Why != "torn-tail" || gap.Count != 1 {
		t.Fatalf("resumed ledger: %d lines, line 3 %+v %+v", len(events), events[3], gap)
	}
	if rep := verify(t, dir, anchor); rep.Lines != 6 || !rep.Ended || !rep.Anchored || rep.TornBytes != 0 {
		t.Fatalf("verify: %+v", rep)
	}
	if _, err := Open(dir, testRef); !errors.Is(err, ErrRunEnded) {
		t.Fatalf("reopen ended run: %v", err)
	}
}

func TestResumeIntactLedgerWritesNoGap(t *testing.T) {
	w, dir, anchor := openTestWriter(t)
	startRun(t, w, 2)
	w.release()
	w2, err := Open(dir, testRef, WithAnchor(anchor))
	if err != nil {
		t.Fatal(err)
	}
	if w2.Seq() != 3 {
		t.Fatalf("seq %d", w2.Seq())
	}
	_ = w2.Close(record.RunEndPayload{Reason: record.RunEndExit})
	if got := len(readAll(t, dir)); got != 4 {
		t.Fatalf("lines %d, want 4", got)
	}
}

// launcherLostGaps counts the gap lines dir's ledger holds for an orphaned run, and fails on any other position
// than just before run_end for the first of them.
func launcherLostGaps(t *testing.T, dir string) int {
	t.Helper()
	events := readAll(t, dir)
	n := 0
	for i, e := range events {
		var g record.GapPayload
		if e.Kind == record.KindGap && e.DecodePayload(&g) == nil && g.Why == record.GapLauncherLost {
			n++
			if g.What != record.GapRecord || g.Count != 0 {
				t.Fatalf("line %d: %+v, want what=record and no count: nothing knows how many lines went", i, g)
			}
			if i != len(events)-2 {
				t.Fatalf("the gap is line %d of %d, want the line before run_end", i, len(events))
			}
		}
	}
	return n
}

// TestSweepOfWholeLinesLostSaysSo is the crash a chain cannot show: a power cut drops whole trailing lines, so what
// survives ends on a line boundary, resume sees no torn tail, and the sweep closes and anchors it. The run verifies
// from run_start to run_end, and only the gap says its record may stop short.
func TestSweepOfWholeLinesLostSaysSo(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, testRef.ID)
	anchor := NewFileChainAnchor(filepath.Join(t.TempDir(), ChainLogFile))
	w, err := Open(dir, testRef, WithAnchor(anchor))
	if err != nil {
		t.Fatal(err)
	}
	startRun(t, w, 6)
	w.release()
	events := filepath.Join(dir, EventsFile)
	b, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(b, []byte("\n"))
	if err := os.WriteFile(events, bytes.Join(lines[:4], nil), 0o600); err != nil { // the last three lines never reached the disk
		t.Fatal(err)
	}
	rep, err := GC(context.Background(), root, 365*24*time.Hour, false, WithWriterOptions(WithAnchor(anchor)))
	if err != nil || len(rep.Errors) != 0 || len(rep.Swept) != 1 {
		t.Fatalf("gc: %+v %v", rep, err)
	}
	if v := verify(t, dir, anchor); v.Lines != 6 || !v.Ended || !v.Anchored || v.TornBytes != 0 {
		t.Fatalf("verify: %+v", v)
	}
	if n := launcherLostGaps(t, dir); n != 1 {
		t.Fatalf("%d launcher-lost gaps, want 1", n)
	}
}

// TestOnlyAnOrphanedCloseWritesTheGap: a run that ended by any other reason kept its own writer to the end.
func TestOnlyAnOrphanedCloseWritesTheGap(t *testing.T) {
	for _, reason := range []string{record.RunEndExit, record.RunEndSignal, record.RunEndStopped, record.RunEndLimit} {
		t.Run(reason, func(t *testing.T) {
			w, dir, _ := openTestWriter(t)
			startRun(t, w, 1)
			if err := w.Close(record.RunEndPayload{Reason: reason}); err != nil {
				t.Fatal(err)
			}
			if n := launcherLostGaps(t, dir); n != 0 {
				t.Fatalf("%d launcher-lost gaps on a run that ended %s", n, reason)
			}
		})
	}
}

// TestOrphanedCloseRefusedRunEndOneGap: a Close whose run_end is refused leaves the Writer open for a Close it can
// write, and the gap the first Close wrote is not written again.
func TestOrphanedCloseRefusedRunEndOneGap(t *testing.T) {
	w, dir, anchor := openTestWriter(t)
	startRun(t, w, 1)
	err := w.Close(record.RunEndPayload{Reason: record.RunEndOrphaned, StoppedBy: "not on a run_end of this reason"})
	if !errors.Is(err, record.ErrInvalidEvent) {
		t.Fatalf("Close: %v, want ErrInvalidEvent", err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndOrphaned}); err != nil {
		t.Fatal(err)
	}
	if n := launcherLostGaps(t, dir); n != 1 {
		t.Fatalf("%d launcher-lost gaps, want 1", n)
	}
	verify(t, dir, anchor)
}

// TestOrphanedCloseGapNotWrittenLeavesTheRunLost: with no room for the gap there is no run_end either, whose line alone
// would say the record is whole. The lock is released, the run reads as lost, and the next sweep ends it with both.
func TestOrphanedCloseGapNotWrittenLeavesTheRunLost(t *testing.T) {
	w, dir, anchor := openTestWriter(t)
	startRun(t, w, 1)
	w.out = partialWriter{w.events, 0, syscall.ENOSPC}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndOrphaned}); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("Close: %v, want ENOSPC", err)
	}
	if s := stateOf(t, dir); s != StateLost {
		t.Fatalf("state %s, want lost", s)
	}
	w2, err := Open(dir, testRef, WithAnchor(anchor))
	if err != nil {
		t.Fatalf("lock must be released: %v", err)
	}
	if err := w2.Close(record.RunEndPayload{Reason: record.RunEndOrphaned}); err != nil {
		t.Fatal(err)
	}
	if n := launcherLostGaps(t, dir); n != 1 {
		t.Fatalf("%d launcher-lost gaps, want 1", n)
	}
}

// TestOrphanedCloseBeforeRunStartWritesNoGap: line 0 is run_start's, and a run with no lines has none to lose.
func TestOrphanedCloseBeforeRunStartWritesNoGap(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndOrphaned}); err != nil {
		t.Fatal(err)
	}
	if n := launcherLostGaps(t, dir); n != 0 {
		t.Fatalf("%d launcher-lost gaps before run_start", n)
	}
}

func TestResumeTornRunStartIsFresh(t *testing.T) {
	dir := filepath.Join(t.TempDir(), testRef.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, EventsFile), []byte(`{"v":1,"seq":0,"id":"`), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if w.Seq() != 0 {
		t.Fatalf("seq %d, want 0", w.Seq())
	}
	startRun(t, w, 0)
	_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
	if got := len(readAll(t, dir)); got != 2 {
		t.Fatalf("lines %d", got)
	}
}

func TestResumeCorruptLedgerFails(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 2)
	w.release()
	b, _ := os.ReadFile(filepath.Join(dir, EventsFile))
	b = bytes.Replace(b, []byte(`"why":"e0"`), []byte(`"why":"e9"`), 1)
	if err := os.WriteFile(filepath.Join(dir, EventsFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, testRef); !errors.Is(err, record.ErrIDMismatch) {
		t.Fatalf("resume over a tampered line: %v", err)
	}
	if _, err := Open(dir, testRef); errors.Is(err, ErrRunLocked) {
		t.Fatal("lock must be released when Open fails")
	}
}

func TestDefaultAnchorPath(t *testing.T) {
	if got := DefaultAnchorPath("/home/u/.tego/runs/" + testRef.ID); got != "/home/u/.tego/chain.log" {
		t.Fatalf("DefaultAnchorPath = %s", got)
	}
	if !strings.HasSuffix(DefaultAnchorPath("runs/"+testRef.ID+"/"), ChainLogFile) {
		t.Fatal("relative run dir")
	}
}

func TestSystemClock(t *testing.T) {
	var c SystemClock
	a := c.Mono()
	if a == 0 {
		t.Fatal("CLOCK_MONOTONIC read 0")
	}
	time.Sleep(time.Millisecond)
	if b := c.Mono(); b <= a {
		t.Fatalf("not monotonic: %d then %d", a, b)
	}
	if c.Now().IsZero() {
		t.Fatal("zero wall clock")
	}
}

func BenchmarkAppend(b *testing.B) {
	dir := filepath.Join(b.TempDir(), testRef.ID)
	w, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	if err != nil {
		b.Fatal(err)
	}
	if err := w.WriteRunStart(startPayload()); err != nil {
		b.Fatal(err)
	}
	e := fsEvent("/home/u/proj/out/report.md", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := w.Append(e); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
}

// BenchmarkAppendRefused is Append of a refused line, with and without the run-readable mirror. Before
// last-refusal.json was written off Append's path each one cost a
// create/write/rename per copy under the Writer's lock: 80-150 µs on tmpfs, 260 µs with the mirror on ext4,
// against BenchmarkAppend's 8 µs.
func BenchmarkAppendRefused(b *testing.B) {
	for _, mirror := range []bool{false, true} {
		b.Run("mirror="+strconv.FormatBool(mirror), func(b *testing.B) {
			dir := filepath.Join(b.TempDir(), testRef.ID)
			w, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
			if err != nil {
				b.Fatal(err)
			}
			if mirror {
				if err := w.MirrorLastRefusal(b.TempDir()); err != nil {
					b.Fatal(err)
				}
			}
			if err := w.WriteRunStart(startPayload()); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if err := w.Append(refusedEvent("/home/u/.ssh/id_ed25519")); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
		})
	}
}

// BenchmarkRefusalFlood is Append's time per line while an agent refuses as fast as it can: distinct refused
// lines back to back, with the run-readable mirror, so the coalesced last-refusal.json writes run on their own
// timer while Append goes on. It is the measure for what post() may add to Append's path (ADR 0061: the ring of
// recent refusals is filled there, under the refusal lock, with no file I/O).
func BenchmarkRefusalFlood(b *testing.B) {
	dir := filepath.Join(b.TempDir(), testRef.ID)
	w, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	if err != nil {
		b.Fatal(err)
	}
	if err := w.MirrorLastRefusal(b.TempDir()); err != nil {
		b.Fatal(err)
	}
	if err := w.WriteRunStart(startPayload()); err != nil {
		b.Fatal(err)
	}
	events := make([]*record.Event, 64)
	for i := range events {
		events[i] = refusedEvent(fmt.Sprintf("/home/u/proj/.env.%02d", i))
	}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		if err := w.Append(events[i%len(events)]); err != nil {
			b.Fatal(err)
		}
		i++
	}
	b.StopTimer()
	_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
}

// BenchmarkRefusalHostileTarget is Append of a refused line whose target the agent made expensive to encode, with
// the run-readable mirror: pathmax is a path within PATH_MAX made of control bytes (4093 of them after "/t/"), each
// escaped as six bytes, so the payload is about 24 KiB; long is a 64 KiB target of them, past any ring slot. Neither
// may cost Append more than its line's own encoding and write: post() copies the payload and never decodes it.
func BenchmarkRefusalHostileTarget(b *testing.B) {
	for _, c := range []struct {
		name string
		n    int
	}{{"pathmax", 4093}, {"long", 64 << 10}} {
		b.Run(c.name, func(b *testing.B) {
			dir := filepath.Join(b.TempDir(), testRef.ID)
			w, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
			if err != nil {
				b.Fatal(err)
			}
			if err := w.MirrorLastRefusal(b.TempDir()); err != nil {
				b.Fatal(err)
			}
			if err := w.WriteRunStart(startPayload()); err != nil {
				b.Fatal(err)
			}
			e := refusedEvent("/t/" + strings.Repeat("\x01", c.n))
			b.ReportAllocs()
			for b.Loop() {
				if err := w.Append(e); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
		})
	}
}

// Resume must validate the same whole-run invariants as Reader.Verify before
// changing any byte or allowing Close to anchor the recovered prefix.
func TestResumeRequiresValidOwnRun(t *testing.T) {
	for _, name := range []string{"foreign-run", "gap-first", "repeated-start", "invalid-source", "valid-own-run"} {
		for _, tail := range []string{"terminated", "unterminated", "torn-tail"} {
			t.Run(name+"/"+tail, func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), testRef.ID)
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				ref := testRef
				if name == "foreign-run" {
					ref.ID = runID(fixedStart, "other1")
				}
				start := &record.Event{Kind: record.KindRunStart, Source: record.SourceSupervisor}
				if err := start.SetPayload(startPayload()); err != nil {
					t.Fatal(err)
				}
				evs := []*record.Event{start, gapEvent("prefix")}
				if name == "gap-first" {
					evs = []*record.Event{gapEvent("no-start")}
				}
				if name == "repeated-start" {
					copyStart := *start
					evs = []*record.Event{start, &copyStart}
				}
				var data []byte
				prev := ""
				for i, e := range evs {
					e.V, e.Run, e.Agent, e.Seq, e.Prev, e.TS = record.Version, ref.ID, ref.Agent, uint64(i), prev, fixedStart
					line, err := e.MarshalLine()
					if err != nil {
						t.Fatal(err)
					}
					if name == "invalid-source" && i == 1 {
						line = bytes.Replace(line, []byte(`"source":"supervisor"`), []byte(`"source":"bogus"`), 1)
						zero := bytes.Replace(line, []byte(e.ID), []byte(record.ZeroID), 1)
						sum := sha256.Sum256(zero)
						line = bytes.Replace(line, []byte(e.ID), []byte(hex.EncodeToString(sum[:])), 1)
					}
					prev = e.ID
					data = append(data, line...)
					data = append(data, '\n')
				}
				if tail == "unterminated" {
					data = bytes.TrimSuffix(data, []byte("\n"))
				}
				if tail == "torn-tail" {
					data = append(data, []byte(`{"v":1,"seq":`)...)
				}
				path := filepath.Join(dir, EventsFile)
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
				anchor := &memAnchor{}
				w, err := Open(dir, testRef, WithAnchor(anchor))
				if name == "valid-own-run" {
					if err != nil {
						t.Fatalf("valid own prefix rejected: %v", err)
					}
					if err := w.Close(record.RunEndPayload{Reason: record.RunEndOrphaned}); err != nil {
						t.Fatal(err)
					}
					rep := verify(t, dir, anchor)
					if !rep.Ended || !rep.Anchored {
						t.Fatalf("valid resumed run: %+v", rep)
					}
					return
				}
				if !errors.Is(err, ErrUnverified) {
					t.Errorf("invalid prefix error=%v, want ErrUnverified", err)
				}
				if name == "foreign-run" && !errors.Is(err, ErrRunMismatch) {
					t.Errorf("foreign prefix error=%v, want ErrRunMismatch", err)
				}
				if name == "invalid-source" && !errors.Is(err, record.ErrInvalidEvent) {
					t.Errorf("invalid event error=%v, want record.ErrInvalidEvent", err)
				}
				if err == nil {
					cerr := w.Close(record.RunEndPayload{Reason: record.RunEndOrphaned})
					t.Errorf("invalid prefix accepted for resume; Close=%v", cerr)
				}
				after, rerr := os.ReadFile(path)
				if rerr != nil {
					t.Fatal(rerr)
				}
				if !bytes.Equal(after, data) {
					t.Error("invalid prefix was appended/altered")
				}
				if h, ok, aerr := anchor.Head(testRef.ID); aerr != nil || ok {
					t.Errorf("invalid run acquired anchor: %q %v %v", h, ok, aerr)
				}
				if w2, lerr := Open(dir, testRef, WithAnchor(&memAnchor{})); errors.Is(lerr, ErrRunLocked) {
					t.Error("failed resume retained lock")
				} else if lerr == nil {
					_ = w2.Abandon()
				}
			})
		}
	}
}
