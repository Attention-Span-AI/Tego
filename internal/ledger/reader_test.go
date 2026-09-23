// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestReaderTornAndCorrupt(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 3)
	full, _ := os.ReadFile(filepath.Join(dir, EventsFile))
	lines := bytes.Split(bytes.TrimSuffix(full, []byte("\n")), []byte("\n"))
	half := lines[3][:len(lines[3])/2]
	tests := []struct {
		name    string
		content []byte
		want    int
		err     error
	}{
		{"complete", full, 4, nil},
		{"empty file", nil, 0, nil},
		{"torn tail", append(append([]byte{}, full...), half...), 4, nil},
		{"unterminated but complete tail", bytes.TrimSuffix(full, []byte("\n")), 4, nil},
		{"torn mid-file", bytes.Join([][]byte{lines[0], half, lines[2], lines[3], nil}, []byte("\n")), 1, ErrCorruptLedger},
		{"unknown key", bytes.Replace(full, []byte(`"why":"e0"`), []byte(`"why":"e0","zzz":[1]`), 1), 4, nil},
		{"v2 line", bytes.Replace(full, []byte(`{"v":1,"seq":2`), []byte(`{"v":2,"seq":2`), 1), 2, ErrUnsupportedVersion},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := t.TempDir()
			if err := os.WriteFile(filepath.Join(d, EventsFile), tc.content, 0o600); err != nil {
				t.Fatal(err)
			}
			r, err := OpenReader(d)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			n := 0
			var got error
			for _, err := range r.Iter() {
				if err != nil {
					got = err
					break
				}
				n++
			}
			if n != tc.want || !errors.Is(got, tc.err) {
				t.Fatalf("n=%d err=%v, want %d %v", n, got, tc.want, tc.err)
			}
			if tc.err != nil && !errors.Is(got, ErrCorruptLedger) {
				t.Fatalf("every mid-file failure wraps ErrCorruptLedger: %v", got)
			}
			// Lines yields the same count, byte for byte what was stored.
			m := 0
			for line, err := range r.Lines() {
				if err != nil {
					t.Fatal(err)
				}
				if m < len(lines) && !bytes.Equal(line, lines[m]) && tc.name == "complete" {
					t.Fatalf("line %d differs", m)
				}
				m++
			}
			if tc.err == nil && m != tc.want {
				t.Fatalf("Lines n=%d", m)
			}
		})
	}
	_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
}

func TestReaderMissingLedger(t *testing.T) {
	if _, err := OpenReader(t.TempDir()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v", err)
	}
}

// Also pins record-ledger.md E14, E27: an open before run_start reads an empty file; a run with no lock file
// is free.
func TestReaderStates(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	if s := stateOf(t, dir); s != StateRunning {
		t.Fatalf("locked, no lines: %s, want running", s)
	}
	startRun(t, w, 1)
	if s := stateOf(t, dir); s != StateRunning {
		t.Fatalf("live: %s", s)
	}
	w.release() // process death without run_end
	if s := stateOf(t, dir); s != StateLost {
		t.Fatalf("dead without run_end: %s, want lost", s)
	}
	r, _ := OpenReader(dir)
	if lost, err := r.Lost(); !lost || err != nil {
		t.Fatalf("Lost = %v %v", lost, err)
	}
	_ = r.Close()
	// E27: no lock file at all is free.
	_ = os.Remove(filepath.Join(dir, LockFile))
	if s := stateOf(t, dir); s != StateLost {
		t.Fatalf("no lock file: %s", s)
	}
	// An empty ledger with a free lock is empty, not lost.
	empty := t.TempDir()
	_ = os.WriteFile(filepath.Join(empty, EventsFile), nil, 0o600)
	if s := stateOf(t, empty); s != StateEmpty {
		t.Fatalf("empty: %s", s)
	}
	w2, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	_ = w2.Close(record.RunEndPayload{Reason: record.RunEndOrphaned})
	if s := stateOf(t, dir); s != StateEnded {
		t.Fatalf("ended: %s", s)
	}
}

// TestReadWhileWrite is record-ledger.md E13: an Iter at EOF on a line boundary yields cleanly, and a fresh Iter
// after the writer appends sees the new lines.
func TestReadWhileWrite(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 2)
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	count := func() int {
		n := 0
		for _, err := range r.Iter() {
			if err != nil {
				t.Fatal(err)
			}
			n++
		}
		return n
	}
	if count() != 3 {
		t.Fatal("first pass")
	}
	_ = w.Append(gapEvent("more"))
	if count() != 4 {
		t.Fatal("a fresh Iter sees the new line (E13)")
	}
	_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
	if count() != 5 {
		t.Fatal("after close")
	}
}

func TestVerifyCancellation(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 5)
	_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
	r, _ := OpenReader(dir)
	defer r.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Verify(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	rep, err := r.Verify(context.Background(), nil)
	if err != nil || rep.Lines != 7 {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestVerifyReportsTornTail(t *testing.T) {
	w, dir, anchor := openTestWriter(t)
	startRun(t, w, 1)
	_, _ = w.events.Write([]byte(`{"v":1,"seq":2,"id":"`))
	w.release()
	rep := verify(t, dir, anchor)
	if rep.Lines != 2 || rep.TornBytes != 21 || rep.Ended {
		t.Fatalf("%+v", rep)
	}
}

// TestVerifyDetectsChainBreak proves I3 on the read side specifically. TestResumeCorruptLedgerFails (in
// writer_test.go) already covers the writer's own resume() catching a byte-tamper, where the stored id no
// longer matches its line's bytes (ErrIDMismatch). This covers the independent path: Reader.Verify, the
// function the doc names as I3's enforcement ("Reader-side verification"), used by verification tooling that
// never goes through a Writer at all. The injected line here is self-consistent -- its id really is the sha256
// of its own bytes -- but its prev names no real previous line, as a spliced-in or replayed line would. Only
// the prev/head chain check can catch that, not a hash check.
func TestVerifyDetectsChainBreak(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 1) // run_start (seq 0), one gap (seq 1)
	w.release()       // no run_end: leave the file exactly as written above

	rogue := gapEvent("rogue")
	rogue.V, rogue.Run, rogue.Agent = record.Version, testRef.ID, testRef.Agent
	rogue.Seq, rogue.Prev, rogue.TS = 2, strings.Repeat("f", 64), fixedStart.Add(time.Hour)
	line, err := rogue.MarshalLine() // self-consistent: id is computed from exactly these bytes
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, EventsFile), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if _, err := r.Verify(context.Background(), nil); !errors.Is(err, ErrCorruptChain) {
		t.Fatalf("Verify over a spliced-in line: %v, want ErrCorruptChain", err)
	} else if errors.Is(err, record.ErrIDMismatch) {
		t.Fatalf("this line's id is self-consistent; the break is in prev, not the hash: %v", err)
	}
}

// Also pins record-ledger.md E28: a torn last line of chain.log is skipped.
func TestFileChainAnchor(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".tego", ChainLogFile)
	a := NewFileChainAnchor(path)
	if _, ok, err := a.Head(testRef.ID); ok || err != nil {
		t.Fatalf("empty anchor: %v %v", ok, err)
	}
	head := strings.Repeat("ab", 32)
	if err := a.Append(testRef.ID, head); err != nil {
		t.Fatal(err)
	}
	if got := fileMode(t, path); got != 0o600 {
		t.Errorf("chain.log mode %o", got)
	}
	other := runID(fixedStart.Add(time.Minute), "zz9zz9")
	if err := a.Append(other, strings.Repeat("cd", 32)); err != nil {
		t.Fatal(err)
	}
	if err := a.Append("bad id", head); err == nil {
		t.Fatal("bad run id accepted")
	}
	// E28: a torn last line is skipped.
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	_, _ = f.WriteString(other + " " + strings.Repeat("ef", 3))
	_ = f.Close()
	h, ok, err := a.Head(testRef.ID)
	if err != nil || !ok || h != head {
		t.Fatalf("Head = %q %v %v", h, ok, err)
	}
	if h, ok, _ := a.Head(other); !ok || h != strings.Repeat("cd", 32) {
		t.Fatalf("other head %q %v", h, ok)
	}
	b, _ := os.ReadFile(path)
	if lines := strings.Count(string(b), "\n"); lines != 2 {
		t.Fatalf("chain.log lines %d: %q", lines, b)
	}
	// A run is anchored once: the same line again is the same anchor, and a second line with another head is a
	// re-anchor, reported rather than letting the last line win.
	if err := a.Append(testRef.ID, head); err != nil {
		t.Fatal(err)
	}
	if h, ok, err := a.Head(testRef.ID); err != nil || !ok || h != head {
		t.Fatalf("a repeated line: Head = %q %v %v", h, ok, err)
	}
	if err := a.Append(testRef.ID, strings.Repeat("99", 32)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Head(testRef.ID); !errors.Is(err, ErrCorruptLedger) {
		t.Fatalf("two heads for one run: %v, want ErrCorruptLedger", err)
	}
	if h, ok, err := a.Head(other); err != nil || !ok || h != strings.Repeat("cd", 32) {
		t.Fatalf("another run's head beside them: %q %v %v", h, ok, err)
	}
	// A malformed terminated line is a hard error.
	_ = os.WriteFile(path, []byte("garbage\n"), 0o600)
	if _, _, err := a.Head(testRef.ID); !errors.Is(err, ErrCorruptLedger) {
		t.Fatalf("garbage: %v", err)
	}
}

func BenchmarkIterFullRun(b *testing.B) {
	dir := filepath.Join(b.TempDir(), testRef.ID)
	w, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	if err != nil {
		b.Fatal(err)
	}
	_ = w.WriteRunStart(startPayload())
	for i := 0; i < 10_000; i++ {
		if err := w.Append(fsEvent("/home/u/proj/out/report.md", nil)); err != nil {
			b.Fatal(err)
		}
	}
	_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
	r, err := OpenReader(dir)
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n := 0
		for _, err := range r.Iter() {
			if err != nil {
				b.Fatal(err)
			}
			n++
		}
		if n != 10_002 {
			b.Fatal(n)
		}
	}
}
