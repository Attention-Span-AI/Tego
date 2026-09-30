// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestTailAfterRunEndIsCorrupt: bytes after run_end that are not a record are a corrupt
// ledger to every reader, naming where they start, as Verify already says. A tail of NUL bytes was taken for
// a torn last line and dropped by Iter and Lines, so events, drift and measure read a clean end, while a
// `garbage\n` line in the same place failed them all. A torn tail on a run that has not ended is still what
// a writer that died mid-write(2) leaves, and is still dropped.
//
// Also pins runtime-launch.md I2: run_end is the last line of a run that has one.
func TestTailAfterRunEndIsCorrupt(t *testing.T) {
	ended := func(t *testing.T) (string, int64) {
		w, dir, _ := openTestWriter(t)
		if err := w.WriteRunStart(startPayload()); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(fsEvent("/work/a", nil)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(filepath.Join(dir, EventsFile))
		if err != nil {
			t.Fatal(err)
		}
		return dir, st.Size()
	}
	for _, tc := range []struct {
		name, tail string
		want       string // "" is a clean read
	}{
		{"NUL bytes", "\x00\x00\x00\x00", "4 bytes at byte offset %d after run_end are not a record"},
		{"a partial line", `{"v":1,"seq":3,"ki`, "18 bytes at byte offset %d after run_end are not a record"},
		{"a garbage line", "garbage\n", "corrupt line 4: at byte offset %d"},
		{"a NUL line", "\x00\x00\n", "corrupt line 4: at byte offset %d"},
		{"nothing", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, size := ended(t)
			f, err := os.OpenFile(filepath.Join(dir, EventsFile), os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString(tc.tail); err != nil {
				t.Fatal(err)
			}
			_ = f.Close()
			r, err := OpenReader(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close() }()
			var iterErr error
			n := 0
			for _, err := range r.Iter() {
				if err != nil {
					iterErr = err
					break
				}
				n++
			}
			var linesErr error
			for _, err := range r.Lines() {
				if err != nil {
					linesErr = err
					break
				}
			}
			if tc.want == "" {
				if iterErr != nil || linesErr != nil || n != 3 {
					t.Fatalf("clean ledger: %d events, iter %v, lines %v", n, iterErr, linesErr)
				}
				return
			}
			want := strings.Replace(tc.want, "%d", strconv.FormatInt(size, 10), 1)
			if !errors.Is(iterErr, ErrCorruptLedger) || !strings.Contains(iterErr.Error(), want) {
				t.Errorf("Iter: %v, want ErrCorruptLedger with %q", iterErr, want)
			}
			if !strings.HasSuffix(tc.tail, "\n") && (!errors.Is(linesErr, ErrCorruptLedger) || !strings.Contains(linesErr.Error(), want)) {
				t.Errorf("Lines: %v, want ErrCorruptLedger with %q", linesErr, want)
			}
			if _, err := r.Verify(context.Background(), nil); !errors.Is(err, ErrUnverified) {
				t.Errorf("Verify: %v, want ErrUnverified", err)
			} else if !strings.HasSuffix(tc.tail, "\n") && !strings.Contains(err.Error(), "at byte offset "+strconv.FormatInt(size, 10)) {
				t.Errorf("Verify: %v does not name offset %d", err, size)
			}
		})
	}

	t.Run("a torn tail on a run that has not ended", func(t *testing.T) {
		w, dir, _ := openTestWriter(t)
		if err := w.WriteRunStart(startPayload()); err != nil {
			t.Fatal(err)
		}
		tearTail(t, w)
		r, err := OpenReader(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Close() }()
		n := 0
		for _, err := range r.Iter() {
			if err != nil {
				t.Fatalf("Iter: %v", err)
			}
			n++
		}
		if n != 1 {
			t.Fatalf("%d events, want run_start alone", n)
		}
		_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
	})
}

// FuzzAppendVerify is the ledger's append→verify property: whatever the Writer appends, from any paths and
// any number of gaps, a closed ledger verifies against its anchor, and Iter returns every line. A path the
// Writer refuses is fine; a chain it corrupts is not.
func FuzzAppendVerify(f *testing.F) {
	f.Add([]byte("/work/a\x00/b\xff\xfe\n/\u202e\n"), uint8(3), true)
	f.Add([]byte(""), uint8(0), false)
	f.Add([]byte(strings.Repeat("/x\n", 40)), uint8(7), false)
	f.Add([]byte("\x00\x00\x00\x00"), uint8(1), true)
	f.Fuzz(func(t *testing.T, data []byte, gaps uint8, stop bool) {
		anchor := &memAnchor{}
		dir := filepath.Join(t.TempDir(), testRef.ID)
		w, err := Open(dir, testRef, WithClock(newStepClock(fixedStart, 5_000_000_000, time.Millisecond)), WithAnchor(anchor))
		if err != nil {
			t.Fatal(err)
		}
		if err := w.WriteRunStart(startPayload()); err != nil {
			t.Fatal(err)
		}
		n := 1
		for p := range bytes.SplitSeq(data, []byte("\n")) {
			if w.Append(fsEvent(string(p), nil)) == nil {
				n++
			}
		}
		for i := 0; i < int(gaps%8); i++ {
			if w.Append(gapEvent("channel-full")) == nil {
				n++
			}
		}
		reason := record.RunEndExit
		if stop {
			reason = record.RunEndStopped
		}
		if err := w.Close(record.RunEndPayload{Reason: reason}); err != nil {
			t.Fatal(err)
		}
		n++
		r, err := OpenReader(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Close() }()
		rep, err := r.Verify(context.Background(), anchor)
		if err != nil {
			t.Fatalf("a ledger the Writer closed does not verify: %v", err)
		}
		if rep.Lines != uint64(n) || !rep.Started || !rep.Ended || !rep.Anchored {
			t.Fatalf("report %+v, want %d lines, started, ended and anchored", rep, n)
		}
		got := 0
		for _, err := range r.Iter() {
			if err != nil {
				t.Fatalf("Iter: %v", err)
			}
			got++
		}
		if got != n {
			t.Fatalf("Iter returned %d lines, want %d", got, n)
		}
	})
}
