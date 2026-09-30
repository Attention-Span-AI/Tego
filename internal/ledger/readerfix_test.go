// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestVerifyWhollyNewerLedgerStartsAndEnds: a newer run_start at seq 0 is the run record's start and a newer
// run_end is its end, so a v1 line after it is flagged.
func TestVerifyWhollyNewerLedgerStartsAndEnds(t *testing.T) {
	// A ledger of one newer run_start and nothing else.
	w, dir, _ := openTestWriter(t)
	w.release()
	l := `{"v":2,"seq":0,"id":"` + record.ZeroID + `","prev":"","run":"` + testRef.ID + `","kind":"run_start","ts":"2031-01-01T00:00:00Z"}`
	sum := sha256.Sum256([]byte(l))
	l = strings.Replace(l, record.ZeroID, hex.EncodeToString(sum[:]), 1)
	if err := os.WriteFile(filepath.Join(dir, EventsFile), []byte(l+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := r.Verify(context.Background(), nil)
	_ = r.Close()
	if err != nil || !rep.Started {
		t.Fatalf("a newer run_start at seq 0: rep %+v err %v, want Started", rep, err)
	}

	dir = plainClosedRun(t)
	// Before the v1 run_end: start, gap, gap.
	spliceVersionLine(t, dir, 3, "2", `"run":"`+testRef.ID+`","kind":"run_end","ts":"2031-01-01T00:00:00Z"`)
	r, err = OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Verify(context.Background(), nil); !errors.Is(err, ErrUnverified) {
		t.Fatalf("a v1 line after a newer run_end: err %v, want ErrUnverified", err)
	}
}

func plainClosedRun(t *testing.T) string {
	t.Helper()
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 2)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestSweepEmptyHoldsTheRunLockAcrossTheHook: a launcher between MakeRunDir and its first line reads empty, so
// the hook that may kill its scope runs under the run's lock, and a run whose lock is held is left alone.
func TestSweepEmptyHoldsTheRunLockAcrossTheHook(t *testing.T) {
	w, dir, _ := openTestWriter(t, WithContract([]byte("version: 0\nname: early-agent\ncommand: [\"/bin/true\"]\n")))
	w.release() // no line, lock free
	w.closeDirs()
	root := filepath.Dir(dir)
	var locked []bool
	hook := WithSweepHook(func(context.Context, sys.Lender, record.RunRef) error {
		held, err := LockHeld(dir)
		locked = append(locked, held && err == nil)
		return nil
	})
	keep := 100 * 365 * 24 * time.Hour
	now := WithNow(func() time.Time { return fixedStart })
	if _, err := GC(context.Background(), root, keep, false, hook, now); err != nil {
		t.Fatal(err)
	}
	if len(locked) != 1 || !locked[0] {
		t.Fatalf("hook ran with lock held = %v, want once, held", locked)
	}
	d, err := openDir(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	held, unlock, err := tryLockAt(d, dir)
	if err != nil || held {
		t.Fatalf("lock not released: %v %v", held, err)
	}
	defer unlock()
	locked = nil
	if _, err := GC(context.Background(), root, keep, false, hook, now); err != nil {
		t.Fatal(err)
	}
	if len(locked) != 0 {
		t.Fatal("the hook ran on a run whose lock is held")
	}
}

// TestVerifyRunDirSwappedLedgerIsAFinding: an anchored run whose events.jsonl became a link, a FIFO or a
// directory is the record's substitution (ErrUnverified, exit 1), not a read failure.
func TestVerifyRunDirSwappedLedgerIsAFinding(t *testing.T) {
	for name, swap := range map[string]func(p string) error{
		"symlink": func(p string) error { return os.Symlink("/etc/hostname", p) },
		"fifo":    func(p string) error { return syscall.Mkfifo(p, 0o600) },
		"dir":     func(p string) error { return os.Mkdir(p, 0o700) },
	} {
		t.Run(name, func(t *testing.T) {
			w, dir, anchor := openTestWriter(t)
			startRun(t, w, 1)
			if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, EventsFile)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := swap(p); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyRunDir(context.Background(), dir, anchor); !errors.Is(err, ErrUnverified) {
				t.Fatalf("err = %v, want ErrUnverified", err)
			}
		})
	}
}
