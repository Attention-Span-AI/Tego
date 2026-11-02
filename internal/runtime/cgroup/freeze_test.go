// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeFreezer is a scope directory with the two files the freezer uses, as a fake root holds them.
func fakeFreezer(t *testing.T, frozen string) Cgroup {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{fileFreeze: "0\n", fileEvents: "populated 1\nfrozen " + frozen + "\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return Cgroup{Path: dir}
}

// TestFreezeWritesTheControlFile: on writes "1", off writes "0", and a scope with no cgroup.freeze says why.
func TestFreezeWritesTheControlFile(t *testing.T) {
	c := fakeFreezer(t, "0")
	for _, tc := range []struct {
		on   bool
		want string
	}{{true, "1"}, {false, "0"}} {
		if err := Freeze(c, tc.on); err != nil {
			t.Fatalf("Freeze(%v) = %v", tc.on, err)
		}
		b, err := os.ReadFile(filepath.Join(c.Path, fileFreeze))
		if err != nil || string(b[:1]) != tc.want {
			t.Fatalf("after Freeze(%v), cgroup.freeze = %q, %v; want %q", tc.on, b, err, tc.want)
		}
	}
	gone := Cgroup{Path: filepath.Join(t.TempDir(), "run-x.scope")}
	if err := Freeze(gone, true); err == nil {
		t.Fatal("Freeze of a missing scope succeeded")
	}
}

// TestWaitFrozen: the asked state already reached returns at once, one reached later wakes the wait, and one never
// reached is ErrNotFrozen after FreezeWait.
func TestWaitFrozen(t *testing.T) {
	ctx := context.Background()
	c := fakeFreezer(t, "1")
	if err := WaitFrozen(ctx, c, true); err != nil {
		t.Fatalf("WaitFrozen of a frozen scope = %v", err)
	}
	if f, err := Frozen(c); err != nil || !f {
		t.Fatalf("Frozen = %v, %v", f, err)
	}

	c = fakeFreezer(t, "0")
	go func() {
		time.Sleep(50 * time.Millisecond)
		// Overwritten in place, not by os.WriteFile: its truncate wakes the watcher on an empty file, which reads
		// as "no frozen line" (a gate flake on 2026-10-27). The kernel's cgroup.events is never seen half written.
		f, err := os.OpenFile(filepath.Join(c.Path, fileEvents), os.O_WRONLY, 0)
		if err != nil {
			return
		}
		// Same length as the "frozen 0" body, so only one byte changes; a failed write fails the WaitFrozen below.
		_, _ = f.WriteAt([]byte("populated 1\nfrozen 1\n"), 0)
		_ = f.Close()
	}()
	if err := WaitFrozen(ctx, c, true); err != nil {
		t.Fatalf("WaitFrozen of a scope that freezes later = %v", err)
	}

	c = fakeFreezer(t, "1")
	start := time.Now()
	if err := WaitFrozen(ctx, c, false); !errors.Is(err, ErrNotFrozen) {
		t.Fatalf("WaitFrozen of a scope that never thaws = %v, want ErrNotFrozen", err)
	}
	if d := time.Since(start); d < FreezeWait || d > FreezeWait+2*time.Second {
		t.Fatalf("WaitFrozen gave up after %s, want about %s", d, FreezeWait)
	}

	if err := os.WriteFile(filepath.Join(c.Path, fileEvents), []byte("populated 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WaitFrozen(ctx, c, true); err == nil {
		t.Fatal("WaitFrozen of a cgroup.events with no frozen line succeeded")
	}
}
