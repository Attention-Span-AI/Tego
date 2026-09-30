// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// swapLedgerRoot is what a user who owns the ledger root's parent can do to a live run (record-ledger.md
// §3): move the ledger root aside and put a link in its place to a tree of their own, where the run's
// name holds blobs/ as a link to victim. It returns where the run's own directory went.
func swapLedgerRoot(t *testing.T, runDir, victim string) (moved string) {
	t.Helper()
	root := filepath.Dir(runDir)
	aside := root + ".old"
	if err := os.Rename(root, aside); err != nil {
		t.Fatal(err)
	}
	evil := filepath.Join(filepath.Dir(root), "evil")
	if err := os.MkdirAll(filepath.Join(evil, filepath.Base(runDir)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(evil, filepath.Base(runDir), BlobsDir)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(evil, root); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(aside, filepath.Base(runDir))
}

// TestAWriterWritesWhereItOpened: every file a Writer writes after Open — a blob, last-refusal.json, the
// lock file's holder line, events.jsonl — lands in the run directory Open opened, although the ledger root
// was replaced meanwhile by a link to a tree where the run's blobs/ is a link to another directory. By
// path, the next blob was created in the link's target: as root, a file root owns in any directory the
// user names, holding bytes the agent's traffic chose (reproduced as root in the KVM guest).
func TestAWriterWritesWhereItOpened(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 0)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	moved := swapLedgerRoot(t, dir, victim)

	body := bytes.Repeat([]byte("agent-chosen bytes "), 400)
	sha, err := w.Blob(body)
	if err != nil {
		t.Fatalf("Blob: %v", err)
	}
	if _, _, err := w.BlobFrom(strings.NewReader("streamed")); err != nil {
		t.Fatalf("BlobFrom: %v", err)
	}
	refused := &record.Event{Kind: record.KindRefused, Source: record.SourceLandlock, PID: 5, TID: 5}
	_ = refused.SetPayload(record.RefusedPayload{Op: "open", Target: "/etc/shadow", Reason: record.ReasonReadDenied,
		Rule: "fs.deny_read[/etc]"})
	if err := w.Append(refused); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteLockInfo([]byte("1 2\n")); err != nil {
		t.Fatalf("WriteLockInfo: %v", err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if entries, _ := os.ReadDir(victim); len(entries) != 0 {
		t.Fatalf("the writer followed the swapped path into the link's target: %v", entries)
	}
	if b, err := os.ReadFile(filepath.Join(moved, BlobsDir, sha)); err != nil || !bytes.Equal(b, body) {
		t.Fatalf("the blob is not in the run directory the writer opened: %v", err)
	}
	for _, name := range []string{LastRefusalFile, LockFile} {
		if _, err := os.Stat(filepath.Join(moved, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(moved, LockFile)); string(b) != "1 2\n" {
		t.Errorf("lock file holds %q, want the holder line written through the flocked descriptor", b)
	}
	lines := readAll(t, moved)
	if n := len(lines); n != 3 || lines[n-1].Kind != record.KindRunEnd {
		t.Fatalf("events.jsonl in the opened directory has %d lines", n)
	}
}

// TestWriteLockInfoReplacesTheContent: the holder line replaces whatever the lock file held, through the
// descriptor that holds the flock, and the lock is still held afterwards.
func TestWriteLockInfoReplacesTheContent(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	for _, line := range []string{"123456 99999999999\n", "7 8\n"} {
		if err := w.WriteLockInfo([]byte(line)); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, LockFile)); string(b) != line {
			t.Fatalf("lock file %q, want %q", b, line)
		}
	}
	if free, err := lockFree(filepath.Join(dir, LockFile)); err != nil || free {
		t.Fatalf("after WriteLockInfo the lock is free=%v (%v)", free, err)
	}
	_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
	if err := w.WriteLockInfo([]byte("1 2\n")); !errors.Is(err, ErrClosed) {
		t.Fatalf("after Close: %v, want ErrClosed", err)
	}
}

// TestFreshRunDirRefusesADirectoryItDidNotMake: WithFreshRunDir opens the directory MakeRunDir just made
// and nothing else — a run directory that already holds something was not made by this launch, whoever
// put it there, and is refused with os.ErrExist before anything is written into it.
func TestFreshRunDirRefusesADirectoryItDidNotMake(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	if err := MakeRunDir(root, testRef.ID); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, testRef.ID)
	w, err := Open(dir, testRef, WithAnchor(&memAnchor{}), WithFreshRunDir())
	if err != nil {
		t.Fatalf("Open on the directory MakeRunDir made: %v", err)
	}
	_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})

	other := record.RunRef{ID: runID(fixedStart.Add(time.Second), "a1b2c3"), Agent: testRef.Agent}
	if err := MakeRunDir(root, other.ID); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(root, other.ID, EventsFile)
	if err := os.WriteFile(planted, []byte("planted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(root, other.ID), other, WithAnchor(&memAnchor{}), WithFreshRunDir()); !errors.Is(err, os.ErrExist) {
		t.Fatalf("Open on a run directory that already held a ledger: %v, want os.ErrExist", err)
	}
	if b, _ := os.ReadFile(planted); string(b) != "planted\n" {
		t.Fatalf("the refused directory was written: %q", b)
	}
}

// TestWriterRefusesALinkInItsRunDirectory: the files the Writer opens by name in its run directory are
// never reached through a symlink — a lock file or events.jsonl that is a link is refused (ErrLinkRefused)
// rather than flocked, truncated or appended to wherever it points.
func TestWriterRefusesALinkInItsRunDirectory(t *testing.T) {
	for _, name := range []string{LockFile, EventsFile} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "runs", testRef.ID)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(dir, testRef, WithAnchor(&memAnchor{})); !errors.Is(err, ErrLinkRefused) {
				t.Fatalf("Open with %s a symlink: %v, want ErrLinkRefused", name, err)
			}
			if st, _ := os.Stat(target); st.Size() != 0 {
				t.Fatalf("the link's target was written")
			}
		})
	}
}
