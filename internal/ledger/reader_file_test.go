// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

func TestOpenReaderFilesKeepsPinnedFiles(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	defer func() { _ = w.Close(record.RunEndPayload{Reason: record.RunEndExit}) }()
	if err := w.WriteRunStart(startPayload()); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(dir, EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := os.Rename(filepath.Join(dir, EventsFile), filepath.Join(dir, "pinned-events")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(dir, EventsFile), 0600); err != nil {
		t.Fatal(err)
	}
	lock, err := os.Open(filepath.Join(dir, LockFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := os.Rename(filepath.Join(dir, LockFile), filepath.Join(dir, "pinned-lock")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(dir, LockFile), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenReaderFiles(f, lock, dir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := r.State()
	if err != nil || state != StateRunning {
		t.Fatalf("pinned state = %q %v", state, err)
	}
	if err := w.Abandon(); err != nil {
		t.Fatal(err)
	}
	if state, err := r.State(); err != nil || state != StateLost {
		t.Fatalf("lock was not probed again: %s %v", state, err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Stat(); err != nil {
		t.Fatalf("reader closed borrowed events: %v", err)
	}
	if _, err := lock.Stat(); err != nil {
		t.Fatalf("reader closed borrowed lock: %v", err)
	}
	pipe, out, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pipe.Close(); _ = out.Close() }()
	if r, err := OpenReaderFiles(pipe, lock, dir); err == nil {
		_ = r.Close()
		t.Fatal("supplied pipe accepted as events")
	}
	if r, err := OpenReaderFiles(f, pipe, dir); err == nil {
		_ = r.Close()
		t.Fatal("supplied pipe accepted as lock")
	}
	if r, err := OpenReaderFiles(nil, lock, dir); err == nil {
		_ = r.Close()
		t.Fatal("nil events accepted")
	}
	if r, err := OpenReaderFiles(f, nil, dir); err == nil {
		_ = r.Close()
		t.Fatal("nil lock accepted")
	}
}
