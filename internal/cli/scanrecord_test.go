// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/scan"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

func scanRecordedLive(ctx context.Context, root, id string, finished time.Time) bool {
	ok, _ := scanRecordProbe(ctx, root, id, finished)
	return ok
}

func scanTestRecordBytes(ctx context.Context, root, id string) ([]byte, error) {
	var b []byte
	err := scan.WithRecordBytes(ctx, root, id, uint32(os.Getuid()), func(_ sys.Lender, _ *os.File, readStart func() ([]byte, error)) error {
		var err error
		b, err = readStart()
		return err
	})
	return b, err
}

type scanClosingAnchor struct {
	entered chan struct{}
	release chan struct{}
}

func (a scanClosingAnchor) Append(string, string) error {
	close(a.entered)
	<-a.release
	return nil
}

func (scanClosingAnchor) Head(string) (string, bool, error) { return "", false, nil }

func TestScanRecordedLiveEndedWhileLockHeld(t *testing.T) {
	root := t.TempDir()
	a := scanClosingAnchor{entered: make(chan struct{}), release: make(chan struct{})}
	w, err := ledger.Open(filepath.Join(root, agentsRunID), record.RunRef{ID: agentsRunID, Agent: "a"}, ledger.WithAnchor(a))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Tier: "landlock", Capture: "forwarder", Command: []string{"private"}}); err != nil {
		_ = w.Abandon()
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- w.Close(record.RunEndPayload{Reason: "exit"}) }()
	<-a.entered
	defer func() {
		close(a.release)
		if err := <-closed; err != nil {
			t.Error(err)
		}
	}()
	if held, err := ledger.LockHeld(filepath.Join(root, agentsRunID)); err != nil || !held {
		t.Fatalf("fixture must hold writer lock after run_end: %t %v", held, err)
	}
	if scanRecordedLive(t.Context(), root, agentsRunID, time.Now()) {
		t.Fatal("ended record promoted while launcher still holds lock")
	}
}

func TestScanRecordProbeRefusals(t *testing.T) {
	for _, name := range []string{"oversized-start", "malformed-start", "symlink-directory", "symlink-events", "writable-events", "symlink-lock", "writable-lock", "hardlink-lock", "directory-lock", "missing-lock", "canceled"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, agentsRunID)
			w, err := ledger.Open(dir, record.RunRef{ID: agentsRunID, Agent: "a"})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = w.Abandon() }()
			if err := w.WriteRunStart(record.RunStartPayload{Tier: "landlock", Capture: "forwarder", Command: []string{"private"}}); err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			events := filepath.Join(dir, ledger.EventsFile)
			switch name {
			case "oversized-start":
				err = os.WriteFile(events, []byte(strings.Repeat(" ", 64<<10)+"\n"), 0600)
			case "malformed-start":
				err = os.WriteFile(events, []byte("{}\n"), 0600)
			case "symlink-directory":
				err = os.Rename(dir, dir+"-target")
				if err == nil {
					err = os.Symlink(dir+"-target", dir)
				}
			case "symlink-events":
				err = os.Rename(events, events+"-target")
				if err == nil {
					err = os.Symlink(events+"-target", events)
				}
			case "writable-events":
				err = os.Chmod(events, 0666)
			case "symlink-lock":
				lock := filepath.Join(dir, ledger.LockFile)
				err = os.Rename(lock, lock+"-target")
				if err == nil {
					err = os.Symlink(lock+"-target", lock)
				}
			case "writable-lock":
				err = os.Chmod(filepath.Join(dir, ledger.LockFile), 0666)
			case "hardlink-lock":
				err = os.Link(filepath.Join(dir, ledger.LockFile), filepath.Join(dir, "lock-copy"))
			case "directory-lock", "missing-lock":
				err = os.Remove(filepath.Join(dir, ledger.LockFile))
				if err == nil && name == "directory-lock" {
					err = os.Mkdir(filepath.Join(dir, ledger.LockFile), 0700)
				}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err != nil {
				t.Fatal(err)
			}
			if ok, reason := scanRecordProbe(ctx, root, agentsRunID, time.Now()); ok || reason == "none" {
				t.Fatalf("unsafe record promoted or unexplained: %t %q", ok, reason)
			}
		})
	}
}

func TestScanRecordBytesAllowsAppend(t *testing.T) {
	root := t.TempDir()
	w, err := ledger.Open(filepath.Join(root, agentsRunID), record.RunRef{ID: agentsRunID, Agent: "a"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close(record.RunEndPayload{Reason: "exit"}) }()
	if err := w.WriteRunStart(record.RunStartPayload{Tier: "landlock", Capture: "forwarder", Command: []string{"private"}}); err != nil {
		t.Fatal(err)
	}
	err = scan.WithRecordBytes(t.Context(), root, agentsRunID, uint32(os.Getuid()), func(_ sys.Lender, _ *os.File, readStart func() ([]byte, error)) error {
		if _, err := readStart(); err != nil {
			return err
		}
		e := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor, PID: 1, TID: 1}
		if err := e.SetPayload(record.GapPayload{What: record.GapRecord, Why: "appended during the probe"}); err != nil {
			return err
		}
		return w.Append(e)
	})
	if err != nil {
		t.Fatalf("normal live append refused: %v", err)
	}
}

func TestScanRecordBytesRejectsReplacedEvents(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, agentsRunID)
	w, err := ledger.Open(dir, record.RunRef{ID: agentsRunID, Agent: "a"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Abandon() }()
	if err := w.WriteRunStart(record.RunStartPayload{Tier: "landlock", Capture: "forwarder", Command: []string{"private"}}); err != nil {
		t.Fatal(err)
	}
	err = scan.WithRecordBytes(t.Context(), root, agentsRunID, uint32(os.Getuid()), func(at sys.Lender, events *os.File, readStart func() ([]byte, error)) error {
		if err := os.Rename(filepath.Join(dir, ledger.EventsFile), filepath.Join(dir, "pinned-events")); err != nil {
			return err
		}
		if err := unix.Mkfifo(filepath.Join(dir, ledger.EventsFile), 0600); err != nil {
			return err
		}
		return scan.WithRecordLock(t.Context(), at, uint32(os.Getuid()), func(lock *os.File) error {
			r, err := ledger.OpenReaderFiles(events, lock, dir)
			if err != nil {
				return err
			}
			defer func() { _ = r.Close() }()
			if state, err := r.State(); err != nil || state != ledger.StateRunning {
				t.Fatalf("probe did not use pinned file: %s %v", state, err)
			}
			_, err = readStart()
			return err
		})
	})
	if scan.RecordReadReason(err) != "changed" {
		t.Fatalf("replacement not refused: %v", err)
	}
}

func TestScanRecordedLiveLargeRecord(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, agentsRunID)
	w, err := ledger.Open(dir, record.RunRef{ID: agentsRunID, Agent: "a"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close(record.RunEndPayload{Reason: "exit"}) }()
	if err := w.WriteRunStart(record.RunStartPayload{Tier: "landlock", Capture: "forwarder", Command: []string{"private"}}); err != nil {
		t.Fatal(err)
	}
	for range 300 {
		e := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor, PID: 1, TID: 1}
		if err := e.SetPayload(record.GapPayload{What: record.GapRecord, Why: strings.Repeat("x", 4000)}); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	st, err := os.Stat(filepath.Join(dir, ledger.EventsFile))
	if err != nil || st.Size() <= 1<<20 {
		t.Fatalf("fixture must exceed old record cap: stat=%v err=%v", st, err)
	}
	start, err := scanTestRecordBytes(t.Context(), root, agentsRunID)
	if err != nil || len(start) > 64<<10 {
		t.Fatalf("bounded start read = %d bytes %v", len(start), err)
	}
	if !scanRecordedLive(t.Context(), root, agentsRunID, time.Now()) {
		t.Fatal("large live record not recognized")
	}
}

func TestScanRecordedLive(t *testing.T) {
	root := t.TempDir()
	id := agentsRunID
	if scanRecordedLive(t.Context(), root, id, time.Now()) {
		t.Fatal("missing record promoted")
	}
	w, err := ledger.Open(filepath.Join(root, id), record.RunRef{ID: id, Agent: "a"})
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = w.Close(record.RunEndPayload{Reason: "exit"})
		}
	}()
	if err := w.WriteRunStart(record.RunStartPayload{Tier: "landlock", Capture: "forwarder", Command: []string{"not retained"}}); err != nil {
		t.Fatal(err)
	}
	if !scanRecordedLive(t.Context(), root, id, time.Now()) {
		t.Fatal("live record not recognized")
	}
	if scanRecordedLive(t.Context(), root, id, time.Unix(0, 0)) {
		t.Fatal("future start promoted")
	}
	if scanRecordedLive(t.Context(), root, "../"+id, time.Now()) {
		t.Fatal("untyped id accepted")
	}
	if err := w.Close(record.RunEndPayload{Reason: "exit"}); err != nil {
		t.Fatal(err)
	}
	closed = true
	if scanRecordedLive(t.Context(), root, id, time.Now()) {
		t.Fatal("ended record promoted")
	}
	if err := os.Remove(filepath.Join(root, id, "lock")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestScanRecordProbeNeverDataOpensSpecialLock(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, agentsRunID)
	w, err := ledger.Open(dir, record.RunRef{ID: agentsRunID, Agent: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Tier: "landlock", Capture: "forwarder", Command: []string{"private"}}); err != nil {
		_ = w.Abandon()
		t.Fatal(err)
	}
	if err := w.Abandon(); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(dir, ledger.LockFile)
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(lock, 0600); err != nil {
		t.Fatal(err)
	}
	watch, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(watch) }()
	if _, err := unix.InotifyAddWatch(watch, lock, unix.IN_OPEN|unix.IN_ACCESS); err != nil {
		t.Fatal(err)
	}
	if ok, reason := scanRecordProbe(t.Context(), root, agentsRunID, time.Now()); ok || reason != "type" {
		t.Fatalf("special lock not refused by scan: %t %q", ok, reason)
	}
	var events [4096]byte
	n, err := unix.Read(watch, events[:])
	if n > 0 {
		t.Fatal("scan data-opened or read the lock FIFO")
	}
	if err != nil && !errors.Is(err, unix.EAGAIN) {
		t.Fatal(err)
	}
}

func TestScanRecordProbeUsesExplicitRecipient(t *testing.T) {
	root := t.TempDir()
	uid := uint32(os.Getuid())
	w, err := ledger.Open(filepath.Join(root, agentsRunID), record.RunRef{ID: agentsRunID, Agent: "a"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Abandon() }()
	if err = w.WriteRunStart(record.RunStartPayload{Tier: "landlock", Capture: "forwarder", Command: []string{scanCanary}}); err != nil {
		t.Fatal(err)
	}
	if ok, reason := scanRecordProbeFor(t.Context(), root, agentsRunID, time.Now(), uid); !ok {
		t.Fatalf("recipient record not checked: %s", reason)
	}
	if uid != 0 {
		if ok, reason := scanRecordProbeFor(t.Context(), root, agentsRunID, time.Now(), 0); ok || reason != "owner" {
			t.Fatalf("collector uid substituted for recipient: %t %s", ok, reason)
		}
	}
}
