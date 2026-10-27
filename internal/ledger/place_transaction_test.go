// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Publication is complete before the signal callback; its delivery failure
// removes only the new marker and retains the persistent serialization inode.
func TestPlaceNewFileThenDeliveryAndRollback(t *testing.T) {
	dir := t.TempDir()
	denied := errors.New("delivery denied")
	err := PlaceNewFileThen(t.Context(), dir, "stop.request", []byte("3s\n"), func(existing bool) error {
		b, err := os.ReadFile(filepath.Join(dir, "stop.request"))
		if existing || err != nil || string(b) != "3s\n" {
			t.Fatalf("callback existing=%v body=%q err=%v", existing, b, err)
		}
		return denied
	})
	if !errors.Is(err, denied) {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "stop.request")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new marker after rejected delivery: %v", err)
	}
	lock := filepath.Join(dir, ".stop.request.lock")
	first, err := os.Stat(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := PlaceNewFileThen(t.Context(), dir, "stop.request", []byte("8s\n"), func(existing bool) error {
		if existing {
			t.Fatal("failed delivery left its marker")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	last, err := os.Stat(lock)
	if err != nil || !os.SameFile(first, last) {
		t.Fatalf("persistent publication lock changed: %v", err)
	}
	names, _ := os.ReadDir(dir)
	if len(names) != 2 {
		t.Fatalf("temporary or missing entries: %v", names)
	}
}

func TestPlaceNewFileThenPreservesExistingNames(t *testing.T) {
	for _, kind := range []string{"file", "link", "directory"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			marker := filepath.Join(dir, "stop.request")
			switch kind {
			case "file":
				if err := os.WriteFile(marker, []byte("old\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "link":
				if err := os.Symlink("foreign", marker); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(marker, 0700); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(marker)
			if err != nil {
				t.Fatal(err)
			}
			denied := errors.New("failed signal")
			if err := PlaceNewFileThen(t.Context(), dir, "stop.request", []byte("new\n"), func(existing bool) error {
				if !existing {
					t.Fatal("previous name not recognized")
				}
				return denied
			}); !errors.Is(err, denied) {
				t.Fatal(err)
			}
			after, err := os.Lstat(marker)
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("earlier marker changed: %v", err)
			}
		})
	}
}

func TestPlaceNewFileThenSerializesFailedAndSuccessfulDeliveries(t *testing.T) {
	dir := t.TempDir()
	entered, release := make(chan struct{}), make(chan struct{})
	denied := errors.New("first delivery failed")
	first := make(chan error, 1)
	go func() {
		first <- PlaceNewFileThen(t.Context(), dir, "stop.request", []byte("1s\n"), func(bool) error {
			close(entered)
			<-release
			return denied
		})
	}()
	<-entered
	second := make(chan error, 1)
	go func() {
		second <- PlaceNewFileThen(t.Context(), dir, "stop.request", []byte("7s\n"), func(existing bool) error {
			if existing {
				return errors.New("successful attempt borrowed a failed marker")
			}
			return nil
		})
	}()
	// A second publisher must not enter a callback while the first can roll back.
	select {
	case err := <-second:
		close(release)
		<-first
		t.Fatalf("second escaped transaction: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-first; !errors.Is(err, denied) {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	if err := PlaceNewFileThen(t.Context(), dir, "stop.request", nil, func(existing bool) error {
		if !existing {
			t.Fatal("successful request disappeared")
		}
		return denied
	}); !errors.Is(err, denied) {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "stop.request"))
	if err != nil || string(b) != "7s\n" {
		t.Fatalf("successful request erased: %q %v", b, err)
	}
}

func TestPlaceNewFileThenRollbackUsesHeldDirectory(t *testing.T) {
	parent := t.TempDir()
	dir, old := filepath.Join(parent, "run"), filepath.Join(parent, "old")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	denied := errors.New("delivery failed after directory rename")
	err := PlaceNewFileThen(t.Context(), dir, "stop.request", []byte("new\n"), func(bool) error {
		if err := os.Rename(dir, old); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "stop.request"), []byte("foreign\n"), 0600); err != nil {
			t.Fatal(err)
		}
		return denied
	})
	if !errors.Is(err, denied) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(old, "stop.request")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("held marker retained: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "stop.request"))
	if err != nil || string(b) != "foreign\n" {
		t.Fatalf("replacement directory touched: %q %v", b, err)
	}
}

func TestPlaceNewFileThenReportsForeignMarkerAtRollback(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "stop.request")
	denied := errors.New("delivery failed")
	err := PlaceNewFileThen(t.Context(), dir, "stop.request", []byte("own\n"), func(bool) error {
		if err := os.Rename(marker, marker+".aside"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(marker, []byte("foreign\n"), 0600); err != nil {
			t.Fatal(err)
		}
		return denied
	})
	if !errors.Is(err, denied) || !strings.Contains(err.Error(), "published inode was replaced") {
		t.Fatalf("rollback error lost: %v", err)
	}
	b, err := os.ReadFile(marker)
	if err != nil || string(b) != "foreign\n" {
		t.Fatalf("foreign marker removed: %q %v", b, err)
	}
}

func TestPlaceNewFileThenLockCancellationAndUnsafeLocks(t *testing.T) {
	dir := t.TempDir()
	lock, err := os.OpenFile(filepath.Join(dir, ".stop.request.lock"), os.O_CREATE|os.O_RDONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	called := false
	if err := PlaceNewFileThen(ctx, dir, "stop.request", nil, func(bool) error { called = true; return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if called {
		t.Fatal("delivery after cancelled lock wait")
	}
	if _, err := os.Stat(filepath.Join(dir, "stop.request")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	for _, kind := range []string{"link", "fifo", "shared-mode", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ".stop.request.lock")
			switch kind {
			case "link":
				err = os.Symlink(lock.Name(), path)
			case "fifo":
				err = syscall.Mkfifo(path, 0600)
			case "shared-mode":
				err = os.WriteFile(path, nil, 0644)
			case "hardlink":
				err = os.Link(lock.Name(), path)
			}
			if err != nil {
				t.Fatal(err)
			}
			if kind == "shared-mode" {
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if err := PlaceNewFileThen(t.Context(), dir, "stop.request", nil, func(bool) error { t.Fatal("unsafe lock admitted"); return nil }); err == nil {
				t.Fatal("unsafe lock accepted")
			}
		})
	}
}
