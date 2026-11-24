// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// otherUser is the uid the retention pass runs as in these tests: not the stamp's owner.
const otherUser = 65534

// asOtherUser runs f on this thread with the file-system identity of otherUser (setfsuid and setfsgid, which are
// per thread). The kernel then checks every path access in f against otherUser's rights, root's capabilities
// dropped, as it does for that user's own `tego run`. It restores root's identity before it returns.
func asOtherUser(t *testing.T, f func()) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Setfsgid(otherUser); err != nil {
		t.Fatalf("setfsgid: %v", err)
	}
	if err := unix.Setfsuid(otherUser); err != nil {
		t.Fatalf("setfsuid: %v", err)
	}
	defer func() { // root again (the callers skip unless they are root)
		if err := unix.Setfsuid(0); err != nil {
			t.Errorf("setfsuid back to root: %v", err)
		}
		_ = unix.Setfsgid(0)
	}()
	f()
}

// TestRootRetentionStampOfAnotherOwnerIsReplaced: the retention stamp of a user's ledger
// root is owned by root, as a root pass that died before its hand-over, or whose chown failed, leaves it
// (TestRetentionStampNotOursIsReplaced stands mode 000 in for that). The user's pass, running as that user, cannot
// open it: a stamp due is replaced by one the user owns, and one inside gc_interval is left, owned by root, with no
// pass due. Needs root to make a file another uid cannot open; it skips for anyone else, and runs in the KVM guest
// with the other root suites.
func TestRootRetentionStampOfAnotherOwnerIsReplaced(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: only root can leave a stamp that another uid owns and cannot open")
	}
	base := t.TempDir()
	for _, d := range []string{base, filepath.Dir(base)} {
		if err := os.Chmod(d, 0o755); err != nil { // the user must reach the ledger root
			t.Fatal(err)
		}
	}
	root := filepath.Join(base, "ledger")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(root, otherUser, otherUser); err != nil {
		t.Fatal(err)
	}
	stamp := filepath.Join(root, retentionStamp)
	rootsStamp := func(age time.Duration) {
		t.Helper()
		_ = os.Remove(stamp)
		if err := os.WriteFile(stamp, []byte("2026-10-01T00:00:00Z\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		at := time.Now().Add(-age)
		if err := os.Chtimes(stamp, at, at); err != nil {
			t.Fatal(err)
		}
	}
	ownerOf := func() uint32 {
		t.Helper()
		var st syscall.Stat_t
		if err := syscall.Lstat(stamp, &st); err != nil {
			t.Fatal(err)
		}
		return st.Uid
	}
	rootsStamp(2 * time.Hour)
	asOtherUser(t, func() {
		if _, err := os.OpenFile(stamp, os.O_RDWR, 0); !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("the other user opened root's stamp (%v): the test does not stand for a foreign owner", err)
		}
	})

	// Due: the pass is claimed and the stamp is the user's from then on.
	var claimed bool
	asOtherUser(t, func() {
		release, ok := claimRetention(root, time.Hour, time.Now())
		if ok {
			release()
		}
		claimed = ok
	})
	if !claimed {
		t.Fatal("a root-owned stamp, due, cost the user the pass")
	}
	if got := ownerOf(); got != otherUser {
		t.Errorf("the replaced stamp is owned by uid %d, want the user's %d", got, otherUser)
	}

	// Inside the interval: no pass, and the stamp stays root's.
	rootsStamp(time.Minute)
	asOtherUser(t, func() {
		release, ok := claimRetention(root, time.Hour, time.Now())
		if ok {
			release()
		}
		claimed = ok
	})
	if claimed {
		t.Error("a start inside gc_interval ran a pass over a stamp it could not open")
	}
	if got := ownerOf(); got != 0 {
		t.Errorf("a stamp inside gc_interval is owned by uid %d after the user's start, want root's: it was touched", got)
	}
}
