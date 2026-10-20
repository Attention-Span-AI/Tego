// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/testutil"
	"golang.org/x/sys/unix"
)

// TestCgroupDirIsOneOwnerAcrossCopies is ADR 0023 C13: the scope's directory is one sys.FD shared by every
// copy of the value Create returned. Dir lends it until any copy closes it, then answers sys.ErrClosed on
// every copy; a hand-built Cgroup lends nothing (nil, so Launcher.Start clones into no cgroup); and a Close
// while the number is lent is deferred until the lease ends, so clone3 or a control-file open never reads a
// number that was closed and reused under it.
func TestCgroupDirIsOneOwnerAcrossCopies(t *testing.T) {
	fs := newTestFS(t)
	c, err := fs.Create("a", "r-owner")
	if err != nil {
		t.Fatal(err)
	}
	copyOf := c
	if Dir := (Cgroup{Path: c.Path}).Dir(); Dir != nil {
		t.Errorf("a hand-built Cgroup lends %v, want nil", Dir)
	}
	var st unix.Stat_t
	if err := c.Dir().Borrow(func(n int) error {
		if err := copyOf.Close(); err != nil {
			t.Errorf("Close under a lease = %v, want nil (deferred)", err)
		}
		return unix.Fstat(n, &st)
	}); err != nil {
		t.Fatalf("the lent number did not stay open across a Close: %v", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		t.Errorf("the lent number names mode %#o, not the directory", st.Mode)
	}
	for name, v := range map[string]Cgroup{"original": c, "copy": copyOf} {
		if err := v.Dir().Borrow(func(int) error { return nil }); !errors.Is(err, sys.ErrClosed) {
			t.Errorf("%s: Dir after Close = %v, want sys.ErrClosed", name, err)
		}
		if err := v.Close(); err != nil {
			t.Errorf("%s: a second Close = %v, want nil", name, err)
		}
	}
	if err := fs.Remove(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

// TestCgroupUnwindsLeaveNoDescriptor: Create and Remove, control-file reads and writes through the open
// directory and through Path once it is closed, their refusals, and the cgroup.events watcher, armed or refused
// its watch, leave the descriptor table as they found it (ADR 0023's NoFDLeak on the unwind paths).
func TestCgroupUnwindsLeaveNoDescriptor(t *testing.T) {
	fs := newTestFS(t)
	testutil.NoFDLeak(t)
	c, err := fs.Create("a", "r-leak")
	if err != nil {
		t.Fatal(err)
	}
	writeCtl(t, c, fileEvents, "populated 0\n")
	if _, err := Populated(c); err != nil {
		t.Fatal(err)
	}
	if err := writeControl(c, fileEvents, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := readControl(c, "absent"); !errors.Is(err, unix.ENOENT) {
		t.Errorf("readControl of a missing file = %v, want ENOENT", err)
	}
	if err := writeControl(c, "absent", "1"); !errors.Is(err, unix.ENOENT) {
		t.Errorf("writeControl of a missing file = %v, want ENOENT", err)
	}
	w := newWatcher(filepath.Join(c.Path, fileEvents))
	w.close()
	// inotify_add_watch refuses a missing file: the watcher polls, and its inotify descriptor is closed.
	if w := newWatcher(filepath.Join(c.Path, "absent")); w.f != nil {
		w.close()
		t.Error("a watcher of a missing file holds an inotify descriptor")
	}
	stale := c
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readControl(stale, fileEvents); err != nil {
		t.Errorf("readControl through Path once closed: %v", err)
	}
	if _, err := fs.ID(stale); err != nil {
		t.Errorf("ID through Path once closed: %v", err)
	}
	if err := os.Remove(filepath.Join(stale.Path, fileEvents)); err != nil { // a real scope's files go with it
		t.Fatal(err)
	}
	if err := fs.Remove(context.Background(), stale); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Create("../bad", "r-leak"); err == nil {
		t.Error("Create of a bad agent name succeeded")
	}
}
