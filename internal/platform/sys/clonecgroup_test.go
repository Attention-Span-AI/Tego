// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestCloneIntoCgroupLendsTheNumberForTheStartOnly: CloneIntoCgroup sets UseCgroupFD and a CgroupFD that names
// the lender's directory for the start alone. A Close during the start is deferred, so the number cannot be
// reused under clone3; the number is gone from attr once the start returns, and the deferred close then runs.
func TestCloneIntoCgroupLendsTheNumberForTheStartOnly(t *testing.T) {
	dir := t.TempDir()
	fd, err := Own(unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		t.Fatal(err)
	}
	var want unix.Stat_t
	if err := unix.Stat(dir, &want); err != nil {
		t.Fatal(err)
	}
	attr := &syscall.SysProcAttr{}
	startErr := errors.New("the start's own error")
	err = CloneIntoCgroup(fd, attr, func() error {
		if !attr.UseCgroupFD {
			t.Error("UseCgroupFD is not set during the start")
		}
		if err := fd.Close(); err != nil {
			t.Errorf("Close during the start = %v, want nil (deferred)", err)
		}
		var st unix.Stat_t
		if err := unix.Fstat(attr.CgroupFD, &st); err != nil || st.Dev != want.Dev || st.Ino != want.Ino {
			t.Errorf("CgroupFD %d does not name the directory during the start (%v)", attr.CgroupFD, err)
		}
		return startErr
	})
	if !errors.Is(err, startErr) {
		t.Errorf("CloneIntoCgroup = %v, want the start's error", err)
	}
	if attr.CgroupFD != -1 || !attr.UseCgroupFD {
		t.Errorf("after the start attr is {UseCgroupFD: %v, CgroupFD: %d}, want {true, -1}", attr.UseCgroupFD, attr.CgroupFD)
	}
	if err := fd.CloseNow(); err != nil {
		t.Errorf("the deferred close did not run at the start's return: CloseNow = %v", err)
	}
}

// TestCloneIntoCgroupRefusesWithoutADirectory: a closed lender, a nil one and a nil attr start nothing.
func TestCloneIntoCgroupRefusesWithoutADirectory(t *testing.T) {
	fd, err := Own(unix.Open(t.TempDir(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := fd.Close(); err != nil {
		t.Fatal(err)
	}
	started := false
	start := func() error { started = true; return nil }
	var nilFD *FD
	for name, l := range map[string]Lender{"closed": fd, "nil *FD": nilFD, "nil": nil} {
		attr := &syscall.SysProcAttr{}
		if err := CloneIntoCgroup(l, attr, start); !errors.Is(err, ErrClosed) {
			t.Errorf("%s: CloneIntoCgroup = %v, want ErrClosed", name, err)
		}
		if started || attr.UseCgroupFD {
			t.Errorf("%s: started %v, UseCgroupFD %v", name, started, attr.UseCgroupFD)
		}
	}
	if err := CloneIntoCgroup(fd, nil, start); err == nil || started {
		t.Errorf("a nil attr = %v (started %v), want an error", err, started)
	}
}
