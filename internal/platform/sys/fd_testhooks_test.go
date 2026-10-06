// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package sys

import (
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestLeakCounterCountsOne: an owner that becomes unreachable while it still owns an open number is counted
// once, and its number is not closed; one that was closed, released or abandoned first is not counted (A8).
func TestLeakCounterCountsOne(t *testing.T) {
	before := LeakedForTest()
	var leaked int
	func() {
		f, err := Own(unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0))
		if err != nil {
			t.Fatal(err)
		}
		leaked = numOf(f)
		c, err := Own(unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0))
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
		a, err := Own(unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0))
		if err != nil {
			t.Fatal(err)
		}
		n := numOf(a)
		a.Abandon()
		_ = unix.Close(n)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for LeakedForTest() == before && time.Now().Before(deadline) {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	if got := LeakedForTest() - before; got != 1 {
		t.Fatalf("LeakedForTest grew by %d, want 1", got)
	}
	if _, err := statNum(leaked); err != nil {
		t.Fatalf("the leaked owner's number was closed (%v): the counter must never close it", err)
	}
	_ = unix.Close(leaked)
}

// TestOwnRefusesNonCloexec: a tegotesthooks build checks FD_CLOEXEC on every fresh number Own and
// OwnSyscall take, the second line behind fdcheck's static F9 (A8).
func TestOwnRefusesNonCloexec(t *testing.T) {
	if _, err := Own(unix.Open("/dev/null", unix.O_RDONLY, 0)); !errors.Is(err, ErrNotCloexec) {
		t.Fatalf("Own of a number without FD_CLOEXEC = %v, want ErrNotCloexec", err)
	}
	path, err := unix.BytePtrFromString("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	cwd := unix.AT_FDCWD
	r1, _, errno := unix.Syscall6(unix.SYS_OPENAT, uintptr(cwd), uintptr(unsafe.Pointer(path)),
		uintptr(unix.O_RDONLY), 0, 0, 0)
	if _, err := OwnSyscall(r1, 0, errno); !errors.Is(err, ErrNotCloexec) {
		t.Fatalf("OwnSyscall of a number without FD_CLOEXEC = %v, want ErrNotCloexec", err)
	}
}

// TestHoldRecordsPC: an ErrLeased names who holds the FD, so a leaked Hold is found from its message.
func TestHoldRecordsPC(t *testing.T) {
	f, err := Strict(Own(unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)))
	if err != nil {
		t.Fatal(err)
	}
	l := holdForPC(t, f)
	err = f.Close()
	if !errors.Is(err, ErrLeased) || !strings.Contains(err.Error(), "holdForPC") {
		t.Fatalf("a strict Close under a lease = %v, want ErrLeased naming holdForPC", err)
	}
	if got := OutstandingLeasesForTest(); got < 1 {
		t.Fatalf("OutstandingLeasesForTest = %d with a Hold out", got)
	}
	l.Return()
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func holdForPC(t *testing.T, f *FD) *Lease {
	t.Helper()
	l, err := f.Hold()
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// TestLeaseNumAfterReturnPanics: in a tegotesthooks build a lease's number read after Return panics, so a
// number copied past its lease is found in the KVM suites.
func TestLeaseNumAfterReturnPanics(t *testing.T) {
	f := openNull(t)
	l, err := f.Hold()
	if err != nil {
		t.Fatal(err)
	}
	l.Return()
	defer func() {
		if recover() == nil {
			t.Fatal("Num after Return did not panic")
		}
	}()
	_ = l.Num()
}

// TestDeferredClosesAreReported: a close deferred by a lease is recorded with the closer and the holders.
func TestDeferredClosesAreReported(t *testing.T) {
	f := openNull(t)
	l := holdForPC(t, f)
	_ = f.Close()
	got := DeferredClosesForTest()
	if len(got) == 0 || !strings.Contains(got[len(got)-1], "TestDeferredClosesAreReported") ||
		!strings.Contains(got[len(got)-1], "holdForPC") {
		t.Fatalf("deferred closes %q, want the last naming this test as the closer and holdForPC as the holder", got)
	}
	l.Return()
}
