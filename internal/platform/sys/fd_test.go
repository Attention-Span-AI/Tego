// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// openNull opens /dev/null as an owner, for the tests below; the raw open is the test's, the owner is the
// code under test.
func openNull(t *testing.T) *FD {
	t.Helper()
	f, err := Own(unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// identity is a number's (dev, ino), or an error when the number is not open.
type identity struct{ dev, ino uint64 }

func statNum(n int) (identity, error) {
	var st unix.Stat_t
	if err := unix.Fstat(n, &st); err != nil {
		return identity{}, err
	}
	return identity{uint64(st.Dev), st.Ino}, nil
}

// wantOpen fails unless n is open and names id.
func wantOpen(t *testing.T, n int, id identity, why string) {
	t.Helper()
	got, err := statNum(n)
	if err != nil {
		t.Fatalf("%s: fd %d: %v, want it open", why, n, err)
	}
	if got != id {
		t.Fatalf("%s: fd %d names %+v, want %+v", why, n, got, id)
	}
}

// wantClosed fails unless fstat on n answers EBADF. Nothing in these tests opens a descriptor between the
// close and the check, so a reused number would be a bug of the test, not a pass.
func wantClosed(t *testing.T, n int, why string) {
	t.Helper()
	if _, err := statNum(n); !errors.Is(err, unix.EBADF) {
		t.Fatalf("%s: fstat(%d) = %v, want EBADF", why, n, err)
	}
}

// numOf is the number an owner was born with, read without a lease: the tests check what close(2) did to it.
func numOf(f *FD) int { return int(f.num) }

func idOf(t *testing.T, f *FD) identity {
	t.Helper()
	id, err := statNum(numOf(f))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestZeroFDOwnsNothing: the zero FD owns no number, so its Close never closes descriptor 0 (A1, the owns bit).
func TestZeroFDOwnsNothing(t *testing.T) {
	var f FD
	id0, err := statNum(0)
	if err != nil {
		t.Skipf("stdin is not open in this test process: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close of the zero FD = %v, want nil", err)
	}
	if err := f.CloseNow(); err != nil {
		t.Fatalf("CloseNow of the zero FD = %v, want nil", err)
	}
	f.Abandon()
	if err := f.Borrow(func(int) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("Borrow of the zero FD = %v, want ErrClosed", err)
	}
	if _, err := f.Hold(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Hold of the zero FD = %v, want ErrClosed", err)
	}
	if _, err := f.ReleaseNumber(); !errors.Is(err, ErrClosed) {
		t.Fatalf("ReleaseNumber of the zero FD = %v, want ErrClosed", err)
	}
	if err := f.OnClosed(func(error) {}); !errors.Is(err, ErrClosed) {
		t.Fatalf("OnClosed of the zero FD = %v, want ErrClosed", err)
	}
	wantOpen(t, 0, id0, "after the zero FD's Close")
}

// TestNilFD: every method of a nil *FD answers ErrClosed, or is a no-op, and none panics (A11).
func TestNilFD(t *testing.T) {
	var f *FD
	checkNilOwner(t, f)
	if _, err := f.Dup(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Dup = %v, want ErrClosed", err)
	}
	if _, err := f.Release("x"); !errors.Is(err, ErrClosed) {
		t.Fatalf("Release = %v, want ErrClosed", err)
	}
	if _, err := f.ReleaseNumber(); !errors.Is(err, ErrClosed) {
		t.Fatalf("ReleaseNumber = %v, want ErrClosed", err)
	}
	f.Abandon()
	if err := f.OnClosed(func(error) {}); !errors.Is(err, ErrClosed) {
		t.Fatalf("OnClosed = %v, want ErrClosed", err)
	}
	if got := f.String(); got == "" {
		t.Fatal("String of a nil FD is empty")
	}
}

// TestNilInInterface: a non-nil Owned or Lender that holds a nil *FD fails every call with ErrClosed and never
// panics (A11).
func TestNilInInterface(t *testing.T) {
	var p *FD
	var o Owned = p
	checkNilOwner(t, o)
	var l Lender = p
	if err := l.Borrow(func(int) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("Lender.Borrow = %v, want ErrClosed", err)
	}
}

func checkNilOwner(t *testing.T, o Owned) {
	t.Helper()
	if err := o.Borrow(func(int) error { t.Fatal("fn ran on a nil owner"); return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("Borrow = %v, want ErrClosed", err)
	}
	if _, err := o.Hold(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Hold = %v, want ErrClosed", err)
	}
	if err := o.Close(); err != nil {
		t.Fatalf("Close = %v, want nil", err)
	}
	if err := o.CloseNow(); err != nil {
		t.Fatalf("CloseNow = %v, want nil", err)
	}
}

// TestOwnRefusesStdio: Own, OwnSyscall and Adopt refuse 0, 1 and 2 without closing them; only Stdio owns
// them (A1, the stdio guard).
func TestOwnRefusesStdio(t *testing.T) {
	for n := 0; n <= 2; n++ {
		id, serr := statNum(n)
		if _, err := Own(n, nil); !errors.Is(err, ErrStdio) {
			t.Errorf("Own(%d) = %v, want ErrStdio", n, err)
		}
		if _, err := OwnSyscall(uintptr(n), 0, 0); !errors.Is(err, ErrStdio) {
			t.Errorf("OwnSyscall(%d) = %v, want ErrStdio", n, err)
		}
		if _, err := Adopt(n, "test"); !errors.Is(err, ErrStdio) {
			t.Errorf("Adopt(%d) = %v, want ErrStdio", n, err)
		}
		if serr == nil {
			wantOpen(t, n, id, "after the refusals")
		}
	}
	if _, err := Stdio(3); err == nil {
		t.Error("Stdio(3) succeeded, want a refusal")
	}
	s, err := Stdio(2)
	if err != nil {
		t.Fatal(err)
	}
	s.Abandon() // the test process keeps its stderr
}

// TestOwnPassesTheProducersError: a producer's error comes back unchanged and nothing is owned.
func TestOwnPassesTheProducersError(t *testing.T) {
	f, err := Own(unix.Open("/nonexistent/tego", unix.O_RDONLY|unix.O_CLOEXEC, 0))
	if f != nil || !errors.Is(err, unix.ENOENT) {
		t.Fatalf("Own(open of a missing path) = %v, %v; want nil, ENOENT", f, err)
	}
	f, err = OwnSyscall(^uintptr(0), 0, unix.EACCES)
	if f != nil || !errors.Is(err, unix.EACCES) {
		t.Fatalf("OwnSyscall(errno EACCES) = %v, %v; want nil, EACCES", f, err)
	}
}

// TestErrorsMatchErrno: ErrClosed is EBADF and ErrLeased is EBUSY under errors.Is, so the errno classifiers
// keep their classes when a Borrow fails (A1, Errors).
func TestErrorsMatchErrno(t *testing.T) {
	if !errors.Is(ErrClosed, unix.EBADF) || errors.Is(ErrClosed, unix.EBUSY) {
		t.Error("ErrClosed does not match EBADF alone")
	}
	if !errors.Is(ErrLeased, unix.EBUSY) || errors.Is(ErrLeased, unix.EBADF) {
		t.Error("ErrLeased does not match EBUSY alone")
	}
	f := openNull(t)
	l, err := f.Hold()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Return()
	if err := f.CloseNow(); !errors.Is(err, unix.EBUSY) || !errors.Is(err, ErrLeased) {
		t.Errorf("CloseNow under a lease = %v, want ErrLeased matching EBUSY", err)
	}
	_ = f.Close()
	if err := f.Borrow(func(int) error { return nil }); !errors.Is(err, unix.EBADF) {
		t.Errorf("Borrow after Close = %v, want ErrClosed matching EBADF", err)
	}
}

// TestCloseClosesNow: with no lease out Close calls close(2) at once and returns its answer.
func TestCloseClosesNow(t *testing.T) {
	f := openNull(t)
	n := numOf(f)
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	wantClosed(t, n, "after Close")
	if err := f.Close(); err != nil {
		t.Fatalf("a second Close = %v, want nil (a no-op)", err)
	}
}

// TestCloseDeferredUntilLastReturn: a Close that meets a lease returns nil and leaves the number open; the
// last Return closes it (A1). This is the window closed: the number cannot be reused under a borrower.
func TestCloseDeferredUntilLastReturn(t *testing.T) {
	f := openNull(t)
	n, id := numOf(f), idOf(t, f)
	a, err := f.Hold()
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.Hold()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close under two leases = %v, want nil", err)
	}
	wantOpen(t, n, id, "Close under two leases")
	if _, err := f.Hold(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Hold after Close = %v, want ErrClosed", err)
	}
	a.Return()
	wantOpen(t, n, id, "one lease of two returned")
	b.Return()
	wantClosed(t, n, "the last lease returned")
}

// TestBorrowReleasesOnPanic: a panic in Borrow's fn returns the lease, so a recovered panic (the supervisor
// recovers one per notification) does not hold the descriptor open for ever.
func TestBorrowReleasesOnPanic(t *testing.T) {
	f := openNull(t)
	n := numOf(f)
	func() {
		defer func() { _ = recover() }()
		_ = f.Borrow(func(int) error { panic("boom") })
	}()
	if got := f.leases(); got != 0 {
		t.Fatalf("leases after a panicking Borrow = %d, want 0", got)
	}
	if err := f.CloseNow(); err != nil {
		t.Fatalf("CloseNow after a panicking Borrow = %v, want nil", err)
	}
	wantClosed(t, n, "CloseNow after the panic")
}

// TestBorrowGivesTheNumber: fn sees the owner's number and its error is Borrow's.
func TestBorrowGivesTheNumber(t *testing.T) {
	f := openNull(t)
	want := errors.New("fn's error")
	err := f.Borrow(func(n int) error {
		if n != numOf(f) {
			t.Errorf("Borrow lent %d, want %d", n, numOf(f))
		}
		return want
	})
	if err != want {
		t.Fatalf("Borrow = %v, want fn's error", err)
	}
}

// TestStrictCloseIsCloseNow: a strict FD never defers a close. Close under a lease is ErrLeased and changes
// nothing; without one it closes at once (A1, Strict at birth).
func TestStrictCloseIsCloseNow(t *testing.T) {
	f, err := Strict(Own(unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)))
	if err != nil {
		t.Fatal(err)
	}
	n, id := numOf(f), idOf(t, f)
	l, err := f.Hold()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); !errors.Is(err, ErrLeased) {
		t.Fatalf("strict Close under a lease = %v, want ErrLeased", err)
	}
	wantOpen(t, n, id, "strict Close refused")
	if err := f.Borrow(func(int) error { return nil }); err != nil {
		t.Fatalf("Borrow after a refused strict Close = %v: the refusal changed the state", err)
	}
	l.Return()
	wantOpen(t, n, id, "the lease returned after a refused strict Close")
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	wantClosed(t, n, "strict Close with no lease")
	if _, err := Strict(nil, unix.EMFILE); !errors.Is(err, unix.EMFILE) {
		t.Fatalf("Strict passes the constructor's error as %v", err)
	}
}

// TestFlockRefusesNonStrict: a lock descriptor must be strict, so Flock refuses any other (A1).
func TestFlockRefusesNonStrict(t *testing.T) {
	path := t.TempDir() + "/lock"
	f, err := Own(unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Flock(unix.LOCK_EX); !errors.Is(err, ErrNotStrict) {
		t.Fatalf("Flock on a non-strict FD = %v, want ErrNotStrict", err)
	}
	s, err := Strict(Own(unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Flock(unix.LOCK_EX | unix.LOCK_NB); err != nil {
		t.Fatalf("Flock on a strict FD = %v", err)
	}
	other, err := Strict(Own(unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.Flock(unix.LOCK_EX | unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("a second exclusive Flock = %v, want EWOULDBLOCK", err)
	}
}

// TestReleaseRefusesWhileLeased: a number cannot be given away under a borrower.
func TestReleaseRefusesWhileLeased(t *testing.T) {
	f := openNull(t)
	l, err := f.Hold()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Release("null"); !errors.Is(err, ErrLeased) {
		t.Fatalf("Release under a lease = %v, want ErrLeased", err)
	}
	if _, err := f.ReleaseNumber(); !errors.Is(err, ErrLeased) {
		t.Fatalf("ReleaseNumber under a lease = %v, want ErrLeased", err)
	}
	l.Return()
	if err := f.Borrow(func(int) error { return nil }); err != nil {
		t.Fatalf("Borrow after the refused Releases = %v", err)
	}
}

// TestReleaseTransfers: after Release the *os.File owns the number and the FD owns nothing.
func TestReleaseTransfers(t *testing.T) {
	f := openNull(t)
	n, id := numOf(f), idOf(t, f)
	file, err := f.Release("null")
	if err != nil {
		t.Fatal(err)
	}
	if file.Name() != "null" {
		t.Errorf("released file named %q", file.Name())
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close after Release = %v, want a no-op", err)
	}
	wantOpen(t, n, id, "Close after Release")
	if err := f.Borrow(func(int) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("Borrow after Release = %v, want ErrClosed", err)
	}
	if err := f.CloseNow(); !errors.Is(err, ErrClosed) || !strings.Contains(err.Error(), "released") {
		t.Fatalf("CloseNow after Release = %v, want ErrClosed naming the release", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	wantClosed(t, n, "the released file closed")
}

// TestReleaseNumberEmpties: ReleaseNumber gives the number and leaves the FD owning nothing.
func TestReleaseNumberEmpties(t *testing.T) {
	f := openNull(t)
	id := idOf(t, f)
	n, err := f.ReleaseNumber()
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(n)
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	wantOpen(t, n, id, "Close after ReleaseNumber")
	if _, err := f.ReleaseNumber(); !errors.Is(err, ErrClosed) {
		t.Fatalf("a second ReleaseNumber = %v, want ErrClosed", err)
	}
}

// TestLeaseReturnIdempotent: a second Return of one lease never ends another holder's lease.
func TestLeaseReturnIdempotent(t *testing.T) {
	f := openNull(t)
	n, id := numOf(f), idOf(t, f)
	a, err := f.Hold()
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.Hold()
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	a.Return()
	a.Return()
	wantOpen(t, n, id, "one lease returned twice while another is out")
	b.Return()
	wantClosed(t, n, "the other lease returned")
	var nilLease *Lease
	nilLease.Return()
}

// TestLeaseNumAfterReturn: Num gives the number while the lease is out and -1 after (tegotesthooks builds
// panic instead, fd_testhooks_test.go).
func TestLeaseNumAfterReturn(t *testing.T) {
	if testHooks != nil {
		t.Skip("a tegotesthooks build panics here; TestLeaseNumAfterReturnPanics covers it")
	}
	f := openNull(t)
	l, err := f.Hold()
	if err != nil {
		t.Fatal(err)
	}
	if l.Num() != numOf(f) {
		t.Fatalf("Num = %d, want %d", l.Num(), numOf(f))
	}
	l.Return()
	if l.Num() != -1 {
		t.Fatalf("Num after Return = %d, want -1", l.Num())
	}
}

// TestHoldsForTest counts the Holds an FD has granted (P4's pins use it).
func TestHoldsForTest(t *testing.T) {
	f := openNull(t)
	_ = f.Borrow(func(int) error { return nil })
	for range 3 {
		l, err := f.Hold()
		if err != nil {
			t.Fatal(err)
		}
		l.Return()
	}
	if got := f.HoldsForTest(); got != 3 {
		t.Fatalf("HoldsForTest = %d, want 3 (Borrow is not a Hold)", got)
	}
}

// TestDupIsIndependent: Dup gives a new owner of the same file under a new close-on-exec number, whose
// lifetime is its own.
func TestDupIsIndependent(t *testing.T) {
	f := openNull(t)
	id := idOf(t, f)
	d, err := f.Dup()
	if err != nil {
		t.Fatal(err)
	}
	dn := numOf(d)
	if dn == numOf(f) || dn <= 2 {
		t.Fatalf("Dup gave %d (the original is %d)", dn, numOf(f))
	}
	if fl, err := unix.FcntlInt(uintptr(dn), unix.F_GETFD, 0); err != nil || fl&unix.FD_CLOEXEC == 0 {
		t.Fatalf("Dup's number is not close-on-exec: %#x, %v", fl, err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	wantOpen(t, dn, id, "the original closed")
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	wantClosed(t, dn, "the duplicate closed")
}

// TestHoldBorrowDupReleaseAfterClose: once closed, nothing lends or gives the number again.
func TestHoldBorrowDupReleaseAfterClose(t *testing.T) {
	f := openNull(t)
	_ = f.Close()
	checkNothingLends(t, f, "after Close")
}

// TestHoldBorrowDupReleaseAfterAbandon: an abandoned FD lends nothing and never closes its number (A5).
func TestHoldBorrowDupReleaseAfterAbandon(t *testing.T) {
	f := openNull(t)
	n, id := numOf(f), idOf(t, f)
	defer unix.Close(n)
	f.Abandon()
	checkNothingLends(t, f, "after Abandon")
	if err := f.Close(); err != nil {
		t.Fatalf("Close after Abandon = %v, want a no-op", err)
	}
	wantOpen(t, n, id, "Close after Abandon")
}

func checkNothingLends(t *testing.T, f *FD, when string) {
	t.Helper()
	if err := f.Borrow(func(int) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("Borrow %s = %v, want ErrClosed", when, err)
	}
	if _, err := f.Hold(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Hold %s = %v, want ErrClosed", when, err)
	}
	if _, err := f.Dup(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Dup %s = %v, want ErrClosed", when, err)
	}
	if _, err := f.Release("x"); !errors.Is(err, ErrClosed) {
		t.Fatalf("Release %s = %v, want ErrClosed", when, err)
	}
	if _, err := f.ReleaseNumber(); !errors.Is(err, ErrClosed) {
		t.Fatalf("ReleaseNumber %s = %v, want ErrClosed", when, err)
	}
}

// TestCloseNowTwice: a second CloseNow is nil (the number is closed) and closes nothing.
func TestCloseNowTwice(t *testing.T) {
	f := openNull(t)
	n := numOf(f)
	if err := f.CloseNow(); err != nil {
		t.Fatal(err)
	}
	wantClosed(t, n, "CloseNow")
	// A sentinel on the freed number: a second close(2) would close it.
	sentinel := sentinelOn(t, n)
	if err := f.CloseNow(); err != nil {
		t.Fatalf("a second CloseNow = %v, want nil", err)
	}
	wantOpen(t, n, sentinel, "a second CloseNow")
}

// sentinelOn dup3s a fresh /dev/zero descriptor onto n and returns its identity; the test closes it.
func sentinelOn(t *testing.T, n int) identity {
	t.Helper()
	id, err := placeSentinel(n)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(n) })
	return id
}

// placeSentinel is sentinelOn for a goroutine that is not the test's, which may not call t.Fatal.
func placeSentinel(n int) (identity, error) {
	z, err := unix.Open("/dev/zero", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return identity{}, err
	}
	if z == n { // the lowest free number was the one just freed: the open put the sentinel there itself
		return statNum(n)
	}
	defer unix.Close(z)
	if err := unix.Dup3(z, n, unix.O_CLOEXEC); err != nil {
		return identity{}, err
	}
	return statNum(n)
}

// TestCloseNowOnKeptFails: CloseNow on a released or abandoned FD is ErrClosed naming which, since the number
// is still open and this FD will never close it.
func TestCloseNowOnKeptFails(t *testing.T) {
	f := openNull(t)
	n := numOf(f)
	defer unix.Close(n)
	f.Abandon()
	if err := f.CloseNow(); !errors.Is(err, ErrClosed) || !strings.Contains(err.Error(), "abandoned") {
		t.Fatalf("CloseNow after Abandon = %v, want ErrClosed naming the abandonment", err)
	}
}

// TestAbandonCancelsDeferredClose: Abandon between a deferred Close and the last Return keeps the number
// open; the last Return closes nothing (A5).
func TestAbandonCancelsDeferredClose(t *testing.T) {
	f := openNull(t)
	n, id := numOf(f), idOf(t, f)
	defer unix.Close(n)
	l, err := f.Hold()
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	f.Abandon()
	l.Return()
	wantOpen(t, n, id, "the last Return after Abandon")
}

// TestAbandonUnderLease: leases out when Abandon comes go on; the last Return closes nothing.
func TestAbandonUnderLease(t *testing.T) {
	f := openNull(t)
	n, id := numOf(f), idOf(t, f)
	defer unix.Close(n)
	l, err := f.Hold()
	if err != nil {
		t.Fatal(err)
	}
	f.Abandon()
	if l.Num() != n {
		t.Fatalf("the lease's number changed under Abandon")
	}
	l.Return()
	wantOpen(t, n, id, "the last Return after Abandon")
}

// blockClose replaces close(2) with one that waits on release once entered, for the "close(2) running
// elsewhere" column of A1's table. The returned channel is closed when close(2) has been entered.
func blockClose(t *testing.T) (entered <-chan struct{}, release func()) {
	t.Helper()
	in, out := make(chan struct{}), make(chan struct{})
	var once sync.Once
	prev := closeNumber
	closeNumber = func(n int) error {
		close(in)
		<-out
		return prev(n)
	}
	rel := func() { once.Do(func() { close(out) }) }
	t.Cleanup(func() { rel(); closeNumber = prev })
	return in, rel
}

// TestCloseNowWaitsForRunningClose: CloseNow while another goroutine is inside close(2) for the number
// waits for that call and returns nil only after it (A1, CloseNow's contract).
func TestCloseNowWaitsForRunningClose(t *testing.T) {
	f := openNull(t)
	n := numOf(f)
	entered, release := blockClose(t)
	go func() { _ = f.Close() }()
	<-entered
	done := make(chan error, 1)
	go func() { done <- f.CloseNow() }()
	select {
	case err := <-done:
		t.Fatalf("CloseNow returned %v while close(2) was still running", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := f.Close(); err != nil {
		t.Fatalf("a non-strict Close while close(2) runs = %v, want a no-op", err)
	}
	release()
	if err := <-done; err != nil {
		t.Fatalf("CloseNow after the running close = %v, want nil", err)
	}
	wantClosed(t, n, "CloseNow returned")
}

// TestWhileCloseRuns is A1's "close(2) running elsewhere" column: nothing lends or gives the number, Abandon
// is too late to keep it, a non-strict Close is a no-op and a strict one waits like CloseNow.
func TestWhileCloseRuns(t *testing.T) {
	f, err := Strict(Own(unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)))
	if err != nil {
		t.Fatal(err)
	}
	n := numOf(f)
	entered, release := blockClose(t)
	go func() { _ = f.CloseNow() }()
	<-entered
	checkNothingLends(t, f, "while close(2) runs")
	f.Abandon()
	done := make(chan error, 1)
	go func() { done <- f.Close() }()
	select {
	case err := <-done:
		t.Fatalf("a strict Close returned %v while close(2) was still running", err)
	case <-time.After(50 * time.Millisecond):
	}
	release()
	if err := <-done; err != nil {
		t.Fatalf("a strict Close after the running close = %v, want nil", err)
	}
	wantClosed(t, n, "Abandon came too late")
}

// TestCloseNowNeverNilWhilePending: a Close deferred by a lease is pending, and CloseNow says so with
// ErrLeased rather than nil (A1: nil only after close(2) has returned).
func TestCloseNowNeverNilWhilePending(t *testing.T) {
	f := openNull(t)
	n := numOf(f)
	l, err := f.Hold()
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if err := f.CloseNow(); !errors.Is(err, ErrLeased) {
		t.Fatalf("CloseNow with the close pending = %v, want ErrLeased", err)
	}
	l.Return()
	if err := f.CloseNow(); err != nil {
		t.Fatalf("CloseNow after the last Return = %v, want nil", err)
	}
	wantClosed(t, n, "the pending close landed")
}

// TestOnClosedRunsAfterCloseOnEveryPath: the hook runs once, after close(2), on whichever path closed the
// number (Close, CloseNow, the last Return), with close(2)'s error; never after Release or Abandon (A1).
func TestOnClosedRunsAfterCloseOnEveryPath(t *testing.T) {
	paths := map[string]func(f *FD){
		"Close":    func(f *FD) { _ = f.Close() },
		"CloseNow": func(f *FD) { _ = f.CloseNow() },
		"last Return": func(f *FD) {
			l, err := f.Hold()
			if err != nil {
				panic(err)
			}
			_ = f.Close()
			l.Return()
		},
		"Close of a strict FD": func(f *FD) { f.state.Or(stStrict); _ = f.Close() },
	}
	for name, closeIt := range paths {
		t.Run(name, func(t *testing.T) {
			f := openNull(t)
			n := numOf(f)
			var runs int
			var closedFirst bool
			if err := f.OnClosed(func(err error) {
				runs++
				_, serr := statNum(n)
				closedFirst = errors.Is(serr, unix.EBADF) && err == nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := f.OnClosed(func(error) {}); err == nil {
				t.Fatal("a second OnClosed was accepted")
			}
			closeIt(f)
			if runs != 1 || !closedFirst {
				t.Fatalf("the hook ran %d times (want 1), after close(2): %v", runs, closedFirst)
			}
			// Registered after the close: runs at once with close(2)'s error.
			var late int
			if err := f.OnClosed(func(err error) { late++ }); err != nil || late != 1 {
				t.Fatalf("OnClosed after the close = %v and ran %d times, want nil and 1", err, late)
			}
		})
	}
	for name, keep := range map[string]func(f *FD){
		"Release": func(f *FD) {
			file, err := f.Release("x")
			if err != nil {
				panic(err)
			}
			_ = file.Close()
		},
		"Abandon": func(f *FD) { f.Abandon(); _ = f.Close() },
		"Abandon of a pending close": func(f *FD) {
			l, _ := f.Hold()
			_ = f.Close()
			f.Abandon()
			l.Return()
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := openNull(t)
			n := numOf(f)
			ran := false
			if err := f.OnClosed(func(error) { ran = true }); err != nil {
				t.Fatal(err)
			}
			keep(f)
			if ran {
				t.Fatalf("the hook ran after %s", name)
			}
			if err := f.OnClosed(func(error) {}); !errors.Is(err, ErrClosed) {
				t.Fatalf("OnClosed after %s = %v, want ErrClosed", name, err)
			}
			if name != "Release" {
				_ = unix.Close(n)
			}
		})
	}
}

// TestOnClosedWhileCloseRuns: a hook registered while close(2) is running is the one that runs after it.
func TestOnClosedWhileCloseRuns(t *testing.T) {
	f := openNull(t)
	entered, release := blockClose(t)
	go func() { _ = f.Close() }()
	<-entered
	ran := make(chan error, 1)
	if err := f.OnClosed(func(err error) { ran <- err }); err != nil {
		t.Fatal(err)
	}
	release()
	if err := <-ran; err != nil {
		t.Fatalf("the hook got %v, want close(2)'s nil", err)
	}
}

// TestCloseErrorReachesTheHook: a deferred close has no caller to return close(2)'s error to, so the hook
// gets it.
func TestCloseErrorReachesTheHook(t *testing.T) {
	f := openNull(t)
	prev := closeNumber
	closeNumber = func(n int) error { _ = prev(n); return unix.EIO }
	t.Cleanup(func() { closeNumber = prev })
	got := make(chan error, 1)
	if err := f.OnClosed(func(err error) { got <- err }); err != nil {
		t.Fatal(err)
	}
	l, _ := f.Hold()
	if err := f.Close(); err != nil {
		t.Fatalf("a deferred Close = %v, want nil", err)
	}
	l.Return()
	if err := <-got; !errors.Is(err, unix.EIO) {
		t.Fatalf("the hook got %v, want close(2)'s EIO", err)
	}
	if err := f.CloseNow(); err != nil {
		t.Fatalf("CloseNow after a close(2) that failed = %v, want nil: the number is closed either way", err)
	}
}

// TestNoFinalizer: dropping an owner closes nothing, whatever the garbage collector does (A8).
func TestNoFinalizer(t *testing.T) {
	var n int
	var id identity
	func() {
		f, err := Own(unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0))
		if err != nil {
			t.Fatal(err)
		}
		n, id = numOf(f), idOf(t, f)
	}()
	runtime.GC()
	runtime.GC()
	wantOpen(t, n, id, "the owner dropped and collected")
	_ = unix.Close(n)
}

// TestTypedMethods: the typed methods are Borrows of the owner's number, and refuse a closed owner.
func TestTypedMethods(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/f", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := Own(unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var st unix.Stat_t
	if err := d.Fstat(&st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		t.Fatalf("Fstat = %v, mode %#o", err, st.Mode)
	}
	if err := d.Fstatat("f", &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || st.Size != 1 {
		t.Fatalf("Fstatat = %v, size %d", err, st.Size)
	}
	var stx unix.Statx_t
	if err := d.Statx("f", unix.AT_SYMLINK_NOFOLLOW, unix.STATX_INO, &stx); err != nil || stx.Ino != st.Ino {
		t.Fatalf("Statx = %v, ino %d want %d", err, stx.Ino, st.Ino)
	}
	f, err := d.Openat("f", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Fsync(); err != nil {
		t.Fatalf("Fsync = %v", err)
	}
	if err := f.Futimes([]unix.Timeval{{Sec: 1}, {Sec: 2}}); err != nil {
		t.Fatalf("Futimes = %v", err)
	}
	g, err := d.Openat2("f", &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH})
	if err != nil && !errors.Is(err, unix.ENOSYS) {
		t.Fatalf("Openat2 = %v", err)
	}
	_ = g.Close()
	if err := d.ProcPath(func(p string) error {
		link, err := os.Readlink(p)
		if err != nil {
			return err
		}
		if link != dir {
			t.Errorf("ProcPath's link reads %q, want %q", link, dir)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s, err := Own(unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if typ, err := s.GetsockoptInt(unix.SOL_SOCKET, unix.SO_TYPE); err != nil || typ != unix.SOCK_STREAM {
		t.Fatalf("GetsockoptInt(SO_TYPE) = %d, %v", typ, err)
	}
	_ = d.Close()
	if err := d.Fstat(&st); !errors.Is(err, ErrClosed) {
		t.Fatalf("Fstat on a closed owner = %v, want ErrClosed", err)
	}
	if _, err := d.Openat("f", unix.O_RDONLY|unix.O_CLOEXEC, 0); !errors.Is(err, ErrClosed) {
		t.Fatalf("Openat on a closed owner = %v, want ErrClosed", err)
	}
}
