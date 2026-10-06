// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// FD owns one open file descriptor number (ADR 0023, as amended 2026-10-05: A1). It is the only thing that
// closes the number, and it closes it once: every later Close is a no-op, so a holder that may be the last
// owner on some path can always Close. The number never changes after birth and leaves the owner only
// through a counted lease (Borrow, Hold), a duplicate (Dup) or a hand-over that ends the ownership (Release,
// ReleaseNumber). A Close that meets a lease is deferred to the last Return, so the number cannot be reused
// under a borrower, which is the window; a strict FD refuses such a Close instead (Strict).
//
// An FD has no finalizer and no cleanup that closes anything: dropping one leaves its number open (A8). It is
// always used as *FD, and every method checks its nil receiver, so a nil *FD, alone or in a Lender or Owned,
// answers ErrClosed and never panics. The zero FD owns nothing, which keeps an owner of descriptor 0 distinct
// from no owner at all.
//
// Constructors: Own and OwnSyscall wrap a producer's result in the expression that creates it, Adopt takes a
// number the kernel wrote into memory, Inherited one this process received at exec, Stdio one of 0–2; the
// helpers in pidfd.go, seccomp.go, landlock.go, pipe.go, rights.go and filedo.go are owner forms of their
// producers. Wrapping a number some other owner holds is the bug class this type exists to end; the lint of ADR 0023
// C3 enforces it outside this package.
type FD struct {
	// state is one word: the flags below and, in its low 32 bits, the count of leases out. Borrow and Return
	// touch nothing else.
	state atomic.Uint64
	num   int32
	// holds counts the Holds this FD has granted (HoldsForTest), for the per-Run and per-loop lease pins.
	holds atomic.Uint32
	// slow is installed on first need (OnClosed, a CloseNow that waits, close(2) failing, a tegotesthooks
	// build) and holds what the leases never touch, so an owner is 24 bytes: the escaping owner of a
	// per-event descriptor costs one small allocation (ADR 0023 P5, P9). stSlow in state says it is there.
	slow atomic.Pointer[fdSlow]
}

// fdSlow is an FD's slow path.
type fdSlow struct {
	mu       sync.Mutex
	hook     func(error) // OnClosed's fn, until finishClose takes it
	hookSet  bool
	closeErr error         // close(2)'s error, written before stReturned is set
	done     chan struct{} // made by a CloseNow that waits for another goroutine's close(2)
	trace    fdTracer      // tegotesthooks only (fd_testhooks.go)
}

// The flags of FD.state.
const (
	stOwns      uint64 = 1 << 63 // set by a constructor; the zero FD owns nothing
	stStrict    uint64 = 1 << 62 // never defer a close (Strict)
	stClosing   uint64 = 1 << 61 // a Close, CloseNow, Release or Abandon was accepted: no new lease
	stKept      uint64 = 1 << 60 // this FD never calls close(2) on its number
	stClaimed   uint64 = 1 << 59 // one goroutine won the right to call close(2)
	stDone      uint64 = 1 << 58 // close(2) has returned, or a kept FD has no lease left
	stReleased  uint64 = 1 << 57 // kept because Release or ReleaseNumber gave the number away
	stAbandoned uint64 = 1 << 56 // kept because Abandon forgot the number
	stSlow      uint64 = 1 << 55 // FD.slow is installed
	stReturned  uint64 = 1 << 54 // close(2) has returned (stDone follows once the hook has run)
	leaseMask   uint64 = 1<<32 - 1
)

// ensureSlow installs the slow path once and returns it. stSlow is set in the state word after the pointer
// is stored, so it is ordered with every other change of that word: a goroutine that sets stReturned or
// stDone afterwards sees it and takes the lock, and one that set either before is seen by whoever installed
// the slow path when it reads the word under the lock.
func (f *FD) ensureSlow() *fdSlow {
	s := f.slow.Load()
	if s == nil {
		n := &fdSlow{}
		if f.slow.CompareAndSwap(nil, n) {
			s = n
		} else {
			s = f.slow.Load()
		}
	}
	f.state.Or(stSlow)
	return s
}

// untrace tells a tegotesthooks build's leak counter that this owner no longer holds a number it will close.
func (f *FD) untrace() {
	if testHooks == nil {
		return
	}
	if s := f.slow.Load(); s != nil && s.trace != nil {
		s.trace.gone()
	}
}

// closeNumber is close(2), never retried: Linux frees the number before it can return EINTR, so a retry
// could close a number another goroutine has just been given. A test replaces it to hold a close(2) open.
var closeNumber = unix.Close

// ownersMade is set by the first owner this process makes other than through Inherited and Stdio; from then
// on Inherited refuses (the seal, ADR 0023 A10).
var ownersMade atomic.Bool

// fdTestHooks is the tegotesthooks build's view of every owner (fd_testhooks.go installs it): the leak
// counter, the close-on-exec check, the holders' PCs and the deferred-close report of ADR 0023 A8. testHooks
// is nil in a product build, so none of it runs there.
type fdTestHooks interface {
	born(f *FD, cloexecFresh bool) error // may refuse a fresh number, which it then closes
	held(l *Lease)
	returned(l *Lease)
	leased(f *FD) error // ErrLeased naming the holders
	deferred(f *FD)     // a Close deferred by leases
	numAfterReturn()
}

var testHooks fdTestHooks

// fdTracer is what a tegotesthooks build keeps per owner, in its slow path (fd_testhooks.go's *fdTrace);
// nil in a product build. gone says the owner no longer holds a number it will close.
type fdTracer interface{ gone() }

// newFD is the one place an owner is born.
func newFD(n int, flags uint64, cloexecFresh bool) (*FD, error) {
	if n >= 0 && n <= 2 {
		return nil, fmt.Errorf("fd %d: %w", n, ErrStdio)
	}
	if n < 0 || n > math.MaxInt32 {
		return nil, fmt.Errorf("sys: %d is not a descriptor number", n)
	}
	f := &FD{num: int32(n)}
	f.state.Store(stOwns | flags)
	if testHooks != nil {
		if err := testHooks.born(f, cloexecFresh); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// seal marks that this process has made an owner other than through Inherited.
func seal() {
	if !ownersMade.Load() {
		ownersMade.Store(true)
	}
}

// Own wraps a producer's results, as in sys.Own(unix.Openat(dirfd, name, flags|unix.O_CLOEXEC, 0)): the
// producer's error comes back unchanged, and a number comes back owned. It refuses 0–2 (ErrStdio) without
// closing them. Its argument is a direct call to a producer of a fresh descriptor; wrapping a number another
// owner holds, or one an API returned, is what ADR 0023 forbids (its lint, A10 F1).
func Own(n int, err error) (*FD, error) {
	if err != nil {
		return nil, err
	}
	seal()
	return newFD(n, 0, true)
}

// OwnSyscall wraps a raw syscall's results, as in sys.OwnSyscall(unix.Syscall(unix.SYS_BPF, …)), for the
// producers x/sys has no wrapper for. errno non-zero is returned as the error. Only syscalls whose result is
// a descriptor may be wrapped (ADR 0023 A10 F10): a landlock VERSION query or a seccomp call without
// NEW_LISTENER answers a number that is not one, and the stdio guard catches only 0–2.
func OwnSyscall(r1, _ uintptr, errno syscall.Errno) (*FD, error) {
	if errno != 0 {
		return nil, errno
	}
	seal()
	if r1 > math.MaxInt32 {
		return nil, fmt.Errorf("sys: syscall answered %d, not a descriptor number", r1)
	}
	return newFD(int(r1), 0, true)
}

// Adopt owns a number the kernel wrote into memory rather than returned: a fanotify event's fd, the pidfd
// clone3 stored through SysProcAttr.PidFD. from names the source for errors. Its sites are listed (ADR 0023
// A10 F4).
func Adopt(n int, from string) (*FD, error) {
	seal()
	f, err := newFD(n, 0, false)
	if err != nil {
		return nil, fmt.Errorf("adopt %s: %w", from, err)
	}
	return f, nil
}

// Stdio owns one of the standard descriptors 0–2, the one way to own them. Closing the owner closes it.
func Stdio(n int) (*FD, error) {
	if n < 0 || n > 2 {
		return nil, fmt.Errorf("sys: Stdio(%d): not a standard descriptor", n)
	}
	f := &FD{num: int32(n)}
	f.state.Store(stOwns)
	return f, nil
}

// Strict takes a constructor's results, as in sys.Strict(sys.Own(unix.Open(…))), and makes the FD strict: it
// never defers a close, so its Close acts as CloseNow and answers ErrLeased while a lease is out. A lock's
// descriptor (Flock), a pipe's write end whose EOF a peer waits for, the seccomp listener and a durability
// file whose close must report its error are born strict (A1).
func Strict(f *FD, err error) (*FD, error) {
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, ErrClosed
	}
	f.state.Or(stStrict)
	return f, nil
}

// acquire takes a lease, or reports that the FD lends nothing any more. One atomic add on the fast path: an
// add that lands on a closing or empty FD is returned at once, through unlease, which closes the number if
// that add was, for an instant, the last lease of a deferred close.
func (f *FD) acquire() bool {
	s := f.state.Add(1)
	if s&leaseMask == 0 {
		panic("sys: FD lease count overflow")
	}
	if s&(stOwns|stClosing) == stOwns {
		return true
	}
	f.unlease()
	return false
}

// unlease returns a lease; the last one out of a deferred close closes the number (or, for a kept FD, only
// marks it done).
func (f *FD) unlease() {
	s := f.state.Add(^uint64(0))
	if s&leaseMask != 0 || s&stClosing == 0 || s&(stClaimed|stDone) != 0 {
		return
	}
	f.lastReturn()
}

// lastReturn claims a deferred close for this goroutine, or leaves it to whoever else got there first.
func (f *FD) lastReturn() {
	for {
		s := f.state.Load()
		if s&leaseMask != 0 || s&stClosing == 0 || s&(stClaimed|stDone) != 0 {
			return // a transient add of a refused acquire is out, and its unlease will come here
		}
		if s&stKept != 0 {
			if f.state.CompareAndSwap(s, s|stDone) {
				return
			}
			continue
		}
		if f.state.CompareAndSwap(s, s|stClaimed) {
			_ = f.finishClose()
			return
		}
	}
}

// finishClose calls close(2) for a goroutine that holds the claim, then runs the hook and marks the FD done.
// close(2)'s error is returned; a deferred close's caller drops it, and the hook still gets it.
func (f *FD) finishClose() error {
	err := closeNumber(int(f.num))
	if err != nil {
		// Kept for an OnClosed that comes later. A failed close(2) is rare, so the slow path's allocation
		// is paid only then.
		s := f.ensureSlow()
		s.mu.Lock()
		s.closeErr = err
		s.mu.Unlock()
	}
	f.untrace()
	var hook func(error)
	if f.state.Or(stReturned)&stSlow != 0 {
		s := f.slow.Load()
		s.mu.Lock()
		hook, s.hook = s.hook, nil
		s.mu.Unlock()
	}
	if hook != nil {
		hook(err)
	}
	if f.state.Or(stDone)&stSlow != 0 {
		s := f.slow.Load()
		s.mu.Lock()
		ch := s.done
		s.mu.Unlock()
		if ch != nil {
			close(ch)
		}
	}
	return err
}

// waitDone waits for another goroutine's close(2), and its hook, to return.
func (f *FD) waitDone() {
	s := f.ensureSlow()
	s.mu.Lock()
	if f.state.Load()&stDone != 0 {
		s.mu.Unlock()
		return
	}
	if s.done == nil {
		s.done = make(chan struct{})
	}
	ch := s.done
	s.mu.Unlock()
	<-ch
}

// Borrow runs fn with the number under a lease and returns fn's error, or ErrClosed when the FD lends nothing
// (closed, closing, released, abandoned, zero or nil). The lease is returned when fn returns or panics. A
// Close meanwhile is deferred until the last lease is back, so the number names this FD's file for all of fn.
// fn must not keep the number past its return. On a concrete *FD, Borrow allocates nothing.
func (f *FD) Borrow(fn func(n int) error) error {
	if f == nil || !f.acquire() {
		return ErrClosed
	}
	defer f.unlease()
	return fn(int(f.num))
}

// Close closes the number once. With no lease out it calls close(2) at once and returns its error, never
// retried. With leases out it marks the FD closing and returns nil, and the last Return calls close(2), whose
// error goes to the OnClosed hook if one is registered. A strict FD acts as CloseNow instead. Every later
// Close, and a Close of a zero, nil, released or abandoned FD, is a no-op.
func (f *FD) Close() error {
	if f == nil {
		return nil
	}
	for {
		s := f.state.Load()
		switch {
		case s&stOwns == 0 || s&stClosing != 0 && s&stStrict == 0:
			return nil
		case s&stStrict != 0:
			return f.closeNow(true)
		case s&stKept != 0: // an inert test owner (InertForTest): nothing to close
			ns := s | stClosing
			if s&leaseMask == 0 {
				ns |= stDone
			}
			if f.state.CompareAndSwap(s, ns) {
				return nil
			}
		case s&leaseMask == 0:
			if f.state.CompareAndSwap(s, s|stClosing|stClaimed) {
				return f.finishClose()
			}
		default:
			if f.state.CompareAndSwap(s, s|stClosing) {
				if testHooks != nil {
					testHooks.deferred(f)
				}
				return nil
			}
		}
	}
}

// CloseNow returns nil exactly when no number this FD owned is still open: close(2) has returned for it, on
// any path, or it never owned one. With no lease out it closes now and returns close(2)'s error (the number
// is freed either way). With a lease out, the close pending or not, it is ErrLeased and nothing changes;
// while another goroutine is inside close(2) for the number it waits for that one call. A released or
// abandoned FD is ErrClosed naming which: its number is open, and this FD will never close it.
func (f *FD) CloseNow() error {
	if f == nil {
		return nil
	}
	return f.closeNow(false)
}

// closeNow is CloseNow, and a strict FD's Close (asClose), which is a no-op on a kept FD.
func (f *FD) closeNow(asClose bool) error {
	for {
		s := f.state.Load()
		switch {
		case s&stOwns == 0:
			return nil
		case s&(stReleased|stAbandoned) != 0:
			if asClose {
				return nil
			}
			how := "released"
			if s&stAbandoned != 0 {
				how = "abandoned"
			}
			return fmt.Errorf("%w: its number was %s and is not this owner's to close", ErrClosed, how)
		case s&stDone != 0:
			return nil
		case s&stClaimed != 0:
			f.waitDone()
			return nil
		case s&leaseMask != 0:
			if testHooks != nil {
				return testHooks.leased(f)
			}
			return ErrLeased
		case s&stKept != 0: // an inert test owner
			if f.state.CompareAndSwap(s, s|stClosing|stDone) {
				return nil
			}
		default:
			if f.state.CompareAndSwap(s, s|stClosing|stClaimed) {
				return f.finishClose()
			}
		}
	}
}

// Abandon forgets the number without closing it: the one way to drop a number of lost or unknown identity,
// which enforce-landlock I12 leaves open rather than close another owner's file (A5). Leases out at the time
// go on and the last Return closes nothing; a pending deferred close is cancelled. Once close(2) is running,
// or the FD is closed, released or abandoned, it is a no-op. A lease holder whose FD is abandoned holds a
// number of unknown identity and re-verifies it before any grant made through it (runtime-launch R25).
func (f *FD) Abandon() {
	if f == nil {
		return
	}
	for {
		s := f.state.Load()
		if s&stOwns == 0 || s&(stKept|stClaimed|stDone) != 0 {
			return
		}
		ns := s | stClosing | stKept | stAbandoned
		if s&leaseMask == 0 {
			ns |= stDone
		}
		if f.state.CompareAndSwap(s, ns) {
			f.untrace()
			return
		}
	}
}

// give ends the ownership without closing: the number is the caller's from here on.
func (f *FD) give() (int, error) {
	if f == nil {
		return -1, ErrClosed
	}
	for {
		s := f.state.Load()
		switch {
		case s&stOwns == 0 || s&(stClosing|stKept) != 0:
			return -1, ErrClosed
		case s&leaseMask != 0:
			if testHooks != nil {
				return -1, testHooks.leased(f)
			}
			return -1, ErrLeased
		}
		if f.state.CompareAndSwap(s, s|stClosing|stKept|stReleased|stDone) {
			f.untrace()
			return int(f.num), nil
		}
	}
}

// Release hands the number to a new *os.File named name, for ExtraFiles or net.FileConn, and leaves this FD
// owning nothing. It is ErrLeased while a lease is out, and ErrClosed once the FD is closing or kept. The
// File then closes the number, from its own cleanup if it becomes unreachable, so it is kept reachable for as
// long as the number is meant to stay open (A8).
func (f *FD) Release(name string) (*os.File, error) {
	n, err := f.give()
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(n), name), nil
}

// ReleaseNumber hands the bare number to an API that takes ownership of it (link.NewFromFD,
// ebpf.NewMapFromFD, ebpf.NewProgramFromFD: ADR 0023 A10 F3), and leaves this FD owning nothing. Its errors
// are Release's.
func (f *FD) ReleaseNumber() (int, error) { return f.give() }

// Dup duplicates the number (F_DUPFD_CLOEXEC, at 3 or above) into a new owner whose lifetime is its own. The
// new FD is not strict; a caller that needs it strict wraps the call in Strict.
func (f *FD) Dup() (*FD, error) {
	if f == nil || !f.acquire() {
		return nil, ErrClosed
	}
	defer f.unlease()
	n, err := unix.FcntlInt(uintptr(f.num), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, fmt.Errorf("fcntl(%d, F_DUPFD_CLOEXEC): %w", f.num, err)
	}
	seal()
	return newFD(n, 0, true)
}

// OnClosed registers fn to run once close(2) has returned for the number, on whichever path closed it (Close,
// CloseNow, or the last Return of a deferred close), with close(2)'s error. Registered after the close, fn
// runs at once. One hook per FD: a second registration fails. A released or abandoned FD never runs it, so a
// dependency tied to the close stays unmet (fail closed) and OnClosed on one is ErrClosed. fn runs on the
// closing goroutine: it must not block, and must not call this FD.
func (f *FD) OnClosed(fn func(err error)) error {
	if f == nil || fn == nil {
		return ErrClosed
	}
	if st := f.state.Load(); st&stOwns == 0 || st&stKept != 0 {
		return ErrClosed
	}
	s := f.ensureSlow()
	s.mu.Lock()
	if f.state.Load()&stReturned != 0 {
		// close(2) has returned: its closer took no hook of ours, since it read the word before this
		// registration, so fn runs here, now.
		err := s.closeErr
		s.mu.Unlock()
		fn(err)
		return nil
	}
	if s.hookSet {
		s.mu.Unlock()
		return errHookSet
	}
	s.hook, s.hookSet = fn, true
	s.mu.Unlock()
	return nil
}

// String names the number for messages: "fd 7", or "fd 7 (closed)" once it lends nothing. It is not a lease:
// the number in it may name another file by the time the message is read.
func (f *FD) String() string {
	if f == nil {
		return "fd (nil)"
	}
	s := f.state.Load()
	if s&stOwns == 0 {
		return "fd (none)"
	}
	if s&stClosing != 0 {
		return "fd " + strconv.Itoa(int(f.num)) + " (closed)"
	}
	return "fd " + strconv.Itoa(int(f.num))
}

// The typed methods below are each one direct Borrow, with no closure and no allocation: they remove most of
// the closures a caller would write, and with them most chances to copy the number out of a lease (A11).

// Fstat is fstat(2) on the number.
func (f *FD) Fstat(st *unix.Stat_t) error {
	if f == nil || !f.acquire() {
		return ErrClosed
	}
	defer f.unlease()
	return unix.Fstat(int(f.num), st)
}

// Fstatat is fstatat(2) of name relative to the number.
func (f *FD) Fstatat(name string, st *unix.Stat_t, flags int) error {
	if f == nil || !f.acquire() {
		return ErrClosed
	}
	defer f.unlease()
	return unix.Fstatat(int(f.num), name, st, flags)
}

// Statx is statx(2) of name relative to the number; "" with AT_EMPTY_PATH is the file itself.
func (f *FD) Statx(name string, flags, mask int, stx *unix.Statx_t) error {
	if f == nil || !f.acquire() {
		return ErrClosed
	}
	defer f.unlease()
	return unix.Statx(int(f.num), name, flags, mask, stx)
}

// Openat is openat(2) of name relative to the number, owned at birth. flags must carry O_CLOEXEC.
func (f *FD) Openat(name string, flags int, mode uint32) (*FD, error) {
	if f == nil || !f.acquire() {
		return nil, ErrClosed
	}
	defer f.unlease()
	return Own(unix.Openat(int(f.num), name, flags, mode))
}

// Openat2 is openat2(2) of name relative to the number (Linux 5.6), owned at birth. how.Flags must carry
// O_CLOEXEC.
func (f *FD) Openat2(name string, how *unix.OpenHow) (*FD, error) {
	if f == nil || !f.acquire() {
		return nil, ErrClosed
	}
	defer f.unlease()
	return Own(unix.Openat2(int(f.num), name, how))
}

// Futimes sets the file's access and modification times (futimes(3)).
func (f *FD) Futimes(tv []unix.Timeval) error {
	if f == nil || !f.acquire() {
		return ErrClosed
	}
	defer f.unlease()
	return unix.Futimes(int(f.num), tv)
}

// Fsync is fsync(2).
func (f *FD) Fsync() error {
	if f == nil || !f.acquire() {
		return ErrClosed
	}
	defer f.unlease()
	return unix.Fsync(int(f.num))
}

// GetsockoptInt is getsockopt(2) of an int option.
func (f *FD) GetsockoptInt(level, opt int) (int, error) {
	if f == nil || !f.acquire() {
		return 0, ErrClosed
	}
	defer f.unlease()
	return unix.GetsockoptInt(int(f.num), level, opt)
}

// Flock is flock(2) on a strict FD, restarted on EINTR; any other is ErrNotStrict, since a lease could defer
// the Close that is meant to drop the lock (A1).
func (f *FD) Flock(how int) error {
	if f == nil || !f.acquire() {
		return ErrClosed
	}
	defer f.unlease()
	if f.state.Load()&stStrict == 0 {
		return ErrNotStrict
	}
	for {
		err := unix.Flock(int(f.num), how)
		if err != unix.EINTR {
			return err
		}
	}
}

// ProcPath runs fn with "/proc/self/fd/N" under a lease, for a Readlink or a reopen through the magic link
// while the number is sure to name this FD's file.
func (f *FD) ProcPath(fn func(path string) error) error {
	if f == nil || !f.acquire() {
		return ErrClosed
	}
	defer f.unlease()
	return fn("/proc/self/fd/" + strconv.Itoa(int(f.num)))
}
