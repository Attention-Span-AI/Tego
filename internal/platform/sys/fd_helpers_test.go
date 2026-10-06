// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// wantCloexec fails unless n carries FD_CLOEXEC.
func wantCloexec(t *testing.T, n int, what string) {
	t.Helper()
	fl, err := unix.FcntlInt(uintptr(n), unix.F_GETFD, 0)
	if err != nil || fl&unix.FD_CLOEXEC == 0 {
		t.Fatalf("%s (fd %d) is not close-on-exec: %#x, %v", what, n, fl, err)
	}
}

// TestPidfdOwnerForms: the pidfd producers' owner forms own a close-on-exec number naming what the int forms
// name. The thread form is handed the thread-group leader's id, which it opens on every supported kernel (from 6.9
// with PIDFD_THREAD, below it by the retry without the flag, TestPidfdOpenThreadAcceptsATgid); this goroutine's own
// tid is the leader's only when it happens to run on the main thread, so on a kernel without PIDFD_THREAD
// (TestKernelWithoutPidfdThread's emulation) the tid failed whenever the scheduler had put the test elsewhere.
func TestPidfdOwnerForms(t *testing.T) {
	p, err := PidfdOpenProcessFD(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	wantCloexec(t, numOf(p), "PidfdOpenProcessFD")
	if err := checkKind(numOf(p), KindPidfd); err != nil {
		t.Fatalf("PidfdOpenProcessFD's number is not a pidfd: %v", err)
	}
	th, err := PidfdOpenThreadFD(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer th.Close()
	wantCloexec(t, numOf(th), "PidfdOpenThreadFD")
	if err := checkKind(numOf(th), KindPidfd); err != nil {
		t.Fatalf("PidfdOpenThreadFD's number is not a pidfd: %v", err)
	}
	null := openNull(t)
	var got *FD
	if err := p.Borrow(func(pidfd int) error {
		return null.Borrow(func(n int) error {
			var err error
			got, err = Strict(PidfdGetfdFD(pidfd, n))
			return err
		})
	}); err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	if idOf(t, got) != idOf(t, null) {
		t.Fatal("PidfdGetfdFD's duplicate names another file")
	}
	wantCloexec(t, numOf(got), "PidfdGetfdFD")
	if _, err := PidfdOpenProcessFD(-5); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("PidfdOpenProcessFD(-5) = %v, want EINVAL", err)
	}
}

// TestSeccompNewListenerFDIsStrict: the listener is born strict, so a Close under a lease is refused rather
// than deferred (ADR 0023 A1), without installing a filter on the test's thread.
func TestSeccompNewListenerFDIsStrict(t *testing.T) {
	real := seccompSetFilter
	t.Cleanup(func() { seccompSetFilter = real })
	seccompSetFilter = func(uintptr, *unix.SockFprog) (int, unix.Errno) {
		n, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return -1, err.(unix.Errno)
		}
		return n, 0
	}
	prog, err := bpf.Assemble([]bpf.Instruction{bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW}})
	if err != nil {
		t.Fatal(err)
	}
	f, err := SeccompNewListenerFD(prog)
	if err != nil {
		t.Fatal(err)
	}
	l, err := f.Hold()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); !errors.Is(err, ErrLeased) {
		t.Fatalf("Close of the listener under a lease = %v, want ErrLeased (strict)", err)
	}
	l.Return()
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	seccompSetFilter = func(uintptr, *unix.SockFprog) (int, unix.Errno) { return -1, unix.EBUSY }
	if f, err := SeccompNewListenerFD(prog); f != nil || !errors.Is(err, unix.EBUSY) {
		t.Fatalf("a refused listener = %v, %v; want nil, EBUSY", f, err)
	}
}

// TestLandlockCreateRulesetFD: the ruleset is born an owner whose number answers as a ruleset.
func TestLandlockCreateRulesetFD(t *testing.T) {
	if _, err := LandlockABI(); err != nil {
		t.Skipf("no Landlock here: %v", err)
	}
	attr := LandlockRulesetAttr{Handled_access_fs: unix.LANDLOCK_ACCESS_FS_READ_FILE}
	f, err := LandlockCreateRulesetFD(&attr)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := checkKind(numOf(f), KindRuleset); err != nil {
		t.Fatalf("LandlockCreateRulesetFD's number: %v", err)
	}
	wantCloexec(t, numOf(f), "LandlockCreateRulesetFD")
}

// highRaw opens /dev/null without FD_CLOEXEC at a number of at least min, as a descriptor inherited without
// the flag would be. The test closes it.
func highRaw(t *testing.T, min int) int {
	t.Helper()
	n, err := unix.Open("/dev/null", unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(n)
	h, err := unix.FcntlInt(uintptr(n), unix.F_DUPFD, min)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(h) })
	return h
}

func cloexecOf(t *testing.T, n int) bool {
	t.Helper()
	fl, err := unix.FcntlInt(uintptr(n), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	return fl&unix.FD_CLOEXEC != 0
}

// TestCloexecFrom: every descriptor from first up gets FD_CLOEXEC and none below it does, by close_range and,
// where a seccomp profile refuses close_range, by the /proc/self/fd walk; when both fail the error comes back
// and the stage fails closed (ADR 0023 T1.3).
func TestCloexecFrom(t *testing.T) {
	below, above := highRaw(t, 700), highRaw(t, 900)
	if err := CloexecFrom(800); err != nil {
		t.Fatal(err)
	}
	if !cloexecOf(t, above) || cloexecOf(t, below) {
		t.Fatalf("after CloexecFrom(800): fd %d cloexec %v (want true), fd %d cloexec %v (want false)",
			above, cloexecOf(t, above), below, cloexecOf(t, below))
	}

	real := closeRangeCloexec
	t.Cleanup(func() { closeRangeCloexec = real })
	closeRangeCloexec = func(int) error { return unix.EPERM } // a seccomp profile that refuses close_range
	above2 := highRaw(t, 950)
	if err := CloexecFrom(800); err != nil {
		t.Fatalf("the /proc/self/fd fallback: %v", err)
	}
	if !cloexecOf(t, above2) || cloexecOf(t, below) {
		t.Fatal("the fallback walk did not set FD_CLOEXEC from 800 up alone")
	}

	prev := procSelfFD
	t.Cleanup(func() { procSelfFD = prev })
	procSelfFD = filepath.Join(t.TempDir(), "missing")
	if err := CloexecFrom(800); err == nil || !strings.Contains(err.Error(), "close_range") {
		t.Fatalf("CloexecFrom with both paths refused = %v, want an error naming both", err)
	}
}

// closeInheritedHelperEnv makes this test binary, re-executed by TestCloseInheritedFrom, sweep from 5 and print
// what it still holds.
const closeInheritedHelperEnv = "TEGO_SYS_CLOSE_INHERITED_HELPER"

// TestCloseInheritedFromHelper is TestCloseInheritedFrom's child, started through proc.Start with four
// descriptors at 3–6: it closes from 5 up and prints every descriptor it holds after.
func TestCloseInheritedFromHelper(t *testing.T) {
	if os.Getenv(closeInheritedHelperEnv) == "" {
		t.Skip("helper process for TestCloseInheritedFrom")
	}
	if err := CloseInheritedFrom(5); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		link, err := os.Readlink("/proc/self/fd/" + e.Name())
		if err != nil || link == "anon_inode:[eventpoll]" || link == "anon_inode:[eventfd]" {
			continue // the listing's own descriptor, and the Go runtime's poller
		}
		fmt.Printf("fd %s %s\n", e.Name(), link)
	}
}

// TestCloseInheritedFrom: a child started by proc.Start with descriptors 3–6 keeps exactly 0–4 after
// CloseInheritedFrom(5), the Go runtime's poller aside; and the sweep fails, closing nothing, when
// /proc/self/fd cannot be listed (ADR 0023: the reaper exits 125 rather than sweep blind).
func TestCloseInheritedFrom(t *testing.T) {
	dir := t.TempDir()
	var files []*os.File
	for i := range 4 {
		f, err := os.Create(filepath.Join(dir, "f"+strconv.Itoa(i)))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		files = append(files, f)
	}
	cmd := proc.Command(os.Args[0], "-test.run=^TestCloseInheritedFromHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), closeInheritedHelperEnv+"=1")
	cmd.ExtraFiles = files
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if _, err := proc.Start(cmd); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("the helper: %v\n%s", err, out.String())
	}
	var got []int
	names := map[int]string{}
	for _, line := range strings.Split(out.String(), "\n") {
		var n int
		var link string
		if _, err := fmt.Sscanf(line, "fd %d %s", &n, &link); err == nil {
			got = append(got, n)
			names[n] = link
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, []int{0, 1, 2, 3, 4}) {
		t.Fatalf("the child holds %v (%v), want 0-4:\n%s", got, names, out.String())
	}
	if names[3] != files[0].Name() || names[4] != files[1].Name() {
		t.Fatalf("3 and 4 name %q and %q, want the first two files", names[3], names[4])
	}

	prev, sealed := procSelfFD, ownersMade.Load()
	t.Cleanup(func() { procSelfFD = prev; ownersMade.Store(sealed) })
	procSelfFD = filepath.Join(t.TempDir(), "missing")
	ownersMade.Store(false)
	if err := CloseInheritedFrom(3); err == nil || errors.Is(err, ErrSealed) {
		t.Fatalf("CloseInheritedFrom with no listing = %v, want the listing's error", err)
	}
}

// TestCloseInheritedFromSealed: once this process has made an owner, the sweep refuses and closes nothing, as
// Inherited does (ADR 0023 A10, the seal): a sweep after that would close numbers live owners hold, and they
// would then close recycled numbers.
func TestCloseInheritedFromSealed(t *testing.T) {
	// The owner sits at 900 or above, so a sweep the seal failed to refuse closes nothing of the test binary's.
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	f, err := DupFile(null, 900)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Borrow(func(n int) error {
		if err := CloseInheritedFrom(n); !errors.Is(err, ErrSealed) {
			return fmt.Errorf("CloseInheritedFrom(%d) after DupFile = %v, want ErrSealed", n, err)
		}
		if _, err := unix.FcntlInt(uintptr(n), unix.F_GETFD, 0); err != nil {
			return fmt.Errorf("the owner's number %d after the refused sweep: %w", n, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestReceiveRights: every number an SCM_RIGHTS message carried is owned, naming the file that was sent; a
// buffer malformed after the first message leaves no number open; a payload that is not whole numbers is
// refused once its whole numbers are owned and closed.
func TestReceiveRights(t *testing.T) {
	a, b, err := Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()
	x, y := openNull(t), openNull(t)
	receive := func() []byte {
		t.Helper()
		if err := a.Borrow(func(an int) error {
			return x.Borrow(func(xn int) error {
				return y.Borrow(func(yn int) error {
					return unix.Sendmsg(an, []byte("r"), unix.UnixRights(xn, yn), nil, 0)
				})
			})
		}); err != nil {
			t.Fatal(err)
		}
		oob := make([]byte, unix.CmsgSpace(2*4))
		var oobn int
		if err := b.Borrow(func(bn int) error {
			var err error
			_, oobn, _, _, err = unix.Recvmsg(bn, make([]byte, 1), oob, unix.MSG_CMSG_CLOEXEC)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return oob[:oobn]
	}

	got, err := ReceiveRights(receive())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || idOf(t, got[0]) != idOf(t, x) || idOf(t, got[1]) != idOf(t, y) {
		t.Fatalf("ReceiveRights owned %v, want the two files sent", got)
	}
	for _, f := range got {
		wantCloexec(t, numOf(f), "a received number")
		_ = f.Close()
	}

	// A first message intact, then a header that claims more bytes than the buffer holds.
	oob := receive()
	nums := receivedNumbers(t, oob)
	bad := make([]byte, unix.CmsgSpace(0))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&bad[0]))
	h.Level, h.Type = unix.SOL_SOCKET, unix.SCM_RIGHTS
	h.SetLen(unix.CmsgLen(64))
	if _, err := ReceiveRights(append(oob, bad...)); err == nil {
		t.Fatal("ReceiveRights accepted a malformed second message")
	}
	for _, n := range nums {
		wantClosed(t, n, "a number from a buffer that failed to parse")
	}

	// A payload with a trailing partial number.
	oob = receive()
	nums = receivedNumbers(t, oob)
	short := make([]byte, unix.CmsgSpace(2*4+2))
	copy(short, oob)
	h = (*unix.Cmsghdr)(unsafe.Pointer(&short[0]))
	h.SetLen(unix.CmsgLen(2*4 + 2))
	if _, err := ReceiveRights(short); err == nil {
		t.Fatal("ReceiveRights accepted a payload of 10 bytes")
	}
	for _, n := range nums {
		wantClosed(t, n, "a whole number of a refused payload")
	}
}

// receivedNumbers reads the numbers of a one-message SCM_RIGHTS buffer the way the test, not the code under
// test, would.
func receivedNumbers(t *testing.T, oob []byte) []int {
	t.Helper()
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("parse: %v, %d messages", err, len(msgs))
	}
	nums, err := unix.ParseUnixRights(&msgs[0])
	if err != nil {
		t.Fatal(err)
	}
	return nums
}

// TestPipe2WriteEndIsStrict: both ends are owned and close-on-exec, and the write end's Close is never
// deferred: its EOF is what the reader waits for.
func TestPipe2WriteEndIsStrict(t *testing.T) {
	r, w, err := Pipe2(unix.O_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	wantCloexec(t, numOf(r), "the read end")
	wantCloexec(t, numOf(w), "the write end")
	if r.state.Load()&stStrict != 0 || w.state.Load()&stStrict == 0 {
		t.Fatal("want the write end strict and the read end not")
	}
	l, err := w.Hold()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); !errors.Is(err, ErrLeased) {
		t.Fatalf("Close of the write end under a lease = %v, want ErrLeased", err)
	}
	l.Return()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	var n int
	if err := r.Borrow(func(rn int) error {
		var rerr error
		n, rerr = unix.Read(rn, buf)
		return rerr
	}); err != nil || n != 0 {
		t.Fatalf("read after the write end closed = %d, %v; want EOF", n, err)
	}
}

// TestAccept4: the accepted connection is born an owner; a closed listener accepts nothing.
func TestAccept4(t *testing.T) {
	ln, err := Own(unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	path := filepath.Join(t.TempDir(), "s")
	if err := ln.Borrow(func(n int) error {
		if err := unix.Bind(n, &unix.SockaddrUnix{Name: path}); err != nil {
			return err
		}
		return unix.Listen(n, 1)
	}); err != nil {
		t.Fatal(err)
	}
	c, err := Own(unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Borrow(func(n int) error { return unix.Connect(n, &unix.SockaddrUnix{Name: path}) }); err != nil {
		t.Fatal(err)
	}
	conn, _, err := Accept4(ln, unix.SOCK_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	wantCloexec(t, numOf(conn), "the accepted connection")
	_ = ln.Close()
	if _, _, err := Accept4(ln, unix.SOCK_CLOEXEC); !errors.Is(err, ErrClosed) {
		t.Fatalf("Accept4 on a closed listener = %v, want ErrClosed", err)
	}
}

// TestFileHelpers: FileDo, DupFile, Flock and FstatFile work under the standard library's lease and refuse a
// closed File.
func TestFileHelpers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := FstatFile(f, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		t.Fatalf("FstatFile = %v, mode %#o", err, st.Mode)
	}
	d, err := DupFile(f, 128)
	if err != nil {
		t.Fatal(err)
	}
	if numOf(d) < 128 {
		t.Fatalf("DupFile(f, 128) gave %d", numOf(d))
	}
	wantCloexec(t, numOf(d), "DupFile")
	if err := Flock(f, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("Flock = %v", err)
	}
	other, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := Flock(other, unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("a second Flock = %v, want EWOULDBLOCK", err)
	}
	ran := false
	if err := FileDo(f, func(int) error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("FileDo = %v, ran %v", err, ran)
	}
	_ = f.Close()
	if err := FileDo(f, func(int) error { t.Fatal("fn ran on a closed File"); return nil }); err == nil {
		t.Fatal("FileDo on a closed File succeeded")
	}
	if _, err := DupFile(f, 3); err == nil {
		t.Fatal("DupFile of a closed File succeeded")
	}
	if err := FileDo(nil, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("FileDo(nil) = %v", err)
	}
	_ = d.Close()
}

// TestInertForTest: an inert owner lends its number like any other and never closes it.
func TestInertForTest(t *testing.T) {
	n := highRaw(t, 600)
	id, err := statNum(n)
	if err != nil {
		t.Fatal(err)
	}
	f := InertForTest(n)
	if err := f.Borrow(func(m int) error {
		if m != n {
			return fmt.Errorf("lent %d, want %d", m, n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	l, err := f.Hold()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.CloseNow(); !errors.Is(err, ErrLeased) {
		t.Fatalf("CloseNow under a lease = %v, want ErrLeased", err)
	}
	_ = f.Close()
	l.Return()
	if err := f.CloseNow(); err != nil {
		t.Fatalf("CloseNow after the inert close = %v", err)
	}
	if err := f.OnClosed(func(error) {}); !errors.Is(err, ErrClosed) {
		t.Fatalf("OnClosed on an inert owner = %v, want ErrClosed", err)
	}
	wantOpen(t, n, id, "an inert owner closed")
	if err := f.Borrow(func(int) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("Borrow after Close = %v, want ErrClosed", err)
	}
}
