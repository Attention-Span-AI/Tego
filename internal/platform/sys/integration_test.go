// SPDX-License-Identifier: Apache-2.0

//go:build integration

package sys

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// notifyGetppidFilter notifies getppid and allows everything else, after an arch guard.
func notifyGetppidFilter(t *testing.T) []bpf.RawInstruction {
	prog, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 4, Size: 4}, // seccomp_data.arch
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: auditArch(t), SkipTrue: 1},
		bpf.RetConstant{Val: unix.SECCOMP_RET_KILL_PROCESS},
		bpf.LoadAbsolute{Off: 0, Size: 4}, // seccomp_data.nr
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.SYS_GETPPID, SkipTrue: 1},
		bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW},
		bpf.RetConstant{Val: unix.SECCOMP_RET_USER_NOTIF},
	})
	if err != nil {
		t.Fatal(err)
	}
	return prog
}

// TestSeccompNotifyRoundTrip installs a NEW_LISTENER filter on one locked thread, makes a notified syscall
// from it and serves the notification from another goroutine (another thread) with CONTINUE.
func TestSeccompNotifyRoundTrip(t *testing.T) {
	runtime.LockOSThread() // never unlocked: the filtered thread retires with this goroutine
	want := os.Getppid()   // read before the filter: every later getppid on this thread is notified
	tid := unix.Gettid()
	if err := SetNoNewPrivs(); err != nil {
		t.Fatal(err)
	}
	fd, err := SeccompSetFilterNewListener(notifyGetppidFilter(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })

	type served struct {
		n     SeccompNotif
		valid bool
		err   error
	}
	done := make(chan served, 1)
	go func() {
		var s served
		if s.err = SeccompNotifRecv(fd, &s.n); s.err == nil {
			s.valid, s.err = SeccompNotifIDValid(fd, s.n.ID)
			if s.err == nil {
				s.err = SeccompNotifSend(fd, &SeccompNotifResp{ID: s.n.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE})
			}
		}
		done <- s
	}()

	got := unix.Getppid()
	if got != want {
		t.Fatalf("getppid through CONTINUE = %d, want %d", got, want)
	}
	select {
	case s := <-done:
		if s.err != nil {
			t.Fatal(s.err)
		}
		if s.n.Data.Nr != unix.SYS_GETPPID || s.n.Pid != uint32(tid) || !s.valid {
			t.Fatalf("notification %+v valid=%v: want nr=%d pid(tid)=%d valid", s.n, s.valid, unix.SYS_GETPPID, tid)
		}
		if s.n.Data.Arch != auditArch(t) {
			t.Fatalf("arch %#x, want %#x", s.n.Data.Arch, auditArch(t))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("notification never served")
	}
	// A second install on the same thread must fail EBUSY: the chain already has a listener (case 6).
	if _, err := SeccompSetFilterNewListener(notifyGetppidFilter(t)); !errors.Is(err, unix.EBUSY) {
		t.Fatalf("second NEW_LISTENER = %v, want EBUSY", err)
	}
	if valid, err := SeccompNotifIDValid(fd, 0xdeadbeef); err != nil || valid {
		t.Fatalf("ID_VALID on an unknown id: valid=%v err=%v", valid, err)
	}
}

// TestLandlockRestrictSelf builds an ABI-1 ruleset with the raw wrappers, applies the production flag
// fallback wrapper on the locked thread and
// checks a write inside the allowed directory succeeds while one outside is EACCES.
func TestLandlockRestrictSelf(t *testing.T) {
	_, err := LandlockABI()
	if err != nil {
		t.Skipf("Landlock unavailable: %v", err)
	}
	// Directories are made and removed on unrestricted threads: the test thread stays Landlocked.
	allowed, err := os.MkdirTemp("", "ll-allowed")
	if err != nil {
		t.Fatal(err)
	}
	denied, err := os.MkdirTemp("", "ll-denied")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		done := make(chan struct{})
		go func() { os.RemoveAll(allowed); os.RemoveAll(denied); close(done) }()
		<-done
	})

	runtime.LockOSThread()
	attr := LandlockRulesetAttr{Handled_access_fs: LandlockAccessFSABI1}
	rs, err := LandlockCreateRuleset(&attr, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rs)
	dir, err := unix.Open(allowed, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dir)
	if err := LandlockAddRule(rs, unix.LANDLOCK_RULE_PATH_BENEATH, unsafe.Pointer(&unix.LandlockPathBeneathAttr{Allowed_access: LandlockAccessFSABI1, Parent_fd: int32(dir)}), 0); err != nil {
		t.Fatal(err)
	}
	if err := LandlockAddRule(rs, unix.LANDLOCK_RULE_PATH_BENEATH, unsafe.Pointer(&unix.LandlockPathBeneathAttr{Allowed_access: LandlockAccessFSABI1, Parent_fd: int32(-1)}), 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("add_rule with a bad parent fd = %v, want EBADF", err)
	}
	// EPERM is the kernel's fixed answer only for a thread with neither no_new_privs nor CAP_SYS_ADMIN. A test
	// binary that inherited no_new_privs (setpriv --no-new-privs, a container run with no-new-privileges, a
	// shell inside a `tego run` on the unprivileged order) can never clear it, so the call succeeds; one
	// whose effective set holds CAP_SYS_ADMIN (run as root) succeeds unless an LSM denies the capability
	// (AppArmor's unprivileged_userns profile does in a user namespace, measured on 6.17). Neither answer says
	// anything about the wrapper, so the refusal is asserted only where it is the only answer.
	nnp, err := NoNewPrivs()
	if err != nil {
		t.Fatal(err)
	}
	sysAdmin := threadCapSet(t, "CapEff")&(1<<unix.CAP_SYS_ADMIN) != 0
	if nnp || sysAdmin {
		t.Logf("not checking restrict_self's EPERM: this thread has no_new_privs=%v CAP_SYS_ADMIN=%v", nnp, sysAdmin)
	} else if err := LandlockRestrictSelf(rs, 0); !errors.Is(err, unix.EPERM) {
		t.Fatalf("restrict_self without no_new_privs = %v, want EPERM", err)
	}
	if err := SetNoNewPrivs(); err != nil {
		t.Fatal(err)
	}
	if err := RestrictSelf(rs, LandlockNoNewPrivs|LandlockLogSameExecOff|LandlockLogSubdomainsOff); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(allowed, "f"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write inside the allowed directory: %v", err)
	}
	err = os.WriteFile(filepath.Join(denied, "f"), []byte("x"), 0o600)
	if !errors.Is(err, unix.EACCES) {
		t.Fatalf("write outside = %v, want EACCES", err)
	}
}

// TestSeccompNotifSetFlagsSyncWakeUp exercises SECCOMP_IOCTL_NOTIF_SET_FLAGS against a real listener.
// SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP (Linux 6.6, commit 48a1084ade02) hands the CPU from the notified task
// straight to the supervisor; below 6.6 the ioctl does not exist. Tego's tested floor is 6.1, so the only
// correct use is a probe — this asserts what the probe must distinguish, including that an unknown flag is
// refused rather than silently accepted.
func TestSeccompNotifSetFlagsSyncWakeUp(t *testing.T) {
	runtime.LockOSThread() // never unlocked: the filtered thread retires with this goroutine
	if err := SetNoNewPrivs(); err != nil {
		t.Fatal(err)
	}
	fd, err := SeccompSetFilterNewListener(notifyGetppidFilter(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })

	// Below 6.6 the ioctl number itself is unknown and seccomp_notify_ioctl's default case answers EINVAL
	// — the same errno a correctly-numbered call gets for a malformed argument — so the kernel version is
	// what separates "this kernel cannot" from "this wrapper is wrong", and only the former may skip.
	kv, err := Kernel()
	if err != nil {
		t.Fatal(err)
	}
	err = SeccompNotifSetFlags(fd, SeccompUserNotifFdSyncWakeUp)
	if err != nil && !kv.AtLeast(6, 6) {
		t.Skipf("kernel %s predates SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP: %v", kv, err)
	}
	if err != nil {
		t.Fatalf("SET_FLAGS(SYNC_WAKE_UP) on kernel %s = %v", kv, err)
	}
	// The kernel validates the flag word, so a future flag this build does not know cannot be set by
	// accident: seccomp_notify_set_flags rejects anything outside the known mask.
	if err := SeccompNotifSetFlags(fd, 1<<20); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("SET_FLAGS with an unknown flag = %v, want EINVAL", err)
	}
	// Setting it twice is idempotent: the probe may run on a listener that already carries the flag.
	if err := SeccompNotifSetFlags(fd, SeccompUserNotifFdSyncWakeUp); err != nil {
		t.Fatalf("SET_FLAGS(SYNC_WAKE_UP) twice = %v", err)
	}
}

// TestSeccompListenerIsWaitKillable proves the listener carries WAIT_KILLABLE_RECV on a kernel that has it
// (5.19+). Once the supervisor has received a notification, a non-fatal signal to the target must not
// withdraw it: that withdrawal is what made the kernel restart a connect or send the supervisor had already
// performed (docs/p0/supervisor.md E35). SIGURG is non-fatal here because the Go runtime handles it. Without
// the flag the signal cancels the notification (ID_VALID false) and the restarted syscall notifies again,
// which the server below answers too, so the test fails rather than hangs.
func TestSeccompListenerIsWaitKillable(t *testing.T) {
	kv, err := Kernel()
	if err != nil {
		t.Fatal(err)
	}
	if !kv.AtLeast(5, 19) {
		t.Skipf("kernel %s predates SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV", kv)
	}
	runtime.LockOSThread() // never unlocked: the filtered thread retires with this goroutine
	want := os.Getppid()
	pid, tid := os.Getpid(), unix.Gettid()
	if err := SetNoNewPrivs(); err != nil {
		t.Fatal(err)
	}
	fd, err := SeccompSetFilterNewListener(notifyGetppidFilter(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })

	type served struct {
		validAfterSignal bool
		err              error
	}
	done := make(chan served, 1)
	go func() {
		var s served
		var n SeccompNotif
		if s.err = SeccompNotifRecv(fd, &n); s.err != nil {
			done <- s
			return
		}
		if s.err = unix.Tgkill(pid, tid, unix.SIGURG); s.err != nil {
			done <- s
			return
		}
		time.Sleep(100 * time.Millisecond) // the signal is delivered, or ignored, well inside this
		if s.validAfterSignal, s.err = SeccompNotifIDValid(fd, n.ID); s.err != nil {
			done <- s
			return
		}
		if !s.validAfterSignal {
			// Withdrawn: the kernel restarts getppid and notifies again. Answer that one so the thread
			// is not left blocked with nobody serving it.
			if s.err = SeccompNotifRecv(fd, &n); s.err != nil {
				done <- s
				return
			}
		}
		s.err = SeccompNotifSend(fd, &SeccompNotifResp{ID: n.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE})
		done <- s
	}()

	if got := unix.Getppid(); got != want {
		t.Fatalf("getppid through CONTINUE = %d, want %d", got, want)
	}
	select {
	case s := <-done:
		if s.err != nil {
			t.Fatal(s.err)
		}
		if !s.validAfterSignal {
			t.Fatal("a non-fatal signal withdrew a received notification: the listener has no WAIT_KILLABLE_RECV")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("notification never served")
	}
}
