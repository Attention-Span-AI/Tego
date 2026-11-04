// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"errors"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestDispatchTables checks both architectures' tables against R1's syscall list on whichever host runs
// the suite: the numbers are compile-time data, so they are checkable without the kernel (I8).
func TestDispatchTables(t *testing.T) {
	tests := []struct {
		arch uint32
		want map[string]int32
	}{
		{
			arch: auditArchX86,
			want: map[string]int32{
				"pidfd_getfd": 438, "connect": 42, "sendto": 44, "sendmsg": 46, "sendmmsg": 307, "bind": 49, "listen": 50,
				"execve": 59, "execveat": 322,
				"open": 2, "openat": 257, "creat": 85,
				"unlink": 87, "unlinkat": 263,
				"rename": 82, "renameat": 264, "renameat2": 316,
				"mkdir": 83, "mkdirat": 258, "rmdir": 84,
				"symlink": 88, "symlinkat": 266,
				"link": 86, "linkat": 265, "mknod": 133, "mknodat": 259,
				"truncate": 76, "chmod": 90, "fchmod": 91, "fchmodat": 268, "fchmodat2": 452,
				"setxattr": 188, "lsetxattr": 189, "fsetxattr": 190, "removexattr": 197, "lremovexattr": 198,
				"fremovexattr": 199, "setxattrat": 463, "removexattrat": 466,
				"chown": 92, "fchown": 93, "lchown": 94, "fchownat": 260,
				"mount": 165, "umount2": 166, "pivot_root": 155, "move_mount": 429,
				"add_key": 248, "request_key": 249, "keyctl": 250, "unshare": 272, "clone": 56, "setns": 308,
				"shmget": 29, "shmat": 30, "shmctl": 31, "semget": 64, "semop": 65, "semctl": 66,
				"msgget": 68, "msgsnd": 69, "msgrcv": 70, "msgctl": 71, "semtimedop": 220,
				"socket": 41, "socketpair": 53, "setsockopt": 54, "sendfile": 40, "splice": 275,
				"kill": 62, "tkill": 200, "tgkill": 234, "rt_sigqueueinfo": 129, "rt_tgsigqueueinfo": 297, "fcntl": 72, "ioctl": 16,
				"prlimit64": 302, "sched_setparam": 142, "sched_setscheduler": 144, "sched_setaffinity": 203,
				"sched_setattr": 314, "setpriority": 141, "ioprio_set": 251,
				"inotify_add_watch": 254, "fanotify_mark": 301,
			},
		},
		{
			arch: auditArchARM,
			want: map[string]int32{
				"pidfd_getfd": 438, "connect": 203, "sendto": 206, "sendmsg": 211, "sendmmsg": 269, "bind": 200, "listen": 201,
				"execve": 221, "execveat": 281,
				"openat": 56, "unlinkat": 35, "renameat": 38, "renameat2": 276,
				"mkdirat": 34, "symlinkat": 36, "linkat": 37, "mknodat": 33,
				"truncate": 45, "fchmod": 52, "fchmodat": 53, "fchmodat2": 452,
				"setxattr": 5, "lsetxattr": 6, "fsetxattr": 7, "removexattr": 14, "lremovexattr": 15,
				"fremovexattr": 16, "setxattrat": 463, "removexattrat": 466, "fchownat": 54, "fchown": 55,
				"mount": 40, "umount2": 39, "pivot_root": 41, "move_mount": 429,
				"add_key": 217, "request_key": 218, "keyctl": 219, "unshare": 97, "clone": 220, "setns": 268,
				"msgget": 186, "msgctl": 187, "msgrcv": 188, "msgsnd": 189, "semget": 190, "semctl": 191,
				"semtimedop": 192, "semop": 193, "shmget": 194, "shmctl": 195, "shmat": 196,
				"socket": 198, "socketpair": 199, "setsockopt": 208, "sendfile": 71, "splice": 76,
				"kill": 129, "tkill": 130, "tgkill": 131, "rt_sigqueueinfo": 138, "rt_tgsigqueueinfo": 240, "fcntl": 25, "ioctl": 29,
				"prlimit64": 261, "sched_setparam": 118, "sched_setscheduler": 119, "sched_setaffinity": 122,
				"sched_setattr": 274, "setpriority": 140, "ioprio_set": 30,
				"inotify_add_watch": 27, "fanotify_mark": 263,
			},
		},
	}
	for _, tc := range tests {
		tbl := buildDispatchFor(tc.arch)
		if len(tbl) != len(tc.want) {
			t.Errorf("arch %#x: %d entries, want %d", tc.arch, len(tbl), len(tc.want))
		}
		for name, nr := range tc.want {
			e, ok := tbl[dispatchKey{arch: tc.arch, nr: nr}]
			if !ok {
				t.Errorf("arch %#x: no entry for %s (%d)", tc.arch, name, nr)
				continue
			}
			if e.name != name {
				t.Errorf("arch %#x: nr %d is %s, want %s", tc.arch, nr, e.name, name)
			}
			if e.fn == nil {
				t.Errorf("arch %#x: %s has no handler", tc.arch, name)
			}
		}
		for k, e := range tbl {
			if k.arch != tc.arch {
				t.Errorf("entry %s is keyed to arch %#x, want %#x", e.name, k.arch, tc.arch)
			}
		}
	}
	if len(buildDispatch()) == 0 {
		t.Fatal("the native table is empty")
	}
}

// TestEveryHandlerFaultRefuses is R25 (b) and I11 on every row of both dispatch tables: a handler that panics or returns
// without answering is refused, whatever the row, and an observe run continues it (R30). Only the handler knew what the
// rules said of the call, and a row that continued a fault gave up that much: a held read, a write a live block names.
func TestEveryHandlerFaultRefuses(t *testing.T) {
	for _, arch := range []uint32{auditArchX86, auditArchARM} {
		for key, e := range buildDispatchFor(arch) {
			for _, fault := range []struct {
				how string
				fn  handlerFunc
			}{
				{"panics", func(*Loop, *notif) { panic("a bounds bug in a handler") }},
				{"returns unanswered", func(*Loop, *notif) {}},
			} {
				for _, observe := range []bool{false, true} {
					f := newFake()
					pol := testPolicy(nil, nil, nil)
					pol.Observe = observe
					l, _ := newTestLoop(t, f, pol)
					l.dispatch = buildDispatchFor(arch)
					row := e
					row.fn = fault.fn
					l.dispatch[key] = row
					n := notifFor(key.nr, 42)
					n.arch = arch
					l.handle(n)
					got, ok := f.lastResp()
					if !ok {
						t.Fatalf("%x/%s %s: no answer (I12)", arch, e.name, fault.how)
					}
					continued := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0
					if continued != observe || !observe && got.Error != -int32(refusalErrno) {
						t.Errorf("%x/%s %s, observe %v: answered %+v", arch, e.name, fault.how, observe, got)
					}
				}
			}
		}
	}
}

// TestResponseShapes pins R18's three shapes.
func TestResponseShapes(t *testing.T) {
	tests := []struct {
		name  string
		in    resp
		cont  bool
		errno int32
		val   int64
	}{
		{name: "continue", in: respContinue(), cont: true},
		{name: "errno", in: respErrno(unix.EACCES), errno: -int32(unix.EACCES), val: -1},
		{name: "relayed success", in: respResult(17, nil), val: 17},
		{name: "relayed errno", in: respResult(0, unix.ECONNREFUSED), errno: -int32(unix.ECONNREFUSED), val: -1},
		{name: "relayed pending", in: respResult(0, unix.EINPROGRESS), errno: -int32(unix.EINPROGRESS), val: -1},
		{name: "relayed non-errno", in: respResult(0, errors.New("x")), errno: -int32(unix.EACCES), val: -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			l, _ := newTestLoop(t, f, testPolicy(nil, nil, nil))
			n := notifFor(connectNR(), 42)
			l.respond(n, tc.in)
			got, ok := f.lastResp()
			if !ok {
				t.Fatal("no response")
			}
			isCont := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0
			if isCont != tc.cont || (!tc.cont && (got.Error != tc.errno || got.Val != tc.val)) {
				t.Errorf("response = %+v, want cont=%v errno=%d val=%d", got, tc.cont, tc.errno, tc.val)
			}
			l.respond(n, respContinue())
			if f.respCount() != 1 {
				t.Errorf("responses = %d, want exactly one per notification (I11)", f.respCount())
			}
		})
	}
}

// TestUnknownSyscallIsRefused is R1/E21 with ADR 0018's default: a number the table has no entry for is
// refused ENOSYS, as the kernel refuses it once the listener is gone. It was continued, so a refusal by
// notification alone failed open on a missing or misnumbered entry.
func TestUnknownSyscallIsRefused(t *testing.T) {
	f := newFake()
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
	l.handle(notifFor(999, 42))
	got, _ := f.lastResp()
	if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(unix.ENOSYS) {
		t.Errorf("response = %+v, want ENOSYS", got)
	}
	if evs := sink.all(); len(evs) != 0 {
		t.Errorf("events = %d, want none", len(evs))
	}
}

// TestSocketOutsideTheAllowlistIsRefusedAndRecorded is ADR 0018's handler: a socket or socketpair the filter
// did not admit is refused with the errno a kernel without it answers, never continued, and recorded as a
// refused line naming the triple.
func TestSocketOutsideTheAllowlistIsRefusedAndRecorded(t *testing.T) {
	socketNR, pairNR := int32(nrX86Socket), int32(nrX86Socketpair)
	if nativeAuditArch() == auditArchARM {
		socketNR, pairNR = nrARMSocket, nrARMSocketpair
	}
	for _, tc := range []struct {
		name   string
		nr     int32
		args   []uint64
		errno  unix.Errno
		op     string
		target string
	}{
		{"sctp", socketNR, []uint64{unix.AF_INET, unix.SOCK_STREAM | unix.SOCK_CLOEXEC, 132}, unix.EPROTONOSUPPORT, "socket", "AF_INET SOCK_STREAM protocol 132"},
		{"udp-lite on v6", socketNR, []uint64{unix.AF_INET6, unix.SOCK_DGRAM, 136}, unix.EPROTONOSUPPORT, "socket", "AF_INET6 SOCK_DGRAM protocol 136"},
		{"vsock", socketNR, []uint64{unix.AF_VSOCK, unix.SOCK_STREAM, 0}, unix.EAFNOSUPPORT, "socket", "AF_VSOCK SOCK_STREAM protocol 0"},
		{"netlink generic", socketNR, []uint64{unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_GENERIC}, unix.EPROTONOSUPPORT, "socket", "AF_NETLINK SOCK_RAW protocol 16"},
		{"netlink sock_diag", socketNR, []uint64{unix.AF_NETLINK, unix.SOCK_DGRAM | unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG}, unix.EPROTONOSUPPORT, "socket", "AF_NETLINK SOCK_DGRAM protocol 4"},
		{"an unnamed family", socketNR, []uint64{250, 7, 3}, unix.EAFNOSUPPORT, "socket", "family 250 type 7 protocol 3"},
		{"socketpair tipc", pairNR, []uint64{unix.AF_TIPC, unix.SOCK_SEQPACKET, 0}, unix.EAFNOSUPPORT, "socketpair", "AF_TIPC SOCK_SEQPACKET protocol 0"},
		{"socketpair inet", pairNR, []uint64{unix.AF_INET, unix.SOCK_STREAM, 0}, unix.EAFNOSUPPORT, "socketpair", "AF_INET SOCK_STREAM protocol 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
			l.handle(notifFor(tc.nr, 42, tc.args...))
			got, _ := f.lastResp()
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(tc.errno) {
				t.Fatalf("response = %+v, want %v", got, tc.errno)
			}
			ev := sink.one(t)
			var p record.RefusedPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if ev.Kind != record.KindRefused || ev.Reason != record.ReasonNetNotAllowed || ev.Rule != agent.UnmatchedRule ||
				p.Op != tc.op || p.Target != tc.target {
				t.Errorf("event %s reason=%s rule=%s payload %+v", ev.Kind, ev.Reason, ev.Rule, p)
			}
		})
	}
}

// TestTCPULPIsRefusedAndRecorded is ADR 0018 (7): under a net: section the filter notifies
// setsockopt(SOL_TCP, TCP_ULP), which turned an admitted TCP socket into an AF_SMC one ("smc"), and the handler refuses
// it whatever the name, with ENOENT, what a kernel without that ULP answers, so a runtime that tries kTLS falls back.
// It is never continued, and each refusal is a refused line naming the ULP as the agent's memory held it, at most the
// 15 bytes the kernel reads; a name it cannot read is said to be unread, and the refusal stands. Any other option at
// this handler, which the filter never notifies, is refused too, naming its numbers.
func TestTCPULPIsRefusedAndRecorded(t *testing.T) {
	nr := int32(nrX86Setsockopt)
	if nativeAuditArch() == auditArchARM {
		nr = nrARMSetsockopt
	}
	const addr = 0x7000
	for _, tc := range []struct {
		name   string
		mem    []byte
		args   []uint64
		errno  unix.Errno
		target string
	}{
		{"smc", []byte("smc\x00"), []uint64{3, unix.SOL_TCP, unix.TCP_ULP, addr, 4}, unix.ENOENT, `TCP_ULP "smc"`},
		{"tls, no NUL", []byte("tls"), []uint64{3, unix.SOL_TCP, unix.TCP_ULP, addr, 3}, unix.ENOENT, `TCP_ULP "tls"`},
		{"a long name is cut where the kernel cuts it", []byte("abcdefghijklmnopqrstuvwxyz"),
			[]uint64{3, unix.SOL_TCP, unix.TCP_ULP, addr, 26}, unix.ENOENT, `TCP_ULP "abcdefghijklmno"`},
		{"optlen bounds the name", []byte("smc-extra"), []uint64{3, unix.SOL_TCP, unix.TCP_ULP, addr, 3}, unix.ENOENT, `TCP_ULP "smc"`},
		{"an unreadable name", nil, []uint64{3, unix.SOL_TCP, unix.TCP_ULP, 0xdead0000, 4}, unix.ENOENT, "TCP_ULP (name unread)"},
		{"int truncation", []byte("smc\x00"), []uint64{3, 7<<32 | unix.SOL_TCP, 9<<32 | unix.TCP_ULP, addr, 4}, unix.ENOENT, `TCP_ULP "smc"`},
		{"an option the filter never notifies", nil, []uint64{3, unix.SOL_TCP, unix.TCP_NODELAY, addr, 4}, unix.EPERM,
			"setsockopt level 6 option 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			if tc.mem != nil {
				f.put(addr, tc.mem)
			}
			l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
			l.handle(notifFor(nr, 42, tc.args...))
			got, _ := f.lastResp()
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(tc.errno) {
				t.Fatalf("response = %+v, want %v", got, tc.errno)
			}
			ev := sink.one(t)
			var p record.RefusedPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if ev.Kind != record.KindRefused || ev.Reason != record.ReasonNetNotAllowed || ev.Rule != agent.UnmatchedRule ||
				p.Op != "setsockopt" || p.Target != tc.target || p.Mechanism != "" {
				t.Errorf("event %s reason=%s rule=%s payload %+v, want op setsockopt target %q", ev.Kind, ev.Reason, ev.Rule, p, tc.target)
			}
		})
	}
}

// TestPanicContainment is R25/I12/E34: a panicking handler answers fail-closed, records a gap, and leaves
// the worker and its siblings running.
func TestPanicContainment(t *testing.T) {
	f := newFake()
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
	const nr = 4242
	l.dispatch[dispatchKey{arch: nativeAuditArch(), nr: nr}] = entry{
		name: "boom", fn: func(*Loop, *notif) { panic("a bounds bug in a reader") },
	}
	l.handle(notifFor(nr, 42))
	got, ok := f.lastResp()
	if !ok {
		t.Fatal("a panicking handler left the target unanswered (I12)")
	}
	if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(unix.EACCES) {
		t.Errorf("response = %+v, want errno %d", got, -int32(unix.EACCES))
	}
	ev := sink.one(t)
	if ev.Kind != record.KindGap {
		t.Fatalf("event kind = %s, want gap", ev.Kind)
	}
	var p record.GapPayload
	if err := ev.DecodePayload(&p); err != nil || p.What != record.GapRecord || p.Why != "handler-panic" {
		t.Errorf("gap = %+v (%v)", p, err)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("gap event does not validate: %v", err)
	}

	// The loop still works afterwards.
	f.put(0x1000, cstr("/tmp/x"))
	l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, 0x1000, 0x241))
	if f.respCount() != 2 {
		t.Errorf("responses = %d, want the next notification answered too", f.respCount())
	}
}

// TestPanicWithDeadTargetIsAbandoned: a panic on a notification whose target already died leaves
// no response behind.
func TestPanicWithDeadTargetIsAbandoned(t *testing.T) {
	f := newFake()
	f.stale[7] = true
	l, _ := newTestLoop(t, f, testPolicy(nil, nil, nil))
	const nr = 4243
	l.dispatch[dispatchKey{arch: nativeAuditArch(), nr: nr}] = entry{
		name: "boom", fn: func(*Loop, *notif) { panic("x") },
	}
	l.handle(notifFor(nr, 42))
	if f.respCount() != 0 {
		t.Errorf("responses = %d, want none for a dead target (R19)", f.respCount())
	}
}

// TestHandlerThatForgetsToAnswer is the safety net behind I11: the target is never left blocked.
func TestHandlerThatForgetsToAnswer(t *testing.T) {
	f := newFake()
	l, _ := newTestLoop(t, f, testPolicy(nil, nil, nil))
	const nr = 4244
	l.dispatch[dispatchKey{arch: nativeAuditArch(), nr: nr}] = entry{
		name: "silent", fn: func(*Loop, *notif) {},
	}
	l.handle(notifFor(nr, 42))
	got, ok := f.lastResp()
	if !ok || got.Error != -int32(unix.EACCES) {
		t.Errorf("response = %+v, want the fail-closed answer", got)
	}
}

// TestRunDrainsAndStops runs the real loop over the fake listener: every queued notification is answered
// exactly once, the counters add up, and a cancelled context returns promptly.
//
// It still polls the real clock (waitFor, and a 3 s bound on Run's return) rather than running in a
// testing/synctest bubble as the other time-dependent tests do, because a bubble cannot run
// this loop: Run's workers take turns at poll+RECV under recvMu, a sync.Mutex, and a goroutine blocked on
// a sync.Mutex is not durably blocked in a bubble, so while one worker sleeps in the fake's Wait holding
// the lock the bubble's clock never advances and the test hangs. Condition for moving it: receive
// serializes its workers on something a bubble counts as durably blocking, such as a one-slot channel in
// place of recvMu, a change to supervisor.go by the supervisor owner; the test then needs no real clock.
func TestRunDrainsAndStops(t *testing.T) {
	f := newFake()
	f.put(0x1000, cstr("/work/x"))
	const count = 32
	nr := nrFor(t, "openat")
	for i := 0; i < count; i++ {
		f.queue(sysNotif{ID: uint64(i + 1), Pid: 42, Data: sysData(nr, argCWD, 0x1000, 0x241)})
	}
	fs := []agent.FSRule{{Path: "/work", Kind: agent.FSWrite}}
	sink := &testSink{}
	// What the loop starts, it ends. Other tests' asynchronous closes and os.File cleanups can
	// shrink the process-wide descriptor count; only growth is a leak. Check this loop's own
	// listener and wake pipe below as well (the package's goroutine gate sees only permanent blocks).
	g0, fd0 := runtime.NumGoroutine(), openFDs(t)
	l, err := New(testListener(), testPolicy(nil, fs, nil), sink, Options{kernel: f, Workers: 4})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	waitFor(t, func() bool { return f.respCount() == count })
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after the context was cancelled (E24)")
	}
	for deadline := time.Now().Add(2 * time.Second); runtime.NumGoroutine() > g0 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	if g, fd := runtime.NumGoroutine(), openFDs(t); g > g0 || fd > fd0 {
		t.Errorf("after Run returned: %d goroutines (%d before New), %d descriptors (%d before)", g, g0, fd, fd0)
	}
	if !f.closedList || l.wakeR != -1 || l.wakeW != -1 {
		t.Errorf("Run left resources open: listener closed=%v, wake pipe=%d/%d", f.closedList, l.wakeR, l.wakeW)
	}
	m := l.Metrics()
	if m.Notifications != count {
		t.Errorf("notifications = %d, want %d", m.Notifications, count)
	}
	if len(sink.all()) != count {
		t.Errorf("events = %d, want %d", len(sink.all()), count)
	}
	if err := l.Run(context.Background()); !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("second Run = %v, want ErrAlreadyRunning", err)
	}
}

// openFDs is how many descriptors this process has open.
func openFDs(t *testing.T) int {
	t.Helper()
	e, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(e)
}

// TestRunStopsOnHangup is the end of a run: the last task carrying the filter is gone, so the loop exits
// cleanly rather than reporting a failure.
func TestRunStopsOnHangup(t *testing.T) {
	f := newFake()
	f.hup = true
	l, _ := newTestLoop(t, f, testPolicy(nil, nil, nil))
	done := make(chan error, 1)
	go func() { done <- l.Run(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v, want nil on a hangup", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return on a listener hangup")
	}
}

// TestRunListenerFailures separates the listener errors that end a run quietly from the ones a caller
// has to see. Nothing closes the listener under a live run, so a closed or invalid fd is a failure Run
// returns, not a shutdown: returning nil left the agent running with every notified syscall failing ENOSYS
// and nothing ending the run (§7). A withdrawn notification is the one errno that is neither.
func TestRunListenerFailures(t *testing.T) {
	// A descriptor number far past anything this process opens, so no other test can reuse it: poll reports
	// POLLNVAL for it, as it does for a listener closed under the loop.
	closed := func(*testing.T) *sysKernel { return &sysKernel{ln: sys.InertForTest(1 << 30)} }
	// The listener's owner closed under the loop: no number is lent at all, which Wait reads as POLLNVAL's
	// failure too (ADR 0023 C7), never as a hangup that ends the run quietly.
	ownerClosed := func(t *testing.T) *sysKernel {
		ln := sys.InertForTest(1 << 30)
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		return &sysKernel{ln: ln}
	}
	tests := []struct {
		name    string
		wait    error
		recv    error
		waitOn  func(*testing.T) *sysKernel
		wantErr error
	}{
		{name: "poll fails EBADF", wait: unix.EBADF, wantErr: ErrListener},
		{name: "poll fails EINVAL", wait: unix.EINVAL, wantErr: ErrListener},
		{name: "fd is not a listener", wait: unix.ENOTTY, wantErr: ErrListener},
		{name: "fd closed under the loop (POLLNVAL)", waitOn: closed, wantErr: ErrListener},
		{name: "listener owner closed under the loop", waitOn: ownerClosed, wantErr: ErrListener},
		{name: "recv on a closed fd", recv: unix.EBADF, wantErr: ErrListener},
		{name: "recv fails EINVAL", recv: unix.EINVAL, wantErr: ErrListener},
		{name: "recv fails ECANCELED", recv: unix.ECANCELED, wantErr: ErrListener},
		{name: "recv finds the notification withdrawn", recv: unix.ENOENT},
		{name: "recv on the wrong ioctl", recv: unix.ENOTTY, wantErr: ErrListener},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.waitErr, f.recvErr = tc.wait, tc.recv
			if tc.waitOn != nil {
				f.waitOn = tc.waitOn(t)
			}
			if tc.recv != nil {
				f.queue(sysNotif{ID: 1, Pid: 42, Data: sysData(connectNR())})
			}
			l, _ := newTestLoop(t, f, testPolicy(nil, nil, nil))
			// A withdrawn notification is not an error: that worker loops, so the context is what ends
			// the run. The others end as soon as they see the errno.
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- l.Run(ctx) }()
			select {
			case err := <-done:
				if tc.wantErr == nil {
					if err != nil {
						t.Fatalf("Run = %v, want nil", err)
					}
				} else if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Run = %v, want %v", err, tc.wantErr)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Run did not return")
			}
			if !f.closedList {
				t.Error("the listener was not closed on the way out")
			}
		})
	}
}

// TestRunClosesTheListenerExactlyOnce: the fd belongs to the loop once Run has it.
func TestRunClosesTheListener(t *testing.T) {
	f := newFake()
	f.hup = true
	l, _ := newTestLoop(t, f, testPolicy(nil, nil, nil))
	if err := l.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !f.closedList {
		t.Error("Run returned without closing the listener")
	}
}

// TestMetricsUnderConcurrency checks the counters are race-free and monotonic (I7); run with -race.
// supervisor.md E22: many threads notify at once, each blocked in its own trap, and the Policy reads under them are race-free (I9); run with -race.
func TestMetricsUnderConcurrency(t *testing.T) {
	f := newFake()
	f.put(0x1000, cstr("/work/x"))
	l, _ := newTestLoop(t, f, testPolicy(nil, nil, nil))
	nr := nrFor(t, "openat")
	var wg sync.WaitGroup
	const workers, each = 8, 50
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for j := 0; j < each; j++ {
				n := notifFor(nr, 42, argCWD, 0x1000, 0x241)
				n.id = uint64(base*each + j + 1)
				l.metrics.notifications.Add(1)
				l.handle(n)
			}
		}(i)
	}
	go func() {
		for i := 0; i < 100; i++ {
			_ = l.Metrics()
		}
	}()
	wg.Wait()
	if got := l.Metrics().Notifications; got != workers*each {
		t.Errorf("notifications = %d, want %d", got, workers*each)
	}
	if f.respCount() != workers*each {
		t.Errorf("responses = %d, want one per notification", f.respCount())
	}
}

// TestBudgetCountsAnomalies: the soft ceiling counts, it never aborts.
func TestBudgetCountsAnomalies(t *testing.T) {
	f := newFake()
	l, _ := newTestLoop(t, f, testPolicy(nil, nil, nil))
	l.budget = time.Nanosecond
	const nr = 4245
	l.dispatch[dispatchKey{arch: nativeAuditArch(), nr: nr}] = entry{
		name: "slow", fn: func(l *Loop, n *notif) {
			time.Sleep(2 * time.Millisecond)
			l.respond(n, respContinue())
		},
	}
	l.handle(notifFor(nr, 42))
	m := l.Metrics()
	if m.Anomalies != 1 {
		t.Errorf("anomalies = %d, want 1", m.Anomalies)
	}
	if m.HeldMS < 1 {
		t.Errorf("held_ms = %d, want at least 1", m.HeldMS)
	}
	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Error("a slow notification was aborted; the ceiling is soft")
	}
}

// TestNewValidates rejects the arguments a run could not decide from.
func TestNewValidates(t *testing.T) {
	f := newFake()
	if _, err := New(nil, testPolicy(nil, nil, nil), &testSink{}, Options{kernel: f}); !errors.Is(err, ErrListener) {
		t.Errorf("New with no listener = %v, want ErrListener", err)
	}
	// New owns the listener from the call on (ADR 0023 C7): one it refuses is closed, since the caller kept none.
	refused := testListener()
	if _, err := New(refused, nil, &testSink{}, Options{kernel: f}); !errors.Is(err, ErrPolicy) {
		t.Errorf("New with no policy = %v, want ErrPolicy", err)
	}
	if err := refused.Borrow(func(int) error { return nil }); !errors.Is(err, sys.ErrClosed) {
		t.Errorf("the listener of a refused New lends %v, want sys.ErrClosed: New left it open", err)
	}
	if _, err := New(testListener(), testPolicy(nil, nil, nil), nil, Options{kernel: f}); !errors.Is(err, ErrPolicy) {
		t.Errorf("New with no sink = %v, want ErrPolicy", err)
	}
	l, err := New(testListener(), testPolicy(nil, nil, nil), &testSink{}, Options{kernel: f})
	if err != nil {
		t.Fatal(err)
	}
	if l.workers != DefaultWorkers || l.budget != SoftCeiling {
		t.Errorf("defaults = %d/%v, want %d/%v", l.workers, l.budget, DefaultWorkers, SoftCeiling)
	}
	if l.table.Load().argvMax != DefaultMaxArgv {
		t.Errorf("argv budget = %d, want %d", l.table.Load().argvMax, DefaultMaxArgv)
	}
}

// TestCompileOrdersFSRulesNearestFirst is SEMANTICS §2's nearest-wins, which the compiled order encodes.
func TestCompileOrdersFSRulesNearestFirst(t *testing.T) {
	c := compile(testPolicy(nil, []agent.FSRule{
		{Path: "/a", Kind: agent.FSWrite},
		{Path: "/a/b/c", Kind: agent.FSDenyRead},
		{Path: "/a/b", Kind: agent.FSWatch},
		{Path: "/a/b/c/d", Kind: agent.FSImplicit},
	}, nil))
	tests := []struct{ path, want string }{
		{"/a/x", "fs.write[/a]"},
		{"/a", "fs.write[/a]"},
		{"/a/b/x", "fs.write[/a]"}, // a watch entry carries no rights and never shadows a grant
		{"/a/b/c/x", "fs.deny_read[/a/b/c]"},
		{"/a/b/c/d/x", "fs.implicit[/a/b/c/d]"},
		{"/a/bb/x", "fs.write[/a]"},
		{"/other", ""},
	}
	for _, tc := range tests {
		got := c.nearestFS(tc.path)
		name := ""
		if got != nil {
			name = got.Name
		}
		if name != tc.want {
			t.Errorf("nearestFS(%q) = %q, want %q", tc.path, name, tc.want)
		}
	}
}

// TestNearestFSHandlesRoot: an entry on "/" is its own separator and must not become an empty prefix.
func TestNearestFSHandlesRoot(t *testing.T) {
	c := compile(testPolicy(nil, []agent.FSRule{
		{Path: "/", Kind: agent.FSWrite},
		{Path: "/etc", Kind: agent.FSDenyRead},
	}, nil))
	for _, tc := range []struct{ path, want string }{
		{"/tmp/x", "fs.write[/]"},
		{"/", "fs.write[/]"},
		{"/etc/passwd", "fs.deny_read[/etc]"},
		{"relative", ""},
	} {
		got := c.nearestFS(tc.path)
		name := ""
		if got != nil {
			name = got.Name
		}
		if name != tc.want {
			t.Errorf("nearestFS(%q) = %q, want %q", tc.path, name, tc.want)
		}
	}
}

// sysData builds a seccomp_data for the native architecture.
func sysData(nr int32, args ...uint64) sys.SeccompData {
	d := sys.SeccompData{Nr: nr, Arch: nativeAuditArch()}
	copy(d.Args[:], args)
	return d
}

// waitFor polls cond until it holds or the test times out.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition never held")
}

// TestAnImplicitEntryDoesNotReAllowADeniedRead: an implicit entry is a write guard that grants no read, so one
// nearer than a deny_read above it (the ledger root beneath ~/.tego, agent-contract R6a) must not turn a read
// Landlock refuses into an allowed line in the ledger.
func TestAnImplicitEntryDoesNotReAllowADeniedRead(t *testing.T) {
	c := compile(testPolicy(nil, []agent.FSRule{
		{Path: "/home/u/.tego", Kind: agent.FSDenyRead, BuiltIn: true},
		{Path: "/home/u/.tego/runs", Kind: agent.FSImplicit},
		{Path: "/home/u/.tego/runs/w", Kind: agent.FSWrite},
	}, nil))
	for _, tc := range []struct {
		path, rule string
		verdict    record.Verdict
	}{
		{"/home/u/.tego/runs/r-1/events.jsonl", "fs.deny_read[/home/u/.tego]", record.VerdictRefused},
		{"/home/u/.tego/chain.log", "fs.deny_read[/home/u/.tego]", record.VerdictRefused},
		{"/home/u/.tego/runs/w/x", "fs.write[/home/u/.tego/runs/w]", record.VerdictAllow},
	} {
		rule, v, _ := c.fsVerdict(tc.path, record.FSOpen, 0, false)
		if rule != tc.rule || v != tc.verdict {
			t.Errorf("read %s = %s %s, want %s %s", tc.path, rule, v, tc.rule, tc.verdict)
		}
	}
}

// TestAPathIsMatchedUnderBothSpellingsOfAnEntry: under a project reached through a symlink an entry's Path is the
// declared spelling and its Resolved the canonical one, and a relative path the target passes is joined to its
// /proc/<pid>/cwd, which the kernel spells canonically. Matched against the declared spellings alone, an allowed
// write was recorded refused and a refused read allow.
func TestAPathIsMatchedUnderBothSpellingsOfAnEntry(t *testing.T) {
	c := compile(testPolicy(nil, []agent.FSRule{
		{Path: "/home/u/link/out", Resolved: "/data/proj/out", Kind: agent.FSWrite, Raw: "./out"},
		{Path: "/home/u/link/secrets", Resolved: "/data/proj/secrets", Kind: agent.FSDenyRead, Raw: "./secrets"},
	}, nil))
	for _, tc := range []struct {
		path    string
		flags   int
		rule    string
		verdict record.Verdict
	}{
		{"/data/proj/out/report", unix.O_WRONLY | unix.O_CREAT, "fs.write[./out]", record.VerdictAllow},
		{"/home/u/link/out/report", unix.O_WRONLY | unix.O_CREAT, "fs.write[./out]", record.VerdictAllow},
		{"/data/proj/secrets/key", 0, "fs.deny_read[./secrets]", record.VerdictRefused},
		{"/home/u/link/secrets/key", 0, "fs.deny_read[./secrets]", record.VerdictRefused},
		{"/data/proj/other", unix.O_WRONLY | unix.O_CREAT, ruleUnmatched, record.VerdictRefused},
	} {
		rule, v, _ := c.fsVerdict(tc.path, record.FSOpen, tc.flags, false)
		if rule != tc.rule || v != tc.verdict {
			t.Errorf("open %s = %s %s, want %s %s", tc.path, rule, v, tc.rule, tc.verdict)
		}
	}
}
