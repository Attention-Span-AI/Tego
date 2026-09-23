// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Every other test in this file drives fanotifyListener.handle directly, bypassing loop's own poll(2)/read(2)
// dispatch entirely. That leaves loop itself — the goroutine RunListener actually starts (attach.go) — with no
// coverage from anything that runs without root: the integration tests that do exercise it (fanotify_test.go
// under //go:build integration) need a real fanotify group. The tests below close that gap using a connected
// AF_UNIX SOCK_DGRAM pair, which is bidirectional and message-preserving the way a real fanotify descriptor is
// (read an event, write a response, on the same fd) — a plain pipe, being one-directional, cannot stand in for
// it the way it does for handle's response-only tests.

// socketpairListener builds a listener whose "fanotify descriptor" is one end of a connected socket pair; the
// caller reads and writes the other end the way the kernel would.
func socketpairListener(t *testing.T, out Emitter, decide func(fanEvent) (verdict, error)) (l *fanotifyListener, kernelSide int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fds[0]) })
	l = &fanotifyListener{
		fd: fds[1], run: Run{ID: "run-1", Agent: "a", CgroupID: 99}, out: out,
		deadline: time.Second, now: time.Now, marks: map[string]uint64{},
	}
	l.decide = decide
	l.markMount = func(string, uint64) error { return nil }
	l.unmarkMounts = func() error { return nil }
	t.Cleanup(func() { _ = l.Close() })
	return l, fds[0]
}

// readRetrying is unix.Read with the EINTR retry a raw blocking syscall needs in a Go program.
//
// The runtime preempts goroutines by sending SIGURG, and a blocking read issued outside the netpoller
// returns EINTR when one lands. Alone this test never saw one; under the whole suite, where many packages
// run at once and preemption is frequent, it failed with "interrupted system call" and looked like the
// listener had not answered. SO_RCVTIMEO still bounds the wait, surfacing as EAGAIN rather than a hang.
func readRetrying(fd int, p []byte) (int, error) {
	for {
		n, err := unix.Read(fd, p)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return n, err
	}
}

// TestListenerLoopReadsDispatchesAndStopsOnCancel drives loop() end to end: an event written the way the
// kernel would is polled for, read, parsed, handed to decide, and answered on the same descriptor — and a
// cancelled context stops the goroutine cleanly rather than needing to be killed from outside. This is I8's
// promise ("no branch of fanotifyListener.loop returns without a paired write") exercised through loop's own
// poll/read machinery, which nothing else in the non-integration suite reaches at all.
func TestListenerLoopReadsDispatchesAndStopsOnCancel(t *testing.T) {
	t.Parallel()
	s := &sink{}
	refusal := verdict{path: "/home/u/.ssh/id_ed25519", rule: "fs.deny_read[~/.ssh]", reason: record.ReasonReadDenied}
	l, kernelSide := socketpairListener(t, s, func(fanEvent) (verdict, error) { return refusal, nil })

	// A receive timeout bounds the read without a sleep: if loop() never answers, this returns promptly
	// instead of hanging the suite.
	if err := unix.SetsockoptTimeval(kernelSide, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5}); err != nil {
		t.Fatalf("SO_RCVTIMEO: %v", err)
	}

	targetFD := openFD(t)
	if _, err := unix.Write(kernelSide, metadata(unix.FAN_OPEN_PERM, targetFD, 777, fanMetadataVersion, 0)); err != nil {
		t.Fatalf("write synthetic event: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	loopErr := make(chan error, 1)
	go func() { loopErr <- l.loop(ctx) }()

	var resp [8]byte
	n, err := readRetrying(kernelSide, resp[:])
	if err != nil {
		t.Fatalf("loop() never answered the event it read: %v", err)
	}
	if n != 8 {
		t.Fatalf("response is %d bytes, want 8", n)
	}
	if gotFD := int32(binary.NativeEndian.Uint32(resp[0:4])); gotFD != targetFD {
		t.Fatalf("responded for descriptor %d, want %d", gotFD, targetFD)
	}
	if got := binary.NativeEndian.Uint32(resp[4:8]); got != unix.FAN_DENY {
		t.Fatalf("response %#x for a refusal, want the bare FAN_DENY %#x (§6 E2)", got, unix.FAN_DENY)
	}

	cancel()
	select {
	case err := <-loopErr:
		if err != nil {
			t.Fatalf("loop() after its context was cancelled = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("loop() did not return after its context was cancelled")
	}

	events := s.all()
	if len(events) != 1 || events[0].Kind != record.KindFS || events[0].Verdict != record.VerdictRefused {
		t.Fatalf("events = %+v, want exactly one refused fs event", events)
	}
}

// TestACancelledLoopDoesNotWaitOutItsPoll: the run's teardown waits for the listener's loop, and the loop used to
// notice its context only when its poll timed out, so every tier-2 run whose last open came just before its end
// ended up to fanPollTimeoutMS late: about 100 ms of each short run, measured with strace in the KVM guest, and
// the whole of kill test 4's go-kind margin (test/vm/README.md). The poll timeout here is a minute, so only the
// wake can end the poll within the bound.
func TestACancelledLoopDoesNotWaitOutItsPoll(t *testing.T) {
	t.Parallel()
	l, _ := socketpairListener(t, &sink{}, func(fanEvent) (verdict, error) { return allowed, nil })
	l.pollTimeoutMS = 60_000
	ctx, cancel := context.WithCancel(context.Background())
	loopErr := make(chan error, 1)
	go func() { loopErr <- l.loop(ctx) }()
	time.Sleep(50 * time.Millisecond) // into the poll, which nothing else wakes
	start := time.Now()
	cancel()
	select {
	case err := <-loopErr:
		if err != nil {
			t.Fatalf("loop() after its context was cancelled = %v, want nil", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("a cancelled loop() waited on its poll's timeout instead of the wake")
	}
	t.Logf("returned %v after the cancel", time.Since(start))
}

// TestListenerLoopIsFatalWhenTheDescriptorDies is §6 E15 and I8's other half: when the group loop reads from
// stops existing, the loop must report that as a fatal, named error rather than spinning or hanging — that is
// what lets RunListener (attach.go) treat the goroutine's death as fatal to the whole run instead of leaving
// the kernel's fail-open window unnoticed.
//
// The descriptor here was never opened by this process, so the kernel reports it as POLLNVAL — the same
// revents bit a closed or otherwise-gone fanotify group produces on poll(2) — without racing this suite's
// other parallel tests for a live, just-closed file descriptor number.
func TestListenerLoopIsFatalWhenTheDescriptorDies(t *testing.T) {
	t.Parallel()
	l := &fanotifyListener{fd: 1 << 20, now: time.Now, marks: map[string]uint64{}}
	l.decide = func(fanEvent) (verdict, error) { return allowed, nil }

	done := make(chan error, 1)
	go func() { done <- l.loop(context.Background()) }()

	select {
	case err := <-done:
		if !errors.Is(err, ErrListenerDied) {
			t.Fatalf("loop() over a dead descriptor = %v, want ErrListenerDied", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("loop() over a dead descriptor never returned; it must not spin or block forever")
	}
}

// TestLoopAnswersAPathAllowedEventWithoutAWorker: an event the policy allows on its path alone is answered by
// the read loop itself (settleByPath), never handed to a worker and decide, and so never waits behind a
// decision that is still running. Before, every event took the loop → worker → decision goroutine hand-offs
// and a timer, about a third of the round trip every open on a marked mount pays (§9), and an allowed open
// queued behind whatever held the workers. Here a refusal candidate is held in its decision while an ordinary
// open arrives after it: the open is answered at once, the held one when its decision returns.
func TestLoopAnswersAPathAllowedEventWithoutAWorker(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	secret, plain := filepath.Join(dir, "secret"), filepath.Join(dir, "plain")
	for _, p := range []string{secret, plain} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	open := func(p string) int32 {
		fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		return int32(fd) // the listener closes it once it has answered, as it does a kernel event's
	}
	secretFD, plainFD := open(secret), open(plain)

	gate := make(chan struct{})
	var mu sync.Mutex
	var decided []int32
	s := &sink{}
	l, kernelSide := socketpairListener(t, s, func(ev fanEvent) (verdict, error) {
		mu.Lock()
		decided = append(decided, ev.FD)
		mu.Unlock()
		<-gate
		return verdict{path: secret, rule: "fs.deny_read[secret]", reason: record.ReasonReadDenied}, nil
	})
	l.policy = newPolicy(policyTable([]agent.FSRule{fsRule(agent.FSDenyRead, secret, "", "secret")}, nil), "/run.scope")
	l.settle = l.settleByPath
	if err := unix.SetsockoptTimeval(kernelSide, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5}); err != nil {
		t.Fatalf("SO_RCVTIMEO: %v", err)
	}
	for _, fd := range []int32{secretFD, plainFD} {
		if _, err := unix.Write(kernelSide, metadata(unix.FAN_OPEN_PERM, fd, 777, fanMetadataVersion, 0)); err != nil {
			t.Fatalf("write synthetic event: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	loopErr := make(chan error, 1)
	go func() { loopErr <- l.loop(ctx) }()

	response := func() (int32, uint32) {
		t.Helper()
		var resp [8]byte
		if n, err := readRetrying(kernelSide, resp[:]); err != nil || n != 8 {
			t.Fatalf("no response (%d bytes, %v)", n, err)
		}
		return int32(binary.NativeEndian.Uint32(resp[0:4])), binary.NativeEndian.Uint32(resp[4:8])
	}
	if fd, r := response(); fd != plainFD || r != unix.FAN_ALLOW {
		t.Fatalf("first response names descriptor %d with %#x, want the ordinary open %d allowed while the "+
			"refusal candidate %d is still being decided", fd, r, plainFD, secretFD)
	}
	close(gate)
	if fd, r := response(); fd != secretFD || r != unix.FAN_DENY {
		t.Fatalf("second response names descriptor %d with %#x, want %d refused", fd, r, secretFD)
	}
	cancel()
	if err := <-loopErr; err != nil {
		t.Fatalf("loop() = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(decided) != 1 || decided[0] != secretFD {
		t.Fatalf("decide saw descriptors %v, want the refusal candidate %d alone", decided, secretFD)
	}
}

// TestSettleByPathLeavesEverythingElseToAWorker pins what the read loop may answer on its own: an allow the
// path gives, for an open or an exec, and nothing else. A path a deny_read entry covers, an exec no entry
// names, and a descriptor whose path cannot be read back all go to a worker, whose decision reads membership
// or reports the gap under E16's deadline.
func TestSettleByPathLeavesEverythingElseToAWorker(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	secret, plain, tool := filepath.Join(dir, "secret"), filepath.Join(dir, "plain"), filepath.Join(dir, "tool")
	for _, p := range []string{secret, plain, tool} {
		if err := os.WriteFile(p, []byte("x"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	dup, err := unix.Dup(int(w.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	l := &fanotifyListener{fd: dup, now: time.Now, marks: map[string]uint64{},
		policy: newPolicy(policyTable([]agent.FSRule{fsRule(agent.FSDenyRead, secret, "", "secret")},
			[]agent.ExecRule{{Path: tool, Raw: "tool", Verdict: agent.VerdictAllow}}), "/run.scope")}
	defer l.Close()
	open := func(p string) int32 {
		fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		return int32(fd)
	}
	for _, tc := range []struct {
		name   string
		mask   uint64
		fd     func() int32
		settle bool
	}{
		{"an ordinary open", unix.FAN_OPEN_PERM, func() int32 { return open(plain) }, true},
		{"an exec an entry names", unix.FAN_OPEN_EXEC_PERM, func() int32 { return open(tool) }, true},
		{"an open under deny_read", unix.FAN_OPEN_PERM, func() int32 { return open(secret) }, false},
		{"an exec no entry names", unix.FAN_OPEN_EXEC_PERM, func() int32 { return open(plain) }, false},
		{"a descriptor that names nothing", unix.FAN_OPEN_PERM, func() int32 { return 1 << 20 }, false},
	} {
		fd := tc.fd()
		before := l.answered.Load()
		if got := l.settleByPath(fanEvent{Mask: tc.mask, FD: fd, PID: 4242}); got != tc.settle {
			t.Errorf("%s: settled %v, want %v", tc.name, got, tc.settle)
		}
		if answered := l.answered.Load() - before; (answered == 1) != tc.settle {
			t.Errorf("%s: %d responses written, want one exactly when it is settled", tc.name, answered)
		}
		if fd < 1<<20 {
			// settleByPath leaves the descriptor to its caller either way: readOnce's closer takes a settled
			// one, a worker any other.
			_ = unix.Close(int(fd))
		}
	}
}

// TestLoopClosesASettledDescriptorOffTheLoop: the read loop answers an open its path allows and leaves the close
// of its descriptor to the closer (fdCloser), so a close that waits holds no later event. A FUSE daemon or an NFS
// server that answered the open the listener's read made and then stopped answering holds that close, and when
// the loop closed on its own goroutine every opener on every marked mount waited behind it (§6 E35). Here the
// first descriptor's close is held: the next open is answered all the same, and loop still closes both before
// it returns.
func TestLoopClosesASettledDescriptorOffTheLoop(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var fds []int32
	for _, name := range []string{"first", "second"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		fds = append(fds, int32(fd))
	}
	l, kernelSide := socketpairListener(t, &sink{}, func(ev fanEvent) (verdict, error) {
		t.Errorf("decide saw descriptor %d, whose path the policy allows", ev.FD)
		return allowed, nil
	})
	l.policy = newPolicy(policyTable([]agent.FSRule{fsRule(agent.FSDenyRead, filepath.Join(dir, "secret"), "", "secret")}, nil), "/run.scope")
	l.settle = l.settleByPath
	held, release := make(chan struct{}), make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	defer releaseOnce()
	var mu sync.Mutex
	var closed []int
	l.closeSettled = func(fd int) error {
		if fd == int(fds[0]) {
			close(held)
			<-release
		}
		mu.Lock()
		closed = append(closed, fd)
		mu.Unlock()
		return unix.Close(fd)
	}
	if err := unix.SetsockoptTimeval(kernelSide, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5}); err != nil {
		t.Fatalf("SO_RCVTIMEO: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	loopErr := make(chan error, 1)
	go func() { loopErr <- l.loop(ctx) }()

	answer := func(fd int32) {
		t.Helper()
		if _, err := unix.Write(kernelSide, metadata(unix.FAN_OPEN_PERM, fd, 777, fanMetadataVersion, 0)); err != nil {
			t.Fatalf("write synthetic event: %v", err)
		}
		var resp [8]byte
		if n, err := readRetrying(kernelSide, resp[:]); err != nil || n != 8 {
			t.Fatalf("no response to descriptor %d (%d bytes, %v): the loop is held", fd, n, err)
		}
		if got, r := int32(binary.NativeEndian.Uint32(resp[0:4])), binary.NativeEndian.Uint32(resp[4:8]); got != fd || r != unix.FAN_ALLOW {
			t.Fatalf("response names descriptor %d with %#x, want %d allowed", got, r, fd)
		}
	}
	answer(fds[0])
	select {
	case <-held:
	case <-time.After(5 * time.Second):
		t.Fatal("the first descriptor was never closed")
	}
	answer(fds[1])
	releaseOnce()
	cancel()
	if err := <-loopErr; err != nil {
		t.Fatalf("loop() = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(closed) != 2 || closed[0] != int(fds[0]) || closed[1] != int(fds[1]) {
		t.Fatalf("closed %v by the time loop returned, want %v in order", closed, fds)
	}
}

// TestNewListenerSettlesOnTheLoop: the listener Prepare builds (newFanotifyListener) answers an open its path
// allows on the read loop, never through decide. Every other test of that answer sets settle itself, so a
// constructor that left it out would bring the worker round trip back to every open on a marked mount (§9: 43–45
// µs an open on 6.17, against 18–19 µs) with the whole suite passing. It swaps fanotifyInit, so it cannot run in
// parallel.
func TestNewListenerSettlesOnTheLoop(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fds[0]) })
	saved := fanotifyInit
	t.Cleanup(func() { fanotifyInit = saved })
	handed := false
	fanotifyInit = func(uint, uint) (int, error) {
		handed = true
		return fds[1], nil
	}
	defer func() {
		if !handed {
			_ = unix.Close(fds[1])
		}
	}()
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := newPolicy(policyTable([]agent.FSRule{fsRule(agent.FSDenyRead, filepath.Join(dir, "secret"), "", "secret")}, nil), "/run.scope")
	l, err := newFanotifyListener(p, Run{ID: "run-1", Agent: "a", CgroupID: 99}, &sink{}, time.Second)
	if errors.Is(err, errThreadBudget) {
		t.Skipf("this host's thread budget refuses a listener before fanotify_init: %v", err)
	}
	if err != nil {
		t.Fatalf("newFanotifyListener: %v", err)
	}
	defer l.Close()
	var decided atomic.Int32
	l.decide = func(fanEvent) (verdict, error) {
		decided.Add(1)
		return allowed, nil
	}
	if err := unix.SetsockoptTimeval(fds[0], unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5}); err != nil {
		t.Fatalf("SO_RCVTIMEO: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	loopErr := make(chan error, 1)
	go func() { loopErr <- l.loop(ctx) }()

	fd, err := unix.Open(plain, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(fds[0], metadata(unix.FAN_OPEN_PERM, int32(fd), 777, fanMetadataVersion, 0)); err != nil {
		t.Fatalf("write synthetic event: %v", err)
	}
	var resp [8]byte
	if n, err := readRetrying(fds[0], resp[:]); err != nil || n != 8 {
		t.Fatalf("no response (%d bytes, %v)", n, err)
	}
	if got, r := int32(binary.NativeEndian.Uint32(resp[0:4])), binary.NativeEndian.Uint32(resp[4:8]); got != int32(fd) || r != unix.FAN_ALLOW {
		t.Fatalf("response names descriptor %d with %#x, want %d allowed", got, r, fd)
	}
	cancel()
	if err := <-loopErr; err != nil {
		t.Fatalf("loop() = %v", err)
	}
	if n := decided.Load(); n != 0 {
		t.Fatalf("an open its path allows went to decide %d time(s): newFanotifyListener does not settle on the "+
			"read loop", n)
	}
}
