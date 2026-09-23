// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// listenerPipe stands a raw pipe in for the child's seccomp listener and returns its read end, the
// number startNotifyLoop is given; the write end is closed when the test ends.
//
// Raw on purpose. startNotifyLoop hands the number to supervisor.New, and from there "Run closes it
// once, as its shutdown step" (supervisor.md §3) — so nothing else in this process may own it. An
// *os.File would: os.File.Fd's own documentation says "do not close the returned descriptor", because
// the File closes it again from its finalizer at whatever moment the collector next runs. That second
// close is a double close, and it does not land on the pipe — by then the number has been handed back out, so
// it lands on whatever this process opened since, which is how a run directory was left behind with
// os.RemoveAll reporting EBADF from unlinkat.
func listenerPipe(t *testing.T) *sys.FD {
	t.Helper()
	r, w, err := sys.Pipe2(syscall.O_CLOEXEC)
	if err != nil {
		t.Fatalf("pipe2: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return r
}

// fdNum is the number f owns, for a test that checks what that number names once f has let it go; -1 when f
// lends nothing.
func fdNum(f *sys.FD) int {
	n := -1
	_ = f.Borrow(func(x int) error { n = x; return nil })
	return n
}

// TestStartNotifyLoopSkipsWhenNoNotifyFDExists covers the facade's own half of R7 for a tier with no
// seccomp filter (the observe backend, whose Prepare hands back an empty ruleset): startNotifyLoop
// must not try to build a supervisor.Loop over an invalid fd, and must leave nothing behind to join.
// Without this guard, startWorkers would call supervisor.New(nil, ...), which fails, turning every
// such run into a startup error it should never have had.
func TestStartNotifyLoopSkipsWhenNoNotifyFDExists(t *testing.T) {
	testutil.NoFDLeak(t)
	g, gctx := newGroup(context.Background())
	r := &runner{
		log: slog.New(slog.DiscardHandler), rt: &agent.RuleTable{}, queue: NewQueue(4),
		group: g,
	}
	if err := r.startNotifyLoop(gctx); err != nil {
		t.Fatalf("startNotifyLoop: %v, want nil for a tier with no notify fd", err)
	}
	if r.sup != nil {
		t.Fatal("no supervisor.Loop should be built when there is no notify fd to hand it")
	}
	g.Cancel()
	if err := g.Wait(); err != nil {
		t.Fatalf("group.Wait: %v, want no member left running", err)
	}
}

// TestStartNotifyLoopFailsClosedOnAnInvalidPolicy is R7's precondition seen from the failure side:
// "the first NOTIF_RECV must be provably in flight before Ack" only means something if a supervisor
// that never got that far is reported as an error rather than treated as armed. A policy
// supervisor.New refuses (here: an empty run id) never reaches Run/Armed at all, so this pins that
// startNotifyLoop's error return — not a silent nil — is what prepare() sees, keeping the child
// blocked behind its ack instead of being released into an execve nothing is listening for.
func TestStartNotifyLoopFailsClosedOnAnInvalidPolicy(t *testing.T) {
	testutil.NoFDLeak(t)
	notifyFD := listenerPipe(t)

	g, gctx := newGroup(context.Background())
	r := &runner{
		// r.id is left at its zero value on purpose: policy.RunID becomes "", which
		// supervisor.Policy.Validate refuses before New ever touches the notify fd.
		log: slog.New(slog.DiscardHandler), rt: &agent.RuleTable{}, queue: NewQueue(4),
		group: g, notifyFD: notifyFD,
	}
	err := r.startNotifyLoop(gctx)
	if err == nil {
		t.Fatal("startNotifyLoop must fail when the supervisor cannot be constructed at all")
	}
	if r.sup != nil {
		t.Fatal("no Loop should be kept for a construction that failed before Run ever started")
	}
	// The listener moved into New, which owns it on every path (ADR 0023 C7): the runner keeps none, and the
	// New that refused closed it.
	if r.notifyFD != nil {
		t.Fatal("the runner kept the listener it moved into supervisor.New")
	}
	if fdNum(notifyFD) != -1 {
		t.Fatal("the listener a refused supervisor.New took is still open")
	}
	g.Cancel()
	_ = g.Wait()
}

// TestStartNotifyLoopReturnsOnceTheLoopIsArmed is R7's success path: prepare() must not return —
// and so must not let writeRunStart/Ack proceed — until the real supervisor.Loop reports itself
// armed. A valid policy over an ordinary pipe fd is enough to drive the loop through its own
// startup and close Armed(), with no kernel notify object needed, because the facade's own
// contribution to R7 is entirely this wait, not anything the loop itself does with the fd.
func TestStartNotifyLoopReturnsOnceTheLoopIsArmed(t *testing.T) {
	testutil.NoFDLeak(t)
	listener := listenerPipe(t)
	notifyFD := fdNum(listener)

	// The stand-in for whatever this process opens after the loop gives the number back: a blob temp
	// file, chain.log, the directory descriptor os.RemoveAll unlinks against. Opened before the number
	// is freed so nothing in this test competes for it.
	victim, err := os.Create(filepath.Join(t.TempDir(), "still-open"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = victim.Close() }()

	g, gctx := newGroup(context.Background())
	r := &runner{
		log:     slog.New(slog.DiscardHandler),
		rt:      &agent.RuleTable{Contract: &agent.Contract{Name: "armed-test"}},
		id:      identity.RunID("r-00000000-000000000000a-aaaaaa"),
		agentID: identity.AgentID("armed-test"),
		queue:   NewQueue(4), group: g, notifyFD: listener,
	}
	done := make(chan error, 1)
	go func() { done <- r.startNotifyLoop(gctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("startNotifyLoop: %v, want the loop to arm cleanly", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("startNotifyLoop never observed the loop arm (R7)")
	}
	if r.sup == nil {
		t.Fatal("a working supervisor.Loop must be kept on the runner once armed")
	}
	g.Cancel()
	if err := g.Wait(); err != nil {
		t.Fatalf("group.Wait: %v", err)
	}

	// Loop.Run has returned, so it has already closed the listener: that number is free, and R7's
	// handover is only honest if it is now free of every owner, not just of the supervisor's. dup2 is
	// atomic, so the unrelated file owns the number from here on.
	if err := syscall.Dup3(int(victim.Fd()), notifyFD, 0); err != nil {
		t.Fatalf("dup3 onto fd %d: %v", notifyFD, err)
	}
	defer func() { _ = syscall.Close(notifyFD) }()
	var before syscall.Stat_t
	if err := syscall.Fstat(notifyFD, &before); err != nil {
		t.Fatalf("fd %d should hold the unrelated file: %v", notifyFD, err)
	}
	// The second close comes from the collector, so make the collector run here — while a
	// sentinel is standing at the number — instead of leaving it to land on whatever this process
	// holds open at some later, load-dependent moment.
	collectFinalizers(t)
	var after syscall.Stat_t
	if err := syscall.Fstat(notifyFD, &after); err != nil {
		t.Fatalf("fd %d was closed a second time once the loop gave it back: something in this "+
			"process still owned the number after the handover: %v", notifyFD, err)
	}
	if before.Ino != after.Ino || before.Dev != after.Dev {
		t.Fatalf("fd %d now points at a different file (ino %d/%d, dev %d/%d)",
			notifyFD, before.Ino, after.Ino, before.Dev, after.Dev)
	}
}
