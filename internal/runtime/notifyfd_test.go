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

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestReleaseKernelStateDoesNotCloseTheSupervisorsListener pins the notify fd's single owner.
//
// supervisor.New takes the listener ("Run closes it once, as its shutdown step"), Loop.Run closes it
// on every return path it has, and docs/p0/runtime-launch.md §9 requires that every fd this package
// holds is "closed exactly once, on exactly one code path" — so releaseKernelState must not close
// that number again. The second close is not benign: it lands after the drain and the ledger's Close
// have opened and closed files, so the kernel's lowest-free-fd rule can have handed the number to an
// unrelated, still-open descriptor. This test stands exactly such a descriptor at the number the
// supervisor gave back and asserts releaseKernelState leaves it alone.
func TestReleaseKernelStateDoesNotCloseTheSupervisorsListener(t *testing.T) {
	testutil.NoFDLeak(t)
	listener := listenerPipe(t)
	notifyFD := fdNum(listener)

	// The stand-in for whatever the shutdown sequence opens between the loop's exit and this call:
	// a blob temp file, chain.log, an upstream socket. Opened before the number is freed so nothing
	// in this test competes for it.
	victim, err := os.Create(filepath.Join(t.TempDir(), "still-open"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = victim.Close() }()

	g, gctx := newGroup(context.Background())
	r := &runner{
		log:     slog.New(slog.DiscardHandler),
		rt:      &agent.RuleTable{Contract: &agent.Contract{Name: "notify-fd-owner"}},
		id:      identity.RunID("r-00000000-000000000000a-aaaaaa"),
		agentID: identity.AgentID("notify-fd-owner"),
		queue:   NewQueue(4), group: g, notifyFD: listener,
	}
	done := make(chan error, 1)
	go func() { done <- r.startNotifyLoop(gctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("startNotifyLoop: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("startNotifyLoop never observed the loop arm (R7)")
	}
	g.Cancel()
	if err := g.Wait(); err != nil {
		t.Fatalf("group.Wait: %v", err)
	}
	// Loop.Run has returned, so it has already closed notifyFD: that number is free now.

	// dup2 is atomic, so the unrelated file owns the number from here on.
	if err := syscall.Dup3(int(victim.Fd()), notifyFD, 0); err != nil {
		t.Fatalf("dup3 onto fd %d: %v", notifyFD, err)
	}
	defer func() { _ = syscall.Close(notifyFD) }()
	var before syscall.Stat_t
	if err := syscall.Fstat(notifyFD, &before); err != nil {
		t.Fatalf("fd %d should hold the unrelated file: %v", notifyFD, err)
	}

	r.releaseKernelState(context.Background(), nil)

	var after syscall.Stat_t
	if err := syscall.Fstat(notifyFD, &after); err != nil {
		t.Fatalf("releaseKernelState closed fd %d a second time; the supervisor had already closed it "+
			"and an unrelated open file owned the number: %v", notifyFD, err)
	}
	if before.Ino != after.Ino || before.Dev != after.Dev {
		t.Fatalf("fd %d now points at a different file (ino %d/%d, dev %d/%d)",
			notifyFD, before.Ino, after.Ino, before.Dev, after.Dev)
	}
}

// TestReleaseKernelStateClosesAListenerNoLoopEverTook is the other half of the same ownership rule:
// when supervisor.New never succeeded there is no Loop to close the listener, so the facade must
// still close it itself or the fd leaks for the life of the process.
func TestReleaseKernelStateClosesAListenerNoLoopEverTook(t *testing.T) {
	testutil.NoFDLeak(t)
	// A run that failed between the child's handoff (WaitNotifyFD) and startNotifyLoop: the runner still owns
	// the listener, and releaseKernelState is its one closer.
	listener := listenerPipe(t)
	r := &runner{log: slog.New(slog.DiscardHandler), rt: &agent.RuleTable{}, queue: NewQueue(4), notifyFD: listener}

	r.releaseKernelState(context.Background(), nil)

	if fdNum(listener) != -1 {
		t.Fatal("the listener is still open: nothing closed the listener no Loop took")
	}
	if r.notifyFD != nil {
		t.Fatal("notifyFD still set after release")
	}
}
