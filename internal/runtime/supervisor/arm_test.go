// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"testing"
)

// TestStartedSeparatesArmingFromReturning is the distinction a caller cannot make from Armed alone.
//
// Run disarms on every return path, including a start that failed before it ever owned the listener,
// so that a caller waiting on Armed is never stranded. That is the right behaviour and it has a
// consequence: both outcomes close the same channel. A caller selecting on Armed and on Run's error
// has both ready at once when the start failed, and Go picks among ready cases at random, so it would
// treat a dead loop as a live one about half the time. Started is what tells them apart.
func TestStartedSeparatesArmingFromReturning(t *testing.T) {
	t.Run("a loop that never ran has not started", func(t *testing.T) {
		l, _ := newTestLoop(t, newFake(), testPolicy(nil, nil, nil))
		if l.Started() {
			t.Error("a loop reports itself started before Run was called")
		}
	})

	t.Run("a second Run fails and closes Armed without starting", func(t *testing.T) {
		l, _ := newTestLoop(t, newFake(), testPolicy(nil, nil, nil))
		// The first Run takes the running flag; the second is refused immediately, which is the
		// cheapest reachable failed start.
		l.running.Store(true)
		err := l.Run(context.Background())
		if err == nil {
			t.Fatal("a second Run must be refused")
		}
		select {
		case <-l.Armed():
		default:
			t.Fatal("a failed start left a caller stranded on Armed")
		}
		if l.Started() {
			t.Error("a loop that was refused before owning the listener reports itself started")
		}
	})

	t.Run("a loop that armed reports it", func(t *testing.T) {
		l, _ := newTestLoop(t, newFake(), testPolicy(nil, nil, nil))
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- l.Run(ctx) }()
		<-l.Armed()
		if !l.Started() {
			t.Error("a loop whose workers are waiting on the listener does not report itself started")
		}
		cancel()
		<-done
		// Started stays true after the loop ends: it records that the loop armed, not that it is
		// running now, which is what the startup handshake needs to know.
		if !l.Started() {
			t.Error("Started went false after a clean shutdown")
		}
	})
}
