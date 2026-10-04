// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// Stop consumes the source's resources permanently, even when no Start happened. A later Start must
// refuse rather than report successful capture through an already closed reader.
func TestUprobeStartAfterStopIsRefused(t *testing.T) {
	u, sink := newTestUprobe(t, nil, Options{})
	if err := u.Stop(); err != nil {
		t.Fatal(err)
	}
	err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink)
	if err == nil {
		_ = u.Stop()
		t.Fatal("Start succeeded after Stop permanently closed capture resources")
	}
	if !errors.Is(err, errStopped) {
		t.Fatalf("Start after Stop: %v", err)
	}
}

type startupRing struct {
	*quietRing
	flushing chan struct{}
	once     sync.Once
}

func (q *startupRing) Flush() error {
	q.once.Do(func() { close(q.flushing) })
	return q.quietRing.Flush()
}

// Start publishes resources before Stop wakes/joins the drain. In particular Stop's ready snapshot must
// not skip the final ring contents just because pre-attach was still finishing when Stop arrived.
func TestUprobeStopJoinsStartupBeforeFinalDrain(t *testing.T) {
	q := &startupRing{quietRing: newQuietRing(), flushing: make(chan struct{})}
	q.push(exchangeOf(41, 100, 0)...)
	entered, release := make(chan struct{}), make(chan struct{})
	u, err := New(Options{Reader: q, Preattach: func() []string {
		close(entered)
		<-release
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	var releaseOnce, stopOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	startReturned, stopReturned := make(chan struct{}), make(chan struct{})
	var startErr, stopErr error
	go func() {
		startErr = u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink)
		close(startReturned)
	}()
	stop := func() {
		stopOnce.Do(func() {
			go func() { stopErr = u.Stop(); close(stopReturned) }()
		})
	}
	wait := func(done <-chan struct{}, what string) bool {
		select {
		case <-done:
			return true
		case <-time.After(2 * time.Second):
			t.Errorf("%s did not finish", what)
			return false
		}
	}
	t.Cleanup(func() {
		unblock()
		stop()
		wait(startReturned, "cleanup Start")
		wait(stopReturned, "cleanup Stop")
	})
	if !wait(entered, "Start entering pre-attach") {
		t.Fatal("startup did not reach the blocked fixture")
	}
	stop()
	// Observe Stop's state transition under the same lock before testing its absence of reader effects.
	// Merely launching its goroutine could miss a premature wake on a busy test host.
	deadline := time.Now().Add(2 * time.Second)
	for {
		u.mu.Lock()
		stopping := u.stopped
		u.mu.Unlock()
		if stopping {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Stop never began its state transition")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-q.flushing:
		t.Fatal("Stop touched the reader before startup completed")
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	if !wait(startReturned, "Start") || !wait(stopReturned, "Stop") {
		t.Fatal("capture lifecycle did not finish")
	}
	if startErr != nil || stopErr != nil {
		t.Fatalf("lifecycle errors: Start=%v Stop=%v", startErr, stopErr)
	}
	if requests, responses := countKinds(sink); requests != 1 || responses != 1 {
		t.Fatalf("final capture lost while startup finished: requests=%d responses=%d", requests, responses)
	}
	q.mu.Lock()
	closed := q.closed
	q.mu.Unlock()
	if !closed {
		t.Error("Stop left the published reader open")
	}
}
