// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func TestUnwindBoundsAnUnstartedRecorderStopAndPreservesItsHandle(t *testing.T) {
	h := &raceHandle{}
	source := &readingSource{plainSource: plainSource{name: "observe"}, release: make(chan struct{}), handle: h}
	var release sync.Once
	unblock := func() { release.Do(func() { close(source.release) }) }
	defer unblock()
	g, _ := newGroup(context.Background())
	r := &runner{log: slog.New(slog.DiscardHandler), group: g, queue: NewQueue(8),
		kernelRecord: source, handle: h, stopWait: 20 * time.Millisecond}
	done := make(chan struct{})
	go func() {
		r.unwind(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Error("startup failure waited indefinitely on the unstarted recorder's Stop")
	}
	if h.isClosed() {
		t.Error("the handle closed while its recorder's Stop still used it")
	}
	unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("unwind did not finish after releasing Stop")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !h.isClosed() {
		if time.Now().After(deadline) {
			t.Fatal("the handle was not released after Stop finished")
		}
		time.Sleep(time.Millisecond)
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.raced {
		t.Fatal("the handle closed underneath its recorder")
	}
}
