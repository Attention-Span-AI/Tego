// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGroupWaitsForEveryMember(t *testing.T) {
	g, ctx := newGroup(context.Background())
	var done atomic.Int64
	for i := 0; i < 8; i++ {
		g.Go("worker", func() error {
			time.Sleep(time.Millisecond)
			done.Add(1)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if done.Load() != 8 {
		t.Fatalf("joined %d of 8 members", done.Load())
	}
	if ctx.Err() == nil {
		t.Fatal("Wait must cancel the group's context")
	}
}

func TestGroupFirstErrorCancelsTheRest(t *testing.T) {
	g, ctx := newGroup(context.Background())
	boom := errors.New("boom")
	g.Go("failing", func() error { return boom })
	g.Go("patient", func() error {
		<-ctx.Done() // a failing member must stop every other one
		return nil
	})
	err := g.Wait()
	if !errors.Is(err, boom) {
		t.Fatalf("Wait: %v, want boom", err)
	}
	if !strings.HasPrefix(err.Error(), "failing: ") {
		t.Fatalf("the error must name its member: %v", err)
	}
}

func TestGroupKeepsOnlyTheFirstError(t *testing.T) {
	g, _ := newGroup(context.Background())
	first := errors.New("first")
	started := make(chan struct{})
	g.Go("first", func() error {
		close(started)
		return first
	})
	<-started
	time.Sleep(5 * time.Millisecond)
	g.Go("second", func() error { return errors.New("second") })
	if err := g.Wait(); !errors.Is(err, first) {
		t.Fatalf("Wait: %v, want the first error", err)
	}
}

func TestGroupCancelStopsMembersWithoutWaiting(t *testing.T) {
	g, ctx := newGroup(context.Background())
	stopped := make(chan struct{})
	g.Go("member", func() error {
		<-ctx.Done()
		close(stopped)
		return nil
	})
	g.Cancel()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Cancel did not release the member")
	}
	if err := g.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}
}
