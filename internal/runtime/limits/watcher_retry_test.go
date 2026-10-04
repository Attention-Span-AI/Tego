// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// failFirstKiller fails its first n kills and then succeeds.
type failFirstKiller struct {
	n     int64
	err   error
	kills atomic.Int64
}

func (k *failFirstKiller) Kill(cgroup.Cgroup) error {
	if k.kills.Add(1) <= k.n {
		return k.err
	}
	return nil
}

// TestObserveTripKillFailureIsRetriedByRun: a token breach on the pipeline goroutine whose cgroup.kill failed
// used to leave the run going past its ceiling, since Tick returns nil once tripped and Observe only logs.
// Run now repeats the kill and, if it fails again, returns the error to the worker group (§7: never swallowed).
func TestObserveTripKillFailureIsRetriedByRun(t *testing.T) {
	boom := errors.New("EMFILE")
	build := func(k Killer) *Watcher {
		w := NewWatcher(agent.ResolvedLimits{Tokens: 100}, testTable(), k,
			cgroup.Cgroup{Path: "/sys/fs/cgroup/test"}, &fakeClock{}, &fakeSink{},
			WithTickInterval(5*time.Millisecond))
		w.Observe(runStart(1_000))
		w.Observe(response(2_000, "claude-sonnet-4-5-20250929", 60, 60, 0, 0))
		return w
	}
	t.Run("the retry succeeds", func(t *testing.T) {
		k := &failFirstKiller{n: 1, err: boom}
		w := build(k)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- w.Run(ctx) }()
		deadline := time.After(2 * time.Second)
		for k.kills.Load() < 2 {
			select {
			case <-deadline:
				t.Fatalf("%d kills: the failed kill was never retried", k.kills.Load())
			case <-time.After(5 * time.Millisecond):
			}
		}
		time.Sleep(30 * time.Millisecond)
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("Run = %v, want nil after the retry succeeded", err)
		}
		if n := k.kills.Load(); n != 2 {
			t.Errorf("%d kills, want the failure and one successful retry", n)
		}
	})
	t.Run("the retry fails", func(t *testing.T) {
		w := build(&failFirstKiller{n: 100, err: boom})
		done := make(chan error, 1)
		go func() { done <- w.Run(t.Context()) }()
		select {
		case err := <-done:
			if !errors.Is(err, boom) {
				t.Fatalf("Run = %v, want the kill error", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Run swallowed a kill that kept failing")
		}
	})
}
