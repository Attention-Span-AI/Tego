// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// waitFanotifyChainProbe owns the worker through cancellation and cleanup. In particular, its caller may remove
// the probe's files only after this returns. The worker must stop on ctx.Done and release its resources first.
func waitFanotifyChainProbe(ctx context.Context, work func(context.Context) (bool, error)) (bool, error) {
	type result struct {
		inChain bool
		err     error
	}
	done := make(chan result, 1)
	go func() {
		inChain, err := work(ctx)
		done <- result{inChain, err}
	}()
	select {
	case r := <-done:
		if err := ctx.Err(); err != nil {
			return false, err
		}
		return r.inChain, r.err
	case <-ctx.Done():
		<-done
		return false, ctx.Err()
	}
}

func TestFanotifyProbeCancellationJoinsWorker(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "cancelled"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			wantErr := context.Canceled
			if deadline {
				cancel()
				ctx, cancel = context.WithDeadline(context.Background(), time.Time{})
				wantErr = context.DeadlineExceeded
			}
			defer cancel()
			started, cancelled := make(chan struct{}), make(chan struct{})
			cleanup, finished := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(cleanup) }) }
			t.Cleanup(release)
			done := make(chan error, 1)
			go func() {
				inChain, err := waitFanotifyChainProbe(ctx, func(ctx context.Context) (bool, error) {
					defer close(finished)
					close(started)
					<-ctx.Done()
					close(cancelled)
					// Model resource cleanup after a delayed attachment or open has observed cancellation.
					<-cleanup
					return true, nil
				})
				if inChain {
					err = errors.New("cancelled probe returned a successful result")
				}
				done <- err
			}()
			<-started
			cancel()
			<-cancelled
			select {
			case err := <-done:
				release()
				<-finished
				t.Fatalf("probe returned before the worker finished cleanup: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			release()
			if err := <-done; !errors.Is(err, wantErr) {
				t.Fatalf("probe error = %v, want %v", err, wantErr)
			}
			select {
			case <-finished:
			default:
				t.Fatal("probe returned without joining the worker")
			}
		})
	}
}
