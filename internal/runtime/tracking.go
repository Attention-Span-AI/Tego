// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// GapCgroupTrackingFailed means the run's enforcement membership could not be maintained or monitored.
const GapCgroupTrackingFailed = "cgroup-tracking-failed"

const trackingPollInterval = 50 * time.Millisecond

func (r *runner) trackingError() error {
	counter, ok := r.handle.(enforce.TrackingFailureCounter)
	if !ok {
		return nil
	}
	n, err := counter.TrackingFailures()
	if err != nil {
		return fmt.Errorf("read descendant membership status: %w", err)
	}
	if n != 0 {
		return fmt.Errorf("%d descendant membership insertions failed", n)
	}
	return nil
}

// startTracking checks before child release, then monitors independently of the recorder's state and ring.
func (r *runner) startTracking(ctx context.Context) error {
	if _, ok := r.handle.(enforce.TrackingFailureCounter); !ok {
		return nil
	}
	if err := r.trackingError(); err != nil {
		r.failTracking(err)
		return err
	}
	r.group.Go("tracking", func() error { return r.watchTracking(ctx, trackingPollInterval) })
	return nil
}

func (r *runner) watchTracking(ctx context.Context, interval time.Duration) error {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := r.trackingError(); err != nil {
				r.failTracking(err)
				return nil
			}
		}
	}
}

func (r *runner) failTracking(err error) {
	r.trackingFailed.Store(true)
	r.trackingOnce.Do(func() {
		r.endRun(identity.ReasonError, "cgroup tracking: "+err.Error(),
			"run: descendant membership lost; ending the run", "run: kill after tracking failure", "err", err)
	})
}

// finalTrackingCheck closes the short-run window and writes an enforcement gap directly after the queue
// drains. A saturated record ring or event queue cannot erase the reason for this run's failed enforcement.
func (r *runner) finalTrackingCheck() {
	if err := r.trackingError(); err != nil {
		r.failTracking(err)
	}
	if r.trackingFailed.Load() {
		r.emitGapNow(source.Gap{What: record.GapEnforce, Why: GapCgroupTrackingFailed, Count: 1})
	}
}
