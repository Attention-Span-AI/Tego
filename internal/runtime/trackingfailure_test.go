// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

type trackingSource struct {
	plainSource
	fail func(error)
}

type trackingHandle struct {
	fakeHandle
	n   uint64
	err error
}

func (h *trackingHandle) TrackingFailures() (uint64, error) { return h.n, h.err }

// A dropped ring sample must not hide an enforcement failure; no recorder is wired in these cases.
func TestTrackingWatchdogWithoutRecorder(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    uint64
		err  error
	}{
		{name: "ring event lost", n: 1},
		{name: "monitor unreadable", err: errors.New("counter unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRunner(Deps{})
			cg := &fakeCgroups{}
			r.cgm, r.cg = cg, cgroup.Cgroup{Path: "/run/test"}
			r.handle = &trackingHandle{n: tc.n, err: tc.err}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := r.watchTracking(ctx, time.Millisecond); err != nil {
				t.Fatal(err)
			}
			if ctx.Err() != nil || r.terminal != identity.ReasonError || cg.killed != 1 || !r.trackingFailed.Load() {
				t.Fatalf("terminal=%v detail=%q killed=%d", r.terminal, r.detail, cg.killed)
			}
			r.failTracking(errors.New("a delayed ring notification"))
			if cg.killed != 1 {
				t.Fatal("counter and ring independently killed the same run")
			}
		})
	}
}

func TestTrackingStartupRefusesFailedMembership(t *testing.T) {
	r := newTestRunner(Deps{})
	r.handle = &trackingHandle{n: 1}
	if err := r.startTracking(context.Background()); err == nil || !r.trackingFailed.Load() {
		t.Fatal("failed membership was accepted before child release")
	}
}

// A run that ends before the first watchdog tick still records a terminal error and a durable gap.
func TestTrackingFinalCheckClosesShortRunWindow(t *testing.T) {
	r := newTestRunner(Deps{})
	r.handle = &trackingHandle{n: 1}
	var events []*record.Event
	r.pipe = &pipeline{handle: func(ev *record.Event) { events = append(events, ev) }}
	r.finalTrackingCheck()
	if r.terminal != identity.ReasonError || len(events) != 1 {
		t.Fatalf("terminal=%v events=%v", r.terminal, events)
	}
	var p record.GapPayload
	err := events[0].DecodePayload(&p)
	if err != nil || p.What != record.GapEnforce || p.Why != GapCgroupTrackingFailed || p.Count != 1 {
		t.Fatalf("gap=%+v err=%v", p, err)
	}
}

func TestTrackingHealthyRunAndCancellation(t *testing.T) {
	r := newTestRunner(Deps{})
	r.handle = &trackingHandle{}
	ctx, cancel := context.WithCancel(context.Background())
	r.group, ctx = newGroup(ctx)
	if err := r.startTracking(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := r.group.Wait(); err != nil {
		t.Fatal(err)
	}
	r.finalTrackingCheck()
	if r.trackingFailed.Load() {
		t.Fatal("a healthy run or cancellation was called a tracking failure")
	}
}

func (s *trackingSource) SetTrackingFailure(fn func(error)) { s.fail = fn }

func TestTrackingFailureEndsRun(t *testing.T) {
	src := &trackingSource{}
	r := newTestRunner(Deps{ObserveFactory: func(string) (source.Source, error) { return src, nil }})
	cg := &fakeCgroups{}
	r.cgm, r.cg = cg, cgroup.Cgroup{Path: "/run/test"}
	r.startKernelRecord(tier2Handle{hash: "test"})
	t.Cleanup(r.closeHookQueues)
	if src.fail == nil {
		t.Fatal("tracking callback not installed")
	}
	src.fail(errors.New("membership full"))
	if r.terminal != identity.ReasonError || !strings.Contains(r.detail, "membership full") || cg.killed != 1 {
		t.Fatalf("reason=%v detail=%q killed=%d", r.terminal, r.detail, cg.killed)
	}
}
