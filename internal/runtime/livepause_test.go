// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// fakeFreezer stands in for cgroup.freeze: it records each write and fails the ones failNext says to. A wait for on
// answers waitErr[on], or for a freeze, notFrozen times ErrNotFrozen first; asking makes an ask hold a thread. Each
// wait moves the fake clock on by its bound, so the attempts and the back-off run on the clock and not the wall.
type fakeFreezer struct {
	writes    []bool
	frozen    bool
	failNext  map[bool]error
	waitErr   map[bool]error
	notFrozen int
	asking    bool
	clock     time.Time
}

func (f *fakeFreezer) install(t *testing.T) {
	t.Helper()
	oldF, oldW, oldA, oldN := freezeCgroup, waitFrozen, pauseAskWaiting, pauseNow
	t.Cleanup(func() { freezeCgroup, waitFrozen, pauseAskWaiting, pauseNow = oldF, oldW, oldA, oldN })
	f.clock = time.Unix(1_800_000_000, 0)
	freezeCgroup = func(_ cgroup.Cgroup, on bool) error {
		f.writes = append(f.writes, on)
		if err := f.failNext[on]; err != nil {
			return err
		}
		f.frozen = on
		return nil
	}
	waitFrozen = func(_ context.Context, _ cgroup.Cgroup, on bool, d time.Duration) error {
		f.clock = f.clock.Add(d)
		if on && f.notFrozen > 0 {
			f.notFrozen--
			return cgroup.ErrNotFrozen
		}
		return f.waitErr[on]
	}
	pauseAskWaiting = func(*runner) bool { return f.asking }
	pauseNow = func() time.Time { return f.clock }
}

// later moves the fake clock past the longest back-off.
func (f *fakeFreezer) later() { f.clock = f.clock.Add(pauseRetryMax + time.Second) }

// pauseRunner is a runner with a run directory, a cgroup path and a queue, enough for the poll.
func pauseRunner(t *testing.T) *runner {
	t.Helper()
	return &runner{log: slog.New(slog.DiscardHandler), dir: t.TempDir(), id: "r-0123abcd-mabc12-abcdef",
		cg: cgroup.Cgroup{Path: "/sys/fs/cgroup/fake/run-x.scope"}, queue: NewQueue(32)}
}

// controlLines drains r's queue for the live-control gap lines: "why serial by".
func controlLines(t *testing.T, r *runner) []string {
	t.Helper()
	r.queue.Close()
	var got []string
	for ev := range r.queue.C() {
		var p record.GapPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.LiveControl == nil {
			continue
		}
		if p.What != record.GapEnforce || p.LiveControl.Serial == 0 {
			t.Fatalf("control line %+v", p)
		}
		got = append(got, p.Why+" "+p.LiveControl.Op+" "+p.LiveControl.By)
	}
	return got
}

func setPause(t *testing.T, dir, run string, on bool, by string) {
	t.Helper()
	if _, err := liveblock.Update(context.Background(), dir, run, func(o *liveblock.Overlay) (bool, error) {
		var ok bool
		if on {
			_, ok = o.Pause(by, time.Now())
		} else {
			_, ok = o.Resume(by, time.Now())
		}
		return ok, nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestPollAppliesPauseAndResume: a pause freezes the run's cgroup, holds the stall clock and is recorded with who
// asked; a resume thaws it, releases the hold and is recorded.
func TestPollAppliesPauseAndResume(t *testing.T) {
	f := &fakeFreezer{}
	f.install(t)
	r := pauseRunner(t)
	b := &liveBlocks{}
	ctx := context.Background()
	setPause(t, r.dir, string(r.id), true, "uid:1000 pid:9 dashboard")
	r.pollLiveBlocks(ctx, b)
	if !f.frozen || !r.held() {
		t.Fatalf("after a pause: frozen %v, held %v", f.frozen, r.held())
	}
	r.pollLiveBlocks(ctx, b) // unchanged overlay: nothing is written again
	setPause(t, r.dir, string(r.id), false, "uid:1000 pid:10 cli")
	r.pollLiveBlocks(ctx, b)
	if f.frozen || r.held() {
		t.Fatalf("after a resume: frozen %v, held %v", f.frozen, r.held())
	}
	if want := []bool{true, false}; !slices.Equal(f.writes, want) {
		t.Fatalf("freezer writes %v, want %v", f.writes, want)
	}
	want := []string{"run-paused pause uid:1000 pid:9 dashboard", "run-resumed resume uid:1000 pid:10 cli"}
	if got := controlLines(t, r); !slices.Equal(got, want) {
		t.Fatalf("lines %q, want %q", got, want)
	}
}

// TestPauseFailureRecordedOnceAndRetried: a freeze the kernel refuses leaves the run running, is recorded once as
// pause-failed, is tried again on each poll, and is recorded as run-paused once it works.
func TestPauseFailureRecordedOnceAndRetried(t *testing.T) {
	f := &fakeFreezer{failNext: map[bool]error{true: syscall.EACCES}}
	f.install(t)
	r := pauseRunner(t)
	b := &liveBlocks{}
	ctx := context.Background()
	setPause(t, r.dir, string(r.id), true, "cli")
	r.pollLiveBlocks(ctx, b)
	r.pollLiveBlocks(ctx, b)
	if f.frozen || r.held() {
		t.Fatalf("a refused freeze: frozen %v, held %v", f.frozen, r.held())
	}
	if len(f.writes) != 1 {
		t.Fatalf("a poll inside the back-off wrote again: %v", f.writes)
	}
	f.failNext = nil
	f.later()
	r.pollLiveBlocks(ctx, b)
	if !f.frozen || !r.held() {
		t.Fatalf("the retry: frozen %v, held %v", f.frozen, r.held())
	}
	want := []string{"pause-failed pause cli", "run-paused pause cli"}
	if got := controlLines(t, r); !slices.Equal(got, want) {
		t.Fatalf("lines %q, want %q", got, want)
	}
}

// TestUnconfirmedFreezeIsThawed: a freeze cgroup.events does not confirm is tried a few times within freezeBudget,
// each attempt thawed again, so a failed pause never leaves the run half frozen.
func TestUnconfirmedFreezeIsThawed(t *testing.T) {
	f := &fakeFreezer{waitErr: map[bool]error{true: cgroup.ErrNotFrozen}}
	f.install(t)
	r := pauseRunner(t)
	setPause(t, r.dir, string(r.id), true, "cli")
	r.pollLiveBlocks(context.Background(), &liveBlocks{})
	most := int(freezeBudget / freezeAttempt)
	if f.frozen || r.held() || len(f.writes) < 2*(most/2) || len(f.writes) > 2*most || f.writes[len(f.writes)-1] {
		t.Fatalf("frozen %v, held %v, writes %v (want %d to %d attempts, each thawed)", f.frozen, r.held(), f.writes, most/2, most)
	}
	for i, w := range f.writes {
		if w != (i%2 == 0) {
			t.Fatalf("write %d is %v: every freeze must be followed by its thaw (%v)", i, w, f.writes)
		}
	}
	if got := controlLines(t, r); !slices.Equal(got, []string{"pause-failed pause cli"}) {
		t.Fatalf("lines %q", got)
	}
}

// TestStopThawsAndStaysThawed: a stop signal thaws a paused run before the handler sees it, and the pause the overlay
// still asks for is not applied again afterwards.
func TestStopThawsAndStaysThawed(t *testing.T) {
	f := &fakeFreezer{}
	f.install(t)
	r := pauseRunner(t)
	g, ctx := newGroup(context.Background())
	r.group = g
	cancel := g.Cancel
	defer cancel()
	b := &liveBlocks{}
	setPause(t, r.dir, string(r.id), true, "cli")
	r.pollLiveBlocks(ctx, b)
	in := make(chan os.Signal, 4)
	out := r.thawOnStop(ctx, in)
	in <- syscall.SIGWINCH
	if s := <-out; s != syscall.SIGWINCH || !f.frozen {
		t.Fatalf("a signal that starts no stop_grace: %v, frozen %v", s, f.frozen)
	}
	in <- syscall.SIGTERM
	if s := <-out; s != syscall.SIGTERM || f.frozen || r.held() {
		t.Fatalf("SIGTERM: %v, frozen %v, held %v", s, f.frozen, r.held())
	}
	setPause(t, r.dir, string(r.id), false, "cli")
	setPause(t, r.dir, string(r.id), true, "cli")
	r.pollLiveBlocks(ctx, b)
	if f.frozen {
		t.Fatal("a pause after the stop froze the run again")
	}
	cancel()
	if err := r.group.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// TestNoCgroupPauseFails: a run with no cgroup of its own records pause-failed and is never held.
func TestNoCgroupPauseFails(t *testing.T) {
	f := &fakeFreezer{}
	f.install(t)
	r := pauseRunner(t)
	r.cg = cgroup.Cgroup{}
	setPause(t, r.dir, string(r.id), true, "cli")
	r.pollLiveBlocks(context.Background(), &liveBlocks{})
	if r.held() || len(f.writes) != 0 {
		t.Fatalf("held %v, writes %v", r.held(), f.writes)
	}
	if got := controlLines(t, r); !slices.Equal(got, []string{"pause-failed pause cli"}) {
		t.Fatalf("lines %q", got)
	}
}

// TestSecondAttemptConfirms: a freeze that lands on an in-flight held read (the deputy frozen with the agent) is
// thawed and tried again at once, and the pause is recorded run-paused, not pause-failed.
func TestSecondAttemptConfirms(t *testing.T) {
	f := &fakeFreezer{notFrozen: 2}
	f.install(t)
	r := pauseRunner(t)
	setPause(t, r.dir, string(r.id), true, "cli")
	r.pollLiveBlocks(context.Background(), &liveBlocks{})
	if !f.frozen || !r.held() || !slices.Equal(f.writes, []bool{true, false, true, false, true}) {
		t.Fatalf("frozen %v, held %v, writes %v", f.frozen, r.held(), f.writes)
	}
	if got := controlLines(t, r); !slices.Equal(got, []string{"run-paused pause cli"}) {
		t.Fatalf("lines %q", got)
	}
}

// TestFailedPauseBacksOff: a pause that is not confirmed is not tried again on every poll, which would keep the agent
// frozen most of the time, but after a back-off that grows, and it is recorded once.
func TestFailedPauseBacksOff(t *testing.T) {
	f := &fakeFreezer{waitErr: map[bool]error{true: cgroup.ErrNotFrozen}}
	f.install(t)
	r := pauseRunner(t)
	b := &liveBlocks{}
	ctx := context.Background()
	setPause(t, r.dir, string(r.id), true, "cli")
	r.pollLiveBlocks(ctx, b)
	n := len(f.writes)
	r.pollLiveBlocks(ctx, b)
	r.pollLiveBlocks(ctx, b)
	if len(f.writes) != n {
		t.Fatalf("polls inside the back-off froze again: %d writes, want %d", len(f.writes), n)
	}
	f.clock = f.clock.Add(pauseRetryFirst)
	r.pollLiveBlocks(ctx, b)
	if len(f.writes) == n {
		t.Fatal("the pause was not tried again once its back-off passed")
	}
	if r.pause.backoff != 2*pauseRetryFirst {
		t.Fatalf("back-off %s after two failures, want %s", r.pause.backoff, 2*pauseRetryFirst)
	}
	if got := controlLines(t, r); !slices.Equal(got, []string{"pause-failed pause cli"}) {
		t.Fatalf("lines %q", got)
	}
}

// TestAskWaitingDefersPause: no freeze is tried while an ask holds a thread for a person (it could not complete);
// the pause is recorded pause-failed, the run is not held by it, and it is put in force once the ask is answered.
func TestAskWaitingDefersPause(t *testing.T) {
	f := &fakeFreezer{asking: true}
	f.install(t)
	r := pauseRunner(t)
	b := &liveBlocks{}
	ctx := context.Background()
	setPause(t, r.dir, string(r.id), true, "uid:1000 pid:9 cli")
	r.pollLiveBlocks(ctx, b)
	r.pollLiveBlocks(ctx, b)
	if len(f.writes) != 0 || r.pause.held.Load() {
		t.Fatalf("a freeze was tried while an ask waits: writes %v, held %v", f.writes, r.pause.held.Load())
	}
	f.asking = false
	r.pollLiveBlocks(ctx, b)
	if !f.frozen || !r.held() {
		t.Fatalf("once answered: frozen %v, held %v", f.frozen, r.held())
	}
	want := []string{"pause-failed pause uid:1000 pid:9 cli", "run-paused pause uid:1000 pid:9 cli"}
	if got := controlLines(t, r); !slices.Equal(got, want) {
		t.Fatalf("lines %q, want %q", got, want)
	}
}

// TestResumeOfAFailedPause: a resume that withdraws a pause the launcher never put in force (the freeze write was
// refused, or the run has no cgroup) touches no cgroup, records run-resumed, and leaves the run unheld, so stall_after
// counts again.
func TestResumeOfAFailedPause(t *testing.T) {
	for _, tc := range []struct {
		name   string
		f      *fakeFreezer
		noCG   bool
		writes []bool
	}{
		{"refused write", &fakeFreezer{failNext: map[bool]error{true: syscall.EACCES, false: syscall.EACCES}}, false, []bool{true}},
		{"no cgroup", &fakeFreezer{}, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.f.install(t)
			r := pauseRunner(t)
			if tc.noCG {
				r.cg = cgroup.Cgroup{}
			}
			b := &liveBlocks{}
			ctx := context.Background()
			setPause(t, r.dir, string(r.id), true, "cli")
			r.pollLiveBlocks(ctx, b)
			if r.held() {
				t.Fatal("a pause that froze nothing holds the run")
			}
			setPause(t, r.dir, string(r.id), false, "cli")
			r.pollLiveBlocks(ctx, b)
			tc.f.later()
			r.pollLiveBlocks(ctx, b)
			if r.held() || tc.f.frozen || !slices.Equal(tc.f.writes, tc.writes) {
				t.Fatalf("held %v, frozen %v, writes %v (want %v)", r.held(), tc.f.frozen, tc.f.writes, tc.writes)
			}
			want := []string{"pause-failed pause cli", "run-resumed resume cli"}
			if got := controlLines(t, r); !slices.Equal(got, want) {
				t.Fatalf("lines %q, want %q", got, want)
			}
		})
	}
}

// TestLostPauseIsRecorded: an overlay whose pause is no longer among its changes still has the run frozen, and the
// freeze is recorded under the overlay's serial, naming no one.
func TestLostPauseIsRecorded(t *testing.T) {
	f := &fakeFreezer{}
	f.install(t)
	r := pauseRunner(t)
	o := liveblock.New(string(r.id))
	o.Serial, o.Paused = 300, true
	data, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.dir, liveblock.FileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	r.pollLiveBlocks(context.Background(), &liveBlocks{})
	if !f.frozen {
		t.Fatal("the overlay's paused was not put in force")
	}
	if got := controlLines(t, r); !slices.Equal(got, []string{"run-paused pause "}) {
		t.Fatalf("lines %q", got)
	}
}

// TestMarkPauseReader: a run with a directory and a cgroup of its own marks that it reads a pause; one with no cgroup
// to freeze does not, so no writer asks a pause of it.
func TestMarkPauseReader(t *testing.T) {
	r := pauseRunner(t)
	r.markPauseReader()
	if !liveblock.TakesControl(r.dir) {
		t.Fatal("a run with a cgroup of its own did not mark that it reads a pause")
	}
	r = pauseRunner(t)
	r.cg = cgroup.Cgroup{}
	r.markPauseReader()
	if liveblock.TakesControl(r.dir) {
		t.Fatal("a run with no cgroup of its own marked that it reads a pause")
	}
}
