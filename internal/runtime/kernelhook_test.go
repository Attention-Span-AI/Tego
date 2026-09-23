// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// streamSource is a kernel recorder that records the hooks it was given (ProcessStream).
type streamSource struct {
	plainSource
	hooks  []source.ProcessHook
	refuse error
}

func (s *streamSource) AddProcessHook(h source.ProcessHook) error {
	if s.refuse != nil {
		return s.refuse
	}
	s.hooks = append(s.hooks, h)
	return nil
}

// followerSource is a capture source that follows the kernel record (KernelFollower).
type followerSource struct {
	plainSource
	hash  string
	calls int
}

func (f *followerSource) FollowKernel(h string)          { f.hash = h; f.calls++ }
func (f *followerSource) OnExec(int, uint64, string)     {}
func (f *followerSource) OnOpen(int, uint64, string)     {}
func (f *followerSource) OnExit(int)                     {}
func (f *followerSource) String() string                 { return f.name }
func (f *followerSource) followed() (hash string, n int) { return f.hash, f.calls }
func (s *streamSource) hooked(f source.ProcessHook) (found bool) {
	for _, h := range s.hooks {
		if sf, ok := h.(stageFilter); ok {
			h = sf.ProcessHook
		}
		if q, ok := h.(*hookQueue); ok {
			h = q.next
		}
		if h == f {
			return true
		}
	}
	return false
}

// TestKernelRecordFeedsTheUprobeSource is the recorder-to-uprobe wiring capture-derive.md §4 describes
// ("onExec driven by observe's exec stream"): a capture source that follows the kernel record is told the
// build the handle pinned and is handed the recorder's process stream, before either of them starts. The
// uprobe source had no caller for OnExec or OnExit at all, so it attached to nothing on every run.
func TestKernelRecordFeedsTheUprobeSource(t *testing.T) {
	follower := &followerSource{plainSource: plainSource{name: "uprobe"}}
	other := &plainSource{name: "forwarder"}
	rec := &streamSource{plainSource: plainSource{name: "observe"}}
	r := newTestRunner(Deps{
		Capture:        []source.Source{other, follower},
		ObserveFactory: func(string) (source.Source, error) { return rec, nil },
	})
	r.startKernelRecord(tier2Handle{hash: "deadbeef"})
	t.Cleanup(r.closeHookQueues)
	if hash, n := follower.followed(); hash != "deadbeef" || n != 1 {
		t.Errorf("the follower was told %q %d times, want the handle's hash once", hash, n)
	}
	if !rec.hooked(follower) || len(rec.hooks) != 1 {
		t.Errorf("recorder hooks %v, want exactly the follower", rec.hooks)
	}
}

// TestNoRecorderNoFollow is the other side: with no recorder to drive it, a follower is told nothing, and
// its own Start reports it as unavailable; and a recorder that refuses the hook (already started) leaves
// the follower untold, rather than telling it a build no exec will ever arrive for.
func TestNoRecorderNoFollow(t *testing.T) {
	t.Run("no recorder", func(t *testing.T) {
		follower := &followerSource{plainSource: plainSource{name: "uprobe"}}
		r := newTestRunner(Deps{
			Capture:        []source.Source{follower},
			ObserveFactory: func(string) (source.Source, error) { return nil, errors.New("no pinned ring buffer") },
		})
		r.startKernelRecord(tier2Handle{hash: "deadbeef"})
		t.Cleanup(r.closeHookQueues)
		if _, n := follower.followed(); n != 0 {
			t.Error("a follower was told a build with no recorder to drive it")
		}
	})
	t.Run("hook refused", func(t *testing.T) {
		follower := &followerSource{plainSource: plainSource{name: "uprobe"}}
		rec := &streamSource{plainSource: plainSource{name: "observe"}, refuse: errors.New("already started")}
		r := newTestRunner(Deps{
			Capture:        []source.Source{follower},
			ObserveFactory: func(string) (source.Source, error) { return rec, nil },
		})
		r.startKernelRecord(tier2Handle{hash: "deadbeef"})
		t.Cleanup(r.closeHookQueues)
		if _, n := follower.followed(); n != 0 {
			t.Error("a follower was told a build whose recorder refused its hook")
		}
	})
}

// execLog is a follower that records the execs it was handed.
type execLog struct {
	followerSource
	execs []string
}

func (e *execLog) OnExec(pid int, cg uint64, path string) {
	e.execs = append(e.execs, fmt.Sprintf("%d %d %s", pid, cg, path))
}

// TestChildStageIsNotTheAgent is the second condition. The run's first process is this launcher's clone,
// which execs the launcher's own binary as `tego __child` in the run's cgroup and then execs the agent in
// place. The kernel record sees both execs, and the uprobe source, handed the first, held a verdict for the
// tego binary and settled it when the agent's exec replaced the image: every tier-2 capture run wrote a
// static-tls-no-symbols line naming tego, about no process of the agent's. The stage's exec — the child's
// pid, the path the launcher execs it by — never reaches a follower; the agent's exec under the same pid, and
// any exec of another pid by that path, still do.
func TestChildStageIsNotTheAgent(t *testing.T) {
	cases := []struct {
		name     string
		launcher *launch.Launcher
		stage    string
	}{
		{"the default /proc/self/exe", &launch.Launcher{}, "/proc/self/exe"},
		{"a launcher given its binary", &launch.Launcher{Exe: "/usr/local/bin/tego"}, "/usr/local/bin/tego"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			follower := &execLog{followerSource: followerSource{plainSource: plainSource{name: "uprobe"}}}
			rec := &streamSource{plainSource: plainSource{name: "observe"}}
			r := newTestRunner(Deps{
				Capture:        []source.Source{follower},
				ObserveFactory: func(string) (source.Source, error) { return rec, nil },
			})
			r.startKernelRecord(tier2Handle{hash: "deadbeef"})
			t.Cleanup(r.closeHookQueues)
			if len(rec.hooks) != 1 {
				t.Fatalf("recorder hooks %v, want the follower", rec.hooks)
			}
			// startChild runs after the recorder is built and before it starts.
			r.launcher, r.child = tc.launcher, &launch.Child{PID: 4242}
			h := rec.hooks[0]
			h.OnExec(4242, 41, tc.stage)                  // the child stage
			h.OnExec(4242, 41, "/usr/local/bin/go-agent") // the agent, execed in place
			h.OnExec(4243, 41, tc.stage)                  // another process of the run re-execing itself
			r.closeHookQueues()                           // the calls are made on the queue's goroutine
			want := []string{"4242 41 /usr/local/bin/go-agent", "4243 41 " + tc.stage}
			if strings.Join(follower.execs, "|") != strings.Join(want, "|") {
				t.Errorf("follower saw %q, want %q", follower.execs, want)
			}
		})
	}
}

// startLog is a follower that notes, when it starts, which build it was told and what had started before it.
type startLog struct {
	followerSource
	order    *[]string
	atStart  string
	anyStart bool
}

func (f *startLog) Start(context.Context, source.RunRef, source.Sink) error {
	f.atStart, f.anyStart = f.hash, true
	*f.order = append(*f.order, f.name)
	return nil
}

// orderedStream is a kernel recorder that notes its start, and whose Start leaves it reading nothing when inert
// is set: another run of the build holds the ring, or the run had no row to scope by. It says so the way
// observe.Recorder does, with gap what=record why=kernel-record-unavailable.
type orderedStream struct {
	streamSource
	order   *[]string
	inert   bool
	started bool
}

func (s *orderedStream) Start(context.Context, source.RunRef, source.Sink) error {
	s.started = true
	*s.order = append(*s.order, s.name)
	return nil
}

func (s *orderedStream) Gaps() []source.Gap {
	if !s.started || !s.inert {
		return nil
	}
	return []source.Gap{{What: record.GapRecord, Why: GapKernelRecordUnavailable, Count: 1}}
}

// TestInertRecorderWithdrawsItsFollowers is the split the one-reader rule could leave: the recorder and the uprobe
// source each walk the build's run set at their own Start, another run's row can appear between the walks, and a
// source that decided to capture beside a recorder that decided to read nothing attaches nothing, since only the
// recorder feeds it execs and opens, while run_start named it as the run's capture. The run starts the recorder
// first, and when it reads nothing, every follower starts told no build, so its own Start records
// mechanism-unavailable. A recorder that reads leaves its followers the build they were told.
func TestInertRecorderWithdrawsItsFollowers(t *testing.T) {
	for _, inert := range []bool{true, false} {
		t.Run(fmt.Sprintf("inert=%v", inert), func(t *testing.T) {
			var order []string
			follower := &startLog{followerSource: followerSource{plainSource: plainSource{name: "uprobe"}}, order: &order}
			forwarder := &plainSource{name: "forwarder"}
			rec := &orderedStream{streamSource: streamSource{plainSource: plainSource{name: "observe"}}, order: &order,
				inert: inert}
			r := newTestRunner(Deps{
				Capture:        []source.Source{follower, forwarder},
				ObserveFactory: func(string) (source.Source, error) { return rec, nil },
			})
			r.startKernelRecord(tier2Handle{hash: "deadbeef"})
			t.Cleanup(r.closeHookQueues)
			// startWorkers' loop: every source in allSources' order.
			for _, s := range r.allSources() {
				if err := s.Start(context.Background(), source.RunRef{}, nil); err != nil {
					t.Fatal(err)
				}
			}
			if strings.Join(order, ",") != "observe,uprobe" {
				t.Fatalf("start order %v, want the recorder before the capture source it drives", order)
			}
			want := "deadbeef"
			if inert {
				want = ""
			}
			if !follower.anyStart || follower.atStart != want {
				t.Errorf("the follower started told build %q, want %q", follower.atStart, want)
			}
		})
	}
}
