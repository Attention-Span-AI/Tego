// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// hookLog is a ProcessHook that records every call in order.
type hookLog struct {
	mu    sync.Mutex
	calls []string
}

func (h *hookLog) OnExec(pid int, cg uint64, path string) {
	h.add(fmt.Sprintf("exec %d %d %s", pid, cg, path))
}
func (h *hookLog) OnOpen(pid int, cg uint64, path string) {
	h.add(fmt.Sprintf("open %d %d %s", pid, cg, path))
}
func (h *hookLog) OnExit(pid int) { h.add(fmt.Sprintf("exit %d", pid)) }

func (h *hookLog) add(s string) {
	h.mu.Lock()
	h.calls = append(h.calls, s)
	h.mu.Unlock()
}

func (h *hookLog) all() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.calls...)
}

// hookSamples is one process's life as the kernel record carries it: its exec, an open of the libssl its
// loader maps, an open whose path the kernel truncated, and its exit.
func hookSamples() [][]byte {
	h := sample{MonoNS: 1000, CgroupID: 77, PID: 50, TID: 50, PPID: 1}
	open := h
	open.Kind, open.MonoNS = KindOpen, 1100
	long := h
	long.Kind, long.MonoNS = KindOpen, 1200
	exit := h
	exit.Kind, exit.MonoNS = KindExit, 1300
	return [][]byte{
		execSample(h, 900*proc.NanosPerTick, "python3", "/usr/bin/python3.13", []string{"python3", "app.py"}, false),
		fsSample(open, 0, 1, 2049, "/usr/lib/x86_64-linux-gnu/libssl.so.3", ""),
		fsSample(long, 0, 2, 2049, "/"+strings.Repeat("d", PathMax), ""),
		exitSample(exit, 0, 0),
	}
}

// TestRecorderFeedsProcessHooks is the recorder's half of the uprobe wiring (capture-derive.md §4): every
// exec, open and exit it drains reaches a hook added before Start, in the order the kernel wrote them and
// with the pid and cgroup the sample carries, and an exec with the path the process exec'd, which is all
// that names a process gone before its hook ran. An open whose path was truncated names no file and is not
// passed on.
func TestRecorderFeedsProcessHooks(t *testing.T) {
	f := newFixture(t)
	hook := &hookLog{}
	ring := newFakeRing(hookSamples()...)
	r, err := New(Options{Rules: f.rules, Reader: ring, Proc: f.procFS, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.AddProcessHook(hook); err != nil {
		t.Fatalf("AddProcessHook before Start: %v", err)
	}
	sink := &fakeSink{}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-host-1", Agent: "a"}, sink); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(hook.all()) == 3 }, "the hook never saw the process's exec, open and exit")
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	want := []string{"exec 50 77 /usr/bin/python3.13", "open 50 77 /usr/lib/x86_64-linux-gnu/libssl.so.3", "exit 50"}
	if got := hook.all(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("hook calls %q, want %q", got, want)
	}
	if len(sink.all()) == 0 {
		t.Error("feeding the hook replaced recording: no event reached the sink")
	}
}

// TestRecorderHandlesAProcessExitOnce: trace_proc reports a thread group's exit from its last thread, and two
// threads that end at one instant can both find the group's live count at 0 and both report it. The hook
// hears of the exit once; a later exit of the pid's next occupant, with its own start time, is its own.
func TestRecorderHandlesAProcessExitOnce(t *testing.T) {
	f := newFixture(t)
	hook := &hookLog{}
	exit := sample{Kind: KindExit, MonoNS: 1300, CgroupID: 77, PID: 50, TID: 51, Start: 900 * proc.NanosPerTick}
	twin := exit
	twin.TID, twin.MonoNS = 52, 1301
	next := exit
	next.MonoNS, next.Start = 5000, 4000*proc.NanosPerTick
	ring := newFakeRing(exitSample(exit, 0, 0), exitSample(twin, 0, 0), exitSample(next, 0, 0))
	r, err := New(Options{Rules: f.rules, Reader: ring, Proc: f.procFS, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.AddProcessHook(hook); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-host-1", Agent: "a"}, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { ring.mu.Lock(); defer ring.mu.Unlock(); return len(ring.samples) == 0 }, "never drained")
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if got := hook.all(); strings.Join(got, "|") != "exit 50|exit 50" {
		t.Errorf("hook calls %q, want one exit for each of the two processes", got)
	}
}

// TestRecordOffStillFeedsExecAndExit is E23 for the hook: under record: off the kernel still emits exec and
// exit, and the recorder, which records nothing, still hands them on — what a hook does with a process is
// not recording.
func TestRecordOffStillFeedsExecAndExit(t *testing.T) {
	f := newFixture(t)
	f.rules.Record = agent.RecordOff
	hook := &hookLog{}
	ring := newFakeRing(hookSamples()...)
	r, err := New(Options{Rules: f.rules, Reader: ring, Proc: f.procFS, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.AddProcessHook(hook); err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-host-1", Agent: "a"}, sink); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		calls := hook.all()
		return len(calls) > 0 && calls[len(calls)-1] == "exit 50"
	}, "the hook never saw the exit under record: off")
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	calls := hook.all()
	if calls[0] != "exec 50 77 /usr/bin/python3.13" {
		t.Errorf("hook calls %q, want the exec first", calls)
	}
	if got := sink.all(); len(got) != 0 {
		t.Errorf("record: off emitted %d events", len(got))
	}
}

// TestAddProcessHookAfterStartIsRefused pins the one precondition: the drain reads the hooks without a lock,
// so one added once it runs would be a data race, and is refused instead of half-honoured.
func TestAddProcessHookAfterStartIsRefused(t *testing.T) {
	f := newFixture(t)
	r, err := New(Options{Rules: f.rules, Reader: newFakeRing(), Proc: f.procFS})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-host-1", Agent: "a"}, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	if err := r.AddProcessHook(&hookLog{}); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("AddProcessHook after Start = %v, want ErrAlreadyStarted", err)
	}
}
