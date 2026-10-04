// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestExecHandoffDelegatesPolicyOnlyWhenReady(t *testing.T) {
	for _, ready := range []bool{false, true} {
		t.Run(map[bool]string{false: "fallback", true: "handoff"}[ready], func(t *testing.T) {
			f := newFake()
			f.tgid[42] = 40
			f.stats[40] = procStat{ppid: 1, start: 1234}
			l, sink := newTestLoop(t, f, searchPolicy())
			l.kernelExecHandoff = func() bool { return ready }
			l.mono = func() uint64 { return 100 }
			execAt(l, f, nrFor(t, "execve"), 42, 0, "/unlisted", "unlisted", "arg")
			r, ok := f.lastResp()
			if !ok {
				t.Fatal("no response")
			}
			if (r.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0) != ready {
				t.Fatalf("response %+v, ready=%v", r, ready)
			}
			if ready {
				if len(sink.all()) != 0 {
					t.Fatal("supervisor predicted a kernel decision")
				}
				n, ok := l.ContinuedExec(42, 40, 1234*proc.NanosPerTick+99, 110)
				if !ok || n.Path != "/unlisted" || len(n.Argv) != 2 || n.Argv[1] != "arg" || n.AttemptMonoNS != 100 {
					t.Fatalf("naming %+v, found=%v", n, ok)
				}
			} else if len(sink.all()) != 1 {
				t.Fatal("fallback lost its refusal")
			}
		})
	}
}

func TestExecNamingDoesNotReuseConsumedOrUnreadableAttempts(t *testing.T) {
	var h execHandover
	put := func(at uint64, named bool, pid int, start uint64, arg string) {
		h.put(continuedExec{tid: 42, pid: pid, startNS: start, named: named,
			naming: ExecNaming{AttemptMonoNS: at, Argv: []string{arg}}})
	}
	put(100, true, 40, 12*proc.NanosPerTick, "first")
	put(200, true, 40, 12*proc.NanosPerTick, "second")
	// A delayed event is bound to its original attempt, not the newest entry.
	if n, ok := h.find(42, 40, 12*proc.NanosPerTick+9, 150); !ok || n.Argv[0] != "first" {
		t.Fatalf("delayed %+v %v", n, ok)
	}
	if _, ok := h.find(42, 40, 12*proc.NanosPerTick, 160); ok {
		t.Fatal("duplicate consumed old naming")
	}
	n, ok := h.find(42, 40, 12*proc.NanosPerTick, 250)
	if !ok || n.Argv[0] != "second" {
		t.Fatalf("second %+v %v", n, ok)
	}
	n.Argv[0] = "mutated"
	if _, ok := h.find(42, 40, 12*proc.NanosPerTick, 260); ok {
		t.Fatal("duplicate exposed prior attempt")
	}
	put(300, false, 40, 12*proc.NanosPerTick, "")
	if _, ok := h.find(42, 40, 12*proc.NanosPerTick, 350); ok {
		t.Fatal("unreadable attempt used prior argv")
	}
	put(400, true, 41, 13*proc.NanosPerTick, "reused")
	if _, ok := h.find(42, 40, 12*proc.NanosPerTick, 450); ok {
		t.Fatal("reused TID accepted old process")
	}
	if _, ok := h.find(42, 41, 14*proc.NanosPerTick, 450); ok {
		t.Fatal("reused PID accepted different birth")
	}
	if _, ok := h.find(42, 41, 13*proc.NanosPerTick, 400); ok {
		t.Fatal("event preceding CONTINUE accepted")
	}
}

func TestExecNamingEvictionAndArgvOwnership(t *testing.T) {
	var h execHandover
	argv := []string{"original"}
	h.put(continuedExec{tid: 42, pid: 42, startNS: proc.NanosPerTick, named: true, naming: ExecNaming{AttemptMonoNS: 1, Argv: argv}})
	argv[0] = "changed"
	n, ok := h.find(42, 42, proc.NanosPerTick, 2)
	if !ok || n.Argv[0] != "original" {
		t.Fatalf("argv borrowed from caller: %+v %v", n, ok)
	}
	for i := 0; i < handoverSize; i++ {
		h.put(continuedExec{tid: 43, pid: 43, startNS: proc.NanosPerTick, named: true, naming: ExecNaming{AttemptMonoNS: uint64(i + 3)}})
	}
	if _, ok := h.find(42, 42, proc.NanosPerTick, 1000); ok {
		t.Fatal("evicted attempt remained available")
	}
}

// TestPlaneExecWithoutOutcomeLinksHandsItsNaming: where the plane decides the run's execs on a kernel whose exec
// outcome links do not attach (5.14: the fast handover is never ready), this loop decides the exec, continues it and
// writes no line, and the kernel's line is the recorder's sched_process_exec record (R7a). That line takes this loop's
// naming, so the attempt is handed over with it: the anonymous image fileless, the argv read, the spelling (only a
// supervisor-owned marker was kept, and the line read as an ordinary file's exec).
func TestPlaneExecWithoutOutcomeLinksHandsItsNaming(t *testing.T) {
	const argvAddr = 0x20000
	f := newFake()
	f.tgid[42] = 40
	f.stats[40] = procStat{ppid: 1, start: 1234}
	f.links["/proc/42/fd/7"] = "/memfd:payload (deleted)"
	f.put(emptyPathAddr, cstr(""))
	execFixture(f, argvAddr, []string{"payload", "arg"})
	pol := contractPolicy(&agent.Contract{Exec: &agent.ExecSection{Allow: []string{}, Anonymous: true}}, nil, nil)
	l, sink := newTestLoop(t, f, pol)
	l.kernelExecHandoff = func() bool { return false }
	l.kernelExecs = func() bool { return true }
	l.mono = func() uint64 { return 100 }
	l.handle(notifFor(nrFor(t, "execveat"), 42, 7, emptyPathAddr, argvAddr, 0, unix.AT_EMPTY_PATH))
	wantExecAnswer(t, f, record.VerdictAllow)
	if lines := sink.all(); len(lines) != 0 {
		t.Fatalf("the kernel's recorder owns the line, and this loop wrote %d: %+v", len(lines), lines)
	}
	n, ok := l.ContinuedExec(42, 40, 1234*proc.NanosPerTick, 110)
	if !ok || n.SupervisorOwned || !n.Fileless || n.Path != "/memfd:payload" || len(n.Argv) != 2 || n.Argv[1] != "arg" ||
		n.ExecID == "" || n.AttemptMonoNS != 100 {
		t.Fatalf("naming %+v, found=%v", n, ok)
	}
}
