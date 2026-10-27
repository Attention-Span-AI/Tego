// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The recorder is a runtime.DeputySkipper: the runtime names the deputy to whatever kernel recorder says it is one.
var _ runtime.DeputySkipper = (*Recorder)(nil)

// The run's open deputy (ADR 0041 D2) opens for the supervisor, which writes each held open's one line: the recorder
// drops every record of the deputy (SetSkipProcess), the decision plane's refusal of one of its opens included, which the
// supervisor attributes with the tier's model as this recorder would (supervisor.md R7a). Every other process's
// records are recorded as before, the plane's refusal of the agent's own open among them.
func TestRecorderDropsEveryRecordOfTheDeputy(t *testing.T) {
	f := newFixture(t)
	rt, rows := planeTable(f)
	f.rules = rt
	s := filepath.Join(f.out, "s")
	if err := os.Mkdir(s, 0o755); err != nil {
		t.Fatal(err)
	}
	di, ok := statDevIno(s)
	if !ok {
		t.Fatal("could not stat the deny_read directory")
	}
	const deputyPID, agentPID = 77, 50
	benign := filepath.Join(f.out, "benign")
	refusal := func(pid uint32, mono uint64, name string) []byte {
		return planeFSSample(sample{PID: pid, TID: pid, MonoNS: mono, Start: 900, Reason: uint8(bpf.ReasonReadDenied)},
			hookNumber(t, "file_open"), uint32(planeRow(t, rows, s)), di.Dev, di.Ino, name, unix.O_RDONLY)
	}
	samples := [][]byte{
		// The deputy's open of a file the supervisor delivered, and the plane's refusal of another: both the
		// supervisor's lines.
		fsSample(sample{PID: deputyPID, TID: deputyPID, MonoNS: 1, Start: 900, Ret: 3, RetOK: true}, unix.O_RDONLY, 0, 0, benign, ""),
		refusal(deputyPID, 2, "k"),
		// The agent's own open and the plane's refusal of its own: recorded as ever (record: full).
		fsSample(sample{PID: agentPID, TID: agentPID, MonoNS: 3, Start: 900, Ret: 3, RetOK: true}, unix.O_RDONLY, 0, 0, benign, ""),
		refusal(agentPID, 4, "j"),
	}
	ring := newFakeRing(samples...)
	r, err := New(Options{Rules: f.rules, Reader: ring, Proc: f.procFS, FlushInterval: time.Hour, DecisionPlane: record.DecisionPlaneLSM})
	if err != nil {
		t.Fatal(err)
	}
	r.SetSkipProcess(deputyPID, 900)
	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.Start(ctx, source.RunRef{ID: "r-host-1", Agent: "retriever"}, sink); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		ring.mu.Lock()
		defer ring.mu.Unlock()
		return len(ring.samples) == 0
	}, "samples were never drained")
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	var deputyLines, agentAllow, agentRefused int
	for _, ev := range sink.byKind(record.KindFS) {
		switch {
		case ev.PID == deputyPID:
			deputyLines++
		case ev.PID == agentPID && ev.Verdict == record.VerdictRefused:
			agentRefused++
		case ev.PID == agentPID:
			agentAllow++
		}
	}
	if deputyLines != 0 || agentAllow != 1 || agentRefused != 1 {
		t.Fatalf("deputy lines %d, agent lines %d allowed and %d refused; want 0, 1 and 1: %+v", deputyLines, agentAllow, agentRefused, sink.events)
	}
}

// The deputy is named by its pid and its start time (SetSkipProcess): once it is gone, a later process the kernel gives
// the same pid is another process, and every record of it is the run's, kept as any other process's is
// (supervisor.md R7a). The deputy's own records, stamped with its start within /proc's one-tick rounding, are
// dropped; a record stamped with a start a tick or more later is a reused pid's and is recorded, an fs open and the
// plane's refusal alike; a record that carries no start (a socket record) names no process apart from its pid and is
// kept. With no start known (the /proc read failed) the pid alone names the deputy, whose zombie the launcher keeps
// unreaped for the whole run (launch.Child.KeepUnreaped), so no later process holds its pid meanwhile.
func TestRecorderKeepsARecordOfTheDeputysPidFromAnotherProcess(t *testing.T) {
	const deputyPID, deputyStart = 77, 5 * proc.NanosPerTick
	for _, tc := range []struct {
		name          string
		known         uint64 // the start SetSkipProcess is given, 0 for none
		start         uint64 // the start the records carry
		wantKeptLines int
	}{
		{"the deputy itself", deputyStart, deputyStart + proc.NanosPerTick/2, 0},
		{"a reused pid", deputyStart, deputyStart + 2*proc.NanosPerTick, 2},
		{"a reused pid, no start known", 0, deputyStart + 2*proc.NanosPerTick, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			rt, rows := planeTable(f)
			f.rules = rt
			s := filepath.Join(f.out, "s")
			if err := os.Mkdir(s, 0o755); err != nil {
				t.Fatal(err)
			}
			di, ok := statDevIno(s)
			if !ok {
				t.Fatal("could not stat the deny_read directory")
			}
			benign := filepath.Join(f.out, "benign")
			ring := newFakeRing(
				fsSample(sample{PID: deputyPID, TID: deputyPID, MonoNS: 1, Start: tc.start, Ret: 3, RetOK: true}, unix.O_RDONLY, 0, 0, benign, ""),
				planeFSSample(sample{PID: deputyPID, TID: deputyPID, MonoNS: 2, Start: tc.start, Reason: uint8(bpf.ReasonReadDenied)},
					hookNumber(t, "file_open"), uint32(planeRow(t, rows, s)), di.Dev, di.Ino, "k", unix.O_RDONLY),
			)
			r, err := New(Options{Rules: f.rules, Reader: ring, Proc: f.procFS, FlushInterval: time.Hour, DecisionPlane: record.DecisionPlaneLSM})
			if err != nil {
				t.Fatal(err)
			}
			r.SetSkipProcess(deputyPID, tc.known)
			sink := &fakeSink{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := r.Start(ctx, source.RunRef{ID: "r-host-1", Agent: "retriever"}, sink); err != nil {
				t.Fatal(err)
			}
			waitFor(t, func() bool {
				ring.mu.Lock()
				defer ring.mu.Unlock()
				return len(ring.samples) == 0
			}, "samples were never drained")
			if err := r.Stop(); err != nil {
				t.Fatalf("Stop: %v", err)
			}
			kept := 0
			for _, ev := range sink.byKind(record.KindFS) {
				if ev.PID == deputyPID {
					kept++
				}
			}
			if kept != tc.wantKeptLines {
				t.Fatalf("%d lines of pid %d kept, want %d: %+v", kept, deputyPID, tc.wantKeptLines, sink.events)
			}
		})
	}
}

// A socket record carries no start time (decodeSock): it is dropped only while no start is known, and kept, as the
// pid's other process's, once one is; the deputy's filter refuses socket(2), so no socket record is the deputy's.
func TestSkipProcessDrops(t *testing.T) {
	const pid, start = 77, 5 * proc.NanosPerTick
	for _, tc := range []struct {
		name  string
		skip  *skipProcess
		rec   Record
		drops bool
	}{
		{"none", nil, Record{Header: Header{PID: pid}, StartNS: start}, false},
		{"another pid", &skipProcess{pid: pid, startNS: start}, Record{Header: Header{PID: pid + 1}, StartNS: start}, false},
		{"the deputy", &skipProcess{pid: pid, startNS: start}, Record{Header: Header{PID: pid}, StartNS: start + 1}, true},
		{"a reused pid", &skipProcess{pid: pid, startNS: start}, Record{Header: Header{PID: pid}, StartNS: start + proc.NanosPerTick}, false},
		{"no start in the record", &skipProcess{pid: pid, startNS: start}, Record{Header: Header{PID: pid}}, false},
		{"no start known", &skipProcess{pid: pid}, Record{Header: Header{PID: pid}, StartNS: start + proc.NanosPerTick}, true},
	} {
		if got := tc.skip.drops(&tc.rec); got != tc.drops {
			t.Errorf("%s: drops = %v, want %v", tc.name, got, tc.drops)
		}
	}
}
