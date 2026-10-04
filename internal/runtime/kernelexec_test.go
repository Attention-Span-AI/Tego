// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

type outcomeHandle struct {
	planeHandle
	coverage bool
}

func (h outcomeHandle) ExecOutcomes() bool { return h.coverage }

type execNamingRecorder struct {
	fsNamingRecorder
	fn               func(int, int, uint64, uint64) (supervisor.ExecNaming, bool)
	results, reading bool
}

func (s *execNamingRecorder) SetContinuedExec(fn func(int, int, uint64, uint64) (supervisor.ExecNaming, bool)) {
	s.fn = fn
}
func (s *execNamingRecorder) SetExecResults(on bool)  { s.results = on }
func (s *execNamingRecorder) ExecHandoverReady() bool { return s.results && s.fn != nil }
func (s *execNamingRecorder) Reading() bool           { return s.reading }

func TestExecHandoffNeedsOutcomeCoverageAndLiveRecorder(t *testing.T) {
	for _, tc := range []struct {
		name                                    string
		mode                                    string
		coverage, execs, started, reading, want bool
	}{
		{"ready lsm", record.DecisionPlaneLSM, true, true, true, true, true},
		{"ready fmodret", record.DecisionPlaneFmodRet, true, true, true, true, true},
		{"no exec restrictions", record.DecisionPlaneLSM, true, false, true, true, true},
		{"missing syscall hooks", record.DecisionPlaneLSM, false, true, true, true, false},
		{"no plane", "", true, true, true, true, false},
		{"source startup failed", record.DecisionPlaneLSM, true, true, false, true, false},
		{"reader stopped", record.DecisionPlaneLSM, true, true, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRunner(Deps{})
			rec := &execNamingRecorder{fsNamingRecorder: fsNamingRecorder{plainSource: plainSource{name: "observe"}, execs: true}, reading: tc.reading}
			r.kernelRecord = rec
			r.handle = outcomeHandle{planeHandle: planeHandle{mode: tc.mode, execs: tc.execs}, coverage: tc.coverage}
			r.kernelDecided = make(chan struct{})
			lookup := func(tid, pid int, start, at uint64) (supervisor.ExecNaming, bool) {
				return supervisor.ExecNaming{Path: "/exec"}, tid == 7 && pid == 8 && start == 9 && at == 10
			}
			r.superviseKernelExec(lookup)
			r.decideKernelRecord(tc.started)
			if got := r.kernelExecHandoff(context.Background())(); got != tc.want {
				t.Fatalf("handoff %v, want %v", got, tc.want)
			}
			if tc.coverage && tc.mode != "" && rec.execs {
				t.Fatal("kernel outcomes configured but supervisor still owns exec lines")
			}
			if n, ok := rec.fn(7, 8, 9, 10); !ok || n.Path != "/exec" {
				t.Fatalf("metadata callback %+v %v", n, ok)
			}
		})
	}
}

func TestExecHandoffMissingNamingAndCancellation(t *testing.T) {
	r := newTestRunner(Deps{})
	rec := &execNamingRecorder{fsNamingRecorder: fsNamingRecorder{plainSource: plainSource{name: "observe"}}, results: true, reading: true}
	r.kernelRecord = rec
	r.kernelDecided = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r.kernelExecHandoff(ctx)() {
		t.Fatal("missing metadata callback delegated exec")
	}
	rec.fn = func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return supervisor.ExecNaming{}, false }
	if r.kernelExecHandoff(ctx)() {
		t.Fatal("cancelled startup delegated exec")
	}
}

func TestExecGateRetainsTerminalReadinessWithoutFastHandover(t *testing.T) {
	p, err := gate.New([]gate.Rule{{Predicate: gate.ExecMatches, Argument: "python *", Score: 90}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	r := newTestRunner(Deps{})
	r.rt = &agent.RuleTable{Gate: p}
	rec := &execNamingRecorder{results: true, reading: true, fn: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) {
		return supervisor.ExecNaming{}, false
	}}
	r.kernelRecord = rec
	r.kernelDecided = make(chan struct{})
	r.decideKernelRecord(true)
	if !r.kernelExecHandoff(context.Background())() {
		t.Fatal("gate discarded actual terminal recorder readiness")
	}
	copy := *r.rt
	copy.Gate = nil
	r.rt = &copy
	if !r.kernelExecHandoff(context.Background())() {
		t.Fatal("gate changed ordinary kernel outcome handover")
	}
}
