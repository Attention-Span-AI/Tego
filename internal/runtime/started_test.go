// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// orderGate is a fake child stage that records, in order, the Ack that would release the agent and the Kill that
// ends the stage before it execs.
type orderGate struct {
	order  *[]string
	ackErr error
}

func (g orderGate) Ack() error {
	*g.order = append(*g.order, "ack")
	return g.ackErr
}

func (g orderGate) Kill(context.Context) error {
	*g.order = append(*g.order, "kill")
	return nil
}

// TestReleaseAgentRunsStartedBeforeTheGroupCheckAndTheAck is ADR 0073 D4 and runtime-launch.md §4.1 steps 9a and 10
// on the runtime's fakes: Started is called exactly once, with the run's id and directory, before the group check and
// before the child's Ack. Its error, or a worker that failed before it, means the agent is never released: no Ack,
// the child killed, run_end reason error with a detail naming the step. A nil Started changes nothing.
func TestReleaseAgentRunsStartedBeforeTheGroupCheckAndTheAck(t *testing.T) {
	const id identity.RunID = "r-00000000-000000000000a-start0"
	for _, tc := range []struct {
		name        string
		hook        func() error // nil: no Deps.Started
		workerFails bool
		ackErr      error
		want        []string
		released    bool
		detail      string
	}{
		{"released", func() error { return nil }, false, nil, []string{"started", "ack"}, true, ""},
		{"nil Started", nil, false, nil, []string{"ack"}, true, ""},
		{"Started error", func() error { return errors.New("the caller could not note the run") }, false, nil,
			[]string{"started", "kill"}, false, "started hook: the caller could not note the run"},
		// The hook still runs, once, while the worker that failed has already cancelled the group: the hook comes
		// before the group check, and the group check before the Ack.
		{"a worker failed before Started", func() error { return nil }, true, nil, []string{"started", "kill"}, false,
			"ack: worker failed before the agent was released: enforce: marks down"},
		{"Started error and a failed worker", func() error { return errors.New("no note") }, true, nil,
			[]string{"started", "kill"}, false, "started hook: no note"},
		{"Ack error", func() error { return nil }, false, errors.New("child died"), []string{"started", "ack", "kill"},
			false, "ack: child died"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var order []string
			var told []StartedRun
			deps := Deps{}
			if tc.hook != nil {
				deps.Started = func(s StartedRun) error {
					order = append(order, "started")
					told = append(told, s)
					return tc.hook()
				}
			}
			r := newTestRunner(deps)
			r.id, r.dir = id, "/ledger/runs/"+string(id)
			g, gctx := newGroup(context.Background())
			r.group = g
			if tc.workerFails {
				g.Go("enforce", func() error { return errors.New("marks down") })
				<-gctx.Done()
			}
			released := r.releaseAgent(context.Background(), orderGate{order: &order, ackErr: tc.ackErr})
			if released != tc.released || !slices.Equal(order, tc.want) {
				t.Fatalf("released %v, calls %v; want %v, %v", released, order, tc.released, tc.want)
			}
			if tc.hook != nil && (len(told) != 1 || told[0].ID != id || told[0].Dir != r.dir) {
				t.Fatalf("Started told %+v, want once with %s and %s", told, id, r.dir)
			}
			if r.terminal != expectTerminal(tc.released) || r.detail != tc.detail {
				t.Fatalf("end %q detail %q, want %q and %q", r.terminal, r.detail, expectTerminal(tc.released),
					tc.detail)
			}
			if !tc.released && !strings.HasPrefix(r.detail, "started hook: ") && !strings.HasPrefix(r.detail, "ack: ") {
				t.Fatalf("the detail %q names no step", r.detail)
			}
		})
	}
}

// TestReleaseAgentLeavesAStartedPanicUnrecovered is ADR 0073 D4's panic rule (runtime-launch R14): a panic in the
// hook is not recovered into a run_end; it leaves releaseAgent before the Ack, so the child stage never execs the agent.
func TestReleaseAgentLeavesAStartedPanicUnrecovered(t *testing.T) {
	var order []string
	r := newTestRunner(Deps{Started: func(StartedRun) error { panic("hook bug") }})
	r.group, _ = newGroup(context.Background())
	got := func() (p any) {
		defer func() { p = recover() }()
		r.releaseAgent(context.Background(), orderGate{order: &order})
		return nil
	}()
	if got != "hook bug" || len(order) != 0 || r.terminal != "" {
		t.Fatalf("panic %v, calls %v, end %q: want the hook's panic, no Ack or Kill and no end decided", got, order,
			r.terminal)
	}
}

// expectTerminal is the end releaseAgent decides: none for a released agent, error for one never released.
func expectTerminal(released bool) identity.EndReason {
	if released {
		return ""
	}
	return identity.ReasonError
}
