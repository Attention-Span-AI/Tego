// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"context"
	"errors"
	"testing"

	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// sink stands in for internal/runtime's bounded queue, the Emitter a run's producers write to.
type sink struct{ got []*record.Event }

func (s *sink) Emit(ev *record.Event) { s.got = append(s.got, ev) }

// TestCgroupPrepareCarriesTheRunsEventSink is the wiring behind docs/p0/enforce-cgroup-observe.md §7:
// a tier-2 refusal (FAN_DENY on a deny_read path, an exec the table does not allow) and each of that
// table's gaps — fanotify-timeout, -overflow, -path-unresolved, -malformed-record, -response-failed —
// are ledger rows of the run, and the listener reaches the ledger only through the backend's Emitter.
// A backend built without one refuses in the kernel and records nothing.
//
// It asserts on the Options a run's backend is built from rather than on the Handle, because nothing
// about the Handle reveals a missing sink: that is exactly why the loss was silent. cgroup.Prepare
// refuses a table compiled for another tier before it touches the kernel, so this needs no privilege.
func TestCgroupPrepareCarriesTheRunsEventSink(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	withObjects(t, true) // Select constructs tier 2 only for a build that embeds its objects
	m := machine("")
	b, ds := Select(m, table(backend.TierCgroup, "cgroup"), probeRootNoBPF)
	if b == nil || hasSeverity(ds, "error") {
		t.Fatalf("Select = %v, %v", b, ds)
	}
	cb, ok := b.(cgroupBackend)
	if !ok {
		t.Fatalf("Select returned %T, want the tier-2 backend", b)
	}

	var got cgroupenforce.Options
	cb.newRun = func(o cgroupenforce.Options) *cgroupenforce.Backend {
		got = o
		return cgroupenforce.New(o)
	}
	out := &sink{}
	rt := &agent.RuleTable{Tier: backend.TierLandlock}
	_, err := cb.Prepare(context.Background(), rt, RunRef{ID: "r", Agent: "a", Events: out})
	if !errors.Is(err, cgroupenforce.ErrTier) {
		t.Fatalf("Prepare error = %v, want %v", err, cgroupenforce.ErrTier)
	}
	if got.Events == nil {
		t.Fatal("the run's tier-2 backend was built with no event sink: every fanotify refusal and §7 gap of the run would be dropped into a counter nothing reads")
	}
	if e, _ := got.Events.(*sink); e != out {
		t.Errorf("Options.Events = %#v, want the run's own sink", got.Events)
	}
	// The run-independent half Select fixed must survive being completed per run: the machine config
	// carries record.ringbuf (§5 R16) and Inherit is the tier-1 ruleset and filter tier 2 installs (§5 R1).
	if got.Machine != m {
		t.Errorf("Options.Machine = %v, want the machine Select was given", got.Machine)
	}
	if got.Inherit == nil {
		t.Error("Options.Inherit is nil: the tier-1 state a tier-2 run inherits was lost (§5 R1)")
	}
}

// TestCgroupRunOptionsWithoutASinkStayNil pins the other half of the Emitter contract: a RunRef with no
// sink must leave Options.Events nil, the value cgroup's listener tests with `if f.out == nil` before it
// drops and counts. Anything non-nil there — a wrapper, or a nil pointer in a non-nil interface — turns
// that documented drop into a call on nothing.
func TestCgroupRunOptionsWithoutASinkStayNil(t *testing.T) {
	cb := cgroupBackend{opts: cgroupenforce.Options{Machine: machine("")}}
	if o := cb.runOptions(RunRef{ID: "r"}); o.Events != nil {
		t.Errorf("Options.Events = %#v, want nil for a run with no sink", o.Events)
	}
}
