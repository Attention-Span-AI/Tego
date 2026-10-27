// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"context"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// stallBounded is a record: off table whose limits bound stall_after: the probes' only use for its run is the
// activity stamp (limits R4, capture-derive R4).
func stallBounded(mode agent.RecordMode) *agent.RuleTable {
	return &agent.RuleTable{Record: mode, Limits: agent.ResolvedLimits{StallAfter: 3 * time.Second, Set: agent.BudgetStallAfter}}
}

// TestRecordOffWithAStallBudgetAttachesForActivity is capture-derive R4's activity-only source: a record: off run
// whose stall_after is bounded, following the tier's kernel record, places the probes the build's runs share, at
// Start on the host's libssl and at an exec, so its TLS calls stamp its slot of tego_activity (A-REC-3, A-REC-4).
// It reads no ring and captures nothing: the gaps are the mechanism's own alone, as for any record: off run, so
// run_start still says capture did not run, no process's coverage is reported, and Stop gives back every reference
// it took.
func TestRecordOffWithAStallBudgetAttachesForActivity(t *testing.T) {
	tree := newProcTree(t)
	_, lib := sharedRootTree(t, tree, []int{601}, map[string]uint64{SymWrite: 0x1100, SymRead: 0x1180})
	libs := preattachLibs(t, 1)
	att := &fakeAttacher{}
	u, sink := newTestUprobe(t, nil, Options{
		Kernel: true, Proc: proc.NewAt(tree.root), Attacher: att, Rules: stallBounded(agent.RecordOff),
		Preattach: func() []string { return libs },
	})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatal(err)
	}
	preattached := att.count()
	if preattached == 0 {
		t.Fatal("no probe pre-attached for a record: off run with a stall budget: CPython's _ssl dlopens the host libssl, " +
			"and the kernel record carries no opens under off, so its first stream would be missed")
	}
	u.OnExec(601, 41, "")
	u.OnOpen(601, 41, lib)
	if att.count() == preattached {
		t.Fatalf("an exec mapping %s placed no probe for an activity-only run", lib)
	}
	if u.reader != nil {
		t.Error("an activity-only source holds a ring reader: it reads no ring")
	}
	if err := u.Stop(); err != nil {
		t.Fatal(err)
	}
	gaps := u.Gaps()
	if len(gaps) != 1 || gaps[0].Why != GapMechanismUnavailable || gaps[0].Binary != Name {
		t.Fatalf("gaps %+v, want the mechanism-unavailable gap alone: an activity-only run keeps no capture", gaps)
	}
	if got := u.UnavailableCause(); got == "" {
		t.Error("UnavailableCause is empty: run_start would say capture ran for a run that records no model traffic")
	}
	att.mu.Lock()
	defer att.mu.Unlock()
	for i, l := range att.links {
		if !l.closed {
			t.Errorf("probe %d on %s is still held after Stop", i, att.paths[i])
		}
	}
	if len(sink.events()) != 0 {
		t.Errorf("an activity-only source emitted %d events", len(sink.events()))
	}
}

// TestActivityOnlyNeedsAStallBudgetAndAKernelRecord: the probes go on for a record: off run only when a stall check
// reads the stamp (stall_after bounded, D3) and the source follows the tier's kernel record (Kernel): without a stall
// budget record: off keeps its zero probes, and summary and full capture as before (where the same probes stamp).
func TestActivityOnlyNeedsAStallBudgetAndAKernelRecord(t *testing.T) {
	libs := preattachLibs(t, 1)
	for _, tc := range []struct {
		name   string
		kernel bool
		rules  *agent.RuleTable
		probes bool
	}{
		{"off/stall/kernel", true, stallBounded(agent.RecordOff), true},
		{"off/no-stall/kernel", true, &agent.RuleTable{Record: agent.RecordOff}, false},
		{"off/stall/no-kernel", false, stallBounded(agent.RecordOff), false},
		{"summary/stall/kernel", true, stallBounded(agent.RecordSummary), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			att := &fakeAttacher{}
			u, sink := newTestUprobe(t, nil, Options{Kernel: tc.kernel, Attacher: att, Rules: tc.rules,
				Preattach: func() []string { return libs }})
			if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = u.Stop() })
			if got := att.count() > 0; got != tc.probes {
				t.Fatalf("probes placed %v, want %v", got, tc.probes)
			}
		})
	}
}
