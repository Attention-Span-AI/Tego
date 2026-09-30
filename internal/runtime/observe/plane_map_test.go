// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRecorderNamesPlaneMapRefusals is TIER3-PLAN T14 in the recorder (enforce-plane R23, R26): the plane's own
// sample of a refused executable mapping is one refused line, op mmap or mprotect by the hook, its file named through
// the directory index as a file operation's is ("anonymous" for a file no path names), rule exec-map, mechanism
// plane; a fail-closed refusal reads path-unresolved. Both are kept under record: off, since they are refusals.
func TestRecorderNamesPlaneMapRefusals(t *testing.T) {
	for _, mode := range []agent.RecordMode{agent.RecordFull, agent.RecordOff} {
		t.Run(string(mode), func(t *testing.T) {
			f := newFixture(t)
			rt, _ := planeTable(f)
			rt.Record = mode
			f.rules = rt
			di, ok := statDevIno(f.out)
			if !ok {
				t.Fatal("could not stat the write directory")
			}
			mapped := func(mono uint64, hook string, reason bpf.ReasonCode, name string) []byte {
				dev, ino := di.Dev, di.Ino
				if name == "" {
					dev, ino = 0, 0
				}
				return planeOwnSample(sample{PID: 50, TID: 50, MonoNS: mono, Start: 900, Reason: uint8(reason)}, KindPlaneMap,
					hookNumber(t, hook), uint32(bpf.PlaneRuleNone), dev, ino, name, 0, 0, 0)
			}
			_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, DecisionPlane: record.DecisionPlaneLSM},
				mapped(1, "mmap_file", bpf.ReasonExecNotAllowed, "drop.so"),
				mapped(2, "file_mprotect", bpf.ReasonExecNotAllowed, "drop.so"),
				mapped(3, "mmap_file", bpf.ReasonExecNotAllowed, ""),
				mapped(4, "mmap_file", bpf.ReasonPathUnresolved, "drop.so"),
			)
			refused := sink.byKind(record.KindRefused)
			if len(refused) != 4 {
				t.Fatalf("%d refused lines, want 4: %+v", len(refused), refused)
			}
			for i, want := range []struct {
				op, target, rule string
				reason           record.Reason
			}{
				{"mmap", filepath.Join(f.out, "drop.so"), PlaneMapRule, record.ReasonExecNotAllowed},
				{"mprotect", filepath.Join(f.out, "drop.so"), PlaneMapRule, record.ReasonExecNotAllowed},
				{"mmap", "anonymous", PlaneMapRule, record.ReasonExecNotAllowed},
				{"mmap", filepath.Join(f.out, "drop.so"), RuleUnmatched, record.ReasonPathUnresolved},
			} {
				ev := refused[i]
				p := payload[record.RefusedPayload](t, ev)
				if ev.Rule != want.rule || ev.Reason != want.reason || p.Op != want.op || p.Target != want.target ||
					p.Mechanism != record.MechanismPlane || p.DecisionPlane != record.DecisionPlaneLSM {
					t.Errorf("map line %d: %s %s %+v, want %s %s op %s target %s", i, ev.Rule, ev.Reason, p, want.rule,
						want.reason, want.op, want.target)
				}
				if err := ev.Validate(); err != nil {
					t.Errorf("a plane line the ledger would refuse: %v: %+v", err, ev)
				}
			}
		})
	}
}

// TestRecorderPlaneMapUnreadNameIsNotAnonymous: a mapping whose name the kernel could not read (path_ok 0, empty
// name: a refused task-storage allocation) is recorded as the truncated path with a gap, not as "anonymous", which
// asserts no path names the file.
func TestRecorderPlaneMapUnreadNameIsNotAnonymous(t *testing.T) {
	f := newFixture(t)
	rt, _ := planeTable(f)
	f.rules = rt
	b := planeOwnSample(sample{PID: 50, TID: 50, MonoNS: 1, Start: 900, Reason: uint8(bpf.ReasonExecNotAllowed)},
		KindPlaneMap, hookNumber(t, "mmap_file"), uint32(bpf.PlaneRuleNone), 0, 0, "", 0, 0, 0)
	e, err := bpf.Decode[bpf.PlaneEvent](b)
	if err != nil {
		t.Fatal(err)
	}
	e.PathOK = 0
	r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, DecisionPlane: record.DecisionPlaneLSM}, wire(&e))
	refused := sink.byKind(record.KindRefused)
	if len(refused) != 1 {
		t.Fatalf("%d refused lines, want 1", len(refused))
	}
	if p := payload[record.RefusedPayload](t, refused[0]); p.Target != TruncatedPath || refused[0].Rule != PlaneMapRule {
		t.Errorf("target %q rule %s, want %q %s", p.Target, refused[0].Rule, TruncatedPath, PlaneMapRule)
	}
	if n := gapCount(r.Gaps())[GapPathTruncated]; n != 1 {
		t.Errorf("path-truncated %d, want 1: %+v", n, r.Gaps())
	}
}
