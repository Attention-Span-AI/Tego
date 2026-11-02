// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

func TestIndexedEvaluatorMatchesReference(t *testing.T) {
	tiers := []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM, backend.TierObserve}
	count := genPlaneTables(sampled(func(desc string, rt *agent.RuleTable) {
		e := NewEvaluator(rt)
		for _, tier := range tiers {
			for _, path := range append(append([]string{}, planeProbes...), "/w/"+strings.Repeat("deep/", 70)+"f") {
				for _, kind := range []agent.ActionKind{agent.ActionFSRead, agent.ActionFSWrite, agent.ActionFSDelete, agent.ActionFSMkdir} {
					a := agent.Action{Kind: kind, Path: path}
					if got, want := e.Evaluate(a, tier), Evaluate(rt, a, tier); got != want {
						t.Fatalf("%s %s %s %s: indexed %+v, reference %+v", desc, tier, kind, path, got, want)
					}
				}
				for _, dst := range renameDests {
					a := agent.Action{Kind: agent.ActionFSRename, Path: path, DestPath: dst}
					if got, want := e.Evaluate(a, tier), Evaluate(rt, a, tier); got != want {
						t.Fatalf("%s %s rename %s -> %s: indexed %+v, reference %+v", desc, tier, path, dst, got, want)
					}
				}
			}
		}
	}))
	if count < 1000 {
		t.Fatalf("only %d generated tables", count)
	}
}

func TestIndexedEvaluatorQueryAllocations(t *testing.T) {
	e := NewEvaluator(realisticTable(backend.TierLandlock))
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM, backend.TierObserve} {
		for _, path := range []string{benchRead, benchDenied, benchNested, benchOutside} {
			for _, kind := range []agent.ActionKind{agent.ActionFSRead, agent.ActionFSWrite, agent.ActionFSDelete, agent.ActionFSMkdir, agent.ActionFSRename} {
				a := agent.Action{Kind: kind, Path: path, DestPath: benchRead}
				if n := testing.AllocsPerRun(100, func() { evaluatorSink = e.Evaluate(a, tier) }); n != 0 {
					t.Fatalf("%s %s %s: %g query allocations", tier, kind, path, n)
				}
			}
		}
	}
}

var evaluatorSink agent.EvalResult

func BenchmarkIndexedEvaluator(b *testing.B) {
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		b.Run(string(tier), func(b *testing.B) {
			e := NewEvaluator(realisticTable(tier))
			actions := []agent.Action{{Kind: agent.ActionFSRead, Path: benchDenied}, {Kind: agent.ActionFSWrite, Path: benchRead}, {Kind: agent.ActionFSDelete, Path: benchNested}, {Kind: agent.ActionFSRename, Path: benchRead, DestPath: benchNested}}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				evaluatorSink = e.Evaluate(actions[i%len(actions)], tier)
			}
		})
	}
}
