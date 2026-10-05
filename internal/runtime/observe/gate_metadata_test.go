// SPDX-License-Identifier: Apache-2.0
package observe

import (
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// The action/floor comes from the compiled fixture; only the joined copied
// metadata is synthetic. Kernel verdict, naming and mapped argv retain ownership.
func TestGateMetadataKeepsOneActualFSOutcomeUnderSummary(t *testing.T) {
	for _, ret := range []int32{0, -13} {
		f := newFixture(t)
		path := filepath.Join(f.out, "file")
		score := 40
		_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, ContinuedFSInfo: func(tid int, op, name, name2 string, at uint64) (supervisor.FSNaming, bool) {
			if tid != 51 || op != record.FSOpen || name != "file" || name2 != "" || at != 20 {
				t.Fatalf("join %d/%s/%s/%s/%d", tid, op, name, name2, at)
			}
			return supervisor.FSNaming{GateFields: supervisor.GateFields{Score: &score, GateRule: "gate.rules[0]", GateOutcome: "allow", GateFacts: "copied_syscall"}}, true
		}}, fsSample(sample{Kind: KindOpen, PID: 50, TID: 51, MonoNS: 20, Ret: ret, RetOK: true}, 0, 1, 2049, path, ""))
		evs := sink.byKind(record.KindFS)
		if len(evs) != 1 {
			t.Fatalf("one scored action, got%v", evs)
		}
		var p struct {
			record.FSPayload
			supervisor.GateFields
		}
		if e := evs[0].DecodePayload(&p); e != nil {
			t.Fatal(e)
		}
		want := record.VerdictAllow
		if ret != 0 {
			want = record.VerdictObserved // a chain EACCES outside the known floor remains observed
		}
		if evs[0].Verdict != want || p.Errno != int(-ret) || p.Path != path || p.Score == nil || *p.Score != 40 || p.GateRule != "gate.rules[0]" || p.GateFacts != "copied_syscall" {
			t.Fatalf("actual outcome%+v payload%+v", evs[0], p)
		}
	}
}

func TestGateMetadataKeepsOneActualExecOutcomeAndKernelArgv(t *testing.T) {
	f := newFixture(t)
	score := 40
	n := outcomeNaming(10)
	n.GateFields = supervisor.GateFields{Score: &score, GateRule: "gate.rules[0]", GateOutcome: "allow", GateFacts: "copied_syscall"}
	kernelArgs := []string{"tool", "changed-after-attempt"}
	_, sink := runRecorder(t, f, Options{ExecResults: true, ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return n, true }}, execSample(execOutcomeHeader(30), execOutcomeHeader(30).Start, "tool", "/kernel/tool", kernelArgs, false))
	_, p := oneExecOutcome(t, sink)
	if p.Score == nil || *p.Score != 40 || p.GateFacts != "copied_syscall" || p.Path != "/kernel/tool" || p.ArgvFrom != "kernel" || !slices.Equal(p.Argv, kernelArgs) {
		t.Fatalf("kernel outcome metadata%+v", p)
	}
}
