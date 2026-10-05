// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"fmt"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestExecRestartGuardKeepsTerminalErrnos(t *testing.T) {
	for _, ret := range []int64{0, 1, -2, -8, -13, -26, -511, -515, -517, -4095} {
		if (ExecResultBody{Ret: ret}).restarting() {
			t.Errorf("terminal result %d classified as a restart", ret)
		}
	}
}

func TestExecRestartDirectResultPreservesNaming(t *testing.T) {
	for _, ret := range []int64{-512, -513, -514, -516} {
		var joins int
		n := outcomeNaming(10)
		n.SupervisorOwned = true
		r := &Recorder{gaps: map[string]int64{}, opts: Options{ExecResults: true,
			ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) {
				joins++
				return n, true
			}}}
		h := execOutcomeHeader(20)
		h.Kind, h.RetOK = KindOpen, true
		var rec Record
		if err := DecodeInto(&rec, execOpenSample(h, "/kernel/image")); err != nil {
			t.Fatal(err)
		}
		r.rememberExecFragment(&rec)
		if err := DecodeInto(&rec, execResultSample(execOutcomeHeader(30), ret)); err != nil {
			t.Fatal(err)
		}
		r.handleExecResult(&rec)
		if joins != 0 || r.execFragments.ring[0].path != "/kernel/image" || len(r.Gaps()) != 0 {
			t.Fatalf("direct restart %d consumed naming/fragments: joins=%d gaps=%v", ret, joins, r.Gaps())
		}
	}
}

// sys_exit runs before signal handling translates or restarts these private
// kernel results. In particular, exec's interruptible cred_guard_mutex can
// return ERESTARTNOINTR even when the handler does not request SA_RESTART.
func TestExecRestartPreservesAttemptAndFragments(t *testing.T) {
	for _, mode := range []agent.RecordMode{agent.RecordFull, agent.RecordSummary, agent.RecordOff} {
		for _, ret := range []int64{-512, -513, -514, -516} {
			t.Run(fmt.Sprintf("%s/%d", mode, ret), func(t *testing.T) {
				f := newFixture(t)
				f.rules.Record = mode
				var joins int
				h := execOutcomeHeader(20)
				h.Kind, h.RetOK = KindOpen, true
				r, sink := runRecorder(t, f, Options{ExecResults: true,
					ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) {
						joins++
						return outcomeNaming(10), true
					}}, execOpenSample(h, "/kernel/image"), execResultSample(execOutcomeHeader(30), ret))
				if joins != 0 || len(sink.byKind(record.KindExec)) != 0 || r.execOutcomes.next != 0 {
					t.Fatalf("restart consumed terminal state: joins=%d outcomes=%d exec=%+v", joins, r.execOutcomes.next, sink.byKind(record.KindExec))
				}
				if r.execFragments.ring[0].path != "/kernel/image" {
					t.Fatal("restart discarded the unfinished attempt's image evidence")
				}
				if gapCount(r.Gaps())[GapExecMetadataMissing] != 0 || gapCount(r.Gaps())[GapMalformedRecord] != 0 {
					t.Fatalf("restart created a false evidence gap: %v", r.Gaps())
				}
			})
		}
	}
}

func TestExecRestartHasOnlyTheFinalOutcome(t *testing.T) {
	for _, success := range []bool{false, true} {
		for _, ret := range []int64{-512, -513, -514, -516} {
			t.Run(fmt.Sprintf("success=%v/%d", success, ret), func(t *testing.T) {
				f := newFixture(t)
				n := outcomeNaming(10)
				var joins int
				h := execOutcomeHeader(20)
				h.Kind, h.RetOK = KindOpen, true
				terminal := execResultSample(execOutcomeHeader(40), -8) // actual ENOEXEC
				if success {
					e, err := bpf.Decode[bpf.ExecEvent](execSample(execOutcomeHeader(40), h.Start, "tool", "/kernel/image", n.Argv, false))
					if err != nil {
						t.Fatal(err)
					}
					e.OldTID = 51
					terminal = wire(&e)
				}
				r, sink := runRecorder(t, f, Options{ExecResults: true,
					ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) {
						joins++
						return n, joins == 1 // metadata is deliberately consumable only once
					}}, execOpenSample(h, "/kernel/image"), execResultSample(execOutcomeHeader(30), ret), terminal)
				_, p := oneExecOutcome(t, sink)
				wantRet := int64(-8)
				if success {
					wantRet = 0
				}
				if joins != 1 || p.SyscallRet != wantRet || p.Path != "/kernel/image" || p.ParentExecID != n.ParentExecID {
					t.Fatalf("final outcome lost its attempt: joins=%d payload=%+v", joins, p)
				}
				if gapCount(r.Gaps())[GapExecMetadataMissing] != 0 {
					t.Fatalf("restart consumed final metadata: %v", r.Gaps())
				}
				for _, seen := range r.execOutcomes.ring {
					if seen.kind == KindExecResult && seen.ret == ret {
						t.Fatal("restart entered the terminal-outcome duplicate cache")
					}
				}
			})
		}
	}
}
