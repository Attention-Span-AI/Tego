// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func execResultSample(h sample, ret int64) []byte {
	h.Kind = KindExecResult
	e := bpf.ExecResultEvent{Hdr: h.header(ExecResultSize), StartNS: h.Start, Ret: ret}
	return wire(&e)
}

func execOpenSample(h sample, path string) []byte {
	b := fsSample(h, 0x20, 1, 2049, path, "")
	e, err := bpf.Decode[bpf.FSEvent](b)
	if err != nil {
		panic(err)
	}
	e.ExecOpen = 1
	return wire(&e)
}

func TestDecodeExecOutcomeFields(t *testing.T) {
	h := sample{PID: 50, TID: 51, MonoNS: 20, Start: 90}
	var got Record
	if err := DecodeInto(&got, execResultSample(h, -8)); err != nil {
		t.Fatal(err)
	}
	if got.Kind != KindExecResult || got.StartNS != 90 || got.ExecResult.Ret != -8 || got.TID != 51 ||
		KindExecResult.String() != "exec_result" || !KindExecResult.Valid() {
		t.Fatalf("failed exec result = %+v", got)
	}
	h.Kind, h.Ret, h.RetOK = KindOpen, -13, true
	if err := DecodeInto(&got, execOpenSample(h, "/bin/tool")); err != nil {
		t.Fatal(err)
	}
	if !got.FS.ExecOpen || got.FS.Ret != -13 || got.FS.Path != "/bin/tool" {
		t.Fatalf("exec open = %+v", got.FS)
	}
	e, err := bpf.Decode[bpf.ExecEvent](execSample(h, 90, "tool", "/bin/tool", []string{"tool"}, false))
	if err != nil {
		t.Fatal(err)
	}
	e.OldTID = 51
	e.Interpreted = 1
	if err := DecodeInto(&got, wire(&e)); err != nil {
		t.Fatal(err)
	}
	if got.Exec.OldTID != 51 || !got.Exec.Interpreted || got.Exec.RawPath != "/bin/tool" || got.ExecResult.Ret != 0 || got.FS.ExecOpen {
		t.Fatalf("success/reset = %+v", got)
	}
}

func execOutcomeHeader(at uint64) sample {
	return sample{PID: 50, TID: 51, Start: 900 * proc.NanosPerTick, MonoNS: at}
}

func outcomeNaming(at uint64) supervisor.ExecNaming {
	return supervisor.ExecNaming{Path: "/attempt/tool", Argv: []string{"tool", "argument"},
		ExecID: "r-host-1/50/9000000000", ParentExecID: "parent-before-exec", AttemptMonoNS: at}
}

func oneExecOutcome(t *testing.T, sink *fakeSink) (*record.Event, execOutcomePayload) {
	t.Helper()
	evs := sink.byKind(record.KindExec)
	if len(evs) != 1 {
		t.Fatalf("%d exec lines, want one: %+v", len(evs), evs)
	}
	if err := evs[0].Validate(); err != nil {
		t.Fatalf("exec outcome validation: %v", err)
	}
	return evs[0], payload[execOutcomePayload](t, evs[0])
}

func TestExecResultConsumesEarlyImageRefusalOnce(t *testing.T) {
	f := newFixture(t)
	f.rules, _ = planeTable(f)
	n := outcomeNaming(10)
	n.ArgvTruncated, n.Fileless, n.Dropped = true, true, true
	h := execOutcomeHeader(20)
	h.Kind, h.Ret, h.RetOK = KindOpen, -13, true
	r, sink := runRecorder(t, f, Options{ExecResults: true,
		ContinuedExec: func(tid, pid int, start, at uint64) (supervisor.ExecNaming, bool) {
			if tid != 51 || pid != 50 || start != h.Start || at != 30 {
				t.Errorf("join = %d/%d/%d/%d", tid, pid, start, at)
			}
			return n, true
		}}, execOpenSample(h, "/kernel/unlisted"), execResultSample(execOutcomeHeader(30), -13))
	ev, p := oneExecOutcome(t, sink)
	if len(sink.byKind(record.KindFS)) != 0 || ev.Verdict != record.VerdictRefused ||
		ev.Rule != RuleUnmatched || ev.Reason != record.ReasonExecNotAllowed || p.Path != "/kernel/unlisted" ||
		p.AttemptPath != n.Path || p.SyscallRet != -13 || p.Mechanism != "" || !p.ArgvTruncated ||
		!p.Fileless || !p.Dropped || !slices.Equal(p.Argv, n.Argv) || p.ParentExecID != n.ParentExecID {
		t.Fatalf("early refusal outcome = %+v / %+v", ev, p)
	}
	if gapCount(r.Gaps())[GapArgvTruncated] != 1 {
		t.Fatalf("gaps = %v", r.Gaps())
	}
}

func TestExecResultConsumesBprmRefusalWithOpenedImage(t *testing.T) {
	f := newFixture(t)
	f.rules, _ = planeTable(f)
	n := outcomeNaming(10)
	h := execOutcomeHeader(20)
	h.Kind, h.RetOK = KindOpen, true
	bprm := execOutcomeHeader(21)
	bprm.Reason = uint8(bpf.ReasonExecNotAllowed)
	_, sink := runRecorder(t, f, Options{ExecResults: true, DecisionPlane: record.DecisionPlaneLSM,
		ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return n, true }},
		execOpenSample(h, "/kernel/interpreter"), planeExecSample(bprm, uint32(bpf.PlaneRuleNone), "./script"),
		execResultSample(execOutcomeHeader(30), -13))
	ev, p := oneExecOutcome(t, sink)
	if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonExecNotAllowed ||
		p.Path != "/kernel/interpreter" || p.Mechanism != record.MechanismPlane || p.DecisionPlane != record.DecisionPlaneLSM ||
		!slices.Equal(p.Argv, n.Argv) || len(sink.byKind(record.KindFS)) != 1 {
		t.Fatalf("bprm outcome = %+v / %+v", ev, p)
	}
}

func TestExecResultRecordsFailuresOutsidePolicyHooks(t *testing.T) {
	for _, ret := range []int64{-8, -26, -2} {
		t.Run(strconv.FormatInt(-ret, 10), func(t *testing.T) {
			f := newFixture(t)
			n := outcomeNaming(10)
			_, sink := runRecorder(t, f, Options{ExecResults: true,
				ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return n, true }},
				execResultSample(execOutcomeHeader(30), ret))
			ev, p := oneExecOutcome(t, sink)
			if ev.Verdict != record.VerdictObserved || ev.Rule != RuleUnmatched || ev.Reason != "" ||
				p.SyscallRet != ret || p.Path != n.Path || p.Mechanism != "" {
				t.Fatalf("unhooked failure = %+v / %+v", ev, p)
			}
		})
	}
}

func TestExecResultRejectsOlderAttemptRefusal(t *testing.T) {
	f := newFixture(t)
	f.rules, _ = planeTable(f)
	h := execOutcomeHeader(20)
	h.Reason = uint8(bpf.ReasonExecNotAllowed)
	_, sink := runRecorder(t, f, Options{ExecResults: true,
		ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return outcomeNaming(25), true }},
		planeExecSample(h, uint32(bpf.PlaneRuleNone), "/old/failed"), execResultSample(execOutcomeHeader(30), -8))
	ev, p := oneExecOutcome(t, sink)
	if ev.Verdict != record.VerdictObserved || p.Path == "/old/failed" || p.Mechanism != "" || p.SyscallRet != -8 {
		t.Fatalf("new attempt inherited lost earlier result: %+v / %+v", ev, p)
	}
}

func TestExecResultMissingJoinNeverBorrowsRefusal(t *testing.T) {
	for _, mode := range []string{"missing", "future", "zero"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			h := execOutcomeHeader(20)
			h.Reason = uint8(bpf.ReasonExecNotAllowed)
			r, sink := runRecorder(t, f, Options{ExecResults: true,
				ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) {
					n := outcomeNaming(0)
					if mode == "future" {
						n.AttemptMonoNS = 40
					}
					return n, mode != "missing"
				}}, planeExecSample(h, uint32(bpf.PlaneRuleNone), "/uncorrelated"), execResultSample(execOutcomeHeader(30), -13))
			ev, p := oneExecOutcome(t, sink)
			if gapCount(r.Gaps())[GapExecMetadataMissing] != 1 || ev.Verdict != record.VerdictObserved || p.Path != TruncatedPath ||
				p.SyscallRet != -13 || p.Mechanism != "" || p.ExecID == "" {
				t.Fatalf("missing join = %+v / %+v gaps=%v", ev, p, r.Gaps())
			}
		})
	}
}

func TestExecResultOtherLSMAndReadDeniedRemainDistinct(t *testing.T) {
	for _, denied := range []bool{false, true} {
		f := newFixture(t)
		n := outcomeNaming(10)
		name := f.git
		if denied {
			name = filepath.Join(f.secrets, "key.pem")
			f.rules.Tier = backend.TierBPFLSM
			f.rules.Exec = append(f.rules.Exec, agent.ExecRule{Path: name, Resolved: name, Verdict: agent.VerdictAllow})
		}
		h := execOutcomeHeader(20)
		h.Kind, h.Ret, h.RetOK = KindOpen, -13, true
		_, sink := runRecorder(t, f, Options{ExecResults: true,
			ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return n, true }},
			execOpenSample(h, name), execResultSample(execOutcomeHeader(30), -13))
		ev, p := oneExecOutcome(t, sink)
		if denied {
			if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonReadDenied || p.By != "lsm-chain" {
				t.Fatalf("read refusal = %+v / %+v", ev, p)
			}
		} else if ev.Verdict != record.VerdictObserved || ev.Reason != "" || p.By != record.FSByOther || p.Errno != 13 {
			t.Fatalf("other LSM refusal = %+v / %+v", ev, p)
		}
	}
}

func TestExecSuccessJoinsOriginalThreadAndVerifiedCwd(t *testing.T) {
	f := newFixture(t)
	f.rules, _ = planeTable(f)
	n := outcomeNaming(10)
	n.Path, n.CwdDev, n.CwdIno = filepath.Join(f.dir, "bin/t"), 2049, 777
	n.RawPath = "./bin/t"
	n.MCPName, n.MCPPath = "tools", n.Path
	h := execOutcomeHeader(20)
	h.Kind, h.RetOK = KindOpen, true
	success := execOutcomeHeader(30)
	success.TID, success.CwdDev, success.CwdIno = 50, n.CwdDev, n.CwdIno
	e, err := bpf.Decode[bpf.ExecEvent](execSample(success, success.Start, "t", "./bin/t", n.Argv, false))
	if err != nil {
		t.Fatal(err)
	}
	e.OldTID, e.Plane, e.Hdr.RuleIdx = 51, bpf.PlaneNamedEntry, 0
	var calls int
	r, sink := runRecorder(t, f, Options{ExecResults: true, DecisionPlane: record.DecisionPlaneLSM,
		ContinuedExec: func(tid, pid int, start, at uint64) (supervisor.ExecNaming, bool) {
			calls++
			if tid != 51 || pid != 50 || start != success.Start || at != 30 {
				t.Errorf("success join = %d/%d/%d/%d", tid, pid, start, at)
			}
			return n, true
		}}, execOpenSample(h, n.Path), wire(&e))
	ev, p := oneExecOutcome(t, sink)
	if calls != 1 || p.Path != n.Path || !slices.Equal(p.Argv, n.Argv) || p.SyscallRet != 0 ||
		ev.Rule != f.rules.Exec[0].RuleName() || p.Mechanism != record.MechanismPlane ||
		gapCount(r.Gaps())[GapExecUnresolved] != 0 || gapCount(r.Gaps())[GapArgvTruncated] != 0 {
		t.Fatalf("successful join = %+v / %+v gaps=%v calls=%d", ev, p, r.Gaps(), calls)
	}
	mcp := sink.byKind(record.KindMCP)
	if len(mcp) != 1 {
		t.Fatalf("MCP starts = %d", len(mcp))
	}
	mp := payload[record.MCPPayload](t, mcp[0])
	if mp.Name != "tools" || mp.Transport != "stdio" || !slices.Equal(mp.Command, n.Argv) || mcp[0].Source != record.SourceKernel {
		t.Fatalf("MCP start = %+v / %+v", mcp[0], mp)
	}
}

func TestExecMCPRequiresActualSuccessAndImageProof(t *testing.T) {
	for _, mode := range []string{"failed", "different", "contradictory spelling"} {
		f := newFixture(t)
		n := outcomeNaming(10)
		n.Argv = []string{"tool"}
		n.MCPName, n.MCPPath = "declared", "/declared/tool"
		h := execOutcomeHeader(20)
		h.Kind, h.RetOK = KindOpen, true
		terminal := execResultSample(execOutcomeHeader(30), -8)
		if mode != "failed" {
			name := "/different/tool"
			if mode == "contradictory spelling" {
				name = n.MCPPath
			}
			e, err := bpf.Decode[bpf.ExecEvent](execSample(execOutcomeHeader(30), h.Start, "tool", name, []string{"tool"}, false))
			if err != nil {
				t.Fatal(err)
			}
			e.OldTID = 51
			terminal = wire(&e)
		}
		_, sink := runRecorder(t, f, Options{ExecResults: true,
			ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return n, true }},
			execOpenSample(h, "/different/tool"), terminal)
		if len(sink.byKind(record.KindMCP)) != 0 {
			t.Fatal("failed or different image invented an MCP start")
		}
	}
}

func TestExecSuccessRejectsChangedRelativePathAndCwd(t *testing.T) {
	for _, changedPath := range []bool{false, true} {
		f := newFixture(t)
		n := outcomeNaming(10)
		n.Path, n.RawPath, n.CwdDev, n.CwdIno = filepath.Join(f.dir, "tool"), "./tool", 2049, 777
		h := execOutcomeHeader(30)
		h.TID, h.CwdDev, h.CwdIno = 50, 2049, 777
		name := "./tool"
		if changedPath {
			name = "./different"
		} else {
			h.CwdIno++
		}
		e, err := bpf.Decode[bpf.ExecEvent](execSample(h, h.Start, "tool", name, n.Argv, false))
		if err != nil {
			t.Fatal(err)
		}
		e.OldTID = 51
		r, sink := runRecorder(t, f, Options{ExecResults: true,
			ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return n, true }}, wire(&e))
		_, p := oneExecOutcome(t, sink)
		if p.Path == n.Path || gapCount(r.Gaps())[GapExecUnresolved] != 1 {
			t.Fatalf("changed path/cwd inherited attempt: %+v gaps=%v", p, r.Gaps())
		}
	}
}

func TestExecResultRejectsReusedTaskAndKeepsRecordOffPolicyFailure(t *testing.T) {
	f := newFixture(t)
	f.rules, _ = planeTable(f)
	f.rules.Record = agent.RecordOff
	h := execOutcomeHeader(20)
	h.Reason = uint8(bpf.ReasonExecNotAllowed)
	n := outcomeNaming(10)
	newTask := execOutcomeHeader(30)
	newTask.Start += proc.NanosPerTick
	_, sink := runRecorder(t, f, Options{ExecResults: true,
		ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return n, true }},
		planeExecSample(h, uint32(bpf.PlaneRuleNone), "/old/task"), execResultSample(newTask, -13))
	if len(sink.byKind(record.KindExec)) != 0 {
		t.Fatal("reused task inherited an old policy refusal under off")
	}
	_, sink = runRecorder(t, f, Options{ExecResults: true,
		ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return n, true }},
		planeExecSample(h, uint32(bpf.PlaneRuleNone), "/same/task"), execResultSample(execOutcomeHeader(30), -13))
	ev, p := oneExecOutcome(t, sink)
	if ev.Verdict != record.VerdictRefused || p.SyscallRet != -13 || p.ArgvFrom != "attempt" {
		t.Fatalf("off policy failure = %+v / %+v", ev, p)
	}
}

func TestExecResultBoundedFragmentsAndInvalidResults(t *testing.T) {
	r := &Recorder{gaps: map[string]int64{}}
	for i := 0; i <= execFragmentLimit; i++ {
		r.rememberExecFragment(&Record{Header: Header{Kind: KindPlaneExec, PID: uint32(i + 1), TID: uint32(i + 1), MonoNS: uint64(i + 1)}})
	}
	if gapCount(r.Gaps())[GapExecFragmentOverflow] != 1 {
		t.Fatalf("overflow not explicit: %v", r.Gaps())
	}
	for _, ret := range []int64{0, 1, -4096} {
		r.handleExecResult(&Record{ExecResult: ExecResultBody{Ret: ret}})
	}
	if gapCount(r.Gaps())[GapMalformedRecord] != 3 {
		t.Fatalf("invalid results not counted: %v", r.Gaps())
	}
}

func TestExecOutcomesRespectSupervisorOwnership(t *testing.T) {
	for _, success := range []bool{false, true} {
		f := newFixture(t)
		n := outcomeNaming(10)
		n.SupervisorOwned = true
		h := execOutcomeHeader(20)
		h.Reason = uint8(bpf.ReasonExecNotAllowed)
		terminal := execResultSample(execOutcomeHeader(30), -13)
		if success {
			e, err := bpf.Decode[bpf.ExecEvent](execSample(execOutcomeHeader(30), h.Start, "tool", "/kernel/tool", n.Argv, false))
			if err != nil {
				t.Fatal(err)
			}
			e.OldTID = 51
			terminal = wire(&e)
		}
		r, sink := runRecorder(t, f, Options{ExecResults: true,
			ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return n, true }},
			planeExecSample(h, uint32(bpf.PlaneRuleNone), "/supervisor/owned"), terminal)
		if len(sink.byKind(record.KindExec)) != 0 || len(sink.byKind(record.KindMCP)) != 0 ||
			gapCount(r.Gaps())[GapExecMetadataMissing] != 0 {
			t.Fatalf("supervisor-owned result duplicated: %+v gaps=%v", sink.all(), r.Gaps())
		}
		for _, fragment := range r.execFragments.ring {
			if fragment.header.MonoNS != 0 {
				t.Fatal("completed supervisor-owned attempt retained fragments")
			}
		}
	}
}

func TestExecOutcomeKeepsSuccessfulWatchedImageRead(t *testing.T) {
	f := newFixture(t)
	n := outcomeNaming(10)
	name := filepath.Join(f.watch, "image")
	h := execOutcomeHeader(20)
	h.Kind, h.RetOK = KindOpen, true
	_, sink := runRecorder(t, f, Options{ExecResults: true,
		ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return n, true }},
		execOpenSample(h, name), execResultSample(execOutcomeHeader(30), -8))
	fs := sink.byKind(record.KindFS)
	if len(fs) != 1 {
		t.Fatalf("successful watched image read lines = %d", len(fs))
	}
	p := payload[record.FSPayload](t, fs[0])
	if p.Path != name || p.Op != record.FSOpen || fs[0].Verdict != record.VerdictAllow || fs[0].Rule != "fs.watch[./config]" {
		t.Fatalf("watched image read changed: %+v / %+v", fs[0], p)
	}
	oneExecOutcome(t, sink)
}

func TestExecResultDuplicateDoesNotBecomeSecondUnmatchedLine(t *testing.T) {
	f := newFixture(t)
	n := outcomeNaming(10)
	var calls int
	terminal := execResultSample(execOutcomeHeader(30), -8)
	r, sink := runRecorder(t, f, Options{ExecResults: true,
		ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) {
			calls++
			return n, calls == 1
		}}, terminal, terminal)
	oneExecOutcome(t, sink)
	if calls != 1 || gapCount(r.Gaps())[GapExecMetadataMissing] != 0 {
		t.Fatalf("duplicate consumed naming again: calls=%d gaps=%v", calls, r.Gaps())
	}
}

func TestExecInterpretedMCPRequiresKernelRewriteAndExactTail(t *testing.T) {
	for _, mode := range []string{"script", "optional interpreter arg", "native forgery", "changed tail", "changed script", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			n := outcomeNaming(10)
			n.Path, n.RawPath = "/declared/script", "./script"
			n.MCPName, n.MCPPath = "script-server", n.Path
			h := execOutcomeHeader(20)
			h.Kind, h.RetOK = KindOpen, true
			args := []string{"interpreter", "./script", "argument"}
			if mode == "optional interpreter arg" {
				args = []string{"interpreter", "-x", "./script", "argument"}
			}
			if mode == "changed tail" {
				args[2] = "different"
			}
			if mode == "changed script" {
				args[1] = "./different"
			}
			e, err := bpf.Decode[bpf.ExecEvent](execSample(execOutcomeHeader(30), h.Start, "interpreter", "./script", args, mode == "truncated"))
			if err != nil {
				t.Fatal(err)
			}
			e.OldTID = 51
			if mode != "native forgery" {
				e.Interpreted = 1
			}
			r, sink := runRecorder(t, f, Options{ExecResults: true,
				ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return n, true }},
				execOpenSample(h, n.Path), wire(&e))
			_, p := oneExecOutcome(t, sink)
			valid := mode == "script" || mode == "optional interpreter arg"
			if !slices.Equal(p.Argv, args) || p.ArgvFrom != "kernel" {
				t.Fatalf("interpreted exec replaced mapped argv: %+v", p)
			}
			if valid {
				if len(sink.byKind(record.KindMCP)) != 1 || gapCount(r.Gaps())[GapExecArgvMismatch] != 0 {
					t.Fatalf("proven script MCP missing: %+v gaps=%v", sink.all(), r.Gaps())
				}
			} else if len(sink.byKind(record.KindMCP)) != 0 || gapCount(r.Gaps())[GapExecArgvMismatch] != 1 {
				t.Fatalf("unproved script MCP accepted: %+v gaps=%v", sink.all(), r.Gaps())
			}
		})
	}
}

func TestExecSuccessKeepsActualArgvAndMarksUnverifiedTail(t *testing.T) {
	for _, tc := range []struct {
		name               string
		kernel             []string
		truncated, partial bool
		want               []string
		from               string
		mismatch           int64
	}{
		{"changed", []string{"tool", "changed"}, false, false, []string{"tool", "changed"}, "kernel", 1},
		{"shebang", []string{"interpreter", "/script", "argument"}, false, false, []string{"interpreter", "/script", "argument"}, "kernel", 1},
		{"matching complete prefix", []string{"tool"}, true, false, []string{"tool", "argument"}, "kernel-prefix+attempt", 0},
		{"matching partial argument", []string{"tool", "arg"}, true, true, []string{"tool", "argument"}, "kernel-prefix+attempt", 0},
		{"changed partial argument", []string{"tool", "cha"}, true, true, []string{"tool", "cha"}, "kernel", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			n := outcomeNaming(10)
			r, err := New(Options{Rules: f.rules, Reader: newFakeRing(), ExecResults: true,
				ContinuedExec: func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return n, true }})
			if err != nil {
				t.Fatal(err)
			}
			r.procs = newProcCache(f.procFS, "r-host-1", DefaultProcCacheSize)
			r.sink = &fakeSink{}
			r.run.ID = "r-host-1"
			r.run.Agent = "retriever"
			rec := Record{Header: Header{PID: 50, TID: 50, MonoNS: 30}, StartNS: 900 * proc.NanosPerTick,
				Exec: ExecBody{OldTID: 51, StartBootNS: 900 * proc.NanosPerTick, Path: "/kernel/tool",
					Argv: tc.kernel, ArgvTruncated: tc.truncated, ArgvLastPartial: tc.partial}}
			r.handleExec(&rec)
			_, p := oneExecOutcome(t, r.sink.(*fakeSink))
			if !slices.Equal(p.Argv, tc.want) || p.ArgvFrom != tc.from || p.ArgvTruncated != tc.truncated ||
				gapCount(r.Gaps())[GapExecArgvMismatch] != tc.mismatch {
				t.Fatalf("actual argv = %+v gaps=%v", p, r.Gaps())
			}
		})
	}
}

func TestExecResultCapabilityGateAndLegacyRefusals(t *testing.T) {
	f := newFixture(t)
	fn := func(int, int, uint64, uint64) (supervisor.ExecNaming, bool) { return outcomeNaming(10), true }
	r, err := New(Options{Rules: f.rules, Reader: newFakeRing()})
	if err != nil {
		t.Fatal(err)
	}
	if r.ExecHandoverReady() {
		t.Fatal("unconfigured handover ready")
	}
	r.SetContinuedExec(fn)
	if r.ExecHandoverReady() {
		t.Fatal("missing producers handover ready")
	}
	r.SetExecResults(true)
	if !r.ExecHandoverReady() {
		t.Fatal("complete handover not ready")
	}
	r.SetContinuedExec(nil)
	if r.ExecHandoverReady() {
		t.Fatal("missing metadata handover ready")
	}
	h := execOutcomeHeader(20)
	h.Reason = uint8(bpf.ReasonExecNotAllowed)
	_, sink := runRecorder(t, f, Options{ContinuedExec: fn},
		planeExecSample(h, uint32(bpf.PlaneRuleNone), "/legacy/refused"), execResultSample(execOutcomeHeader(30), -13))
	_, p := oneExecOutcome(t, sink)
	if p.Path != "/legacy/refused" || p.SyscallRet != 0 {
		t.Fatalf("legacy refusal changed: %+v", p)
	}
}

// TestPlaneExecWithoutOutcomeLinksJoinsNaming: on a kernel whose exec outcome links do not attach (5.14), the plane
// still decides the run's execs and the recorder's sched_process_exec record is the allowed exec's one line. That
// line takes the supervisor's naming of the attempt as the outcome-linked line does: an anonymous image is recorded
// fileless and a dropped one dropped (supervisor.md R7a, R16b; the line named
// /proc/self/fd/4 with neither flag, so it read as an exec of an ordinary file by descriptor). A supervisor-owned
// attempt drops the kernel's line as on the outcome-linked path, with no gap: the attempt a success record joins is
// always that exec's own, and its marker says this loop wrote the exec's line (a recorder failure before the final
// drain; the drain wrote a second line). An exec with no attempt is the linked line's gap.
func TestPlaneExecWithoutOutcomeLinksJoinsNaming(t *testing.T) {
	for _, tc := range []struct {
		name              string
		found, owned      bool
		fileless, dropped bool
		lines             int
		missing           int64
	}{
		{"joined", true, false, true, true, 1, 0},
		{"a supervisor-owned attempt", true, true, false, false, 0, 0},
		{"no attempt", false, false, false, false, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.rules, _ = planeTable(f)
			n := outcomeNaming(10)
			n.Path, n.Argv, n.Fileless, n.Dropped, n.SupervisorOwned = "/memfd:payload", []string{"t"}, true, true, tc.owned
			success := execOutcomeHeader(30)
			e, err := bpf.Decode[bpf.ExecEvent](execSample(success, success.Start, "t", "/proc/self/fd/4", n.Argv, false))
			if err != nil {
				t.Fatal(err)
			}
			e.OldTID, e.Plane, e.Hdr.RuleIdx = 51, bpf.PlaneNamedEntry, 0
			var calls int
			r, sink := runRecorder(t, f, Options{DecisionPlane: record.DecisionPlaneLSM,
				ContinuedExec: func(tid, pid int, start, at uint64) (supervisor.ExecNaming, bool) {
					calls++
					if tid != 51 || pid != 50 || start != success.Start || at != 30 {
						t.Errorf("join = %d/%d/%d/%d", tid, pid, start, at)
					}
					return n, tc.found
				}}, wire(&e))
			if tc.lines == 0 {
				if evs := sink.byKind(record.KindExec); len(evs) != 0 || calls != 1 || len(r.Gaps()) != 0 {
					t.Fatalf("supervisor-owned exec kept %d kernel lines: %+v gaps=%v calls=%d", len(evs), evs, r.Gaps(), calls)
				}
				return
			}
			ev, p := oneExecOutcome(t, sink)
			if calls != 1 || p.Path != "/proc/self/fd/4" || p.Fileless != tc.fileless || p.Dropped != tc.dropped ||
				ev.Verdict != record.VerdictAllow || p.Mechanism != record.MechanismPlane ||
				gapCount(r.Gaps())[GapExecMetadataMissing] != tc.missing {
				t.Fatalf("line = %+v / %+v gaps=%v calls=%d", ev, p, r.Gaps(), calls)
			}
		})
	}
}
