// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"context"
	"encoding/binary"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

func bindResultSample(h sample, ret int64, flags, rule uint32, dev, ino uint64, name string) []byte {
	h.Kind = KindBindResult
	e := bpf.BindResultEvent{Hdr: h.header(200), StartNS: h.Start, Ret: ret, Flags: flags, RuleIdx: rule, Dev: kernelDev(dev), DirIno: ino, NameLen: uint32(len(name))}
	copy(e.Name[:], name)
	return wire(&e)
}

func listenResultSample(h sample, ret int64, flags, rule uint32, dev, ino uint64, name string) []byte {
	b := bindResultSample(h, ret, flags, rule, dev, ino, name)
	binary.NativeEndian.PutUint16(b[2:4], uint16(KindListenResult))
	return b
}

func TestTerminalBindBeforePathDecisionDoesNotClaimPermission(t *testing.T) {
	f := newFixture(t)
	f.rules.Listen = []agent.ListenRule{{Raw: "unix:/wrong", Proto: agent.ProtoUnix, UnixPath: "/wrong"}}
	_, sink := runRecorder(t, f, Options{BindResults: true, ContinuedBind: func(int, int, uint64, uint64) (supervisor.BindNaming, bool) {
		return supervisor.BindNaming{Path: "/wrong", Rule: "net.listen[wrong]"}, true
	}}, bindResultSample(sample{PID: 50, TID: 50, Start: 900, MonoNS: 1, Verdict: KernelObserved}, -int64(unix.EADDRINUSE), bpf.BindMarked|bpf.BindNameOK, uint32(bpf.PlaneRuleNone), 0, 0, "relative.sock"))
	evs := sink.byKind(record.KindNet)
	if len(evs) != 1 {
		t.Fatalf("events %+v", evs)
	}
	p := payload[record.NetPayload](t, evs[0])
	if evs[0].Verdict != record.VerdictObserved || evs[0].Rule != RuleUnmatched || p.VerdictFrom != "unknown" || p.Mechanism != "" || p.Dst != "unix:relative.sock" || p.SyscallErrno != int(unix.EADDRINUSE) {
		t.Fatalf("undecided pathname fabricated permission %+v %+v", evs[0], p)
	}
}

func TestListenerOutcomesRejectUnrelatedAndUnknownReasons(t *testing.T) {
	terminalInvalid := []bpf.ReasonCode{bpf.ReasonNone, bpf.ReasonDeleteOutsideContract,
		bpf.ReasonRenameOutsideContract, bpf.ReasonMkdirOutsideContract, bpf.ReasonExecNotAllowed,
		bpf.ReasonNetHTTP, bpf.ReasonRefer, bpf.ReasonDenyWriteAncestor, bpf.ReasonProcessScope, 255}
	listenerInvalid := append(append([]bpf.ReasonCode{}, terminalInvalid...),
		bpf.ReasonWriteOutsideContract, bpf.ReasonReadDenied)
	for _, op := range []string{"bind", "listen"} {
		t.Run(op, func(t *testing.T) {
			f := newFixture(t)
			join := func(int, int, uint64, uint64) (supervisor.BindNaming, bool) { return supervisor.BindNaming{}, true }
			samples := make([][]byte, 0, len(terminalInvalid)+len(listenerInvalid))
			for i, reason := range terminalInvalid {
				h := sample{PID: 50, TID: 50, Start: 900, MonoNS: uint64(i + 1), Verdict: KernelRefused, Reason: uint8(reason)}
				makeResult := bindResultSample
				if op == "listen" {
					makeResult = listenResultSample
				}
				samples = append(samples, makeResult(h, -int64(unix.EACCES), bpf.BindMarked|bpf.BindDecided|
					bpf.BindNameOK|bpf.BindAbstract, uint32(bpf.PlaneRuleNone), 0, 0, "untrusted"))
			}
			for i, reason := range listenerInvalid {
				samples = append(samples, planeOwnSample(sample{PID: 50, TID: 50, Start: 900,
					MonoNS: uint64(len(terminalInvalid) + i + 1), Verdict: KernelRefused, Reason: uint8(reason)},
					KindPlaneSocket, hookNumber(t, "socket_"+op), uint32(bpf.PlaneRuleNone), 0, 0, "untrusted", unix.AF_UNIX, unix.SOCK_STREAM, 0))
			}
			r, sink := runRecorder(t, f, Options{BindResults: true, ListenResults: true,
				ContinuedBind: join, ContinuedListen: join}, samples...)
			if got := sink.byKind(record.KindNet); len(got) != 0 {
				t.Fatalf("invalid reasons invented network actions: %+v", got)
			}
			if n := gapCount(r.Gaps())[GapMalformedRecord]; n != int64(len(samples)) {
				t.Fatalf("malformed gaps %d, want %d", n, len(samples))
			}
		})
	}
}

func TestTerminalListenUsesSeparateJoinAndActualBoundName(t *testing.T) {
	for _, mode := range []agent.RecordMode{agent.RecordFull, agent.RecordOff} {
		t.Run(string(mode), func(t *testing.T) {
			f := newFixture(t)
			f.rules.Record = mode
			f.rules.Listen = []agent.ListenRule{{Raw: "unix:@bound", Proto: agent.ProtoUnix, UnixPath: "bound", Abstract: true}}
			bindJoins, listenJoins := 0, 0
			bindJoin := func(int, int, uint64, uint64) (supervisor.BindNaming, bool) {
				bindJoins++
				return supervisor.BindNaming{}, true
			}
			listenJoin := func(tid, pid int, start, at uint64) (supervisor.ListenNaming, bool) {
				listenJoins++
				if tid != 50 || pid != 50 || start != 900 {
					t.Errorf("wrong joined task %d/%d/%d", tid, pid, start)
				}
				return supervisor.ListenNaming{Path: "wrong-attempted-secret", SupervisorOwned: at == 3}, true
			}
			h := sample{PID: 50, TID: 50, Start: 900, MonoNS: 1, Verdict: KernelAllow}
			allow := listenResultSample(h, 0, bpf.BindMarked|bpf.BindDecided|bpf.BindNameOK|bpf.BindAbstract, bpf.PlaneRuleListen, 0, 0, "bound")
			h.MonoNS, h.Verdict, h.Reason = 2, KernelRefused, uint8(bpf.ReasonNetNotAllowed)
			deny := listenResultSample(h, -int64(unix.EACCES), bpf.BindMarked|bpf.BindDecided|bpf.BindNameOK|bpf.BindAbstract, bpf.PlaneRuleListen|uint32(bpf.PlaneRuleNone), 0, 0, "other")
			h.MonoNS, h.Verdict, h.Reason = 3, KernelObserved, 0
			owned := listenResultSample(h, 0, 0, uint32(bpf.PlaneRuleNone), 0, 0, "")
			r, sink := runRecorder(t, f, Options{ListenResults: true, BindResults: true, ContinuedBind: bindJoin, ContinuedListen: listenJoin}, allow, deny, deny, owned)
			if bindJoins != 0 || listenJoins != 3 || !r.ListenHandoverReady() {
				t.Fatalf("bindjoins%d listenjoins%d ready%v", bindJoins, listenJoins, r.ListenHandoverReady())
			}
			evs := sink.byKind(record.KindNet)
			want := 2
			if mode == agent.RecordOff {
				want = 1
			}
			if len(evs) != want {
				t.Fatalf("events %+v", evs)
			}
			for _, ev := range evs {
				p := payload[record.NetPayload](t, ev)
				if p.Op != "listen" || p.Proto != "unix" || p.Dst == "unix:wrong-attempted-secret" {
					t.Fatalf("wrong listener metadata %+v %+v", ev, p)
				}
			}
			if mode == agent.RecordFull {
				p := payload[record.NetPayload](t, evs[0])
				if p.Dst != "unix:@bound" || evs[0].Rule != f.rules.Listen[0].RuleName() || evs[0].Verdict != record.VerdictAllow {
					t.Fatalf("actual bound proof %+v %+v", evs[0], p)
				}
			}
			p := payload[record.NetPayload](t, evs[len(evs)-1])
			if p.Dst != "unix:@other" || p.SyscallRet != -int64(unix.EACCES) || evs[len(evs)-1].Verdict != record.VerdictRefused {
				t.Fatalf("listen refusal %+v %+v", evs[len(evs)-1], p)
			}
		})
	}
}

func TestTerminalBindAndListenDedupAreIndependent(t *testing.T) {
	f := newFixture(t)
	join := func(int, int, uint64, uint64) (supervisor.BindNaming, bool) { return supervisor.BindNaming{}, true }
	h := sample{PID: 50, TID: 50, Start: 900, MonoNS: 1, Verdict: KernelObserved}
	_, sink := runRecorder(t, f, Options{BindResults: true, ListenResults: true, ContinuedBind: join, ContinuedListen: join},
		bindResultSample(h, -int64(unix.EBADF), 0, uint32(bpf.PlaneRuleNone), 0, 0, ""),
		listenResultSample(h, -int64(unix.EBADF), 0, uint32(bpf.PlaneRuleNone), 0, 0, ""))
	evs := sink.byKind(record.KindNet)
	if len(evs) != 2 || payload[record.NetPayload](t, evs[0]).Op != "bind" || payload[record.NetPayload](t, evs[1]).Op != "listen" {
		t.Fatalf("cross-operation dedup %+v", evs)
	}
}

func TestTerminalListenerDropsStaleGenerationBeforeJoin(t *testing.T) {
	f := newFixture(t)
	joins := 0
	join := func(int, int, uint64, uint64) (supervisor.BindNaming, bool) {
		joins++
		return supervisor.BindNaming{}, true
	}
	ring := newFakeRing(
		bindResultSample(sample{PID: 50, TID: 50, Start: 900, CgroupID: 41, RunIdx: 3, Gen: 7001, MonoNS: 1}, -int64(unix.EACCES), 0, uint32(bpf.PlaneRuleNone), 0, 0, ""),
		listenResultSample(sample{PID: 50, TID: 50, Start: 900, CgroupID: 41, RunIdx: 9, Gen: 7002, MonoNS: 2}, -int64(unix.EACCES), 0, uint32(bpf.PlaneRuleNone), 0, 0, ""))
	r, err := New(Options{Rules: f.rules, Reader: ring, Proc: f.procFS, BindResults: true, ListenResults: true, ContinuedBind: join, ContinuedListen: join,
		RunSet: &fakeRunSet{rows: map[uint64]uint32{41: 3}, gens: map[uint64]uint32{41: 7002}}})
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if err := r.Start(context.Background(), source.RunRef{ID: "r-host-1", Agent: "retriever", CgroupID: 41}, sink); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Stop() })
	waitFor(t, func() bool { ring.mu.Lock(); defer ring.mu.Unlock(); return len(ring.samples) == 0 }, "scoped samples not drained")
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if joins != 0 || len(sink.byKind(record.KindNet)) != 0 {
		t.Fatalf("stale consumed metadata joins%d events%+v", joins, sink.all())
	}
}

func TestRecorderTerminalBindUsesKernelEvidenceOnce(t *testing.T) {
	for _, mode := range []agent.RecordMode{agent.RecordFull, agent.RecordOff} {
		t.Run(string(mode), func(t *testing.T) {
			f := newFixture(t)
			f.rules.Record = mode
			f.rules.Listen = []agent.ListenRule{{Raw: "unix:@actual", Proto: agent.ProtoUnix, UnixPath: "actual", Abstract: true}}
			di, ok := statDevIno(f.out)
			if !ok {
				t.Fatal("stat directory")
			}
			joins := 0
			join := func(tid, pid int, start, at uint64) (supervisor.BindNaming, bool) {
				joins++
				if tid != 50 || pid != 50 || start != 900 {
					t.Errorf("join task %d/%d birth%d", tid, pid, start)
				}
				return supervisor.BindNaming{Path: "stale-wrong-secret", Rule: "stale-wrong-rule", AttemptMonoNS: at - 1, SupervisorOwned: at == 5}, true
			}
			allow := bindResultSample(sample{PID: 50, TID: 50, Start: 900, MonoNS: 1, Verdict: KernelAllow}, 0, bpf.BindMarked|bpf.BindDecided|bpf.BindNameOK|bpf.BindAbstract, bpf.PlaneRuleListen, 0, 0, "actual")
			refuse := bindResultSample(sample{PID: 50, TID: 50, Start: 900, MonoNS: 2, Verdict: KernelRefused, Reason: uint8(bpf.ReasonNetNotAllowed)}, -int64(unix.EACCES), bpf.BindMarked|bpf.BindDecided|bpf.BindNameOK|bpf.BindAbstract, bpf.PlaneRuleListen|uint32(bpf.PlaneRuleNone), 0, 0, "other\x00actual")
			r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, DecisionPlane: record.DecisionPlaneLSM, BindResults: true, ContinuedBind: join},
				allow, refuse, refuse,
				bindResultSample(sample{PID: 50, TID: 50, Start: 900, MonoNS: 3, Verdict: KernelAllow}, -int64(unix.EADDRINUSE), bpf.BindMarked|bpf.BindDecided|bpf.BindNameOK|bpf.BindResolved, bpf.PlaneRuleListen, di.Dev, di.Ino, "agent.sock"),
				bindResultSample(sample{PID: 50, TID: 50, Start: 900, MonoNS: 4, Verdict: KernelObserved}, -int64(unix.EBADF), 0, uint32(bpf.PlaneRuleNone), 0, 0, ""),
				bindResultSample(sample{PID: 50, TID: 50, Start: 900, MonoNS: 5, Verdict: KernelObserved}, 0, 0, uint32(bpf.PlaneRuleNone), 0, 0, ""))
			if joins != 5 {
				t.Fatalf("joins=%d want5 distinctoutcomes", joins)
			}
			if !r.BindHandoverReady() {
				t.Fatal("configured handover not ready")
			}
			evs := sink.byKind(record.KindNet)
			want := 4
			if mode == agent.RecordOff {
				want = 1
			}
			if len(evs) != want {
				t.Fatalf("netlines=%d want%d: %+v", len(evs), want, evs)
			}
			for _, ev := range evs {
				if err := ev.Validate(); err != nil {
					t.Error(err)
				}
			}
			index := 0
			if mode != agent.RecordOff {
				p := payload[record.NetPayload](t, evs[0])
				if p.Dst != "unix:@actual" || evs[0].Rule != f.rules.Listen[0].RuleName() || p.VerdictFrom != "plane" {
					t.Fatalf("allow %+v %+v", evs[0], p)
				}
				index = 1
				p = payload[record.NetPayload](t, evs[2])
				if p.Dst != "unix:"+filepath.Join(f.out, "agent.sock") || evs[2].Verdict != record.VerdictAllow || p.SyscallErrno != int(unix.EADDRINUSE) {
					t.Fatalf("kerneladdress/error %+v %+v", evs[2], p)
				}
				p = payload[record.NetPayload](t, evs[3])
				if p.Dst != "<unavailable>" || p.VerdictFrom != "unknown" || evs[3].Rule != RuleUnmatched || evs[3].Verdict != record.VerdictObserved || p.SyscallRet != -int64(unix.EBADF) {
					t.Fatalf("no-marker evidence %+v %+v", evs[3], p)
				}
			}
			p := payload[record.NetPayload](t, evs[index])
			if p.Dst != "unix:@other\x00actual" || p.SyscallRet != -int64(unix.EACCES) || p.Mechanism != record.MechanismPlane || evs[index].Reason != record.ReasonNetNotAllowed || evs[index].Rule != RuleUnmatched {
				t.Fatalf("refusal %+v %+v", evs[index], p)
			}
		})
	}
}

func TestBindMissingJoinNeverReusesNamesOrRecoversTrust(t *testing.T) {
	f := newFixture(t)
	f.rules.Record = agent.RecordOff
	r, sink := runRecorder(t, f, Options{BindResults: true, FlushInterval: time.Hour, ContinuedBind: func(int, int, uint64, uint64) (supervisor.BindNaming, bool) {
		return supervisor.BindNaming{Path: "secret-stale", Rule: "stale"}, false
	}},
		bindResultSample(sample{PID: 50, TID: 50, Start: 900, MonoNS: 2, Verdict: KernelObserved}, -int64(unix.EACCES), 0, uint32(bpf.PlaneRuleNone), 0, 0, ""))
	evs := sink.byKind(record.KindNet)
	if len(evs) != 1 {
		t.Fatalf("missing-chain-refusal: %+v", evs)
	}
	p := payload[record.NetPayload](t, evs[0])
	if p.Dst != "<unavailable>" || evs[0].Rule != RuleUnmatched || evs[0].Reason != record.ReasonPathUnresolved || p.Mechanism != "" || p.VerdictFrom != record.FSVerdictChain || gapCount(r.Gaps())[GapBindMetadataMissing] != 1 {
		t.Fatalf("invented attribution %+v %+v gaps%+v", evs[0], p, r.Gaps())
	}
}

func TestBindRestartAndMalformedOutcomeDoNotConsumeNaming(t *testing.T) {
	f := newFixture(t)
	joins := 0
	r, sink := runRecorder(t, f, Options{BindResults: true, FlushInterval: time.Hour, ContinuedBind: func(int, int, uint64, uint64) (supervisor.BindNaming, bool) {
		joins++
		return supervisor.BindNaming{}, true
	}},
		bindResultSample(sample{PID: 50, TID: 50, Start: 900, MonoNS: 1, Verdict: KernelObserved}, -512, 0, uint32(bpf.PlaneRuleNone), 0, 0, ""),
		bindResultSample(sample{PID: 50, TID: 50, Start: 900, MonoNS: 2, Verdict: KernelObserved}, 1, 0, uint32(bpf.PlaneRuleNone), 0, 0, ""))
	if joins != 0 || len(sink.byKind(record.KindNet)) != 0 || gapCount(r.Gaps())[GapMalformedRecord] != 1 {
		t.Fatalf("joins%d events%+v gaps%+v", joins, sink.all(), r.Gaps())
	}
}

func TestDecodeBindResultAndZeroReuse(t *testing.T) {
	var rec Record
	if err := DecodeInto(&rec, bindResultSample(sample{Start: 13}, -int64(unix.EACCES), bpf.BindMarked|bpf.BindDecided|bpf.BindNameOK|bpf.BindAbstract, bpf.PlaneRuleListen, 0, 0, "a\x00b")); err != nil {
		t.Fatal(err)
	}
	if rec.BindResult.Name != "a\x00b" || rec.BindResult.Ret != -int64(unix.EACCES) || rec.StartNS != 13 {
		t.Fatalf("decode %+v", rec)
	}
	if err := DecodeInto(&rec, planeExecSample(sample{}, uint32(bpf.PlaneRuleNone), "/tool")); err != nil {
		t.Fatal(err)
	}
	if rec.BindResult != (BindResultBody{}) {
		t.Fatal("previous bind body remained")
	}
}

// TestURingListenerResultsNeedNoSupervisorNaming is enforce-plane §2.20's io_uring records: IORING_OP_BIND and
// IORING_OP_LISTEN pass no seccomp notification, so a TEGO_BIND_URING record is decoded, joins no supervisor
// naming and counts no bind-metadata-missing gap, and its refusal is the plane's line like a syscall's.
func TestURingListenerResultsNeedNoSupervisorNaming(t *testing.T) {
	f := newFixture(t)
	f.rules.Listen = []agent.ListenRule{{Raw: "unix:@declared", Proto: agent.ProtoUnix, UnixPath: "declared", Abstract: true}}
	joins := 0
	join := func(int, int, uint64, uint64) (supervisor.BindNaming, bool) {
		joins++
		return supervisor.BindNaming{}, false
	}
	h := sample{PID: 50, TID: 50, Start: 900, MonoNS: 1, Verdict: KernelRefused, Reason: uint8(bpf.ReasonNetNotAllowed)}
	flags := bpf.BindURing | bpf.BindMarked | bpf.BindDecided | bpf.BindNameOK | bpf.BindAbstract
	bind := bindResultSample(h, -int64(unix.EACCES), flags, bpf.PlaneRuleListen|uint32(bpf.PlaneRuleNone), 0, 0, "undeclared")
	h.MonoNS = 2
	listen := listenResultSample(h, -int64(unix.EACCES), bpf.BindURing|bpf.BindMarked|bpf.BindDecided,
		bpf.PlaneRuleListen|uint32(bpf.PlaneRuleNone), 0, 0, "")
	r, sink := runRecorder(t, f, Options{BindResults: true, ListenResults: true, ContinuedBind: join, ContinuedListen: join}, bind, listen)
	if joins != 0 {
		t.Fatalf("an io_uring result asked the supervisor for naming %d times", joins)
	}
	gaps := gapCount(r.Gaps())
	if gaps[GapBindMetadataMissing] != 0 || gaps[GapMalformedRecord] != 0 {
		t.Fatalf("gaps %+v", gaps)
	}
	evs := sink.byKind(record.KindNet)
	if len(evs) != 2 {
		t.Fatalf("events %+v", evs)
	}
	p := payload[record.NetPayload](t, evs[0])
	if evs[0].Verdict != record.VerdictRefused || p.Op != "bind" || p.Dst != "unix:@undeclared" || p.Mechanism != record.MechanismPlane ||
		p.SyscallErrno != int(unix.EACCES) {
		t.Fatalf("io_uring bind refusal %+v %+v", evs[0], p)
	}
	if p := payload[record.NetPayload](t, evs[1]); evs[1].Verdict != record.VerdictRefused || p.Op != "listen" {
		t.Fatalf("io_uring listen refusal %+v %+v", evs[1], p)
	}
}

func TestBindLookupWithoutKernelMarkerDisclosesMissingEvidence(t *testing.T) {
	f := newFixture(t)
	r, sink := runRecorder(t, f, Options{BindResults: true, ContinuedBind: func(int, int, uint64, uint64) (supervisor.BindNaming, bool) {
		return supervisor.BindNaming{Path: "/copied-attempt-not-kernel-evidence", Rule: "wrong"}, true
	}}, bindResultSample(sample{PID: 50, TID: 50, Start: 900, MonoNS: 1, Verdict: KernelObserved},
		-int64(unix.ENOTDIR), 0, uint32(bpf.PlaneRuleNone), 0, 0, ""))
	evs := sink.byKind(record.KindNet)
	if len(evs) != 1 {
		t.Fatalf("terminal results: %+v", evs)
	}
	p := payload[record.NetPayload](t, evs[0])
	if evs[0].Verdict != record.VerdictObserved || evs[0].Rule != RuleUnmatched || p.Dst != "<unavailable>" ||
		p.SyscallErrno != int(unix.ENOTDIR) || p.VerdictFrom != "unknown" || p.Mechanism != "" {
		t.Fatalf("missing kernel evidence became a named decision: %+v %+v", evs[0], p)
	}
	if gapCount(r.Gaps())[GapBindMetadataMissing] != 1 {
		t.Fatalf("missing marker was not disclosed: %+v", r.Gaps())
	}
}
