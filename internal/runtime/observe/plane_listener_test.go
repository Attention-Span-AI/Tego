// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

func planeListenerSample(h sample, hook uint16, rule uint32, dev, ino uint64, name string, abstract bool) []byte {
	h.Kind = KindPlaneSocket
	h.Verdict = KernelRefused
	e := bpf.PlaneEvent{Hdr: h.header(PlaneSize), StartNS: h.Start, Hook: hook, RuleIdx: rule, Dev: kernelDev(dev), DirIno: ino,
		Family: unix.AF_UNIX, PathOK: 1, Flags: uint32(len(name)) << 16}
	if abstract {
		e.Flags |= 1
	}
	copy(e.Path[:], name)
	return wire(&e)
}

func TestDecodePlaneListenerExactAbstractNameAndReuse(t *testing.T) {
	name := "service\x00suffix"
	var rec Record
	if err := DecodeInto(&rec, planeListenerSample(sample{}, hookNumber(t, "socket_bind"), bpf.PlaneRuleListen|2, 0, 0, name, true)); err != nil {
		t.Fatal(err)
	}
	if rec.Plane.Path != name || rec.Plane.PathTruncated || rec.FS.Flags&1 == 0 || rec.Plane.RuleIdx != bpf.PlaneRuleListen|2 {
		t.Fatalf("lost exact abstract name: %+v", rec)
	}
	if err := DecodeInto(&rec, planeOwnSample(sample{}, KindPlaneControl, hookNumber(t, "bpf"), uint32(bpf.PlaneRuleNone), 0, 0, "", 0, 5, 0)); err != nil {
		t.Fatal(err)
	}
	if rec.FS.Flags != 0 || rec.Plane.Path != "" || rec.Plane.RuleIdx != uint32(bpf.PlaneRuleNone) {
		t.Fatalf("previous listener state leaked: %+v", rec)
	}
	if err := DecodeInto(&rec, planeListenerSample(sample{}, hookNumber(t, "socket_bind"), bpf.PlaneRuleListen, 0, 0, string(make([]byte, 108)), true)); err == nil {
		t.Fatal("oversized name accepted")
	}
}

func TestRecorderPlaneListenerRefusals(t *testing.T) {
	for _, mode := range []agent.RecordMode{agent.RecordFull, agent.RecordOff} {
		t.Run(string(mode), func(t *testing.T) {
			f := newFixture(t)
			f.rules.Record = mode
			name := "service\x00suffix"
			f.rules.Listen = []agent.ListenRule{{Raw: "unix:@service", Proto: agent.ProtoUnix, Abstract: true, UnixPath: name}}
			di, ok := statDevIno(f.out)
			if !ok {
				t.Fatal("stat write directory")
			}
			_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, DecisionPlane: record.DecisionPlaneLSM},
				planeListenerSample(sample{PID: 50, TID: 50, Start: 900, MonoNS: 1, Reason: uint8(bpf.ReasonNetNotAllowed)}, hookNumber(t, "socket_bind"), bpf.PlaneRuleListen, 0, 0, name, true),
				planeListenerSample(sample{PID: 50, TID: 50, Start: 900, MonoNS: 2, Reason: uint8(bpf.ReasonIdentityMismatch)}, hookNumber(t, "socket_bind"), bpf.PlaneRuleListen|uint32(bpf.PlaneRuleNone), di.Dev, di.Ino, "agent.sock", false),
				planeListenerSample(sample{PID: 50, TID: 50, Start: 900, MonoNS: 3, Reason: uint8(bpf.ReasonNetNotAllowed)}, hookNumber(t, "socket_listen"), bpf.PlaneRuleListen, 0, 0, name, true))
			evs := sink.byKind(record.KindNet)
			if len(evs) != 3 || len(sink.byKind(record.KindFS)) != 0 {
				t.Fatalf("listener actions net=%d fs=%d", len(evs), len(sink.byKind(record.KindFS)))
			}
			for i, ev := range evs {
				p := payload[record.NetPayload](t, ev)
				if ev.Verdict != record.VerdictRefused || ev.Source != record.SourceKernel || p.Proto != "unix" || p.Mechanism != record.MechanismPlane || p.DecisionPlane != record.DecisionPlaneLSM {
					t.Errorf("listener %d: %+v %+v", i, ev, p)
				}
				if err := ev.Validate(); err != nil {
					t.Errorf("invalid listener event: %v", err)
				}
			}
			first := payload[record.NetPayload](t, evs[0])
			last := payload[record.NetPayload](t, evs[2])
			if first.Op != "bind" || first.Dst != "unix:@"+name || evs[0].Rule != f.rules.Listen[0].RuleName() || last.Op != "listen" {
				t.Fatalf("abstract rule/name: %+v %+v", first, last)
			}
			middle := payload[record.NetPayload](t, evs[1])
			if middle.Dst != "unix:"+filepath.Join(f.out, "agent.sock") || middle.PlaneReason != record.PlaneReasonIdentityMismatch || evs[1].Reason != record.ReasonPathUnresolved || evs[1].Rule != RuleUnmatched {
				t.Fatalf("pathname identity mismatch: %+v %+v", evs[1], middle)
			}
		})
	}
}
