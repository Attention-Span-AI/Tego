// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestRecorderPlaneControlRefusals(t *testing.T) {
	for _, mode := range []agent.RecordMode{agent.RecordFull, agent.RecordOff} {
		t.Run(string(mode), func(t *testing.T) {
			f := newFixture(t)
			f.rules.Record = mode
			cases := []struct {
				hook, op, rule, target string
				code                   bpf.ReasonCode
				reason                 record.Reason
				peer, arg              int32
			}{
				{"ptrace_access_check", "ptrace", "process-scope", "123", bpf.ReasonProcessScope, record.ReasonLandlockTopology, 123, 0},
				{"ptrace_traceme", "ptrace_traceme", "process-scope", "456", bpf.ReasonProcessScope, record.ReasonLandlockTopology, 456, 0},
				{"bpf", "bpf", "bpf", "command 5", bpf.ReasonProcessScope, record.ReasonLandlockTopology, 0, 5},
				{"key_permission", "key_permission", "keyring", "permission 3", bpf.ReasonReadDenied, record.ReasonReadDenied, 0, 3},
				{"key_permission", "key_permission", "keyring", "permission 3", bpf.ReasonPathUnresolved, record.ReasonPathUnresolved, 0, 3},
			}
			var samples [][]byte
			for i, c := range cases {
				samples = append(samples, planeOwnSample(sample{PID: 50, TID: 50, Start: 900, MonoNS: uint64(i + 1), Reason: uint8(c.code)},
					KindPlaneControl, hookNumber(t, c.hook), uint32(bpf.PlaneRuleNone), 0, 0, "", c.peer, c.arg, 0))
			}
			_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, DecisionPlane: record.DecisionPlaneLSM}, samples...)
			got := sink.byKind(record.KindRefused)
			if len(got) != len(cases) {
				t.Fatalf("got %d control refusals, want %d", len(got), len(cases))
			}
			for i, ev := range got {
				c := cases[i]
				p := payload[record.RefusedPayload](t, ev)
				if ev.Source != record.SourceKernel || ev.Rule != c.rule || ev.Reason != c.reason || p.Op != c.op || p.Target != c.target || p.Rule != c.rule || p.Reason != c.reason || p.Mechanism != record.MechanismPlane || p.DecisionPlane != record.DecisionPlaneLSM {
					t.Errorf("control %d: %+v payload %+v", i, ev, p)
				}
				if err := ev.Validate(); err != nil {
					t.Errorf("invalid control event: %v", err)
				}
			}
		})
	}
}

func TestMalformedPlaneControlCannotInventRefusal(t *testing.T) {
	f := newFixture(t)
	f.rules.Record = agent.RecordOff
	bad := planeOwnSample(sample{PID: 50, MonoNS: 1, Reason: uint8(bpf.ReasonNetNotAllowed)}, KindPlaneControl, hookNumber(t, "bpf"), uint32(bpf.PlaneRuleNone), 0, 0, "", 0, 5, 0)
	unknown := planeOwnSample(sample{PID: 50, MonoNS: 2, Reason: uint8(bpf.ReasonProcessScope)}, KindPlaneControl, hookNumber(t, "socket_create"), uint32(bpf.PlaneRuleNone), 0, 0, "", 0, 5, 0)
	r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour}, bad, unknown)
	if got := sink.byKind(record.KindRefused); len(got) != 0 {
		t.Fatalf("malformed samples invented actions: %+v", got)
	}
	if gapCount(r.Gaps())[GapMalformedRecord] != 2 {
		t.Fatalf("gaps %+v", r.Gaps())
	}
}
