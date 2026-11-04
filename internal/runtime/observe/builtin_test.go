// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestBuiltinTTYKernelAttribution(t *testing.T) {
	r := &Recorder{rules: &ruleIndex{rt: &agent.RuleTable{Builtins: &agent.BuiltinRefusals{}}}, ownTTY: [2]uint64{10, 20}}
	for _, tt := range []struct {
		name, path string
		dev, ino   uint64
		ret        int32
		want       bool
	}{
		{"foreign read", "/dev/pts/2", 10, 21, -int32(unix.EACCES), true},
		{"foreign console", "/dev/tty3", 11, 22, -int32(unix.EPERM), true},
		{"own terminal", "/dev/pts/1", 10, 20, -int32(unix.EACCES), false},
		{"allowed open", "/dev/pts/2", 10, 21, 0, false},
		{"ordinary file", "/work/x", 10, 21, -int32(unix.EACCES), false},
		{"serial", "/dev/ttyUSB0", 10, 21, -int32(unix.EACCES), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := &Record{FS: FSBody{Dev: tt.dev, Ino: tt.ino, Ret: tt.ret, RetOK: true}}
			if got := r.builtinTTYRefusal(rec, tt.path); got != tt.want {
				t.Fatalf("actual kernel refusal attribution %v want %v", got, tt.want)
			}
		})
	}
}

func TestBuiltinNativePeerRecord(t *testing.T) {
	for _, rule := range []string{agent.BuiltinHostIPC, agent.BuiltinTegoSurface} {
		t.Run(rule, func(t *testing.T) {
			f := newFixture(t)
			rt, _ := planeTable(f)
			rt.Builtins = &agent.BuiltinRefusals{TegoDirs: []string{f.out}}
			rt.DenyWrite = append(rt.DenyWrite, agent.FSRule{Path: f.out, Resolved: f.out, Kind: agent.FSDenyWrite, BuiltinRule: rule})
			f.rules = rt
			rows, err := decide.CompilePlane(rt)
			if err != nil {
				t.Fatal(err)
			}
			row := uint32(planeRow(t, rows, f.out))
			di, ok := statDevIno(f.out)
			if !ok {
				t.Fatal("stat fixture")
			}
			var samples [][]byte
			for i, idx := range []uint32{row, bpf.PlaneRuleBuiltinHost, bpf.PlaneRuleBuiltinSurface} {
				samples = append(samples, planeFSSample(sample{PID: 50, TID: 50, MonoNS: uint64(i + 1), Start: 900, Reason: uint8(bpf.ReasonNetNotAllowed)}, hookNumber(t, "unix_may_send"), idx, di.Dev, di.Ino, "socket", 0))
			}
			_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, DecisionPlane: record.DecisionPlaneFmodRet}, samples...)
			events := sink.byKind(record.KindNet)
			if len(events) != 3 {
				t.Fatalf("native peer lines: %+v", sink.events)
			}
			for i, ev := range events {
				want := rule
				if i == 1 {
					want = agent.BuiltinHostIPC
				}
				if i == 2 {
					want = agent.BuiltinTegoSurface
				}
				if ev.Rule != want || ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonNetNotAllowed {
					t.Errorf("native peer attribution: %+v", ev)
				}
				if err := ev.Validate(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
