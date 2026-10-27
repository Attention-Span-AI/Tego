// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// sockoptSample builds cgroup/setsockopt's own refusal record (struct tego_ev_sockopt).
func sockoptSample(h sample, level, optname, optlen int32, name string) []byte {
	h.Kind = KindSockopt
	h.Verdict = KernelRefused
	e := bpf.SockoptEvent{Hdr: h.header(SockoptSize), Level: level, Optname: optname, Optlen: optlen}
	copy(e.Name[:], name)
	return wire(&e)
}

// TestRecorderNamesSockoptRefusals is ADR 0018 (7) in the recorder: a TCP_ULP cgroup/setsockopt
// refused is one refused line, op setsockopt, the ULP spelled as the supervisor spells its own refusal of the same
// option (supervisor socket.go, record.SocketOption), its name cut where the kernel cuts it (at optlen, the first NUL
// and 15 bytes), reason net-not-allowed, rule unmatched, mechanism cgroup and no decision_plane. It is kept under
// record: off, since it is a refusal (ADR 0016 (3)).
func TestRecorderNamesSockoptRefusals(t *testing.T) {
	for _, mode := range []agent.RecordMode{agent.RecordFull, agent.RecordSummary, agent.RecordOff} {
		for _, plane := range []string{"", record.DecisionPlaneFmodRet} {
			t.Run(string(mode)+"/"+plane, func(t *testing.T) {
				f := newFixture(t)
				f.rules.Record = mode
				refused := func(mono uint64, optlen int32, name string) []byte {
					return sockoptSample(sample{PID: 50, TID: 50, MonoNS: mono, CgroupID: 41,
						Reason: uint8(bpf.ReasonNetNotAllowed)}, unix.SOL_TCP, unix.TCP_ULP, optlen, name)
				}
				r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, DecisionPlane: plane},
					refused(1, 4, "smc"),
					refused(2, 2, "smc"),
					refused(3, 4096, "abcdefghijklmno"),
					refused(4, 0, "tls"),
				)
				lines := sink.byKind(record.KindRefused)
				if len(lines) != 4 || len(sink.all()) != 4 {
					t.Fatalf("%d refused lines of %d, want one per refused option (4): %+v", len(lines), len(sink.all()), sink.all())
				}
				for i, target := range []string{`TCP_ULP "smc"`, `TCP_ULP "sm"`, `TCP_ULP "abcdefghijklmno"`, `TCP_ULP ""`} {
					ev := lines[i]
					p := payload[record.RefusedPayload](t, ev)
					if ev.Rule != RuleUnmatched || ev.Reason != record.ReasonNetNotAllowed || ev.Verdict != "" ||
						ev.Authority != "" || ev.Attr != nil || p.Op != "setsockopt" || p.Target != target ||
						p.Mechanism != record.MechanismCgroup || p.DecisionPlane != "" ||
						p.Rule != RuleUnmatched || p.Reason != record.ReasonNetNotAllowed {
						t.Errorf("line %d: rule %s reason %s verdict %q authority %q %+v, want refused setsockopt %q, mechanism cgroup",
							i, ev.Rule, ev.Reason, ev.Verdict, ev.Authority, p, target)
					}
					if err := ev.Validate(); err != nil {
						t.Errorf("line %d is one the ledger would refuse: %v", i, err)
					}
				}
				if n := gapCount(r.Gaps())[GapMalformedRecord]; n != 0 {
					t.Errorf("%d malformed-record gaps for well-formed records", n)
				}
			})
		}
	}
}

// TestRecorderSockoptRecordOutOfShapeIsAGap: a cgroup/setsockopt record that cannot be the program's (a reason other
// than net-not-allowed, or an option other than TCP_ULP, which the program never refuses) still writes its refused
// line, since the kernel refused that call whatever the record says, and is a malformed-record gap.
func TestRecorderSockoptRecordOutOfShapeIsAGap(t *testing.T) {
	for _, c := range []struct {
		name            string
		reason          bpf.ReasonCode
		level, optname  int32
		target          string
		optlen          int32
		ulp             string
		wantMalformedOf int64
	}{
		{"another reason", bpf.ReasonPathUnresolved, unix.SOL_TCP, unix.TCP_ULP, `TCP_ULP "smc"`, 4, "smc", 1},
		{"no reason", bpf.ReasonNone, unix.SOL_TCP, unix.TCP_ULP, `TCP_ULP "smc"`, 4, "smc", 1},
		{"another option", bpf.ReasonNetNotAllowed, unix.SOL_TCP, unix.TCP_NODELAY, "setsockopt level 6 option 1", 4, "", 1},
		{"another level", bpf.ReasonNetNotAllowed, unix.SOL_SOCKET, unix.TCP_ULP, "setsockopt level 1 option 31", 4, "smc", 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour},
				sockoptSample(sample{PID: 50, TID: 50, MonoNS: 1, Reason: uint8(c.reason)}, c.level, c.optname, c.optlen, c.ulp))
			lines := sink.byKind(record.KindRefused)
			if len(lines) != 1 || lines[0].Reason != record.ReasonNetNotAllowed || lines[0].Rule != RuleUnmatched {
				t.Fatalf("%+v, want one refused net-not-allowed line", lines)
			}
			if p := payload[record.RefusedPayload](t, lines[0]); p.Op != "setsockopt" || p.Target != c.target {
				t.Errorf("payload %+v, want setsockopt %q", p, c.target)
			}
			if n := gapCount(r.Gaps())[GapMalformedRecord]; n != c.wantMalformedOf {
				t.Errorf("%d malformed-record gaps, want %d", n, c.wantMalformedOf)
			}
		})
	}
}

// TestRecorderDropsAnotherGensSockoptRecord is ADR 0026 (6) for this record, as for cgroup/sock_create's: a scoped
// recorder writes no line for a record of another generation of its slot, nor of another slot.
func TestRecorderDropsAnotherGensSockoptRecord(t *testing.T) {
	rs := &fakeRunSet{rows: map[uint64]uint32{41: 3}, gens: map[uint64]uint32{41: 7}}
	mine := sample{PID: 50, TID: 50, MonoNS: 1, CgroupID: 41, RunIdx: 3, Gen: 7, Reason: uint8(bpf.ReasonNetNotAllowed)}
	stale, other := mine, mine
	stale.Gen, stale.MonoNS = 6, 2
	other.RunIdx, other.MonoNS = 9, 3
	_, sink := startScoped(t, rs, nil,
		sockoptSample(stale, unix.SOL_TCP, unix.TCP_ULP, 4, "old"),
		sockoptSample(other, unix.SOL_TCP, unix.TCP_ULP, 4, "oth"),
		sockoptSample(mine, unix.SOL_TCP, unix.TCP_ULP, 4, "smc"),
	)
	lines := sink.byKind(record.KindRefused)
	if len(lines) != 1 {
		t.Fatalf("%d refused lines, want only this run's generation's: %+v", len(lines), lines)
	}
	if p := payload[record.RefusedPayload](t, lines[0]); p.Target != `TCP_ULP "smc"` {
		t.Errorf("kept %q, want this generation's line", p.Target)
	}
}

// TestDecodeSockopt: the record decodes into its option, value length and name; a record of another width is refused,
// and a recorder counts it as a malformed record and writes no line.
func TestDecodeSockopt(t *testing.T) {
	var rec Record
	if err := DecodeInto(&rec, sockoptSample(sample{PID: 7, Gen: 4}, unix.SOL_TCP, unix.TCP_ULP, 4, "smc")); err != nil {
		t.Fatal(err)
	}
	if rec.Kind != KindSockopt || rec.Sockopt.Level != unix.SOL_TCP || rec.Sockopt.Optname != unix.TCP_ULP ||
		rec.Sockopt.Optlen != 4 || string(rec.Sockopt.Name[:3]) != "smc" || rec.Gen != 4 || rec.PID != 7 {
		t.Fatalf("decoded %+v", rec)
	}
	if KindSockopt.String() != "sockopt" || !KindSockopt.Valid() || Kind(32).Valid() {
		t.Errorf("kind 29: %s valid %v; kind 32 valid %v", KindSockopt, KindSockopt.Valid(), Kind(32).Valid())
	}
	short := sample{Kind: KindSockopt, Size: SockoptSize - 4}.bytes(make([]byte, SockoptSize-4-HeaderSize))
	if err := DecodeInto(&rec, short); !errors.Is(err, ErrShortRecord) {
		t.Errorf("a short sockopt record decoded: %v", err)
	}
	f := newFixture(t)
	r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour}, short)
	if len(sink.all()) != 0 || gapCount(r.Gaps())[GapMalformedRecord] != 1 {
		t.Errorf("a short record: %d lines, gaps %+v", len(sink.all()), r.Gaps())
	}
}
