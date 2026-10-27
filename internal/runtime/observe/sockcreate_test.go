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

// sockCreateSample builds cgroup/sock_create's own refusal record (struct tego_ev_sock).
func sockCreateSample(h sample, family, typ, protocol int32) []byte {
	h.Kind = KindSockCreate
	h.Verdict = KernelRefused
	e := bpf.SockEvent{Hdr: h.header(SockSize), Family: family, Type: typ, Protocol: protocol}
	return wire(&e)
}

// TestRecorderNamesSockCreateRefusals is ADR 0018 PR 2 in the recorder (enforce-cgroup-observe §5 R4, R5): a socket
// cgroup/sock_create refused is one refused line, op socket, the triple spelled as the supervisor spells its own
// socket refusal (supervisor socket.go, record.SocketTriple), reason net-not-allowed, rule unmatched, mechanism cgroup
// and no decision_plane, since no plane decided it, a plane mode's run included; MPTCP is named by its whole number.
// It is kept under record: off, as the plane's socket refusal is, since it is a refusal (ADR 0016 (3)).
func TestRecorderNamesSockCreateRefusals(t *testing.T) {
	for _, mode := range []agent.RecordMode{agent.RecordFull, agent.RecordSummary, agent.RecordOff} {
		for _, plane := range []string{"", record.DecisionPlaneFmodRet} {
			t.Run(string(mode)+"/"+plane, func(t *testing.T) {
				f := newFixture(t)
				f.rules.Record = mode
				refused := func(mono uint64, family, typ, protocol int32) []byte {
					return sockCreateSample(sample{PID: 50, TID: 50, MonoNS: mono, CgroupID: 41,
						Reason: uint8(bpf.ReasonNetNotAllowed)}, family, typ, protocol)
				}
				r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, DecisionPlane: plane},
					refused(1, unix.AF_INET, unix.SOCK_STREAM, 132),
					refused(2, unix.AF_INET6, unix.SOCK_STREAM, 262),
					refused(3, unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP),
				)
				lines := sink.byKind(record.KindRefused)
				if len(lines) != 3 || len(sink.all()) != 3 {
					t.Fatalf("%d refused lines of %d, want one per refused socket (3): %+v", len(lines), len(sink.all()), sink.all())
				}
				for i, target := range []string{"AF_INET SOCK_STREAM protocol 132", "AF_INET6 SOCK_STREAM protocol 262",
					"AF_INET SOCK_DGRAM protocol 1"} {
					ev := lines[i]
					p := payload[record.RefusedPayload](t, ev)
					if ev.Rule != RuleUnmatched || ev.Reason != record.ReasonNetNotAllowed || ev.Verdict != "" ||
						ev.Authority != "" || ev.Attr != nil || p.Op != "socket" || p.Target != target ||
						p.Mechanism != record.MechanismCgroup || p.DecisionPlane != "" ||
						p.Rule != RuleUnmatched || p.Reason != record.ReasonNetNotAllowed {
						t.Errorf("line %d: rule %s reason %s verdict %q authority %q %+v, want refused socket %q, mechanism cgroup",
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

// TestRecorderSockCreateRecordOutOfShapeIsAGap: a cgroup/sock_create record that cannot be the program's (a reason
// other than net-not-allowed, or a triple ADR 0018's allowlist admits even without an ICMP entry) still writes its
// refused line, since the kernel refused that socket whatever the record says, and is a malformed-record gap.
func TestRecorderSockCreateRecordOutOfShapeIsAGap(t *testing.T) {
	for _, c := range []struct {
		name                  string
		reason                bpf.ReasonCode
		family, typ, protocol int32
	}{
		{"another reason", bpf.ReasonPathUnresolved, unix.AF_INET, unix.SOCK_STREAM, 132},
		{"no reason", bpf.ReasonNone, unix.AF_INET, unix.SOCK_STREAM, 132},
		{"an unknown reason", 250, unix.AF_INET, unix.SOCK_STREAM, 132},
		{"an allowed tcp socket", bpf.ReasonNetNotAllowed, unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_TCP},
		{"a unix socket", bpf.ReasonNetNotAllowed, unix.AF_UNIX, unix.SOCK_DGRAM, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour},
				sockCreateSample(sample{PID: 50, TID: 50, MonoNS: 1, Reason: uint8(c.reason)}, c.family, c.typ, c.protocol))
			lines := sink.byKind(record.KindRefused)
			if len(lines) != 1 || lines[0].Reason != record.ReasonNetNotAllowed || lines[0].Rule != RuleUnmatched {
				t.Fatalf("%+v, want one refused net-not-allowed line", lines)
			}
			if n := gapCount(r.Gaps())[GapMalformedRecord]; n != 1 {
				t.Errorf("%d malformed-record gaps, want 1", n)
			}
		})
	}
}

// TestRecorderDropsAnotherGensSockCreateRecord is ADR 0026 (6) as amended for this record: the program stamps the
// owner's gen, and a scoped recorder writes no line for a record of another generation of its slot, nor of another
// slot.
func TestRecorderDropsAnotherGensSockCreateRecord(t *testing.T) {
	rs := &fakeRunSet{rows: map[uint64]uint32{41: 3}, gens: map[uint64]uint32{41: 7}}
	mine := sample{PID: 50, TID: 50, MonoNS: 1, CgroupID: 41, RunIdx: 3, Gen: 7, Reason: uint8(bpf.ReasonNetNotAllowed)}
	stale, other := mine, mine
	stale.Gen, stale.MonoNS = 6, 2
	other.RunIdx, other.MonoNS = 9, 3
	_, sink := startScoped(t, rs, nil,
		sockCreateSample(stale, unix.AF_INET, unix.SOCK_STREAM, 132),
		sockCreateSample(other, unix.AF_INET, unix.SOCK_STREAM, 132),
		sockCreateSample(mine, unix.AF_INET, unix.SOCK_SEQPACKET, 132),
	)
	lines := sink.byKind(record.KindRefused)
	if len(lines) != 1 {
		t.Fatalf("%d refused lines, want only this run's generation's: %+v", len(lines), lines)
	}
	if p := payload[record.RefusedPayload](t, lines[0]); p.Target != "AF_INET SOCK_SEQPACKET protocol 132" {
		t.Errorf("kept %q, want this generation's SOCK_SEQPACKET line", p.Target)
	}
}

// TestDecodeSockCreate: the record decodes into its triple; a record of another width is refused, and a recorder
// counts it as a malformed record and writes no line.
func TestDecodeSockCreate(t *testing.T) {
	var rec Record
	if err := DecodeInto(&rec, sockCreateSample(sample{PID: 7, Gen: 4}, unix.AF_INET6, unix.SOCK_STREAM, 262)); err != nil {
		t.Fatal(err)
	}
	if rec.Kind != KindSockCreate || rec.Sock.Family != unix.AF_INET6 || rec.Sock.Type != unix.SOCK_STREAM ||
		rec.Sock.Protocol != 262 || rec.Gen != 4 || rec.PID != 7 {
		t.Fatalf("decoded %+v", rec)
	}
	if KindSockCreate.String() != "sock_create" || !KindSockCreate.Valid() || Kind(32).Valid() {
		t.Errorf("kind 28: %s valid %v; kind 32 valid %v", KindSockCreate, KindSockCreate.Valid(), Kind(32).Valid())
	}
	short := sample{Kind: KindSockCreate, Size: SockSize - 4}.bytes(make([]byte, SockSize-4-HeaderSize))
	if err := DecodeInto(&rec, short); !errors.Is(err, ErrShortRecord) {
		t.Errorf("a short sock_create record decoded: %v", err)
	}
	f := newFixture(t)
	r, sink := runRecorder(t, f, Options{FlushInterval: time.Hour}, short)
	if len(sink.all()) != 0 || gapCount(r.Gaps())[GapMalformedRecord] != 1 {
		t.Errorf("a short record: %d lines, gaps %+v", len(sink.all()), r.Gaps())
	}
}
