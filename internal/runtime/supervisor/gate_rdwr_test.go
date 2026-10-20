// SPDX-License-Identifier: Apache-2.0
//go:build amd64 || arm64

package supervisor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestGateReadMatchesScoresAReadingWriteOpen: gateFS scored an open carrying a write
// flag with the fs.write predicates alone and returned early when the gate had none, so under `fs.read matches
// "*.pem": 90` the agent's O_RDONLY open of out/x.pem was refused fs-gate while os.open("out/x.pem", O_RDWR), beneath
// a write entry, was continued and read the bytes, its line carrying no gate fields. A write open whose access mode
// reads (O_RDWR, or O_RDONLY with O_CREAT or O_TRUNC) hands the agent the file's bytes, so it is scored with the read
// predicates as well, the two kinds' scores summed (ADR 0007, 2026-10-20), as a move's source is (gate.md R1). An
// O_WRONLY open reads nothing.
func TestGateReadMatchesScoresAReadingWriteOpen(t *testing.T) {
	const pathAddr = 0x10000
	fs := []agent.FSRule{{Path: "/work", Kind: agent.FSWrite}}
	for _, tc := range []struct {
		name    string
		path    string
		flags   int
		refused bool
	}{
		{"read-write open of a matching name", "/work/out/x.pem", unix.O_RDWR, true},
		{"read-write create of a matching name", "/work/out/x.pem", unix.O_RDWR | unix.O_CREAT, true},
		{"read-only truncating open of a matching name", "/work/out/x.pem", unix.O_RDONLY | unix.O_TRUNC, true},
		{"read-only open of a matching name", "/work/out/x.pem", unix.O_RDONLY, true},
		{"write-only open of a matching name", "/work/out/x.pem", unix.O_WRONLY | unix.O_TRUNC, false},
		{"read-write open of another name", "/work/out/x.txt", unix.O_RDWR, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(pathAddr, cstr(tc.path))
			pol := testPolicy(nil, fs, nil)
			pol.Rules.Workdir = "/work"
			pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.pem", 90)
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, pathAddr, uint64(tc.flags)))
			got, _ := f.lastResp()
			ev := sink.one(t)
			if !tc.refused {
				if got.Flags == 0 || ev.Verdict == record.VerdictRefused {
					t.Fatalf("response %+v line %+v; want continued", got, ev)
				}
				return
			}
			if got.Flags != 0 || got.Error != -int32(refusalErrno) {
				t.Fatalf("response %+v; want the gate's refusal", got)
			}
			if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonFSGate || ev.Authority != record.AuthorityGate {
				t.Fatalf("line %+v; want refused fs-gate under the gate's authority", ev)
			}
			if p := gateLineOf(t, ev); p.Score == nil || *p.Score != 90 || p.GateRule != "gate.rules[0]" || p.GateOutcome != "refused" {
				t.Fatalf("line %s; want the read predicate's score 90 on it", ev.Payload)
			}
		})
	}
}

// An allowed O_RDWR open whose read score lies in the ask range is held for a person, as a read-open of the same
// file is: before, a gate with no fs.write rule never held it and the open was continued.
func TestGateReadAskHoldsAReadingWriteOpen(t *testing.T) {
	x := newAskReadFixture(t)
	x.pol.Rules.Workdir = x.dir
	x.pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.pem", 60)
	out := filepath.Join(x.dir, "out")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	pem := filepath.Join(out, "x.pem")
	if err := os.WriteFile(pem, []byte("GATE-ASKED-PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	x.writable(out)
	l, sink, asked := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{Reason: ask.ReasonDenied, By: "uid:1 pid:2"} })
	x.open(t, l, pem, unix.O_RDWR)
	if len(*asked) != 1 || (*asked)[0].GateRule != "gate.rules[0]" {
		t.Fatalf("asked %+v; want the read gate's ask, once", *asked)
	}
	evs := sink.all()
	if len(x.k.delivered) != 0 || len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Reason != record.ReasonAskDenied {
		t.Fatalf("delivered %q lines %+v; want the denied open refused", x.k.delivered, evs)
	}
}

// A held fs.ask write opened O_RDWR is put to the read gate too, on the held target and on a write alternate: the
// target asked/x.pem is refused fs-gate without asking anyone, and a held O_RDWR write
// answered with out/x.pem, a file the agent's own read is refused, is refused at answer time and at delivery.
func TestReadingHeldWriteIsPutToTheReadGate(t *testing.T) {
	for _, alternate := range []bool{false, true} {
		x := newAskReadFixture(t)
		scope := filepath.Join(x.dir, "asked")
		out := filepath.Join(x.dir, "out")
		for _, d := range []string{scope, out} {
			if err := os.Mkdir(d, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		target, pem := filepath.Join(scope, "target"), filepath.Join(out, "x.pem")
		if !alternate {
			target = filepath.Join(scope, "x.pem")
		}
		for _, p := range []string{target, pem} {
			if err := os.WriteFile(p, []byte("GATE-REFUSED-PEM"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		x.pol.Rules.Workdir = x.dir
		x.pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.pem", 90)
		x.pol.Rules.FSAsk = []agent.FSRule{{Path: scope, Resolved: scope, Kind: agent.FSAsk, Raw: scope}}
		x.writable(out)
		var check error
		l, sink, asked := x.loop(t, func(req ask.Request) ask.Decision {
			_, check = req.Alternates.Check(altOf(t, pem))
			return alternateDecision(t, pem)
		})
		x.open(t, l, target, unix.O_RDWR)
		evs := sink.all()
		if !alternate {
			if len(*asked) != 0 || len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Reason != record.ReasonFSGate {
				t.Fatalf("target: asked %d lines %+v; want the target refused fs-gate, no one asked", len(*asked), evs)
			}
			continue
		}
		if len(*asked) != 1 {
			t.Fatalf("alternate: asked %d times; want the unscored target held once", len(*asked))
		}
		if check == nil || !strings.Contains(check.Error(), "gate.rules[0]") {
			t.Fatalf("alternate: the check at answer time said %v; want the read gate's refusal", check)
		}
		if len(x.k.delivered) != 0 || len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Reason != record.ReasonAskUnavailable {
			t.Fatalf("alternate: delivered %q lines %+v; want the open refused ask-unavailable", x.k.delivered, evs)
		}
	}
}
