// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"encoding/json"
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

// alternateGateLine is the gate metadata and the paths of a delivered open's line.
type alternateGateLine struct {
	Path         string `json:"path"`
	AlternateFor string `json:"alternate_for"`
	FDDelivered  bool   `json:"fd_delivered"`
	Score        *int   `json:"score"`
	GateRule     string `json:"gate_rule"`
	GateOutcome  string `json:"gate_outcome"`
}

func gateLineOf(t *testing.T, ev *record.Event) alternateGateLine {
	t.Helper()
	var p alternateGateLine
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// A file the contract's gate refuses is never an alternate: the agent's own read of keys/x.pem is
// refused fs-gate by `fs.read matches "*.pem"` at 90, so the person naming it for a held read must not hand it over.
// The check at answer time refuses it, naming the gate, and the delivery refuses the open ask-unavailable with
// nothing delivered. Below the refusal threshold the gate does not stop the person's choice.
func TestReadAlternateIsPutToTheGate(t *testing.T) {
	for _, score := range []int{90, 60} {
		x := newAskReadFixture(t)
		x.pol.Rules.Workdir = x.dir
		x.pol.Rules.Gate = testGate(t, gate.ReadMatches, "*.pem", score)
		keys := filepath.Join(x.dir, "keys")
		if err := os.Mkdir(keys, 0o700); err != nil {
			t.Fatal(err)
		}
		pem := filepath.Join(keys, "x.pem")
		if err := os.WriteFile(pem, []byte("GATE-REFUSED-PEM"), 0o600); err != nil {
			t.Fatal(err)
		}
		var check error
		l, sink, asked := x.loop(t, func(req ask.Request) ask.Decision {
			_, check = req.Alternates.Check(altOf(t, pem))
			return alternateDecision(t, pem)
		})
		x.open(t, l, x.secret, unix.O_RDONLY)
		if len(*asked) != 1 {
			t.Fatalf("score %d: asked %d times, want once", score, len(*asked))
		}
		evs := sink.all()
		if score == 90 {
			if check == nil || !strings.Contains(check.Error(), "gate") || !strings.Contains(check.Error(), "gate.rules[0]") {
				t.Fatalf("score 90: the check at answer time said %v; want the gate's refusal, named", check)
			}
			if len(x.k.delivered) != 0 || len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Reason != record.ReasonAskUnavailable {
				t.Fatalf("score 90: delivered %q lines %+v; want the open refused ask-unavailable, nothing delivered", x.k.delivered, evs)
			}
			if res, _ := x.f.lastResp(); res.Error != -int32(unix.EACCES) {
				t.Fatalf("score 90: answered %+v", res)
			}
			continue
		}
		if check != nil || len(x.k.delivered) != 1 || x.k.delivered[0] != "GATE-REFUSED-PEM" || len(evs) != 1 || evs[0].Verdict != record.VerdictAllow {
			t.Fatalf("score 60: check %v delivered %q lines %+v; want the alternate delivered", check, x.k.delivered, evs)
		}
	}
}

// A write alternate is put to the write gate: `fs.write outside worktree` at 90 refuses the agent's
// own write of elsewhere/x, a write entry outside the worktree, so a held fs.ask write answered with that file is
// refused at answer time and at delivery, and the file keeps its bytes (the delivery's O_TRUNC never ran).
func TestWriteAlternateIsPutToTheGate(t *testing.T) {
	x := newAskReadFixture(t)
	proj := filepath.Join(x.dir, "proj")
	scope := filepath.Join(proj, "asked")
	if err := os.MkdirAll(scope, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(scope, "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(x.dir, "elsewhere")
	if err := os.Mkdir(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(elsewhere, "x")
	if err := os.WriteFile(outside, []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	x.pol.Rules.Workdir = proj
	x.pol.Rules.Gate = testGate(t, gate.WriteOutsideWorktree, "", 90)
	x.pol.Rules.FSAsk = []agent.FSRule{{Path: scope, Resolved: scope, Kind: agent.FSAsk, Raw: scope}}
	x.writable(elsewhere)
	var check error
	l, sink, asked := x.loop(t, func(req ask.Request) ask.Decision {
		_, check = req.Alternates.Check(altOf(t, outside))
		return alternateDecision(t, outside)
	})
	x.open(t, l, target, unix.O_WRONLY|unix.O_TRUNC)
	if len(*asked) != 1 {
		t.Fatalf("asked %d times: the target inside the worktree is held, not refused by the gate", len(*asked))
	}
	if check == nil || !strings.Contains(check.Error(), "gate.rules[0]") {
		t.Fatalf("the check at answer time said %v; want the write gate's refusal", check)
	}
	evs := sink.all()
	if len(x.k.delivered) != 0 || len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Reason != record.ReasonAskUnavailable {
		t.Fatalf("delivered %q lines %+v; want the open refused ask-unavailable", x.k.delivered, evs)
	}
	if b, _ := os.ReadFile(outside); string(b) != "ORIGINAL" {
		t.Fatalf("the gate-refused file was opened to write: %q", b)
	}
}

// The delivered alternate's line carries the gate's decision on the file delivered, not the target's: `fs.read
// matches "token"` scores the held target 60 and a stand-in nothing, so the line on the stand-in
// says score 0; `fs.read matches "*.pem"` scores the target nothing and a .pem stand-in 60, so that line says 60 and
// names the rule. Both went through an ask, so gate_outcome is ask.
func TestDeliveredAlternateLineCarriesTheAlternatesGateDecision(t *testing.T) {
	for _, tc := range []struct {
		name, glob, standIn string
		score               int
		rule                string
	}{
		{"the target scored, the stand-in not", "token", "stand-in", 0, ""},
		{"the stand-in scored, the target not", "*.pem", "stand-in.pem", 60, "gate.rules[0]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newAskReadFixture(t)
			x.pol.Rules.Workdir = x.dir
			x.pol.Rules.Gate = testGate(t, gate.ReadMatches, tc.glob, 60)
			standIn := filepath.Join(x.dir, tc.standIn)
			if err := os.WriteFile(standIn, []byte("stand-in"), 0o600); err != nil {
				t.Fatal(err)
			}
			l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return alternateDecision(t, standIn) })
			x.open(t, l, x.secret, unix.O_RDONLY)
			evs := sink.all()
			if len(evs) != 1 || evs[0].Verdict != record.VerdictAllow {
				t.Fatalf("lines %+v; want the delivered alternate's", evs)
			}
			p := gateLineOf(t, evs[0])
			if p.Path != standIn || p.AlternateFor != x.secret || !p.FDDelivered {
				t.Fatalf("the line %s: want the stand-in delivered for the target", evs[0].Payload)
			}
			if p.Score == nil || *p.Score != tc.score || p.GateRule != tc.rule || p.GateOutcome != "ask" {
				t.Fatalf("the line %s: want score %d, gate_rule %q, gate_outcome ask: the gate's decision on the file delivered", evs[0].Payload, tc.score, tc.rule)
			}
		})
	}
}
