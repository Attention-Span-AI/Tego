// SPDX-License-Identifier: Apache-2.0

package derive_test

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Two processes of the run each make a model call; the first one's response arrives while the second's is
// still in flight. The decisions the first response carries belong to the first step, but stampDecision asks
// AttributeByTime, which picks the one in-flight thread: the second's.
func TestHardeningDecisionStampedWithOtherThreadsStep(t *testing.T) {
	s := derive.NewSteps()
	s.Apply(sslRequest(100, "api.anthropic.com", "")) // step 1, thread t100
	s.Apply(sslRequest(200, "api.anthropic.com", "")) // step 2, thread t200
	s.Apply(sslResponse(100))                         // t100's answer
	dec := ev(record.KindDecision, 100, record.DecisionPayload{ToolUseID: "toolu_1", Tool: "bash", InputHash: "x"})
	s.Apply(dec)
	var p record.DecisionPayload
	if err := dec.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if p.Step != 1 {
		t.Fatalf("decision from thread t100's response (step 1) stamped step %d", p.Step)
	}
}

// The Host header the uprobe source records is the raw header; Steps compares it byte for byte with the
// contract's models[] host, while the uprobe source's own endpoint()/provider() compare case-insensitively
// with the port stripped. A model request with "Host: api.anthropic.com:443" is parsed and budgeted as
// anthropic traffic but opens no step.
func TestHardeningStepsHostNotNormalised(t *testing.T) {
	s := derive.NewSteps("api.anthropic.com")
	s.Apply(sslRequest(100, "api.anthropic.com:443", ""))
	if s.Count() != 1 {
		t.Fatalf("a model request with a ported Host header opened %d steps", s.Count())
	}
}

// On one thread (Node's event loop, Python asyncio: every request from one tid), the response to a
// non-model TLS request the uprobe source also captures closes the model step still in flight, and the
// next model request opens a new step while the first is outstanding (R33: only if none is already open).
func TestHardeningNonModelResponseClosesModelStep(t *testing.T) {
	s := derive.NewSteps("api.anthropic.com")
	model, other := sslRequest(100, "api.anthropic.com", ""), sslRequest(100, "github.com", "")
	model.Pair, other.Pair = 1, 2 // the pair tokens a capture source puts on both lines of an exchange
	answer := sslResponse(100)
	answer.Pair = 2
	s.Apply(model)                                    // model step 1, in flight
	s.Apply(other)                                    // not a model host: no step
	s.Apply(answer)                                   // github's answer
	s.Apply(sslRequest(100, "api.anthropic.com", "")) // concurrent model call, step 1 still unanswered
	if s.Count() != 1 {
		t.Fatalf("a non-model response closed the open model step: %d steps", s.Count())
	}
}

// A source that gave up on a request (Abandon) leaves the thread not in flight, so the thread's next turn is
// its own step and the stale entry does not unattribute another thread's actions (R33).
func TestStepsAbandonedRequestDoesNotSwallowTheNextTurn(t *testing.T) {
	for _, early := range []bool{false, true} {
		s := derive.NewSteps("api.anthropic.com")
		first := sslRequest(500, "api.anthropic.com", "")
		first.Source, first.Pair = record.SourceSSL, 7
		if early {
			s.Abandon(7) // before the request reaches the stage
		}
		s.Apply(first)
		if !early {
			s.Abandon(7)
		}
		next := sslRequest(500, "api.anthropic.com", "")
		next.Source, next.Pair = record.SourceSSL, 8
		s.Apply(next)
		if got := s.States()["t500"].Step; got != 2 {
			t.Errorf("early=%v: second turn is step %d, want 2", early, got)
		}
		other := sslRequest(501, "api.anthropic.com", "")
		other.Source, other.Pair = record.SourceSSL, 9
		s.Apply(other)
		s.Apply(sslResponse(500))
		act := action(501)
		s.Apply(act)
		if act.Attr.Step != 3 {
			t.Errorf("early=%v: action attributed to step %d, want 3", early, act.Attr.Step)
		}
	}
}

// A burst of abandoned pairs past the bound evicts the oldest one at a time: emptying the whole memory left a
// request still on its way to the stage in flight for good, unattributing every other thread's actions (R33).
func TestStepsAbandonedMemoryEvictsOldestOnly(t *testing.T) {
	s := derive.NewSteps("api.anthropic.com")
	const limit = 4096 // maxPairs
	for pair := uint64(1); pair <= limit+1; pair++ {
		s.Abandon(pair)
	}
	first := sslRequest(500, "api.anthropic.com", "")
	first.Source, first.Pair = record.SourceSSL, limit // still remembered: only pair 1 was evicted
	s.Apply(first)
	next := sslRequest(500, "api.anthropic.com", "")
	next.Source, next.Pair = record.SourceSSL, limit+2
	s.Apply(next)
	if got := s.States()["t500"].Step; got != 2 {
		t.Errorf("second turn is step %d, want 2: the abandoned request was left in flight", got)
	}
}
