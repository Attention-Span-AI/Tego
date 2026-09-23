// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestAttributeStageFollowsCapture pins which attribution method a run uses and why. With nothing
// capturing there is no turn structure to derive from, so method none is the honest label: no
// attribution was attempted. With a capture source running, derive.Steps is installed and the method
// becomes time, which is P0-DESIGN §5's M1 to M2 step.
func TestAttributeStageFollowsCapture(t *testing.T) {
	t.Run("no sources means method none", func(t *testing.T) {
		r := newTestRunner(Deps{})
		r.rt = &agent.RuleTable{}
		if got := r.attributeStage(); got != nil {
			t.Error("a run with nothing to derive from installed a derivation stage")
		}
		if r.steps != nil {
			t.Error("step tracking was started for a run with no model traffic")
		}
	})

	t.Run("a capture source installs step derivation", func(t *testing.T) {
		r := newTestRunner(Deps{Capture: []source.Source{&plainSource{name: "forwarder"}}})
		r.rt = &agent.RuleTable{}
		stage := r.attributeStage()
		if stage == nil || r.steps == nil {
			t.Fatal("a capturing run did not install step derivation")
		}

		// One request opens a step; an action on the same thread while the response is outstanding
		// belongs to it.
		var out []*record.Event
		handle := stage(func(ev *record.Event) { out = append(out, ev) })
		req := &record.Event{Kind: record.KindSSLRequest, Source: record.SourceForwarder, PID: 7, TID: 7}
		if err := req.SetPayload(record.SSLRequestPayload{Host: "api.example.com", Method: "POST"}); err != nil {
			t.Fatal(err)
		}
		handle(req)
		act := &record.Event{Kind: record.KindFS, Source: record.SourceSeccomp, PID: 7, TID: 7,
			Rule: "fs.write[./out]", Verdict: record.VerdictAllow, Authority: record.AuthorityRule}
		if err := act.SetPayload(record.FSPayload{Op: record.FSOpen, Path: "/w/out/a"}); err != nil {
			t.Fatal(err)
		}
		handle(act)

		if len(out) != 2 {
			t.Fatalf("%d events reached the next stage, want 2", len(out))
		}
		if act.Attr == nil {
			t.Fatal("the action reached the ledger unattributed by any method")
		}
		if act.Attr.Method != record.MethodTime {
			t.Errorf("method %q, want %q", act.Attr.Method, record.MethodTime)
		}
		if act.Attr.Step != 1 {
			t.Errorf("step %d, want the one the request opened", act.Attr.Step)
		}
		if r.steps.Count() != 1 {
			t.Errorf("the run opened %d steps, want 1", r.steps.Count())
		}
	})
}

// TestModelHostsReadsTheContract covers what decides which requests open a step.
func TestModelHostsReadsTheContract(t *testing.T) {
	if got := modelHosts(nil); got != nil {
		t.Errorf("modelHosts(nil) = %v", got)
	}
	if got := modelHosts(&agent.RuleTable{}); got != nil {
		t.Errorf("a table with no contract gave %v", got)
	}
	rt := &agent.RuleTable{Contract: &agent.Contract{Models: []agent.ModelEndpoint{
		{Provider: "anthropic", Host: "api.anthropic.com", Port: 443},
		{Provider: "other", Host: "", Port: 443}, // an entry with no host contributes nothing
	}}}
	got := modelHosts(rt)
	if len(got) != 1 || got[0] != "api.anthropic.com" {
		t.Errorf("modelHosts = %v, want the one declared host", got)
	}
}

// TestAttributeStageFollowsExits is P8's wiring: with a kernel record running, the attribute stage is handed
// its process exits and retires an exited process's threads, so a run holds its live threads and not every
// thread it ever saw. With no recorder there is nothing to hand it, and the stage still derives steps.
func TestAttributeStageFollowsExits(t *testing.T) {
	request := func(pid, tid int) *record.Event {
		ev := &record.Event{Kind: record.KindSSLRequest, Source: record.SourceSSL, PID: pid, TID: tid}
		if err := ev.SetPayload(record.SSLRequestPayload{Host: "api.example.com", Method: "POST"}); err != nil {
			t.Fatal(err)
		}
		return ev
	}
	rec := &streamSource{plainSource: plainSource{name: "observe"}}
	r := newTestRunner(Deps{
		Capture:        []source.Source{&plainSource{name: "uprobe"}},
		ObserveFactory: func(string) (source.Source, error) { return rec, nil },
	})
	r.rt = &agent.RuleTable{}
	r.startKernelRecord(tier2Handle{hash: "deadbeef"})
	t.Cleanup(r.closeHookQueues)
	stage := r.attributeStage()
	if stage == nil || r.steps == nil {
		t.Fatal("a capturing run did not install step derivation")
	}
	handle := stage(func(*record.Event) {})
	handle(request(7, 7))
	handle(&record.Event{Kind: record.KindSSLResponse, Source: record.SourceSSL, PID: 7, TID: 7})
	handle(request(8, 9))
	if len(r.steps.States()) != 2 {
		t.Fatalf("states %v, want both threads", r.steps.States())
	}
	var exits []source.ProcessHook
	for _, h := range rec.hooks {
		if _, ok := h.(exitsTo); ok {
			exits = append(exits, h)
		}
	}
	if len(exits) != 1 {
		t.Fatalf("recorder hooks %v, want the attribute stage's exits once", rec.hooks)
	}
	exits[0].OnExit(7)
	states := r.steps.States()
	if _, ok := states["t7"]; ok || len(states) != 1 {
		t.Errorf("states %v after pid 7 exited, want only t9", states)
	}

	t.Run("no recorder", func(t *testing.T) {
		r := newTestRunner(Deps{Capture: []source.Source{&plainSource{name: "forwarder"}}})
		r.rt = &agent.RuleTable{}
		if r.attributeStage() == nil || r.steps == nil {
			t.Fatal("a capturing run with no recorder did not install step derivation")
		}
	})
}
