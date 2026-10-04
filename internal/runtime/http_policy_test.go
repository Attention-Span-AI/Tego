// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/policy/httppolicy"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

type policySource struct {
	plainSource
	policy *httppolicy.Policy
	ready  bool
}

func TestProxyConstructorRejectsUncompiledPolicyAndOpaqueModelBudgets(t *testing.T) {
	c := &agent.Contract{Name: "proxy", Capture: agent.CaptureForwarder, Models: []agent.ModelEndpoint{{Host: "h", Port: 443}}, Net: &agent.NetSection{Proxy: &agent.ProxyPolicy{Connect: []string{"h:443"}}}}
	rt := &agent.RuleTable{Contract: c, Capture: agent.CaptureForwarder}
	deps := Deps{Config: &config.Machine{}, Enforce: tierBackend{tier: backend.TierLandlock}}
	if _, err := newRunner(rt, []string{"x"}, deps); err == nil {
		t.Fatal("uncompiled proxy policy accepted")
	}
	p, err := agent.CompileProxyPolicy(c)
	if err != nil {
		t.Fatal(err)
	}
	rt.Proxy = p
	rt.Limits.Set = agent.BudgetCostUSD
	if _, err := newRunner(rt, []string{"x"}, deps); err == nil || !strings.Contains(err.Error(), "cannot enforce model") {
		t.Fatalf("constructor accepted opaque budget: %v", err)
	}
	r := newTestRunner(deps)
	r.rt = rt
	if err := r.requireHTTPPolicy(); err == nil || !strings.Contains(err.Error(), "cannot enforce model") {
		t.Fatalf("runtime readiness ignored opaque budget: %v", err)
	}
}

func (s *policySource) HTTPPolicyReady(p *httppolicy.Policy) bool { return s.ready && s.policy == p }

func TestHTTPPolicyStartedSourceGateAndCapability(t *testing.T) {
	p, err := httppolicy.Compile([]httppolicy.Rule{{Host: "h", Port: 443, Allow: []string{"/"}}})
	if err != nil {
		t.Fatal(err)
	}
	other, err := httppolicy.Compile([]httppolicy.Rule{{Host: "h", Port: 443, Allow: []string{"/"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		sources []source.Source
		tier    backend.Tier
		want    bool
	}{
		{"missing", nil, backend.TierLandlock, false},
		{"capture-only", []source.Source{&plainSource{name: "forwarder"}}, backend.TierLandlock, false},
		{"not-started", []source.Source{&policySource{plainSource{name: "forwarder"}, p, false}}, backend.TierLandlock, false},
		{"different-policy", []source.Source{&policySource{plainSource{name: "forwarder"}, other, true}}, backend.TierLandlock, false},
		{"wrong-mechanism", []source.Source{&policySource{plainSource{name: "uprobe"}, p, true}}, backend.TierLandlock, false},
		{"observe", []source.Source{&policySource{plainSource{name: "forwarder"}, p, true}}, backend.TierObserve, false},
		{"active", []source.Source{&policySource{plainSource{name: "forwarder"}, p, true}}, backend.TierLandlock, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRunner(Deps{Enforce: tierBackend{tier: tc.tier}})
			r.rt = &agent.RuleTable{HTTP: p, Capture: agent.CaptureForwarder}
			r.sources = tc.sources
			if got := r.httpPolicyReady(); got != tc.want {
				t.Fatalf("ready=%v", got)
			}
			if got := r.capabilityLine("forwarder")[string(backend.CapNetHTTPRules)]; got != tc.want {
				t.Fatalf("capability=%v", got)
			}
			if (r.requireHTTPPolicy() == nil) != tc.want {
				t.Fatal("unready policy source released child")
			}
		})
	}
}

func TestHTTPPolicyConstructorRejectsObserveAndMissingCompilation(t *testing.T) {
	c := &agent.Contract{Name: "h", Capture: agent.CaptureForwarder, Net: &agent.NetSection{HTTP: []agent.HTTPRule{{Host: "h", Allow: []string{"/"}}}}}
	rt := &agent.RuleTable{Contract: c, Capture: agent.CaptureForwarder}
	deps := Deps{Config: &config.Machine{}, Enforce: tierBackend{tier: backend.TierLandlock}}
	if _, err := newRunner(rt, []string{"x"}, deps); err == nil {
		t.Fatal("uncompiled declared policy accepted")
	}
	rt.HTTP, _ = httppolicy.Compile([]httppolicy.Rule{{Host: "h", Port: 443, Allow: []string{"/"}}})
	deps.Enforce = tierBackend{tier: backend.TierObserve}
	if _, err := newRunner(rt, []string{"x"}, deps); err == nil {
		t.Fatal("observe downgrade accepted")
	}
}

func TestHTTPPolicyRefusalUsesExistingReasonPipeline(t *testing.T) {
	sink := &collectSink{}
	p := testPipeline(t, NewQueue(4), sink)
	ev := &record.Event{Kind: record.KindNet, Source: record.SourceForwarder, Verdict: record.VerdictRefused, Reason: record.ReasonNetHTTP, Rule: agent.UnmatchedRule, Authority: record.AuthorityRule, PID: 123}
	ev.V, ev.TS, ev.Run, ev.Agent = record.Version, time.Unix(1, 0), "run", "h"
	if err := ev.SetPayload(record.NetPayload{Op: "http_request", Proto: "http", Dst: "h:443", HTTPAuthority: "h:443", Method: "POST", Path: "/denied"}); err != nil {
		t.Fatal(err)
	}
	p.handle(ev)
	got := sink.all()
	if len(got) != 2 || got[0].Kind != record.KindNet || got[1].Kind != record.KindRefused || got[1].Reason != record.ReasonNetHTTP {
		t.Fatalf("missing action/refusal companion: %+v", got)
	}
	for _, ev := range got {
		if strings.Contains(string(ev.Payload), "/denied") {
			t.Fatalf("pipeline persisted private HTTP resource path: %s", ev.Payload)
		}
		if err := ev.Validate(); err != nil {
			t.Fatalf("HTTP pipeline payload not valid: %v", err)
		}
	}
}
