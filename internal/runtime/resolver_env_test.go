// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

func TestGuardedResolverEnvPreservesOptions(t *testing.T) {
	rt := &agent.RuleTable{Capture: agent.CaptureForwarder, Contract: &agent.Contract{Models: []agent.ModelEndpoint{{Host: "model.example", Port: 443}}}}
	for _, tc := range []struct {
		name      string
		env, want []string
	}{
		{"absent", []string{"A=1"}, []string{"A=1", "RES_OPTIONS=single-request"}},
		{"existing options", []string{"RES_OPTIONS=rotate timeout:2 attempts:3", "A=1"}, []string{"RES_OPTIONS=rotate timeout:2 attempts:3 single-request", "A=1"}},
		{"already sequential", []string{"RES_OPTIONS=single-request rotate"}, []string{"RES_OPTIONS=single-request rotate"}},
		{"reopen implies sequential", []string{"RES_OPTIONS=timeout:2\tsingle-request-reopen"}, []string{"RES_OPTIONS=timeout:2\tsingle-request-reopen"}},
		{"do not accept a prefix", []string{"RES_OPTIONS=single-request-extra"}, []string{"RES_OPTIONS=single-request-extra single-request"}},
		{"duplicate variable", []string{"RES_OPTIONS=rotate", "A=1", "RES_OPTIONS=single-request-reopen"}, []string{"RES_OPTIONS=rotate single-request", "A=1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := slices.Clone(tc.env)
			got := guardedResolverEnv(rt, backend.TierLandlock, tc.env)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if !slices.Equal(tc.env, before) {
				t.Fatal("mutated source environment")
			}
			if again := guardedResolverEnv(rt, backend.TierLandlock, got); !slices.Equal(again, got) {
				t.Fatalf("not idempotent: %q", again)
			}
		})
	}
}

func TestGuardedResolverEnvScopeAndComposition(t *testing.T) {
	model := []agent.ModelEndpoint{{Host: "model.example", Port: 443}}
	for _, tc := range []struct {
		name    string
		capture agent.CaptureMode
		tier    backend.Tier
		models  []agent.ModelEndpoint
		want    bool
	}{
		{"landlock forwarder", agent.CaptureForwarder, backend.TierLandlock, model, true},
		{"cgroup forwarder", agent.CaptureForwarder, backend.TierCgroup, model, true},
		{"observe", agent.CaptureForwarder, backend.TierObserve, model, false},
		{"uprobe", agent.CaptureUprobe, backend.TierCgroup, model, false},
		{"off", agent.CaptureOff, backend.TierCgroup, model, false},
		{"no models", agent.CaptureForwarder, backend.TierLandlock, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &agent.RuleTable{Capture: tc.capture, Contract: &agent.Contract{Models: tc.models}}
			got := guardedResolverEnv(rt, tc.tier, []string{"A=1"})
			if (lookupEnv(got, "RES_OPTIONS") == "single-request") != tc.want {
				t.Fatalf("got %q", got)
			}
		})
	}
	rt := &agent.RuleTable{Capture: agent.CaptureForwarder, Contract: &agent.Contract{Models: model}, Env: []string{}, Set: map[string]string{"RES_OPTIONS": "attempts:2"}}
	env := guardedResolverEnv(rt, backend.TierLandlock, buildEnv(rt, []string{"RES_OPTIONS=rotate"}))
	if got := lookupEnv(env, "RES_OPTIONS"); got != "attempts:2 single-request" {
		t.Fatalf("env.set preservation = %q", got)
	}
	rt.Deny = []string{"RES_OPTIONS"}
	env = guardedResolverEnv(rt, backend.TierLandlock, buildEnv(rt, []string{"RES_OPTIONS=rotate"}))
	if got := lookupEnv(env, "RES_OPTIONS"); got != "single-request" {
		t.Fatalf("runtime compatibility option after env.deny = %q", got)
	}
}

// TestGatedResolverEnvIsSingleRequest is supervisor-3: a network gate returns ENOSYS to an unaddressed IP
// datagram batch, as the models[] guard does (gate.md R4), and glibc's paired A/AAAA lookup is exactly that
// batch, sent with sendmmsg on its connected UDP socket, with no fallback to individual sends. The shim
// keyed on guarded models only, so a gated run with capture uprobe or off, or with no models[], had every
// getaddrinfo(AF_UNSPEC) fail "Temporary failure in name resolution". A run whose gate scores network
// actions gets single-request whatever its capture; one whose gate scores none keeps its environment.
func TestGatedResolverEnvIsSingleRequest(t *testing.T) {
	model := []agent.ModelEndpoint{{Host: "model.example", Port: 443}}
	policy := func(p gate.Predicate, arg string, score int) *gate.Policy {
		g, err := gate.New([]gate.Rule{{Predicate: p, Argument: arg, Score: score}}, 50, 80)
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	netTo := policy(gate.NetTo, "93.184.216.34:443", 90)
	undeclared := policy(gate.NetUndeclared, "", 30)
	readOnly := policy(gate.ReadMatches, "*.env", 90)
	for _, tc := range []struct {
		name    string
		capture agent.CaptureMode
		tier    backend.Tier
		models  []agent.ModelEndpoint
		g       *gate.Policy
		want    bool
	}{
		{"landlock net gate no models", agent.CaptureForwarder, backend.TierLandlock, nil, netTo, true},
		{"cgroup uprobe net gate", agent.CaptureUprobe, backend.TierCgroup, model, netTo, true},
		{"bpflsm uprobe undeclared gate", agent.CaptureUprobe, backend.TierBPFLSM, model, undeclared, true},
		{"cgroup off undeclared gate", agent.CaptureOff, backend.TierCgroup, nil, undeclared, true},
		{"fs gate only", agent.CaptureUprobe, backend.TierCgroup, model, readOnly, false},
		{"observe", agent.CaptureUprobe, backend.TierObserve, nil, netTo, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &agent.RuleTable{Capture: tc.capture, Gate: tc.g, Contract: &agent.Contract{Models: tc.models}}
			got := guardedResolverEnv(rt, tc.tier, []string{"A=1", "RES_OPTIONS=rotate"})
			if (lookupEnv(got, "RES_OPTIONS") == "rotate single-request") != tc.want {
				t.Fatalf("got %q, want single-request %t", got, tc.want)
			}
		})
	}
}
