// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"net/netip"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestEvaluateRefusesAModelEndpointWithNoNetSection is SEMANTICS §1's exception to "no net: — deny
// nothing": under capture: forwarder a direct connection to a declared models[] endpoint is refused, because
// the forwarder is the only capture there is (capture-derive R38). With no net: section, Evaluate answered
// allow/unmatched for it, the supervisor continued it, and kt2's forwarder half reached the model stand-in
// straight past the forwarder in every tier. Every other destination stays allowed; a net: section and the
// other capture modes are unchanged.
func TestEvaluateRefusesAModelEndpointWithNoNetSection(t *testing.T) {
	f := newFixture(t)
	const models = "models:\n  - { provider: anthropic, host: api.anthropic.com, port: 443 }\n" +
		"  - { provider: openai, host: \"127.0.0.1\", port: 8443 }\n  - { provider: local, host: \"[::1]\", port: 9443 }\n"
	rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\ncapture: forwarder\n" + models))
	if rt.Capture != CaptureForwarder || !rt.NetUnrestricted() {
		t.Fatalf("compiled capture %s, net unrestricted %v; want forwarder with no net: section", rt.Capture, rt.NetUnrestricted())
	}
	if got := rt.GuardedModels(); len(got) != 3 {
		t.Fatalf("GuardedModels = %+v, want the three models[] entries", got)
	}
	for _, tc := range []struct {
		name string
		a    Action
		want EvalResult
	}{
		{"the model host by name", Action{Kind: ActionNetConnect, Host: "api.anthropic.com", Port: 443},
			EvalResult{Verdict: VerdictRefused, Rule: "models[api.anthropic.com:443]", Reason: record.ReasonNetNotAllowed}},
		{"the model host by name, another case", Action{Kind: ActionNetConnect, Host: "API.Anthropic.com", Port: 443},
			EvalResult{Verdict: VerdictRefused, Rule: "models[api.anthropic.com:443]", Reason: record.ReasonNetNotAllowed}},
		{"the model host over UDP (QUIC)", Action{Kind: ActionNetConnect, Host: "api.anthropic.com", Port: 443, Proto: "udp"},
			EvalResult{Verdict: VerdictRefused, Rule: "models[api.anthropic.com:443]", Reason: record.ReasonNetNotAllowed}},
		{"a literal model address", Action{Kind: ActionNetConnect, Host: "127.0.0.1", Port: 8443},
			EvalResult{Verdict: VerdictRefused, Rule: "models[127.0.0.1:8443]", Reason: record.ReasonNetNotAllowed}},
		{"a literal model address, v4-mapped", Action{Kind: ActionNetConnect, Host: "::ffff:127.0.0.1", Port: 8443},
			EvalResult{Verdict: VerdictRefused, Rule: "models[127.0.0.1:8443]", Reason: record.ReasonNetNotAllowed}},
		{"an IPv6 model address", Action{Kind: ActionNetConnect, Host: "::1", Port: 9443},
			EvalResult{Verdict: VerdictRefused, Rule: "models[[::1]:9443]", Reason: record.ReasonNetNotAllowed}},
		// The kernel sends a connection to the unspecified address to loopback (ip_route_connect,
		// tcp_v6_connect), and a server bound to all interfaces answers on every loopback address, so a
		// loopback endpoint is refused under each of those spellings too. 0.0.0.0:<port> is what local model
		// servers print; with it the agent reached kt2's stand-in around the forwarder.
		{"the unspecified address on a loopback model's port", Action{Kind: ActionNetConnect, Host: "0.0.0.0", Port: 8443},
			EvalResult{Verdict: VerdictRefused, Rule: "models[127.0.0.1:8443]", Reason: record.ReasonNetNotAllowed}},
		{"the unspecified address, v4-mapped", Action{Kind: ActionNetConnect, Host: "::ffff:0.0.0.0", Port: 8443},
			EvalResult{Verdict: VerdictRefused, Rule: "models[127.0.0.1:8443]", Reason: record.ReasonNetNotAllowed}},
		{"the IPv6 unspecified address", Action{Kind: ActionNetConnect, Host: "::", Port: 9443},
			EvalResult{Verdict: VerdictRefused, Rule: "models[[::1]:9443]", Reason: record.ReasonNetNotAllowed}},
		{"the IPv6 unspecified address, bracketed", Action{Kind: ActionNetConnect, Host: "[::]", Port: 9443},
			EvalResult{Verdict: VerdictRefused, Rule: "models[[::1]:9443]", Reason: record.ReasonNetNotAllowed}},
		{"another loopback address", Action{Kind: ActionNetConnect, Host: "127.0.0.2", Port: 8443},
			EvalResult{Verdict: VerdictRefused, Rule: "models[127.0.0.1:8443]", Reason: record.ReasonNetNotAllowed}},
		{"IPv6 loopback on an IPv4 loopback model's port", Action{Kind: ActionNetConnect, Host: "::1", Port: 8443},
			EvalResult{Verdict: VerdictRefused, Rule: "models[127.0.0.1:8443]", Reason: record.ReasonNetNotAllowed}},
		{"localhost on a loopback model's port", Action{Kind: ActionNetConnect, Host: "localhost", Port: 8443},
			EvalResult{Verdict: VerdictRefused, Rule: "models[127.0.0.1:8443]", Reason: record.ReasonNetNotAllowed}},
		{"the unspecified address on another port", Action{Kind: ActionNetConnect, Host: "0.0.0.0", Port: 8080},
			EvalResult{Verdict: VerdictAllow, Rule: UnmatchedRule}},
		// Another address on a loopback model's port could be one of this host's own (a LAN or bridge
		// address), which reaches a model server bound to all interfaces as loopback does; Evaluate cannot
		// tell, so it answers as it does for a named endpoint (LEFT-F3). It used to answer allow.
		{"another address on a loopback model's port", Action{Kind: ActionNetConnect, Host: "192.0.2.7", Port: 8443},
			EvalResult{Verdict: VerdictRefused, Rule: UnresolvedRule, Reason: record.ReasonNetNotAllowed}},
		{"another host by name on a loopback model's port", Action{Kind: ActionNetConnect, Host: "example.com", Port: 8443},
			EvalResult{Verdict: VerdictAllow, Rule: UnmatchedRule}},
		// Nothing resolved api.anthropic.com into the table, so an address on its port could be it: the
		// answer E18/E19 give a literal only an unresolved entry could match, never a guessed allow.
		{"an address on a named model's port", Action{Kind: ActionNetConnect, Host: "160.79.104.10", Port: 443},
			EvalResult{Verdict: VerdictRefused, Rule: UnresolvedRule, Reason: record.ReasonNetNotAllowed}},
		{"the model address on another port", Action{Kind: ActionNetConnect, Host: "127.0.0.1", Port: 8080},
			EvalResult{Verdict: VerdictAllow, Rule: UnmatchedRule}},
		// With no net: section another name on the model's port is not refused (SEMANTICS §1, amended
		// 2026-10-05): the 2026-10-01 port reservation refused github.com:443, pypi.org:443 and every other
		// HTTPS host of a contract that declares no network policy at all.
		{"another host on the model's port", Action{Kind: ActionNetConnect, Host: "github.com", Port: 443},
			EvalResult{Verdict: VerdictAllow, Rule: UnmatchedRule}},
		// No net: section and no host_sockets: true: the unix-only state refuses a socket the run did not bind (ADR 0070).
		{"a unix socket", Action{Kind: ActionNetConnect, Path: "/run/user/1000/bus"},
			EvalResult{Verdict: VerdictRefused, Rule: HostSocketsRule, Reason: record.ReasonNetNotAllowed}},
		// The run guards every IP socket, raw ones included (the supervisor's decideGuarded), so Evaluate
		// guards every protocol but unix: it answered allow/unmatched for these while the run refused them.
		{"a raw datagram to the model address", Action{Kind: ActionNetConnect, Host: "127.0.0.1", Port: 8443, Proto: "raw"},
			EvalResult{Verdict: VerdictRefused, Rule: "models[127.0.0.1:8443]", Reason: record.ReasonNetNotAllowed}},
		{"an icmp send to the model address", Action{Kind: ActionNetConnect, Host: "127.0.0.1", Port: 8443, Proto: "icmp"},
			EvalResult{Verdict: VerdictRefused, Rule: "models[127.0.0.1:8443]", Reason: record.ReasonNetNotAllowed}},
		{"a raw datagram to the model host by name", Action{Kind: ActionNetConnect, Host: "api.anthropic.com", Port: 443, Proto: "RAW"},
			EvalResult{Verdict: VerdictRefused, Rule: "models[api.anthropic.com:443]", Reason: record.ReasonNetNotAllowed}},
		{"a raw datagram elsewhere", Action{Kind: ActionNetConnect, Host: "127.0.0.1", Port: 8080, Proto: "raw"},
			EvalResult{Verdict: VerdictAllow, Rule: UnmatchedRule}},
	} {
		for _, tier := range enforcingTiers() {
			if got := rt.Evaluate(tc.a, tier); got != tc.want {
				t.Errorf("%s, tier %s: %+v = %+v, want %+v", tc.name, tier, tc.a, got, tc.want)
			}
		}
	}
	// A localhost name is loopback (RFC 6761 §6.3) without a lookup: it guards the loopback and unspecified
	// addresses on its port by its own rule; another address there could be one of this host's, so it is
	// refused unresolved, and another name is allowed.
	rt, _ = f.compile(f.load("version: 0\nname: a\ncommand: [python]\ncapture: forwarder\n" +
		"models:\n  - { provider: local, host: localhost, port: 8000 }\n"))
	for _, tc := range []struct {
		host string
		want EvalResult
	}{
		{"localhost", EvalResult{Verdict: VerdictRefused, Rule: "models[localhost:8000]", Reason: record.ReasonNetNotAllowed}},
		{"127.0.0.1", EvalResult{Verdict: VerdictRefused, Rule: "models[localhost:8000]", Reason: record.ReasonNetNotAllowed}},
		{"0.0.0.0", EvalResult{Verdict: VerdictRefused, Rule: "models[localhost:8000]", Reason: record.ReasonNetNotAllowed}},
		{"::", EvalResult{Verdict: VerdictRefused, Rule: "models[localhost:8000]", Reason: record.ReasonNetNotAllowed}},
		{"app.localhost", EvalResult{Verdict: VerdictRefused, Rule: "models[localhost:8000]", Reason: record.ReasonNetNotAllowed}},
		{"192.0.2.7", EvalResult{Verdict: VerdictRefused, Rule: UnresolvedRule, Reason: record.ReasonNetNotAllowed}},
		{"example.com", EvalResult{Verdict: VerdictAllow, Rule: UnmatchedRule}},
	} {
		if got := rt.Evaluate(Action{Kind: ActionNetConnect, Host: tc.host, Port: 8000}, backend.TierLandlock); got != tc.want {
			t.Errorf("models[localhost:8000]: %s:8000 = %+v, want %+v", tc.host, got, tc.want)
		}
	}
	// An endpoint on one of this host's other addresses (the model server's LAN address, say): the unspecified
	// address reaches it from a socket bound to that address, since the kernel sends such a connect to the
	// bound source, and it never leaves the host, so it matches every guarded endpoint on its port. Loopback
	// reaches the same server when it is bound to all interfaces, which Evaluate cannot rule out.
	rt, _ = f.compile(f.load("version: 0\nname: a\ncommand: [python]\ncapture: forwarder\n" +
		"models:\n  - { provider: local, host: \"192.0.2.9\", port: 7000 }\n"))
	for _, tc := range []struct {
		host string
		want EvalResult
	}{
		{"192.0.2.9", EvalResult{Verdict: VerdictRefused, Rule: "models[192.0.2.9:7000]", Reason: record.ReasonNetNotAllowed}},
		{"0.0.0.0", EvalResult{Verdict: VerdictRefused, Rule: "models[192.0.2.9:7000]", Reason: record.ReasonNetNotAllowed}},
		{"::", EvalResult{Verdict: VerdictRefused, Rule: "models[192.0.2.9:7000]", Reason: record.ReasonNetNotAllowed}},
		{"127.0.0.1", EvalResult{Verdict: VerdictRefused, Rule: UnresolvedRule, Reason: record.ReasonNetNotAllowed}},
	} {
		if got := rt.Evaluate(Action{Kind: ActionNetConnect, Host: tc.host, Port: 7000}, backend.TierLandlock); got != tc.want {
			t.Errorf("models[192.0.2.9:7000]: %s:7000 = %+v, want %+v", tc.host, got, tc.want)
		}
	}
	if got := rt.Evaluate(Action{Kind: ActionNetConnect, Host: "0.0.0.0", Port: 7001}, backend.TierLandlock); got.Verdict != VerdictAllow {
		t.Errorf("the unspecified address on another port = %+v, want allow", got)
	}
	rt, _ = f.compile(f.load("version: 0\nname: a\ncommand: [python]\ncapture: forwarder\n" + models))

	// An observe run enforces nothing, the guard included.
	if got := rt.Evaluate(Action{Kind: ActionNetConnect, Host: "127.0.0.1", Port: 8443}, backend.TierObserve); got.Verdict != VerdictAllow {
		t.Errorf("observe: the model address = %+v, want allow", got)
	}

	// No guard where another mechanism captures or nothing does, or where a net: section decides.
	for _, tc := range []struct{ name, yaml string }{
		{"capture: uprobe", "capture: uprobe\n"},
		{"capture: off", "capture: off\n"},
	} {
		rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\ntier: cgroup\n" + tc.yaml + models))
		if got := rt.Evaluate(Action{Kind: ActionNetConnect, Host: "127.0.0.1", Port: 8443}, backend.TierCgroup); got.Verdict != VerdictAllow || got.Rule != UnmatchedRule {
			t.Errorf("%s: the model address = %+v, want allow/unmatched", tc.name, got)
		}
	}
	rt, _ = f.compile(f.load("version: 0\nname: a\ncommand: [python]\ncapture: forwarder\nnet:\n  allow: [\"127.0.0.1:8443\"]\n" + models))
	if got := rt.Evaluate(Action{Kind: ActionNetConnect, Host: "127.0.0.1", Port: 8443}, backend.TierLandlock); got.Verdict != VerdictRefused || got.Rule != "models[127.0.0.1:8443]" {
		t.Errorf("a model endpoint net.allow names = %+v, want refused by the forwarder boundary", got)
	}
	if got := rt.GuardedModels(); len(got) != 3 {
		t.Errorf("GuardedModels under a net: section = %+v, want all models guarded", got)
	}
	rt, _ = f.compile(f.load("version: 0\nname: a\ncommand: [python]\ncapture: forwarder\nnet: {}\n" + models))
	if got := rt.Evaluate(Action{Kind: ActionNetConnect, Host: "127.0.0.1", Port: 8443}, backend.TierLandlock); got.Verdict != VerdictRefused || got.Rule != "models[127.0.0.1:8443]" {
		t.Errorf("net: {} = %+v, want refused by the model guard", got)
	}
}

// TestGuardAddrMatches pins the predicate Evaluate and the supervisor's guard share: an address matches itself
// in either spelling, loopback matches loopback, and the unspecified address matches every endpoint, because
// the kernel sends it to this host (loopback, or the socket's bound source) and it never leaves the host.
// Another address matches only itself: whether it is one of this host's is the run's to count (LEFT-F3).
func TestGuardAddrMatches(t *testing.T) {
	for _, tc := range []struct {
		dst, ep string
		want    bool
	}{
		{"127.0.0.1", "127.0.0.1", true},
		{"::ffff:127.0.0.1", "127.0.0.1", true},
		{"127.0.0.2", "127.0.0.1", true},
		{"::1", "127.0.0.1", true},
		{"0.0.0.0", "127.0.0.1", true},
		{"0.0.0.0", "192.0.2.9", true},
		{"::", "192.0.2.9", true},
		{"::ffff:0.0.0.0", "2001:db8::9", true},
		{"192.0.2.9", "192.0.2.9", true},
		{"127.0.0.1", "192.0.2.9", false},
		{"192.0.2.7", "127.0.0.1", false},
		{"192.0.2.7", "192.0.2.9", false},
	} {
		if got := GuardAddrMatches(netip.MustParseAddr(tc.dst), netip.MustParseAddr(tc.ep)); got != tc.want {
			t.Errorf("GuardAddrMatches(%s, %s) = %v, want %v", tc.dst, tc.ep, got, tc.want)
		}
	}
}

// A named model's port is reserved to the forwarder only under a net: section, where an undeclared destination
// net.allow does not admit is refused models.port rather than unmatched. With no net: section the port is not
// reserved (SEMANTICS §1, amended 2026-10-05): another name there is allowed, a literal the pure evaluator cannot
// place is refused unresolved as before 2026-10-01, and compile warns nothing about the port.
func TestNamedModelPortRequiresExplicitAllowance(t *testing.T) {
	f := newFixture(t)
	const base = "version: 0\nname: guarded\ncommand: [python]\ncapture: forwarder\nmodels:\n  - { provider: anthropic, host: model.example, port: 443 }\n"
	rt, ds := f.compile(f.load(base))
	for _, d := range ds {
		if d.Code == "model-port-restricted" {
			t.Errorf("no net: section reserves no port, but compile warned %+v", d)
		}
	}
	for _, tc := range []struct {
		host string
		want EvalResult
	}{
		{"unrelated.example", EvalResult{Verdict: VerdictAllow, Rule: UnmatchedRule}},
		{"198.51.100.1", EvalResult{Verdict: VerdictRefused, Rule: UnresolvedRule, Reason: record.ReasonNetNotAllowed}},
		{"2001:db8::1", EvalResult{Verdict: VerdictRefused, Rule: UnresolvedRule, Reason: record.ReasonNetNotAllowed}},
		{"model.example", EvalResult{Verdict: VerdictRefused, Rule: "models[model.example:443]", Reason: record.ReasonNetNotAllowed}},
	} {
		if got := rt.Evaluate(Action{Kind: ActionNetConnect, Host: tc.host, Port: 443}, backend.TierLandlock); got != tc.want {
			t.Errorf("no net: section, %s:443 = %+v, want %+v", tc.host, got, tc.want)
		}
	}
	rt, _ = f.compile(f.load(base+"net:\n  allow: [\"198.51.100.1:443\", \"model.example:443\"]\n"), Offline())
	for _, tc := range []struct {
		host    string
		port    int
		allowed bool
	}{
		{"198.51.100.1", 443, true}, {"198.51.100.1", 444, false}, {"198.51.100.2", 443, false}, {"model.example", 443, false},
	} {
		got := rt.Evaluate(Action{Kind: ActionNetConnect, Host: tc.host, Port: tc.port}, backend.TierLandlock)
		if (got.Verdict == VerdictAllow) != tc.allowed {
			t.Errorf("%s:%d = %+v", tc.host, tc.port, got)
		}
	}
	if got := rt.Evaluate(Action{Kind: ActionNetConnect, Host: "unrelated.example", Port: 443}, backend.TierLandlock); got.Verdict != VerdictRefused || got.Rule != "models.port[model.example:443]" {
		t.Errorf("under a net: section, unrelated.example:443 = %+v, want refused models.port[model.example:443]", got)
	}
}
