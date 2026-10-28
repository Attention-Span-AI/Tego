// SPDX-License-Identifier: Apache-2.0

package modelroute

import (
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func endpoint() agent.ModelEndpoint {
	off := false
	return agent.ModelEndpoint{Provider: "anthropic", Host: "API.Anthropic.com.", Port: 443, Routes: []agent.ModelRoute{
		{Name: "corp", Host: "llm-proxy.corp.example", Port: 8443},
		{Name: "local", Host: "127.0.0.1", Port: 11434, TLS: &off},
	}}
}

func TestResolve(t *testing.T) {
	m := endpoint()
	for _, tc := range []struct {
		live, name, authority string
		tls, ok               bool
	}{
		{"", Direct, "api.anthropic.com:443", true, true},
		{Direct, Direct, "api.anthropic.com:443", true, true},
		{"corp", "corp", "llm-proxy.corp.example:8443", true, true},
		{"local", "local", "127.0.0.1:11434", false, true},
		{"evil", Direct, "api.anthropic.com:443", true, false},
	} {
		r, ok := Resolve(m, tc.live)
		if r.Name != tc.name || r.Authority() != tc.authority || r.TLS != tc.tls || ok != tc.ok {
			t.Errorf("Resolve(%q) = %+v %s %v", tc.live, r, r.Authority(), ok)
		}
		if got := r.Taken(); got.Name != tc.name || got.Authority != tc.authority {
			t.Errorf("Taken = %+v", got)
		}
	}
	if d := DirectOf(agent.ModelEndpoint{Host: "h"}); d.Port != 443 || !d.IsDirect() {
		t.Errorf("DirectOf without a port = %+v", d)
	}
	if got := Names(m); !slices.Equal(got, []string{"direct", "corp", "local"}) {
		t.Errorf("Names = %q", got)
	}
}

func TestWidens(t *testing.T) {
	for _, tc := range []struct {
		from, to string
		want     bool
	}{
		{Direct, "corp", true},
		{"", "corp", true},
		{"corp", "local", true},
		{"corp", Direct, false},
		{"corp", "", false},
		{"corp", "corp", false},
		{Direct, Direct, false},
	} {
		if got := Widens(tc.from, tc.to); got != tc.want {
			t.Errorf("Widens(%q, %q) = %v", tc.from, tc.to, got)
		}
	}
}
