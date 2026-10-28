// SPDX-License-Identifier: Apache-2.0

package modelroute

import (
	"maps"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestCountsKeyedByEndpoint: two endpoints that declare a route of the same name and backend have their requests counted
// apart, by the host each line names.
func TestCountsKeyedByEndpoint(t *testing.T) {
	ms := []agent.ModelEndpoint{
		{Provider: "anthropic", Host: "api.anthropic.com", Port: 443, Routes: []agent.ModelRoute{{Name: "corp", Host: "gw.example", Port: 8443}}},
		{Provider: "openai", Host: "api.openai.com", Port: 443, Routes: []agent.ModelRoute{{Name: "corp", Host: "gw.example", Port: 8443}}},
	}
	count := RequestCounter(ms)
	got := map[[2]string]int{}
	line := func(provider, host, route, backend string) *record.Event {
		e := &record.Event{Kind: record.KindSSLRequest}
		if err := e.SetPayload(record.SSLRequestPayload{Endpoint: provider, Host: host, Method: "POST", Path: "/v1",
			Route: &record.RouteTaken{Name: route, Authority: backend}}); err != nil {
			t.Fatal(err)
		}
		return e
	}
	count(line("anthropic", "api.anthropic.com", "corp", "gw.example:8443"), got)
	count(line("openai", "api.openai.com", "corp", "gw.example:8443"), got)
	count(line("openai", "api.openai.com", "corp", "gw.example:8443"), got)
	count(line("openai", "api.openai.com", "direct", "api.openai.com:443"), got)
	count(line("openai", "elsewhere.example", "corp", "gw.example:8443"), got) // no entry: left out
	want := map[[2]string]int{{"api.anthropic.com:443", "corp"}: 1, {"api.openai.com:443", "corp"}: 2, {"api.openai.com:443", "direct"}: 1}
	if !maps.Equal(got, want) {
		t.Fatalf("counts %v, want %v", got, want)
	}
}
