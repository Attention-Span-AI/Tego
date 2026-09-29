// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
)

// TestDeclaredHostPathsOutsideV1FailClosed covers capture-derive.md R25: "outside /v1 is silent" is a fact
// about api.anthropic.com. A models[] entry declaring provider anthropic on a gateway reaches Claude under a
// prefix of the gateway's own; there a Messages call outside /v1 was silent, metered at zero and never
// reported unmetered, so a token or cost budget went unenforced with nothing to say so.
func TestDeclaredHostPathsOutsideV1FailClosed(t *testing.T) {
	const gw = "gateway.example.com"
	d := derive.NewDispatcher([]derive.Parser{New(gw)})
	turn := `{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5","content":[],` +
		`"stop_reason":"end_turn","usage":{"input_tokens":150000,"output_tokens":9}}`
	for _, p := range []string{"/anthropic/v1/messages", "/model/claude-opus-5/invoke-with-response-stream",
		"/api/v1/messages", "/api/anthropic/V1;x/messages", "/v2/messages",
		// After one decode a remaining percent escape is still ambiguous. A gateway
		// that decodes again may serve a billed API; it cannot be free telemetry (R25).
		"/api/%2576%2531/messages", "/api/%2576%2531/models", "/api/%252Fv1/messages"} {
		for _, meta := range []derive.Meta{{Provider: "anthropic", Host: gw}, {Host: gw}, {Provider: "anthropic"}} {
			if d.Silent(meta.Provider, meta.Host, "POST", p) {
				t.Errorf("%s on %q: silent, want a path the parser does not read", p, meta.Host)
			}
			req := request([]byte(`{"model":"claude-opus-5","max_tokens":64,"messages":[]}`))
			req.Path = p
			res, err := d.Handle(req, response([]byte(turn), "application/json"), meta)
			if err != nil {
				t.Fatal(err)
			}
			if !res.Facts.Unmetered {
				t.Errorf("%s on %q: answered 2xx and not unmetered (facts %+v)", p, meta.Host, res.Facts)
			}
		}
	}
	// A harness's telemetry and the root path stay silent on a declared host, and Anthropic's own host keeps
	// reading everything outside /v1 as silent.
	for _, p := range []string{"/", "/api/event_logging/batch", "/API/oauth/profile"} {
		if !d.Silent("anthropic", gw, "POST", p) {
			t.Errorf("%s on the declared host: not silent", p)
		}
	}
	for _, p := range []string{"/anthropic/v1/messages", "/api/hello", "/health"} {
		if !d.Silent("anthropic", "api.anthropic.com", "POST", p) {
			t.Errorf("%s on api.anthropic.com: not silent", p)
		}
	}
}
