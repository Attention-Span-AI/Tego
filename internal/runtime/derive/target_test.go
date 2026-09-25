// SPDX-License-Identifier: Apache-2.0

package derive_test

import (
	"net/http"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
)

const r3Reply = `{"id":"msg_01","type":"message","role":"assistant","model":"claude-test","content":[],` +
	`"stop_reason":"end_turn","usage":{"input_tokens":3,"output_tokens":1}}`

// TestRequestTargetForms: on the derive side, an absolute-form target is read
// by its URL's path (RFC 9112 §3.2.2), and a target no form reads is unmetered on a successful answer rather
// than normalized to a path outside /v1, which spent nothing.
func TestRequestTargetForms(t *testing.T) {
	d := derive.NewDispatcher([]derive.Parser{anthropic.New()})
	for _, tc := range []struct {
		target    string
		usageIn   int
		unmetered bool
	}{
		{"/v1/messages", 3, false},
		{"https://api.anthropic.com/v1/messages", 3, false},
		{"HTTPS://api.anthropic.com:443/v1/messages?beta=true", 3, false},
		{"http://api.anthropic.com/v1/%6Dessages", 3, false},
		{"https://api.anthropic.com/api/event_logging/batch", 0, false},
		{"api.anthropic.com/v1/messages", 0, true},
		{"ftp://api.anthropic.com/v1/messages", 0, true},
		{"https:///v1/messages", 0, true},
		{"https:/api.anthropic.com/v1/messages", 0, true},
	} {
		req := &derive.Message{Method: "POST", Path: tc.target, Header: http.Header{},
			Body: []byte(`{"model":"claude-test","messages":[]}`), Decoded: true}
		resp := &derive.Message{Status: 200, Header: http.Header{"Content-Type": {"application/json"}},
			Body: []byte(r3Reply), Decoded: true}
		res, err := d.Handle(req, resp, testMeta("anthropic", "api.anthropic.com"))
		if err != nil {
			t.Fatal(err)
		}
		in := 0
		if res.Facts.Usage != nil {
			in = res.Facts.Usage.Input
		}
		if in != tc.usageIn || res.Facts.Unmetered != tc.unmetered {
			t.Errorf("%q: usage input %d unmetered %v, want %d %v", tc.target, in, res.Facts.Unmetered,
				tc.usageIn, tc.unmetered)
		}
	}
}

// TestSplitTarget pins the forms themselves.
func TestSplitTarget(t *testing.T) {
	for _, tc := range []struct {
		target, authority, path string
		ok                      bool
	}{
		{"/v1/messages?x=1", "", "/v1/messages?x=1", true},
		{"*", "", "*", true},
		{"https://api.anthropic.com/v1/messages?x=1", "api.anthropic.com", "/v1/messages?x=1", true},
		{"http://api.anthropic.com:8080", "api.anthropic.com:8080", "/", true},
		{"api.anthropic.com:443", "", "api.anthropic.com:443", false},
		{"mailto:a@b", "", "mailto:a@b", false},
		{"v1/messages", "", "v1/messages", false},
	} {
		a, p, ok := derive.SplitTarget(tc.target)
		if a != tc.authority || p != tc.path || ok != tc.ok {
			t.Errorf("SplitTarget(%q) = %q, %q, %v; want %q, %q, %v", tc.target, a, p, ok, tc.authority, tc.path, tc.ok)
		}
	}
}

// TestTrailingDotHost: a fully qualified host names the same parser (R33).
func TestTrailingDotHost(t *testing.T) {
	d := derive.NewDispatcher([]derive.Parser{anthropic.New()})
	for _, h := range []string{"api.anthropic.com.", "API.Anthropic.com.:443"} {
		if _, ok := d.Parser("", h); !ok {
			t.Errorf("Parser(%q): no parser for the declared host with a trailing dot", h)
		}
	}
}
