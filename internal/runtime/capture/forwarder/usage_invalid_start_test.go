// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"io"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A readable output delta cannot recover the input counters of an unreadable message_start. The wire
// scanner must leave that exchange unmetered, even with a known max_tokens, so budgets fail closed.
func TestInvalidStreamStartUsageStaysUnmetered(t *testing.T) {
	for _, input := range []string{`18446744073709551615`, `-1`, `"unreadable"`} {
		t.Run(input, func(t *testing.T) {
			stream := strings.Replace(r4Stream, `"input_tokens":1200`, `"input_tokens":`+input, 1)
			h := newHarness(t, sseHandler(stream), Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
			m := meter(h)
			resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","max_tokens":7,"stream":true,"messages":[]}`), nil)
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			p := payloadOf[record.SSLResponsePayload](t, h.sink.waitFor(t, record.KindSSLResponse, 1)[0])
			if p.Usage != nil {
				t.Fatalf("unreadable opening usage became a partial charge: %+v", p.Usage)
			}
			if got := waitReported(m, 1); len(got) != 1 {
				t.Fatalf("unreadable opening usage was not reported unmetered: %v", got)
			}
		})
	}
}

// A later readable delta cannot repair input/cache accounting lost in an earlier accounting frame.
func TestLaterDeltaDoesNotRestoreIncompleteAccounting(t *testing.T) {
	startEnd := strings.Index(r4Stream, "event: content_block_start")
	if startEnd < 0 {
		startEnd = strings.Index(r4Stream, "event: message_delta")
	}
	start, rest := r4Stream[:startEnd], r4Stream[startEnd:]
	cases := map[string]string{
		"missing start":        rest,
		"missing input":        strings.Replace(r4Stream, `"input_tokens":1200,`, "", 1),
		"null input":           strings.Replace(r4Stream, `"input_tokens":1200`, `"input_tokens":null`, 1),
		"missing usage":        strings.Replace(r4Stream, `"usage":{"input_tokens":1200,"output_tokens":1}`, `"usage":null`, 1),
		"invalid later usage":  start + "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":\"unknown\",\"output_tokens\":2}}\n\n" + rest,
		"negative later usage": start + "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"cache_read_input_tokens\":-1,\"output_tokens\":2}}\n\n" + rest,
		"repeated start":       start + start + rest,
	}
	for name, stream := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, sseHandler(stream), Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
			m := meter(h)
			resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","max_tokens":7,"stream":true,"messages":[]}`), nil)
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			h.sink.waitFor(t, record.KindSSLResponse, 1)
			if got := waitReported(m, 1); len(got) != 1 {
				t.Fatalf("incomplete accounting became metered: %v", got)
			}
		})
	}
}
