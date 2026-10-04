// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"net/http"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
)

// Wire framing treats all unknown fields as SSE fields, even when their names look like JSON or the
// line exceeds the incremental scanner's retention limit. Only data fields contribute accounting.
func TestWireSSEUnknownJSONFieldsAreIgnored(t *testing.T) {
	const start = "event: message_start\ndata: " + `{"message":{"id":"m","model":"x","usage":{"input_tokens":5,"output_tokens":1}}}` + "\n\n"
	const delta = "event: message_delta\ndata: " + `{"usage":{"output_tokens":7}}` + "\n\n"
	const stop = "event: message_stop\ndata: {}\n\n"
	const fake = `{"type":"message_delta","usage":{"output_tokens":99999}}` + "\n\n"
	for name, body := range map[string]string{
		"before start": fake + start + delta + stop,
		"before stop":  start + delta + fake + stop,
		"inside frame": start + "event: message_delta\n" + strings.TrimSuffix(fake, "\n") + `data: {"usage":{"output_tokens":7}}` + "\n\n" + stop,
		"oversized unknown": start + delta + `{"type":"message_delta","usage":{"output_tokens":99999},"padding":"` +
			strings.Repeat("x", 2*maxScanLine) + "\"}\n\n" + stop,
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := parseStreamResponse([]byte(body), true)
			if err != nil || resp == nil || resp.incompleteUsage || !resp.FinalUsage || resp.Usage.InputTokens != 5 || resp.Usage.OutputTokens != 7 {
				t.Fatalf("wire parser read unknown field: %+v, %v", resp, err)
			}
			for _, chunk := range []int{1, 7, 4096} {
				scanner := StreamUsageScanner{WireSSE: true}
				for off := 0; off < len(body); off += chunk {
					_, _ = scanner.Write([]byte(body[off:min(off+chunk, len(body))]))
				}
				u, model, final := scanner.Result()
				if scanner.Incomplete() || u == nil || u.Input != 5 || u.Output != 7 || model != "x" || !final {
					t.Fatalf("chunk %d: scanner read unknown field: %+v %q final=%v incomplete=%v", chunk, u, model, final, scanner.Incomplete())
				}
			}
		})
	}
}

// Older callers can still read payloads collected without wire framing. Current capture selects wire
// mode explicitly so this compatibility cannot interpret an unknown SSE field as a provider event.
func TestCollectedStreamCompatibilityRemainsExplicit(t *testing.T) {
	body := []byte(`{"type":"message_start","message":{"id":"m","model":"x","usage":{"input_tokens":5,"output_tokens":1}}}` + "\n" +
		`{"type":"message_delta","usage":{"output_tokens":7}}` + "\n" + `{"type":"message_stop"}` + "\n")
	resp, _, err := ParseStream(body)
	if err != nil || resp == nil || !resp.FinalUsage || resp.Usage.InputTokens != 5 || resp.Usage.OutputTokens != 7 {
		t.Fatalf("legacy stream lost compatibility: %+v, %v", resp, err)
	}
	var legacy StreamUsageScanner
	_, _ = legacy.Write(body)
	u, model, final := legacy.Result()
	if u == nil || u.Input != 5 || u.Output != 7 || model != "x" || !final || legacy.Incomplete() {
		t.Fatalf("legacy scanner lost compatibility: %+v %q final=%v", u, model, final)
	}
	wire := StreamUsageScanner{WireSSE: true}
	_, _ = wire.Write(body)
	if u, _, _ := wire.Result(); u != nil {
		t.Fatalf("wire scanner accepted bare JSON fields: %+v", u)
	}
}

// A malformed content frame does not erase later readable accounting. JSON escapes are valid in
// routing keys and values, so recovery must retain the same final counters as the relay scanner.
func TestEscapedFinalUsageSurvivesMalformedFrame(t *testing.T) {
	const start = "event: message_start\ndata: " + `{"type":"message_start","message":{"id":"m","model":"x","usage":{"input_tokens":5,"output_tokens":1}}}` + "\n\n"
	const malformed = "event: unknown\ndata: [bad\n\n"
	for name, delta := range map[string]string{
		"escaped value": `{"type":"message\u005fdelta","usage":{"output_tokens":10000}}`,
		"escaped key":   `{"ty\u0070e":"message_delta","usage":{"output_tokens":10000}}`,
		"both escaped":  `{"ty\u0070e":"message\u005fdelta","usage":{"output_tokens":10000}}`,
	} {
		t.Run(name, func(t *testing.T) {
			body := []byte(start + malformed + "data: " + delta + "\n\n" + "event: message_stop\ndata: {}\n\n")
			for _, wire := range []bool{false, true} {
				for _, full := range []bool{false, true} {
					resp, _, err := parseStream(body, full, wire)
					if err == nil || resp == nil || !resp.FinalUsage || resp.Usage.InputTokens != 5 || resp.Usage.OutputTokens != 10000 {
						t.Fatalf("wire=%v full=%v: known final usage lost: %+v, %v", wire, full, resp, err)
					}
				}
				scanner := StreamUsageScanner{WireSSE: wire}
				for off := 0; off < len(body); off += 7 {
					_, _ = scanner.Write(body[off:min(off+7, len(body))])
				}
				u, _, final := scanner.Result()
				if u == nil || u.Input != 5 || u.Output != 10000 || !final {
					t.Fatalf("wire=%v: scanner lost final usage: %+v, final=%v", wire, u, final)
				}
				facts, err := New().Parse(
					&derive.Message{Method: http.MethodPost, Path: "/v1/messages", Body: []byte(`{"model":"x","max_tokens":10}`)},
					&derive.Message{Status: http.StatusOK, Body: body, SSE: true, WireSSE: wire},
				)
				if err != nil || facts.Usage == nil || facts.Usage.Output != 10000 || facts.Usage.OutputBound {
					t.Fatalf("wire=%v: request bound replaced known final spend: %+v, %v", wire, facts, err)
				}
			}
		})
	}
}
