// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
)

// TestParseStreamKeepsUsageOfMalformedMembers: a message_delta whose delta member is not an object, and a
// message_start whose message has a field of another type, still reported their usage; ParseStream keeps it
// (with its schema error), as the scanner reads it, so both capture paths charge the same exchange alike.
func TestParseStreamKeepsUsageOfMalformedMembers(t *testing.T) {
	const start = `data: {"type":"message_start","message":{"id":"m","model":"x","usage":{"input_tokens":5,"output_tokens":1}}}` + "\n\n"
	const badStart = `data: {"type":"message_start","message":{"id":"m","model":"x","role":5,"usage":{"input_tokens":5,"output_tokens":1}}}` + "\n\n"
	const stop = `data: {"type":"message_stop"}` + "\n\n"
	const delta = `data: {"type":"message_delta","usage":{"output_tokens":500}}` + "\n\n"
	for _, tc := range []struct {
		name, body string
		in, out    int64
		final      bool
	}{
		{"delta not an object", start +
			`data: {"type":"message_delta","delta":"x","usage":{"output_tokens":500}}` + "\n\n" + stop, 5, 500, true},
		{"message field of another type", badStart + delta + stop, 5, 500, true},
		{"message field of another type, no delta", badStart, 5, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, _, err := ParseStream([]byte(tc.body))
			if err == nil {
				t.Fatal("a malformed member parsed without an error")
			}
			if resp == nil {
				t.Fatal("the usage on the wire was dropped with the stream")
			}
			u, model, final := scanAll([]byte(tc.body))
			if u == nil || int64(u.Input) != tc.in || int64(u.Output) != tc.out || final != tc.final || model != "x" {
				t.Fatalf("scanner read %+v %q %v, want in %d out %d final %v", u, model, final, tc.in, tc.out, tc.final)
			}
			if got := resp.Usage.Record(); int64(got.Input) != tc.in || int64(got.Output) != tc.out ||
				resp.FinalUsage != tc.final || resp.Model != "x" {
				t.Fatalf("ParseStream read %+v %q final %v; the scanner read in %d out %d", got, resp.Model, resp.FinalUsage, tc.in, tc.out)
			}
		})
	}
}

func TestKnownOutputSurvivesMissingOpeningUsage(t *testing.T) {
	for _, opening := range []string{
		`{"model":"x"}`,
		`{"model":"x","usage":null}`,
		`{"model":"x","usage":{"output_tokens":1}}`,
		`{"model":"x","usage":{"input_tokens":null,"output_tokens":1}}`,
	} {
		body := []byte(`{"type":"message_start","message":` + opening + "}\n" +
			`{"type":"message_delta","usage":{"output_tokens":7}}` + "\n" +
			`{"type":"message_stop"}` + "\n")
		var scanner StreamUsageScanner
		for _, b := range body {
			_, _ = scanner.Write([]byte{b})
		}
		u, model, final := scanner.Result()
		if u == nil || u.Input != 0 || u.Output != 7 || model != "x" || !final || !scanner.Incomplete() {
			t.Errorf("scanner discarded observed output or restored unknown input for %s: %+v, %q, final=%v incomplete=%v",
				opening, u, model, final, scanner.Incomplete())
		}
		resp, _, err := ParseStream(body)
		if err == nil || resp == nil || !resp.incompleteUsage || !resp.FinalUsage || resp.Usage.OutputTokens != 7 {
			t.Fatalf("full parser disagrees for %s: %+v, %v", opening, resp, err)
		}
		req := &derive.Message{Method: "POST", Path: MessagesPath, Body: []byte(`{"model":"x","max_tokens":10,"messages":[]}`), Decoded: true}
		facts, err := New().Parse(req, response(body, "text/event-stream"))
		if err != nil || !facts.Unmetered || !facts.IncompleteUsage || facts.Usage == nil || facts.Usage.Output != 7 ||
			BoundCutStream(&facts, 10, true, 200) {
			t.Fatalf("known output falsely bounded unknown opening spend for %s: %+v, %v", opening, facts, err)
		}
	}
}
