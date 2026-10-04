// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Named SSE events may supply the routing type omitted from their JSON data. Capture preserves it for
// the same provider parser the forwarder uses, across split fields, CRLF and multiline JSON.
func TestNamedSSEAccountingEventsAreDerived(t *testing.T) {
	for _, nl := range []string{"\n", "\r\n", "\r"} {
		t.Run(strconv.Quote(nl), func(t *testing.T) {
			body := "\xef\xbb\xbf: heartbeat\nretry: 100\nid: transport-id\nevent: message_start\n" +
				"data: {\"message\":{\"id\":\"m\",\"model\":\"x\",\n" +
				"data: \"usage\":{\"input_tokens\":5,\"output_tokens\":1}}}\n\n" +
				"event: message_delta\ndata: {\"usage\":{\"output_tokens\":7}}\n\n" +
				"event: message_stop\ndata: {}\n\n"
			body = strings.ReplaceAll(body, "\n", nl)
			response := "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
			records := [][]byte{chunkRecord(41, 100, 100, 0xabc, bpf.SSLWrite, 1_000_000, []byte(exchangeRequest), false)}
			for off := 0; off < len(response); off += 17 {
				records = append(records, chunkRecord(41, 100, 100, 0xabc, bpf.SSLRead,
					9_000_000+uint64(off), []byte(response[off:min(off+17, len(response))]), false))
			}
			u, _ := newTestUprobe(t, records, Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
			sink := runMetered(t, u, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
			if sink.reported() != 0 {
				t.Fatalf("named valid events reported unmetered: %d", sink.reported())
			}
			var usage *record.Usage
			for _, ev := range sink.events() {
				if ev.Kind != record.KindSSLResponse {
					continue
				}
				var p record.SSLResponsePayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				usage = p.Usage
				if p.Model != "x" || p.ResponseID != "m" || p.ParserVersion != anthropic.ParserVersion {
					t.Fatalf("routing identity lost: %+v", p)
				}
			}
			if usage == nil || usage.Input != 5 || usage.Output != 7 {
				t.Fatalf("named events lost usage: %+v", usage)
			}
		})
	}
}

// SSE framing is provider input: losing an empty accounting event makes an incomplete exchange look metered.
func TestEmptySSEAccountingFrameIsNotLostBeforeDerive(t *testing.T) {
	const start = "event: message_start\ndata: " + `{"type":"message_start","message":{"id":"m","model":"x","usage":{"input_tokens":5,"output_tokens":1}}}` + "\n\n"
	const final = "event: message_delta\ndata: " + `{"type":"message_delta","usage":{"output_tokens":7}}` + "\n\n" +
		"event: message_stop\ndata: " + `{"type":"message_stop"}` + "\n\n"
	for _, name := range []string{"message_start", "message_delta"} {
		t.Run(name, func(t *testing.T) {
			body := start + "event: " + name + "\ndata: \n\n" + final
			response := "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
			records := [][]byte{
				chunkRecord(41, 100, 100, 0xabc, bpf.SSLWrite, 1_000_000, []byte(exchangeRequest), false),
				chunkRecord(41, 100, 100, 0xabc, bpf.SSLRead, 9_000_000, []byte(response), false),
			}
			u, _ := newTestUprobe(t, records, Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
			sink := runMetered(t, u, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
			if sink.reported() != 1 {
				t.Fatalf("empty accounting event vanished: reported %d exchanges unmetered, want 1", sink.reported())
			}
			var usage *record.Usage
			var schemaFailure bool
			for _, ev := range sink.events() {
				switch ev.Kind {
				case record.KindSSLResponse:
					var p record.SSLResponsePayload
					if err := ev.DecodePayload(&p); err != nil {
						t.Fatal(err)
					}
					usage = p.Usage
				case record.KindDecision:
					var p record.DecisionPayload
					if err := ev.DecodePayload(&p); err != nil {
						t.Fatal(err)
					}
					schemaFailure = schemaFailure || p.Unparsed && p.Why == derive.WhySchema
				}
			}
			if usage == nil || usage.Input != 5 || usage.Output != 7 || !schemaFailure {
				t.Fatalf("known usage or incomplete decision lost: usage=%+v schemaFailure=%v", usage, schemaFailure)
			}
		})
	}
}
