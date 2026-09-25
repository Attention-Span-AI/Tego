// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const scanStream = "event: message_start\n" +
	`data: {"type":"message_start","message":{"id":"msg_1","model":"claude-opus-5","usage":{"input_tokens":1200,"output_tokens":1}}}` + "\n\n" +
	"event: content_block_start\n" +
	`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n" +
	"event: content_block_delta\n" +
	`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}` + "\n\n" +
	"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
	"event: message_delta\n" +
	`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}` + "\n\n" +
	"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

// scanAll feeds body to a StreamUsageScanner in the pieces cut at the given offsets.
func scanAll(body []byte, cuts ...int) (*record.Usage, string, bool) {
	var s StreamUsageScanner
	prev := 0
	for _, c := range cuts {
		_, _ = s.Write(body[prev:c])
		prev = c
	}
	_, _ = s.Write(body[prev:])
	return s.Result()
}

// TestStreamUsageScannerReadsKeysAsWritten: the wire scanner reads usage keys exactly as written,
// as ParseStream does, so a case variant beside the real key, before or after it, is ignored and never charged.
func TestStreamUsageScannerReadsKeysAsWritten(t *testing.T) {
	for _, tc := range []struct {
		name, from, to string
	}{
		{"variant after", `"input_tokens":1200,`, `"input_tokens":1200,"INPUT_TOKENS":999999,`},
		{"variant before", `"input_tokens":1200,`, `"Input_Tokens":999999,"input_tokens":1200,`},
		{"delta variant", `"usage":{"output_tokens":7}`, `"usage":{"output_tokens":7,"OUTPUT_TOKENS":888888}`},
		{"usage variant", `"usage":{"output_tokens":7}`, `"usage":{"output_tokens":7},"USAGE":{"output_tokens":888888}`},
		{"kelvin sign", `"input_tokens":1200,`, "\"input_tokens\":1200,\"input_toKens\":999999,"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(strings.Replace(scanStream, tc.from, tc.to, 1))
			resp, _, err := ParseStream(body)
			if err != nil {
				t.Fatal(err)
			}
			want := resp.Usage.Record()
			got, model, final := scanAll(body, 17, 101)
			if got == nil || !reflect.DeepEqual(*got, want) || model != "claude-opus-5" || !final {
				t.Fatalf("scanner read %+v %q %v; derive %+v", got, model, final, want)
			}
			if got.Input != 1200 || got.Output != 7 {
				t.Errorf("scanner charged a case variant: %+v", got)
			}
		})
	}
}

// TestStreamUsageScannerExtra: the 1-hour cache writes and server-tool counts reach the scanner's usage, folded as
// derive folds them.
func TestStreamUsageScannerExtra(t *testing.T) {
	body := []byte(`data: {"type":"message_start","message":{"model":"m","usage":{"input_tokens":10,` +
		`"cache_creation_input_tokens":300,"cache_creation":{"ephemeral_5m_input_tokens":200,"ephemeral_1h_input_tokens":100}}}}` + "\n\n" +
		`data: {"type":"message_delta","usage":{"output_tokens":20,"server_tool_use":{"web_search_requests":3}}}` + "\n\n")
	got, model, final := scanAll(body)
	want := &record.Usage{Input: 10, Output: 20, CacheWrite: 300, CacheWrite1h: 100,
		ServerTool: map[string]int{"web_search_requests": 3}}
	if model != "m" || !final || !reflect.DeepEqual(got, want) {
		t.Fatalf("scanned %+v %q %v, want %+v", got, model, final, want)
	}
	if u, _, _ := scanAll([]byte("data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":-1}}}\n")); u != nil {
		t.Errorf("a negative count was folded: %+v", u)
	}
	long := []byte("data: {\"type\":\"message_delta\",\"x\":\"" + strings.Repeat("y", maxScanLine) +
		"\",\"usage\":{\"output_tokens\":5}}\n")
	if u, _, _ := scanAll(long, 3); u != nil {
		t.Errorf("a line past maxScanLine was read: %+v", u)
	}
}

// TestStreamUsageScannerFramesAsParseStream: valid event streams the scanner read differently from
// ParseStream — a type given only by the `event:` line, a payload split over several `data:` lines, a type spelled
// with a JSON escape — each hid the message_delta, so the scanner reported message_start's placeholder output.
func TestStreamUsageScannerFramesAsParseStream(t *testing.T) {
	const start = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"model\":\"x\"," +
		"\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n"
	const stop = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	for _, tc := range []struct{ name, body string }{
		{"type in the event line only", start +
			"event: message_delta\ndata: {\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":900}}\n\n" + stop},
		{"data over two lines", start +
			"event: message_delta\ndata: {\"type\":\"message_delta\",\ndata: \"usage\":{\"output_tokens\":900}}\n\n" + stop},
		{"escaped type", start +
			"data: {\"type\":\"message\\u005fdelta\",\"usage\":{\"output_tokens\":900}}\n\n" + stop},
		{"last line with no newline", start +
			"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":900}}\n\n" +
			"data: {\"type\":\"message_stop\"}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, _, err := ParseStream([]byte(tc.body))
			if err != nil || resp.Usage.OutputTokens != 900 || !resp.FinalUsage {
				t.Fatalf("ParseStream: %v, output %d final %v", err, resp.Usage.OutputTokens, resp.FinalUsage)
			}
			for _, cut := range []int{0, 1, 40, len(tc.body) / 2} {
				u, model, final := scanAll([]byte(tc.body), cut)
				if u == nil || u.Output != 900 || u.Input != 10 || !final || model != "x" {
					t.Errorf("cut at %d: scanner read %+v %q final %v; ParseStream output 900, final", cut, u, model, final)
				}
			}
		})
	}
	// Extension fields, including colonless names, are ignored by SSE clients and by both parsers.
	body := []byte(start + "bogus line\n\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":900}}\n\n" + stop)
	if u, _, final := scanAll(body); u == nil || u.Output != 900 || !final {
		t.Errorf("extension field hid later usage: %+v final %v", u, final)
	}
	pending := []byte(start + "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":900}}\nGARBAGE\n\n" + stop)
	resp, _, err := ParseStream(pending)
	if err != nil || resp == nil || resp.Usage.OutputTokens != 900 || !resp.FinalUsage {
		t.Fatalf("ParseStream: %v, %+v", err, resp)
	}
	for _, cut := range []int{0, 5, len(pending) - 3} {
		if u, _, final := scanAll(pending, cut); u == nil || u.Output != 900 || !final {
			t.Errorf("cut at %d: extension field hid pending usage: %+v final %v", cut, u, final)
		}
	}
}

// FuzzUsageScanner: the scanner's result does not depend on how the relay split the bytes, so a "final" it
// reports, which replaces derive's max_tokens bound (the forwarder's mergeUsage), is a property of the stream and
// not of the reads that carried it.
func FuzzUsageScanner(f *testing.F) {
	f.Add([]byte(scanStream), uint16(1), uint16(7))
	f.Add([]byte(scanStream[:200]), uint16(3), uint16(50))
	f.Add([]byte(strings.Replace(scanStream, `"output_tokens":7}`, `"output_tokens":7,"OUTPUT_TOKENS":9}`, 1)), uint16(9), uint16(90))
	f.Add([]byte("data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":3}}\r\n"), uint16(5), uint16(9))
	f.Add([]byte("data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":-1}}}\n"), uint16(0), uint16(0))
	f.Fuzz(func(t *testing.T, body []byte, a, b uint16) {
		u1, m1, f1 := scanAll(body)
		i, j := int(a)%(len(body)+1), int(b)%(len(body)+1)
		if i > j {
			i, j = j, i
		}
		u2, m2, f2 := scanAll(body, i, j)
		if !reflect.DeepEqual(u1, u2) || m1 != m2 || f1 != f2 {
			t.Fatalf("split at %d,%d: %+v %q %v vs whole %+v %q %v", i, j, u2, m2, f2, u1, m1, f1)
		}
	})
}

// longLine reports whether body holds a line, or a frame's data, the scanner passes over for its length
// (maxScanLine) where ParseStream reads it.
func longLine(body []byte) bool {
	frame := 0
	for line := range bytes.SplitSeq(body, []byte("\n")) {
		if len(line) >= maxScanLine {
			return true
		}
		if len(bytes.TrimSuffix(line, []byte("\r"))) == 0 {
			frame = 0
		}
		if frame += len(line) + 1; frame >= maxScanLine {
			return true
		}
	}
	return false
}

// usageAtLeast reports whether every counter of got is at least want's.
func usageAtLeast(got, want record.Usage) bool {
	if got.Input < want.Input || got.Output < want.Output || got.CacheRead < want.CacheRead ||
		got.CacheWrite < want.CacheWrite || got.CacheWrite1h < want.CacheWrite1h {
		return false
	}
	for k, v := range want.ServerTool {
		if got.ServerTool[k] < v {
			return false
		}
	}
	return true
}

// FuzzStreamUsageScannerAgreesWithParseStream compares the scanner with ParseStream on whole streams:
// on a stream ParseStream assembles, they read the same usage, model and final flag; on one it fails,
// the scanner reads at least the usage ParseStream kept, and a final count wherever ParseStream saw one, since a
// failure makes ParseStream read less of the stream, never more.
func FuzzStreamUsageScannerAgreesWithParseStream(f *testing.F) {
	f.Add([]byte(scanStream))
	f.Add([]byte(strings.ReplaceAll(scanStream, `"type":"message_delta",`, ``)))
	f.Add([]byte(strings.ReplaceAll(scanStream, `"type":"message_delta",`, `"type":"message_delta",`+"\ndata: ")))
	f.Add([]byte(strings.ReplaceAll(scanStream, `message_delta"`, `message_delta"`)))
	f.Add([]byte(strings.ReplaceAll(scanStream, "data: ", "")))
	f.Add([]byte(strings.TrimSuffix(scanStream, "\n\n")))
	f.Add([]byte(": hb\r\nid: 1\r\n" + strings.ReplaceAll(scanStream, "\n", "\r\n")))
	f.Add([]byte(`{"type":"message_delta","usage":{"output_tokens":99999}}` + "\n\n" + scanStream))
	f.Add([]byte(strings.Replace(scanStream, "event: message_stop", `{"type":"message_delta","usage":{"output_tokens":99999}}`+"\n\nevent: message_stop", 1)))
	f.Add([]byte("event: message_start\ndata: " + `{"type":"message_start","message":{"id":"m","model":"x","usage":{"input_tokens":5,"output_tokens":1}}}` +
		"\n\nevent: unknown\ndata: [bad\n\ndata: " + `{"type":"message\u005fdelta","usage":{"output_tokens":10000}}` + "\n\n"))
	f.Fuzz(func(t *testing.T, body []byte) {
		if longLine(body) {
			return
		}
		// The same accounting truth must hold for current wire capture and legacy collected callers.
		for _, wireSSE := range []bool{false, true} {
			scanner := StreamUsageScanner{WireSSE: wireSSE}
			cut := len(body) / 2
			_, _ = scanner.Write(body[:cut])
			_, _ = scanner.Write(body[cut:])
			u, model, final := scanner.Result()
			got := record.Usage{}
			if u != nil {
				got = *u
			}
			resp, _, err := parseStream(body, true, wireSSE)
			if resp == nil || resp.ErrorAnswer {
				continue
			}
			want := resp.Usage.Record()
			if err != nil {
				if !usageAtLeast(got, want) || (resp.FinalUsage && !final) {
					t.Fatalf("ParseStream failed (%v) with %+v final %v; the scanner read less: %+v final %v",
						err, want, resp.FinalUsage, got, final)
				}
				continue
			}
			if len(got.ServerTool) == 0 && len(want.ServerTool) == 0 {
				got.ServerTool, want.ServerTool = nil, nil
			}
			if u == nil {
				model = resp.Model // the scanner names a model only beside a usage it read
			}
			if !reflect.DeepEqual(got, want) || model != resp.Model || final != resp.FinalUsage {
				t.Fatalf("scanner read %+v %q %v; ParseStream %+v %q %v", got, model, final, want, resp.Model, resp.FinalUsage)
			}
		}
	})
}

// Capture reads transport chunks of arbitrary sizes. Every CR/LF split must preserve the same usage as
// the complete body, even with proxy fields or an initial UTF-8 signature.
func TestStreamFramingAcrossEveryChunkBoundary(t *testing.T) {
	for _, ending := range []string{"\n", "\r", "\r\n"} {
		body := []byte("\xef\xbb\xbf" + strings.ReplaceAll("event: unused\n\nx-proxy: trace\n"+scanStream, "\n", ending))
		resp, _, err := ParseStream(body)
		if err != nil || resp == nil || resp.Usage.OutputTokens != 7 {
			t.Fatalf("ending %q: %+v, %v", ending, resp, err)
		}
		want := resp.Usage.Record()
		for cut := 0; cut <= len(body); cut++ {
			u, model, final := scanAll(body, cut)
			if u == nil || !reflect.DeepEqual(*u, want) || model != resp.Model || !final {
				t.Fatalf("ending %q cut %d: %+v %q %v, want %+v", ending, cut, u, model, final, want)
			}
		}
		var scanner StreamUsageScanner
		for _, b := range body {
			_, _ = scanner.Write([]byte{b})
		}
		u, _, final := scanner.Result()
		if u == nil || !reflect.DeepEqual(*u, want) || !final {
			t.Fatalf("bytewise %q: %+v final %v", ending, u, final)
		}
	}
}

// Skipped content is safe only when its complete structural type proves it carries no accounting.
func TestOversizedFrameCannotHideAccounting(t *testing.T) {
	startEnd := strings.Index(scanStream, "event: content_block_start")
	start, rest := scanStream[:startEnd], scanStream[startEnd:]
	pad := strings.Repeat("x", maxScanLine+50)
	for _, tc := range []struct {
		name, frame string
		incomplete  bool
	}{
		{"content", `{"type":"content_block_delta","delta":{"text":"` + pad + `"}}`, false},
		{"late content type", `{"delta":{"text":"` + pad + `"},"type":"content_block_delta"}`, false},
		{"accounting", `{"type":"message_delta","padding":"` + pad + `","usage":{"input_tokens":9000,"output_tokens":2}}`, true},
		{"late accounting type", `{"padding":"` + pad + `","type":"message_delta","usage":{"input_tokens":9000,"output_tokens":2}}`, true},
		{"duplicate type", `{"type":"content_block_delta","padding":"` + pad + `","type":"message_delta","usage":{"input_tokens":9000}}`, true},
		{"unknown", `{"padding":"` + pad + `"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, framed := range []bool{false, true} {
				frame := tc.frame + "\n"
				if framed {
					frame = "data: " + tc.frame + "\n\n"
				}
				body := []byte(start + frame + rest)
				for _, chunk := range []int{1, 7, 65536, len(body)} {
					var scan StreamUsageScanner
					for off := 0; off < len(body); off += chunk {
						_, _ = scan.Write(body[off:min(off+chunk, len(body))])
					}
					u, _, final := scan.Result()
					if scan.Incomplete() != tc.incomplete || u == nil || u.Input != 1200 || u.Output != 7 || !final {
						t.Fatalf("framed=%v chunk=%d: incomplete=%v usage=%+v final=%v", framed, chunk, scan.Incomplete(), u, final)
					}
				}
			}
		})
	}
}

func TestOversizedFrameSignatureAndEventName(t *testing.T) {
	pad := strings.Repeat("x", maxScanLine+20)
	cases := []string{
		"\ufeffdata: " + `{"type":"message_start","padding":"` + pad + `","message":{"model":"m","usage":{"input_tokens":5000}}}` + "\n\n" + scanStream,
		"\ufeff" + `{"type":"message_start","padding":"` + pad + `","message":{"model":"m","usage":{"input_tokens":5000}}}` + "\n" + scanStream,
		"event: content_block_delta\nevent: " + pad + "\ndata: " + `{"text":"` + pad + `"}` + "\n\n" + scanStream,
	}
	for i, body := range cases {
		for _, chunk := range []int{1, 2, 3, len(body)} {
			var s StreamUsageScanner
			for off := 0; off < len(body); off += chunk {
				_, _ = s.Write([]byte(body[off:min(off+chunk, len(body))]))
			}
			s.Result()
			if !s.Incomplete() {
				t.Fatalf("case%d chunk%d: unreadable accounting was restored", i, chunk)
			}
		}
	}
}
