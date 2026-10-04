// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"strings"
	"testing"
)

func TestEventTypeScanner(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		safe       bool
	}{
		{"content", `{"type":"content_block_delta","delta":{"text":"message_start message_delta"}}`, true},
		{"late type", `{"delta":{"text":"\"type\":\"message_start\""},"type":"content_block_delta"}`, true},
		{"escaped type", `{"\u0074ype":"content_block_\u0064elta"}`, true},
		{"nested type", `{"type":"content_block_start","delta":{"type":"message_start","list":[null,true,false,12.2e+3,{},[]]}}`, true},
		{"ping", `{"type":"ping"}`, true},
		{"stop", `{"type":"message_stop"}`, true},
		{"error", `{"type":"error"}`, true},
		{"start", `{"type":"message_start"}`, false},
		{"delta", `{"type":"message_delta"}`, false},
		{"unknown", `{"type":"content_future"}`, false},
		{"duplicate type", `{"type":"message_delta","type":"content_block_delta"}`, false},
		{"escaped duplicate", `{"type":"content_block_delta","\u0074ype":"message_delta"}`, false},
		{"duplicate content", `{"type":"content_block_delta","type":"content_block_delta"}`, false},
		{"case variant", `{"TYPE":"message_delta","type":"content_block_delta"}`, true},
		{"missing", `{"delta":{"type":"content_block_delta"}}`, false},
		{"null", `{"type":null}`, false},
		{"object type", `{"type":{"type":"content_block_delta"}}`, false},
		{"incomplete", `{"type":"content_block_delta","delta":"unfinished`, false},
		{"trailing comma", `{"type":"content_block_delta",}`, false},
		{"mismatched bracket", `{"type":"content_block_delta","delta":[}}`, false},
		{"bad scalar", `{"type":"content_block_delta","delta":undefined}`, false},
		{"bad escape", `{"type":"content_block_delta","delta":"\x00"}`, false},
		{"two objects", `{"type":"content_block_delta"}{"type":"message_start"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, step := range []int{1, 2, 7, 128} {
				var s eventTypeScanner
				for b := []byte(tc.body); len(b) > 0; {
					n := min(step, len(b))
					s.Write(b[:n])
					b = b[n:]
				}
				if got := s.NonAccounting(nil); got != tc.safe {
					t.Fatalf("chunk=%d: NonAccounting=%t, want %t", step, got, tc.safe)
				}
			}
		})
	}
}

func TestEventTypeScannerOversizedContent(t *testing.T) {
	chunk := []byte(strings.Repeat("text containing message_delta ", 4096))
	for _, suffix := range []struct {
		text string
		safe bool
	}{
		{`"}}`, true},
		{`"},"type":"message_delta","usage":{"input_tokens":9000}}`, false},
	} {
		var s eventTypeScanner
		s.Write([]byte(`{"type":"content_block_delta","delta":{"text":"`))
		for range 64 {
			s.Write(chunk)
		}
		s.Write([]byte(suffix.text))
		if got := s.NonAccounting(nil); got != suffix.safe {
			t.Fatalf("suffix %q: NonAccounting=%t, want %t", suffix.text, got, suffix.safe)
		}
	}
	var deep eventTypeScanner
	deep.Write([]byte(`{"type":"content_block_delta","delta":` + strings.Repeat("[", 256) + "0" + strings.Repeat("]", 256) + "}"))
	if deep.NonAccounting(nil) {
		t.Fatal("overdeep content classified as safely readable")
	}
}

func TestEventTypeScannerEventNameFallback(t *testing.T) {
	for _, tc := range []struct {
		body string
		safe bool
	}{
		{`{"delta":{"text":"large content"}}`, true},
		{`{"type":"","delta":{"text":"large content"}}`, true},
		{`{"type":"message_delta"}`, false},
		{`{"type":null}`, false},
		{`{"type":"","type":"content_block_delta"}`, false},
		{`{"delta":{"text":"cut content`, false},
	} {
		var s eventTypeScanner
		s.Write([]byte(tc.body))
		if got := s.NonAccounting([]byte(EventContentBlockDelta)); got != tc.safe {
			t.Errorf("%s: NonAccounting=%t, want %t", tc.body, got, tc.safe)
		}
	}
}

func FuzzEventTypeScanner(f *testing.F) {
	f.Add([]byte(`{"type":"content_block_delta","delta":{"text":"message_start"}}`), uint8(7))
	f.Add([]byte(`{"type":"message_delta","type":"ping"}`), uint8(1))
	f.Fuzz(func(t *testing.T, body []byte, step uint8) {
		var s eventTypeScanner
		for b := body; len(b) > 0; {
			n := min(int(step)+1, len(b))
			s.Write(b[:n])
			b = b[n:]
		}
		if !s.NonAccounting(nil) {
			return
		}
		var ev struct {
			Type string `json:"type"`
		}
		if unmarshal(body, &ev) != nil {
			t.Fatalf("malformed frame classified as non-accounting: %q", body)
		}
		switch ev.Type {
		case EventContentBlockStart, EventContentBlockDelta, EventContentBlockStop, EventPing, EventMessageStop, EventError:
		default:
			t.Fatalf("accounting or unknown frame classified as non-accounting: %q", body)
		}
	})
}
