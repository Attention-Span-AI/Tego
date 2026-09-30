// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// checkRedactedTarget asserts R9a's fixed output vocabulary, rather than trying to identify secrets in
// arbitrary client text. Every target reduces to one public route and an optional constant query marker.
func checkRedactedTarget(t *testing.T, in, out string) {
	t.Helper()
	if again := RedactTarget(out); again != out {
		t.Fatalf("RedactTarget is not idempotent: %q -> %q -> %q", in, out, again)
	}
	path, query, hasQuery := strings.Cut(out, "?")
	if hasQuery && query != "redacted" {
		t.Fatalf("RedactTarget(%q) = %q keeps query text", in, out)
	}
	switch path {
	case "*", "/", "/redacted", "/v1/messages", "/v1/messages/count_tokens", "/v1/chat/completions",
		"/v1/responses", "/v1/models", "/v1/files", "/v1/messages/batches":
	default:
		t.Fatalf("RedactTarget(%q) = %q keeps an arbitrary path or authority", in, out)
	}
}

// FuzzRedactTarget is record-ledger.md R9a's promise over any target: see checkRedactedTarget.
func FuzzRedactTarget(f *testing.F) {
	for _, s := range []string{
		"/v1/messages", "/v1/models/gemini:generateContent?key=AIzaSyREAL", "/f?code=abc&alt=json", "/f?verbose",
		"/v1/messages?sk-ant-api03-SECRET", "/f?token=a=b=c", "/f?", "http://user:pw@api.example.com/v1/m",
		"https://u:p@h/v1?key=s", "http://h/v1/a@b", "/v1//a@b/c", "api.example.com:443", "*", "1a://h/p",
		"a://b@c://d@e/?x=1", "http://u?x@host/p", "h://@", "s://a@b@c?d@e=f&&g",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, target string) {
		checkRedactedTarget(t, target, RedactTarget(target))
	})
}

// FuzzRedact is record-ledger.md R9 and R9a at the stage: an event's payload, built as every producer builds one
// (record.Event.SetPayload, which is json.Marshal), comes out with only allow-listed header names, an
// ssl_request's path holding to checkRedactedTarget and any other kind's path byte for byte as it went in,
// and a second pass leaves the bytes as the first did.
func FuzzRedact(f *testing.F) {
	f.Add(uint8(0), "/v1/messages?key=secret", "x-api-key", "sk-ant-secret", "Content-Type", "application/json")
	f.Add(uint8(0), "http://u:p@h/v1?sk-ant-api03-SECRETSECRET", "Authorization", "Bearer x", "request-id", "r-1")
	f.Add(uint8(1), "/v1/messages?key=secret", "COOKIE", "a=b", "anthropic-version", "2023-06-01")
	f.Add(uint8(2), "/tmp/a?b=c", "", "", "user-agent", "x")
	f.Add(uint8(3), "/home/u/f?key=v", "Traceparent", "00-x", "traceparent", "00-y")
	kinds := []record.Kind{record.KindSSLRequest, record.KindSSLResponse, record.KindExec, record.KindFS}
	f.Fuzz(func(t *testing.T, kind uint8, path, h1, v1, h2, v2 string) {
		k := kinds[int(kind)%len(kinds)]
		in, err := json.Marshal(map[string]any{"path": path, "headers": map[string]string{h1: v1, h2: v2}, "method": "POST"})
		if err != nil {
			t.Fatal(err)
		}
		var sent struct{ Path string }
		if err := json.Unmarshal(in, &sent); err != nil {
			t.Fatal(err)
		}
		e := &record.Event{Kind: k, Payload: in}
		if err := Redact(e); err != nil {
			t.Fatalf("Redact refused a payload json.Marshal made: %v\n%s", err, in)
		}
		first := append([]byte(nil), e.Payload...)
		if err := Redact(e); err != nil || !bytes.Equal(e.Payload, first) {
			t.Fatalf("Redact is not idempotent (%v):\n%s\n%s", err, first, e.Payload)
		}
		var got struct {
			Path    *string
			Headers map[string]json.RawMessage
		}
		if err := json.Unmarshal(first, &got); err != nil {
			t.Fatalf("Redact wrote a payload that does not parse: %v\n%s", err, first)
		}
		for name := range got.Headers {
			if _, ok := allowedHeaders[name]; !ok {
				t.Fatalf("header %q reached the payload: %s", name, first)
			}
		}
		if got.Path == nil {
			t.Fatalf("Redact dropped a string path: %s", first)
		}
		if k == record.KindSSLRequest {
			checkRedactedTarget(t, sent.Path, *got.Path)
		} else if *got.Path != sent.Path {
			t.Fatalf("a %s path changed: %q -> %q", k, sent.Path, *got.Path)
		}
	})
}
