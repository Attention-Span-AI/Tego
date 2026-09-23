// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRedactTarget covers the second place a captured request carries a credential. The capture tier reads
// whatever TLS traffic the agent generates, so the request target reaching the ledger is whatever the agent's
// HTTP client put on the wire, query string and all.
func TestRedactTarget(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"static route", "/v1/messages", "/v1/messages"},
		{"short path secret", "/v1/secret123", "/redacted"},
		{"short bare query secret", "/v1/messages?secret123", "/v1/messages?redacted"},
		{"short parameter name secret", "/v1/messages?secret123=", "/v1/messages?redacted"},
		{"dynamic model and query", "/v1/models/gemini:generateContent?key=AIzaSyREAL", "/redacted?redacted"},
		{"unknown route and query names", "/f?code=abc&alt=json", "/redacted?redacted"},
		{"bare flag", "/v1/messages?verbose", "/v1/messages?redacted"},
		{"bare token", "/v1/messages?sk-ant-api03-SECRET", "/v1/messages?redacted"},
		{"empty query", "/v1/messages?", "/v1/messages?redacted"},
		{"empty target", "", "/redacted"},
		{"userinfo and authority", "http://user:pw@api.example.com/v1/messages", "/v1/messages"},
		{"absolute query", "https://u:p@secret-host/v1/messages?key=s", "/v1/messages?redacted"},
		{"absolute empty path", "http://user:pw@secret-host?key=s", "/?redacted"},
		{"at sign path", "http://h/v1/a@b", "/redacted"},
		{"double slash path", "/v1//a@b/c", "/redacted"},
		{"authority form", "api.example.com:443", "/redacted"},
		{"asterisk form", "*", "*"},
		{"invalid scheme", "1a://h/v1/messages", "/redacted"},
		{"resource ID", "/v1/files/secret123", "/redacted"},
		{"encoded secret", "/v1/messages%2fsecret123", "/redacted"},
		{"encoded route", "/v1/%6dessages", "/redacted"},
		{"route prefix", "/v1/messages/secret123", "/redacted"},
		{"fragment", "/v1/messages#secret123?secret456", "/v1/messages"},
		{"query and fragment", "/v1/messages?secret123#secret456", "/v1/messages?redacted"},
		{"already redacted", "/redacted?redacted", "/redacted?redacted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RedactTarget(tc.in); got != tc.want {
				t.Errorf("RedactTarget(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestRedactSSLRequestPath is the guarantee end to end: a query-string credential on an ssl_request never
// reaches the payload the writer would append.
func TestRedactSSLRequestPath(t *testing.T) {
	const secret = "AIzaSyTHIS-MUST-NOT-REACH-DISK"
	e := &record.Event{Kind: record.KindSSLRequest, Source: record.SourceSSL}
	if err := e.SetPayload(record.SSLRequestPayload{
		Endpoint: "google", Method: "POST", Host: "generativelanguage.googleapis.com",
		Path:    "/v1/models/gemini:generateContent?key=" + secret,
		Headers: map[string]string{"x-api-key": "sk-ant-also-secret", "content-type": "application/json"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := Redact(e); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(e.Payload), secret) {
		t.Errorf("the query credential survived redaction: %s", e.Payload)
	}
	if strings.Contains(string(e.Payload), "sk-ant-also-secret") {
		t.Errorf("the header credential survived redaction: %s", e.Payload)
	}
	var got record.SSLRequestPayload
	if err := json.Unmarshal(e.Payload, &got); err != nil {
		t.Fatal(err)
	}
	if want := "/redacted?redacted"; got.Path != want {
		t.Errorf("path %q, want %q", got.Path, want)
	}
	if _, ok := got.Headers["content-type"]; !ok {
		t.Errorf("the allowed header did not survive: %v", got.Headers)
	}
}

// TestRedactLeavesFilesystemPaths is the scoping rule: exec and fs carry a path too, and theirs is a
// filesystem path the kernel reported. A '?' in a filename is legal and must survive byte for byte.
func TestRedactLeavesFilesystemPaths(t *testing.T) {
	for _, k := range []record.Kind{record.KindFS, record.KindExec} {
		t.Run(string(k), func(t *testing.T) {
			e := &record.Event{Kind: k, Source: record.SourceLandlock}
			if err := e.SetPayload(map[string]string{"op": "open", "path": "/w/report?draft=2&key=v"}); err != nil {
				t.Fatal(err)
			}
			before := string(e.Payload)
			if err := Redact(e); err != nil {
				t.Fatal(err)
			}
			if string(e.Payload) != before {
				t.Errorf("a %s path was rewritten:\n got %s\nwant %s", k, e.Payload, before)
			}
		})
	}
}

// TestRedactDropsNonStringPath mirrors the headers rule: a shape the ledger cannot inspect is dropped rather
// than persisted unexamined.
func TestRedactDropsNonStringPath(t *testing.T) {
	e := &record.Event{Kind: record.KindSSLRequest, Source: record.SourceSSL}
	e.Payload = json.RawMessage(`{"path":{"nested":"secret"},"method":"POST"}`)
	if err := Redact(e); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(e.Payload), "secret") {
		t.Errorf("an uninspectable path was persisted: %s", e.Payload)
	}
	if !strings.Contains(string(e.Payload), `"method"`) {
		t.Errorf("redaction removed more than the path: %s", e.Payload)
	}
}
