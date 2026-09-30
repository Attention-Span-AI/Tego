// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// bigRequest is an ssl_request payload as the forwarder builds one ahead of the blob split: a path, allow-listed
// headers and a large inline body whose text quotes the word headers, as an HTTP tool's arguments do.
func bigRequest(t *testing.T, path string) []byte {
	t.Helper()
	body := strings.Repeat(`{"tool":"http","input":{"headers":{"accept":"*/*"},"url":"https://x"}} `, 1<<14)
	b, err := json.Marshal(map[string]any{
		"path": path, "method": "POST", "headers": map[string]string{"content-type": "application/json"},
		"body": body,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// allocBytes reports the bytes f allocates, averaged over n runs.
func allocBytes(n int, f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range n {
		f()
	}
	runtime.ReadMemStats(&after)
	return (after.TotalAlloc - before.TotalAlloc) / uint64(n)
}

// Redact reads only the top-level headers and path of an ssl_request: its inline body, up to 64 MiB before the
// blob split, is neither decoded nor copied when nothing changes, and copied once when the path is rewritten
// (R9). Decoding the whole payload into a map copied the body on every request.
func TestRedactDoesNotDecodeTheBody(t *testing.T) {
	plain := bigRequest(t, "/v1/messages")
	got := allocBytes(5, func() {
		e := record.Event{Kind: record.KindSSLRequest, Payload: plain}
		if err := Redact(&e); err != nil {
			t.Fatal(err)
		}
		if &e.Payload[0] != &plain[0] {
			t.Fatal("a payload with nothing to remove was rewritten")
		}
	})
	if limit := uint64(len(plain) / 16); got > limit {
		t.Errorf("Redact of a %d-byte request with nothing to remove allocated %d bytes; want under %d", len(plain), got, limit)
	}

	query := bigRequest(t, "/v1/messages?beta=true")
	got = allocBytes(5, func() {
		e := record.Event{Kind: record.KindSSLRequest, Payload: query}
		if err := Redact(&e); err != nil {
			t.Fatal(err)
		}
	})
	if limit := uint64(len(query)) + uint64(len(query))/8; got > limit {
		t.Errorf("Redact of a %d-byte request with a query allocated %d bytes; want one copy, under %d", len(query), got, limit)
	}
	e := record.Event{Kind: record.KindSSLRequest, Payload: append([]byte(nil), query...)}
	if err := Redact(&e); err != nil {
		t.Fatal(err)
	}
	var in, out map[string]json.RawMessage
	if err := json.Unmarshal(query, &in); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(e.Payload, &out); err != nil {
		t.Fatalf("rewritten payload does not parse: %v", err)
	}
	if string(out["path"]) != `"/v1/messages?redacted"` || string(out["body"]) != string(in["body"]) ||
		string(out["headers"]) != string(in["headers"]) || len(out) != len(in) {
		t.Errorf("rewrite changed more than the path: path %s, %d members", out["path"], len(out))
	}
}

// A key's opening quote is never escaped, so an escaped quote in a string value ("say \"headers\"") does not
// start a key match.
func TestContainsKeyFoldSkipsEscapedQuotes(t *testing.T) {
	for payload, want := range map[string]bool{
		`{"body":"say \"headers\" now"}`: false,
		`{"body":"a \\"}`:                false,
		`{"body":"a \\","headers":{}}`:   true,
		`{"Headers":1}`:                  true,
	} {
		if got := containsKeyFold([]byte(payload), HeadersField); got != want {
			t.Errorf("containsKeyFold(%s) = %v, want %v", payload, got, want)
		}
	}
}

// Redact walks the top level itself, so it must bound every value shape and refuse a structure it cannot.
func TestRedactTopLevelWalk(t *testing.T) {
	for _, tc := range []struct{ payload, want string }{
		{`{"a":[1,{"b":"}\"]"}],"n":-1.5e3,"t":true,"z":null,"headers":{"cookie":"c"}}`, `{"a":[1,{"b":"}\"]"}],"n":-1.5e3,"t":true,"z":null}`},
		{` { "headers" : { "Content-Type" : "a" } , "x":"\\" } `, `{"headers":{"content-type":"a"},"x":"\\"}`},
		{`{"x":"a\\\"headers\\","headers":{"x-api-key":"k"}}`, `{"x":"a\\\"headers\\"}`},
		{`{"headers":{"authorization":"b","request-id":"r"}}`, `{"headers":{"request-id":"r"}}`},
	} {
		e := record.Event{Kind: record.KindSSLResponse, Payload: []byte(tc.payload)}
		if err := Redact(&e); err != nil {
			t.Fatalf("Redact(%s): %v", tc.payload, err)
		}
		if string(e.Payload) != tc.want {
			t.Errorf("Redact(%s) = %s, want %s", tc.payload, e.Payload, tc.want)
		}
	}
	for _, bad := range []string{`{"headers":`, `["headers"]`, `{"headers":{}}x`, `{"headers" {}}`, `{"headers":{} "a":1}`, `{"headers":"x`} {
		e := record.Event{Kind: record.KindSSLResponse, Payload: []byte(bad)}
		if err := Redact(&e); err == nil {
			t.Errorf("Redact(%s) accepted a malformed payload: %s", bad, e.Payload)
		}
	}
}

// FuzzRedactAnyObject holds the top-level walk to encoding/json on any payload: a valid JSON object is never
// refused, comes out valid, keeps no header a reader would decode outside the allow-list and no ssl_request
// query value, and a second pass leaves it as the first did (R9, R9a).
func FuzzRedactAnyObject(f *testing.F) {
	for _, s := range []string{
		`{"headers":{"x-api-key":"k"},"path":"/v1?k=v","body":"say \"headers\""}`,
		`{"a":[1,{"b":"}\"]"}],"Headers":{"Cookie":"c"},"PATH":"/x?y=z"}`,
		` {"x":"\\","headers":[],"path":1} `, `{"headers":{"content-type":"a"},"headers":{"cookie":"c"}}`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, payload string) {
		var obj map[string]json.RawMessage
		if json.Unmarshal([]byte(payload), &obj) != nil || obj == nil {
			return
		}
		e := &record.Event{Kind: record.KindSSLRequest, Payload: []byte(payload)}
		if err := Redact(e); err != nil {
			t.Fatalf("Redact refused a valid object: %v\n%s", err, payload)
		}
		first := string(e.Payload)
		if err := Redact(e); err != nil || string(e.Payload) != first {
			t.Fatalf("Redact is not idempotent (%v):\n%s\n%s", err, first, e.Payload)
		}
		var got struct {
			Path    *string
			Headers map[string]json.RawMessage
		}
		if err := json.Unmarshal([]byte(first), &got); err != nil {
			t.Fatalf("Redact wrote a payload that does not parse: %v\n%s\n%s", err, payload, first)
		}
		for name := range got.Headers {
			if _, ok := allowedHeaders[name]; !ok {
				t.Fatalf("header %q reached the payload: %s", name, first)
			}
		}
		if got.Path != nil && RedactTarget(*got.Path) != *got.Path {
			t.Fatalf("an unredacted target reached the payload: %s", first)
		}
	})
}
