// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// An ssl event whose producer recorded RecordedHeaders has nothing for Redact to remove, so its payload is
// left as written: re-encoding it would walk the whole unsplit body, up to 64 MiB, for nothing (R9). The
// key order and spacing below are ones marshalPayload would change, so a rewrite shows.
func TestRedactLeavesAllowListedHeadersByteIdentical(t *testing.T) {
	body := `"{\"model\":\"m\",\"messages\":[{\"content\":\"say \\\"hi\\\"\"}]}"`
	for _, tc := range []struct {
		kind    record.Kind
		payload string
	}{
		{record.KindSSLResponse, `{"status":200, "headers":{"request-id":"r1","content-type":"application/json"},"body":` + body + `}`},
		{record.KindSSLRequest, `{"path":"/v1/messages", "method":"POST","headers":{"content-type":"application/json"},"body":` + body + `}`},
	} {
		e := record.Event{Kind: tc.kind, Payload: []byte(tc.payload)}
		if err := Redact(&e); err != nil {
			t.Fatal(err)
		}
		if string(e.Payload) != tc.payload {
			t.Errorf("%s: payload rewritten with nothing to remove:\n got %s\nwant %s", tc.kind, e.Payload, tc.payload)
		}
	}
}

// A headers object that is not already its filtered self is still rewritten: an upper-case allowed name,
// a denied name, and an empty object each change the payload. Only the headers member is rewritten; the
// others keep their place and bytes (MarshalLine sorts the line's payload keys later).
func TestRedactRewritesHeadersThatNeedIt(t *testing.T) {
	for _, tc := range []struct{ payload, want string }{
		{`{"headers":{"Content-Type":"a"},"body":"b"}`, `{"headers":{"content-type":"a"},"body":"b"}`},
		{`{"headers":{"content-type":"a","x-api-key":"k"},"body":"b"}`, `{"headers":{"content-type":"a"},"body":"b"}`},
		{`{"headers":{},"body":"b"}`, `{"body":"b"}`},
		{`{"Headers":{"content-type":"a"},"body":"b"}`, `{"Headers":{"content-type":"a"},"body":"b"}`},
	} {
		e := record.Event{Kind: record.KindSSLResponse, Payload: []byte(tc.payload)}
		if err := Redact(&e); err != nil {
			t.Fatal(err)
		}
		if string(e.Payload) != tc.want {
			t.Errorf("Redact(%s) = %s, want %s", tc.payload, e.Payload, tc.want)
		}
	}
}

// A backslash that is not a \u escape cannot spell a key's letter, so an exec event whose argv holds an
// escaped quote takes the substring shortcut rather than a decode of the whole payload.
func TestRedactSkipsDecodeForNonUnicodeEscape(t *testing.T) {
	payload := []byte(`{"argv":["sh","-c","echo \"a\\b\"\n"],"path":"/bin/sh"}`)
	allocs := testing.AllocsPerRun(20, func() {
		e := record.Event{Kind: record.KindExec, Payload: payload}
		if err := Redact(&e); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Errorf("Redact of an exec payload with no headers key allocated %v times; want the shortcut", allocs)
	}
	// A \u escape still forces the decode, which finds the key it spells.
	e := record.Event{Kind: record.KindExec, Payload: []byte(`{"headers":{"cookie":"c"},"path":"/bin/sh"}`)}
	if err := Redact(&e); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(e.Payload), "cookie") {
		t.Errorf("escaped headers key kept its cookie: %s", e.Payload)
	}
}
