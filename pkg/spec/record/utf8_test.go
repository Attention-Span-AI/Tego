// SPDX-License-Identifier: Apache-2.0

package record

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"unicode/utf8"
)

// This file pins E18's sanitization against I9's round trip. The two used to disagree: the codec compared and
// sorted decoded keys but wrote UTF-8-sanitized ones, and wrote invalid bytes as the "�" escape while
// reading them back as the U+FFFD rune. Every case below produced a line MarshalLine(Decode(line)) did not
// reproduce -- and the first one produced a line Decode rejected outright.

// TestMarshalLineRejectsKeysCollidingAfterSanitization pins the encode-time half of E18 for payload *keys*.
// Two keys that differ only in invalid UTF-8 are one key once sanitized (E18), so they are one duplicate key
// (the rule payloadFields already applies to `{"a":1,"a":2}`) and the event must be rejected. Before, they were
// compared raw and so passed as distinct, and canonical then wrote the same key twice: a line with a valid id
// that VerifyLine accepted but Decode rejected as malformed -- which in a ledger stops Reader.Iter at that line
// and fails Writer.resume for the rest of the run's life.
func TestMarshalLineRejectsKeysCollidingAfterSanitization(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
	}{
		{"two raw invalid bytes", "{\"a\xfe\":1,\"a\xff\":2}"},
		// One key raw, one already spelled as the escape: unquote takes its fast path on the first and its
		// json.Unmarshal path on the second, and both must still land on the same sanitized key.
		{"raw byte and \\ufffd escape", "{\"a\xfe\":1,\"a\\ufffd\":2}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := base(KindGap, tc.payload)
			line, err := e.MarshalLine()
			if !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("MarshalLine = (%s, %v), want ErrInvalidEvent", line, err)
			}
			if line != nil || e.ID != "" {
				t.Fatalf("on error no bytes and no id: %q %q", line, e.ID)
			}
		})
	}
}

// TestLineRoundTripsInvalidUTF8 pins I9 ("MarshalLine(Decode(line)) reproduces a canonical line byte for byte")
// for every place a string reaches a line: a payload key, the sort order those keys are written in, a common
// field and an attribution field. Sanitization has to be a fixed point of the codec, or a decoded event
// re-serializes to different bytes and therefore to a different id.
//
// Also pins record-ledger.md E18: invalid UTF-8 is replaced, never corrupting the line.
func TestLineRoundTripsInvalidUTF8(t *testing.T) {
	refused := func(rule string) *Event {
		e := base(KindRefused, `{"op":"open","target":"/x"}`)
		e.Rule, e.Reason = rule, ReasonReadDenied
		return e
	}
	payload := func(raw string) *Event {
		e := base(KindGap, "")
		e.Payload = json.RawMessage(raw)
		return e
	}
	thread := func(id string) *Event {
		e := action(KindFS, `{"op":"open","path":"/x"}`)
		e.Attr = AttributedByTime(id, 3)
		return e
	}
	for _, tc := range []struct {
		name  string
		event *Event
	}{
		{"payload key", payload("{\"a\xfe\":1}")},
		// "a\xe0" sorts before "aࠀ" by raw bytes but after it once sanitized to "a�" (0xef > 0xe0),
		// so a codec that sorts on the raw key writes the two in an order Decode's re-sort does not reproduce.
		{"payload key sort order", payload("{\"a\xe0\":1,\"aࠀ\":2}")},
		{"payload value", payload("{\"p\":\"a\xfe\xffb\"}")},
		{"common field", refused("fs.deny_read[a\xff]")},
		{"attribution field", thread("t\xff1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, err := tc.event.MarshalLine()
			if err != nil {
				t.Fatal(err)
			}
			if !utf8.Valid(line) {
				t.Fatalf("a written line must itself be valid UTF-8: %q", line)
			}
			got, err := Decode(line)
			if err != nil {
				t.Fatalf("Decode of a line this package wrote: %v (line %s)", err, line)
			}
			again, err := got.MarshalLine()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(line, again) {
				t.Fatalf("I9: re-serialization differs\n first: %s\n again: %s", line, again)
			}
			if got.ID != tc.event.ID {
				t.Fatalf("I9: id changed across the round trip: %s -> %s", tc.event.ID, got.ID)
			}
		})
	}
}

// TestUTF8SanitizationIsUniformAcrossTheLine pins that the package has one sanitizer, not two. compactValue
// used strings.ToValidUTF8, which collapses a run of invalid bytes into a single U+FFFD, while writeJSONString
// replaced each byte: the same two bytes rendered as one replacement in a payload value and two in a common
// field, on the same line.
func TestUTF8SanitizationIsUniformAcrossTheLine(t *testing.T) {
	e := base(KindRefused, "{\"op\":\"open\",\"target\":\"a\xfe\xffb\"}")
	e.Rule, e.Reason = "a\xfe\xffb", ReasonReadDenied
	line := mustLine(t, e)
	const want = "a��b" // one replacement per invalid byte, as encoding/json maps them
	if !bytes.Contains(line, []byte(`"rule":"`+want+`"`)) {
		t.Errorf("common field: want %q in %s", want, line)
	}
	if !bytes.Contains(line, []byte(`"target":"`+want+`"`)) {
		t.Errorf("payload value: want %q in %s", want, line)
	}
}
