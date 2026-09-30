// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"strings"
	"testing"
)

// TestDecodeFailureKeepsTheConnection covers R15: a body that was framed whole but will not decode costs
// that body one gap why=malformed, and the connection's next exchange is captured.
func TestDecodeFailureKeepsTheConnection(t *testing.T) {
	for _, coding := range []string{"gzip", "compress", "gzip, gzip, gzip"} {
		t.Run(coding, func(t *testing.T) {
			a := NewAssembler(Options{})
			msgs, err := feedAll(a, testKey,
				req(postRequest(reqBody)),
				respBytes(httpResponse("200 OK", []string{"Content-Encoding: " + coding}, []byte("xxxxx"))))
			if err != nil {
				t.Fatalf("a decode failure returned an error: %v", err)
			}
			if len(msgs) != 2 || !msgs[1].Truncated {
				t.Fatalf("messages = %+v", msgs)
			}
			if n := gapCount(a.Gaps(), GapMalformed); n != 1 {
				t.Fatalf("malformed = %d, want 1: %v", n, a.Gaps())
			}
			rest, err := keepAlive(a, testKey, 2)
			if err != nil {
				t.Fatalf("later exchange: %v", err)
			}
			if len(rest) != 4 || string(rest[3].Body) != `{"r":1}` || rest[3].RequestIndex != rest[2].Index {
				t.Fatalf("later exchanges not captured and paired: %d messages", len(rest))
			}
			if n := gapCount(a.Gaps(), GapMalformed); n != 1 {
				t.Errorf("malformed = %d after the later exchanges, want still 1", n)
			}
		})
	}
}

// TestUndecodableSSEKeepsWireBytes covers R15: an event stream in a coding the package cannot undo is kept
// as the wire carried it, not reduced to nothing as non-data lines.
func TestUndecodableSSEKeepsWireBytes(t *testing.T) {
	wireBody := "data: hi\n\n"
	a := NewAssembler(Options{})
	msgs, err := feedAll(a, testKey,
		req(postRequest(reqBody)),
		respBytes(httpResponse("200 OK", []string{"Content-Type: text/event-stream", "Content-Encoding: foo"}, []byte(wireBody))))
	if err != nil || len(msgs) != 2 {
		t.Fatalf("msgs=%d err=%v", len(msgs), err)
	}
	if string(msgs[1].Body) != wireBody || !msgs[1].SSE {
		t.Fatalf("body = %q SSE=%v, want the wire bytes kept", msgs[1].Body, msgs[1].SSE)
	}
}

// TestSplitContentEncodingLinesAreOneList covers R15: repeated Content-Encoding field lines form one list
// (RFC 9110 §5.3), so a gzip after an identity line is undone, not kept compressed and labelled identity.
func TestSplitContentEncodingLinesAreOneList(t *testing.T) {
	a := NewAssembler(Options{})
	msgs, err := feedAll(a, testKey,
		req(postRequest(reqBody)),
		respBytes(httpResponse("200 OK", []string{"Content-Encoding: identity", "Content-Encoding: gzip"}, gzipBytes(t, []byte("hello")))))
	if err != nil || len(msgs) != 2 {
		t.Fatalf("msgs=%d err=%v", len(msgs), err)
	}
	if string(msgs[1].Body) != "hello" {
		t.Fatalf("body=%q encoding=%q, want the decoded body", msgs[1].Body, msgs[1].ContentEncoding)
	}
}

// TestWireBytesCountsACutBody covers R11: WireBytes is the wire's length even when MaxBody kept less.
func TestWireBytesCountsACutBody(t *testing.T) {
	body := strings.Repeat("a", 100)
	a := NewAssembler(Options{MaxBody: 10})
	msgs, err := feedAll(a, testKey, req(postRequest(body)))
	if err != nil || len(msgs) != 1 {
		t.Fatalf("msgs=%d err=%v", len(msgs), err)
	}
	if len(msgs[0].Body) != 10 || msgs[0].WireBytes != 100 {
		t.Fatalf("kept %d, WireBytes %d, want 10 and 100", len(msgs[0].Body), msgs[0].WireBytes)
	}
}
