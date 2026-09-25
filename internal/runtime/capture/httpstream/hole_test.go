// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// kernelCall feeds one SSL_write or SSL_read the way bpf/uprobe_ssl.bpf.c emits it: at most four chunks of
// 32 KiB, and when the call moved more, the last one says how many bytes followed it that the probe dropped.
func kernelCall(a *Assembler, key ConnKey, dir Direction, wire []byte) ([]*Message, error) {
	const chunk, chunks = 32 << 10, 4
	var out []*Message
	for i := 0; i < chunks && i*chunk < len(wire); i++ {
		end := min((i+1)*chunk, len(wire))
		ch := Chunk{Data: wire[i*chunk : end]}
		if i == chunks-1 && len(wire) > end {
			ch.Skipped = uint64(len(wire) - end)
		}
		msgs, err := a.Feed(key, dir, ch)
		out = append(out, msgs...)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// bigRequest is a request whose whole wire form is one call longer than R6's 128 KiB, as CPython writes one:
// SSLSocket.sendall hands httpx's request, head and body together, to a single SSL_write_ex.
func bigRequest(bodyLen int) []byte {
	body := `{"model":"opus","messages":[` + strings.Repeat(`{"role":"user","content":"x"},`, bodyLen/30)
	body = body[:bodyLen]
	return []byte(fmt.Sprintf("POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n"+
		"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", bodyLen, body))
}

// TestHoleInsideABodyKeepsTheConnection: one SSL_write over 128 KiB killed capture on its
// connection. The kernel emitted four 32 KiB chunks and recorded the dropped length nowhere, so the request's
// Content-Length still counted the dropped bytes, the request never completed, its response paired with
// nothing, and every later exchange on the connection was lost under one malformed count. The hole is named
// now (Chunk.Skipped): the request is recorded as its truncated prefix, as edge case #8 promises, and all six
// exchanges on the connection are recorded.
func TestHoleInsideABodyKeepsTheConnection(t *testing.T) {
	a := NewAssembler(Options{})
	const bodyLen = 300 << 10
	wire := bigRequest(bodyLen)
	msgs, err := kernelCall(a, testKey, DirRequest, wire)
	if err != nil {
		t.Fatalf("the call over 128 KiB: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("%d messages from the call over 128 KiB, want its request", len(msgs))
	}
	first := msgs[0]
	head := len(wire) - bodyLen
	if !first.Truncated || len(first.Body) != 128<<10-head || string(first.Body) != string(wire[head:128<<10]) {
		t.Errorf("request truncated=%v with a %d-byte body, want the truncated %d-byte prefix", first.Truncated,
			len(first.Body), 128<<10-head)
	}
	resp, err := a.Feed(testKey, DirResponse, Chunk{Data: httpResponse("200 OK", nil, []byte(`{"r":0}`))})
	if err != nil || len(resp) != 1 || resp[0].RequestIndex != first.Index {
		t.Fatalf("the response to the call over 128 KiB: %d messages, %v", len(resp), err)
	}
	rest, err := keepAlive(a, testKey, 5)
	if err != nil {
		t.Fatalf("the exchanges after it: %v", err)
	}
	if len(rest) != 10 {
		t.Fatalf("%d messages after the call over 128 KiB, want the 5 exchanges' 10", len(rest))
	}
	for i := 0; i < len(rest); i += 2 {
		if rest[i+1].RequestIndex != rest[i].Index || rest[i].Truncated || rest[i+1].Truncated {
			t.Errorf("exchange %d after the hole: response answers %d, request %d", i/2+1, rest[i+1].RequestIndex,
				rest[i].Index)
		}
	}
	if len(a.Gaps()) != 0 {
		t.Errorf("gaps %v for a hole inside a body, which the connection steps over", a.Gaps())
	}
}

// TestHoleInsideAChunkedBody: the data of one chunk says how far it reaches, so a hole inside it is stepped
// over like one inside a Content-Length body; the size lines after it are read as they come.
func TestHoleInsideAChunkedBody(t *testing.T) {
	a := NewAssembler(Options{})
	data := strings.Repeat("d", 200<<10)
	wire := []byte(fmt.Sprintf("POST /v1/messages HTTP/1.1\r\nHost: api\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s",
		len(data), data))
	msgs, err := kernelCall(a, testKey, DirRequest, wire)
	if err != nil || len(msgs) != 0 {
		t.Fatalf("the chunked call over 128 KiB: %d messages, %v", len(msgs), err)
	}
	msgs, err = a.Feed(testKey, DirRequest, Chunk{Data: []byte("\r\n5\r\nhello\r\n0\r\n\r\n")})
	if err != nil || len(msgs) != 1 {
		t.Fatalf("the rest of the chunked body: %d messages, %v", len(msgs), err)
	}
	m := msgs[0]
	if !m.Truncated || strings.Contains(string(m.Body), "hello") || strings.Count(string(m.Body), "d") != len(m.Body) {
		t.Errorf("chunked request truncated=%v, body of %d bytes (hello kept: %v), want the prefix before the hole",
			m.Truncated, len(m.Body), strings.Contains(string(m.Body), "hello"))
	}
	resp, err := a.Feed(testKey, DirResponse, Chunk{Data: httpResponse("200 OK", nil, []byte(`{"r":0}`))})
	if err != nil || len(resp) != 1 {
		t.Fatalf("the response: %d messages, %v", len(resp), err)
	}
	rest, err := keepAlive(a, testKey, 2)
	if err != nil || len(rest) != 4 {
		t.Fatalf("the exchanges after it: %d messages, %v", len(rest), err)
	}
	if len(a.Gaps()) != 0 {
		t.Errorf("gaps %v", a.Gaps())
	}
}

// TestHoleThatEndsTheBody: a hole that reaches exactly the body's end completes the message there.
func TestHoleThatEndsTheBody(t *testing.T) {
	a := NewAssembler(Options{})
	msgs, err := a.Feed(testKey, DirRequest, Chunk{
		Data:    []byte("POST /v1/messages HTTP/1.1\r\nHost: api\r\nContent-Length: 10\r\n\r\n0123"),
		Skipped: 6,
	})
	if err != nil || len(msgs) != 1 || !msgs[0].Truncated || string(msgs[0].Body) != "0123" {
		t.Fatalf("got %d messages, %v", len(msgs), err)
	}
}

// TestHoleAfterAnUnreadableChunk: a chunk whose plaintext the probe could not read arrives with no data and
// the whole of its length as the hole, and is stepped over like any other hole in a body.
func TestHoleAfterAnUnreadableChunk(t *testing.T) {
	a := NewAssembler(Options{})
	var got []*Message
	for _, f := range []struct {
		dir Direction
		ch  Chunk
	}{
		{DirRequest, Chunk{Data: []byte(postRequest(`{"n":0}`))}},
		{DirResponse, Chunk{Data: []byte("HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nabc")}},
		{DirResponse, Chunk{Skipped: 10}}, // the probe could not read this chunk's 10 bytes
		{DirResponse, Chunk{Data: []byte("0123456")}},
	} {
		msgs, err := a.Feed(testKey, f.dir, f.ch)
		if err != nil {
			t.Fatalf("%s chunk: %v", f.dir, err)
		}
		got = append(got, msgs...)
	}
	if len(got) != 2 || got[1].Dir != DirResponse || !got[1].Truncated || string(got[1].Body) != "abc" {
		t.Fatalf("got %d messages, want the request and its truncated response with the prefix before the hole", len(got))
	}
	rest, err := keepAlive(a, testKey, 2)
	if err != nil || len(rest) != 4 {
		t.Fatalf("the exchanges after it: %d messages, %v", len(rest), err)
	}
}

// TestHoleCrossingTheFraming: a hole whose end the framing cannot place gaps the connection.
func TestHoleCrossingTheFraming(t *testing.T) {
	cases := []struct {
		name string
		data string
		hole uint64
	}{
		{"past the body's end", "POST / HTTP/1.1\r\nHost: api\r\nContent-Length: 10\r\n\r\n0123", 7},
		{"inside the header block", "POST / HTTP/1.1\r\nHost: api\r\nContent-Le", 3},
		{"inside a chunk-size line", "POST / HTTP/1.1\r\nHost: api\r\nTransfer-Encoding: chunked\r\n\r\n1", 3},
		{"past one chunk's data", "POST / HTTP/1.1\r\nHost: api\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab", 4},
		{"at a message boundary", "POST / HTTP/1.1\r\nHost: api\r\nContent-Length: 2\r\n\r\nab", 30},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAssembler(Options{})
			_, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte(tc.data), Skipped: tc.hole})
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
			if got := gapCount(a.Gaps(), GapMalformed); got != 1 {
				t.Errorf("malformed = %d, want 1", got)
			}
		})
	}
}
