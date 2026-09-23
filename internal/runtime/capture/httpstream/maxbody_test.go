// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"testing"
)

// TestMaxBodyBoundsWhatIsHeld is the difference between a flag and a bound.
//
// MaxBody is documented as "how much of one body capture keeps in memory". It was applied when
// decompressing, and again at completion to decide the Truncated flag, but never to the buffer the
// body accumulates into. So an encoded body really was cut to the cap while an unencoded one of the
// same size was kept whole and merely labelled truncated: the same flag, a different amount of memory.
//
// The bound has to be on the write. A body is assembled before anything looks at its size, so a check
// at completion bounds what is kept and not what is held, and the bytes are chosen by whatever server
// the agent is talking to while the launcher is the trusted process holding them.
func TestMaxBodyBoundsWhatIsHeld(t *testing.T) {
	const cap0 = 1024
	big := strings.Repeat("x", 64*1024)

	cases := []struct {
		name string
		resp func() []byte
	}{
		{"content-length", func() []byte {
			return []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(big), big))
		}},
		{"chunked", func() []byte {
			var b bytes.Buffer
			b.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
			for i := 0; i < len(big); i += 4096 {
				end := min(i+4096, len(big))
				fmt.Fprintf(&b, "%x\r\n%s\r\n", end-i, big[i:end])
			}
			b.WriteString("0\r\n\r\n")
			return b.Bytes()
		}},
		{"gzip", func() []byte {
			var z bytes.Buffer
			w := gzip.NewWriter(&z)
			_, _ = w.Write([]byte(big))
			_ = w.Close()
			return []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n%s",
				z.Len(), z.String()))
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAssembler(Options{MaxBody: cap0})
			key := ConnKey{PidTgid: 1, SSLPtr: 2}
			if _, err := a.Feed(key, DirRequest, Chunk{Data: []byte("POST /v1/messages HTTP/1.1\r\nHost: api\r\nContent-Length: 0\r\n\r\n")}); err != nil {
				t.Fatalf("request: %v", err)
			}
			msgs, err := a.Feed(key, DirResponse, Chunk{Data: tc.resp()})
			if err != nil {
				t.Fatalf("response: %v", err)
			}
			var resp *Message
			for _, m := range msgs {
				if m.Dir == DirResponse {
					resp = m
				}
			}
			if resp == nil {
				t.Fatalf("no response completed from %d messages", len(msgs))
			}
			if int64(len(resp.Body)) > cap0 {
				t.Errorf("kept %d body bytes against a %d cap: the cap bounds the flag, not the memory",
					len(resp.Body), cap0)
			}
			if !resp.Truncated {
				t.Error("a body cut to the cap is not marked truncated")
			}
		})
	}
}

// TestMaxBodyZeroKeepsEverything is R14 under its implementation condition: a caller that configures no cap
// gets DefaultMaxBody, so an ordinary body — far below it — is still assembled whole and nothing claims it
// was cut. The cap bounds the launcher's memory against a body chosen by a peer; it must never show up as
// truncation on traffic of a normal size.
func TestMaxBodyZeroKeepsEverything(t *testing.T) {
	body := strings.Repeat("y", 40*1024)
	a := NewAssembler(Options{})
	key := ConnKey{PidTgid: 3, SSLPtr: 4}
	if _, err := a.Feed(key, DirRequest, Chunk{Data: []byte("POST /v1/messages HTTP/1.1\r\nHost: api\r\nContent-Length: 0\r\n\r\n")}); err != nil {
		t.Fatal(err)
	}
	msgs, err := a.Feed(key, DirResponse, Chunk{Data: []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body))})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if m.Dir != DirResponse {
			continue
		}
		if len(m.Body) != len(body) {
			t.Errorf("kept %d of %d bytes with no cap configured", len(m.Body), len(body))
		}
		if m.Truncated {
			t.Error("an uncapped body is marked truncated")
		}
	}
}
