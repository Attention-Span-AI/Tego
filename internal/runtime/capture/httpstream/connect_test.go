// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Finding 6: a 2xx to CONNECT has no body, and what follows on both halves is the tunnel's bytes. They were
// read as a close-delimited body and a malformed request, which gapped the connection.
func TestConnectTunnelIsNotParsed(t *testing.T) {
	a := NewAssembler(Options{})
	key := ConnKey{Src: record.SourceSSL, PidTgid: 1, SSLPtr: 1}
	feed := func(dir Direction, data string) []*Message {
		t.Helper()
		msgs, err := a.Feed(key, dir, Chunk{Data: []byte(data)})
		if err != nil {
			t.Fatalf("feed %s %q: %v", dir, data, err)
		}
		return msgs
	}
	feed(DirRequest, "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n")
	msgs := feed(DirResponse, "HTTP/1.1 200 Connection Established\r\n\r\n\x16\x03\x03\x00\x7a")
	if len(msgs) != 1 || msgs[0].Status != 200 || msgs[0].RequestIndex != 0 || len(msgs[0].Body) != 0 {
		t.Fatalf("the 200 was %+v, want it complete, bodiless and paired with the CONNECT", msgs)
	}
	for range 3 {
		if got := feed(DirRequest, "\x16\x03\x01\x02\x00\x01\x00\x01\xfc"); len(got) != 0 {
			t.Errorf("tunnel bytes gave messages: %+v", got)
		}
		if got := feed(DirResponse, "\x17\x03\x03\x00\x20garbage"); len(got) != 0 {
			t.Errorf("tunnel bytes gave messages: %+v", got)
		}
	}
	if got := a.Close(key); len(got) != 0 {
		t.Errorf("close gave %+v", got)
	}
	if gaps := a.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps %+v, want none: a tunnel loses nothing HTTP capture could read", gaps)
	}
}

// A CONNECT refused (407) is an ordinary exchange, and the connection goes on as HTTP.
func TestConnectRefusedStaysHTTP(t *testing.T) {
	a := NewAssembler(Options{})
	key := ConnKey{Src: record.SourceSSL, PidTgid: 1, SSLPtr: 1}
	if _, err := a.Feed(key, DirRequest, Chunk{Data: []byte("CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org:443\r\n\r\n")}); err != nil {
		t.Fatal(err)
	}
	msgs, err := a.Feed(key, DirResponse, Chunk{Data: httpResponse("407 Proxy Authentication Required", nil, []byte("no"))})
	if err != nil || len(msgs) != 1 || string(msgs[0].Body) != "no" {
		t.Fatalf("407: %+v %v", msgs, err)
	}
	if _, err := a.Feed(key, DirRequest, Chunk{Data: []byte(postRequest(reqBody))}); err != nil {
		t.Fatal(err)
	}
	msgs, err = a.Feed(key, DirResponse, Chunk{Data: httpResponse("200 OK", nil, []byte(respBody))})
	if err != nil || len(msgs) != 1 || msgs[0].RequestIndex != 1 {
		t.Fatalf("after the 407: %+v %v", msgs, err)
	}
}

// Finding 4: a request body past MaxBody is kept as a prefix derive cannot parse; its max_tokens is read off
// every byte by the scanner the wiring supplies (Options.BodyScanner). A body kept whole leaves it to derive, one
// that lost bytes to capture gives none, and without a scanner nothing is read.
func TestMaxTokensOfACutRequest(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"user","content":"` + strings.Repeat("x", 8<<10) + `"}],"max_tokens":321}`
	for _, tc := range []struct {
		name    string
		maxBody int64
		hole    bool
		noScan  bool
		want    int
	}{
		{"cut by MaxBody", 1 << 10, false, false, 321},
		{"kept whole", 64 << 10, false, false, 0},
		{"cut, then a hole", 1 << 10, true, false, 0},
		{"cut, no scanner", 1 << 10, false, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{MaxBody: tc.maxBody}
			if !tc.noScan {
				opts.BodyScanner = func() BodyScanner { return &anthropic.MaxTokensScanner{} }
			}
			a := NewAssembler(opts)
			key := ConnKey{Src: record.SourceSSL, PidTgid: 1, SSLPtr: 1}
			wire := postRequest(body)
			var got []*Message
			for i := 0; i < len(wire); i += 1000 {
				ch := Chunk{Data: []byte(wire[i:min(i+1000, len(wire))])}
				if tc.hole && i == 4000 {
					ch.Data, ch.Skipped = ch.Data[:500], 500
				}
				msgs, err := a.Feed(key, DirRequest, ch)
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, msgs...)
			}
			if len(got) != 1 || got[0].MaxTokens != tc.want {
				t.Fatalf("messages %d, max_tokens %d; want one with %d", len(got), got[0].MaxTokens, tc.want)
			}
		})
	}
}
