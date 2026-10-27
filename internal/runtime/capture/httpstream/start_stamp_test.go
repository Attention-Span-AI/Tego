// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"testing"
	"time"
)

// TestStartStampAcrossSplitLines covers the first-byte clocks consumed by the
// uprobe response's request-to-response latency (capture-derive.md E25).
func TestStartStampAcrossSplitLines(t *testing.T) {
	for _, tc := range []struct {
		name  string
		dir   Direction
		parts []string
	}{
		{"request-unsplit", DirRequest, []string{"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n", "hi"}},
		{"request-split-line", DirRequest, []string{"POST /", " HTTP/1.1\r\nContent-Length: 2\r\n\r\n", "hi"}},
		{"request-three-pieces", DirRequest, []string{"PO", "ST / HT", "TP/1.1\r\nContent-Length: 2\r\n\r\n", "hi"}},
		{"response-unsplit", DirResponse, []string{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", "hi"}},
		{"response-split-line", DirResponse, []string{"HTTP/", "1.1 200 OK\r\nContent-Length: 2\r\n\r\n", "hi"}},
		{"response-three-pieces", DirResponse, []string{"HT", "TP/1.1 2", "00 OK\r\nContent-Length: 2\r\n\r\n", "hi"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAssembler(Options{})
			defer a.CloseAll()
			if tc.dir == DirResponse {
				if _, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte("GET / HTTP/1.1\r\n\r\n")}); err != nil {
					t.Fatal(err)
				}
			}
			origin := time.Unix(1700000000, 0).UTC()
			var out []*Message
			for i, part := range tc.parts {
				got, err := a.Feed(testKey, tc.dir, Chunk{Data: []byte(part), TS: origin.Add(time.Duration(i) * time.Second), MonoNS: uint64(i+1) * 1_000_000})
				if err != nil {
					t.Fatal(err)
				}
				out = append(out, got...)
			}
			if len(out) != 1 {
				t.Fatalf("messages=%d", len(out))
			}
			m := out[0]
			if !m.Start.Equal(origin) || m.StartNS != 1_000_000 {
				t.Errorf("start=%v/%d, want first chunk %v/1000000", m.Start, m.StartNS, origin)
			}
			if m.EndNS != uint64(len(tc.parts))*1_000_000 || m.LatencyMS() != int64(len(tc.parts)-1) {
				t.Errorf("end=%d latency=%d, want %d/%d", m.EndNS, m.LatencyMS(), uint64(len(tc.parts))*1_000_000, len(tc.parts)-1)
			}
		})
	}
}

func TestStartStampResetsAtMessageBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		dir   Direction
		parts []string
		want  []uint64
	}{
		{"pipeline-same-chunk", DirRequest, []string{"GET /one HTTP/1.1\r\n\r\nGET /two", " HTTP/1.1\r\n\r\n"}, []uint64{1, 1}},
		{"next-message", DirRequest, []string{"GET /one HTTP/1.1\r\n\r\n", "GET /two", " HTTP/1.1\r\n\r\n"}, []uint64{1, 2}},
		{"leading-empty-line", DirRequest, []string{"\r\n", "GET /", " HTTP/1.1\r\n\r\n"}, []uint64{2}},
		{"skipped-request-tail", DirRequest, []string{"{\"orphan\":true}\r\n", "GET /", " HTTP/1.1\r\n\r\n"}, []uint64{2}},
		{"interim-response", DirResponse, []string{"HTTP/1.1 100 Continue\r\n\r\n", "HT", "TP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"}, []uint64{2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAssembler(Options{})
			defer a.CloseAll()
			if tc.dir == DirResponse {
				if _, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte("GET / HTTP/1.1\r\n\r\n")}); err != nil {
					t.Fatal(err)
				}
			}
			var out []*Message
			for i, part := range tc.parts {
				got, err := a.Feed(testKey, tc.dir, Chunk{Data: []byte(part), MonoNS: uint64(i+1) * 1_000_000})
				if err != nil {
					t.Fatal(err)
				}
				out = append(out, got...)
				if tc.name == "skipped-request-tail" && i == 0 {
					// R18 requires the unseen request's response before another
					// complete request, keeping their response pairing unambiguous.
					got, err := a.Feed(testKey, DirResponse, Chunk{Data: []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")})
					if err != nil || len(got) != 0 {
						t.Fatalf("headless response: messages=%d, err=%v", len(got), err)
					}
				}
			}
			if len(out) != len(tc.want) {
				t.Fatalf("messages=%d, want %d", len(out), len(tc.want))
			}
			for i, m := range out {
				if m.StartNS != tc.want[i]*1_000_000 {
					t.Errorf("message %d start=%d, want %d", i, m.StartNS, tc.want[i]*1_000_000)
				}
			}
		})
	}
}
