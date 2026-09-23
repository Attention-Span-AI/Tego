// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestChunkedReader is the chunked decoder on its own: every framing shape RFC 9112 §7.1 allows, and the
// ones it does not.
func TestChunkedReader(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		done    bool
		wantErr error
	}{
		{"one chunk", "3\r\nabc\r\n0\r\n\r\n", "abc", true, nil},
		{"two chunks", "3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n", "abcde", true, nil},
		{"extension ignored", "3;name=value\r\nabc\r\n0\r\n\r\n", "abc", true, nil},
		{"upper-case hex", "A\r\n0123456789\r\n0\r\n\r\n", "0123456789", true, nil},
		{"trailers", "3\r\nabc\r\n0\r\nX-A: 1\r\nX-B: 2\r\n\r\n", "abc", true, nil},
		{"bare lf", "3\nabc\n0\n\n", "abc", true, nil},
		{"incomplete size line", "3", "", false, nil},
		{"incomplete data", "5\r\nab", "ab", false, nil},
		{"missing terminator", "3\r\nabc\r\n", "abc", false, nil},
		{"bad hex", "zz\r\n", "", false, ErrMalformed},
		{"empty size", ";ext\r\n", "", false, ErrMalformed},
		{"oversize hex", strings.Repeat("f", 17) + "\r\n", "", false, ErrMalformed},
		{"data not followed by crlf", "3\r\nabcX", "abc", false, ErrMalformed},
		{"trailer without colon", "0\r\nnot-a-header\r\n\r\n", "", false, ErrMalformed},
		{"size line too long", strings.Repeat("0", maxChunkSizeLine+2), "", false, ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c chunkedReader
			var out bytes.Buffer
			_, err := c.feed([]byte(tc.in), &out)
			if tc.wantErr == nil && err != nil {
				t.Fatalf("feed: %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if got := out.String(); got != tc.want {
				t.Errorf("body = %q, want %q", got, tc.want)
			}
			if c.done() != tc.done {
				t.Errorf("done = %t, want %t", c.done(), tc.done)
			}
		})
	}
}

// TestChunkedSplitEverywhere is capture-derive.md E17 (edge case #17) exhaustively: the same body fed with a break at every single
// offset must decode identically, because the parser's state lives on the connection.
func TestChunkedSplitEverywhere(t *testing.T) {
	const in = "1a;x=1\r\nabcdefghijklmnopqrstuvwxyz\r\n5\r\n01234\r\n0\r\nX-T: v\r\n\r\n"
	const want = "abcdefghijklmnopqrstuvwxyz01234"
	for split := 0; split <= len(in); split++ {
		var c chunkedReader
		var out bytes.Buffer
		buf := []byte(in[:split])
		used, err := c.feed(buf, &out)
		if err != nil {
			t.Fatalf("split %d: first half: %v", split, err)
		}
		rest := append(append([]byte(nil), buf[used:]...), in[split:]...)
		if _, err := c.feed(rest, &out); err != nil {
			t.Fatalf("split %d: second half: %v", split, err)
		}
		if !c.done() {
			t.Fatalf("split %d: not done", split)
		}
		if out.String() != want {
			t.Fatalf("split %d: body = %q", split, out.String())
		}
	}
}

// TestParseChunkSize covers the size parser's own bounds, including the overflow guard.
func TestParseChunkSize(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"0", 0, true},
		{"ff", 255, true},
		{"FF", 255, true},
		{"1a2b ", 0x1a2b, true},
		{"10;ext", 16, true},
		{"7fffffffffffffff", 1<<63 - 1, true},
		{"ffffffffffffffff", 0, false},
		{"", 0, false},
		{"-1", 0, false},
		{"0x10", 0, false},
	}
	for _, tc := range cases {
		got, err := parseChunkSize([]byte(tc.in))
		if tc.ok != (err == nil) {
			t.Errorf("parseChunkSize(%q) error = %v, want ok=%t", tc.in, err, tc.ok)
			continue
		}
		if tc.ok && got != tc.want {
			t.Errorf("parseChunkSize(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestTakeLine covers the line splitter both caps depend on.
func TestTakeLine(t *testing.T) {
	cases := []struct {
		in       string
		max      int
		wantLine string
		wantN    int
		wantOK   bool
	}{
		{"a\r\n", 16, "a", 3, true},
		{"a\n", 16, "a", 2, true},
		{"\r\n", 16, "", 2, true},
		{"abc", 16, "", 0, false},
		{"abcdef", 3, "", -1, false},
		{"abcdef\n", 3, "", -1, false},
		{"", 0, "", 0, false},
		{"a", 0, "", -1, false},
	}
	for _, tc := range cases {
		line, n, ok := takeLine([]byte(tc.in), tc.max)
		if string(line) != tc.wantLine || n != tc.wantN || ok != tc.wantOK {
			t.Errorf("takeLine(%q, %d) = %q, %d, %t; want %q, %d, %t",
				tc.in, tc.max, line, n, ok, tc.wantLine, tc.wantN, tc.wantOK)
		}
	}
}
