// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"fmt"
	"strings"
	"testing"
)

// halfArrays is what one half of a connection holds of the heap between two messages: its unparsed bytes,
// and its body buffer, each counted by capacity, since the array is what the heap keeps however little of it
// is filled. The chunked decoder keeps no buffer of its own: it writes into the body.
func halfArrays(h *half) int {
	return cap(h.buf) + cap(h.body)
}

// TestIdleConnectionHoldsNoArray covers the first half: a keep-alive connection that has finished its
// exchanges holds none of the arrays its bodies grew. complete copied the body out and Reset the buffer, which
// keeps the array, so every connection — idle ones included — pinned the capacity its largest body grew to
// (up to MaxBody, 64 MiB) until the table reached MaxConns and evicted it: 4096 × 64 MiB in theory, and 1.5 GiB
// of launcher heap for 24 connections, as measured.
func TestIdleConnectionHoldsNoArray(t *testing.T) {
	for _, tc := range []struct {
		name string
		body func(string) string
		head string
	}{
		{"content-length", func(b string) string { return b }, "Content-Length: %d"},
		{"chunked", func(b string) string {
			var s strings.Builder
			for i := 0; i < len(b); i += 30 << 10 {
				end := min(i+30<<10, len(b))
				fmt.Fprintf(&s, "%x\r\n%s\r\n", end-i, b[i:end])
			}
			s.WriteString("0\r\n\r\n")
			return s.String()
		}, "Transfer-Encoding: chunked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAssembler(Options{})
			key := ConnKey{PidTgid: 1, SSLPtr: 2}
			body := strings.Repeat("x", 4<<20)
			head := tc.head
			if strings.Contains(head, "%d") {
				head = fmt.Sprintf(head, len(body))
			}
			wire := "POST /v1/messages HTTP/1.1\r\nHost: api\r\n" + head + "\r\n\r\n" + tc.body(body)
			// Fed as the kernel emits a large write, in pieces of at most one chunk.
			for i := 0; i < len(wire); i += 32 << 10 {
				if _, err := a.Feed(key, DirRequest, Chunk{Data: []byte(wire[i:min(i+32<<10, len(wire))])}); err != nil {
					t.Fatalf("request: %v", err)
				}
			}
			resp := "HTTP/1.1 200 OK\r\nContent-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" + body
			var got []*Message
			for i := 0; i < len(resp); i += 32 << 10 {
				msgs, err := a.Feed(key, DirResponse, Chunk{Data: []byte(resp[i:min(i+32<<10, len(resp))])})
				if err != nil {
					t.Fatalf("response: %v", err)
				}
				got = append(got, msgs...)
			}
			if len(got) != 1 || len(got[0].Body) != len(body) {
				t.Fatalf("got %d messages, want the one response with its %d-byte body", len(got), len(body))
			}
			a.mu.Lock()
			c := a.conns[key]
			held := halfArrays(&c.halves[DirRequest]) + halfArrays(&c.halves[DirResponse])
			a.mu.Unlock()
			if held > 64<<10 {
				t.Errorf("an idle connection holds %d bytes of arrays after its %d-byte bodies completed", held, len(body))
			}
		})
	}
}

// TestBudgetBoundsBodiesInFlight covers the second half: MaxBody bounds one body, and nothing bounded how
// many connections hold one at once. Sixteen connections each send a body of MaxBody and stop one byte short
// of its end, which is where 24 unanswered 48 MiB requests grew the launcher by 1.5 GiB. Every array the
// assembler holds is reserved from its Budget, so what is held stays inside it; a body the budget cuts keeps
// its prefix, is marked Truncated when it completes, and costs one gap why=size-cap.
func TestBudgetBoundsBodiesInFlight(t *testing.T) {
	const (
		maxBody = 1 << 20
		limit   = 4 << 20
		conns   = 16
	)
	a := NewAssembler(Options{MaxBody: maxBody, MaxBytes: limit})
	// Short of MaxBody, which a body that reaches it is marked truncated at, whole or not.
	body := strings.Repeat("y", maxBody-4096)
	head := fmt.Sprintf("POST /v1/messages HTTP/1.1\r\nHost: api\r\nContent-Length: %d\r\n\r\n", len(body))
	held := func() int {
		a.mu.Lock()
		defer a.mu.Unlock()
		n := 0
		for _, c := range a.conns {
			n += halfArrays(&c.halves[DirRequest]) + halfArrays(&c.halves[DirResponse])
		}
		return n
	}
	for i := range conns {
		key := ConnKey{PidTgid: uint64(i + 1), SSLPtr: 7}
		wire := head + body[:len(body)-1]
		for off := 0; off < len(wire); off += 32 << 10 {
			if _, err := a.Feed(key, DirRequest, Chunk{Data: []byte(wire[off:min(off+32<<10, len(wire))])}); err != nil {
				t.Fatalf("connection %d: %v", i, err)
			}
			if used := a.Budget().Used(); used > limit {
				t.Fatalf("budget holds %d bytes, over its %d limit", used, limit)
			}
		}
	}
	if got := held(); got > limit+conns*(64<<10) {
		t.Errorf("%d connections with an unfinished body hold %d bytes of arrays against a budget of %d", conns, got, limit)
	}
	starved := gapCount(a.Gaps(), GapSizeCap)
	if starved == 0 {
		t.Fatalf("no gap why=size-cap for bodies the budget cut: %+v", a.Gaps())
	}
	// Each body's last byte completes it: the ones the budget cut are truncated prefixes, the others whole,
	// and none holds any of the budget once it is handed over.
	var whole, cut int64
	for i := range conns {
		key := ConnKey{PidTgid: uint64(i + 1), SSLPtr: 7}
		msgs, err := a.Feed(key, DirRequest, Chunk{Data: []byte("y")})
		if err != nil || len(msgs) != 1 {
			t.Fatalf("connection %d: %d messages, %v", i, len(msgs), err)
		}
		m := msgs[0]
		switch {
		case !m.Truncated && len(m.Body) == len(body):
			whole++
		case m.Truncated && len(m.Body) < len(body) && strings.Count(string(m.Body), "y") == len(m.Body):
			cut++
		default:
			t.Errorf("connection %d: body of %d bytes, truncated %v", i, len(m.Body), m.Truncated)
		}
	}
	if cut != starved || whole+cut != conns {
		t.Errorf("%d whole and %d cut bodies, %d size-cap gaps counted", whole, cut, starved)
	}
	if used := a.Budget().Used(); used != 0 {
		t.Errorf("the budget still holds %d bytes once every body was handed over", used)
	}
}

// TestBudgetReturnedByAGappedConnection: a connection abandoned mid-body gives its reservation back with its
// arrays, or every gapped connection would shrink the budget for the rest of the run.
func TestBudgetReturnedByAGappedConnection(t *testing.T) {
	a := NewAssembler(Options{})
	key := ConnKey{PidTgid: 1, SSLPtr: 2}
	if _, err := a.Feed(key, DirResponse, Chunk{Data: []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"100000\r\n" + strings.Repeat("z", 1<<20) + "\r\n")}); err != nil {
		t.Fatal(err)
	}
	if a.Budget().Used() == 0 {
		t.Fatal("a body in flight reserved nothing")
	}
	if _, err := a.Feed(key, DirResponse, Chunk{Data: []byte("zz\r\n")}); err == nil {
		t.Fatal("a bad chunk-size line did not gap the connection")
	}
	if used := a.Budget().Used(); used != 0 {
		t.Errorf("a gapped connection still holds %d bytes of the budget", used)
	}
}

// TestBudgetFloor: no Options value makes the budget smaller than one exchange at its largest.
func TestBudgetFloor(t *testing.T) {
	if got := NewAssembler(Options{MaxBody: 1 << 20, MaxBytes: 1}).Budget().Limit(); got != budgetBodies<<20 {
		t.Errorf("a 1-byte MaxBytes gives a budget of %d, want the floor of %d", got, budgetBodies<<20)
	}
	if got := NewAssembler(Options{}).Budget().Limit(); got != DefaultMaxBytes {
		t.Errorf("the zero Options gives a budget of %d, want DefaultMaxBytes (%d)", got, DefaultMaxBytes)
	}
}
