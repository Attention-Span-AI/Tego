// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// stressEnv runs the stress shapes below at full size, e.g.
// TEGO_STRESS=1 go test -run HeadBytesCharged ./internal/runtime/capture/httpstream/; the plain run runs
// them small.
const stressEnv = "TEGO_STRESS"

// heldArrays is what every connection's halves hold of the heap, by capacity (halfArrays).
func heldArrays(a *Assembler) int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	var n int64
	for _, c := range a.conns {
		n += int64(halfArrays(&c.halves[DirRequest]) + halfArrays(&c.halves[DirResponse]))
	}
	return n
}

// chargedArrays is heldArrays less each half's uncharged head allowance: what the Budget must have reserved.
func chargedArrays(a *Assembler) int64 {
	a.mu.Lock()
	var free int64
	for _, c := range a.conns {
		for d := range c.halves {
			if h := &c.halves[d]; !h.bufAliased {
				free += int64(cap(h.buf)) - h.bufHeld
			}
		}
	}
	a.mu.Unlock()
	return heldArrays(a) - free
}

// TestHeadBytesChargedToBudget: the bytes a half buffers while a start line or header block is still arriving
// were charged to nothing, where bodies were charged to the Budget. MaxConns connections each parked on a 63
// KiB partial header added 260 MiB of launcher heap past DefaultMaxBytes, per direction, and an
// agent running its own TLS server chooses both. Now the arrays are reserved from the budget, the connections
// past it gap why=size-cap, and every reservation goes back when its connection closes.
func TestHeadBytesChargedToBudget(t *testing.T) {
	stress := os.Getenv(stressEnv) != ""
	conns, opts := 256, Options{MaxBody: 1 << 20, MaxBytes: 3 << 20}
	if stress {
		conns, opts = DefaultMaxConns, Options{}
	}
	pad := "X-Pad: " + strings.Repeat("a", 63<<10) // what each half holds once its start line is parsed
	req := []byte("POST /v1/messages HTTP/1.1\r\n" + pad)
	resp := []byte("HTTP/1.1 200 OK\r\n" + pad)
	var m0, m1 runtime.MemStats
	if stress {
		runtime.GC()
		runtime.ReadMemStats(&m0)
	}
	a := NewAssembler(opts)
	b := a.Budget()
	// Both directions of every connection, as an agent talking to a TLS server of its own can make them: twice
	// what the budget holds even at MaxConns and the defaults.
	for i := range conns {
		key := ConnKey{Src: record.SourceSSL, PidTgid: uint64(i + 1), SSLPtr: 1}
		_, _ = a.Feed(key, DirRequest, Chunk{Data: req})
		_, _ = a.Feed(key, DirResponse, Chunk{Data: resp})
		if b.Used() > b.Limit() {
			t.Fatalf("after %d connections %d bytes are reserved, past the budget of %d", i+1, b.Used(), b.Limit())
		}
	}
	// Past the budget, each half holds at most its uncharged head allowance (MaxConns × 2 × headAllowance).
	held := heldArrays(a)
	if bound := b.Limit() + int64(conns)*2*headAllowance; held > bound {
		t.Errorf("%d connections parked on partial headers hold %d bytes, past the budget of %d and the head allowances (%d)",
			conns, held, b.Limit(), bound)
	}
	if charged := chargedArrays(a); charged != b.Used() {
		t.Errorf("the halves hold %d bytes of arrays past their head allowance and %d are reserved: every one must be charged",
			charged, b.Used())
	}
	var capped int64
	for _, g := range a.Gaps() {
		if g.Why == GapSizeCap {
			capped = g.Count
		}
	}
	// Each connection holds its two heads or has gapped, so the ones the budget holds are at most its limit over
	// their size and the rest each cost one gap.
	if whole := b.Limit() / int64(2*(len(pad)-headAllowance)); capped < int64(conns)-whole {
		t.Errorf("%d size-cap gaps for %d connections of which at most %d fit the budget", capped, conns, whole)
	}
	if stress {
		runtime.GC()
		runtime.ReadMemStats(&m1)
		grew := int64(m1.HeapInuse) - int64(m0.HeapInuse)
		t.Logf("%d conns x 63 KiB partial header each way: heap +%d MiB, %d gaps", conns, grew>>20, capped)
		if grew > b.Limit()+int64(conns)*2*headAllowance+32<<20 {
			t.Errorf("heap grew %d MiB, past the budget of %d MiB", grew>>20, b.Limit()>>20)
		}
	}
	a.CloseAll()
	if b.Used() != 0 {
		t.Errorf("%d bytes still reserved once every connection closed", b.Used())
	}
	runtime.KeepAlive(a)
}

// TestHeadBytesReleased: a head's reservation lasts as long as its bytes do. A header block arriving a byte at
// a time holds a reservation while it is incomplete, the connection holds none once the message completes,
// and none once a connection it was still buffering on gaps.
func TestHeadBytesReleased(t *testing.T) {
	a := NewAssembler(Options{})
	b := a.Budget()
	key := ConnKey{Src: record.SourceSSL, PidTgid: 1, SSLPtr: 1}
	req := []byte("POST /v1/messages HTTP/1.1\r\nX-Pad: " + strings.Repeat("a", 4<<10) + "\r\nContent-Length: 0\r\n\r\n")
	var got []*Message
	var peak int64
	for i := range req {
		msgs, err := a.Feed(key, DirRequest, Chunk{Data: req[i : i+1]})
		if err != nil {
			t.Fatalf("byte %d: %v", i, err)
		}
		got = append(got, msgs...)
		if held := chargedArrays(a); held != b.Used() {
			t.Fatalf("byte %d: %d bytes of arrays held past the head allowance and %d reserved", i, held, b.Used())
		}
		peak = max(peak, b.Used())
	}
	if peak < 4<<10-headAllowance+1 {
		t.Errorf("a header line past the head allowance arriving a byte at a time reserved at most %d bytes", peak)
	}
	if len(got) != 1 {
		t.Fatalf("got %d messages, want the request", len(got))
	}
	if b.Used() != 0 || heldArrays(a) != 0 {
		t.Errorf("a completed request leaves %d bytes reserved and %d held", b.Used(), heldArrays(a))
	}

	// A connection that gaps mid-head gives its reservation back with the rest of what it held.
	key2 := ConnKey{Src: record.SourceSSL, PidTgid: 2, SSLPtr: 1}
	if _, err := a.Feed(key2, DirRequest, Chunk{Data: []byte("POST / HTTP/1.1\r\nX-A: " + strings.Repeat("b", 2*headAllowance))}); err != nil {
		t.Fatal(err)
	}
	if b.Used() == 0 {
		t.Fatal("a partial header line holds no reservation")
	}
	if _, err := a.Feed(key2, DirRequest, Chunk{Data: []byte("\r\nbad header line\r\n")}); err == nil {
		t.Fatal("a header line with no colon did not gap the connection")
	}
	if b.Used() != 0 {
		t.Errorf("%d bytes still reserved after the connection gapped", b.Used())
	}
}

// TestLineSearchedOnce: takeLine searched the whole buffer on every call, so a 63 KiB header line
// fed a byte at a time was searched 63 Ki times from its start — 42 ms of one feed loop. The half now remembers
// how much of its buffer holds no line end, and each feed searches only the byte it added.
func TestLineSearchedOnce(t *testing.T) {
	a := NewAssembler(Options{})
	key := ConnKey{Src: record.SourceSSL, PidTgid: 1, SSLPtr: 1}
	req := []byte("POST /v1/messages HTTP/1.1\r\nX-Pad: " + strings.Repeat("a", 63<<10) + "\r\nContent-Length: 0\r\n\r\n")
	pad := strings.Index(string(req), "X-Pad")
	end := strings.Index(string(req[pad:]), "\r") + pad
	for i := range req {
		if _, err := a.Feed(key, DirRequest, Chunk{Data: req[i : i+1]}); err != nil {
			t.Fatalf("byte %d: %v", i, err)
		}
		if i < pad || i >= end {
			continue
		}
		a.mu.Lock()
		h := &a.conns[key].halves[DirRequest]
		known := 0
		if len(h.buf) > 0 && h.noLFAt == &h.buf[0] {
			known = h.noLF
		}
		held := len(h.buf)
		a.mu.Unlock()
		if known != held {
			t.Fatalf("byte %d: %d of the %d buffered bytes are known to hold no line end; the next feed searches "+
				"the rest again", i, known, held)
		}
	}
}

// BenchmarkFeed1ByteChunks is one exchange fed a byte per chunk: a request whose head carries a 32 KiB header
// line, and an event-stream response in chunked framing. It is the shape a slow or adversarial peer makes, and
// where a per-feed cost that grows with what is buffered shows.
func BenchmarkFeed1ByteChunks(b *testing.B) {
	req := []byte("POST /v1/messages HTTP/1.1\r\nX-Pad: " + strings.Repeat("a", 32<<10) + "\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(reqBody), reqBody))
	var resp strings.Builder
	resp.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
	for range 20 {
		ev := "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":" +
			"{\"type\":\"text_delta\",\"text\":\"" + strings.Repeat("z", 200) + "\"}}\n\n"
		fmt.Fprintf(&resp, "%x\r\n%s\r\n", len(ev), ev)
	}
	resp.WriteString("0\r\n\r\n")
	rsp := []byte(resp.String())
	a := NewAssembler(Options{})
	key := ConnKey{Src: record.SourceSSL, PidTgid: 1, SSLPtr: 1}
	b.SetBytes(int64(len(req) + len(rsp)))
	b.ReportAllocs()
	for b.Loop() {
		for i := range req {
			if _, err := a.Feed(key, DirRequest, Chunk{Data: req[i : i+1]}); err != nil {
				b.Fatal(err)
			}
		}
		n := 0
		for i := range rsp {
			msgs, err := a.Feed(key, DirResponse, Chunk{Data: rsp[i : i+1]})
			if err != nil {
				b.Fatal(err)
			}
			n += len(msgs)
		}
		if n != 1 {
			b.Fatalf("%d responses, want 1", n)
		}
	}
}
