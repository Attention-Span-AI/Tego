// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	bin "encoding/binary"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/capture/httpstream"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// closeRecord builds the record bpf/uprobe_ssl.bpf.c writes at SSL_free.
func closeRecord(cgroup uint64, pid, tid uint32, ssl uint64, monoNS uint64) []byte {
	b := make([]byte, bpf.SSLCloseSize)
	o := bin.NativeEndian
	o.PutUint16(b[0:2], bpf.EventsVersion)
	o.PutUint16(b[2:4], uint16(bpf.KindSSLClose))
	o.PutUint32(b[4:8], uint32(bpf.SSLCloseSize))
	o.PutUint64(b[8:16], monoNS)
	o.PutUint64(b[16:24], cgroup)
	o.PutUint32(b[24:28], pid)
	o.PutUint32(b[28:32], tid)
	o.PutUint64(b[bpf.HeaderSize:bpf.HeaderSize+8], ssl)
	return b
}

// reuse is one SSL* whose first connection's response is cut off, then freed, and whose address the next
// SSL_new is handed on the same thread (glibc's allocator does exactly that with the freed SSL_CONNECTION).
type reuse struct {
	ssl  uint64
	pid  uint32
	mono uint64
	seq  uint32
	recs [][]byte
}

func (r *reuse) next() uint64 { r.mono += 1_000_000; return r.mono }

// chunk appends one chunk of the connection, numbered as the kernel numbers it when numbering is on.
func (r *reuse) chunk(dir uint8, s string, number bool) {
	rec := chunkRecord(41, r.pid, r.pid, r.ssl, dir, r.next(), []byte(s), false)
	if number {
		r.seq++
		rec = numbered(rec, r.seq)
	}
	r.recs = append(r.recs, rec)
}

// free appends SSL_free's record, and restarts the kernel's count for the pointer as the probe does.
func (r *reuse) free() {
	r.recs = append(r.recs, closeRecord(41, r.pid, r.pid+1, r.ssl, r.next()))
	r.seq = 0
}

// exchanges appends n whole exchanges of the pointer's new connection.
func (r *reuse) exchanges(n int, number bool) {
	for range n {
		r.chunk(bpf.SSLWrite, exchangeRequest, number)
		r.chunk(bpf.SSLRead, exchangeResponse, number)
	}
}

// TestSSLFreeEndsTheConnection (capture-derive.md R3a, E9): over a chunked response, an aborted stream on one SSL*, then a new connection whose
// SSL* lands at the same address. With no SSL_free probe the reassembler never learned the first connection ended:
// the new response went into the old chunked body, the key gapped once, and every later exchange on it was dropped
// with no further count. SSL_free's record (from another thread of the process, as a garbage collector frees it) now
// ends the connection: the aborted response is recorded truncated with its one gap, and all ten exchanges of the new
// connection are recorded.
func TestSSLFreeEndsTheConnection(t *testing.T) {
	r := &reuse{ssl: 0x5200, pid: 701, mono: 1_000_000}
	r.chunk(bpf.SSLWrite, exchangeRequest, true)
	r.chunk(bpf.SSLRead, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"+
		"1e\r\nevent: message_start\ndata: {}\n\r\n", true)
	r.free()
	r.exchanges(10, true)
	u, sink := newTestUprobe(t, r.recs, Options{})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	reqs, resps := countKinds(sink)
	if reqs != 11 || resps != 11 {
		t.Errorf("%d requests and %d responses, want the aborted exchange and the ten after it; gaps %+v", reqs, resps,
			u.Gaps())
	}
	if got := gapCount(u.Gaps(), httpstream.GapMalformed); got != 1 {
		t.Errorf("malformed = %d, want 1 for the stream the close cut short", got)
	}
}

// TestSSLFreeRevivesAGappedKey is the review's own bytes, whose chunk-size line is wrong for its data: the first
// connection gaps on its response, and a gapped key dropped every later chunk until it was evicted. The close
// record closes a gapped connection too, so the pointer's next connection is captured whole.
func TestSSLFreeRevivesAGappedKey(t *testing.T) {
	r := &reuse{ssl: 0x5210, pid: 706, mono: 1_000_000}
	r.chunk(bpf.SSLWrite, exchangeRequest, true)
	r.chunk(bpf.SSLRead, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"+
		"1c\r\nevent: message_start\ndata: {}\n\r\n", true)
	r.free()
	r.exchanges(10, true)
	u, sink := newTestUprobe(t, r.recs, Options{})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	reqs, resps := countKinds(sink)
	if reqs != 11 || resps != 10 {
		t.Errorf("%d requests and %d responses, want the ten exchanges after the gapped one; gaps %+v", reqs, resps,
			u.Gaps())
	}
	if got := gapCount(u.Gaps(), httpstream.GapMalformed); got != 1 {
		t.Errorf("malformed = %d, want 1 for the chunk-size line", got)
	}
}

// TestSSLFreeEndsALengthBody is the same reuse over a Content-Length response: the new connection's responses
// were swallowed as the old body with no error at all, and the old response was recorded, not truncated, with a
// body made of other responses' raw HTTP bytes.
func TestSSLFreeEndsALengthBody(t *testing.T) {
	r := &reuse{ssl: 0x5300, pid: 702, mono: 1_000_000}
	r.chunk(bpf.SSLWrite, exchangeRequest, true)
	r.chunk(bpf.SSLRead, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 300\r\n\r\n"+
		strings.Repeat("x", 100), true)
	r.free()
	r.exchanges(3, true)
	checkNoSplicedBody(t, r.recs, 4)
}

// TestReusedPointerWithTheCloseLostStartsAfresh: the close record lost to a full ring, SSL_free on the thread
// that did the I/O still removed the pointer's count, so the new connection counts from 1 and the reader
// closes what the key held before feeding it.
func TestReusedPointerWithTheCloseLostStartsAfresh(t *testing.T) {
	r := &reuse{ssl: 0x5400, pid: 703, mono: 1_000_000}
	r.chunk(bpf.SSLWrite, exchangeRequest, true)
	r.chunk(bpf.SSLRead, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 300\r\n\r\n"+
		strings.Repeat("x", 100), true)
	r.seq = 0 // SSL_free ran; its record did not reach the ring
	r.exchanges(3, true)
	checkNoSplicedBody(t, r.recs, 4)
}

// TestCloseDelimitedEndsAtTheNextRequest: with neither a close record nor a restarted count (the SSL* freed on
// another thread, its record lost), a request line on the key while its response is close-delimited ends that
// response, which only the connection's close can end (RFC 9112 §6.3), instead of every later exchange going
// into its body until Stop.
func TestCloseDelimitedEndsAtTheNextRequest(t *testing.T) {
	r := &reuse{ssl: 0x5500, pid: 704, mono: 1_000_000}
	r.chunk(bpf.SSLWrite, exchangeRequest, false)
	r.chunk(bpf.SSLRead, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":\"msg_close\"}", false)
	r.exchanges(3, false)
	blobs := &fakeBlobs{}
	u, sink := newTestUprobe(t, r.recs, Options{Blobs: blobs})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	reqs, resps := countKinds(sink)
	if reqs != 4 || resps != 4 {
		t.Errorf("%d requests and %d responses, want 4 exchanges; gaps %+v", reqs, resps, u.Gaps())
	}
	if len(u.Gaps()) != 0 {
		t.Errorf("gaps %+v: a close-delimited body that ended is a whole body", u.Gaps())
	}
	for _, b := range blobs.put {
		if strings.Contains(string(b), "HTTP/1.1") {
			t.Errorf("a recorded body holds another message's bytes: %q", b)
		}
	}
}

// TestAnotherProcessesFreeClosesNothing: a close names its process; the same address in another process is
// another object.
func TestAnotherProcessesFreeClosesNothing(t *testing.T) {
	recs := [][]byte{
		chunkRecord(41, 705, 705, 0x5600, bpf.SSLWrite, 1_000_000, []byte(exchangeRequest), false),
		closeRecord(41, 999, 999, 0x5600, 2_000_000),
		chunkRecord(41, 705, 705, 0x5600, bpf.SSLRead, 3_000_000, []byte(exchangeResponse), false),
	}
	u, sink := newTestUprobe(t, recs, Options{})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	if reqs, resps := countKinds(sink); reqs != 1 || resps != 1 || len(u.Gaps()) != 0 {
		t.Errorf("%d requests, %d responses, gaps %+v, want the one pair", reqs, resps, u.Gaps())
	}
}

// checkNoSplicedBody runs the records and asserts that want exchanges were recorded, the cut response among
// them as truncated, and that no recorded body holds another message's raw HTTP.
func checkNoSplicedBody(t *testing.T, recs [][]byte, want int) {
	t.Helper()
	blobs := &fakeBlobs{}
	u, sink := newTestUprobe(t, recs, Options{Blobs: blobs})
	runSource(t, u, sink, source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41})
	for _, b := range blobs.put {
		if strings.Contains(string(b), "HTTP/1.1") {
			t.Errorf("a recorded body holds another response's status line: %q", b)
		}
	}
	reqs, resps := countKinds(sink)
	if reqs != want || resps != want {
		t.Errorf("%d requests and %d responses, want %d exchanges; gaps %+v", reqs, resps, want, u.Gaps())
	}
	// The record's payload does not say a body is truncated; the one malformed gap is what says it was cut.
	if got := gapCount(u.Gaps(), httpstream.GapMalformed); got != 1 {
		t.Errorf("malformed = %d, want 1 for the body the close cut short", got)
	}
}
