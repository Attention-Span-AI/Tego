// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestDefaultMaxBodyIsAlwaysSet pins the bound itself rather than its effect: whatever a caller passes,
// an Assembler never ends up assembling a body of unbounded size. Every production caller builds one with
// a zero Options (uprobe.New), so a missing default is the difference between a bounded parser and one
// whose memory is chosen by whichever server the traced agent happens to talk to.
func TestDefaultMaxBodyIsAlwaysSet(t *testing.T) {
	if got := NewAssembler(Options{}).opts.MaxBody; got != DefaultMaxBody {
		t.Errorf("MaxBody with a zero Options = %d, want DefaultMaxBody (%d)", got, DefaultMaxBody)
	}
	if got := NewAssembler(Options{MaxBody: -1}).opts.MaxBody; got <= 0 {
		t.Errorf("MaxBody from a negative option = %d: no Options value may disable the bound", got)
	}
	if got := NewAssembler(Options{MaxBody: 4096}).opts.MaxBody; got != 4096 {
		t.Errorf("MaxBody = %d, want the caller's own 4096", got)
	}
	// DefaultMaxBody has to stay clear of the "32 MB body handled" acceptance, or the default
	// would truncate a body the component is required to reassemble whole.
	if DefaultMaxBody <= 32<<20 {
		t.Errorf("DefaultMaxBody = %d, which cuts the 32 MB body the acceptance needs", DefaultMaxBody)
	}
	// writeBody's own fallback for a cap the constructor did not set: it must mean "the default",
	// never "keep nothing" — an unset cap that silently discarded every body would be a worse failure
	// than the unbounded one it replaced.
	var h half
	h.writeBody([]byte(respBody), 0, nil)
	if string(h.body) != respBody || h.capped {
		t.Errorf("writeBody with an unset cap kept %dB (capped=%v), want the whole %dB body",
			len(h.body), h.capped, len(respBody))
	}
}

// TestGzipBombIsBoundedByDefault is the attack the default exists for. Uprobes capture every TLS
// connection in the traced cgroup, not just the model's, so any host the agent talks to can answer with a
// small compressed body that expands without limit. The launcher holding this assembler also holds the
// ledger writer and the seccomp supervisor: if it is OOM-killed, enforcement and the audit trail end
// together and no gap is left behind to explain it (I4).
//
// 128 KiB on the wire against a 64 MiB ceiling is the whole point — the bound has to be on what decodes,
// not on what arrives.
func TestGzipBombIsBoundedByDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("decodes up to the 64 MiB default cap")
	}
	const expand = 128 << 20 // four times the default cap, from a few hundred KiB on the wire
	var z bytes.Buffer
	w := gzip.NewWriter(&z)
	zeros := make([]byte, 1<<20)
	for written := 0; written < expand; written += len(zeros) {
		if _, err := w.Write(zeros); err != nil {
			t.Fatalf("building the bomb: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("closing the bomb: %v", err)
	}
	if z.Len() > 1<<20 {
		t.Fatalf("test bomb is %d bytes on the wire, too large to prove amplification", z.Len())
	}

	a := NewAssembler(Options{})
	if _, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte(postRequest(reqBody))}); err != nil {
		t.Fatalf("request: %v", err)
	}
	head := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", z.Len())
	msgs, err := a.Feed(testKey, DirResponse, Chunk{Data: append([]byte(head), z.Bytes()...)})
	if err != nil {
		t.Fatalf("response: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("want the response, got %d messages", len(msgs))
	}
	if int64(len(msgs[0].Body)) > DefaultMaxBody {
		t.Errorf("a %d-byte compressed body decoded into %d bytes of launcher memory, past the %d-byte default bound",
			z.Len(), len(msgs[0].Body), DefaultMaxBody)
	}
	if !msgs[0].Truncated {
		t.Error("a body cut at the default bound is not marked Truncated: the loss must be recorded, never silent")
	}
}

// TestGappedConnectionReleasesItsBuffers covers what a connection keeps holding after it is abandoned.
// gapForLocked marks it dead and Feed then short-circuits on it, so nothing can ever read its half buffers
// again — but the assembler only removes an entry at Close, and nothing in the uprobe path calls Close per
// connection, so whatever was buffered at the moment of death stayed resident until Stop. A connection
// that gapped part-way through a large body is exactly the case where that is worth megabytes.
func TestGappedConnectionReleasesItsBuffers(t *testing.T) {
	const chunkBytes = 1 << 20
	a := NewAssembler(Options{})
	head := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	if _, err := a.Feed(testKey, DirResponse, Chunk{Data: []byte(head)}); err != nil {
		t.Fatalf("response head: %v", err)
	}
	body := fmt.Sprintf("%x\r\n%s\r\n", chunkBytes, strings.Repeat("x", chunkBytes))
	if _, err := a.Feed(testKey, DirResponse, Chunk{Data: []byte(body)}); err != nil {
		t.Fatalf("first chunk: %v", err)
	}
	c := a.conns[testKey]
	if c == nil {
		t.Fatal("no connection tracked")
	}
	if len(c.halves[DirResponse].body) < chunkBytes {
		t.Fatalf("buffered %d body bytes, want at least %d: the test never reached the state it is about",
			len(c.halves[DirResponse].body), chunkBytes)
	}
	// A chunk-size line that is not hex: the connection gaps mid-body, holding the megabyte it had
	// already decoded.
	if _, err := a.Feed(testKey, DirResponse, Chunk{Data: []byte("zz\r\n")}); err == nil {
		t.Fatal("a bad chunk-size line did not gap the connection")
	}
	if !c.dead {
		t.Fatal("connection not marked dead after a malformed chunk size")
	}
	for i := range c.halves {
		h := &c.halves[i]
		if cap(h.body) != 0 || h.buf != nil || h.msg != nil {
			t.Errorf("%s half of an abandoned connection still holds body=%dB buf=%dB msg=%v",
				h.dir, cap(h.body), len(h.buf), h.msg != nil)
		}
	}
}

// TestMaxConnsRetiresFinishedConnections covers the table bound as a bound rather than as an ending.
// Entries were only ever removed by Close, and nothing in the uprobe path calls it per connection (there is
// no SSL_free probe), so the table only grew: once MaxConns connections had been seen — one short-lived TLS
// client per shell tool call reaches 4096 in a long run — every connection after that was refused for the
// rest of the run and capture quietly stopped producing pairs for limits and derive to read.
func TestMaxConnsRetiresFinishedConnections(t *testing.T) {
	a := NewAssembler(Options{MaxConns: 2})
	first := ConnKey{Src: record.SourceSSL, SSLPtr: 1}
	second := ConnKey{Src: record.SourceSSL, SSLPtr: 2}
	for _, k := range []ConnKey{first, second} {
		exchange(t, a, k)
	}
	third := ConnKey{Src: record.SourceSSL, SSLPtr: 3}
	if _, err := a.Feed(third, DirRequest, Chunk{Data: []byte(postRequest(reqBody))}); err != nil {
		t.Fatalf("third connection: %v, want it tracked in place of a finished one", err)
	}
	if a.Conns() != 2 {
		t.Errorf("Conns = %d, want the table still bounded at 2", a.Conns())
	}
	if _, ok := a.conns[first]; ok {
		t.Error("retired the wrong connection: the one idle longest must go first")
	}
	if _, ok := a.conns[second]; !ok {
		t.Error("retired the more recently used connection")
	}
	if hasGap(a.Gaps(), GapSizeCap) {
		t.Errorf("gaps = %v: retiring a finished connection loses nothing and must not be reported as a shortfall", a.Gaps())
	}
}

// TestMaxConnsRetiresGappedConnectionsFirst covers the ordering of that eviction. A connection already
// abandoned holds nothing but the memo that says to ignore its key, while an idle live one still holds the
// message ordinals and Seq continuity a later chunk on the same key would use — so the dead one goes first
// even when it is the more recently used.
func TestMaxConnsRetiresGappedConnectionsFirst(t *testing.T) {
	a := NewAssembler(Options{MaxConns: 2})
	idle := ConnKey{Src: record.SourceSSL, SSLPtr: 1}
	exchange(t, a, idle)
	gapped := ConnKey{Src: record.SourceSSL, SSLPtr: 2}
	if _, err := a.Feed(gapped, DirRequest, Chunk{Data: []byte("GET\r\n\r\n")}); err == nil {
		t.Fatal("a bad request line did not gap the connection")
	}
	fresh := ConnKey{Src: record.SourceSSL, SSLPtr: 3}
	if _, err := a.Feed(fresh, DirRequest, Chunk{Data: []byte(postRequest(reqBody))}); err != nil {
		t.Fatalf("fresh connection: %v", err)
	}
	if _, ok := a.conns[gapped]; ok {
		t.Error("kept an abandoned connection and retired a live one instead")
	}
	if _, ok := a.conns[idle]; !ok {
		t.Error("retired the live idle connection while an abandoned one was still tracked")
	}
}

// exchange drives one complete request/response pair on a key, leaving the connection idle between
// messages — the state a finished connection sits in forever, since nothing retires it.
func exchange(t *testing.T, a *Assembler, k ConnKey) {
	t.Helper()
	if _, err := a.Feed(k, DirRequest, Chunk{Data: []byte(postRequest(reqBody))}); err != nil {
		t.Fatalf("%s request: %v", k, err)
	}
	if _, err := a.Feed(k, DirResponse, Chunk{Data: httpResponse("200 OK", nil, []byte(respBody))}); err != nil {
		t.Fatalf("%s response: %v", k, err)
	}
	if c := a.conns[k]; c == nil || !c.retirable() {
		t.Fatalf("%s did not end the exchange idle: the test never reached the state it is about", k)
	}
}
