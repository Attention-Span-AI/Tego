// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// responseDeriver hands every response derive is given to the test.
type responseDeriver struct{ ch chan *derive.Message }

func (d *responseDeriver) Handle(_, resp *derive.Message, _ derive.Meta) (derive.Result, error) {
	d.ch <- resp
	return derive.Result{}, nil
}

// TestGzipCutMidStreamIsTruncated: a gzip body that ends mid-stream decoded to a prefix, and decodeWith returned it
// as neither decoded nor truncated, so the record's body was a prefix nothing marked and R15's gap why=malformed was
// never counted. The prefix is now decoded content cut short: truncated, with the malformed gap, and not counted a
// second time as the capture cap.
func TestGzipCutMidStreamIsTruncated(t *testing.T) {
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	_, _ = zw.Write([]byte(strings.Repeat(`{"type":"message","content":"abcdefgh"}`, 4000)))
	_ = zw.Close()
	cut := zb.Bytes()[:zb.Len()/2]
	d := &responseDeriver{ch: make(chan *derive.Message, 1)}
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(cut)
	}, Options{Deriver: d})
	resp := h.post("/v1/messages", []byte(`{"model":"m"}`), nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	m := <-d.ch
	// The ssl_response is built after derive returns, and building it is where a size-cap gap is counted:
	// read the gaps before it exists and a wrong count is missed on most schedules (it failed only on a
	// loaded CI runner, and always at -cpu=1).
	h.sink.waitFor(t, record.KindSSLResponse, 1)
	if !m.Truncated || !m.Decoded || len(m.Body) == 0 || !strings.HasPrefix(string(m.Body), `{"type":"message"`) {
		t.Errorf("derive saw %d bytes, decoded %v, truncated %v; want the decoded prefix, truncated", len(m.Body),
			m.Decoded, m.Truncated)
	}
	if gapCount(h.listener, GapMalformed) != 1 {
		t.Errorf("malformed = %d, want 1 for the mid-stream decode error (R15)", gapCount(h.listener, GapMalformed))
	}
	if n := gapCount(h.listener, GapSizeCap); n != 0 {
		t.Errorf("size-cap = %d for a body no capture bound cut", n)
	}
}

// TestDecodeWithReportsABrokenStream is the unit half: a decoded prefix is ok and broken and not limited, a
// stream that decodes nothing is broken and keeps nothing, and a limit is limited without being broken.
func TestDecodeWithReportsABrokenStream(t *testing.T) {
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	_, _ = zw.Write(bytes.Repeat([]byte("0123456789"), 10000))
	_ = zw.Close()
	gunzip := func(r io.Reader) (io.Reader, error) { return gzip.NewReader(r) }
	b := newBudget(0, DefaultMaxBody)
	out, ok, limited, broken := decodeWith(b, zb.Bytes()[:zb.Len()/2], DefaultMaxBody, gunzip)
	if out == nil || len(out.bytes()) == 0 || !ok || limited || !broken {
		t.Errorf("cut stream: ok %v limited %v broken %v, want a decoded prefix, broken and not limited", ok, limited, broken)
	}
	if out, _, _, broken := decodeWith(b, []byte("not gzip at all"), DefaultMaxBody, gunzip); out != nil || !broken {
		t.Errorf("a stream that decodes nothing: kept %v, broken %v", out != nil, broken)
	}
	if _, _, limited, broken := decodeWith(b, zb.Bytes(), 1024, gunzip); !limited || broken {
		t.Errorf("a decode stopped at its limit: limited %v broken %v, want limited and not broken", limited, broken)
	}
}

// TestChunkedRequestSizeIsWhatWasSent: a chunked request (no Content-Length) larger than MaxBody is forwarded whole,
// and its ssl_request's size was what capture kept, not what the client sent. The size of such a body exists only
// once its last byte has gone upstream, so its line is written then, still before its response's.
func TestChunkedRequestSizeIsWhatWasSent(t *testing.T) {
	const size = 3 << 20
	var got int
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = len(b)
		w.WriteHeader(http.StatusOK)
	}, Options{MaxBody: 64 << 10})
	body := io.MultiReader(bytes.NewReader(bytes.Repeat([]byte("a"), size))) // no length for net/http to declare
	req, err := http.NewRequest(http.MethodPost, h.listener.BaseURL()+"/v1/messages", body)
	if err != nil {
		t.Fatal(err)
	}
	resp := h.do(req)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	h.sink.waitFor(t, record.KindSSLResponse, 1)
	var kinds []record.Kind
	for _, ev := range h.sink.all() {
		kinds = append(kinds, ev.Kind)
	}
	if len(kinds) < 2 || kinds[0] != record.KindSSLRequest || kinds[1] != record.KindSSLResponse {
		t.Fatalf("lines %v, want the ssl_request before its ssl_response", kinds)
	}
	rp := payloadOf[record.SSLRequestPayload](t, h.sink.of(record.KindSSLRequest)[0])
	if got != size || rp.Size != size {
		t.Errorf("the upstream received %d bytes and ssl_request.size is %d, want both %d", got, rp.Size, size)
	}
}

// leavingWriter is a client that takes limit bytes of a response and is gone after that.
type leavingWriter struct {
	header http.Header
	took   int
	limit  int
}

func (w *leavingWriter) Header() http.Header { return w.header }
func (w *leavingWriter) WriteHeader(int)     {}
func (w *leavingWriter) Write(p []byte) (int, error) {
	if w.took >= w.limit {
		return 0, io.ErrClosedPipe
	}
	w.took += len(p)
	return len(p), nil
}

// TestRelayMarksAClientThatLeftTruncated is the write side of the client leaving, without the race a live
// connection has between the write that fails and the cancelled request that ends the upstream read: relay
// stopped reading at the failed write and returned the copy as a whole body.
func TestRelayMarksAClientThatLeftTruncated(t *testing.T) {
	l, err := NewListener(agent.ModelEndpoint{Provider: "anthropic", Host: "api.anthropic.com"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	body := strings.Repeat("y", 4*streamChunk)
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
		ContentLength: -1, Body: io.NopCloser(strings.NewReader(body))}
	r := l.relay(&leavingWriter{header: http.Header{}, limit: streamChunk}, resp)
	if !r.truncated || len(r.body) >= len(body) {
		t.Errorf("kept %d of %d bytes, truncated %v: a copy the client's leaving cut short is recorded whole",
			len(r.body), len(body), r.truncated)
	}
	if r.sizeCut {
		t.Error("the client's leaving is counted as the capture cap")
	}
}

// TestClientGoneMidStreamIsTruncated: the client leaves mid-stream and the forwarder stops reading the upstream,
// so the record's copy is a prefix of the response; it was handed to derive and recorded as a whole body. The
// stream stays under MaxBody, so nothing but the client's leaving can cut the copy.
func TestClientGoneMidStreamIsTruncated(t *testing.T) {
	d := &responseDeriver{ch: make(chan *derive.Message, 1)}
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		chunk := []byte("data: " + strings.Repeat("x", 16<<10) + "\n\n")
		for range 200 {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			_ = rc.Flush()
			time.Sleep(2 * time.Millisecond)
		}
	}, Options{Deriver: d})
	resp := h.post("/v1/messages", []byte(`{"model":"m","stream":true}`), nil)
	buf := make([]byte, 1024)
	_, _ = resp.Body.Read(buf)
	_ = resp.Body.Close() // the client gives up after the first bytes
	select {
	case m := <-d.ch:
		if !m.Truncated {
			t.Errorf("a response the forwarder stopped reading when the client left is recorded as whole (%d bytes)",
				len(m.Body))
		}
	case <-time.After(20 * time.Second):
		t.Fatal("no exchange derived")
	}
}

// TestAnUpstreamCutMidRuneKeepsThePrefix: an upstream that fails mid-stream can stop inside a multi-byte
// character. The record's copy is then a prefix no capture bound cut, and only a size cut used to drop the
// unfinished rune, so the copy was invalid UTF-8 and the whole body was left off the record: the body of
// the exchange an operator most wants to see. The rune is now dropped for any truncated copy, and no
// size-cap gap is counted for a cut capture did not make.
func TestAnUpstreamCutMidRuneKeepsThePrefix(t *testing.T) {
	prefix := `{"text":"héllo wörld `
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(append([]byte(prefix), 0xe2, 0x82))
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}, Options{})
	resp := h.post("/v1/messages", []byte(`{"model":"m"}`), nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	ev := h.sink.waitFor(t, record.KindSSLResponse, 1)[0]
	var p struct {
		Body *string `json:"body"`
	}
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.Body == nil || *p.Body != prefix {
		t.Errorf("recorded body %v, want the prefix before the split rune %q", p.Body, prefix)
	}
	if n := gapCount(h.listener, GapSizeCap); n != 0 {
		t.Errorf("size-cap = %d for a body no capture bound cut", n)
	}
}

// A compressed copy a capture bound cut short ends mid-stream, and its decode then failed at the cut: relay counted
// that as a gap why=malformed on top of the size-cap gap setPayload counts, two gaps for one shortfall, and a parse
// fault for what was a capture bound. Incompressible gzip is the size-cap case that reaches it: its compressed
// bytes pass MaxBody before its decoded form does. The decode error at the cut is the cut, counted once as size-cap.
func TestGzipCutByTheCapIsOneSizeCapGap(t *testing.T) {
	const maxBody = 16 << 10
	raw := make([]byte, 40<<10)
	for i := range raw {
		raw[i] = byte(i*7919 + i>>3*104729)
	}
	var zb bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&zb, gzip.NoCompression) // stored blocks: the wire is longer than the body
	_, _ = zw.Write(raw)
	_ = zw.Close()
	d := &responseDeriver{ch: make(chan *derive.Message, 1)}
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(zb.Bytes())
	}, Options{Deriver: d, MaxBody: maxBody})
	resp := h.post("/v1/messages", []byte(`{"model":"m"}`), nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	m := <-d.ch
	h.sink.waitFor(t, record.KindSSLResponse, 1)
	if !m.Truncated || len(m.Body) == 0 || !bytes.HasPrefix(raw, m.Body) {
		t.Errorf("derive saw %d bytes, truncated %v; want a decoded prefix, truncated", len(m.Body), m.Truncated)
	}
	if n := gapCount(h.listener, GapMalformed); n != 0 {
		t.Errorf("malformed = %d, want 0: the decode failed only where the capture cap cut the copy", n)
	}
	if n := gapCount(h.listener, GapSizeCap); n != 1 {
		t.Errorf("size-cap = %d, want 1 for the one shortfall", n)
	}
}
