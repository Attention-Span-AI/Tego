// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/attention-span-ai/tego/internal/runtime/capture/httpstream"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// encodedResponse is the Anthropic response every coding below carries, and the usage derive must read out
// of it once the forwarder has undone the coding.
const encodedResponse = `{"id":"msg_01Xq0002Z","type":"message","model":"claude-opus-5","stop_reason":"end_turn",` +
	`"content":[{"type":"text","text":"done"}],"usage":{"input_tokens":1000,"output_tokens":102}}`

// recordingTransport is a cannedTransport that also keeps the headers of the last request it was sent, so a
// test can see what the upstream was offered.
type recordingTransport struct {
	cannedTransport
	mu   sync.Mutex
	last http.Header
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.last = req.Header.Clone()
	r.mu.Unlock()
	return r.cannedTransport.RoundTrip(req)
}

func (r *recordingTransport) seen() http.Header {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last
}

// Every coding R15 names reaches the record decoded, and derive reads the usage out of it
// (capture-derive.md R15, and E22 for the forwarder). Before the forwarder shared capture/httpstream's decoders it undid gzip and deflate only, so a
// br or zstd answer was recorded as compressed bytes, derive said unparsed why=encoding, the ssl_response
// carried no usage, and a run's token and cost budgets never counted the call. The deflate rows pin both
// forms a server sends: the zlib wrapper RFC 9110 §8.4.1.2 defines, and the bare stream many send instead.
func TestEveryCodingIsDecodedForTheRecordAndForUsage(t *testing.T) {
	cases := []struct {
		name     string
		encoding string
		encode   func(*testing.T, []byte) []byte
	}{
		{"identity", "", func(_ *testing.T, b []byte) []byte { return b }},
		{"gzip", "gzip", func(t *testing.T, b []byte) []byte { return gzipBytes(t, string(b)) }},
		{"x-gzip", "x-gzip", func(t *testing.T, b []byte) []byte { return gzipBytes(t, string(b)) }},
		{"deflate as zlib", "deflate", zlibEncoded},
		{"deflate bare", "deflate", rawDeflateEncoded},
		{"br", "br", brotliEncoded},
		{"zstd", "zstd", zstdEncoded},
		{"stacked", "gzip, br", func(t *testing.T, b []byte) []byte {
			return brotliEncoded(t, gzipBytes(t, string(b)))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := http.Header{"Content-Type": {"application/json"}}
			if tc.encoding != "" {
				header.Set("Content-Encoding", tc.encoding)
			}
			sink := serveCanned(t, &recordingTransport{cannedTransport: cannedTransport{
				status: http.StatusOK, header: header, body: string(tc.encode(t, []byte(encodedResponse))),
			}}, nil)
			ev := sink.waitFor(t, record.KindSSLResponse, 1)[0]
			p := payloadOf[record.SSLResponsePayload](t, ev)
			if p.ContentEncoding != tc.encoding {
				t.Errorf("content_encoding = %q, want %q: the record says what the wire used", p.ContentEncoding, tc.encoding)
			}
			if p.Usage == nil || p.Usage.Input != 1000 || p.Usage.Output != 102 {
				t.Errorf("usage = %+v, want input 1000 and output 102: a %s answer the forwarder cannot "+
					"decode reaches no budget", p.Usage, tc.name)
			}
			if p.Model != "claude-opus-5" {
				t.Errorf("model = %q, want claude-opus-5", p.Model)
			}
			if got := recordedBody(t, ev); got != encodedResponse {
				t.Errorf("recorded body = %q, want the decoded response (R15: blob(sha) hashes decoded content)", got)
			}
			for _, d := range sink.of(record.KindDecision) {
				if strings.Contains(string(d.Payload), "unparsed") {
					t.Errorf("derive reported %s for a %s body it should have read", d.Payload, tc.name)
				}
			}
		})
	}
}

// A coding with no decoder anywhere is still recorded as it came off the wire and reported
// undecoded, never guessed at (R15, R29).
func TestAnUndecodableCodingIsRecordedAsTheWireSentIt(t *testing.T) {
	wire := "\x1f\x9d compressed with LZW"
	sink := serveCanned(t, &recordingTransport{cannedTransport: cannedTransport{
		status: http.StatusOK,
		header: http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {"compress"}},
		body:   wire,
	}}, nil)
	ev := sink.waitFor(t, record.KindSSLResponse, 1)[0]
	if p := payloadOf[record.SSLResponsePayload](t, ev); p.Usage != nil {
		t.Errorf("usage = %+v read out of a body nothing decoded", p.Usage)
	}
	decisions := sink.waitFor(t, record.KindDecision, 1)
	if !strings.Contains(string(decisions[0].Payload), `"why":"encoding"`) {
		t.Errorf("decision = %s, want unparsed why=encoding", decisions[0].Payload)
	}
}

// The upstream is offered only codings capture can undo with a decoder of fixed size (R20).
// The upstream chooses the response's coding from the request's offer, so passing a client's
// "br, zstd, dcb" through untouched lets the upstream answer in a coding whose decoder holds a window of
// up to 16 MiB outside the capture budget, or in one nothing here decodes at all, which records no usage.
func TestAcceptEncodingIsNarrowedToWhatCaptureCanDecode(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"gzip and br keeps gzip", []string{"gzip, deflate, br, zstd"}, "gzip, deflate"},
		{"q-values are the client's own", []string{"br;q=1.0, gzip;q=0.5"}, "gzip;q=0.5"},
		{"a wildcard is not an offer capture can keep", []string{"*"}, "identity"},
		{"nothing decodable leaves identity", []string{"br, zstd, dcb, dcz"}, "identity"},
		{"repeated fields are one list", []string{"br", "GZip"}, "GZip"},
		{"x-gzip is gzip", []string{"x-gzip, compress"}, "x-gzip"},
		{"identity stays", []string{"identity"}, "identity"},
		{"an explicit refusal stays the client's", []string{"gzip;q=0, deflate"}, "gzip;q=0, deflate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := narrowAcceptEncoding(tc.in); !ok || got != tc.want {
				t.Errorf("narrowAcceptEncoding(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	t.Run("the upstream sees the narrowed offer", func(t *testing.T) {
		tr := &recordingTransport{cannedTransport: cannedTransport{status: http.StatusOK, body: `{}`}}
		sink := serveCanned(t, tr, http.Header{"Accept-Encoding": {"br, zstd, gzip"}})
		sink.waitFor(t, record.KindSSLResponse, 1)
		if got := tr.seen().Values("Accept-Encoding"); len(got) != 1 || got[0] != "gzip" {
			t.Errorf("the upstream was offered %q, want [gzip]", got)
		}
	})
	t.Run("an absent offer stays absent", func(t *testing.T) {
		tr := &recordingTransport{cannedTransport: cannedTransport{status: http.StatusOK, body: `{}`}}
		sink := serveCanned(t, tr, http.Header{})
		sink.waitFor(t, record.KindSSLResponse, 1)
		if got := tr.seen().Values("Accept-Encoding"); len(got) != 0 {
			t.Errorf("the upstream was offered %q for a request that offered nothing", got)
		}
	})
}

// The decoder state a br or zstd answer costs is bounded by the window its stream
// declares, never by the body. A zero grant decodes one probe byte, and a stream that decodes to 64 MiB
// still costs about one window per decode rather than the body the upstream expanded to.
func TestABrOrZstdDecodeCostsItsWindowNotItsBody(t *testing.T) {
	b := newBudget(DefaultMaxCaptureBytes, 0)
	bomb := bytes.Repeat([]byte("A"), 64<<20)
	for _, tc := range []struct {
		coding string
		wire   []byte
		// ceiling is the coding's largest window plus the decoder's fixed tables and the loop's
		// own allocations: 16 MiB for br (RFC 7932), 8 MiB for zstd as httpstream caps it (RFC 9659).
		ceiling uint64
	}{
		{"br", brotliEncoded(t, bomb), 24 << 20},
		{"zstd", zstdEncoded(t, bomb), 12 << 20},
	} {
		t.Run(tc.coding, func(t *testing.T) {
			open, ok := decoderFor(tc.coding)
			if !ok {
				t.Fatalf("no %s decoder", tc.coding)
			}
			const n = 4
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			for range n {
				if out, _, _, _ := decodeWith(b, tc.wire, 0, open); out != nil && len(out.bytes()) != 0 {
					t.Fatalf("a zero grant kept %d decoded bytes", len(out.bytes()))
				}
			}
			runtime.ReadMemStats(&after)
			if per := (after.TotalAlloc - before.TotalAlloc) / n; per > tc.ceiling {
				t.Errorf("a %s decode with no grant allocated %d bytes per call for a 64 MiB body, want at "+
					"most %d: its heap outside the budget has to be the decoder's window", tc.coding, per, tc.ceiling)
			}
		})
	}
}

// A Content-Encoding list longer than httpstream.MaxCodings is recorded as the wire sent it
// and reported undecoded, and relaying it costs no decoder window at all. Every layer of a stack is open
// until its decode ends, and a header names a layer in five bytes, so before the cap thirty zstd layers in
// a body of a few hundred bytes allocated 270 MB, and gzip repeated to the 1 MiB header limit was about
// 200k windows of 42 KB, all of it outside the capture budget (§3). A list at the cap still decodes, and
// costs no more than that many windows.
func TestAContentEncodingOfManyLayersIsNotDecoded(t *testing.T) {
	layered := func(coding string, n int, encode func(*testing.T, []byte) []byte) (string, []byte) {
		wire := []byte(encodedResponse)
		names := make([]string, n)
		for i := range n {
			wire = encode(t, wire)
			names[i] = coding
		}
		return strings.Join(names, ", "), wire
	}
	relay := func(t *testing.T, encoding string, wire []byte) (*upstreamResult, uint64) {
		t.Helper()
		h := newHarness(t, func(http.ResponseWriter, *http.Request) {}, Options{})
		resp := &http.Response{
			StatusCode:    http.StatusOK,
			Header:        http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {encoding}},
			Body:          io.NopCloser(bytes.NewReader(wire)),
			ContentLength: int64(len(wire)),
		}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		r := h.listener.relay(httptest.NewRecorder(), resp)
		runtime.ReadMemStats(&after)
		t.Cleanup(func() { h.listener.budget.give(r.held) })
		return r, after.TotalAlloc - before.TotalAlloc
	}
	gz := func(t *testing.T, b []byte) []byte { return gzipBytes(t, string(b)) }
	// One window per layer the cap allows, each with a block of headroom, plus the relay's own buffers.
	ceiling := uint64(httpstream.MaxCodings*(httpstream.ZstdMaxWindow+1<<20) + 1<<20)

	for _, tc := range []struct {
		coding string
		layers int
		encode func(*testing.T, []byte) []byte
	}{
		{"zstd", 30, zstdWideWindow},
		{"gzip", 1000, gz},
	} {
		t.Run(fmt.Sprintf("%d %s layers", tc.layers, tc.coding), func(t *testing.T) {
			encoding, wire := layered(tc.coding, tc.layers, tc.encode)
			r, allocated := relay(t, encoding, wire)
			if r.decoded {
				t.Error("a list past MaxCodings was decoded")
			}
			if !bytes.Equal(r.body, wire) {
				t.Errorf("recorded %d bytes, want the %d the wire carried: an undecodable coding is "+
					"recorded as it came (R15)", len(r.body), len(wire))
			}
			if allocated > ceiling {
				t.Errorf("relaying %d bytes under %d %s layers allocated %d bytes, want at most %d: "+
					"every layer's window was opened", len(wire), tc.layers, tc.coding, allocated, ceiling)
			}
		})
	}

	t.Run("a list at the cap decodes", func(t *testing.T) {
		encoding, wire := layered("zstd", httpstream.MaxCodings, zstdWideWindow)
		r, allocated := relay(t, encoding, wire)
		if !r.decoded || string(r.body) != encodedResponse {
			t.Errorf("decoded = %v, body = %q: a list of %d codings is within the cap", r.decoded, r.body,
				httpstream.MaxCodings)
		}
		if allocated > ceiling {
			t.Errorf("a %d-layer decode allocated %d bytes, want at most %d", httpstream.MaxCodings,
				allocated, ceiling)
		}
	})

	t.Run("derive says why", func(t *testing.T) {
		encoding, wire := layered("gzip", httpstream.MaxCodings+1, gz)
		sink := serveCanned(t, &recordingTransport{cannedTransport: cannedTransport{
			status: http.StatusOK,
			header: http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {encoding}},
			body:   string(wire),
		}}, nil)
		ev := sink.waitFor(t, record.KindSSLResponse, 1)[0]
		if p := payloadOf[record.SSLResponsePayload](t, ev); p.ContentEncoding != encoding || p.Usage != nil {
			t.Errorf("content_encoding = %q, usage = %+v: want the wire's list and no usage read out of "+
				"bytes nothing decoded", p.ContentEncoding, p.Usage)
		}
		decisions := sink.waitFor(t, record.KindDecision, 1)
		if !strings.Contains(string(decisions[0].Payload), `"why":"encoding"`) {
			t.Errorf("decision = %s, want unparsed why=encoding", decisions[0].Payload)
		}
	})
}

// zstdWideWindow wraps b in one zstd frame whose header declares the largest window httpstream accepts,
// holding b as a single raw block. The decoder allocates the declared window before it reads the block, so
// each layer of these costs a window however few bytes it carries, which is the shape that made a
// 271-byte body cost 270 MB.
func zstdWideWindow(t *testing.T, b []byte) []byte {
	t.Helper()
	if len(b) >= 128<<10 {
		t.Fatalf("a raw zstd block holds less than 128 KiB, not %d bytes", len(b))
	}
	exponent := byte(0)
	for 1<<(10+int(exponent)) < httpstream.ZstdMaxWindow {
		exponent++
	}
	// Magic; a Frame_Header_Descriptor of 0 (a Window_Descriptor follows, no content size, no checksum);
	// the Window_Descriptor; then a block header marking the one block last and raw, and its size.
	block := uint32(len(b))<<3 | 1
	out := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, exponent << 3, byte(block), byte(block >> 8), byte(block >> 16)}
	return append(out, b...)
}

// serveCanned runs one POST through a listener whose upstream is tr and returns the sink it emitted into.
func serveCanned(t *testing.T, tr http.RoundTripper, header http.Header) *fakeSink {
	t.Helper()
	l, err := NewListener(
		agent.ModelEndpoint{Provider: "anthropic", Host: "api.anthropic.com", Port: 443},
		Options{
			Transport: tr,
			Deriver:   derive.NewDispatcher([]derive.Parser{anthropic.New()}),
			Bodies:    true,
		})
	if err != nil {
		t.Fatalf("new listener: %v", err)
	}
	sink := &fakeSink{}
	l.peers = anyPeer
	l.Bind(testRun, sink)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = l.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); _ = l.Close(); <-done })

	req, err := http.NewRequest(http.MethodPost, l.BaseURL()+"/v1/messages",
		strings.NewReader(`{"model":"claude-opus-5","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	// A transport that never asks for compression itself, so the header under test is the only offer.
	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return sink
}

func zlibEncoded(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func rawDeflateEncoded(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func brotliEncoded(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := brotli.NewWriterLevel(&buf, brotli.DefaultCompression)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zstdEncoded(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// An upstream's response headers are held to the 1 MiB a request's are (§3 "Forwarder capture
// buffers"). A response event carries the upstream's allow-listed headers outside the capture budget, and
// net/http's Transport would otherwise take up to 10 MiB of them, ten times the bound §3 states. A response
// past the bound is an upstream failure the agent sees as 502 (R26) and the record as a request with no
// response, closed to a gap.
func TestUpstreamResponseHeadersAreBoundedLikeRequestHeaders(t *testing.T) {
	if got := NewTransport("api.anthropic.com").MaxResponseHeaderBytes; got != http.DefaultMaxHeaderBytes {
		t.Fatalf("MaxResponseHeaderBytes = %d, want http.DefaultMaxHeaderBytes (%d)", got, http.DefaultMaxHeaderBytes)
	}
	big := strings.Repeat("h", 2<<20)
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Oversized", big)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(up.Close)
	host, port := hostPort(t, up.Listener.Addr().String())
	tr := NewTransport(host)
	pool := x509.NewCertPool()
	pool.AddCert(up.Certificate())
	tr.TLSClientConfig.RootCAs = pool
	t.Cleanup(tr.CloseIdleConnections)

	l, err := NewListener(agent.ModelEndpoint{Provider: "anthropic", Host: host, Port: port},
		Options{Transport: tr, Bodies: true})
	if err != nil {
		t.Fatalf("new listener: %v", err)
	}
	sink := &fakeSink{}
	l.peers = anyPeer
	l.Bind(testRun, sink)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = l.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); _ = l.Close(); <-done })

	resp, err := http.Post(l.BaseURL()+"/v1/messages", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d for an upstream answering with 2 MiB of headers, want 502 (R26)", resp.StatusCode)
	}
	if n := len(sink.of(record.KindSSLResponse)); n != 0 {
		t.Errorf("%d ssl_response lines carry headers past the bound", n)
	}
}

// TestExpectIsNotForwardedUpstream: the listener answers a client's Expect: 100-continue itself when it reads
// the body, so the expectation is spent before the upstream leg exists. Forwarded, it made the Transport
// withhold a body already in hand until the upstream sent an interim 100, a 1s stall (ExpectContinueTimeout)
// on every such request to an upstream that sends none (R20).
func TestExpectIsNotForwardedUpstream(t *testing.T) {
	tr := &recordingTransport{cannedTransport: cannedTransport{status: http.StatusOK, body: `{}`}}
	sink := serveCanned(t, tr, http.Header{"Expect": {"100-continue"}})
	sink.waitFor(t, record.KindSSLResponse, 1)
	if got := tr.seen().Values("Expect"); len(got) != 0 {
		t.Errorf("the upstream was sent Expect %q the listener already answered", got)
	}
}

func TestAcceptEncodingHonorsIdentityRefusal(t *testing.T) {
	for _, offer := range []string{"br, identity;q=0", "br, *;q=0", "gzip;q=0, deflate;q=0, identity;q=0", "*;q=0"} {
		if got, ok := narrowAcceptEncoding([]string{offer}); ok {
			t.Errorf("%q accepted as %q", offer, got)
		}
	}
	for _, tc := range []struct{ offer, want string }{
		{"gzip, *;q=0", "gzip, identity;q=0"},
		{"br, identity;q=0, *;q=0.5", "identity;q=0, gzip;q=0.5"},
		{"identity;q=0.1, *;q=0", "identity;q=0.1"},
	} {
		if got, ok := narrowAcceptEncoding([]string{tc.offer}); !ok || got != tc.want {
			t.Errorf("%q: %q %v; want %q", tc.offer, got, ok, tc.want)
		}
	}
}

func TestUnacceptableEncodingNeverContactsUpstream(t *testing.T) {
	tr := &recordingTransport{cannedTransport: cannedTransport{status: http.StatusOK, body: `{}`}}
	l, err := NewListener(agent.ModelEndpoint{Host: "api.anthropic.com", Provider: "anthropic"}, Options{Transport: tr})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	r := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader("{}"))
	r.Header.Set("Accept-Encoding", "br, identity;q=0")
	w := httptest.NewRecorder()
	l.forward(w, r, 1)
	if w.Code != http.StatusNotAcceptable {
		t.Fatalf("status %d, want 406", w.Code)
	}
	if tr.seen() != nil {
		t.Fatal("unsupported negotiation reached the upstream")
	}
}
