// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bufio"
	"bytes"
	"compress/flate"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The decoded form of a body is bounded like any other body.
//
// The cap capture applies before decoding bounds the compressed bytes, which is no bound at all on the
// decoded ones: DEFLATE expands by up to 1032:1, so an unbounded decode turns a captured body of MaxBody
// into gigabytes held in the launcher — the process outside the run's cgroup, holding the supervisor's
// notify loop and the ledger writer. Past the limit the decoded prefix is kept and reported truncated,
// which R14/R29 already give a meaning to.
func TestDecodeWithBoundsItsOutput(t *testing.T) {
	const limit = 1024
	deflated := func(t *testing.T, n int) []byte {
		t.Helper()
		var buf bytes.Buffer
		zw, err := flate.NewWriter(&buf, flate.BestCompression)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := zw.Write(bytes.Repeat([]byte("A"), n)); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	open := func(r io.Reader) (io.Reader, error) { return flate.NewReader(r), nil }

	cases := []struct {
		name      string
		decoded   int
		wantLen   int
		wantTrunc bool
	}{
		{"a body under the limit decodes whole", limit - 1, limit - 1, false},
		{"a body that ends exactly at the limit is not cut short", limit, limit, false},
		{"a body past the limit keeps its prefix and says so", limit + 1, limit, true},
		{"a bomb is bounded by the limit, not by its own expansion", 64 << 20, limit, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newBudget(DefaultMaxCaptureBytes, 0)
			kept, ok, truncated, _ := decodeWith(b, deflated(t, tc.decoded), limit, open)
			if !ok || kept == nil {
				t.Fatal("the decode was reported as not decoded")
			}
			out := kept.bytes()
			if len(out) != tc.wantLen {
				t.Errorf("decoded %d bytes, want %d — the limit bounds the output, not the input",
					len(out), tc.wantLen)
			}
			if used := b.used.Load(); cap(out) > kept.reserved() || int64(kept.reserved()) != used {
				t.Errorf("the decoded array has capacity %d, the buffer reserves %d and the budget "+
					"counts %d: every byte of the array has to be counted (§3)", cap(out),
					kept.reserved(), used)
			}
			if truncated != tc.wantTrunc {
				t.Errorf("truncated = %v, want %v", truncated, tc.wantTrunc)
			}
		})
	}
}

// What a decode costs beyond its grant does not grow with the body.
//
// decodeWith reads at most one byte past its limit, but the decoder under it has state the budget does
// not count: flate's 32 KiB window and its tables. Listener.relay calls that fixed per-exchange overhead,
// like the pump's chunk buffer, and this pins "fixed". At a zero grant a small response and an 8 MiB bomb
// each cost only the decoder's few tens of KB, where a path that inflated the bomb whole and kept only
// the limit's worth would allocate megabytes per call and still pass every check on the output's length.
func TestADecodeCostsTheSameWhateverTheBody(t *testing.T) {
	gunzip, ok := decoderFor("gzip")
	if !ok {
		t.Fatal("no gzip decoder")
	}
	b := newBudget(DefaultMaxCaptureBytes, 0)
	perCall := func(wire []byte) uint64 {
		const n = 20
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		for range n {
			if out, _, _, _ := decodeWith(b, wire, 0, gunzip); out != nil && len(out.bytes()) != 0 {
				t.Fatalf("a zero grant kept %d decoded bytes", len(out.bytes()))
			}
		}
		runtime.ReadMemStats(&after)
		return (after.TotalAlloc - before.TotalAlloc) / n
	}
	// About 42 KB is measured on go1.27; the ceiling leaves room for the runtime's own allocations
	// during the loop while staying far below the 8 MiB the bomb decodes to.
	const ceiling = 128 << 10
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"a small response", gzipBytes(t, `{"ok":true}`)},
		{"an 8 MiB bomb", gzipBytes(t, strings.Repeat("A", 8<<20))},
	} {
		if got := perCall(tc.wire); got > ceiling {
			t.Errorf("%s: a decode with no grant allocated %d bytes per call from %d compressed ones, "+
				"want at most %d: the heap a decode uses outside the budget has to be the decoder's "+
				"fixed state, never a function of the body", tc.name, got, len(tc.wire), ceiling)
		}
	}
}

// The same bound on the whole path — a compressible response the upstream sends reaches the
// record as at most one body's worth, while the agent still receives every byte of it (R15, R21).
func TestACompressedResponseCannotExpandPastTheCap(t *testing.T) {
	const (
		maxBody  = 64 << 10
		expanded = 8 << 20
	)
	payload := strings.Repeat("A", expanded)
	wire := gzipBytes(t, payload)
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(wire)
	}, Options{MaxBody: maxBody})

	resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","messages":[]}`), nil)
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	// The test's own client added Accept-Encoding and so decompresses what it reads; what matters is
	// that every byte the upstream sent arrived, whatever the record kept of it.
	if string(got) != payload {
		t.Errorf("the client received %d bytes, want the %d the upstream sent: the cap bounds what "+
			"capture keeps, never what is forwarded (R21)", len(got), expanded)
	}

	ev := h.sink.waitFor(t, record.KindSSLResponse, 1)[0]
	if n := len(recordedBody(t, ev)); n > maxBody {
		t.Errorf("the record kept %d decoded bytes of a %d byte body from %d compressed ones; "+
			"the cap has to bound the decode too, or the launcher holds the whole expansion",
			n, expanded, len(wire))
	}
	if gapCount(h.listener, GapSizeCap) == 0 {
		t.Error("a decode stopped at the cap was not counted as a size-cap gap for the run's report (I4)")
	}
}

// A decode's output is paid for out of the capture budget, each array reserved before it
// exists, and never out of the reservation of the compressed bytes it reads from.
//
// decodeWith reads the compressed copy until its output is complete, so the two arrays are live together
// for the whole decode, and the budget is over every array capture holds (§3). A decode that borrowed the
// compressed form's reservation would leave its own array uncounted, up to one body for every compressed
// response in flight, in the launcher: the process whose OOM takes the supervisor and the ledger writer
// down with it. Here the held requests and their events' copies fill the budget but for the compressed
// response, so the budget sits at exactly its limit when that response is decoded: any byte decodeWith
// takes out of the decoder past its one probe byte is kept in an array no reservation covers. The record
// has to keep none of the body and say it was cut (gap why=size-cap).
func TestADecodeIsReservedOnTopOfWhatItReads(t *testing.T) {
	const (
		maxBody = 1024
		payload = `{"ok":true}`
		held    = 3
	)
	wire := gzipBytes(t, payload)
	// Each held request keeps its body and its event's copy of it, which is the body as a JSON string.
	hold := bytes.Repeat([]byte("a"), maxBody)
	fill := held*(maxBody+quotedLen(hold)) + len(wire)

	// The gzip decoder is metered where it hands bytes out, and each read is weighed against what the
	// budget has reserved at that moment. The budget is full while this decode runs, so no byte the
	// decoder hands out can land in an array the budget counts, and what capture holds live is every
	// reservation plus those bytes. Restored by a cleanup registered before the harness's own, so it
	// runs only once Close has joined the handler goroutines that read the table.
	var (
		shared  atomic.Pointer[budget]
		mu      sync.Mutex
		decoded int64
		peak    int64
	)
	gunzip := decoders["gzip"]
	t.Cleanup(func() { decoders["gzip"] = gunzip })
	decoders["gzip"] = func(r io.Reader) (io.Reader, error) {
		zr, err := gunzip(r)
		if err != nil {
			return nil, err
		}
		return &meteredReader{r: zr, read: func(n int) {
			mu.Lock()
			defer mu.Unlock()
			decoded += int64(n)
			if b := shared.Load(); b != nil {
				peak = max(peak, b.used.Load()+decoded)
			}
		}}, nil
	}

	release := make(chan struct{})
	blocked := make(chan struct{}, held)
	var seen atomic.Int64
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if seen.Add(1) <= held {
			// Held so their request bodies and their events' copies still own their
			// reservations when the last exchange captures its response, which then takes the
			// last of the budget.
			blocked <- struct{}{}
			<-release
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(wire)
	}, Options{MaxBody: maxBody, MaxCaptureBytes: fill})
	var wg sync.WaitGroup
	unblock := releaseOnCleanup(t, release, &wg)
	shared.Store(h.listener.budget)
	limit := h.listener.budget.limit
	if limit != int64(fill) {
		t.Fatalf("budget limit = %d, want %d: the held requests and the compressed response no "+
			"longer fill it, so the decode is not made at a full budget", limit, fill)
	}

	for range held {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := h.post("/v1/messages", hold, nil)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()
	}
	for range held {
		<-blocked
	}

	resp := h.post("/v1/messages", nil, nil)
	got, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || string(got) != payload {
		t.Errorf("the client received %q (%v), want %q: the budget bounds the record, never the "+
			"agent's call (§7)", got, err, payload)
	}

	ev := h.sink.waitFor(t, record.KindSSLResponse, 1)[0]
	mu.Lock()
	gotDecoded, gotPeak := decoded, peak
	mu.Unlock()
	if gotDecoded == 0 {
		t.Fatal("the gzip decoder never ran, so nothing here tested the decode")
	}
	if gotPeak > limit+1 {
		t.Errorf("capture held %d bytes live during the decode against a budget of %d: %d decoded "+
			"bytes were kept with no reservation while the compressed ones they came from were "+
			"still held (§3)", gotPeak, limit, gotPeak-limit)
	}
	if body := recordedBody(t, ev); body != "" {
		t.Errorf("recorded body = %q with the budget exhausted, want none of it: every decoded byte "+
			"kept here is one the budget never granted", body)
	}
	if gapCount(h.listener, GapSizeCap) == 0 {
		t.Error("a decode the budget cut to nothing was not counted as a size-cap gap (I4)")
	}

	unblock()
	wg.Wait()
	h.sink.waitFor(t, record.KindSSLResponse, held+1)
	waitForBudgetReturned(t, h)
}

// releaseOnCleanup returns the function that lets a test's held upstream handlers go, and registers a
// cleanup that calls it too and then waits for wg's clients. A test that stops early (t.Fatal, or a
// waitFor that gives up) would otherwise leave those handlers blocked: httptest.Server.Close waits for
// every active request, so the harness's cleanup never returns and the failure surfaces as the package's
// timeout panic instead of its own message. Call it after newHarness: cleanups run last-registered
// first, so this one then runs before the harness closes the listener and the upstream.
func releaseOnCleanup(t *testing.T, release chan struct{}, wg *sync.WaitGroup) func() {
	t.Helper()
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() {
		unblock()
		wg.Wait()
	})
	return unblock
}

// meteredReader reports how many bytes each read produced.
type meteredReader struct {
	r    io.Reader
	read func(n int)
}

func (m *meteredReader) Read(p []byte) (int, error) {
	n, err := m.r.Read(p)
	if n > 0 {
		m.read(n)
	}
	return n, err
}

// The codings this component undoes and the ones it leaves alone, from the one table both
// the decode and the memory reserved for it read — capture/httpstream's, so br and zstd are undone here
// as they are on the uprobe path (R15). A coding with no decoder here is not an error: its bytes are
// recorded as they came off the wire, reported undecoded, and derive says unparsed why=encoding (R15) —
// which is what identityEncoding separates from a body that needed nothing done. A list is decodable
// only when every coding in it is.
func TestDecoderForKnowsExactlyWhatItCanUndo(t *testing.T) {
	cases := []struct {
		encoding string
		decodes  bool
		identity bool
	}{
		{"", false, true},
		{"identity", false, true},
		{"gzip", true, false},
		{"GZIP", true, false},
		{" x-gzip ", true, false},
		{"deflate", true, false},
		{"br", true, false},
		{"zstd", true, false},
		{"gzip, br", true, false},
		{"gzip, identity", true, false},
		{"compress", false, false},
		{"gzip, compress", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.encoding, func(t *testing.T) {
			if _, ok := decoderFor(tc.encoding); ok != tc.decodes {
				t.Errorf("decoderFor(%q) = %v, want %v", tc.encoding, ok, tc.decodes)
			}
			if got := identityEncoding(tc.encoding); got != tc.identity {
				t.Errorf("identityEncoding(%q) = %v, want %v", tc.encoding, got, tc.identity)
			}
		})
	}
}

// recordedBody reads the body an event's payload carries, for the assertions about what capture kept.
func recordedBody(t *testing.T, ev *record.Event) string {
	t.Helper()
	var fields struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(ev.Payload, &fields); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return fields.Body
}

// TestGzipStreamCutByBudgetIsUnmetered pins M2: a gzip event stream whose record copy the decode limit cut
// after message_start is not scanned on the wire, so derive saw message_start's usage alone; it is reported
// unmetered, as the uprobe path's SizeCut rule reports it, even though derive bounded its output (H3).
func TestGzipStreamCutByBudgetIsUnmetered(t *testing.T) {
	var sse strings.Builder
	sse.WriteString("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-opus-5\",\"usage\":{\"input_tokens\":150000,\"output_tokens\":1}}}\n\n")
	for i := 0; i < 64; i++ {
		fmt.Fprintf(&sse, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"%s\"}}\n\n", strings.Repeat("x", 4096))
	}
	sse.WriteString("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":900}}\n\n")
	sse.WriteString("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	wire := gzipBytes(t, sse.String())
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(wire)
	}, Options{MaxBody: 16 << 10, Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})
	m := meter(h)
	resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","max_tokens":4096,"stream":true,"messages":[]}`), nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	h.sink.waitFor(t, record.KindSSLResponse, 1)
	deadline := time.Now().Add(2 * time.Second)
	for len(m.reported()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := m.reported(); len(got) != 1 {
		t.Fatalf("reported %q, want the budget-cut gzip stream reported unmetered once", got)
	}
}

// TestScannedDeltaReplacesTheBound: derive's max_tokens bound gives way to the message_delta the scanner read
// on the wire, and stands when the scanner saw none (H3).
func TestScannedDeltaReplacesTheBound(t *testing.T) {
	derived := &record.Usage{Input: 100, Output: 4096, OutputBound: true}
	scanned := &record.Usage{Input: 100, Output: 900}
	if got := mergeUsage(derived, scanned, true); got.Output != 900 || got.OutputBound {
		t.Errorf("with the final delta scanned: %+v, want output 900 unbounded", got)
	}
	if got := mergeUsage(derived, &record.Usage{Input: 100, Output: 1}, false); got.Output != 4096 || !got.OutputBound {
		t.Errorf("without it: %+v, want the bound kept", got)
	}
}

// oneByte is a body that never ends, one byte per read.
type oneByte struct{}

func (oneByte) Read(p []byte) (int, error) { p[0] = 'x'; return 1, nil }

// TestBodyTotalDeadlineFakeClock pins M3 on idleBody: a body that keeps arriving within its idle deadline is
// still ended at its total one.
func TestBodyTotalDeadlineFakeClock(t *testing.T) {
	start := time.Unix(1_000_000, 0)
	clock := start
	b := &idleBody{r: oneByte{}, rc: http.NewResponseController(httptest.NewRecorder()), idle: 30 * time.Second,
		deadline: start.Add(DefaultBodyTimeout), now: func() time.Time { return clock }}
	buf := make([]byte, 1)
	for i := 0; ; i++ {
		_, err := b.Read(buf)
		if err != nil {
			if !errors.Is(err, errBodyTimeout) {
				t.Fatalf("err = %v, want errBodyTimeout", err)
			}
			if elapsed := clock.Sub(start); elapsed < DefaultBodyTimeout {
				t.Fatalf("ended after %v, before the total deadline", elapsed)
			}
			return
		}
		if i > 1000 {
			t.Fatal("a body trickling one byte every 29 s was never ended")
		}
		clock = clock.Add(29 * time.Second)
	}
}

// TestTricklingBodyIsCutAtItsTotalDeadline pins M3 end to end: a body that never goes idle long enough for the
// idle deadline is still answered 400 at its total deadline, and gives its reservation back.
func TestTricklingBodyIsCutAtItsTotalDeadline(t *testing.T) {
	h := newHarness(t, func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
	}, Options{BodyIdleTimeout: 300 * time.Millisecond, BodyTimeout: 500 * time.Millisecond})
	c, err := net.Dial("tcp", strings.TrimPrefix(h.listener.BaseURL(), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n{", 1<<20)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				if _, err := c.Write([]byte("x")); err != nil {
					return
				}
			}
		}
	}()
	began := time.Now()
	// The bounds are ten and twenty times the 500 ms total deadline, so a loaded runner does not fail a
	// forwarder that answered on time.
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("no answer to a trickling upload within 10 s: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
	if took := time.Since(began); took > 5*time.Second {
		t.Errorf("answered after %v", took)
	}
	deadline := time.Now().Add(time.Second)
	for h.listener.budget.used.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if used := h.listener.budget.used.Load(); used != 0 {
		t.Errorf("the cut upload still holds %d bytes", used)
	}
}
