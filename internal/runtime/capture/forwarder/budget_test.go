// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Take grants what is left rather than refusing, and give puts it back. A reservation that
// leaked would silently turn capture off for the rest of the run, which is why the accounting is one
// small type with one caller per direction.
func TestBudgetGrantsWhatIsLeft(t *testing.T) {
	b := newBudget(100, 0)
	if got := b.take(60, 60); got != 60 {
		t.Fatalf("take(60) = %d, want 60", got)
	}
	if got := b.take(60, 60); got != 40 {
		t.Errorf("take(60) with 40 left = %d, want the 40 — a small body still lands whole", got)
	}
	if got := b.take(1, 1); got != 0 {
		t.Errorf("take(1) on an exhausted budget = %d, want 0", got)
	}
	b.give(100)
	if used := b.used.Load(); used != 0 {
		t.Errorf("used = %d after everything was returned, want 0", used)
	}
	if got := b.take(100, 100); got != 100 {
		t.Errorf("take(100) after the budget was returned = %d, want 100", got)
	}
}

// A collection is asked for only by a grant that loses bytes. held.grow asks for twice
// its capacity so that later bytes need no copy, and held.fit asks for a trimmed copy it can do without;
// a grant short of either still keeps every byte in hand, so it is no reason to spend the launcher's CPU
// on runtime.GC. A grant short of what the bytes in hand need is one, and still starts a collection.
// Measured on the rework: with 3000 bytes free and one event copy awaiting, growing a full 2048-byte
// buffer by 100 asked for 4096, got 3000, lost nothing, and forced a collection anyway.
func TestOnlyALossyGrantAsksForACollection(t *testing.T) {
	const filled = 2048
	setup := func(free int) (*budget, *held) {
		b := newBudget(filled+free, 0)
		h := b.hold(1 << 20)
		if room := h.grow(filled); room != filled {
			t.Fatalf("grow(%d) = %d on an empty budget", filled, room)
		}
		h.buf = h.buf[:filled]
		// One event copy awaiting the collector, which is what makes a collection worth asking for.
		b.awaiting.Store(1)
		return b, h
	}
	started := func(b *budget) bool { return b.lastCollect.Load() != 0 }

	b, h := setup(3000)
	if room := h.grow(100); room < 100 {
		t.Fatalf("grow(100) = %d with 3000 bytes free, want room for the 100", room)
	}
	if started(b) {
		t.Error("a doubling granted less than it asked for but everything it needed started a collection")
	}

	b, h = setup(3000)
	h.buf = h.buf[:filled-1000]
	used := b.used.Load()
	b.used.Store(b.limit) // no room for the trimmed copy, so fit keeps its headroom
	h.fit()
	b.used.Store(used)
	if started(b) {
		t.Error("a trim the budget could not pay for, which keeps its headroom and every byte, started a collection")
	}

	b, h = setup(50)
	if room := h.grow(100); room >= 100 {
		t.Fatalf("grow(100) = %d with 50 bytes free", room)
	}
	if !started(b) {
		t.Error("a grant short of the bytes in hand, which cuts the body, did not ask for the collection " +
			"that may free the room it lacks")
	}

	// A read of unknown length asks for a chunk of room it may never fill: a body of 30 more bytes read
	// into an array of 3000 lost nothing, though the grant was short of the chunk asked for.
	b, h = setup(3000)
	if extra, err := h.fill(bytes.NewReader(make([]byte, 30)), decodeChunk); extra != nil || err != nil {
		t.Fatalf("fill = %v, %v, want the whole 30 bytes kept", extra, err)
	}
	if len(h.bytes()) != filled+30 {
		t.Fatalf("fill kept %d bytes, want %d", len(h.bytes()), filled+30)
	}
	if started(b) {
		t.Error("a read granted less than its speculative chunk but room for every byte it read started a collection")
	}
	// The same read with no room left at all stops keeping bytes, and that is worth a collection.
	b, h = setup(0)
	if extra, _ := h.fill(bytes.NewReader(make([]byte, 30)), decodeChunk); extra == nil {
		t.Fatal("a read with no room kept a body it had no room for")
	}
	if !started(b) {
		t.Error("a read left with no room, which cuts the body, did not ask for a collection")
	}
	// Room reserved ahead of a declared length holds no byte yet, so a short grant there is not a loss.
	b, h = setup(50)
	h.growFor(1000, 0)
	if started(b) {
		t.Error("a reservation ahead of the bytes, short of what it asked for, started a collection")
	}
}

// Whatever MaxBody is raised to, one exchange at its largest still fits — its request
// and the request event's copy, its response with the decoded form or the decoded form with the response
// event's copy, and headroom for growth and escaping — so no configuration turns capture into nothing by
// arithmetic.
func TestBudgetFloorsAtOneExchange(t *testing.T) {
	if got := newBudget(1, 8<<20).limit; got != 5*(8<<20) {
		t.Errorf("limit = %d, want one exchange at its largest: five MaxBody-sized arrays", got)
	}
	if got := newBudget(0, 0).limit; got != DefaultMaxCaptureBytes {
		t.Errorf("limit = %d, want DefaultMaxCaptureBytes", got)
	}
}

// The budget a Manager shares across its listeners keeps the floor a single listener's
// own budget has. Options.MaxBody's zero means DefaultMaxBody and NewListener fills that in on its copy,
// but the shared budget is sized from the caller's Options before any listener exists — so sizing the
// floor from the raw zero drops it, and a run that caps MaxCaptureBytes while leaving MaxBody at its
// default is left holding less than the one body MaxBody promises to keep (§3, "floor one exchange").
func TestManagerSharedBudgetKeepsTheFloor(t *testing.T) {
	m, err := NewManager([]agent.ModelEndpoint{{Provider: "anthropic", Host: "api.anthropic.com"}},
		Options{MaxCaptureBytes: 4096})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer func() { _ = m.Stop() }()
	l := m.Listeners()[0]
	if want := int64(5 * l.opts.MaxBody); l.budget.limit != want {
		t.Errorf("shared budget limit = %d for a listener whose MaxBody is %d, want the floor %d: "+
			"no configuration may leave a run unable to keep one exchange", l.budget.limit,
			l.opts.MaxBody, want)
	}
}

// At the floor a lone exchange keeps its whole request and its whole compressed
// response, decoded, in its buffers and in its events' copies.
//
// A decode is reserved on top of the compressed bytes it reads from, since both are live until it ends,
// and an event's copy of a body is reserved until the event is unreachable (§3). So one exchange with a
// coded response holds four arrays at once, twice: its request, the request event's copy, and either the
// response as it came off the wire with the decoded form or the decoded form with the response event's
// copy. A floor short of that leaves the last of them a sliver, or nothing, however idle the rest of the
// run is. The budget is sized below the floor here, the request is MaxBody and the response decodes to
// exactly MaxBody from a compressed form that is most of MaxBody too.
func TestTheFloorKeepsOneExchangeWithACompressedResponse(t *testing.T) {
	const maxBody = 4096
	// Random base64 has no repeats to find, so Huffman coding alone takes it to about three quarters of
	// its size: a compressed form that is most of MaxBody while still under it, so the wire is captured
	// whole. The default level stores such input verbatim instead, which would overrun MaxBody.
	raw := make([]byte, maxBody)
	rng := rand.NewChaCha8([32]byte{1})
	_, _ = rng.Read(raw)
	prefix, suffix := `{"text":"`, `"}`
	text := base64.StdEncoding.EncodeToString(raw)[:maxBody-len(prefix)-len(suffix)]
	payload := prefix + text + suffix
	var compressed bytes.Buffer
	zw, err := gzip.NewWriterLevel(&compressed, gzip.HuffmanOnly)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(zw, payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	wire := compressed.Bytes()
	if len(wire) < maxBody/2 || len(wire) > maxBody {
		t.Fatalf("the compressed response is %d bytes; the case needs one between %d and %d",
			len(wire), maxBody/2, maxBody)
	}
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(wire)
	}, Options{MaxBody: maxBody, MaxCaptureBytes: 1})

	request := bytes.Repeat([]byte("a"), maxBody)
	roundTrip(t, h, newPost(t, h, request))

	req := h.sink.waitFor(t, record.KindSSLRequest, 1)[0]
	if n := len(recordedBody(t, req)); n != maxBody {
		t.Errorf("the request kept %d of its %d bytes at the floor", n, maxBody)
	}
	resp := h.sink.waitFor(t, record.KindSSLResponse, 1)[0]
	if got := recordedBody(t, resp); got != payload {
		t.Errorf("the response kept %d of its %d decoded bytes from %d compressed ones: the floor "+
			"did not cover the decode of a lone exchange's response (§3, floor one exchange)",
			len(got), len(payload), len(wire))
	}
	if n := gapCount(h.listener, GapSizeCap); n != 0 {
		t.Errorf("%d size-cap gaps for a lone exchange that fits the floor", n)
	}
	waitForBudgetReturned(t, h)
}

// The bytes every exchange in flight holds are bounded between them, and the bound falls on
// the record, never on the agent's call.
//
// One body is bounded by MaxBody, but how many are in flight at once is the agent's to choose: net/http
// serves every accepted connection in its own goroutine and R38 makes this listener the agent's only
// route to the model. Only the child is cloned into the run's cgroup, so an agent that opens enough
// concurrent calls would otherwise stay inside its own limits.memory while the launcher holding the
// supervisor and the ledger writer is OOM-killed. Three held exchanges fill the budget here with their
// request bodies and their events' copies of them, and under that pressure the fourth keeps less of its
// body — and says so as a size-cap gap (I4) — while the upstream still receives every byte of all four
// (§7: capture is best-effort against the agent's own call).
func TestCaptureBudgetBoundsEveryExchangeTogether(t *testing.T) {
	const (
		maxBody = 4096
		size    = 4000
		held    = 3
	)
	var (
		mu      sync.Mutex
		forward []int64
		seen    int
	)
	body := make([]byte, size)
	for i := range body {
		body[i] = byte('a' + i%26)
	}
	// Each held exchange keeps its body and its request event's copy, the body as a JSON string.
	fill := held * (size + quotedLen(body))
	release := make(chan struct{})
	blocked := make(chan struct{}, held)
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		got, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			t.Errorf("upstream read: %v", err)
		}
		mu.Lock()
		forward = append(forward, got)
		seen++
		hold := seen <= held
		mu.Unlock()
		if hold {
			// Held so the first exchanges still own their reservations when the last one
			// arrives: the bound is on what is in flight together, not on one body.
			blocked <- struct{}{}
			<-release
		}
		w.WriteHeader(http.StatusOK)
	}, Options{MaxBody: maxBody, MaxCaptureBytes: fill})
	var wg sync.WaitGroup
	unblock := releaseOnCleanup(t, release, &wg)
	if want := int64(fill); h.listener.budget.limit != want {
		t.Fatalf("budget limit = %d, want %d: the %d held exchanges no longer fill it, so nothing "+
			"here is under pressure", h.listener.budget.limit, want, held)
	}

	for range held {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := h.post("/v1/messages", body, nil)
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}()
	}
	for range held {
		<-blocked
	}

	resp := h.post("/v1/messages", body, nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	reqs := h.sink.waitFor(t, record.KindSSLRequest, held+1)
	last := payloadOf[record.SSLRequestPayload](t, reqs[held])
	if last.Size != size {
		t.Errorf("size = %d, want the whole %d the client sent — the record says what was sent, "+
			"whether or not capture kept it", last.Size, size)
	}
	if n := len(recordedBody(t, reqs[held])); n >= size {
		t.Errorf("the last concurrent exchange kept %d of %d body bytes; with %d full bodies "+
			"already in flight the budget had no room left for it", n, size, held)
	}
	if gapCount(h.listener, GapSizeCap) == 0 {
		t.Error("a body the budget cut short was not counted as a size-cap gap (I4)")
	}

	unblock()
	wg.Wait()
	h.sink.waitFor(t, record.KindSSLResponse, held+1)
	mu.Lock()
	defer mu.Unlock()
	if len(forward) != held+1 {
		t.Fatalf("%d requests reached the upstream, want %d", len(forward), held+1)
	}
	for i, n := range forward {
		if n != size {
			t.Errorf("request %d reached the upstream as %d bytes, want %d: the budget bounds "+
				"what capture keeps, never what the agent sends (§7)", i, n, size)
		}
	}
	waitForBudgetReturned(t, h)
}

// waitForBudgetReturned fails the test unless every reserved byte goes back once the exchanges have
// ended and nothing holds their events any more.
//
// What an exchange's buffers held goes back at the end of derive, just after the last event it emitted,
// and what an event's copy of a body holds goes back once the collector finds the event unreachable
// (§3). The harness's sink stands in for the run queue and the ledger writer, which hold every event
// until it is written, so it lets go of them, including any a derive still finishing emits after the
// client has its answer, and the wait collects until the cleanups have run rather than racing them.
func waitForBudgetReturned(t *testing.T, h *harness) {
	t.Helper()
	b := h.listener.budget
	deadline := time.Now().Add(5 * time.Second)
	for {
		h.sink.forget()
		if b.used.Load() == 0 || time.Now().After(deadline) {
			break
		}
		runtime.GC()
		time.Sleep(time.Millisecond)
	}
	if used := b.used.Load(); used != 0 {
		t.Errorf("%d bytes still reserved after every exchange ended and its events were let go; "+
			"a leak here turns capture off for the rest of the run", used)
	}
}

// An exchange Close already claimed is left alone (#28) — but the response buffer the
// racing handler built after that claim is still the handler's to return. Nothing else can: Close
// returned what the request held and never saw a response. A leak here is permanent for the run, and it
// degrades exactly the capture the budget exists to keep honest.
func TestFinishReturnsTheBudgetOfAnExchangeCloseAlreadyClaimed(t *testing.T) {
	h := newHarness(t, func(http.ResponseWriter, *http.Request) {}, Options{})
	const held = 512
	if got := h.listener.budget.take(held, held); got != held {
		t.Fatalf("take(%d) = %d", held, got)
	}
	// Never tracked, so claim() fails the way it does for an exchange Close has already taken.
	h.listener.finish(&exchange{id: "fx-claimed-by-close"}, &upstreamResult{held: held})
	if used := h.listener.budget.used.Load(); used != 0 {
		t.Errorf("%d bytes still reserved by an exchange Close had already claimed", used)
	}
}

// Every path that reserves capture budget gives it back, including the ones that never
// reach derive.
//
// derive's release covers only a tracked exchange; the others (a request refused before it became an
// exchange, one whose outbound leg failed, the room a read or a decode did not use) each have a give of
// their own, and budget.give's comment lists them. Each case here drives one of those paths, so a give
// deleted from any of them fails its case instead of silently leaving capture short for the rest of the
// run (§3).
func TestEveryReservationPathGivesItsBytesBack(t *testing.T) {
	const reply = `{"id":"msg_1","type":"message","content":[]}`
	plain := func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(reply))
	}
	wire := gzipBytes(t, reply)
	gzipped := func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(wire)
	}
	body := []byte(`{"model":"claude-opus-5","messages":[]}`)
	cases := []struct {
		name    string
		handler http.HandlerFunc
		rand    io.Reader
		send    func(t *testing.T, h *harness) int
		status  int
	}{
		{
			// A body of unknown length grows as it is read, each array it outgrows going back as
			// it is replaced and the headroom it ends with going back when it is trimmed; derive
			// returns the rest with the response.
			name:    "the room a read did not use, and a recorded exchange",
			handler: plain,
			send: func(t *testing.T, h *harness) int {
				req, err := http.NewRequest(http.MethodPost, h.listener.BaseURL()+"/v1/messages",
					io.NopCloser(bytes.NewReader(body)))
				if err != nil {
					t.Fatal(err)
				}
				return roundTrip(t, h, req)
			},
			status: http.StatusOK,
		},
		{
			// The decoded body grows as it is read and is trimmed when it ends; the compressed
			// bytes it replaced go back once it is complete.
			name:    "the compressed bytes a decode replaced and the room it did not use",
			handler: gzipped,
			send: func(t *testing.T, h *harness) int {
				return roundTrip(t, h, newPost(t, h, body))
			},
			status: http.StatusOK,
		},
		{
			name:    "a request whose exchange id could not be drawn",
			handler: plain,
			rand:    &failingRand{after: 0},
			send: func(t *testing.T, h *harness) int {
				return roundTrip(t, h, newPost(t, h, body))
			},
			status: http.StatusBadRequest,
		},
		{
			// The exchange id is drawn; the span id for the outbound leg is not.
			name:    "a request whose outbound leg could not be built",
			handler: plain,
			rand:    &failingRand{after: 1},
			send: func(t *testing.T, h *harness) int {
				return roundTrip(t, h, newPost(t, h, body))
			},
			status: http.StatusBadGateway,
		},
		{
			// The client declares more than it sends and then stops, so the read fails with the
			// reservation for the declared length still held.
			name:    "a request whose body could not be read",
			handler: plain,
			send: func(t *testing.T, h *harness) int {
				conn, err := net.Dial("tcp", h.listener.ln.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = conn.Close() }()
				_, err = io.WriteString(conn, "POST /v1/messages HTTP/1.1\r\nHost: forwarder\r\n"+
					"Content-Type: application/json\r\nContent-Length: 4096\r\n\r\n"+string(body))
				if err != nil {
					t.Fatal(err)
				}
				if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
					t.Fatal(err)
				}
				resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
				if err != nil {
					t.Fatalf("read response: %v", err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				return resp.StatusCode
			},
			status: http.StatusBadRequest,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.handler, Options{MaxBody: 4096, Rand: tc.rand})
			if got := tc.send(t, h); got != tc.status {
				t.Fatalf("status = %d, want %d: the case did not take the path it names", got, tc.status)
			}
			waitForBudgetReturned(t, h)
		})
	}
}

// newPost is a request with a body of declared length to the messages path.
func newPost(t *testing.T, h *harness, body []byte) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.listener.BaseURL()+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// roundTrip sends one request through the forwarder, drains the answer and returns its status.
func roundTrip(t *testing.T, h *harness, req *http.Request) int {
	t.Helper()
	resp := h.do(req)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// failingRand serves its first `after` reads with nonzero bytes and fails every read after them, so a
// case can choose which of the listener's random draws is the one that cannot be made.
type failingRand struct {
	mu    sync.Mutex
	after int
	n     int
}

func (r *failingRand) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.n >= r.after {
		return 0, errors.New("no randomness")
	}
	r.n++
	for i := range p {
		p[i] = byte(r.n)
	}
	return len(p), nil
}

// Every array capture holds is counted by its capacity, not by the length it was filled to.
//
// The array is what the heap holds, however much of it is filled. A buffer that grows by doubling, or
// reads one probe byte past its cap into the same array, ends with a capacity up to twice its length; a
// budget that counts lengths then lets every exchange in flight hold twice what it reserved, and the
// agent chooses how many are in flight. Each case reads one kind of body the way the forwarder does and
// checks that the array it kept is no larger than what the budget counts for it — and that the budget
// counts nothing else, so a buffer this path outgrew or trimmed went back.
func TestEveryCaptureArrayIsReservedToItsCapacity(t *testing.T) {
	const maxBody = 8192
	// chunks hands a body out a few hundred bytes at a time, the way a socket does, so a buffer of
	// unknown final size grows several times while it is read.
	chunks := func(b []byte) io.Reader { return &chunkReader{b: b, n: 700} }
	text := func(n int) []byte { return bytes.Repeat([]byte("abcdefghij"), n/10+1)[:n] }

	requests := []struct {
		name string
		req  func(t *testing.T, h *harness) *http.Request
		want int
	}{
		{"a request of declared length", func(t *testing.T, h *harness) *http.Request {
			return newPost(t, h, text(5000))
		}, 5000},
		{"a request of exactly MaxBody", func(t *testing.T, h *harness) *http.Request {
			return newPost(t, h, text(maxBody))
		}, maxBody},
		{"a chunked request", func(t *testing.T, h *harness) *http.Request {
			return chunkedPost(t, h, chunks(text(5000)))
		}, 5000},
		{"a chunked request past MaxBody", func(t *testing.T, h *harness) *http.Request {
			return chunkedPost(t, h, chunks(text(3*maxBody)))
		}, maxBody},
	}
	for _, tc := range requests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(http.ResponseWriter, *http.Request) {}, Options{MaxBody: maxBody})
			x, err := h.listener.readRequest(httptest.NewRecorder(), tc.req(t, h), 0)
			if err != nil {
				t.Fatalf("read request: %v", err)
			}
			if len(x.body) != tc.want {
				t.Fatalf("kept %d bytes of the body, want %d", len(x.body), tc.want)
			}
			assertCounted(t, h.listener.budget, "the request body", x.body, x.held)
			h.listener.budget.give(x.held)
		})
	}

	gzipped := gzipBytes(t, string(text(6000)))
	responses := []struct {
		name     string
		body     io.Reader
		length   int64
		encoding string
		want     int
	}{
		{"a response of declared length", bytes.NewReader(text(5000)), 5000, "", 5000},
		{"a streamed response", chunks(text(5000)), -1, "", 5000},
		{"a streamed response past MaxBody", chunks(text(3 * maxBody)), -1, "", maxBody},
		{"a decoded response", chunks(gzipped), -1, "gzip", 6000},
	}
	for _, tc := range responses {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(http.ResponseWriter, *http.Request) {}, Options{MaxBody: maxBody})
			resp := &http.Response{
				StatusCode:    http.StatusOK,
				Header:        http.Header{"Content-Type": {"application/json"}},
				Body:          io.NopCloser(tc.body),
				ContentLength: tc.length,
			}
			if tc.encoding != "" {
				resp.Header.Set("Content-Encoding", tc.encoding)
			}
			r := h.listener.relay(httptest.NewRecorder(), resp)
			if len(r.body) != tc.want {
				t.Fatalf("kept %d bytes of the response, want %d", len(r.body), tc.want)
			}
			assertCounted(t, h.listener.budget, "the response body", r.body, r.held)
			h.listener.budget.give(r.held)
		})
	}
}

// assertCounted fails unless body's array is no larger than what its buffer reserved and the budget
// counts exactly that reservation.
func assertCounted(t *testing.T, b *budget, what string, body []byte, held int) {
	t.Helper()
	if cap(body) > held {
		t.Errorf("%s keeps %d bytes in an array of %d, but only %d are counted: the other %d are "+
			"heap no budget bounds (§3)", what, len(body), cap(body), held, cap(body)-held)
	}
	if used := b.used.Load(); used != int64(held) {
		t.Errorf("the budget counts %d bytes with only %s held, which reserves %d: an array this "+
			"path let go of was not given back, or one it keeps was not counted", used, what, held)
	}
}

// chunkedPost is a request whose body has no declared length, so the forwarder reads it without knowing
// how large it will be. -1 is how net/http's server presents a chunked body to a handler, and it is also
// what a client sends as one.
func chunkedPost(t *testing.T, h *harness, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.listener.BaseURL()+"/v1/messages", io.NopCloser(body))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1
	return req
}

// chunkReader returns at most n bytes per read.
type chunkReader struct {
	b []byte
	n int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.b) == 0 {
		return 0, io.EOF
	}
	k := copy(p[:min(len(p), c.n)], c.b)
	c.b = c.b[k:]
	return k, nil
}

// A response the budget kept short is recorded as a prefix of the body, even when room
// comes back while it is still streaming.
//
// The pump reserves as each chunk arrives, and other exchanges give room back at any time. Were a later
// chunk kept once room returned, the record would join the bytes before the cut to the bytes after it
// with the gap closed up: a body the wire never carried, which blob(sha) would hash and derive would
// parse as though it were the response. Here the budget is full when the first chunk arrives and free
// again before the second.
func TestAResponseKeptShortStaysAPrefixOfTheBody(t *testing.T) {
	h := newHarness(t, func(http.ResponseWriter, *http.Request) {}, Options{MaxBody: 4096})
	b := h.listener.budget
	blocker := b.take(int(b.limit), int(b.limit))
	first, second := strings.Repeat("a", 100), strings.Repeat("b", 100)
	body := &scriptedReader{chunks: []string{first, second}, before: map[int]func(){
		1: func() { b.give(blocker) },
	}}
	rec := httptest.NewRecorder()
	r := h.listener.relay(rec, &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": {"text/event-stream"}},
		Body:          io.NopCloser(body),
		ContentLength: -1,
	})
	if got := rec.Body.String(); got != first+second {
		t.Errorf("the client received %d bytes, want all %d: the budget bounds the record, never "+
			"the agent's call (§7)", len(got), len(first+second))
	}
	if !strings.HasPrefix(first+second, string(r.body)) {
		t.Errorf("the record kept %q, which is not a prefix of the body: the chunk after the cut was "+
			"joined to the bytes before it", r.body)
	}
	if !r.truncated {
		t.Error("a response kept short was not marked truncated")
	}
	b.give(r.held)
}

// scriptedReader returns one chunk per read and runs before[i], when there is one, ahead of chunk i.
type scriptedReader struct {
	chunks []string
	before map[int]func()
	next   int
}

func (s *scriptedReader) Read(p []byte) (int, error) {
	if s.next == len(s.chunks) {
		return 0, io.EOF
	}
	if f := s.before[s.next]; f != nil {
		f()
	}
	n := copy(p, s.chunks[s.next])
	s.next++
	return n, nil
}
