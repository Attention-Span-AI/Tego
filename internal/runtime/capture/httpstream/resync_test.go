// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// gapCount is how many occurrences a reason carries across an assembler's gaps.
func gapCount(gaps []Gap, why string) int64 {
	var n int64
	for _, g := range gaps {
		if g.Why == why {
			n += g.Count
		}
	}
	return n
}

// keepAlive feeds n request/response exchanges on one key, each request then its response, the way a client
// that waits for every answer uses a keep-alive connection, and returns every message and the first error.
func keepAlive(a *Assembler, key ConnKey, n int) ([]*Message, error) {
	var out []*Message
	var first error
	for i := 0; i < n; i++ {
		for _, w := range []wire{
			req(postRequest(fmt.Sprintf(`{"n":%d}`, i))),
			respBytes(httpResponse("200 OK", nil, []byte(fmt.Sprintf(`{"r":%d}`, i)))),
		} {
			msgs, err := a.Feed(key, w.dir, Chunk{Data: w.data})
			out = append(out, msgs...)
			if err != nil && first == nil {
				first = err
			}
		}
	}
	return out, first
}

// checkPaired asserts that msgs are n whole exchanges in order, each response answering the request just
// before it.
func checkPaired(t *testing.T, msgs []*Message, n int) {
	t.Helper()
	if len(msgs) != 2*n {
		t.Fatalf("%d messages, want %d exchanges (%d messages)", len(msgs), n, 2*n)
	}
	for i := 0; i < len(msgs); i += 2 {
		q, r := msgs[i], msgs[i+1]
		if q.Dir != DirRequest || r.Dir != DirResponse {
			t.Fatalf("exchange %d is %s then %s", i/2, q.Dir, r.Dir)
		}
		if r.RequestIndex != q.Index {
			t.Fatalf("exchange %d: response paired with request %d, want %d", i/2, r.RequestIndex, q.Index)
		}
		if want := fmt.Sprintf(`{"r":%d}`, q.Index); string(r.Body) != want {
			t.Fatalf("exchange %d: response body %q answers another request, want %q", i/2, r.Body, want)
		}
	}
}

// TestResponseWithNoRequestIsPassedOver is kill test 2's uprobe failure, reduced to its bytes: the probes
// were placed after the process's first SSL_write and before its SSL_read (docs/p0/capture-derive.md R4,
// edge case 2), so the connection's first chunk is a whole response whose request capture never saw, and
// the 19 exchanges after it are complete. The response is passed over as one counted gap and the 19 pair.
// Before, that response abandoned the connection: 0 of 20 pairs and one gap that counted one.
// h2Preface is the connection preface of HTTP/2 (RFC 9113 section 3.4); checkPreface matches its
// "PRI * HTTP/2" prefix only (R17).
const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

func TestResponseWithNoRequestIsPassedOver(t *testing.T) {
	a := NewAssembler(Options{})
	msgs, err := a.Feed(testKey, DirResponse, Chunk{Data: httpResponse("200 OK", nil, []byte(`{"r":-1}`))})
	if err != nil {
		t.Fatalf("a response with no request abandoned the connection: %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("a response with no request was handed over (I3): %+v", msgs[0])
	}
	rest, err := keepAlive(a, testKey, 19)
	if err != nil {
		t.Fatalf("the exchanges after it: %v", err)
	}
	checkPaired(t, rest, 19)
	if got := gapCount(a.Gaps(), GapMalformed); got != 1 {
		t.Errorf("malformed = %d, want 1 for the one exchange whose request was not seen: %v", got, a.Gaps())
	}
	if len(a.Gaps()) != 1 {
		t.Errorf("gaps = %v, want the one malformed", a.Gaps())
	}
}

// TestResponseTailWithNoRequestIsPassedOver is the same race one read later: the probes were placed while the
// process was already inside the SSL_read that carried the response's head, so the uretprobe of that call
// never fires and the first chunks are the rest of a body. They are passed over, chunk by chunk, until a
// chunk starts a status line, as one counted gap; the exchanges after them pair.
func TestResponseTailWithNoRequestIsPassedOver(t *testing.T) {
	a := NewAssembler(Options{})
	for _, tail := range []string{`,"content":[{"type":"text","text":"he`, "llo\"}]}\r\n", `{"more":1}`} {
		msgs, err := a.Feed(testKey, DirResponse, Chunk{Data: []byte(tail)})
		if err != nil {
			t.Fatalf("the tail of a response with no request abandoned the connection: %v", err)
		}
		if len(msgs) != 0 {
			t.Fatalf("bytes of an unseen response became a message: %+v", msgs[0])
		}
	}
	rest, err := keepAlive(a, testKey, 19)
	if err != nil {
		t.Fatalf("the exchanges after it: %v", err)
	}
	checkPaired(t, rest, 19)
	if got := gapCount(a.Gaps(), GapMalformed); got != 1 {
		t.Errorf("malformed = %d, want 1 for the one response whose head was not seen: %v", got, a.Gaps())
	}
}

// TestTwoResponsesWithNoRequestAreTwoGaps: every exchange passed over is counted, so kill test 2's "every
// missing pair is explained" holds by count and not only by the presence of a gap line.
func TestTwoResponsesWithNoRequestAreTwoGaps(t *testing.T) {
	a := NewAssembler(Options{})
	for i := 0; i < 2; i++ {
		if _, err := a.Feed(testKey, DirResponse, Chunk{Data: httpResponse("200 OK", nil, []byte("x"))}); err != nil {
			t.Fatalf("response %d: %v", i, err)
		}
	}
	rest, err := keepAlive(a, testKey, 3)
	if err != nil {
		t.Fatal(err)
	}
	checkPaired(t, rest, 3)
	if got := gapCount(a.Gaps(), GapMalformed); got != 2 {
		t.Errorf("malformed = %d, want 2: %v", got, a.Gaps())
	}
}

// TestResponseWithNoRequestAtCloseIsOneGap: a response Close completes, whether its body ends at the close or
// is cut short by it, is passed over there as well when it answers no request, and counted once: not also as a
// body cut short, which would count its one exchange twice.
func TestResponseWithNoRequestAtCloseIsOneGap(t *testing.T) {
	for _, tc := range []struct{ name, wire string }{
		{"close-delimited", "HTTP/1.1 200 OK\r\n\r\n{\"r\":1}"},
		{"cut short", "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{\"r\":1}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAssembler(Options{})
			if _, err := a.Feed(testKey, DirResponse, Chunk{Data: []byte(tc.wire)}); err != nil {
				t.Fatal(err)
			}
			if msgs := a.Close(testKey); len(msgs) != 0 {
				t.Fatalf("Close handed over a response with no request: %+v", msgs[0])
			}
			if got := gapCount(a.Gaps(), GapMalformed); got != 1 {
				t.Errorf("malformed = %d, want 1: %v", got, a.Gaps())
			}
		})
	}
}

// TestResponseWhileItsRequestIsArrivingStillGaps is the fail-closed side of passing a response over: with a
// request still arriving on the request half, the response may be that request's early answer (a 413 sent
// before the body), and passing it over would leave the request queued for the next response's answer. The
// connection gaps as R18 says, rather than risk pairing a response with a request it did not answer.
func TestResponseWhileItsRequestIsArrivingStillGaps(t *testing.T) {
	a := NewAssembler(Options{})
	head := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: 100\r\n\r\n{\"model\":"
	if _, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte(head)}); err != nil {
		t.Fatal(err)
	}
	_, err := a.Feed(testKey, DirResponse, Chunk{Data: httpResponse("413 Content Too Large", nil, nil)})
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("error = %v, want ErrMalformed", err)
	}
	if got, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte(`"x"}`)}); err != nil || got != nil {
		t.Errorf("the connection went on after the gap: %v, %v", got, err)
	}
}

// TestResponseTailWhileARequestIsQueuedStillGaps: bytes that begin no status line while a request waits for
// its answer are that request's response with its head missing, and nothing says where it ends. Passing them
// over could hand the next response to this request, so the connection gaps as before.
func TestResponseTailWhileARequestIsQueuedStillGaps(t *testing.T) {
	a := NewAssembler(Options{})
	if _, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte(postRequest(reqBody))}); err != nil {
		t.Fatal(err)
	}
	_, err := a.Feed(testKey, DirResponse, Chunk{Data: []byte("{\"id\":\"msg_01\"}\r\n")})
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("error = %v, want ErrMalformed", err)
	}
}

// TestPipelineOverflowKeepsTheRefusedRequestsPlace is R11 once the FIFO has room again. The ninth request is
// refused; the client reads the first answer and sends a tenth, which the FIFO queues behind the eighth. The
// server answers in request order (RFC 9112 §9.3): 1..8, then the refused ninth, then the tenth. The ninth
// answer is passed over, its exchange already counted as R11's size-cap, and the tenth pairs with the tenth.
// Without the refused request's place, the ninth answer paired with the tenth request and the tenth answer
// had none.
func TestPipelineOverflowKeepsTheRefusedRequestsPlace(t *testing.T) {
	a := NewAssembler(Options{})
	feed := func(w wire) []*Message {
		t.Helper()
		msgs, err := a.Feed(testKey, w.dir, Chunk{Data: w.data})
		if err != nil {
			t.Fatalf("feed %s: %v", w.dir, err)
		}
		return msgs
	}
	answer := func(i int) wire {
		return respBytes(httpResponse("200 OK", nil, []byte(fmt.Sprintf(`{"r":%d}`, i))))
	}
	for i := 0; i < 9; i++ {
		feed(req(postRequest(fmt.Sprintf(`{"n":%d}`, i))))
	}
	if got := feed(answer(0)); len(got) != 1 || got[0].RequestIndex != 0 {
		t.Fatalf("first answer: %+v", got)
	}
	feed(req(postRequest(`{"n":9}`)))
	for i := 1; i <= 7; i++ {
		if got := feed(answer(i)); len(got) != 1 || got[0].RequestIndex != i {
			t.Fatalf("answer %d: %+v", i, got)
		}
	}
	if got := feed(answer(8)); len(got) != 0 {
		t.Fatalf("the refused request's answer was paired with request %d (R11, I3)", got[0].RequestIndex)
	}
	got := feed(answer(9))
	if len(got) != 1 || got[0].RequestIndex != 9 {
		t.Fatalf("the tenth answer: %+v, want it paired with request 9", got)
	}
	if n := gapCount(a.Gaps(), GapSizeCap); n != 1 {
		t.Errorf("size-cap = %d, want 1 for the refused request: %v", n, a.Gaps())
	}
	if n := gapCount(a.Gaps(), GapMalformed); n != 0 {
		t.Errorf("malformed = %d, want 0: the refused request's answer is its size-cap gap, not a second one", n)
	}
}

// feedAll feeds wires on one key and returns every message and the first error.
func feedAll(a *Assembler, key ConnKey, ws ...wire) ([]*Message, error) {
	var out []*Message
	var first error
	for _, w := range ws {
		msgs, err := a.Feed(key, w.dir, Chunk{Data: w.data})
		out = append(out, msgs...)
		if err != nil && first == nil {
			first = err
		}
	}
	return out, first
}

// TestRequestTailWithNoHeadIsPassedOver is the attach race on the request half: httpx writes a request's
// head and its body in separate SSL_writes, and the probes were placed between them (docs/p0/capture-derive.md
// R4, edge case 2), so the connection's first bytes are the body, in two writes, and then the response. The
// exchange is passed over as one counted gap, its response with it and not counted again, and the 19
// exchanges after it pair. Before, the body was a malformed request line and the connection was lost whole.
func TestRequestTailWithNoHeadIsPassedOver(t *testing.T) {
	a := NewAssembler(Options{})
	msgs, err := feedAll(a, testKey,
		req(`{"model":"claude-opus-4","messages":[{"role":"user",`),
		req(`"content":"hello"}]}`),
		respBytes(httpResponse("200 OK", nil, []byte(`{"r":-1}`))))
	if err != nil {
		t.Fatalf("a request with no head abandoned the connection: %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("an exchange whose request head was missed was handed over: %+v", msgs[0])
	}
	rest, err := keepAlive(a, testKey, 19)
	if err != nil {
		t.Fatalf("the exchanges after it: %v", err)
	}
	checkPaired(t, rest, 19)
	if got := gapCount(a.Gaps(), GapMalformed); got != 1 {
		t.Errorf("malformed = %d, want 1 for the one exchange whose request head was missed: %v", got, a.Gaps())
	}
	if len(a.Gaps()) != 1 {
		t.Errorf("gaps = %v, want the one malformed", a.Gaps())
	}
}

// TestRequestTailAtCloseIsOneGap: a request tail whose response never comes is still one exchange, counted
// when its tail was passed over, and not again as a request with no response at Close.
func TestRequestTailAtCloseIsOneGap(t *testing.T) {
	a := NewAssembler(Options{})
	if _, err := feedAll(a, testKey, req(`{"model":"claude-opus-4"}`)); err != nil {
		t.Fatal(err)
	}
	if msgs := a.Close(testKey); len(msgs) != 0 {
		t.Fatalf("Close handed over %+v", msgs[0])
	}
	if got := gapCount(a.Gaps(), GapMalformed); got != 1 {
		t.Errorf("malformed = %d, want 1: %v", got, a.Gaps())
	}
}

// TestARequestBeforeAHeadlessOnesResponseGaps is the fail-closed side of passing a request tail over. A
// request that completes before the tail's response is either pipelined behind it or follows a response
// the tail's server sent early, which was then passed over as answering nothing; the next response answers
// one of the two and nothing says which, so the connection gaps rather than pair it (I3).
func TestARequestBeforeAHeadlessOnesResponseGaps(t *testing.T) {
	for _, tc := range []struct {
		name string
		ws   []wire
	}{
		{"pipelined", []wire{req(`{"model":"opus"}`), req(postRequest(`{"n":0}`))}},
		{"after an early answer", []wire{respBytes(httpResponse("413 Content Too Large", nil, nil)),
			req(`{"model":"opus"}`), req(postRequest(`{"n":0}`))}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAssembler(Options{})
			msgs, err := feedAll(a, testKey, append(tc.ws, respBytes(httpResponse("200 OK", nil, []byte(`{"r":0}`))))...)
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("error = %v, want ErrMalformed", err)
			}
			for _, m := range msgs {
				if m.Dir == DirResponse {
					t.Fatalf("a response was paired with request %d when it may answer the headless one", m.RequestIndex)
				}
			}
		})
	}
}

// TestRequestTailIsNeverJoinedToTheNextRequest: a tail that begins like a request line, and only ends at
// the next request's start, is not taken for a request with the next request's line glued to it. The next
// request comes before the tail's response here, the order a client that writes before it reads produces:
// both exchanges are passed over and counted, and the one after them pairs. In the order a blocking client
// produces, the tail's response comes first, and TestRequestTailShapedLikeARequestLineFailsClosed pins what
// happens then.
func TestRequestTailIsNeverJoinedToTheNextRequest(t *testing.T) {
	for _, tail := range []string{"P", "GE", "POST", `GET the weather","n":1}`, "POST /x"} {
		t.Run(tail, func(t *testing.T) {
			a := NewAssembler(Options{})
			msgs, err := feedAll(a, testKey,
				req(tail),
				req(postRequest(`{"n":-2}`)),
				respBytes(httpResponse("200 OK", nil, []byte(`{"r":-3}`))),
				respBytes(httpResponse("200 OK", nil, []byte(`{"r":-2}`))))
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			for _, m := range msgs {
				t.Errorf("handed over %s %s %q, joined from a tail and the next request", m.Dir, m.Method, m.Body)
			}
			rest, err := keepAlive(a, testKey, 3)
			if err != nil {
				t.Fatal(err)
			}
			checkPaired(t, rest, 3)
			if got := gapCount(a.Gaps(), GapMalformed); got != 2 {
				t.Errorf("malformed = %d, want 2, the tail's exchange and the one it swallowed: %v", got, a.Gaps())
			}
		})
	}
}

// TestFirstRequestLineInPiecesStillParses: the wait that guards against a joined tail still lets a real
// first request whose line arrives in pieces through, whatever the split.
func TestFirstRequestLineInPiecesStillParses(t *testing.T) {
	full := postRequest(`{"n":0}`)
	for _, cut := range []int{1, 2, 4, 5, 9, 20} {
		a := NewAssembler(Options{})
		msgs, err := feedAll(a, testKey, req(full[:cut]), req(full[cut:]),
			respBytes(httpResponse("200 OK", nil, []byte(`{"r":0}`))))
		if err != nil {
			t.Fatalf("cut %d: %v", cut, err)
		}
		checkPaired(t, msgs, 1)
	}
}

// TestExpectContinueWithAMissedHeadIsOneGap: a request whose head asked for 100-continue and was written
// before the probes. The interim 100 comes with nothing queued, the body is a tail, and the final response
// pops the tail's place: one count in all, and the connection pairs after it.
func TestExpectContinueWithAMissedHeadIsOneGap(t *testing.T) {
	a := NewAssembler(Options{})
	msgs, err := feedAll(a, testKey,
		resp("HTTP/1.1 100 Continue\r\n\r\n"),
		req(`{"model":"opus"}`),
		respBytes(httpResponse("200 OK", nil, []byte(`{"r":-1}`))))
	if err != nil || len(msgs) != 0 {
		t.Fatalf("msgs %v, err %v", msgs, err)
	}
	rest, err := keepAlive(a, testKey, 2)
	if err != nil {
		t.Fatal(err)
	}
	checkPaired(t, rest, 2)
	if got := gapCount(a.Gaps(), GapMalformed); got != 1 {
		t.Errorf("malformed = %d, want 1: %v", got, a.Gaps())
	}
}

// TestResponseToAnUnseenHeadIsNotPairedWithTheNextRequest: whether a response answers a request is decided
// at its first byte. A response to a HEAD capture never saw declares a body it will not send, so it is
// framed as carrying 20 bytes and takes the first 20 of the next response. Decided when it completed, it
// was paired with the request queued meanwhile and handed over as that request's answer; decided at its
// first byte it is passed over, and the next response, its start eaten, gaps the connection (R18).
func TestResponseToAnUnseenHeadIsNotPairedWithTheNextRequest(t *testing.T) {
	a := NewAssembler(Options{})
	msgs, err := feedAll(a, testKey,
		resp("HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n"),
		req("GET /v1/models HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n"),
		resp("HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok"))
	for _, m := range msgs {
		if m.Dir == DirResponse {
			t.Fatalf("response (status %d, body %q) paired with request %d, which it does not answer",
				m.Status, m.Body, m.RequestIndex)
		}
	}
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("error = %v, want ErrMalformed for the response whose start was eaten", err)
	}
}

// TestEvictionKeepsAConnectionOwedAResponse: a connection whose queue is empty but that is still owed the
// response of a request R11 refused is not finished. Retired, the owed response would arrive on a fresh
// connection as one with no request and be counted a second time.
func TestEvictionKeepsAConnectionOwedAResponse(t *testing.T) {
	a := NewAssembler(Options{MaxConns: 2})
	owed := ConnKey{Src: record.SourceSSL, SSLPtr: 1}
	for i := 0; i < 9; i++ { // the ninth is refused at R11's depth of 8
		if _, err := a.Feed(owed, DirRequest, Chunk{Data: []byte(postRequest(fmt.Sprintf(`{"n":%d}`, i)))}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 8; i++ {
		if _, err := a.Feed(owed, DirResponse, Chunk{Data: httpResponse("200 OK", nil, []byte(fmt.Sprintf(`{"r":%d}`, i)))}); err != nil {
			t.Fatal(err)
		}
	}
	idle := ConnKey{Src: record.SourceSSL, SSLPtr: 2}
	exchange(t, a, idle) // retirable, and used more recently than the owed connection
	fresh := ConnKey{Src: record.SourceSSL, SSLPtr: 3}
	if _, err := a.Feed(fresh, DirRequest, Chunk{Data: []byte(postRequest(reqBody))}); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.conns[owed]; !ok {
		t.Fatal("retired a connection still owed a response")
	}
	if _, err := a.Feed(owed, DirResponse, Chunk{Data: httpResponse("200 OK", nil, []byte(`{"r":8}`))}); err != nil {
		t.Fatal(err)
	}
	if got := gapCount(a.Gaps(), GapMalformed); got != 0 {
		t.Errorf("malformed = %d: the refused request's response was counted again: %v", got, a.Gaps())
	}
	if got := gapCount(a.Gaps(), GapSizeCap); got != 1 {
		t.Errorf("size-cap = %d, want 1: %v", got, a.Gaps())
	}
}

// TestOwedResponseIsFramedByItsOwnRequest: the response R11's refused request is owed is framed as one that
// may carry a body, not by the HEAD queued behind it. Framed as HEAD's it would stop at its headers, its body
// would be read as the next status line, and the connection would gap.
func TestOwedResponseIsFramedByItsOwnRequest(t *testing.T) {
	a := NewAssembler(Options{})
	feed := func(w wire) []*Message {
		t.Helper()
		msgs, err := a.Feed(testKey, w.dir, Chunk{Data: w.data})
		if err != nil {
			t.Fatalf("feed %s: %v", w.dir, err)
		}
		return msgs
	}
	for i := 0; i < 9; i++ { // the ninth is refused, its place owed after the eighth
		feed(req(postRequest(fmt.Sprintf(`{"n":%d}`, i))))
	}
	feed(respBytes(httpResponse("200 OK", nil, []byte(`{"r":0}`))))
	feed(req("HEAD /v1/models HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")) // request 9, queued behind the eighth
	for i := 1; i < 8; i++ {
		feed(respBytes(httpResponse("200 OK", nil, []byte(fmt.Sprintf(`{"r":%d}`, i)))))
	}
	if got := feed(resp("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")); len(got) != 0 {
		t.Fatalf("the owed response was paired with request %d", got[0].RequestIndex)
	}
	got := feed(resp("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"))
	if len(got) != 1 || got[0].RequestIndex != 9 || len(got[0].Body) != 0 {
		t.Fatalf("HEAD's response = %+v, want it paired with request 9 and bodiless", got)
	}
}

// TestTwoSeparateHeadlessRunsAreEachCounted: a run of passed-over response bytes ends at a status line, so a
// later run on the same connection is a second lost exchange and counted as one; left running, it would be
// passed over with no count, a silent loss (I4).
func TestTwoSeparateHeadlessRunsAreEachCounted(t *testing.T) {
	a := NewAssembler(Options{})
	tail := resp(`,"content":[{"type":"text","text":"hi"}]}`)
	if _, err := feedAll(a, testKey, tail); err != nil {
		t.Fatal(err)
	}
	if _, err := keepAlive(a, testKey, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := feedAll(a, testKey, tail); err != nil {
		t.Fatal(err)
	}
	if got := gapCount(a.Gaps(), GapMalformed); got != 2 {
		t.Errorf("malformed = %d, want 2 for two separate runs: %v", got, a.Gaps())
	}
}

// TestARequestTailOnlyAtCapturesStart: passing request bytes over as a tail is for the first request capture
// sees on a connection. Once a request line has ended the run, bytes that begin no request line are
// malformed and gap the connection as R18 says; still passed over, they would be lost with no count.
func TestARequestTailOnlyAtCapturesStart(t *testing.T) {
	a := NewAssembler(Options{})
	if _, err := feedAll(a, testKey, req(`{"model":"opus"}`), respBytes(httpResponse("200 OK", nil, []byte(`{"r":-1}`)))); err != nil {
		t.Fatal(err)
	}
	if _, err := keepAlive(a, testKey, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := feedAll(a, testKey, req("{\"model\":\"opus\"}\r\n")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("error = %v, want ErrMalformed for bytes that begin no request line mid-connection", err)
	}
}

// TestUnseenResponseIsNotFramedByARequestQueuedAfterIt: a response decided at its first byte to answer no
// request is framed as one that may carry a body, even when a HEAD is queued before its headers end. Framed
// by that HEAD it would stop at its headers, its body would be read as the next status line, and the
// connection would gap; the HEAD's own response would never pair.
func TestUnseenResponseIsNotFramedByARequestQueuedAfterIt(t *testing.T) {
	a := NewAssembler(Options{})
	msgs, err := feedAll(a, testKey,
		resp("HTTP/1.1 200 OK\r\n"),
		req("HEAD /v1/models HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n"),
		resp("Content-Length: 5\r\n\r\nhello"),
		resp("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	var resps []*Message
	for _, m := range msgs {
		if m.Dir == DirResponse {
			resps = append(resps, m)
		}
	}
	if len(resps) != 1 || resps[0].RequestIndex != 0 || len(resps[0].Body) != 0 {
		t.Fatalf("responses %+v, want the HEAD's alone, bodiless and paired with request 0", resps)
	}
	if got := gapCount(a.Gaps(), GapMalformed); got != 1 {
		t.Errorf("malformed = %d, want 1 for the unseen request's response: %v", got, a.Gaps())
	}
}

// TestARequestTailWhileAResponseIsArrivingGaps: request bytes that begin no request line while a response
// is still arriving are not passed over as a tail. That response may be the tail's early answer (a 413),
// and which request it answers cannot be told, so the connection gaps as R18 says.
func TestARequestTailWhileAResponseIsArrivingGaps(t *testing.T) {
	for _, tc := range []struct{ name, head string }{
		{"mid-body", "HTTP/1.1 413 Content Too Large\r\nContent-Length: 10\r\n\r\nabc"},
		{"mid-status-line", "HTTP/1.1 41"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAssembler(Options{})
			_, err := feedAll(a, testKey, resp(tc.head), req("{\"model\":\"opus\"}\r\n"))
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("error = %v, want ErrMalformed", err)
			}
		})
	}
}

// TestOwedResponseTailIsTheOwedOne: with nothing queued and R11 owed a response, response bytes that begin
// no status line are that response with its head lost, and pay its debt. Counted as a response with no
// request instead, the debt would stand, and the next request's own response would be passed over in its
// place, leaving that request to take the answer after it.
func TestOwedResponseTailIsTheOwedOne(t *testing.T) {
	a := NewAssembler(Options{})
	for i := 0; i < 9; i++ {
		if _, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte(postRequest(fmt.Sprintf(`{"n":%d}`, i)))}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 8; i++ {
		if _, err := a.Feed(testKey, DirResponse, Chunk{Data: httpResponse("200 OK", nil, []byte(fmt.Sprintf(`{"r":%d}`, i)))}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := feedAll(a, testKey, resp(`{"r":8}`)); err != nil {
		t.Fatal(err)
	}
	msgs, err := feedAll(a, testKey, req(postRequest(`{"n":9}`)), respBytes(httpResponse("200 OK", nil, []byte(`{"r":9}`))))
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 || msgs[1].RequestIndex != 9 || string(msgs[1].Body) != `{"r":9}` {
		t.Fatalf("messages %+v, want request 9 and its own response", msgs)
	}
	if got := gapCount(a.Gaps(), GapMalformed); got != 0 {
		t.Errorf("malformed = %d, want 0: the owed response was counted with its request (R11)", got)
	}
}

// TestH2PrefaceInPiecesIsStillH2: the wait at a connection's first bytes covers the h2 preface arriving in
// pieces, which is R17's gap and nothing else, never a tail passed over.
func TestH2PrefaceInPiecesIsStillH2(t *testing.T) {
	for _, cut := range []int{1, 2, 3, 4, 8} {
		a := NewAssembler(Options{})
		_, err := feedAll(a, testKey, req(h2Preface[:cut]), req(h2Preface[cut:]))
		if !errors.Is(err, ErrHTTP2) {
			t.Fatalf("cut %d: error = %v, want ErrHTTP2", cut, err)
		}
		if got := gapCount(a.Gaps(), GapMalformed); got != 0 {
			t.Errorf("cut %d: malformed = %d, want only the h2 gap: %v", cut, got, a.Gaps())
		}
	}
}

// TestRequestTailThatNeverEndsItsLineIsPassedOver: a tail that begins like a known method and a space and
// then runs past the longest start line with no line end is a tail, not a start line over the cap.
func TestRequestTailThatNeverEndsItsLineIsPassedOver(t *testing.T) {
	a := NewAssembler(Options{})
	msgs, err := feedAll(a, testKey,
		req("GET the weather "),
		req(strings.Repeat("a", maxStartLine+1)),
		respBytes(httpResponse("200 OK", nil, []byte(`{"r":-1}`))))
	if err != nil || len(msgs) != 0 {
		t.Fatalf("msgs %v, err %v", msgs, err)
	}
	rest, err := keepAlive(a, testKey, 2)
	if err != nil {
		t.Fatal(err)
	}
	checkPaired(t, rest, 2)
	if got := gapCount(a.Gaps(), GapMalformed); got != 1 {
		t.Errorf("malformed = %d, want 1: %v", got, a.Gaps())
	}
}

// TestResponseInPiecesIsDecidedAtItsFirstByte: whether a response answers a request is settled at the first
// byte of it the response half holds, not once its status line is whole. Here that line arrives in pieces,
// cut inside "HTTP/" and after it, and a request is queued between the pieces: capture saw the request after
// the response's first byte, so the response is not its answer (half.noRequest). It is passed over and
// counted once, and the request pairs with its own response. Decided at the parsed status line, the unseen
// response was paired with the queued request: framed by a HEAD, its body was then passed over as a response
// with no request and the HEAD's own answer framed as a body; paired with a POST, the POST's own answer was
// passed over in its place. Neither raised an error, so the ledger got a silent mispair (I3).
func TestResponseInPiecesIsDecidedAtItsFirstByte(t *testing.T) {
	const unseen = "HTTP/1.1 202 Accepted\r\nContent-Length: 5\r\n\r\nhello"
	for _, tc := range []struct {
		name   string
		query  string // the request queued between the pieces
		answer []byte // that request's own response
		body   string // the body its response is handed over with
	}{
		{"HEAD", "HEAD /v1/models HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n",
			[]byte("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"), ""},
		{"POST", postRequest(`{"n":0}`), httpResponse("200 OK", nil, []byte(`{"r":0}`)), `{"r":0}`},
	} {
		// "H", "HT", "HTTP/", "HTTP/1.1 ", "HTTP/1.1 202 A", the whole line without its end, with its CR,
		// and with its CRLF.
		for _, cut := range []int{1, 2, 5, 9, 14, 21, 22, 23} {
			t.Run(fmt.Sprintf("%s/%q", tc.name, unseen[:cut]), func(t *testing.T) {
				a := NewAssembler(Options{})
				msgs, err := feedAll(a, testKey,
					resp(unseen[:cut]), req(tc.query), resp(unseen[cut:]), respBytes(tc.answer))
				if err != nil {
					t.Fatalf("error = %v", err)
				}
				if len(msgs) != 2 || msgs[0].Dir != DirRequest || msgs[1].Dir != DirResponse {
					t.Fatalf("messages %+v, want the queued request and its own response", msgs)
				}
				if r := msgs[1]; r.RequestIndex != msgs[0].Index || r.Status != 200 || string(r.Body) != tc.body {
					t.Fatalf("response (status %d, body %q) paired with request %d, want the queued request's own "+
						"(status 200, body %q)", r.Status, r.Body, r.RequestIndex, tc.body)
				}
				if got := gapCount(a.Gaps(), GapMalformed); got != 1 || len(a.Gaps()) != 1 {
					t.Fatalf("gaps = %v, want one malformed counting 1 for the unseen request's response", a.Gaps())
				}
				rest, err := keepAlive(a, testKey, 2)
				if err != nil {
					t.Fatal(err)
				}
				// keepAlive's requests come after the queued one, so they are requests 1 and 2 answered by
				// bodies 0 and 1.
				if len(rest) != 4 {
					t.Fatalf("%d messages after it, want 2 exchanges", len(rest))
				}
				for i := 0; i < 2; i++ {
					q, r := rest[2*i], rest[2*i+1]
					if q.Index != i+1 || r.RequestIndex != q.Index || string(r.Body) != fmt.Sprintf(`{"r":%d}`, i) {
						t.Fatalf("exchange %d after it: request %d, response (body %q) paired with %d",
							i, q.Index, r.Body, r.RequestIndex)
					}
				}
			})
		}
	}
}

// TestRequestTailShapedLikeARequestLineFailsClosed pins what a request tail that looks like the start of a
// request costs in the order a client that reads each response before its next request produces: the tail,
// then its response, then the later exchanges. A tail that is a whole line of a token and a space (a
// text/plain body, "hello world") is parsed as a request line and is malformed. A tail that is a known
// method still arriving ("P", "GET me a coffee", "POST /x") leaves the request half waiting for the rest of
// its line, so its response begins while a request may still be arriving: it may be that request's early
// answer, and with nothing queued it is a response with no request in flight. Either way the connection
// gaps (R18) with one count, and none of the later exchanges pair: a loss the count understates, which R4
// and edge case 2 name. The waited bytes are not passed over when the response starts, because they can be
// the first piece of a real request line, whose rest would then be parsed as a request of another method.
func TestRequestTailShapedLikeARequestLineFailsClosed(t *testing.T) {
	for _, tail := range []string{"hello world\n", "P", "GET me a coffee", "POST /x"} {
		t.Run(tail, func(t *testing.T) {
			a := NewAssembler(Options{})
			msgs, err := feedAll(a, testKey, req(tail), respBytes(httpResponse("200 OK", nil, []byte(`{"r":-1}`))))
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("error = %v, want ErrMalformed", err)
			}
			if len(msgs) != 0 {
				t.Fatalf("handed over %+v", msgs[0])
			}
			rest, err := keepAlive(a, testKey, 3)
			if err != nil || len(rest) != 0 {
				t.Fatalf("the connection went on after the gap: %d messages, %v", len(rest), err)
			}
			if got := gapCount(a.Gaps(), GapMalformed); got != 1 {
				t.Errorf("malformed = %d, want 1 for the connection: %v", got, a.Gaps())
			}
		})
	}
}

// TestResponseTailThatBeganLikeAStatusLineIsDecidedAgain: a response tail whose first chunk could still have
// been a status line ("H" of a body's "Hello") settles noRequest at that chunk, and the next chunk shows the
// bytes to be no status line, so they are passed over (skip). The decision was about bytes that began no
// message and goes with them: kept, it would pass over the next request's own response as one with no request
// and pair every later response with the request before its own (I3).
func TestResponseTailThatBeganLikeAStatusLineIsDecidedAgain(t *testing.T) {
	a := NewAssembler(Options{})
	msgs, err := feedAll(a, testKey, resp("H"), resp("ello, world\r\n"))
	if err != nil || len(msgs) != 0 {
		t.Fatalf("msgs %v, err %v", msgs, err)
	}
	rest, err := keepAlive(a, testKey, 3)
	if err != nil {
		t.Fatal(err)
	}
	checkPaired(t, rest, 3)
	if got := gapCount(a.Gaps(), GapMalformed); got != 1 {
		t.Errorf("malformed = %d, want 1 for the tail: %v", got, a.Gaps())
	}
}

// TestResponseAfterAPassedOverTailIsDecidedAtItsOwnFirstByte pins the half of skip() the test above does not:
// the decision is cleared, not only noRequest. A tail that began like a status line ("H", then "ello, world")
// is passed over; the next response, a 202 whose request capture never saw, arrives with nothing queued and is
// passed over too; then the client's POST and, before the POST's own 200, the rest of the 202 ("Content-Length:
// 5", "hello"). With the decision left set by the first skip, the 202's head was never decided at its own first
// byte, nothing passed it over, and its "hello" was handed out as the POST's answer with no error: the I3
// mispairing the test above guards against, reached one response later. The tail and the 202 are one malformed
// count each; the POST and its own 200 must be the only messages, paired.
func TestResponseAfterAPassedOverTailIsDecidedAtItsOwnFirstByte(t *testing.T) {
	a := NewAssembler(Options{})
	const question, answer = `{"n":0}`, `{"r":0}`
	msgs, err := feedAll(a, testKey,
		resp("H"), resp("ello, world\r\n"),
		resp("HTTP/1.1 202 Accepted\r\n"),
		req(postRequest(question)),
		resp("Content-Length: 5\r\n\r\nhello"),
		respBytes(httpResponse("200 OK", nil, []byte(answer))),
	)
	if err != nil {
		t.Fatalf("err %v: the connection failed where the 202 should have been passed over", err)
	}
	for _, m := range msgs {
		if m.Dir == DirResponse && (m.Status != 200 || string(m.Body) != answer) {
			t.Fatalf("response (status %d, body %q) paired with request %d: a response the POST did not get "+
				"was handed out as its answer (I3)", m.Status, m.Body, m.RequestIndex)
		}
	}
	checkPaired(t, msgs, 1)
	if string(msgs[0].Body) != question {
		t.Fatalf("request body %q, want %q", msgs[0].Body, question)
	}
	if got := gapCount(a.Gaps(), GapMalformed); got != 2 {
		t.Errorf("malformed = %d, want 2: the tail and the 202 with no request: %v", got, a.Gaps())
	}
}

// TestRequestTailThatFailsAsItIsParsed pins the two tail shapes R4 says fail the connection closed as soon as
// they are parsed, whatever comes after them: a whole first line of a token and a space, and a first chunk of a
// token and a space whose line runs past the 8 KiB start-line cap (a text/plain body over 8 KiB in one
// SSL_write; a capture chunk holds up to 32 KiB), a known method's included. Neither waits for a response to
// decide: the tail's own feed is the error, and the next request and its response are lost with the connection.
func TestRequestTailThatFailsAsItIsParsed(t *testing.T) {
	long := strings.Repeat("a", maxStartLine+1)
	for name, tail := range map[string]string{
		"whole line":            "hello world\n",
		"token past the cap":    "hello " + long,
		"known method past cap": "GET me " + long,
	} {
		t.Run(name, func(t *testing.T) {
			a := NewAssembler(Options{})
			msgs, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte(tail)})
			if !errors.Is(err, ErrMalformed) || len(msgs) != 0 {
				t.Fatalf("the tail's own feed = %d messages, %v; want ErrMalformed before any response", len(msgs), err)
			}
			rest, err := keepAlive(a, testKey, 1)
			if err != nil || len(rest) != 0 {
				t.Fatalf("the connection went on after the tail: %d messages, %v", len(rest), err)
			}
			if got := gapCount(a.Gaps(), GapMalformed); got != 1 {
				t.Errorf("malformed = %d, want 1: %v", got, a.Gaps())
			}
		})
	}
}
