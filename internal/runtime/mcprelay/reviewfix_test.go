// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/mcptool"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The review (findings F1 to F8): a tools/list answer is filtered whatever the client accepted, however its id is
// spelt, whichever request it collides with, however the stream splits it, and whichever method opened the stream.

// httpRelayWith is httpRelayFor over an upstream handler of the test's own.
func httpRelayWith(t *testing.T, h http.HandlerFunc, rules mcptool.Rules) (*Service, *sink, string) {
	t.Helper()
	up := httptest.NewServer(h)
	t.Cleanup(up.Close)
	s, sk, _ := start(t, nil, Server{Name: "web", URL: up.URL + "/mcp", Rules: rules})
	s.https[0].admitConn = func(netip.AddrPort, netip.AddrPort, uint64) error { return nil }
	s.https[0].holderPID = os.Getpid
	return s, sk, s.httpURLs()["web"]
}

// rawClient is a client that does its own content decoding: it says what it accepts and reads the bytes it gets.
func rawClient(method, url, body string, header map[string]string) (int, []byte, http.Header, error) {
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Transport: &http.Transport{DisableCompression: true}}).Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header, nil
}

func gz(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return b.Bytes()
}

// F1: a client that accepts gzip must not get the list in a form the relay could not read.
func TestHTTPClientAcceptingGzipGetsAFilteredList(t *testing.T) {
	// A server that compresses for whoever accepts it.
	_, _, relay := httpRelayWith(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(gz(listResult("1")))
			return
		}
		_, _ = io.WriteString(w, listResult("1"))
	}, webRules())
	code, body, _, err := rawClient(http.MethodPost, relay, listReq("1"), map[string]string{"Accept-Encoding": "gzip", "Content-Type": "application/json"})
	if err != nil || code != 200 {
		t.Fatalf("status %d: %v", code, err)
	}
	hidesDenied(t, body)
}

// A server that compresses whatever it was asked: an answer the relay cannot read is never passed on.
func TestHTTPCompressedAnswerThatCannotBeReadIsRefused(t *testing.T) {
	for _, ct := range []string{"application/json", "text/event-stream"} {
		t.Run(ct, func(t *testing.T) {
			_, sk, relay := httpRelayWith(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", ct)
				w.Header().Set("Content-Encoding", "gzip")
				_, _ = w.Write(gz("data: " + listResult("1") + "\n\n"))
			}, webRules())
			code, body, _, err := rawClient(http.MethodPost, relay, listReq("1"), map[string]string{"Accept-Encoding": "gzip"})
			if err != nil || code != http.StatusBadGateway || bytes.Contains(body, []byte("delete_file")) {
				t.Fatalf("status %d: %v: %q", code, err, body)
			}
			if n := len(sk.of(record.KindMCP)); n != 1 {
				t.Fatalf("record lines %d: the answer that was not passed on is a line", n)
			}
		})
	}
}

// An answer to a list that is not JSON at all is not passed on either, whatever its type says.
func TestHTTPListAnswerThatIsNotJSONIsRefused(t *testing.T) {
	_, _, relay := httpRelayWith(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "\x1f\x8bnot json delete_file")
	}, webRules())
	code, body, _ := postJSON(t, relay, listReq("1"))
	if code != http.StatusBadGateway || strings.Contains(body, "delete_file") {
		t.Fatalf("status %d: %q", code, body)
	}
}

// F2 / F9: one number is one id, whatever it is spelt; a string is another.
func TestStdioListIDSpelledAsAnotherNumberIsStillFiltered(t *testing.T) {
	for _, spelt := range []string{"1.0", "1e0", "1.00", "10e-1"} {
		t.Run(spelt, func(t *testing.T) {
			s, _, _ := start(t, nil, filesServer())
			sh, _ := dial(t, s, "files", filesCmd)
			sh.client(listReq(spelt))
			sh.read()
			sh.server(listResult("1")) // a server answers with its own spelling
			hidesDenied(t, sh.read().ToClient)
		})
	}
}

func TestHTTPListIDSpelledAsAnotherNumberIsStillFiltered(t *testing.T) {
	_, _, relay := httpRelayWith(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, listResult("1"))
	}, webRules())
	for _, spelt := range []string{"1.0", "1e0"} {
		_, body, _ := postJSON(t, relay, listReq(spelt))
		hidesDenied(t, []byte(body))
	}
}

func TestBatchIDsThatAreOneNumberAreRepeated(t *testing.T) {
	s, _, _ := start(t, nil, filesServer())
	sh, _ := dial(t, s, "files", filesCmd)
	sh.client(batchOf(toolCall(1, "read_file"), `{"jsonrpc":"2.0","id":1.0,"method":"ping"}`, `{"jsonrpc":"2.0","id":"1","method":"ping"}`))
	toClient, toServer := sh.frames(2)
	if len(members(t, toClient[0])) != 2 || strings.Join(idsOf(t, toServer[0]), ",") != `"1"` {
		t.Fatalf("to the client %s, to the server %s: 1 and 1.0 are one id and \"1\" another", toClient[0], toServer[0])
	}
}

// Any answer that carries a tools array is filtered, whatever its id.
func TestStdioListAnswerWithAnotherIDIsStillFiltered(t *testing.T) {
	s, _, _ := start(t, nil, filesServer())
	sh, _ := dial(t, s, "files", filesCmd)
	sh.client(listReq(`"a"`))
	sh.read()
	sh.server(listResult(`"unrelated"`))
	hidesDenied(t, sh.read().ToClient)
	sh.server(`{"jsonrpc":"2.0","result":{"tools":[{"name":"delete_file"},{"name":"read_file"}]}}`) // no id at all
	hidesDenied(t, sh.read().ToClient)
}

// F3: a call and a list that share an id in flight.
func TestStdioRequestWithAnIDStillInFlightIsRefused(t *testing.T) {
	s, sk, _ := start(t, nil, filesServer())
	sh, _ := dial(t, s, "files", filesCmd)
	sh.client(toolCall(1, "read_file"))
	sh.read()
	sh.client(listReq("1"))
	f := sh.read()
	if f.ToServer != nil || !strings.Contains(string(f.ToClient), "-32001") || !strings.Contains(string(f.ToClient), `"id":1`) {
		t.Fatalf("a second request under an id still waiting was passed: %+v", f)
	}
	if n := len(sk.of(record.KindMCP)); n != 2 {
		t.Fatalf("record lines %d", n)
	}
	// Once the first is answered the id is free again.
	sh.server(`{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`)
	sh.read()
	sh.client(listReq("1"))
	if f := sh.read(); f.ToServer == nil {
		t.Fatalf("the id was not freed by its answer: %+v", f)
	}
}

// The shape filter is the backstop: even if the call's answer takes the id, the list's is still filtered.
func TestStdioListAnswerAfterACollidingCallAnswerIsFiltered(t *testing.T) {
	s, _, _ := start(t, nil, filesServer())
	sh, _ := dial(t, s, "files", filesCmd)
	sh.client(toolCall(1, "read_file"))
	sh.read()
	sh.server(`{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`)
	sh.read()
	sh.client(listReq("1"))
	sh.read()
	sh.server(listResult("1"))
	hidesDenied(t, sh.read().ToClient)
}

// F4: an event whose JSON is spread over several data lines is assembled before it is filtered.
func TestHTTPEventWithItsJSONOverSeveralDataLinesIsFiltered(t *testing.T) {
	for name, stream := range map[string]string{
		"two data lines": "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\ndata: \"result\":{\"tools\":[{\"name\":\"delete_file\"},{\"name\":\"read_file\"}]}}\n\n",
		"bare CR ends":   "event: message\rdata: {\"jsonrpc\":\"2.0\",\"id\":1,\rdata: \"result\":{\"tools\":[{\"name\":\"delete_file\"},{\"name\":\"read_file\"}]}}\r\r",
		"CRLF":           "data: {\"jsonrpc\":\"2.0\",\"id\":1,\r\ndata: \"result\":{\"tools\":[{\"name\":\"delete_file\"},{\"name\":\"read_file\"}]}}\r\n\r\n",
		"no final blank": "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"delete_file\"},{\"name\":\"read_file\"}]}}\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, _, relay := httpRelayWith(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, stream)
			}, webRules())
			_, body, _ := postJSON(t, relay, listReq("1"))
			hidesDenied(t, []byte(body))
		})
	}
}

// A list's event that is not complete JSON is dropped and recorded, never passed.
func TestHTTPEventWithDataThatIsNotJSONIsDroppedWhenAListWasAsked(t *testing.T) {
	_, sk, relay := httpRelayWith(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"delete_file\"\n\ndata: "+listResult("1")+"\n\n")
	}, webRules())
	_, body, _ := postJSON(t, relay, listReq("1"))
	hidesDenied(t, []byte(body))
	if n := len(sk.of(record.KindMCP)); n != 1 {
		t.Fatalf("record lines %d: the dropped event is a line", n)
	}
}

// F5: a GET that resumes a stream, and replays an answer, is filtered by its shape.
func TestHTTPResumedStreamReplayIsFiltered(t *testing.T) {
	_, _, relay := httpRelayWith(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Last-Event-ID") == "" {
			t.Errorf("request %s, Last-Event-ID %q", r.Method, r.Header.Get("Last-Event-ID"))
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "id: 7\ndata: "+listResult("1")+"\n\n: keep-alive\n\nevent: endpoint\ndata: /messages?s=1\n\n")
	}, webRules())
	code, body, _, err := rawClient(http.MethodGet, relay, "", map[string]string{"Last-Event-ID": "6", "Accept": "text/event-stream"})
	if err != nil || code != 200 {
		t.Fatalf("status %d: %v", code, err)
	}
	hidesDenied(t, body)
	if !bytes.Contains(body, []byte("id: 7")) || !bytes.Contains(body, []byte("/messages?s=1")) || !bytes.Contains(body, []byte(": keep-alive")) {
		t.Fatalf("the stream lost its other fields: %q", body)
	}
}

// F6: asks outstanding across the whole relay are bounded at the bound of one batch.
func TestAsksOutstandingAreBoundedAcrossBatches(t *testing.T) {
	s, _, _ := start(t, nil, filesServer())
	release := make(chan struct{})
	var mu sync.Mutex
	asked := 0
	s.ConfigureMCPAsk(func(ctx context.Context, _ ask.Request) (ask.Decision, error) {
		mu.Lock()
		asked++
		mu.Unlock()
		select {
		case <-release:
		case <-ctx.Done():
		}
		return ask.Decision{Approved: true}, nil
	})
	sh, _ := dial(t, s, "files", filesCmd)
	const bound = 128
	for b := range 2 {
		var ms []string
		for i := range bound {
			ms = append(ms, toolCall(1000*(b+1)+i, "write_file"))
		}
		sh.client(batchOf(ms...))
	}
	// 256 asks were made; the bound lets 128 through to a person and refuses the rest at once, ask-unavailable.
	refused := 0
	for refused < bound {
		f := sh.read()
		if f.ToClient == nil {
			t.Fatalf("a frame to the server while every ask waits: %+v", f)
		}
		refused += len(members(t, f.ToClient))
	}
	mu.Lock()
	n := asked
	mu.Unlock()
	if n != bound {
		t.Fatalf("%d cards were raised, want %d", n, bound)
	}
	close(release)
}

// F6: a call that has no id has no one to be answered; a person's denial of it is recorded and sends no frame.
func TestHeldCallWithNoIDIsRecordedAndNotAnswered(t *testing.T) {
	s, sk, _ := start(t, nil, filesServer())
	s.ConfigureMCPAsk(func(context.Context, ask.Request) (ask.Decision, error) {
		return ask.Decision{Reason: ask.ReasonDenied}, nil
	})
	sh, _ := dial(t, s, "files", filesCmd)
	var c *stdioConn
	s.mu.Lock()
	for k := range s.conns {
		c = k
	}
	s.mu.Unlock()
	if c == nil {
		t.Fatal("no connection")
	}
	cl := call{raw: []byte(callNotification("write_file")), method: "tools/call", tool: "write_file", isCall: true}
	c.holdAsk(cl, mcptool.Result{Decision: mcptool.Ask, Rule: "mcp[files].tools.ask[write_file]"}, cl.raw)
	deadline := time.Now().Add(5 * time.Second)
	for len(sk.of(record.KindMCP)) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(sk.of(record.KindMCP)) != 1 {
		t.Fatal("the denial was not recorded")
	}
	sh.nextIsServerPing(9) // no stray error came first
}

// F8: a placement by exclusion is not kept once the process no longer hides its descriptors.
func TestHTTPExcludedHolderThatBecomesReadableIsSearchedAgain(t *testing.T) {
	procs := layout(0, map[int]fdState{200: fdsHidden})
	_, _, relay, reqs, mu := askedRelay(t, procs)
	c := &http.Client{Transport: &http.Transport{MaxConnsPerHost: 1}}
	post := func(id int) string {
		resp, err := c.Post(relay, "application/json", strings.NewReader(toolCall(id, "write_file")))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	post(1)
	procs.mu.Lock()
	procs.state[200] = fdsRead // it can be read now, and it does not hold the socket
	procs.mu.Unlock()
	out := post(2)
	mu.Lock()
	defer mu.Unlock()
	if len(*reqs) != 1 || !strings.Contains(out, "ask-unavailable") {
		t.Fatalf("asked %+v, second answer %s: the excluded placement outlived the exclusion", *reqs, out)
	}
	_ = strconv.Itoa
}
