// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The rule of C204 (ADR 0126 §4, amended 2026-11-21): a tools/list is answered filtered, however it was asked: alone, in
// a batch, twice with one id, among many, or over a stream. The relay never passes an answer it could not filter.

func listResult(id string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,"result":{"tools":[{"name":"read_file"},{"name":"write_file"},{"name":"delete_file"}]}}`
}

func listReq(id string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/list"}`
}

func (sh *shim) server(line string) {
	sh.t.Helper()
	if err := sh.fw.Write(Frame{S: []byte(line)}); err != nil {
		sh.t.Fatal(err)
	}
}

func hidesDenied(t *testing.T, b []byte) {
	t.Helper()
	if strings.Contains(string(b), "delete_file") || !strings.Contains(string(b), "read_file") {
		t.Fatalf("the list the client gets: %s", b)
	}
}

func TestBatchedToolsListAnswerIsFiltered(t *testing.T) {
	s, _, _ := start(t, nil, filesServer())
	sh, _ := dial(t, s, "files", filesCmd)
	sh.client(batchOf(listReq(`"L1"`), ping(2)))
	if f := sh.read(); f.ToServer == nil {
		t.Fatalf("frame %+v", f)
	}
	// A server answers a batch with a batch.
	sh.server(`[` + listResult(`"L1"`) + `,{"jsonrpc":"2.0","id":2,"result":{}}]`)
	f := sh.read()
	hidesDenied(t, f.ToClient)
	if got := idsOf(t, f.ToClient); strings.Join(got, ",") != `"L1",2` {
		t.Fatalf("the answer lost a member: %s", f.ToClient)
	}
}

// TestToolsListWithOneIDTwiceIsRefusedTheSecondTime: two requests in flight under one id are answered by no one a client could
// tell apart; the second is refused with an error of its own, and the first's answer is filtered.
func TestToolsListWithOneIDTwiceIsRefusedTheSecondTime(t *testing.T) {
	s, sk, _ := start(t, nil, filesServer())
	sh, _ := dial(t, s, "files", filesCmd)
	sh.client(listReq(`"L"`))
	sh.client(listReq(`"L"`))
	f1, f2 := sh.read(), sh.read()
	if f1.ToServer == nil || f2.ToServer != nil || !strings.Contains(string(f2.ToClient), "-32001") || !strings.Contains(string(f2.ToClient), `"id":"L"`) {
		t.Fatalf("frames %+v %+v", f1, f2)
	}
	sh.server(listResult(`"L"`))
	hidesDenied(t, sh.read().ToClient)
	if n := len(sk.of(record.KindMCP)); n != 1 {
		t.Fatalf("record lines %d", n)
	}
	sh.client(listReq(`"L"`)) // answered, so the id is free
	if f := sh.read(); f.ToServer == nil {
		t.Fatalf("frame %+v", f)
	}
}

// TestManyRequestsInFlightAreRefusedPastTheBound: more requests waiting than the relay remembers are refused with an error
// of their own, and every answer to one it passed is filtered.
func TestManyRequestsInFlightAreRefusedPastTheBound(t *testing.T) {
	s, sk, _ := start(t, nil, filesServer())
	sh, _ := dial(t, s, "files", filesCmd)
	const sent = maxInflight + 6
	for i := range sent {
		sh.client(listReq(strconv.Itoa(i)))
	}
	passed, refused := 0, 0
	for range sent {
		f := sh.read()
		switch {
		case f.ToServer != nil:
			passed++
		case strings.Contains(string(f.ToClient), "-32001"):
			refused++
		default:
			t.Fatalf("frame %+v", f)
		}
	}
	if passed != maxInflight || refused != 6 {
		t.Fatalf("passed %d, refused %d, want %d and 6", passed, refused, maxInflight)
	}
	for i := range maxInflight {
		sh.server(listResult(strconv.Itoa(i)))
		hidesDenied(t, sh.read().ToClient)
	}
	sh.client(listReq("100000")) // the room is free again
	if f := sh.read(); f.ToServer == nil {
		t.Fatalf("frame %+v", f)
	}
	if n := len(sk.of(record.KindMCP)); n != 6 {
		t.Fatalf("record lines %d, want one for each refused request", n)
	}
}

func TestHTTPToolsListInAnEventStreamBatchIsFiltered(t *testing.T) {
	rec := &recorder{answer: func(string) (string, int, string) {
		return "text/event-stream", 200, "event: message\ndata: [" + listResult("1") + ",{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}]\n\n"
	}}
	_, _, _, relay := httpRelayFor(t, rec, webRules())
	_, body, _ := postJSON(t, relay, batchOf(listReq("1"), ping(2)))
	hidesDenied(t, []byte(body))
}

func TestHTTPToolsListAnswerTypeIsReadAsItIsSpelt(t *testing.T) {
	for _, ct := range []string{"application/json", "Application/JSON; charset=utf-8", "application/vnd.mcp+json"} {
		t.Run(ct, func(t *testing.T) {
			rec := &recorder{answer: func(string) (string, int, string) { return ct, 200, listResult("1") }}
			_, _, _, relay := httpRelayFor(t, rec, webRules())
			code, body, _ := postJSON(t, relay, listReq("1"))
			if code != 200 {
				t.Fatalf("status %d: %s", code, body)
			}
			hidesDenied(t, []byte(body))
		})
	}
}

func TestHTTPToolsListAnswerOfAnotherTypeIsNotPassedUnfiltered(t *testing.T) {
	rec := &recorder{answer: func(string) (string, int, string) { return "text/plain", 200, listResult("1") }}
	_, sk, _, relay := httpRelayFor(t, rec, webRules())
	code, body, _ := postJSON(t, relay, listReq("1"))
	if code != http.StatusBadGateway || strings.Contains(body, "delete_file") {
		t.Fatalf("status %d: %s", code, body)
	}
	if n := len(sk.of(record.KindMCP)); n != 1 {
		t.Fatalf("record lines %d: the answer that was not passed on is a line", n)
	}
}

func TestHTTPToolsListWithOneIDTwiceInABatchIsRefused(t *testing.T) {
	rec := &recorder{}
	_, _, _, relay := httpRelayFor(t, rec, webRules())
	code, body, _ := postJSON(t, relay, batchOf(listReq("1"), listReq("1")))
	if code != 200 || len(rec.sent()) != 0 || strings.Count(body, "-32001") != 2 {
		t.Fatalf("status %d, sent %q: %s", code, rec.sent(), body)
	}
}

func TestFilterResponseOfABatchLeavesTheOthersAlone(t *testing.T) {
	s, _, _ := start(t, nil, filesServer())
	in := `[{"jsonrpc":"2.0","id":5,"result":{"x":1}},` + listResult("7") + `]`
	out := string(s.filterResponse("files", []byte(in)))
	if strings.Contains(out, "delete_file") || !strings.Contains(out, `"id":5,"result":{"x":1}`) {
		t.Fatalf("%s", out)
	}
	if same := string(s.filterResponse("files", []byte(`[1,2]`))); same != `[1,2]` {
		t.Fatalf("a batch of no messages was changed: %s", same)
	}
}
