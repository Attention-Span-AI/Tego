// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestCloseWhereClosesAProcessesConnections: an SSL_free record names a process and a pointer, and the connections it
// ends are keyed by whichever threads did their I/O. CloseWhere closes exactly the ones its match accepts, a gapped
// one included so its key starts afresh, and flushes each as Close does.
func TestCloseWhereClosesAProcessesConnections(t *testing.T) {
	a := NewAssembler(Options{})
	key := func(pid, tid uint32, ssl uint64) ConnKey {
		return ConnKey{Src: record.SourceSSL, PidTgid: uint64(pid)<<32 | uint64(tid), SSLPtr: ssl}
	}
	mine1, mine2, gapped := key(10, 10, 0x77), key(10, 11, 0x77), key(10, 12, 0x77)
	other, otherPtr := key(20, 20, 0x77), key(10, 10, 0x78)
	for _, k := range []ConnKey{mine1, mine2, other, otherPtr} {
		if _, err := a.Feed(k, DirRequest, Chunk{Data: []byte(postRequest(`{}`))}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.Feed(gapped, DirRequest, Chunk{Data: []byte("NOT A REQUEST LINE\r\n")}); err == nil {
		t.Fatal("the gapped connection did not gap")
	}
	closed, _ := a.CloseWhere(func(k ConnKey) bool { return k.PidTgid>>32 == 10 && k.SSLPtr == 0x77 })
	if len(closed) != 3 {
		t.Fatalf("closed %v, want the process's three connections on the pointer", closed)
	}
	if a.Conns() != 2 {
		t.Errorf("%d connections left, want the other process's and the other pointer's", a.Conns())
	}
	// Each closed connection had a request with no response: one gap each for the two live ones.
	if got := gapCount(a.Gaps(), GapMalformed); got != 3 {
		t.Errorf("malformed = %d, want 1 for the gapped connection and 1 for each unanswered request", got)
	}
}

// TestRequestLineEndsACloseDelimitedResponse: a close-delimited body ends only when the connection closes (RFC 9112
// §6.3), and a client sends no request on a connection its server is closing, so a request line on the key while its
// response is close-delimited is a new connection at a reused SSL* whose end capture did not see. The response ends
// there, whole and paired, before the new request; it used to take every later exchange into its body and end only at
// Stop.
func TestRequestLineEndsACloseDelimitedResponse(t *testing.T) {
	a := NewAssembler(Options{})
	if _, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte(postRequest(`{"n":0}`))}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Feed(testKey, DirResponse, Chunk{Data: []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"r\":0}")}); err != nil {
		t.Fatal(err)
	}
	msgs, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte(postRequest(`{"n":1}`))})
	if err != nil {
		t.Fatalf("the next request: %v", err)
	}
	if len(msgs) != 2 || msgs[0].Dir != DirResponse || msgs[0].Truncated || string(msgs[0].Body) != `{"r":0}` ||
		msgs[0].RequestIndex != 0 || msgs[1].Dir != DirRequest {
		t.Fatalf("got %d messages, want the close-delimited response whole and paired, then the new request", len(msgs))
	}
	rest, err := a.Feed(testKey, DirResponse, Chunk{Data: httpResponse("200 OK", nil, []byte(`{"r":1}`))})
	if err != nil || len(rest) != 1 || rest[0].RequestIndex != msgs[1].Index {
		t.Fatalf("the new request's response: %d messages, %v", len(rest), err)
	}
	if len(a.Gaps()) != 0 {
		t.Errorf("gaps %v", a.Gaps())
	}
}

// TestCloseDelimitedBodyIsNotEndedByBodyBytes: only a whole request start ends it; bytes of the body that
// happen to arrive on the request half's key are not the shape.
func TestCloseDelimitedBodyIsNotEndedByBodyBytes(t *testing.T) {
	a := NewAssembler(Options{})
	if _, err := a.Feed(testKey, DirRequest, Chunk{Data: []byte(postRequest(`{"n":0}`))}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Feed(testKey, DirResponse, Chunk{Data: []byte("HTTP/1.1 200 OK\r\n\r\npart")}); err != nil {
		t.Fatal(err)
	}
	if !a.conns[testKey].closeDelimitedEnded([]byte("POST /v1 HTTP/1.1\r\n")) {
		t.Error("a request line does not end the close-delimited response")
	}
	for _, data := range []string{"{\"x\":1}", "POSTAL", "post / HTTP/1.1\r\n", ""} {
		if a.conns[testKey].closeDelimitedEnded([]byte(data)) {
			t.Errorf("%q ended the close-delimited response", data)
		}
	}
}
