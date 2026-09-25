// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"net/url"
	"strconv"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// taggedRequest is exchangeRequest naming its exchange i in the target, and taggedResponse is its answer
// naming the same i in Request-Id, so a test can tell a response paired with its own request from one paired
// with a neighbour's: counting pairs cannot, since a shift by one leaves both counts unchanged.
func taggedRequest(i int) string {
	return "POST /v1/messages?i=" + strconv.Itoa(i) + " HTTP/1.1\r\nHost: api.anthropic.com\r\n" +
		"Content-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"model\":\"opus\"}\n"
}

func taggedResponse(i int) string {
	return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nRequest-Id: req_" + strconv.Itoa(i) +
		"\r\nContent-Length: 22\r\n\r\n{\"id\":\"msg_01\",\"x\":1}\n"
}

// checkPairs is capture-derive.md I3 over one sink: every ssl_response carries the pair token of an ssl_request
// emitted before it, and, for tagged exchanges, the request it pairs with is the one it answers. It returns
// the number of ssl_request and ssl_response events.
func checkPairs(t *testing.T, sink *fakeSink) (reqs, resps int) {
	t.Helper()
	tagOf := map[uint64]string{}
	for _, ev := range sink.events() {
		switch ev.Kind {
		case record.KindSSLRequest:
			reqs++
			var p record.SSLRequestPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			tag := ""
			if u, err := url.Parse(p.Path); err == nil {
				tag = u.Query().Get("i")
			}
			tagOf[ev.Pair] = tag
		case record.KindSSLResponse:
			resps++
			var p record.SSLResponsePayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			tag, ok := tagOf[ev.Pair]
			if !ok {
				t.Errorf("ssl_response %q has no earlier ssl_request with its pair token (I3)", p.RequestID)
				continue
			}
			if tag != "" && p.RequestID != "req_"+tag {
				t.Errorf("request %s paired with response %s: a wrong pairing (I3)", tag, p.RequestID)
			}
		}
	}
	return reqs, resps
}
