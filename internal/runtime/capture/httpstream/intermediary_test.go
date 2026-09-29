// SPDX-License-Identifier: Apache-2.0

package httpstream

import "testing"

// TestH1BytesStayH1WhateverAnIntermediaryNegotiated is capture-derive.md E20: h2 is decided by the traced
// process's own bytes (R17's preface), so a process that speaks h1 stays h1 however a front end upstream of it
// negotiated the connection. Capture never sees that negotiation, and an h1 exchange raises no h2 gap and is
// reassembled whole.
func TestH1BytesStayH1WhateverAnIntermediaryNegotiated(t *testing.T) {
	ws := []wire{
		req("POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: 2\r\n\r\n{}"),
		resp("HTTP/1.1 200 OK\r\nAlt-Svc: h2=\":443\"\r\nContent-Length: 2\r\n\r\n{}"),
	}
	msgs, gaps, err := run(t, Options{}, 0, true, ws)
	if err != nil {
		t.Fatalf("feed: %v", err)
	}
	if hasGap(gaps, GapH2) {
		t.Errorf("gaps = %v, an h1 exchange raised an h2 gap", gaps)
	}
	if len(msgs) != 2 || string(msgs[1].Body) != "{}" {
		t.Errorf("messages = %d, want the request and its whole response", len(msgs))
	}
}
