// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

const testRunID = "r-3f9c2a1b-0dllq06ts7400-k7m2pq"

// The traceparent vectors of spec/identity/RUN-IDENTITY.md (R20).
func TestTraceparent(t *testing.T) {
	want := sha256.Sum256([]byte(testRunID))
	runTraceID := hex.EncodeToString(want[:16])
	cases := []struct {
		name, in                       string
		wantTraceID, wantParent, flags string
	}{
		{name: "no header: a trace derived from the run id, sampled",
			wantTraceID: runTraceID, flags: "01"},
		{name: "a valid parent keeps its trace id and flags, and is recorded as the parent",
			in:          "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00",
			wantTraceID: "4bf92f3577b34da6a3ce929d0e0e4736", wantParent: "00f067aa0ba902b7", flags: "00"},
		{name: "a future version is not parsed as version 00",
			in: "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", wantTraceID: runTraceID, flags: "01"},
		{name: "an all-zero trace id is invalid",
			in: "00-00000000000000000000000000000000-00f067aa0ba902b7-01", wantTraceID: runTraceID, flags: "01"},
		{name: "an all-zero parent id is invalid",
			in: "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", wantTraceID: runTraceID, flags: "01"},
		{name: "upper-case hex is invalid",
			in: "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01", wantTraceID: runTraceID, flags: "01"},
		{name: "a short trace id is invalid", in: "00-4bf9-00f067aa0ba902b7-01", wantTraceID: runTraceID, flags: "01"},
		{name: "a truncated header is invalid", in: "00-4bf92f3577b34da6a3ce929d0e0e4736", wantTraceID: runTraceID, flags: "01"},
		{name: "an empty header is invalid", in: "", wantTraceID: runTraceID, flags: "01"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.in != "" {
				h.Set(HeaderTraceparent, tc.in)
			}
			tr, err := newTrace(testRunID, h, &countingRand{})
			if err != nil {
				t.Fatalf("new trace: %v", err)
			}
			if tr.TraceID != tc.wantTraceID {
				t.Errorf("trace id = %q, want %q", tr.TraceID, tc.wantTraceID)
			}
			if tr.ParentSpanID != tc.wantParent {
				t.Errorf("parent span id = %q, want %q", tr.ParentSpanID, tc.wantParent)
			}
			if tr.Flags != tc.flags {
				t.Errorf("flags = %q, want %q", tr.Flags, tc.flags)
			}
			if len(tr.SpanID) != 16 || tr.SpanID == strings.Repeat("0", 16) {
				t.Errorf("span id = %q, want 8 fresh non-zero bytes", tr.SpanID)
			}
			if tr.SpanID == tr.ParentSpanID {
				t.Error("the parent id was not replaced")
			}
			header := tr.header()
			if got, ok := parseTraceparent(header); !ok || got.TraceID != tr.TraceID || got.SpanID != tr.SpanID {
				t.Errorf("the header it writes does not parse back: %q", header)
			}
			if strings.Contains(header, testRunID) {
				t.Error("the run id travelled inside traceparent")
			}
		})
	}
}

// Tracestate rules (R20). The prior tego member is removed as its own step, before the
// prepend, so a request that already carried one never leaves with two.
func TestTracestate(t *testing.T) {
	long := make([]string, 40)
	for i := range long {
		long[i] = "v" + itoa(i) + "=x"
	}
	cases := []struct {
		name, in string
		fresh    bool
		want     string
	}{
		{name: "nothing in, one member out", want: "tego=" + testRunID},
		{name: "a fresh trace discards what the client sent", in: "other=1", fresh: true, want: "tego=" + testRunID},
		{name: "a continued trace keeps the client's members", in: "a=1,b=2",
			want: "tego=" + testRunID + ",a=1,b=2"},
		{name: "a prior tego member is removed, not duplicated",
			in: "tego=r-old,a=1", want: "tego=" + testRunID + ",a=1"},
		{name: "a prior tego member anywhere is removed",
			in: "a=1,tego=r-old,b=2", want: "tego=" + testRunID + ",a=1,b=2"},
		{name: "spacing around a member is tolerated",
			in: " tego = r-old , a=1 ", want: "tego=" + testRunID + ",a=1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tracestateFor(testRunID, tc.in, tc.fresh)
			if got != tc.want {
				t.Errorf("tracestate = %q, want %q", got, tc.want)
			}
			if strings.Count(got, "tego=") != 1 {
				t.Errorf("tracestate carries %d tego members: %q", strings.Count(got, "tego="), got)
			}
		})
	}
	t.Run("members past 32 are dropped from the right", func(t *testing.T) {
		got := tracestateFor(testRunID, strings.Join(long, ","), false)
		members := strings.Split(got, ",")
		if len(members) != maxTracestateMembers {
			t.Fatalf("%d members, want %d", len(members), maxTracestateMembers)
		}
		if members[0] != "tego="+testRunID {
			t.Errorf("first member = %q", members[0])
		}
		if members[len(members)-1] != "v30=x" {
			t.Errorf("last member = %q, want the right-most dropped", members[len(members)-1])
		}
	})
}

// The RFC 7230 §6.1 hop-by-hop set, plus whatever Connection names, is removed; everything
// else passes byte for byte (R20).
func TestCopyHeaderDropsHopByHop(t *testing.T) {
	src := http.Header{
		"Connection":          {"keep-alive, X-Custom-Hop"},
		"Keep-Alive":          {"timeout=5"},
		"Proxy-Authenticate":  {"Basic"},
		"Proxy-Authorization": {"Basic Zm9v"},
		"Proxy-Connection":    {"keep-alive"},
		"Te":                  {"trailers"},
		"Trailer":             {"Expires"},
		"Transfer-Encoding":   {"chunked"},
		"Upgrade":             {"websocket"},
		"X-Custom-Hop":        {"named by Connection"},
		"Content-Type":        {"application/json"},
		"X-Api-Key":           {"sk-ant-test-credential"},
		"X-Repeated":          {"a", "b"},
	}
	dst := http.Header{}
	copyHeader(dst, src)
	for _, name := range []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "X-Custom-Hop"} {
		if dst.Get(name) != "" {
			t.Errorf("%s survived", name)
		}
	}
	if dst.Get("Content-Type") != "application/json" || dst.Get("X-Api-Key") != "sk-ant-test-credential" {
		t.Errorf("a forwarded header changed: %v", dst)
	}
	if v := dst.Values("X-Repeated"); len(v) != 2 {
		t.Errorf("repeats collapsed: %v", v)
	}
}

// A capture-only listener (neither net.http nor net.proxy) answers an upgrade offer as R20 says: Upgrade,
// Connection and what Connection names are stripped and the request is forwarded as HTTP/1.1, which RFC 9110
// §7.8 lets a server do with an offer it declines. An h2c offer (curl --http2, java.net.http's default) and
// Codex's WebSocket attempt at /v1/responses were refused with 400 and a malformed gap instead.
func TestCaptureOnlyUpgradeOfferIsStrippedAndForwarded(t *testing.T) {
	seen := make(chan http.Header, 4)
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		_, _ = w.Write([]byte(`{}`))
	}, Options{})
	for _, offer := range []http.Header{
		{"Connection": {"Upgrade, HTTP2-Settings"}, "Upgrade": {"h2c"}, "Http2-Settings": {"AAMAAABkAAQCAAAAAAIAAAAA"}},
		{"Upgrade": {"h2c"}},
		{"Connection": {"upgrade"}},
		{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Sec-Websocket-Version": {"13"}, "Sec-Websocket-Key": {"dGhlIHNhbXBsZSBub25jZQ=="}},
	} {
		resp := h.post("/v1/responses", []byte(`{}`), offer)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%v: status %d, want the request forwarded", offer, resp.StatusCode)
		}
		up := <-seen
		for _, name := range []string{"Connection", "Upgrade", "Http2-Settings"} {
			if up.Get(name) != "" {
				t.Fatalf("%v: %s reached the upstream", offer, name)
			}
		}
	}
	if gaps := h.listener.Gaps(); len(gaps) != 0 {
		t.Fatalf("a declined upgrade offer counted as a capture gap: %v", gaps)
	}
}

// No credential ever leaves this package in a value a payload could carry (I5).
func TestCredentialsNeverReachAPayload(t *testing.T) {
	const secret = "sk-ant-test-credential"
	h := http.Header{
		"X-Api-Key":     {secret},
		"Authorization": {"Bearer " + secret},
		"Cookie":        {"session=" + secret},
		"Content-Type":  {"application/json"},
		"Request-Id":    {"req_1"},
	}
	kept := recordedHeaders(h)
	for name, v := range kept {
		if strings.Contains(v, secret) {
			t.Errorf("%s carried the credential into a payload", name)
		}
	}
	if kept["content-type"] != "application/json" || kept["request-id"] != "req_1" {
		t.Errorf("headers = %v, want the allow-listed ones kept", kept)
	}
	sum := credential(h)
	if sum == credential(http.Header{}) {
		t.Error("the credential hash does not depend on the credential")
	}
	if strings.Contains(hex.EncodeToString(sum[:]), secret) {
		t.Error("the hash is not a hash")
	}
	// Authorization is used when x-api-key is absent, so a subscription token is still distinguished.
	only := credential(http.Header{"Authorization": {"Bearer " + secret}})
	if only == credential(http.Header{}) {
		t.Error("Authorization was ignored as a credential")
	}
}
