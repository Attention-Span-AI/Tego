// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bytes"
	"crypto/sha256"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The retry key is a function of exactly the four things a retry repeats, and of nothing
// else (R23).
func TestComputeRetryKey(t *testing.T) {
	cred := sha256.Sum256([]byte("sk-ant-a"))
	other := sha256.Sum256([]byte("sk-ant-b"))
	body := []byte(`{"model":"claude-opus-5"}`)
	base := ComputeRetryKey("POST", "/v1/messages", body, cred)

	if base != ComputeRetryKey("POST", "/v1/messages", body, cred) {
		t.Error("the key is not deterministic")
	}
	cases := []struct {
		name string
		key  RetryKey
	}{
		{"method", ComputeRetryKey("GET", "/v1/messages", body, cred)},
		{"path", ComputeRetryKey("POST", "/v1/messages/count_tokens", body, cred)},
		{"body", ComputeRetryKey("POST", "/v1/messages", append(body, ' '), cred)},
		{"credential", ComputeRetryKey("POST", "/v1/messages", body, other)},
	}
	for _, tc := range cases {
		if tc.key == base {
			t.Errorf("a different %s produced the same key", tc.name)
		}
	}
	// The separator matters: without it "POST" + "/v1" and "POST/v1" + "" would collide.
	if ComputeRetryKey("POST", "/v1", body, cred) == ComputeRetryKey("POST/v1", "", body, cred) {
		t.Error("the key concatenated its fields without a separator")
	}
}

// The SDK's counter (capture-derive.md E29, edge case #29).
func TestRetryCount(t *testing.T) {
	cases := []struct {
		value string
		want  int
		ok    bool
	}{
		{value: "", want: 0, ok: false},
		{value: "0", want: 0, ok: true},
		{value: "1", want: 1, ok: true},
		{value: "17", want: 17, ok: true},
		{value: "-1", ok: false},
		{value: "one", ok: false},
		{value: "1.5", ok: false},
		{value: " 1", ok: false},
	}
	for _, tc := range cases {
		h := http.Header{}
		if tc.value != "" {
			h.Set(RetryHeader, tc.value)
		}
		got, ok := RetryCount(h)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("%q: (%d, %v), want (%d, %v)", tc.value, got, ok, tc.want, tc.ok)
		}
	}
}

// The cache keeps the last 256 requests and forgets one past the TTL, which is where a
// same-key request stops being a retry and becomes a new step (capture-derive.md R24).
func TestRetryCacheWindow(t *testing.T) {
	c := newRetryCache(4, 650*time.Second)
	key := func(n byte) RetryKey {
		var k RetryKey
		k[0] = n
		return k
	}
	c.remember(0, key(1), "fx-1", 0)
	if id, ok := c.lookup(0, key(1), uint64(600*time.Second)); !ok || id != "fx-1" {
		t.Errorf("inside the window: (%q, %v)", id, ok)
	}
	if _, ok := c.lookup(0, key(1), uint64(651*time.Second)); ok {
		t.Error("a request past the TTL is a new step, not a retry (R24)")
	}

	c = newRetryCache(4, 650*time.Second)
	for i := byte(1); i <= 5; i++ {
		c.remember(0, key(i), "fx-"+itoa(int(i)), 0)
	}
	if _, ok := c.lookup(0, key(1), 0); ok {
		t.Error("the least recently used entry was not evicted at the cap")
	}
	for i := byte(2); i <= 5; i++ {
		if _, ok := c.lookup(0, key(i), 0); !ok {
			t.Errorf("entry %d was evicted too early", i)
		}
	}
	if id, ok := c.recent(0, 0); !ok || id != "fx-5" {
		t.Errorf("recent = (%q, %v), want the last request", id, ok)
	}
	if _, ok := c.recent(0, uint64(651*time.Second)); ok {
		t.Error("the fallback outlived the TTL")
	}
}

// A repeat of a key refreshes it rather than adding a second entry.
func TestRetryCacheRefreshesAKey(t *testing.T) {
	c := newRetryCache(2, time.Minute)
	var k RetryKey
	c.remember(0, k, "fx-1", 0)
	c.remember(0, k, "fx-2", uint64(time.Second))
	if id, ok := c.lookup(0, k, uint64(2*time.Second)); !ok || id != "fx-2" {
		t.Errorf("lookup = (%q, %v), want the most recent id", id, ok)
	}
	if c.order.Len() != 1 {
		t.Errorf("%d entries, want the key refreshed in place", c.order.Len())
	}
}

// R23's key is defined over the raw body, and a body capture the cap truncated is not
// that body. Two requests that share their first MaxBody bytes and differ only past them hash alike — one
// long conversation appends its next turn past the cap and repeats every byte before it — so the hash
// path is skipped for a truncated capture and the second request is the first attempt it is. Tagging it
// would be worse than missing a retry: R33 does not open a new step for a retry, it extends the original,
// so one false retry_of folds two distinct model turns into one and every turn after them follows.
func TestATruncatedBodyIsNotARetryCandidate(t *testing.T) {
	const keep = 64
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}, Options{MaxBody: keep})
	shared := bytes.Repeat([]byte("a"), keep)
	first := append(append([]byte{}, shared...), []byte(`,"turn":1}`)...)
	second := append(append([]byte{}, shared...), []byte(`,"turn":2}`)...)

	for _, body := range [][]byte{first, second} {
		resp := h.post("/v1/messages", body, nil)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	// The SDK's own counter is the one signal a truncated body keeps: what it names is the most
	// recent request, which is what an SDK retry actually repeats (#29).
	resp := h.post("/v1/messages", second, http.Header{RetryHeader: {"1"}})
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	reqs := h.sink.waitFor(t, record.KindSSLRequest, 3)
	ids := make([]record.SSLRequestPayload, 0, 3)
	for _, ev := range reqs {
		ids = append(ids, payloadOf[record.SSLRequestPayload](t, ev))
	}
	if ids[0].RetryOf != "" {
		t.Errorf("the first request was tagged retry_of %q", ids[0].RetryOf)
	}
	if ids[1].RetryOf != "" {
		t.Errorf("a distinct turn sharing the truncated prefix was recorded as retry_of %q; "+
			"R23's key is over the raw body, and a prefix cannot establish that identity", ids[1].RetryOf)
	}
	if ids[2].RetryOf != ids[1].RequestID {
		t.Errorf("retry_of = %q, want the most recent request %q: the counter path (#29) is what a "+
			"truncated body still has", ids[2].RetryOf, ids[1].RequestID)
	}
}
