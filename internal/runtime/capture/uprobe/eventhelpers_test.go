// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/capture/httpstream"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func TestDecodableRefusesWhatHTTPStreamCannotUndo(t *testing.T) {
	for enc, want := range map[string]bool{
		"":               true,
		"identity":       true,
		"gzip":           true,
		"GZIP":           true,
		"gzip, br":       true,
		"zstd":           true,
		"compress":       false,
		"gzip, unknown":  false,
		"gzip, gzip, br": false, // more codings than the assembler undoes
	} {
		if got := decodable(enc); got != want {
			t.Errorf("decodable(%q) = %v, want %v", enc, got, want)
		}
	}
}

func TestLatencyMSNeverGoesNegative(t *testing.T) {
	for _, c := range []struct {
		start, end uint64
		want       int64
	}{
		{0, 0, 0},
		{5_000_000, 5_000_000, 0},
		{5_000_000, 1_000_000, 0}, // a clock read out of order is 0, not a wrapped huge number
		{1_000_000, 4_999_999, 3},
		{1_000_000_000, 3_500_000_000, 2500},
	} {
		if got := latencyMS(c.start, c.end); got != c.want {
			t.Errorf("latencyMS(%d, %d) = %d, want %d", c.start, c.end, got, c.want)
		}
	}
}

func TestStampOrNowPrefersTheChunksOwnTime(t *testing.T) {
	fallback := time.Unix(100, 0)
	now := func() time.Time { return fallback }
	own := time.Unix(50, 0)
	if got := stampOrNow(own, now); !got.Equal(own) {
		t.Errorf("got %v, want the chunk's own %v", got, own)
	}
	if got := stampOrNow(time.Time{}, now); !got.Equal(fallback) {
		t.Errorf("got %v, want the clock's %v", got, fallback)
	}
}

// A CONNECT target is a host and a port and nothing else; any other shape must not be read as a host, or a
// crafted target could name whatever authority the contract's policy then judged.
func TestConnectAuthorityAcceptsOnlyHostAndPort(t *testing.T) {
	for _, c := range []struct {
		target string
		ok     bool
	}{
		{"api.anthropic.com:443", true},
		{"[::1]:8080", true},
		{"api.anthropic.com", false},
		{":443", false},
		{"host:", false},
		{"host:443/path", false},
		{"user@host:443", false},
		{"host:443?x=1", false},
		{"host:443#f", false},
		{"", false},
	} {
		authority, path, ok, tunnel := connectAuthority(c.target)
		if ok != c.ok || tunnel != c.ok || path != c.target {
			t.Errorf("connectAuthority(%q) = %q %q %v %v", c.target, authority, path, ok, tunnel)
		}
		if c.ok && authority != c.target {
			t.Errorf("connectAuthority(%q) authority = %q", c.target, authority)
		}
		if !c.ok && authority != "" {
			t.Errorf("connectAuthority(%q) authority = %q, want none", c.target, authority)
		}
	}
}

// connHosts is a bounded table: filling it starts it afresh rather than growing without limit.
func TestNoteHostIsBounded(t *testing.T) {
	u := &Uprobe{connHosts: map[httpstream.ConnKey]string{}}
	k := func(i int) httpstream.ConnKey { return httpstream.ConnKey{ConnID: uint64(i)} }
	for i := 0; i < maxConnHosts; i++ {
		u.noteHost(k(i), "a.example")
	}
	if len(u.connHosts) != maxConnHosts {
		t.Fatalf("table holds %d, want %d", len(u.connHosts), maxConnHosts)
	}
	u.noteHost(k(0), "b.example") // an existing key updates in place, never clears
	if len(u.connHosts) != maxConnHosts || u.connHosts[k(0)] != "b.example" {
		t.Fatalf("an update must not restart the table: %d entries", len(u.connHosts))
	}
	u.noteHost(k(maxConnHosts+1), "c.example")
	if len(u.connHosts) != 1 || u.connHosts[k(maxConnHosts+1)] != "c.example" {
		t.Fatalf("a new key past the bound starts afresh with itself: %d entries", len(u.connHosts))
	}
}

type silentDeriver struct{ silent bool }

func (d silentDeriver) Handle(req, resp *derive.Message, meta derive.Meta) (derive.Result, error) {
	return derive.Result{}, nil
}

func (d silentDeriver) Silent(provider, host, method, target string) bool {
	return d.silent && method == "GET" && target == "/health"
}

// A request is silent (spends nothing, so is not unmetered when lost) only when the Deriver says so and the
// request's host is known and it is no tunnel: anything less certain is treated as possible spend.
func TestSilentNeedsAKnownHostAndADeriverThatSaysSo(t *testing.T) {
	u := &Uprobe{opts: Options{Deriver: silentDeriver{silent: true}}}
	req := func(host, method, path string, tunnel bool) *openRequest {
		return &openRequest{Host: host, Method: method, Path: path, Tunnel: tunnel}
	}
	if !u.silent(req("api.x", "GET", "/health", false)) {
		t.Error("a health check the deriver calls silent is silent")
	}
	for name, r := range map[string]*openRequest{
		"a POST":          req("api.x", "POST", "/health", false),
		"another path":    req("api.x", "GET", "/v1/messages", false),
		"an unknown host": req("", "GET", "/health", false),
		"a tunnel":        req("api.x", "GET", "/health", true),
	} {
		if u.silent(r) {
			t.Errorf("%s must not be silent", name)
		}
	}
	if (&Uprobe{opts: Options{Deriver: silentDeriver{}}}).silent(req("api.x", "GET", "/health", false)) {
		t.Error("a deriver that says no is not silent")
	}
	if (&Uprobe{}).silent(req("api.x", "GET", "/health", false)) {
		t.Error("no deriver, nothing known to be silent")
	}
}

func TestMeteredHostIsFailClosedForUnknownHosts(t *testing.T) {
	u := &Uprobe{opts: Options{Rules: &agent.RuleTable{Contract: &agent.Contract{
		Models: []agent.ModelEndpoint{{Provider: "anthropic", Host: "api.anthropic.com", Port: 443}},
	}}}}
	if !u.meteredHost("") {
		t.Error("a host capture never learned may have been a model's")
	}
	if !u.meteredHost("api.anthropic.com:443") {
		t.Error("a declared model host is metered")
	}
	if u.meteredHost("example.test") {
		t.Error("a host neither declared nor claimed is not model spend")
	}
}
