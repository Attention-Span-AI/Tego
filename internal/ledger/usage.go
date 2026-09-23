// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"math"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TokenUsage is one model response's token accounting, as a budget counts it.
type TokenUsage struct {
	// Model is ssl_response.model, the key of the price table (limits-check-doctor-cli.md R2).
	Model string
	// In, Out, CacheRead and CacheWrite are usage{input, output, cache_read, cache_write}, with a
	// negative count read as 0.
	In, Out, CacheRead, CacheWrite uint64
	// CacheWrite1h is usage.cache_write_1h, the part of CacheWrite written with the 1-hour lifetime, never more
	// than CacheWrite: a ledger that says more is read as CacheWrite having been at least that much.
	CacheWrite1h uint64
	// ServerTool is usage.server_tool, the per-request server-tool counts, shared with the decoded event and
	// never written to. A count at or below 0 counts nothing.
	ServerTool map[string]int
	// Modified is usage.modified: billed under a modifier (fast speed, a priority tier, geo pinning, extra
	// iterations) the token counters do not show. The price table cannot price it.
	Modified bool
}

// Usage is the token accounting of e (limits-check-doctor-cli.md §4 ledger.Usage): ok is true exactly
// when e is an ssl_response whose payload decodes and carries a usage object. It is the one decode the
// live budget (limits.Watcher.Observe, R1/R2) and the after-the-fact view (measure.ComputeAt, R20) share,
// so the two can never read a response differently (I5); each still runs its own totals, since the
// engine and the read side never import each other (C1).
//
// A negative count is 0 rather than an error: usage comes from the upstream's response body, and a
// budget must neither wrap an unsigned total nor be credited tokens back by a malformed or hostile
// reply. A response with no usage object (a streamed error, an unparsed body) is not ok and costs
// nothing (E14).
func Usage(e *record.Event) (TokenUsage, bool) {
	if e == nil || e.Kind != record.KindSSLResponse {
		return TokenUsage{}, false
	}
	var p record.SSLResponsePayload
	if err := e.DecodePayload(&p); err != nil || p.Usage == nil {
		return TokenUsage{}, false
	}
	u := p.Usage
	t := TokenUsage{
		Model: p.Model,
		In:    nonNegative(u.Input), Out: nonNegative(u.Output),
		CacheRead: nonNegative(u.CacheRead), CacheWrite: nonNegative(u.CacheWrite),
		CacheWrite1h: nonNegative(u.CacheWrite1h), ServerTool: u.ServerTool, Modified: u.Modified,
	}
	t.CacheWrite = max(t.CacheWrite, t.CacheWrite1h)
	return t, true
}

// nonNegative reads a negative count as 0.
func nonNegative(n int) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

// SatAdd is a+b, held at the largest uint64 rather than wrapped: a total of counts a hostile reply chose must
// never wrap to a small number below a ceiling. It is the one addition the live budget and measure share.
func SatAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}
