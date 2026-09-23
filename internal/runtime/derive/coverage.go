// SPDX-License-Identifier: Apache-2.0

package derive

import (
	"slices"
	"strings"
	"sync"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Gap is one uncovered capture path, in the shape the run facade's own Gap carries. Capture reports
// what it failed to see and nothing else: an agent that went around the forwarder is refused by the
// compiled net.allow and recorded as net verdict=refused, never as a gap (R38).
type Gap struct {
	What   string // always capture here
	Why    string // one of CaptureWhys (R37)
	Binary string
	Count  int64
}

// Process is what library discovery found for one process of the run (R4, R39): the binary it execed,
// the TLS library its maps or its own ELF offered, and the R1–R3 symbols that library exports. Every field is what the discovery step observed; Classify turns them
// into the one closed reason that explains an uncaptured process.
type Process struct {
	PID int
	// Binary is the realpath of the executable, resolved through /proc/<pid>/root for an adopted
	// container's process (R39).
	Binary string
	// Library is the file discovery read as the process's TLS stack: a mapped libssl, or, with none that
	// exports R1–R3, the candidate R4 reports the process against, its own executable included (static TLS
	// lives there). "" means discovery could read nothing: the process's maps were refused or gone, or the
	// host refused the attach, which the closed why set files the same way (§7, edge case #31).
	Library string
	// Symbols are the R1–R3 entry points that library exports.
	Symbols []string
}

// Write and read entry points (R1–R3). A library needs at least one of each to be captured: the writes
// carry the request, the reads carry the response, and one without the other is half a conversation.
var (
	writeSymbols = []string{"SSL_write", "SSL_write_ex", "SSL_write_ex2"}
	readSymbols  = []string{"SSL_read", "SSL_read_ex"}
)

// Classify names the one reason a process is uncaptured, or reports that it is captured.
//
// An HTTP/2 connection is not a process's verdict: reassembly finds it by its preface, one connection at a
// time (R17). It was, through an ALPN field nothing set. No-openssl is for a process where
// discovery could read nothing — which per edge case
// #31 also covers a /proc read the kernel's ptrace check refused and an attach the host refused, because
// the closed why set (R37) has no value of its own for either. Then static-tls-no-symbols, for a candidate
// that was read and exports none of the entry points: Bun's BoringSSL, a rustls binary, and, without E71's
// signature scan, a Go binary or a process with no TLS stack at all (R37 as amended).
func Classify(p Process) (why string, gap bool) {
	if p.Library == "" {
		return GapNoOpenSSL, true
	}
	if !hasAny(p.Symbols, writeSymbols) || !hasAny(p.Symbols, readSymbols) {
		return GapStaticTLSNoSymbols, true
	}
	return "", false
}

// hasAny reports whether have contains one of want.
func hasAny(have, want []string) bool {
	for _, s := range have {
		if slices.Contains(want, s) {
			return true
		}
	}
	return false
}

// Coverage is the per-process gap ledger of one run: what capture could not see, deduplicated by
// binary and reason so a process that execs a hundred times is one gap with a count, not a hundred
// lines (R37, I4).
//
// The uprobe source keeps one per run and settles every process verdict R4 reached through it (Settle), so
// the reason on a per-binary capture line is always Classify's: one classifier for every such line. The
// source fills in the Process from what discovery read, and Classify decides the reason from it. Tier 1
// captures through the forwarder, whose reach does not depend on a binary's TLS library, so there is no
// per-binary question to ask there. What Classify can decide and the source never asks is h2 per binary:
// the source learns of h2 from the reassembler, per connection, and reports it with no binary.
type Coverage struct {
	mu   sync.Mutex
	gaps map[coverageKey]int64
}

// MaxCoverageKeys caps the distinct (binary, reason) pairs one ledger keeps. Binaries are named by the agent
// (a test loop execs a fresh /tmp/go-build.../x.test each time), so past the cap a gap is counted into
// one entry per reason with no binary, and the total count is kept (R37).
const MaxCoverageKeys = 256

// count adds n to the (binary, why) pair, or to the reason's overflow entry past the cap. The caller
// holds c.mu.
func (c *Coverage) count(binary, why string, n int64) {
	key := coverageKey{binary: binary, why: why}
	if _, ok := c.gaps[key]; !ok && len(c.gaps) >= MaxCoverageKeys {
		key.binary = ""
	}
	c.gaps[key] += n
}

// coverageKey is one (binary, reason) pair.
type coverageKey struct{ binary, why string }

// NewCoverage returns an empty ledger.
func NewCoverage() *Coverage {
	return &Coverage{gaps: make(map[coverageKey]int64)}
}

// Settle classifies one process verdict and counts it, for a caller that holds each process's verdict
// until the process can no longer be captured and then settles it exactly once: the uprobe source, whose
// verdict at an exec can still be withdrawn by the open that loads the process's libssl (R4). It keeps no
// set of pids, because a pid the kernel hands out again within the run is another
// process, and each image a process execs is its own verdict. A captured process counts nowhere.
func (c *Coverage) Settle(p Process) (why string, gap bool) {
	why, gap = Classify(p)
	if !gap {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count(p.Binary, why, 1)
	return why, true
}

// Note counts a gap a caller classified itself: a ring-buffer drop with its lost count, a cap, a
// connection that did not reassemble. An unknown reason is recorded as malformed rather than widening
// the closed set (R37).
func (c *Coverage) Note(binary, why string, count int64) {
	if !IsCaptureWhy(why) {
		why = GapMalformed
	}
	if count <= 0 {
		count = 1
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count(binary, why, count)
}

// Gaps is the run's gap report, ordered by reason then binary so two runs of the same shape compare.
func (c *Coverage) Gaps() []Gap {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Gap, 0, len(c.gaps))
	for key, count := range c.gaps {
		out = append(out, Gap{What: record.GapCapture, Why: key.why, Binary: key.binary, Count: count})
	}
	slices.SortFunc(out, func(a, b Gap) int {
		if a.Why != b.Why {
			return strings.Compare(a.Why, b.Why)
		}
		return strings.Compare(a.Binary, b.Binary)
	})
	return out
}

// Events renders the report as gap events, one per (binary, reason) — the ledger form of Gaps, for a
// caller that reports coverage at run end rather than as it happens.
func (c *Coverage) Events(meta Meta) []*record.Event {
	gaps := c.Gaps()
	out := make([]*record.Event, 0, len(gaps))
	for _, g := range gaps {
		m := meta
		m.Binary = g.Binary
		count := 0
		if g.Count > 1 {
			count = int(g.Count)
		}
		out = append(out, GapEvent(m, g.Why, count))
	}
	return out
}
