// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"sync"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// An open Rules page or line page of a busy run asks for InForce about once a second, and cachedScan opened the
// ledger for run_start and decoded up to maxExecScan exec payloads every time: about two thirds of a warm InForce
// on a 55k-line run (r7 debt lane). What it finds depends only on the run's lines, so it is kept per run
// version: the run's directory, the read model's revision of the run (it moves with any appended line, a replaced
// file or a live-state change, and it starts at the clock, so a restarted dashboard never repeats one), its line
// count and its newest line's seq. The compile, the live blocks, the rules file and the journal are still read on
// every call: they change without a line being written. A Run with no revision (one built for the line bound, or a
// test's literal) is scanned every time.

// scanKey is the run version a cached scan was read from.
type scanKey struct {
	dir     string
	rev     uint64
	lines   int
	lastSeq uint64
}

// maxScans bounds the scans kept: the least recently used goes past it.
const maxScans = 64

type scanEntry struct {
	sc   *runScan
	used uint64
}

var (
	scanMu    sync.Mutex
	scans     = map[scanKey]*scanEntry{}
	scanClock uint64
	scanReads int // cachedScan calls made, for tests
)

// memoScan is cachedScan(dir, r), from the memo while r's version is the one scanned. The scan is shared: InForce
// only reads it.
func memoScan(dir string, r *ledgerview.Run) (*runScan, error) {
	if r.Rev == 0 {
		return cachedScan(dir, r)
	}
	k := scanKey{dir: dir, rev: r.Rev, lines: r.Lines, lastSeq: r.LastSeq}
	scanMu.Lock()
	if e, ok := scans[k]; ok {
		scanClock++
		e.used = scanClock
		scanMu.Unlock()
		return e.sc, nil
	}
	scanReads++
	scanMu.Unlock()
	sc, err := cachedScan(dir, r)
	if err != nil {
		return nil, err // a run without its run_start yet is read again next time
	}
	scanMu.Lock()
	defer scanMu.Unlock()
	if len(scans) >= maxScans {
		var oldest scanKey
		var at uint64
		first := true
		for key, e := range scans {
			if first || e.used < at {
				oldest, at, first = key, e.used, false
			}
		}
		delete(scans, oldest)
	}
	scanClock++
	scans[k] = &scanEntry{sc: sc, used: scanClock}
	return sc, nil
}
