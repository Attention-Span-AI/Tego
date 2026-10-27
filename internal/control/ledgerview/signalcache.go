// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// A run page asks for the run's Signal on every request, and a live run's page every few seconds. A run's lines only
// grow, so the result is kept per run and reused while the run has the same lines: the key is the run, its line
// count, its first and last line (so a run read again from a rewritten file does not match) and its Sensitive (the
// contract entries that make a path a secret, and the person's severity rules, so a change re-sorts every run at once). The key also holds what the Signal reads besides the lines: whether the run is live and
// how many asks are open (an ask is pending only while the run is live), and the run's revision, which moves when
// either changes. A run that goes from live to lost leaves no new line, and without these its open asks stayed
// "pending" in the cache.
//
// A run that gained lines is not read again from the first line: while it is live, its fold (signalfold.go) is kept
// beside the result, and the new version folds only the lines it gained, then runs the post-pass. A 100k-line live
// run so costs a few milliseconds per update instead of a whole pass. The fold is used only when the new lines extend
// the ones it took (signalFold.extends) and the Sensitive is the same; anything else (another contract, a replaced
// file, a cut run) is a whole pass from the first line. An ended or lost run keeps only its result: its lines no
// longer grow.
type signalKey struct {
	run         string
	n           int
	first, last time.Time
	lastSeq     uint64
	sens        string // sensKey: the contract's entries, the working folder and the person's severity rules
	live        bool
	pending     int
	rev         uint64
}

// signalSlot is one run's cache entry. mu is held while its Signal is computed, so concurrent requests for the same
// run wait for one computation instead of each doing it.
type signalSlot struct {
	mu   sync.Mutex
	key  signalKey
	sig  *RunSignal
	fold *signalFold // kept while the run is live
}

// maxSignals bounds the cache: one entry per run, dropped wholesale when more runs than this were asked for. It is
// far above a ledger's run count: the overview asks for every run with a refusal on each load, and a bound below
// that count emptied the cache on every load.
const maxSignals = 1 << 14

var (
	signalMu    sync.Mutex
	signalCache = map[string]*signalSlot{}
	// For tests: signalComputes counts the Signals not served from the cache, signalFolds the ones of them that
	// folded only the lines a run gained.
	signalComputes atomic.Int64
	signalFolds    atomic.Int64
)

// Signal reads one run's lines for its highlights and grouped refusals, from the cache while the run has the same
// lines. The result is the caller's to change (the web layer labels the groups): its Groups slice is its own copy.
func Signal(r *Run, s Sensitive) *RunSignal {
	evs := r.AllEvents()
	if len(evs) == 0 {
		return computeSignal(r, s)
	}
	last := &evs[len(evs)-1]
	k := signalKey{run: r.ID, n: len(evs), first: evs[0].TS, last: last.TS, lastSeq: last.Seq,
		sens: sensKey(s), live: r.Live, pending: len(r.Pending), rev: r.Rev}
	signalMu.Lock()
	slot := signalCache[r.ID]
	if slot == nil {
		if len(signalCache) >= maxSignals {
			clear(signalCache)
		}
		slot = &signalSlot{}
		signalCache[r.ID] = slot
	}
	signalMu.Unlock()

	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.sig == nil || slot.key != k {
		signalComputes.Add(1)
		// Any other version (an older one a slower request still holds, another file, another contract) starts a
		// fold from the first line: the newer version that comes next extends that fold again, so a race costs one
		// whole pass, never a wrong Signal.
		f := slot.fold
		if f != nil && f.sens.key == k.sens && f.extends(evs) {
			signalFolds.Add(1)
			f.add(evs[f.n:])
		} else {
			f = newSignalFold(s)
			f.add(evs)
		}
		slot.key, slot.sig = k, f.finish(r)
		slot.fold = nil
		if r.Live {
			slot.fold = f
		}
	}
	return own(slot.sig)
}

// own is a copy of sig the caller may change: the struct and its Groups slice.
func own(sig *RunSignal) *RunSignal {
	out := *sig
	out.Groups = slices.Clone(sig.Groups)
	return &out
}
