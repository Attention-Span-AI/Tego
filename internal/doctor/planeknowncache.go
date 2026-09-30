// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
)

// The known answers' cache (docs/p0/enforce-plane.md R21, §2.5). The known answers ask the kernel's verifier and the
// plane's programs questions whose answer depends on the kernel, its boot and the programs, never on a run: so a
// mode's answers, once every cell matched, are kept in the run-probe cache's directory under the run-probe cache's
// key (the boot, the kernel, the LSM list, lockdown, the build's hash, this binary and the asking process), one file
// per mode and build, and a later probe of the same key reads them instead of filling a scratch slot again. That is
// what keeps the known answers off a warm probe's time where each map-in-map update waits for an RCU grace period
// (AL2023's 6.1: about 900 ms fresh). Only a full match is kept; a mode whose cells differ, or a probe that could not
// run them, finds nothing kept and runs them again, and so does a test that flips a cell (planeKnownFlip). The mode's
// exec pin cell (ADR 0048 (7)) is kept with them, passed or failed, since it too is the kernel's answer; answers whose
// cell could not run to its end are not kept, so the next probe runs both again.

// planeKnownEntry is one kept mode's answers.
type planeKnownEntry struct {
	Key   runCacheKey        `json:"key"`
	Mode  bpfobj.PlaneMode   `json:"mode"`
	Build bpfobj.Object      `json:"build"`
	Known []PlaneKnownAnswer `json:"known"`
	// ExecPin is the mode's exec pin cell.
	ExecPin *PlaneExecPinCell `json:"exec_pin"`
}

// planeKnownCache is where a probe keeps and finds its known answers; key is false when the run-probe cache's key
// could not be read, and then nothing is kept or read.
type planeKnownCache struct {
	cache *runCache
	key   runCacheKey
	ok    bool
}

// newPlaneKnownCache is the machine's known-answers cache for the probe of release by uid, or none (nothing kept or
// read) when keep is false: doctor's own scope measures every cell afresh (limits-check-doctor-cli R27).
func newPlaneKnownCache(release string, uid int, keep bool) planeKnownCache {
	if !keep {
		return planeKnownCache{}
	}
	c := defaultRunCache()
	k, ok := c.key(release, uid)
	return planeKnownCache{cache: c, key: k, ok: ok}
}

// name is mode m's file for build o.
func (p planeKnownCache) name(m bpfobj.PlaneMode, o bpfobj.Object) string {
	b, _ := json.Marshal(p.key)
	sum := sha256.Sum256(b)
	return "plane-known-" + p.key.BPFHash + "-" + hex.EncodeToString(sum[:8]) + "-" + string(o) + "-" + string(m) + ".json"
}

// load returns mode m's kept answers for build o: every cell of today's table, in its order, each with today's
// expected answer and each matched, and the exec pin cell's answer. Anything else is none.
func (p planeKnownCache) load(m bpfobj.PlaneMode, o bpfobj.Object) ([]PlaneKnownAnswer, *PlaneExecPinCell, bool) {
	if !p.ok || p.cache == nil || planeKnownFlip != "" {
		return nil, nil, false
	}
	b, _, ok := p.cache.readFile(p.name(m, o))
	if !ok {
		return nil, nil, false
	}
	var e planeKnownEntry
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil || !reflect.DeepEqual(e.Key, p.key) || e.Mode != m || e.Build != o ||
		!knownAllMatch(e.Known) || e.ExecPin == nil {
		return nil, nil, false
	}
	return e.Known, e.ExecPin, true
}

// store keeps mode m's answers for build o, with its exec pin cell's, when every cell matched and the pin cell ran
// to an answer, and removes any kept ones otherwise. It never fails the probe: an answer it cannot write is one the
// next probe does not find.
func (p planeKnownCache) store(m bpfobj.PlaneMode, o bpfobj.Object, known []PlaneKnownAnswer, pin *PlaneExecPinCell) {
	if !p.ok || p.cache == nil || planeKnownFlip != "" {
		return
	}
	if !knownAllMatch(known) || pin == nil {
		p.cache.dropName(p.name(m, o))
		return
	}
	b, err := json.Marshal(planeKnownEntry{Key: p.key, Mode: m, Build: o, Known: known, ExecPin: pin})
	if err == nil {
		_, _ = p.cache.writeFile(p.name(m, o), b)
	}
}

// knownAllMatch reports whether known is today's table, cell for cell with its expected answer, all matched.
func knownAllMatch(known []PlaneKnownAnswer) bool {
	cells := planeKnownCells()
	if len(known) != len(cells) {
		return false
	}
	for i, c := range cells {
		a := known[i]
		if a.Cell != c.Cell || a.Want != c.Want || a.WantCounts != c.WantCounts || !a.OK() {
			return false
		}
	}
	return true
}
