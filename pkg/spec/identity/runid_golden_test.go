// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"bytes"
	"crypto/rand"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestNewRunIDHost8AndTime36AreComputedFromInputs pins R1's exact host8/time36 formulas against
// values computed independently of production, not against the id's own substrings.
//
// TestNewRunIDShape (runid_test.go) already checks widths, but its host8 assertion compares
// parts[1] to id.Host8() — and Host8() is defined as string(r)[2:10], i.e. it re-extracts the same
// characters from the very same id string. That comparison is true by construction no matter which
// bytes of hostID (or none at all) NewRunID actually used, so it cannot catch host8 being built from
// the wrong slice of hostID, and nothing anywhere checks time36's value (only its width) against
// now.UTC().UnixNano(). Both are real gaps: production was edited locally to compute host8 from
// hostID[4:8] instead of hostID[:4], and separately to feed UnixNano()+1 into time36 — the full
// existing suite (including TestNewRunIDShape) passed unchanged both times; only this test catches
// either.
func TestNewRunIDHost8AndTime36AreComputedFromInputs(t *testing.T) {
	// Bytes chosen so a wrong slice (e.g. hostID[4:8], or a reversed/rotated read) yields a
	// different, obviously-wrong host8 rather than accidentally matching this one.
	hostID := [32]byte{
		0xde, 0xad, 0xbe, 0xef, // hostID[0:4] -> host8
		0x11, 0x22, 0x33, 0x44, // a distinct decoy range a wrong slice might read instead
	}
	now := time.Date(2026, 9, 22, 12, 0, 0, 123456789, time.UTC)

	id, err := NewRunID(hostID, now, bytes.NewReader([]byte{0, 0, 0, 0}))
	if err != nil {
		t.Fatalf("NewRunID: %v", err)
	}
	parts := strings.Split(string(id), "-")
	if len(parts) != 4 {
		t.Fatalf("unexpected id shape %q", id)
	}

	const wantHost8 = "deadbeef" // golden literal: lower hex of hostID[0:4] (R1), independent of Host8()
	if parts[1] != wantHost8 {
		t.Errorf("R1: host8 = %q, want %q (lower hex of hostID[0:4])", parts[1], wantHost8)
	}

	// zeroPad below duplicates padLeft's contract, not its code (a distinct loop), so a bug in
	// padLeft itself would still show up as a mismatch here.
	wantTime36 := zeroPad(strconv.FormatInt(now.UTC().UnixNano(), 36), time36Width)
	if parts[2] != wantTime36 {
		t.Errorf("R1: time36 = %q, want %q (base36 of now.UTC().UnixNano(), zero-padded to 13)", parts[2], wantTime36)
	}
}

// zeroPad left-pads s to width with '0', written independently of production's padLeft so this
// test does not mask a bug in padLeft by calling it to build its own expectation.
func zeroPad(s string, width int) string {
	for len(s) < width {
		s = "0" + s
	}
	return s
}

// TestNewRunIDZeroHostID pins E4: a zero-value [32]byte hostID (a caller bug, per I8, not
// identity's to detect) must not be special-cased — NewRunID must still mint a normally-shaped,
// Valid id rather than erroring or panicking on it.
// identity-config.md E4.
func TestNewRunIDZeroHostID(t *testing.T) {
	var zero [32]byte
	id, err := NewRunID(zero, time.Unix(1, 0), bytes.NewReader([]byte{1, 2, 3, 4}))
	if err != nil {
		t.Fatalf("E4: zero hostID rejected: %v", err)
	}
	if !id.Valid() {
		t.Fatalf("E4: zero hostID produced invalid id %q", id)
	}
	if got := id.Host8(); got != "00000000" {
		t.Errorf("E4: host8 of zero hostID = %q, want %q", got, "00000000")
	}
}

// TestNewRunIDClockStepsBackward pins E2: a clock stepping backward between two mints (an NTP
// correction) must not error — ids stay unique and Valid, they are simply not required to sort by
// time in that case. Nothing else in this suite mints two ids with a later time followed by an
// earlier one.
// identity-config.md E2.
func TestNewRunIDClockStepsBackward(t *testing.T) {
	later := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	earlier := later.Add(-time.Hour)

	id1, err := NewRunID(testHost, later, bytes.NewReader([]byte{1, 2, 3, 4}))
	if err != nil {
		t.Fatalf("E2: mint at later time: %v", err)
	}
	id2, err := NewRunID(testHost, earlier, bytes.NewReader([]byte{5, 6, 7, 8}))
	if err != nil {
		t.Fatalf("E2: mint at earlier time after a backward clock step: %v", err)
	}
	if !id1.Valid() || !id2.Valid() {
		t.Fatalf("E2: backward clock step produced an invalid id: %q, %q", id1, id2)
	}
	if id1 == id2 {
		t.Fatal("E2: backward clock step produced a duplicate id")
	}
}

// TestNewRunIDConcurrentSameTick pins E24: goroutines racing NewRunID within the same clock tick
// (identical now) must neither collide nor corrupt each other's output. identity holds no shared
// mutable state across calls, so this needs no lock inside identity by design (E24) — but that is
// exactly the property a future change (e.g. a reused scratch buffer) could silently break, and
// nothing else in this suite calls NewRunID from more than one goroutine. Meaningful under
// `go test -race`, which is how CI runs the suite.
// identity-config.md E24.
func TestNewRunIDConcurrentSameTick(t *testing.T) {
	const n = 64
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) // identical tick for every goroutine

	ids := make([]RunID, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			ids[i], errs[i] = NewRunID(testHost, now, rand.Reader)
		}(i)
	}
	wg.Wait()

	seen := make(map[RunID]struct{}, n)
	for i, id := range ids {
		if errs[i] != nil {
			t.Fatalf("E24: goroutine %d: %v", i, errs[i])
		}
		if !id.Valid() {
			t.Fatalf("E24: goroutine %d minted invalid id %q", i, id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("E24: goroutine %d minted a duplicate id %q at the same tick", i, id)
		}
		seen[id] = struct{}{}
	}
}
