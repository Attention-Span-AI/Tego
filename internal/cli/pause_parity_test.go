// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestPauseReadersAgree: `tego status` and the dashboard read one run's pause from the same launcher lines, and
// say one thing about whether the run is paused. A run is paused from its run-paused or resume-failed line until a
// run-resumed line; a pause-failed line moves nothing (a pause that failed leaves a run as it was, so a run that was
// paused stays paused). tego status used to read only the last line, and said a paused run was not paused when a
// failed pause followed its pause.
//
// This file is one of the internal/cli tests allowed to import the dashboard (.golangci.yml
// engine-never-imports-control): the parity it checks spans both binaries.
func TestPauseReadersAgree(t *testing.T) {
	P, R, PF, RF := record.GapRunPaused, record.GapRunResumed, record.GapPauseFailed, record.GapResumeFailed
	for _, whys := range [][]string{
		nil,
		{P}, {R}, {PF}, {RF},
		{P, R}, {P, PF}, {P, RF}, {PF, P}, {PF, R},
		{P, RF, PF}, {P, RF, R}, {P, PF, R}, {P, R, PF}, {P, R, P}, {RF, PF},
	} {
		t.Run(strings.Join(whys, ","), func(t *testing.T) {
			var gaps []record.GapPayload
			for i, w := range whys {
				gaps = append(gaps, pauseGap(w, uint64(i+1)))
			}
			dir, id := controlLedger(t, gaps)
			r, err := ledgerview.LoadRun(strings.TrimSuffix(dir, "/"+id), id)
			if err != nil {
				t.Fatal(err)
			}
			f := ledgerview.LiveFactsOf(r) // the run ended: its pause is EndedPaused
			if got, want := readPause(dir, id).Paused, f.EndedPaused; got != want {
				t.Errorf("tego status reads paused=%v, the dashboard %v", got, want)
			}
		})
	}
}

// TestLiveFactsReadersAgree: `tego block --list` and the dashboard both say whether a live block is in force from
// the launcher's lines; the serial they hold as confirmed, the limits they hold as passed and the run_start facts they
// compare against are one answer for one ledger.
func TestLiveFactsReadersAgree(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 12, 3, 0, 0, time.UTC)
	block := func(why, op string, serial uint64, until time.Time) record.GapPayload {
		return record.GapPayload{What: record.GapEnforce, Why: why, LiveBlock: &record.LiveBlockChange{Op: op, Kind: "exec",
			Value: "/usr/bin/curl", Rule: record.LiveRule("exec", "/usr/bin/curl"), By: "uid:1000 pid:9 cli", Serial: serial, At: t0, Until: until}}
	}
	for name, gaps := range map[string][]record.GapPayload{
		"none":         nil,
		"added":        {block(record.GapLiveBlockAdded, record.LiveOpAdd, 3, time.Time{})},
		"out of order": {block(record.GapLiveBlockAdded, record.LiveOpAdd, 5, time.Time{}), block(record.GapLiveBlockRemoved, record.LiveOpRemove, 4, time.Time{})},
		"expired": {block(record.GapLiveBlockAdded, record.LiveOpAdd, 1, t0.Add(time.Hour)),
			block(record.GapLiveBlockExpired, record.LiveOpExpire, 1, t0.Add(time.Hour))},
		"unblock expired": {block(record.GapLiveUnblockExpired, record.LiveOpExpire, 1, t0.Add(time.Minute))},
		"pause beside":    {pauseGap(record.GapRunPaused, 2), block(record.GapLiveBlockAdded, record.LiveOpAdd, 3, time.Time{})},
	} {
		t.Run(name, func(t *testing.T) {
			dir, id := controlLedger(t, gaps)
			r, err := ledgerview.LoadRun(filepath.Dir(dir), id)
			if err != nil {
				t.Fatal(err)
			}
			f := ledgerview.LiveFactsOf(r)
			facts, top, limits := liveFacts(dir, true)
			f.Ended = false // the CLI reads run_start only
			if !reflect.DeepEqual(facts, f.Facts) || top != f.Confirmed || !reflect.DeepEqual(limits, f.Limits) {
				t.Errorf("tego block: %+v confirmed %d limits %+v\ndashboard: %+v confirmed %d limits %+v", facts, top, limits, f.Facts, f.Confirmed, f.Limits)
			}
		})
	}
}
