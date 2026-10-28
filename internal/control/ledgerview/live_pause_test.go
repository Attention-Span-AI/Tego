// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"testing"
	"time"
)

// pauseGap is a launcher's gap line for one pause or resume.
func pauseGap(run string, seq int, ts time.Time, why, op string, serial int) string {
	return line(run, "probe", seq, ts, "gap", fmt.Sprintf(
		`"what":"enforce","why":"%s","live_control":{"op":"%s","by":"uid:1000 pid:9 dashboard","serial":%d,"at":"2026-10-27T12:00:00Z"}`,
		why, op, serial))
}

// TestLiveFactsPause: the run is paused from its run-paused line (who asked, when it was applied) until a run-resumed
// line; a pause that failed is not a pause, a resume that failed leaves the run paused, a live block's line does not
// move it, and an ended run is never paused.
func TestLiveFactsPause(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	start := `"tier":"landlock","command":["sh"]`
	cases := []struct {
		name     string
		lines    func(run string) []string
		paused   bool
		why      string
		seq      uint64
		pausedAt time.Time
	}{
		{"never", func(string) []string { return nil }, false, "", 0, time.Time{}},
		{"paused", func(r string) []string {
			return []string{pauseGap(r, 1, t0.Add(time.Second), "run-paused", "pause", 1), liveGap(r, 2, t0.Add(2*time.Second), "live-block-added", "add", 2)}
		}, true, "run-paused", 1, t0.Add(time.Second)},
		{"resumed", func(r string) []string {
			return []string{pauseGap(r, 1, t0.Add(time.Second), "run-paused", "pause", 1), pauseGap(r, 2, t0.Add(2*time.Second), "run-resumed", "resume", 2)}
		}, false, "run-resumed", 2, t0.Add(time.Second)},
		{"pause failed", func(r string) []string {
			return []string{pauseGap(r, 1, t0.Add(time.Second), "pause-failed", "pause", 1)}
		}, false, "pause-failed", 1, time.Time{}},
		{"pause failed, then withdrawn", func(r string) []string {
			return []string{pauseGap(r, 1, t0.Add(time.Second), "pause-failed", "pause", 1), pauseGap(r, 2, t0.Add(2*time.Second), "run-resumed", "resume", 2)}
		}, false, "run-resumed", 2, time.Time{}},
		{"resume failed", func(r string) []string {
			return []string{pauseGap(r, 1, t0.Add(time.Second), "run-paused", "pause", 1), pauseGap(r, 2, t0.Add(2*time.Second), "resume-failed", "resume", 2)}
		}, true, "resume-failed", 2, t0.Add(time.Second)},
		{"ended while paused", func(r string) []string {
			return []string{pauseGap(r, 1, t0.Add(time.Second), "run-paused", "pause", 1), line(r, "probe", 2, t0.Add(2*time.Second), "run_end", `"reason":"stopped","exit_code":143`)}
		}, false, "run-paused", 1, t0.Add(time.Second)},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := fmt.Sprintf("r-aaaa-%04d-pausex", i)
			writeRun(t, root, run, append([]string{line(run, "probe", 0, t0, "run_start", start)}, tc.lines(run)...)...)
			r, err := LoadRun(root, run)
			if err != nil {
				t.Fatal(err)
			}
			f := LiveFactsOf(r)
			if f.Paused != tc.paused || f.Pause != tc.why || f.PauseSeq != tc.seq || !f.PausedAt.Equal(tc.pausedAt) {
				t.Fatalf("pause facts = paused %v %q #%d at %v; want %v %q #%d at %v", f.Paused, f.Pause, f.PauseSeq, f.PausedAt,
					tc.paused, tc.why, tc.seq, tc.pausedAt)
			}
			if f.PauseSerial != tc.seq { // each case's serials follow its seqs
				t.Fatalf("PauseSerial = %d, want %d", f.PauseSerial, tc.seq)
			}
			if tc.paused && f.PausedBy != "uid:1000 pid:9 dashboard" {
				t.Fatalf("PausedBy = %q", f.PausedBy)
			}
		})
	}
}
