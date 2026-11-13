// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"strings"
	"testing"
	"time"
)

func TestCacheCountsBadTimestampAndContinues(t *testing.T) {
	for _, stamp := range []string{"2026-09-22T09:00:00,002Z", "2026-09-22T9:00:00Z", "2026-09-22T09:00:00+24:00", "2026-09-22T09:00:00+00:60"} {
		t.Run(stamp, func(t *testing.T) {
			root := t.TempDir()
			run := "r-aaaa-0001-stampx"
			now := time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC)
			bad := strings.Replace(line(run, "x", 1, now, "gap", `"what":"record","why":"test"`), now.Format(time.RFC3339Nano), stamp, 1)
			writeRun(t, root, run, line(run, "x", 0, now, "run_start", ""), bad, line(run, "x", 2, now, "run_end", `"reason":"exit","exit_code":0`))
			s, err := Load(root)
			if err != nil {
				t.Fatal(err)
			}
			r := s.Find(run)
			if r == nil || r.Bad != 1 || r.Lines != 2 || !r.Ended {
				t.Fatalf("cached run: %+v", r)
			}
		})
	}
}

func TestCacheHoldsBadTimestampUntilNewline(t *testing.T) {
	for _, stamp := range []string{"2026-09-22T09:00:00,002Z", "2026-09-22T9:00:00Z", "2026-09-22T09:00:00+24:00", "2026-09-22T09:00:00+00:60"} {
		t.Run(stamp, func(t *testing.T) {
			root := t.TempDir()
			run := "r-aaaa-0001-pendts"
			now := time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC)
			bad := strings.Replace(line(run, "x", 1, now, "gap", `"what":"record","why":"test"`), now.Format(time.RFC3339Nano), stamp, 1)
			writeRun(t, root, run, line(run, "x", 0, now, "run_start", ""), strings.TrimSuffix(bad, "\n"))
			store := Open(root)
			check := func(lines, bad int, ended bool) {
				t.Helper()
				s, err := store.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				r := s.Find(run)
				if r == nil || r.Lines != lines || r.Bad != bad || r.Ended != ended {
					t.Fatalf("cached run: %+v; want lines=%d bad=%d ended=%v", r, lines, bad, ended)
				}
			}
			check(1, 0, false) // A cache waits for a newline even when the JSON object closes.
			appendLines(t, root, run, "\n")
			check(1, 1, false)
			appendLines(t, root, run, line(run, "x", 2, now, "run_end", `"reason":"exit","exit_code":0`))
			check(2, 1, true)
		})
	}
}
