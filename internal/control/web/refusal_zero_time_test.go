// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// The fixture goes through record.Decode: the RFC3339 zero date is valid, but
// malformed and absent timestamps must remain unreadable instead of becoming it.
func TestDailyRefusalsDecodedZeroTimestamp(t *testing.T) {
	for _, truncated := range []bool{false, true} {
		for _, period := range []string{"modern", "zero-day", "before-zero", "invalid", "missing"} {
			t.Run(fmt.Sprintf("%s/truncated=%v", period, truncated), func(t *testing.T) {
				oldLimit := ledgerview.MaxLines
				if truncated {
					ledgerview.MaxLines = 4
				}
				t.Cleanup(func() { ledgerview.MaxLines = oldLimit })
				root := t.TempDir()
				id := "r-aaaaaaaa-0000000000097-zerots"
				zero := time.Time{}
				now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
				if period == "zero-day" || period == "before-zero" {
					now = zero.Add(12 * time.Hour)
				}
				at := time.Date(now.Year(), now.Month(), now.Day(), 1, 0, 0, 0, time.UTC)
				first, last := zero, at
				if period == "before-zero" {
					at = zero.Add(-time.Hour)
					first, last = at, zero
				}
				refused := `"op":"exec","target":"curl","rule":"unmatched","reason":"exec-not-allowed"`
				data := line(id, "counter", 0, zero, "refused", refused)
				data += line(id, "counter", 1, at, "refused", refused)
				if period == "invalid" || period == "missing" {
					bad := line(id, "counter", 2, at, "refused", refused)
					if period == "invalid" {
						bad = strings.Replace(bad, at.Format(time.RFC3339Nano), "not-a-timestamp", 1)
					} else {
						bad = strings.Replace(bad, `"ts":"`+at.Format(time.RFC3339Nano)+`",`, "", 1)
					}
					data += bad
				}
				for seq := 3; seq < 15; seq++ {
					data += line(id, "counter", seq, at, "gap", `"what":"record","why":"routine"`)
				}
				data += line(id, "counter", 15, at, "run_end", `"reason":"exit","exit_code":0`)
				if err := os.MkdirAll(filepath.Join(root, id), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, id, "events.jsonl"), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
				snap, err := ledgerview.Load(root)
				if err != nil {
					t.Fatal(err)
				}
				r := snap.Find(id)
				if r == nil {
					t.Fatal("decoded run missing")
				}
				if r.Refusals != 2 || !r.RefusalFirst.Equal(first) || !r.RefusalLast.Equal(last) {
					t.Errorf("decoded refusal count=%d bounds=%s..%s, want 2 and %s..%s", r.Refusals, r.RefusalFirst, r.RefusalLast, first, last)
				}
				bad := period == "invalid" || period == "missing"
				wantBad := 0
				if bad {
					wantBad = 1
				}
				if r.Bad != wantBad {
					t.Fatalf("invalid timestamp accepted or zero timestamp rejected: Bad=%d", r.Bad)
				}
				if r.Cut != truncated {
					t.Fatalf("Cut=%v, want %v", r.Cut, truncated)
				}
				want, lower := 1, bad
				if period == "zero-day" {
					want = 2 // Both valid dates belong to this complete aggregate.
				} else if truncated {
					want, lower = 0, true // The cross-period aggregate cannot date omitted rows.
				}
				n, gotLower, records := dailyRefusals(snap, now)
				if n != want || gotLower != lower || (len(records) > 0) != lower {
					t.Errorf("daily=(%d, lower=%v, records=%d), want (%d, lower=%v)", n, gotLower, len(records), want, lower)
				}
			})
		}
	}
}
