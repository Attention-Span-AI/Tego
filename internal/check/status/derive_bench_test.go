// SPDX-License-Identifier: Apache-2.0

package status

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
)

// BenchmarkDerive is what `tego status` pays for one run, on ledgers of 9,800 and 137,200 events. It reads the whole
// ledger, so its time grows with it: the event count, the step, the gap line and the pending asks it prints are
// totals over every line, and the ledger is the only store (ADR 0004), so no line can be skipped
// (limits-check-doctor-cli.md R7-R12, "What reads the whole ledger").
func BenchmarkDerive(b *testing.B) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "run-fixture.jsonl"))
	if err != nil {
		b.Fatal(err)
	}
	for _, copies := range []int{100, 1400} {
		dir := b.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), bytes.Repeat(src, copies), 0o600); err != nil {
			b.Fatal(err)
		}
		r, err := ledger.OpenReader(dir)
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { _ = r.Close() })
		now := time.Now()
		b.Run(strconv.Itoa(copies*98), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := Derive(r, false, now, 0); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
