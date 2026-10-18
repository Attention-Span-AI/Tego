// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/events"
	"github.com/attention-span-ai/tego/internal/ledger"
)

// longRun writes the record fixture copies times over into a run directory: 98 lines a copy, so 1,400 copies is
// the 137,200 events of the custom-agent POC's soak run that `events --last` took seconds to read. Each copy is
// stamped an hour after the one before, so no two copies share an instant, as no two events of a run do.
func longRun(tb testing.TB, copies int) string {
	tb.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "spec", "record", "v1", "fixtures", "run-fixture.jsonl"))
	if err != nil {
		tb.Fatal(err)
	}
	dir := tb.TempDir()
	f, err := os.OpenFile(filepath.Join(dir, ledger.EventsFile), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		tb.Fatal(err)
	}
	tsOf := regexp.MustCompile(`"ts":"([^"]*)"`)
	for i := range copies {
		shifted := tsOf.ReplaceAllFunc(src, func(m []byte) []byte {
			ts, err := time.Parse(time.RFC3339Nano, string(tsOf.FindSubmatch(m)[1]))
			if err != nil {
				tb.Fatal(err)
			}
			return []byte(`"ts":"` + ts.Add(time.Duration(i)*time.Hour).UTC().Format(time.RFC3339Nano) + `"`)
		})
		if _, err := f.Write(shifted); err != nil {
			tb.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		tb.Fatal(err)
	}
	return dir
}

// BenchmarkEventsLast is `tego events <run> --last` (table, and --json) on ledgers of 9,800 and 137,200 events.
// It read the whole ledger twice, so its time grew with the ledger; read from the end it is the same at both sizes
// (limits-check-doctor-cli.md R29 `events --last`). The nomatch case is a filter nothing matches, the most --last
// can now read: the whole ledger once, from the end.
func BenchmarkEventsLast(b *testing.B) {
	for _, copies := range []int{100, 1400} {
		dir := longRun(b, copies)
		for _, c := range []struct {
			name  string
			kinds []string
		}{{"table", nil}, {"json", nil}, {"nomatch", []string{"ask"}}} {
			kinds := c.kinds
			if kinds == nil {
				kinds = []string{"refused", "gap", "limit"}
			}
			f, err := events.ParseFilter(kinds, nil, nil, nil, nil, 0)
			if err != nil {
				b.Fatal(err)
			}
			b.Run(strconv.Itoa(copies*98)+"/"+c.name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					var out bytes.Buffer
					if code := runEvents(context.Background(), dir, f, true, c.name == "json", &out, io.Discard); code != 0 || out.Len() == 0 {
						b.Fatalf("exit %d, %d bytes", code, out.Len())
					}
				}
			})
		}
	}
}
