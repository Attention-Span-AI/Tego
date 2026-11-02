// SPDX-License-Identifier: Apache-2.0

package events

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
	_ "time/tzdata" // a machine with no zone database still has America/New_York

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestTablePrintsTheReadersZone: the table prints each time in the reader's zone and names the zone in the
// header, so a time read off `tego events` beside the dashboard is the same; the JSON view keeps the ledger's UTC.
func TestTablePrintsTheReadersZone(t *testing.T) {
	old := tableClock
	edt := time.FixedZone("EDT", -4*3600)
	tableClock = func() *time.Location { return edt }
	t.Cleanup(func() { tableClock = old })

	r := fixtureReader(t)
	var table, js bytes.Buffer
	if _, err := Table(t.Context(), &table, r, Filter{Limit: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := JSON(t.Context(), &js, r, Filter{Limit: 1}); err != nil {
		t.Fatal(err)
	}
	var first struct {
		TS time.Time `json:"ts"`
	}
	if err := json.Unmarshal(bytes.SplitN(js.Bytes(), []byte("\n"), 2)[0], &first); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(table.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("table: %q", table.String())
	}
	if !strings.HasPrefix(lines[0], "SEQ  TIME (EDT)  ") {
		t.Errorf("header %q does not name the zone", lines[0])
	}
	if want := first.TS.In(edt).Format("15:04:05.000"); !strings.Contains(lines[1], "  "+want+"  ") {
		t.Errorf("row %q lacks the local time %s (UTC %s)", lines[1], want, first.TS.UTC().Format("15:04:05.000"))
	}
	if !strings.Contains(js.String(), `"ts":"`+first.TS.UTC().Format("2006-01-02T15:04:05")) {
		t.Errorf("the JSON view no longer prints the ledger's UTC: %s", js.String())
	}
}

// TestTableZoneIsTheRowsOwn: a zone's name belongs to an instant. A run read after a daylight-saving change was
// printed in the time it happened in, under a header that named today's zone, an hour off every row; and a run that
// crossed the change had one header for two offsets. The dates are fixed, so one of the two cases fails on any day
// the header reads the clock.
func TestTableZoneIsTheRowsOwn(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	old := tableClock
	tableClock = func() *time.Location { return ny }
	t.Cleanup(func() { tableClock = old })

	table := func(stamps ...time.Time) []string {
		t.Helper()
		var b bytes.Buffer
		bw := bufio.NewWriter(&b)
		entries := func(yield func(ledger.Entry, error) bool) {
			for _, ts := range stamps {
				e := ledgertest.Event(t, record.KindGap, record.GapPayload{What: record.GapEnforce, Why: "paused"}, func(e *record.Event) { e.TS = ts })
				if !yield(ledger.Entry{Event: e}, nil) {
					return
				}
			}
		}
		if _, err := writeTable(t.Context(), newTable(bw), "dir", entries, Filter{}); err != nil {
			t.Fatal(err)
		}
		if err := bw.Flush(); err != nil {
			t.Fatal(err)
		}
		return strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	}

	july := time.Date(2026, 7, 1, 16, 0, 0, 0, time.UTC)
	if got := table(july); !strings.HasPrefix(got[0], "SEQ  TIME (EDT)") || !strings.Contains(got[1], "  12:00:00.000  ") {
		t.Errorf("a July run:\n%s", strings.Join(got, "\n"))
	}
	january := time.Date(2026, 1, 15, 17, 0, 0, 0, time.UTC)
	if got := table(january); !strings.HasPrefix(got[0], "SEQ  TIME (EST)") || !strings.Contains(got[1], "  12:00:00.000  ") {
		t.Errorf("a January run:\n%s", strings.Join(got, "\n"))
	}

	// 2026-11-01 01:59:59 EDT, then 01:00:01 EST two seconds later: the clock goes back and the column cannot say so
	// alone.
	before, after := time.Date(2026, 11, 1, 5, 59, 59, 0, time.UTC), time.Date(2026, 11, 1, 6, 0, 1, 0, time.UTC)
	got := table(before, after)
	if !strings.HasPrefix(got[0], "SEQ  TIME (EDT)") {
		t.Errorf("the header of a run across the change: %q", got[0])
	}
	if !strings.Contains(got[1], "  01:59:59.000  ") || strings.Contains(got[1], "EST") {
		t.Errorf("the row before the change: %q", got[1])
	}
	if !strings.Contains(got[2], "  01:00:01.000 EST  ") {
		t.Errorf("the row after the change does not say its zone: %q", got[2])
	}
}
