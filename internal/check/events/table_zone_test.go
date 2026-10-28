// SPDX-License-Identifier: Apache-2.0

package events

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
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
