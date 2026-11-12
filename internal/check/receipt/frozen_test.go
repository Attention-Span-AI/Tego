// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestCoverageNamesTheFrozenDirectories (GAPS A12): under Coverage the receipt names the directories run_start's
// deny_read_frozen names, in which a name made during the run was unreadable to it, and keeps them when Check prices
// the receipt again. They are no coverage gap (Complete is unchanged). A run_start without the field, from a tego
// before revision 30 or a run whose ruleset listed none, gives the receipt no such key and no such line.
func TestCoverageNamesTheFrozenDirectories(t *testing.T) {
	frozen := start("off", true)
	p := frozen.payload.(record.RunStartPayload)
	p.RecordMinor = record.MinorDenyReadFrozen
	p.DenyReadFrozen = &record.DenyReadFrozen{Dirs: []string{"/", "/home", "/home/u"}, Omitted: 2}
	frozen.payload = p
	rc := compute(t, []line{frozen, end(time.Second, 0)}, Options{})
	plain := compute(t, []line{start("off", true), end(time.Second, 0)}, Options{})
	if rc.Coverage.Complete != plain.Coverage.Complete || len(rc.Coverage.Gaps) != len(plain.Coverage.Gaps) {
		t.Errorf("the frozen directories changed the gaps: %+v, was %+v", rc.Coverage, plain.Coverage)
	}
	if f := rc.Coverage.DenyReadFrozen; f == nil || strings.Join(f.Dirs, " ") != "/ /home /home/u" || f.Omitted != 2 {
		t.Fatalf("coverage.deny_read_frozen = %+v", f)
	}
	var b bytes.Buffer
	if err := rc.Text(&b); err != nil {
		t.Fatal(err)
	}
	want := "  Frozen at launch: deny_read listed /, /home, /home/u and 2 more once; a file or directory made directly in one " +
		"of them during the run could not be read.\n"
	if cov := b.String()[strings.Index(b.String(), "\nCoverage\n"):]; !strings.Contains(cov, want) {
		t.Errorf("the text's coverage does not name them:\n%s", cov)
	}
	b.Reset()
	if err := rc.JSON(&b); err != nil {
		t.Fatal(err)
	}
	var j struct {
		Coverage map[string]json.RawMessage `json:"coverage"`
	}
	var got bytes.Buffer
	if err := json.Unmarshal(b.Bytes(), &j); err != nil || json.Compact(&got, j.Coverage["deny_read_frozen"]) != nil ||
		got.String() != `{"dirs":["/","/home","/home/u"],"omitted":2}` {
		t.Errorf("coverage JSON %s (%v)", b.Bytes(), err)
	}
	rc.reprice(0, 0, false)
	if rc.Coverage.DenyReadFrozen == nil {
		t.Error("pricing the receipt again dropped the frozen directories")
	}

	b.Reset()
	if err := plain.JSON(&b); err != nil || strings.Contains(b.String(), "deny_read_frozen") {
		t.Errorf("a run_start without the field: %s (%v)", b.Bytes(), err)
	}
	b.Reset()
	if err := plain.Text(&b); err != nil || strings.Contains(b.String(), "Frozen at launch") {
		t.Errorf("a run_start without the field:\n%s (%v)", b.String(), err)
	}
}
