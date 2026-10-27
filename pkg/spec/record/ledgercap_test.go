// SPDX-License-Identifier: Apache-2.0

package record

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestRecordMinorCoversTheLedgerCap: the ledger ceiling is revision 22, the next free one after live blocks' 21
// (TestRecordMinorsAreContiguous), and this build writes it; its limit line, which=ledger_bytes with no reason, is a
// valid v1 line, and the README documents it.
func TestRecordMinorCoversTheLedgerCap(t *testing.T) {
	if MinorLedgerCap != MinorLiveBlock+1 || Minor < MinorLedgerCap {
		t.Fatalf("Minor %d, MinorLedgerCap %d: the ledger cap is 22, after live blocks at 21", Minor, MinorLedgerCap)
	}
	ev := &Event{V: 1, Seq: 1, Prev: strings.Repeat("a", IDLen), Run: "r-00000000-0dmelo027fwny-kmm5cd", Agent: "tester",
		TS: time.Unix(1, 0).UTC(), Kind: KindLimit, Source: SourceSupervisor}
	if err := ev.SetPayload(LimitPayload{Which: LimitLedgerBytes, Value: 70000, Ceiling: 65536}); err != nil {
		t.Fatal(err)
	}
	if err := ev.Validate(); err != nil {
		t.Fatalf("a ledger_bytes limit line with no reason: %v", err)
	}
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := "At `record_minor` " + strconv.Itoa(MinorLedgerCap) + " ("
	i := strings.Index(string(b), want)
	if i < 0 {
		t.Fatalf("spec/record/v1/README.md has no %q", want)
	}
	text := string(b[i:min(len(b), i+1200)])
	for _, s := range []string{"`record.max_run_bytes`", "`run_start.limits.ledger_bytes`", "`which=ledger_bytes`",
		"`run_end reason limit`"} {
		if !strings.Contains(text, s) {
			t.Errorf("README's record_minor %d entry does not name %s", MinorLedgerCap, s)
		}
	}
}
