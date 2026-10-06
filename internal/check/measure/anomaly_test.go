// SPDX-License-Identifier: Apache-2.0

package measure

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestTwoRunEndsKeepTheFirst is limits-check-doctor-cli.md §6 case 5 (E5): a ledger with two run_end lines, which
// a healthy writer never produces, is read by its first by chain order, as status reads it, and the anomaly is
// reported rather than silently resolved: the report counts it and --json names it. measure kept the last.
func TestTwoRunEndsKeepTheFirst(t *testing.T) {
	sec := func(n uint64) uint64 { return n * uint64(time.Second) }
	rep, err := Compute(ledgerOf(t, []event{
		{kind: record.KindRunStart, mono: sec(1)},
		{kind: record.KindRunEnd, mono: sec(2), reason: record.RunEndExit},
		{kind: record.KindRunEnd, mono: sec(3), reason: record.RunEndLimit},
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.EndReason != record.RunEndExit {
		t.Errorf("end reason %q, want the first run_end's %q", rep.EndReason, record.RunEndExit)
	}
	if rep.ExtraRunEnds != 1 {
		t.Errorf("ExtraRunEnds = %d, want 1", rep.ExtraRunEnds)
	}
	anomalies := rep.Anomalies()
	if len(anomalies) != 1 || !strings.Contains(anomalies[0], "run_end") {
		t.Fatalf("Anomalies() = %q, want one naming run_end", anomalies)
	}
	var js bytes.Buffer
	if err := rep.JSON(&js); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(js.String(), `"ledger_anomalies":["`) {
		t.Errorf("--json does not name the anomaly: %s", js.String())
	}

	one, err := Compute(ledgerOf(t, []event{
		{kind: record.KindRunStart, mono: sec(1)},
		{kind: record.KindRunEnd, mono: sec(2), reason: record.RunEndExit},
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	js.Reset()
	if err := one.JSON(&js); err != nil {
		t.Fatal(err)
	}
	if len(one.Anomalies()) != 0 || strings.Contains(js.String(), "ledger_anomalies") {
		t.Errorf("a healthy ledger reports an anomaly: %q %s", one.Anomalies(), js.String())
	}
}
