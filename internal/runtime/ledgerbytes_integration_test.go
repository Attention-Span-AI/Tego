// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationLedgerCeilingEndsTheRun: a run whose events.jsonl reaches the machine's
// record.max_run_bytes (64 KiB here) is ended as a limit, exit 124, with a limit line
// which=ledger_bytes and run_end reason limit, which a unit's Restart=on-failure restarts as a new run on a new
// ledger; run_start.limits says the ceiling it ran under, and the ledger still verifies against its anchor.
func TestIntegrationLedgerCeilingEndsTheRun(t *testing.T) {
	const ceiling = 64 << 10
	f := newFixtureWithMachine(t, contractFor("iledgercap", []string{"/bin/sleep"}, []string{"/bin/sleep"}),
		func(m *config.Machine) {
			m.Record.MaxRunBytes = config.Ceiling[config.ByteSize]{Value: ceiling, Bounded: true}
		})
	deps := f.deps(t, nil)
	// A line every millisecond: the ceiling is reached in about a second, long before the agent's own end.
	deps.Capture = []source.Source{&usageSource{every: time.Millisecond, tokens: 1}}
	res, err := Run(context.Background(), f.rt, []string{"/bin/sleep", "60"}, deps)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Reason != record.RunEndLimit || res.ExitCode != identity.ExitLimit {
		t.Fatalf("result %+v, want limit/124", res)
	}
	dir := runDirs(t, f.root)[0]
	evs := events(t, dir)
	lim := limitEvent(t, evs)
	if lim.Which != record.LimitLedgerBytes || lim.Ceiling != ceiling || lim.Value < ceiling {
		t.Fatalf("limit payload %+v, want ledger_bytes at or over %d", lim, ceiling)
	}
	var start record.RunStartPayload
	if err := evs[0].DecodePayload(&start); err != nil || start.Limits == nil || start.Limits.LedgerBytes == nil ||
		*start.Limits.LedgerBytes != ceiling || start.RecordMinor < record.MinorLedgerCap {
		t.Fatalf("run_start limits %+v, record_minor %d (%v)", start.Limits, start.RecordMinor, err)
	}
	var end record.RunEndPayload
	if err := evs[len(evs)-1].DecodePayload(&end); err != nil || end.Reason != record.RunEndLimit ||
		end.ExitCode != identity.ExitLimit {
		t.Fatalf("run_end %+v (%v), want limit/124", end, err)
	}
	if _, err := ledger.VerifyRunDir(context.Background(), dir,
		ledger.NewFileChainAnchor(ledger.DefaultAnchorPath(dir))); err != nil {
		t.Fatalf("the ledger a ceiling ended does not verify: %v", err)
	}
	// The watcher reads the size at each event and each Tick, so the ledger passes the ceiling by the lines in flight.
	st, err := os.Stat(filepath.Join(dir, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("events.jsonl %d bytes at the end, ceiling %d, limit line at %v", st.Size(), ceiling, lim.Value)
}
