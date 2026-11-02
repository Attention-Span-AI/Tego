// SPDX-License-Identifier: Apache-2.0

package status

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestDeriveDirReadsTheLedgerSize: a snapshot says how many bytes the run's events.jsonl holds and the
// record.max_run_bytes run_start says it runs under, and LedgerLine shows both, so a 24/7 run's growth is visible
// before its ceiling ends it.
func TestDeriveDirReadsTheLedgerSize(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "r-3f9c2a1b-0dllq06ts7400-k7m2pq")
	w, err := ledger.Open(dir, record.RunRef{ID: filepath.Base(dir), Agent: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"true"}, Cwd: "/", Tier: "landlock",
		Limits: &record.Limits{LedgerBytes: new(int64(1 << 30))}}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Abandon() }()
	s, err := DeriveDir(t.Context(), dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	if s.LedgerBytes != st.Size() || s.LedgerBytes == 0 || s.LedgerCeiling != 1<<30 {
		t.Fatalf("LedgerBytes %d (file %d), LedgerCeiling %d", s.LedgerBytes, st.Size(), s.LedgerCeiling)
	}
	if _, err := w.Blob(make([]byte, 5000)); err != nil {
		t.Fatal(err)
	}
	if s, err = DeriveDir(t.Context(), dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	if s.LedgerBytes != st.Size()+5000 {
		t.Fatalf("LedgerBytes with a blob of 5000 = %d, want %d, what the ceiling is compared against", s.LedgerBytes, st.Size()+5000)
	}
	if got, want := LedgerLine(&Snapshot{LedgerBytes: 3 << 19, LedgerCeiling: 1 << 30}),
		"1.5 MiB of 1.0 GiB (record.max_run_bytes)"; got != want {
		t.Errorf("LedgerLine = %q, want %q", got, want)
	}
	if got, want := LedgerLine(&Snapshot{LedgerBytes: 900}), "900 B, no ceiling"; got != want {
		t.Errorf("LedgerLine = %q, want %q", got, want)
	}
}
