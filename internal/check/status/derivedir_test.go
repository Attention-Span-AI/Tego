// SPDX-License-Identifier: Apache-2.0

package status

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
)

// TestDeriveDirNamesARunWithoutRunStart: the one derivation DeriveAll and the CLI's named-run path share
// gives a run that died before run_start its directory's name.
func TestDeriveDirNamesARunWithoutRunStart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "r-3f9c2a1b-0dllq06ts7400-k7m2pq")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := DeriveDir(t.Context(), dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if s.Run != filepath.Base(dir) {
		t.Errorf("Run = %q, want %q", s.Run, filepath.Base(dir))
	}
}
