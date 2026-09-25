// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"

	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
)

// TestDoctorSaysWhatNoSweepFinishes: at the CLI, doctor names the ledger
// root, each other host's run count with the machine-id hint, and each ended run no sweep has finished.
func TestDoctorSaysWhatNoSweepFinishes(t *testing.T) {
	var b bytes.Buffer
	lc := tegoruntime.LedgerCheck{
		Root:       "/l/runs",
		Host:       "0badf00d",
		Foreign:    map[string]int{"deadbeef": 3},
		Unfinished: []string{"r-0badf00d-000000000000c-stuck0"},
	}
	if err := writeLedgerCheck(&b, lc); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"ledger /l/runs:", "3 run(s) minted on host deadbeef, not this one (0badf00d)",
		"machine's id changed", "run r-0badf00d-000000000000c-stuck0 ended", "events --verify r-0badf00d-000000000000c-stuck0"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor's ledger lines lack %q:\n%s", want, out)
		}
	}
}
