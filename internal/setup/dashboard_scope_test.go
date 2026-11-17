// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestDashboardScopeRetainsConfiguredLedger(t *testing.T) {
	dir := t.TempDir()
	served := filepath.Join(dir, "served")
	machine := config.Builtin()
	machine.LedgerRoot.Value = filepath.Join(dir, "configured-before")
	_, before, err := DashboardScope(machine, served)
	if err != nil {
		t.Fatal(err)
	}
	machine.LedgerRoot.Value = served
	_, after, err := DashboardScope(machine, served)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("an explicit served ledger erased a change in the loaded machine's ledger setting")
	}
}
