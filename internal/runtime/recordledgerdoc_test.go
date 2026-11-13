// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"strings"
	"testing"
)

// TestRecordLedgerEmptyContractRetentionSpec holds the empty-run cleanup
// description to contractAgentChecked: only a missing contract establishes the
// pre-start case, while a present unreadable or invalid copy requires retry.
func TestRecordLedgerEmptyContractRetentionSpec(t *testing.T) {
	source, err := os.ReadFile("../../docs/p0/record-ledger.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(source)
	start := strings.Index(doc, "**`gc(root string, keep time.Duration, dryRun bool)")
	if start < 0 {
		t.Fatal("record-ledger.md does not contain the GC contract")
	}
	gc := strings.SplitN(doc[start:], "\n\n", 2)[0]
	if strings.Contains(gc, "With no contract copy, or one that names no agent") {
		t.Error("GC spec infers no cgroup from a present invalid contract")
	}
	for _, want := range []string{
		"With no contract copy, the hook does not run, since there was no cgroup yet.",
		"A present copy that cannot be read or names no valid agent keeps the run and reports an error for retry.",
	} {
		if !strings.Contains(gc, want) {
			t.Errorf("GC spec does not distinguish missing and uncertain contract identity: missing %q", want)
		}
	}
}
