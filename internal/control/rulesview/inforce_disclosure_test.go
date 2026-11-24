// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"strings"
	"testing"
)

// TestInForceNamesTheProfilesTheRunMerged (C155): run_start records the profiles the run's contract merged, and the
// Rules in force view says which, and where each was read, from the ledger or the read model alike.
func TestInForceNamesTheProfilesTheRunMerged(t *testing.T) {
	f := newFixtureWith(t, "r-aaaaaaaa-0000000000105-cprofs", sourceText,
		`,"profiles":[{"name":"base/mini","source":"builtin","sha256":"aa"},{"name":"team","source":"dir","sha256":"0123456789abcdef0123456789abcdef"}]`)
	for name, v := range both(t, f) {
		found := false
		for _, n := range v.View.Notes {
			found = found || strings.Contains(n, "base/mini (built into tego)") && strings.Contains(n, "team (the profiles folder, sha256 0123456789ab)")
		}
		if !found {
			t.Errorf("%s: no note names the merged profiles and their sources: %q", name, v.View.Notes)
		}
	}
}
