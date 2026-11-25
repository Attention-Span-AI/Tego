// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"testing"

	"golang.org/x/net/bpf"
)

type truncateInherited bool

func (truncateInherited) LandlockRuleset() (int, bool)                { return -1, false }
func (truncateInherited) SeccompFilter() ([]bpf.RawInstruction, bool) { return nil, false }
func (w truncateInherited) LandlockDecidesTruncate() bool             { return bool(w) }

// TestHandleForwardsLandlockDecidesTruncate: a root tier installs the filter tier 1 composed, so the supervisor's word on
// truncate(2) is the inherited handle's, whichever side of Landlock ABI 3 the kernel is, and a handle that inherited
// nothing that says, or nothing, says no (the supervisor then refuses a notified truncate).
func TestHandleForwardsLandlockDecidesTruncate(t *testing.T) {
	for _, tc := range []struct {
		name      string
		inherited Inherited
		want      bool
	}{
		{"ABI 3 and above", truncateInherited(true), true},
		{"below ABI 3", truncateInherited(false), false},
		{"nothing inherited", nil, false},
	} {
		if got := (&Handle{inherited: tc.inherited}).LandlockDecidesTruncate(); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	// A state that does not implement the word at all, as an older Inherited would not.
	if got := (&Handle{inherited: noWord{}}).LandlockDecidesTruncate(); got {
		t.Error("an inherited state that says nothing of truncate said yes")
	}
}

type noWord struct{}

func (noWord) LandlockRuleset() (int, bool)                { return -1, false }
func (noWord) SeccompFilter() ([]bpf.RawInstruction, bool) { return nil, false }
