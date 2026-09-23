// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// enforcingTiers are the three tiers that refuse; observe records and refuses nothing.
func enforcingTiers() []backend.Tier {
	return []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM}
}

// TestBuiltInDenyReadAppliesWithoutFSSection pins the deny_read tri-state of SEMANTICS §1: the
// built-in credential list is disabled only by the explicit `deny_read: []`, which warns
// (deny-read-disabled), and never by the mere absence of an `fs:` key.
//
// The regression this guards is a fail-open: with no deny_read entries in the table the landlock
// backend takes its "no targets" branch and holds "/" with the whole read set
// (internal/runtime/enforce/landlock/enumerate.go), and the tier-2 listener builds an empty
// denyRead list and allows every open — so ~/.ssh, ~/.aws, ~/.netrc and the project's .env are
// readable by an agent whose contract merely omits `fs:`, with no diagnostic anywhere. Adding an
// unrelated `fs: {write: [...]}` used to be what restored the whole list.
// agent-contract.md R21: the built-in deny_read list is refused whatever the contract says.
func TestBuiltInDenyReadAppliesWithoutFSSection(t *testing.T) {
	f := newFixture(t)
	rt, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\n"))

	for _, want := range []string{
		filepath.Join(f.home, ".ssh"),
		filepath.Join(f.home, ".aws"),
		filepath.Join(f.home, ".netrc"),
		filepath.Join(f.project, ".env"),
	} {
		r := findFS(rt, FSDenyRead, want)
		if r == nil {
			t.Fatalf("no built-in deny_read entry for %s in a contract with no fs: section:\n%s", want, render(ds))
		}
		if !r.BuiltIn {
			t.Errorf("%s: BuiltIn = false, want true", want)
		}
		if r.Unenforced {
			t.Errorf("%s: Unenforced = true with no write entry to shadow it", want)
		}
	}

	// R9 still holds: the four implicit entries are there and no write entry was invented.
	implicit := 0
	for _, r := range rt.FS {
		if r.Kind == FSImplicit {
			implicit++
		}
		if r.Kind == FSWrite {
			t.Errorf("no fs: section compiled a write entry %s", r.Path)
		}
		if r.Access != 0 && r.Kind != FSWrite {
			t.Errorf("%s: %s entry grants %v", r.Path, r.Kind, r.Access)
		}
	}
	if implicit != 4 {
		t.Errorf("%d implicit entries, want the 4 of R9", implicit)
	}

	// The reads the list exists for are refused in every enforcing tier.
	key := filepath.Join(f.home, ".ssh", "id_ed25519")
	for _, tier := range enforcingTiers() {
		got := rt.Evaluate(Action{Kind: ActionFSRead, Path: key}, tier)
		if got.Verdict != VerdictRefused {
			t.Errorf("tier %s: read of %s is %q (rule %s), want refused", tier, key, got.Verdict, got.Rule)
		}
	}
}

// TestExplicitEmptyDenyReadStillDisablesTheList is the other half of the tri-state: `deny_read: []`
// remains the one way to switch the built-in list off, and it is the loud one (SEMANTICS §1).
func TestExplicitEmptyDenyReadStillDisablesTheList(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  deny_read: []\n")
	rt, _ := f.compile(c)
	if r := findFS(rt, FSDenyRead, filepath.Join(f.home, ".ssh")); r != nil {
		t.Errorf("deny_read: [] kept the built-in entry %s", r.Path)
	}
}
