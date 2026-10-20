// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"testing"
)

// TestKnownRuleNaming pins the known differences between the rule a generated cell's ledger line names and the rule
// compile --test's column names (ADR 0017's 2026-10-19 note): each class is recognized where it was
// observed, and the same pair of names anywhere else, on another axis, op or verdict, or naming an entry that does
// not cover the action's names, is no known class, which the kernel runner reports as a ledger disagreement.
func TestKnownRuleNaming(t *testing.T) {
	var (
		landlock = NamingAxis{Tier: TierLandlock}
		listener = NamingAxis{Tier: TierCgroup}
		fmodRet  = NamingAxis{Tier: TierCgroup, Plane: string(ModeFmodRet)}
		lsm      = NamingAxis{Tier: TierCgroup, Plane: string(ModeLSM)}
		bpflsm   = NamingAxis{Tier: TierBPFLSM, Plane: string(ModeLSM)}
	)
	cases := []struct {
		fixture, cell   string
		ax              NamingAxis
		verdict         string
		ledger, compile string
		want            NamingClass
	}{
		// An allowed rename: the line names the write entry that grants it, compile the nearer watch or deny_read.
		{"grid-write.none.watch", "rename-across-abc", landlock, Allow, "fs.write[./a/]", "fs.watch[./a/b/c/]", NamingRenameNamesGrant},
		{"grid-write.none.deny", "rename-within-abc", landlock, Allow, "fs.write[./a/]", "fs.deny_read[./a/b/c/]", NamingRenameNamesGrant},
		{"grid-none.write.watch", "rename-within-abc", fmodRet, Allow, "fs.write[./a/b/]", "fs.watch[./a/b/c/]", NamingRenameNamesGrant},
		{"grid-write.write.watch", "rename-within-abc", bpflsm, Allow, "fs.write[./a/b/]", "fs.watch[./a/b/c/]", NamingRenameNamesGrant},
		// A refusal whose line names the nearest entry, a watch, where compile names the entry that refuses.
		{"grid-none.none.watch", "create-abc", lsm, Refused, "fs.watch[./a/b/c/]", "fs.implicit[/]", NamingRefusalNamesWatch},
		{"grid-none.deny.watch", "unlink-abc", bpflsm, Refused, "fs.watch[./a/b/c/]", "fs.deny_read[./a/b/]", NamingRefusalNamesWatch},
		{"grid-deny.none.watch", "read-abc", listener, Refused, "fs.watch[./a/b/c/]", "fs.deny_read[./a/]", NamingRefusalNamesWatch},
		// A rename refused on the lsm plane: the two name different entries among those covering its two names.
		{"grid-none.none.deny", "rename-across-ab", lsm, Refused, "fs.deny_read[./a/b/c/]", "fs.implicit[/]", NamingPlaneRename},
		{"grid-none.write.deny", "rename-across-abc", bpflsm, Refused, "unmatched", "fs.deny_read[./a/b/c/]", NamingPlaneRename},
		{"grid-watch.deny.write", "rename-across-a", lsm, Refused, "fs.deny_read[./a/b/]", "fs.watch[./a/]", NamingPlaneRename},
		// Tier landlock's reads.
		{"grid-write.deny.write", "read-abc", landlock, Allow, "fs.write[./a/b/c/]", "fs.deny_read[./a/b/] (unenforced: parent writable)", NamingReadNamesWrite},
		{"grid-deny.write.watch", "read-abc", landlock, Allow, "fs.watch[./a/b/c/]", "fs.write[./a/b/]", NamingReadNamesWatch},

		// Not a known class: the same names on another axis, op or verdict, or an entry that covers nothing.
		{"grid-none.none.watch", "create-abc", fmodRet, Refused, "fs.watch[./a/b/c/]", "fs.implicit[/]", ""},
		{"grid-none.none.watch", "create-abc", listener, Refused, "fs.watch[./a/b/c/]", "fs.implicit[/]", ""},
		{"grid-none.none.watch", "create-abc", landlock, Refused, "fs.watch[./a/b/c/]", "fs.implicit[/]", ""},
		{"grid-none.none.watch", "create-ab", lsm, Refused, "fs.watch[./a/b/c/]", "fs.implicit[/]", ""},
		{"grid-none.deny.watch", "unlink-abc", bpflsm, Refused, "fs.watch[./a/b/c/]", "fs.implicit[/]", ""},
		{"grid-write.none.watch", "rename-across-abc", landlock, Refused, "fs.write[./a/]", "fs.watch[./a/b/c/]", ""},
		{"grid-write.none.watch", "rename-across-abc", landlock, Allow, "fs.watch[./a/b/c/]", "fs.write[./a/]", ""},
		{"grid-write.none.watch", "unlink-abc", landlock, Allow, "fs.write[./a/]", "fs.watch[./a/b/c/]", ""},
		{"grid-none.none.deny", "rename-across-ab", fmodRet, Refused, "fs.deny_read[./a/b/c/]", "fs.implicit[/]", ""},
		{"grid-none.none.deny", "rename-across-ab", lsm, Refused, "fs.deny_read[./a/]", "fs.implicit[/]", ""},
		{"grid-none.none.deny", "rename-across-ab", lsm, Refused, "unmatched", "fs.implicit[/]", ""},
		{"grid-write.deny.write", "read-abc", listener, Allow, "fs.write[./a/b/c/]", "fs.deny_read[./a/b/] (unenforced: parent writable)", ""},
		{"grid-write.deny.write", "read-abc", landlock, Allow, "fs.write[./a/b/c/]", "fs.deny_read[./a/b/]", ""},
		{"grid-deny.write.watch", "read-abc", landlock, Refused, "fs.watch[./a/b/c/]", "fs.write[./a/b/]", ""},
		{"grid-deny.write.watch", "read-ab", landlock, Allow, "fs.watch[./a/b/c/]", "fs.write[./a/b/]", ""},
	}
	grid := map[string]*Fixture{}
	for _, fx := range GenFSGrid() {
		grid[fx.Name] = &fx
	}
	for _, tc := range cases {
		fx := grid[tc.fixture]
		if fx == nil {
			t.Fatalf("no grid fixture %s", tc.fixture)
		}
		var c *Cell
		for i := range fx.Cells {
			if fx.Cells[i].Name == tc.cell {
				c = &fx.Cells[i]
			}
		}
		if c == nil {
			t.Fatalf("no cell %s in %s", tc.cell, tc.fixture)
		}
		if got := KnownRuleNaming(fx, c, tc.ax, tc.verdict, tc.ledger, tc.compile); got != tc.want {
			t.Errorf("%s/%s on %+v, %s, line %q, compile %q: class %q, want %q", tc.fixture, tc.cell, tc.ax, tc.verdict, tc.ledger, tc.compile, got, tc.want)
		}
	}
	// A handwritten fixture's cell is in no class, whatever it names: only the generator's grid was classified.
	hand := Fixtures()[0]
	if got := KnownRuleNaming(&hand, &hand.Cells[0], landlock, Allow, "fs.write[./a/]", "fs.watch[./a/b/c/]"); got != "" {
		t.Errorf("a handwritten cell: class %q, want none", got)
	}
}
