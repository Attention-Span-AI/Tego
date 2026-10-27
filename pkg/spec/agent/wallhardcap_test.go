// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"strings"
	"testing"
)

// G7: wall is a hard cap by definition, and a contract that sets it with no stall_after is told so, with
// stall_after as the way to bound an interactive session. It is a note (compile prints it, a run only under -v).
// A contract that also sets stall_after, or sets no wall, gets nothing.
func TestWallWithoutStallAfterIsNotedAsAHardCap(t *testing.T) {
	const base = "version: 0\nname: wallcap\ncommand: [\"/bin/sh\"]\ntier: landlock\n"
	for _, tc := range []struct {
		name, limits string
		want         int
	}{
		{"wall alone", "limits: {wall: 30m}\n", 1},
		{"wall and stall_after", "limits: {wall: 30m, stall_after: 10m}\n", 0},
		{"stall_after alone", "limits: {stall_after: 10m}\n", 0},
		{"no limits", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			_, ds := f.compile(f.load(base + tc.limits))
			var got []Diagnostic
			for _, d := range ds {
				if d.Code == CodeWallHardCap {
					got = append(got, d)
				}
			}
			if len(got) != tc.want {
				t.Fatalf("%d wall-hard-cap findings, want %d:\n%s", len(got), tc.want, render(ds))
			}
			for _, d := range got {
				if !d.Informational() || !strings.Contains(d.Message, "hard cap") || !strings.Contains(d.Fix, "stall_after") {
					t.Fatalf("the finding %+v: want a note saying hard cap and naming stall_after", d)
				}
			}
		})
	}
}
