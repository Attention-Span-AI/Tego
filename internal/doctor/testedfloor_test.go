// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestTestedFloorMatchesDocs holds the two documents that state the tested floor to the one D1 prints
// (TestedFloor): docs/ARCHITECTURE.md §14's "Tested floor" and every tier cell of
// spec/backend/CAPABILITIES.md's minimum-kernel row, which names it as the upstream tested floor and calls
// no older kernel a floor. RHEL 9's 5.14 was called a second "tested floor" there while doctor reported
// it "below the tested floor 6.1.0" on that machine (CAPABILITIES' 2026-10-16 amendment).
func TestTestedFloorMatchesDocs(t *testing.T) {
	floor := fmt.Sprintf("%d.%d", TestedFloor.Major, TestedFloor.Minor)

	arch, err := os.ReadFile(filepath.Join("..", "..", "docs", "ARCHITECTURE.md"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`\*\*Tested floor: ([0-9.]+)\*\*`).FindAllSubmatch(arch, -1)
	if len(m) != 1 {
		t.Fatalf("ARCHITECTURE.md states the tested floor %d times, want once", len(m))
	}
	if got := string(m[0][1]); got != floor {
		t.Errorf("ARCHITECTURE.md's tested floor %s, TestedFloor %s", got, floor)
	}

	caps, err := os.ReadFile(filepath.Join("..", "..", "spec", "backend", "CAPABILITIES.md"))
	if err != nil {
		t.Fatal(err)
	}
	var row string
	for line := range strings.SplitSeq(string(caps), "\n") {
		if strings.HasPrefix(line, "| minimum kernel |") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatal("CAPABILITIES.md has no minimum kernel row")
	}
	cells := strings.Split(strings.Trim(row, "|"), "|")
	if len(cells) != 4 {
		t.Fatalf("minimum kernel row has %d cells, want 4", len(cells))
	}
	// The amendment says D1's floor clause is advice and D1 fails, withholding every tier, only below MinKernel;
	// the figure it names must be the one probeKernelVersion compares against.
	minKernel := fmt.Sprintf("`MinKernel` %d.%d", MinKernel.Major, MinKernel.Minor)
	if !strings.Contains(string(caps), "D1 stays ok at or above "+minKernel) {
		t.Errorf("CAPABILITIES.md does not say D1 stays ok at or above %s", minKernel)
	}

	want := "upstream tested floor " + floor
	for _, cell := range cells[1:] {
		cell = strings.TrimSpace(cell)
		if !strings.Contains(cell, want) {
			t.Errorf("minimum kernel cell %q does not name %q", cell, want)
		}
		if strings.Contains(cell, "tested floors") {
			t.Errorf("minimum kernel cell %q names more than one tested floor", cell)
		}
	}
}
