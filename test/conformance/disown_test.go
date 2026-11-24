// SPDX-License-Identifier: Apache-2.0

package conformance

import "testing"

// TestSiblingCellsDoNotShareALine is the by-the-other-name cell of mounts-bindwrite counting two lines for one action
// (the Ubuntu 25.10 guest, every tier): its canonical path is the own-name cell's own path, so the own-name cell's one
// refusal was matched by both cells. Each action has one line; a real second line still shows where it belongs.
func TestSiblingCellsDoNotShareALine(t *testing.T) {
	var fx *Fixture
	for _, f := range Fixtures() {
		if f.Name == "mounts-bindwrite" {
			f := f
			fx = &f
		}
	}
	if fx == nil {
		t.Fatal("no fixture mounts-bindwrite")
	}
	cell := func(name string) *Cell {
		for i := range fx.Cells {
			if fx.Cells[i].Name == name {
				return &fx.Cells[i]
			}
		}
		t.Fatalf("no cell %s", name)
		return nil
	}
	e := &env{project: "/p"}
	line := func(path string) map[string]any {
		return map[string]any{"kind": "fs", "path": path, "verdict": "refused", "rule": "fs.deny_write[./w/locked]", "source": "seccomp"}
	}
	other, own := cell("write-target-through-the-other-name"), cell("write-target-by-its-own-name")
	events := []map[string]any{line("/p/walias/locked"), line("/p/w/locked")}
	for _, c := range []*Cell{other, own} {
		if got := len(fsLines(e, fx, c, events)); got != 1 {
			t.Errorf("%s: %d lines, want its own one", c.Name, got)
		}
	}
	// A second line for either action is still seen.
	twice := []map[string]any{line("/p/walias/locked"), line("/p/walias/locked"), line("/p/w/locked")}
	if got := len(fsLines(e, fx, other, twice)); got != 2 {
		t.Errorf("a doubled line of the other-name action: %d lines, want 2", got)
	}
	once := []map[string]any{line("/p/walias/locked"), line("/p/w/locked"), line("/p/w/locked")}
	if got := len(fsLines(e, fx, own, once)); got != 2 {
		t.Errorf("a doubled line of the own-name action: %d lines, want 2", got)
	}
}

// fsLines is ledgerLines' fs case.
func fsLines(e *env, fx *Fixture, c *Cell, events []map[string]any) []map[string]any {
	return pathLines(e, fx, c, "fs", "path", e.path(c.canon()), e.path(c.Path), events)
}
