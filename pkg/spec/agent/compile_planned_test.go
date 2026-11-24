// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPlannedDirectoryChecksAllProtections(t *testing.T) {
	f := newFixture(t)
	planned := filepath.Join(f.project, "new-parent", "out")
	c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [./new-parent/out/]\n")
	_, ds, _ := f.compileErr(c)
	if !strings.Contains(render(ds), CodePathMissing) {
		t.Fatal("fixture does not require creation of a parent")
	}
	rt, ds := f.compile(c, WithPlannedDirectories([]string{planned}))
	if HasErrors(ds) || rt == nil {
		t.Fatalf("planned setup directory refused: %s", render(ds))
	}
	// The exception is exact, never a prefix or an unrelated path.
	_, ds, _ = f.compileErr(c, WithPlannedDirectories([]string{filepath.Dir(planned)}))
	if !strings.Contains(render(ds), CodePathMissing) {
		t.Fatal("parent plan waived unplanned child")
	}
	// A planned directory still cannot hold a contract or its mutable lookup name.
	own := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [./new-parent/out/]\n")
	_, ds, _ = f.compileErr(own, WithPlannedDirectories([]string{planned}), WithChainAnchor(filepath.Join(planned, "chain.log")))
	if !HasErrors(ds) || !strings.Contains(render(ds), CodeContradiction) {
		t.Fatalf("planned directory bypassed protected state: %s", render(ds))
	}
}
