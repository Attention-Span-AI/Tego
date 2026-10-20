// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestGeneratorDeterministic: the generator has no randomness and no state, so two calls build equal spaces and the
// manifest renders the same bytes twice (plan C5).
func TestGeneratorDeterministic(t *testing.T) {
	for _, sp := range Spaces() {
		if sp.Name == SpaceHandwritten {
			continue
		}
		if a, b := sp.Fixtures(), sp.Fixtures(); !reflect.DeepEqual(a, b) {
			t.Errorf("space %s: two calls differ", sp.Name)
		}
	}
	a, err := Manifest()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("the manifest differs between two renderings")
	}
}

// TestFSGridShape holds space 1 to its definition: 64 contracts, every assignment of the four kinds to the three
// depths exactly once, 39 cells each, every cell generated and owning its paths.
func TestFSGridShape(t *testing.T) {
	grid := GenFSGrid()
	if len(grid) != 64 {
		t.Fatalf("%d contracts, want 4^3 = 64", len(grid))
	}
	names := map[string]bool{}
	for i := range grid {
		fx := &grid[i]
		if names[fx.Name] {
			t.Errorf("%s twice", fx.Name)
		}
		names[fx.Name] = true
		if len(fx.Cells) != GridCellsPerFixture {
			t.Errorf("%s: %d cells, want %d", fx.Name, len(fx.Cells), GridCellsPerFixture)
		}
		owned := map[string]string{}
		for j := range fx.Cells {
			c := &fx.Cells[j]
			if !c.Generated || c.Want != nil || c.Source == "" {
				t.Errorf("%s: a generated cell has no want and a source", fx.ID(c))
			}
			for _, p := range []string{c.Path, c.Dest} {
				if p == "" || (c.Op == OpSymlink && p == c.Dest) {
					continue
				}
				if other, dup := owned[p]; dup {
					t.Errorf("%s and %s both act on %s", fx.ID(c), other, p)
				}
				owned[p] = fx.ID(c)
			}
		}
	}
}

// TestGeneratedManifest: testdata/generated.txt is the manifest of the generated spaces, so a change that adds,
// drops or alters a generated cell shows in review. -conformance.update=<a generated space> rewrites it.
func TestGeneratedManifest(t *testing.T) {
	want, err := Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if space := requestedSpace(t); space != "" && space != SpaceHandwritten {
		if err := writeFileLike(manifestPath, want); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s rewritten", manifestPath)
		return
	}
	have, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(have, want) {
		t.Errorf("%s is not the generator's manifest (first difference: %s); review the change, then run "+
			"go test ./test/conformance -run TestGeneratedManifest -%s=%s", manifestPath, firstDifference(have, want), updateFlag, SpaceFSGrid)
	}
}

// TestGeneratedContractsCompile: every generated contract loads and compiles offline, and the model the invariants
// read is the contract's own fs entries (TestGeneratedModelIsTheContract's half that needs the loader).
func TestGeneratedContractsCompile(t *testing.T) {
	for _, sp := range Spaces() {
		if sp.Name == SpaceHandwritten {
			continue
		}
		for _, fx := range sp.Fixtures() {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			subst := strings.NewReplacer("{{P}}", root).Replace
			if err := Layout(root, &fx, []byte("#!/bin/false\n"), subst); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "agent.yaml")
			data := []byte(subst(fx.Contract))
			c, ds, err := agent.LoadBytes(path, data, nil)
			if err != nil {
				t.Fatalf("%s: load: %v %v", fx.Name, err, ds)
			}
			m := config.Builtin()
			m.LedgerRoot.Value = filepath.Join(root, "ledger")
			if _, ds, err := agent.Compile(c, m, agent.WithCwd(root), agent.WithHome(filepath.Join(root, "home")), agent.WithMountInfo(""), agent.Offline()); err != nil {
				t.Fatalf("%s: compile: %v %v", fx.Name, err, ds)
			}
			// TestGeneratedModelIsTheContract: the model's entries are the contract's, read back by the loader.
			var write, deny []string
			if c.FS != nil {
				write, deny = trimEntries(c.FS.Write), trimEntries(c.FS.DenyRead)
			}
			if !reflect.DeepEqual(write, fx.Model.Write) || !reflect.DeepEqual(deny, fx.Model.DenyRead) {
				t.Errorf("%s: the contract declares write %q deny_read %q, the model %q %q", fx.Name, write, deny, fx.Model.Write, fx.Model.DenyRead)
			}
		}
	}
}

// trimEntries spells ./a/b/ entries as the model does, a/b.
func trimEntries(es []string) []string {
	var out []string
	for _, e := range es {
		out = append(out, strings.TrimSuffix(strings.TrimPrefix(e, "./"), "/"))
	}
	return out
}
