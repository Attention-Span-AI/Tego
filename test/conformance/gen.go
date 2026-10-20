// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// The deterministic generator (ADR 0017's "it generates contracts", plan C5): a space is a set of fixtures built
// from a grid, in a fixed order, with no randomness, so two calls are equal and the manifest
// (testdata/generated.txt) shows every cell a change adds or drops. A generated cell carries no authored want: the
// kernel is its judge (ADR 0017 D1, A-0017-1). Its run is checked kernel == ledger == compile --test's column for
// the axis, and against the invariants and the effect judge, which read the contract's model alone.

// SpaceFSGrid is space 1: today's filesystem grid.
const SpaceFSGrid = "fsgrid"

// SpacesEnv selects the spaces the runners run: unset, the handwritten cells and every space a PR runs (PerPR);
// "all", every space (the nightly matrix); otherwise a comma-separated list of space names.
const SpacesEnv = "TEGO_CONFORMANCE_SPACES"

// SelectedSpaces is the spaces SpacesEnv selects, in Spaces' order, and whether that is every space. A name that is
// no space is an error, so a typo never runs fewer cells than it reads as.
func SelectedSpaces() ([]Space, bool, error) {
	env := strings.TrimSpace(os.Getenv(SpacesEnv))
	all := Spaces()
	var out []Space
	switch env {
	case "all":
		return all, true, nil
	case "":
		for _, sp := range all {
			if sp.Name == SpaceHandwritten || sp.PerPR {
				out = append(out, sp)
			}
		}
	default:
		want := map[string]bool{}
		for _, n := range strings.Split(env, ",") {
			want[strings.TrimSpace(n)] = true
		}
		for _, sp := range all {
			if want[sp.Name] {
				out = append(out, sp)
				delete(want, sp.Name)
			}
		}
		if len(want) > 0 {
			var bad []string
			for n := range want {
				bad = append(bad, n)
			}
			sort.Strings(bad)
			return nil, false, fmt.Errorf("%s=%s: no such space %s (spaces: %s)", SpacesEnv, env, strings.Join(bad, ", "), spaceList())
		}
	}
	return out, len(out) == len(all), nil
}

func spaceList() string {
	var names []string
	for _, sp := range Spaces() {
		names = append(names, sp.Name)
	}
	return strings.Join(names, ", ")
}

// gridKind is one entry kind the fs grid places at a depth.
type gridKind struct{ name, key string }

// gridKinds are the entry kinds of space 1, in order: no entry, a write entry, a deny_read and a watch.
var gridKinds = []gridKind{{"none", ""}, {"write", "write"}, {"deny", "deny_read"}, {"watch", "watch"}}

// gridDepths are the three nested directories an entry may name.
var gridDepths = []string{"a", "a/b", "a/b/c"}

// gridOps are the 13 actions every depth takes, each on a path of its own (plan C5).
var gridOps = []string{OpRead, OpWriteOpen, OpCreate, OpOpenTrunc, OpTruncate, OpUnlink, OpMkdir, OpRmdir, "rename-within",
	"rename-across", OpLink, OpSymlink, OpChmod}

// GridCellsPerFixture is the number of cells each grid contract carries: 13 actions at each of 3 depths.
const GridCellsPerFixture = 13 * 3

// GenFSGrid is space 1: every assignment of an entry kind to each of the depths a, a/b and a/b/c (4^3 = 64
// contracts, in lexicographic order of the kinds), each fixture's 39 cells performing the 13 actions at every depth.
// The contract and the model are rendered from the same assignment, never from compile output.
func GenFSGrid() []Fixture {
	var out []Fixture
	for _, k0 := range gridKinds {
		for _, k1 := range gridKinds {
			for _, k2 := range gridKinds {
				out = append(out, gridFixture([3]gridKind{k0, k1, k2}))
			}
		}
	}
	return out
}

func gridFixture(kinds [3]gridKind) Fixture {
	entries := map[string][]string{}
	var model Model
	for i, k := range kinds {
		switch k.key {
		case "":
			continue
		case "write":
			model.Write = append(model.Write, gridDepths[i])
		case "deny_read":
			model.DenyRead = append(model.DenyRead, gridDepths[i])
		}
		entries[k.key] = append(entries[k.key], fmt.Sprintf("%q", "./"+gridDepths[i]+"/"))
	}
	model.ExecAllow, model.NetDeclared = []string{"bin/actor"}, true
	var b strings.Builder
	b.WriteString("version: 0\nname: conformance-fsgrid\ncommand: [\"{{P}}/bin/actor\", \"run\", \"{{P}}/script.json\"]\n")
	if len(entries) > 0 {
		b.WriteString("fs:\n")
		for _, key := range []string{"write", "deny_read", "watch"} {
			if len(entries[key]) > 0 {
				fmt.Fprintf(&b, "  %s: [%s]\n", key, strings.Join(entries[key], ", "))
			}
		}
	}
	b.WriteString("exec:\n  allow: [\"{{P}}/bin/actor\"]\nnet:\n  allow: []\n")
	b.WriteString(footer)
	fx := Fixture{
		Name:     "grid-" + kinds[0].name + "." + kinds[1].name + "." + kinds[2].name,
		Contract: b.String(),
		Files:    map[string]string{},
		Model:    model,
	}
	for i, d := range gridDepths {
		tag := strings.ReplaceAll(d, "/", "")
		next := gridDepths[(i+1)%len(gridDepths)]
		fx.Dirs = append(fx.Dirs, d+"/rmdir-old")
		for _, op := range gridOps {
			c := Cell{Name: op + "-" + tag, Op: op, Generated: true, Source: "ADR 0017 space 1 (the fs grid; the kernel judges)"}
			switch op {
			case OpRead, OpWriteOpen, OpOpenTrunc, OpTruncate, OpUnlink, OpChmod:
				c.Path = d + "/" + op + ".txt"
				fx.Files[c.Path] = "x"
			case OpCreate:
				c.Path = d + "/create.txt"
			case OpMkdir:
				c.Path = d + "/mkdir-new"
			case OpRmdir:
				c.Path = d + "/rmdir-old"
			case "rename-within":
				c.Op, c.Path, c.Dest = OpRename, d+"/rwithin.txt", d+"/rwithin-moved.txt"
				fx.Files[c.Path] = "x"
			case "rename-across":
				// To the next depth, and from the deepest back to a: out of and into every nesting.
				c.Op, c.Path, c.Dest = OpRename, d+"/racross.txt", next+"/racross-from-"+tag+".txt"
				fx.Files[c.Path] = "x"
			case OpLink:
				c.Path, c.Dest = d+"/link-src.txt", d+"/link-new.txt"
				fx.Files[c.Path] = "x"
			case OpSymlink:
				c.Path, c.Dest = d+"/symlink-new", "read.txt"
			}
			fx.Cells = append(fx.Cells, c)
		}
	}
	return fx
}

// manifestPath is the generated cells' manifest: per space a line with its sha256 and counts, then its cell IDs.
const manifestPath = "testdata/generated.txt"

// Manifest renders the manifest of the generated spaces: for each, "space <name> sha256 <hex> fixtures <n> cells
// <n>", the sha256 over the fixtures' JSON (contract, tree, model and cells, maps in key order), then one cell ID
// a line, so a review sees every cell a change adds, drops or alters.
func Manifest() ([]byte, error) {
	var b strings.Builder
	b.WriteString("# The generated conformance cells (ADR 0017 plan C5). TestGeneratedManifest fails on any drift;\n")
	b.WriteString("# go test ./test/conformance -run TestGeneratedManifest -conformance.update=<space> rewrites it.\n")
	for _, sp := range Spaces() {
		if sp.Name == SpaceHandwritten {
			continue
		}
		fxs := sp.Fixtures()
		data, err := json.Marshal(fxs)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		n := 0
		for i := range fxs {
			n += len(fxs[i].Cells)
		}
		fmt.Fprintf(&b, "space %s sha256 %s fixtures %d cells %d\n", sp.Name, hex.EncodeToString(sum[:]), len(fxs), n)
		for i := range fxs {
			for j := range fxs[i].Cells {
				fmt.Fprintf(&b, "%s\n", fxs[i].ID(&fxs[i].Cells[j]))
			}
		}
	}
	return []byte(b.String()), nil
}
