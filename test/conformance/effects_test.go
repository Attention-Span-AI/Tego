// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// The effect judge over synthetic trees (ADR 0017 (c)): every op it judges, refused and allowed, an empty and a
// non-empty leftover of a refused create, each a fail-open on every axis, a spelling through a symlink, and a later
// rename of a directory that moves the names an earlier cell acted on.

func file(content string) Node {
	return Node{Mode: 0o644, Size: int64(len(content)), Sum: content} // Sum stands in for the digest here
}

var dirNode = Node{Mode: fs.ModeDir | 0o755}

func link(target string) Node { return Node{Mode: fs.ModeSymlink | 0o777, Link: target} }

// effectsBefore is the tree every case starts from.
func effectsBefore() Tree {
	return Tree{
		"out": dirNode, "out/f": file("x"), "out/t": file("xyz"), "out/c": file("x"), "out/rd": dirNode,
		"out/src": file("x"), "out/keys": dirNode, "out/keys/k": file("s"), "wl": link("out"),
	}
}

func TestJudgeEffects(t *testing.T) {
	refused, ok := Outcome{Errno: 13}, Outcome{OK: true}
	cases := []struct {
		name  string
		c     Cell
		o     Outcome
		after func(Tree) // the run's changes to the before tree
		want  EffectClass
	}{
		{"refused create left nothing", Cell{Op: OpCreate, Path: "out/n"}, refused, nil, EffectHeld},
		// Not a residue, on the listener's axis either: there the supervisor refuses an O_CREAT open before the kernel
		// acts (fallbackMutation), so an empty file a refused create left is that refusal missing.
		{"refused create left an empty file", Cell{Op: OpCreate, Path: "out/n"}, refused, func(t Tree) { t["out/n"] = file("") }, EffectFailOpen},
		{"refused create left a non-empty file", Cell{Op: OpCreate, Path: "out/n"}, refused, func(t Tree) { t["out/n"] = file("data") }, EffectFailOpen},
		{"allowed create", Cell{Op: OpCreate, Path: "out/n"}, ok, func(t Tree) { t["out/n"] = file("") }, EffectHeld},
		{"allowed create left nothing", Cell{Op: OpCreate, Path: "out/n"}, ok, nil, EffectMissing},
		{"refused mkdir", Cell{Op: OpMkdir, Path: "out/d"}, refused, nil, EffectHeld},
		{"refused mkdir left a directory", Cell{Op: OpMkdir, Path: "out/d"}, refused, func(t Tree) { t["out/d"] = dirNode }, EffectFailOpen},
		{"allowed mkdir", Cell{Op: OpMkdir, Path: "out/d"}, ok, func(t Tree) { t["out/d"] = dirNode }, EffectHeld},
		{"refused symlink left a link", Cell{Op: OpSymlink, Path: "out/l", Dest: "../x"}, refused, func(t Tree) { t["out/l"] = link("../x") }, EffectFailOpen},
		{"allowed symlink", Cell{Op: OpSymlink, Path: "out/l", Dest: "../x"}, ok, func(t Tree) { t["out/l"] = link("../x") }, EffectHeld},
		{"allowed symlink to another target", Cell{Op: OpSymlink, Path: "out/l", Dest: "../x"}, ok, func(t Tree) { t["out/l"] = link("y") }, EffectMissing},
		{"refused link", Cell{Op: OpLink, Path: "out/f", Dest: "out/h"}, refused, nil, EffectHeld},
		{"refused link left the new name", Cell{Op: OpLink, Path: "out/f", Dest: "out/h"}, refused, func(t Tree) { t["out/h"] = file("x") }, EffectFailOpen},
		{"allowed link", Cell{Op: OpLink, Path: "out/f", Dest: "out/h"}, ok, func(t Tree) { t["out/h"] = file("x") }, EffectHeld},
		{"refused unlink", Cell{Op: OpUnlink, Path: "out/f"}, refused, nil, EffectHeld},
		{"refused unlink removed the name", Cell{Op: OpUnlink, Path: "out/f"}, refused, func(t Tree) { delete(t, "out/f") }, EffectFailOpen},
		{"allowed unlink", Cell{Op: OpUnlink, Path: "out/f"}, ok, func(t Tree) { delete(t, "out/f") }, EffectHeld},
		{"allowed unlink left the name", Cell{Op: OpUnlink, Path: "out/f"}, ok, nil, EffectMissing},
		{"refused rmdir removed the directory", Cell{Op: OpRmdir, Path: "out/rd"}, refused, func(t Tree) { delete(t, "out/rd") }, EffectFailOpen},
		{"allowed rmdir", Cell{Op: OpRmdir, Path: "out/rd"}, ok, func(t Tree) { delete(t, "out/rd") }, EffectHeld},
		{"refused rename", Cell{Op: OpRename, Path: "out/src", Dest: "out/dst"}, refused, nil, EffectHeld},
		{"refused rename moved the file", Cell{Op: OpRename, Path: "out/src", Dest: "out/dst"}, refused,
			func(t Tree) { t["out/dst"] = t["out/src"]; delete(t, "out/src") }, EffectFailOpen},
		{"refused rename made the destination", Cell{Op: OpRename, Path: "out/src", Dest: "out/dst"}, refused,
			func(t Tree) { t["out/dst"] = file("x") }, EffectFailOpen},
		{"allowed rename", Cell{Op: OpRename, Path: "out/src", Dest: "out/dst"}, ok,
			func(t Tree) { t["out/dst"] = t["out/src"]; delete(t, "out/src") }, EffectHeld},
		{"allowed rename left the source", Cell{Op: OpRename, Path: "out/src", Dest: "out/dst"}, ok,
			func(t Tree) { t["out/dst"] = t["out/src"] }, EffectMissing},
		{"refused creat left nothing", Cell{Op: OpCreat, Path: "out/n"}, refused, nil, EffectHeld},
		{"refused creat left an empty file", Cell{Op: OpCreat, Path: "out/n"}, refused, func(t Tree) { t["out/n"] = file("") }, EffectFailOpen},
		{"allowed creat", Cell{Op: OpCreat, Path: "out/n"}, ok, func(t Tree) { t["out/n"] = file("") }, EffectHeld},
		{"allowed creat left nothing", Cell{Op: OpCreat, Path: "out/n"}, ok, nil, EffectMissing},
		{"refused exchange", Cell{Op: OpExchange, Path: "out/src", Dest: "out/keys/k"}, refused, nil, EffectHeld},
		{"refused exchange swapped the names", Cell{Op: OpExchange, Path: "out/src", Dest: "out/keys/k"}, refused,
			func(t Tree) { t["out/src"], t["out/keys/k"] = t["out/keys/k"], t["out/src"] }, EffectFailOpen},
		{"refused exchange removed the destination", Cell{Op: OpExchange, Path: "out/src", Dest: "out/keys/k"}, refused,
			func(t Tree) { delete(t, "out/keys/k") }, EffectFailOpen},
		{"allowed exchange", Cell{Op: OpExchange, Path: "out/src", Dest: "out/keys/k"}, ok,
			func(t Tree) { t["out/src"], t["out/keys/k"] = t["out/keys/k"], t["out/src"] }, EffectHeld},
		{"allowed exchange left the names", Cell{Op: OpExchange, Path: "out/src", Dest: "out/keys/k"}, ok, nil, EffectMissing},
		{"refused truncate", Cell{Op: OpTruncate, Path: "out/t"}, refused, nil, EffectHeld},
		{"refused truncate emptied the file", Cell{Op: OpTruncate, Path: "out/t"}, refused, func(t Tree) { t["out/t"] = file("") }, EffectFailOpen},
		{"allowed truncate", Cell{Op: OpTruncate, Path: "out/t"}, ok, func(t Tree) { t["out/t"] = file("") }, EffectHeld},
		{"allowed truncate left the content", Cell{Op: OpTruncate, Path: "out/t"}, ok, nil, EffectMissing},
		{"refused chmod changed the mode", Cell{Op: OpChmod, Path: "out/c"}, refused,
			func(t Tree) { n := t["out/c"]; n.Mode = 0o600; t["out/c"] = n }, EffectFailOpen},
		{"allowed chmod", Cell{Op: OpChmod, Path: "out/c"}, ok, func(t Tree) { n := t["out/c"]; n.Mode = 0o600; t["out/c"] = n }, EffectHeld},
		{"refused unlink spelled through a symlink", Cell{Op: OpUnlink, Path: "wl/f"}, refused, func(t Tree) { delete(t, "out/f") }, EffectFailOpen},
		{"allowed truncate spelled through a symlink", Cell{Op: OpTruncate, Path: "wl/t"}, ok, func(t Tree) { t["out/t"] = file("") }, EffectHeld},
		{"a read has no effect to judge", Cell{Op: OpRead, Path: "out/f"}, ok, nil, EffectNone},
		{"a write-open writes nothing", Cell{Op: OpWriteOpen, Path: "out/f"}, refused, nil, EffectNone},
		{"an action that failed otherwise is not judged", Cell{Op: OpCreate, Path: "out/n"}, Outcome{Errno: 2},
			func(t Tree) { t["out/n"] = file("data") }, EffectNone},
	}
	for _, tc := range cases {
		before := effectsBefore()
		after := maps.Clone(before)
		if tc.after != nil {
			tc.after(after)
		}
		tc.c.Name = "cell"
		fx := Fixture{Name: "fx", Cells: []Cell{tc.c}}
		got := JudgeEffects(&fx, before, after, map[string]Outcome{"fx/cell": tc.o})["fx/cell"]
		if got.Class != tc.want {
			t.Errorf("%s: %q (%s), want %q", tc.name, got.Class, got.Detail, tc.want)
		}
	}
}

// TestJudgeEffectsFollowsALaterRename: the fs fixture renames a deny_read directory last, so where the kernel allowed
// that rename, the names the earlier cells acted on beneath it are in the after tree under its new name.
func TestJudgeEffectsFollowsALaterRename(t *testing.T) {
	fx := Fixture{Name: "fx", Cells: []Cell{
		{Name: "unlink", Op: OpUnlink, Path: "out/keys/k"},
		{Name: "mkdir", Op: OpMkdir, Path: "out/keys/sub"},
		{Name: "move", Op: OpRename, Path: "out/keys", Dest: "out/keys.old"},
	}}
	before := effectsBefore()
	after := maps.Clone(before)
	delete(after, "out/keys/k")
	delete(after, "out/keys")
	after["out/keys.old"] = dirNode
	after["out/keys.old/sub"] = dirNode
	ok := Outcome{OK: true}
	got := JudgeEffects(&fx, before, after, map[string]Outcome{"fx/unlink": ok, "fx/mkdir": ok, "fx/move": ok})
	for id, e := range got {
		if e.Class != EffectHeld {
			t.Errorf("%s: %q (%s), want held", id, e.Class, e.Detail)
		}
	}
	// The same run with the rename refused: nothing moves, and a name found under the new name is no effect.
	after = maps.Clone(before)
	delete(after, "out/keys/k")
	after["out/keys/sub"] = dirNode
	got = JudgeEffects(&fx, before, after, map[string]Outcome{"fx/unlink": ok, "fx/mkdir": ok, "fx/move": {Errno: 1}})
	for id, e := range got {
		if e.Class != EffectHeld {
			t.Errorf("rename refused, %s: %q (%s), want held", id, e.Class, e.Detail)
		}
	}
}

// TestJudgeEffectsSourceRefilledByALaterRename: refer's S1 cells move the exec.allow directory away and then rename a
// fresh directory onto its name, so the first rename's source exists again in the after tree. That is the later
// cell's effect, judged on it, not a missing effect of the first; a source still there with no later rename onto it
// still is one.
func TestJudgeEffectsSourceRefilledByALaterRename(t *testing.T) {
	fx := Fixture{Name: "fx", Cells: []Cell{
		{Name: "away", Op: OpRename, Path: "out/xbin", Dest: "out/xbin-old"},
		{Name: "back", Op: OpRename, Path: "out/xnew", Dest: "out/xbin"},
	}}
	before := Tree{"out": dirNode, "out/xbin": dirNode, "out/xnew": dirNode}
	after := Tree{"out": dirNode, "out/xbin-old": dirNode, "out/xbin": dirNode}
	ok := Outcome{OK: true}
	for id, e := range JudgeEffects(&fx, before, after, map[string]Outcome{"fx/away": ok, "fx/back": ok}) {
		if e.Class != EffectHeld {
			t.Errorf("%s: %q (%s), want held", id, e.Class, e.Detail)
		}
	}
	// Without the later rename the source still being there is a missing effect.
	got := JudgeEffects(&fx, before, after, map[string]Outcome{"fx/away": ok, "fx/back": {Errno: 1}})
	if e := got["fx/away"]; e.Class != EffectMissing {
		t.Errorf("the source left in place with no later rename onto it: %q (%s), want missing", e.Class, e.Detail)
	}
}

// TestJudgeEffectsResolvesInTheTreeEarlierCellsLeft: refer's replaced-link cells move an exec.allow directory's declared
// link out of its directory, rename a directory holding a real bl onto the emptied one, and then move a file into
// out/el/bl. The kernel's walk finds the real directory there, so the move's effect is under it; resolved in the
// starting tree, the destination followed the stale link to out/rb and the effect read missing.
func TestJudgeEffectsResolvesInTheTreeEarlierCellsLeft(t *testing.T) {
	fx := Fixture{Name: "fx", Cells: []Cell{
		{Name: "away", Op: OpRename, Path: "out/el/bl", Dest: "out/bl-old"},
		{Name: "onto", Op: OpRename, Path: "out/eln", Dest: "out/el"},
		{Name: "into", Op: OpRename, Path: "out/n", Dest: "out/el/bl/n"},
	}}
	before := Tree{"out": dirNode, "out/rb": dirNode, "out/el": dirNode, "out/el/bl": link("../rb"), "out/eln": dirNode,
		"out/eln/bl": dirNode, "out/n": file("x")}
	after := Tree{"out": dirNode, "out/rb": dirNode, "out/bl-old": link("../rb"), "out/el": dirNode, "out/el/bl": dirNode,
		"out/el/bl/n": file("x")}
	ok := Outcome{OK: true}
	for id, e := range JudgeEffects(&fx, before, after, map[string]Outcome{"fx/away": ok, "fx/onto": ok, "fx/into": ok}) {
		if e.Class != EffectHeld {
			t.Errorf("%s: %q (%s), want held", id, e.Class, e.Detail)
		}
	}
	// With the first rename refused, the link stands, and the move lands in out/rb.
	after = Tree{"out": dirNode, "out/rb": dirNode, "out/rb/n": file("x"), "out/el/bl": link("../rb"), "out/eln": dirNode,
		"out/eln/bl": dirNode}
	got := JudgeEffects(&fx, before, after, map[string]Outcome{"fx/away": {Errno: 1}, "fx/onto": {Errno: 1}, "fx/into": ok})
	if e := got["fx/into"]; e.Class != EffectHeld {
		t.Errorf("the move through the standing link: %q (%s), want held", e.Class, e.Detail)
	}
}

// TestJudgeEffectsNameEndWithSlashIsTheName: an rmdir, an unlink, a rename's ends and a link's new name spelled with
// a trailing slash act on the name in its directory, never where a final symlink leads (filename_parentat strips the
// slash), while a link's old name is looked up whole and follows it. The judge took the slash as one more component
// and followed rl to out/rdl, so the link removed under a refusal read held, and the directory it leads to, which a
// refused rmdir never touches, was the one checked.
func TestJudgeEffectsNameEndWithSlashIsTheName(t *testing.T) {
	refused := Outcome{Errno: 13}
	before := Tree{"out": dirNode, "out/rdl": dirNode, "rl": link("out/rdl"), "out/f": file("x")}
	for _, tc := range []struct {
		name  string
		cell  Cell
		after Tree
		want  EffectClass
	}{
		{"the link removed under a refused rmdir", Cell{Name: "c", Op: OpRmdir, Path: "rl/"},
			Tree{"out": dirNode, "out/rdl": dirNode, "out/f": file("x")}, EffectFailOpen},
		{"control, the link standing", Cell{Name: "c", Op: OpRmdir, Path: "rl/"}, before, EffectHeld},
		{"the link removed under a refused unlink", Cell{Name: "c", Op: OpUnlink, Path: "rl//"},
			Tree{"out": dirNode, "out/rdl": dirNode, "out/f": file("x")}, EffectFailOpen},
		{"the link replaced under a refused rename onto it", Cell{Name: "c", Op: OpRename, Path: "out/f", Dest: "rl/"},
			Tree{"out": dirNode, "out/rdl": dirNode, "rl": file("x")}, EffectFailOpen},
		// A link's old name spelled with a slash is where its link leads: a new name made under a refusal is caught either way.
		{"control, a refused link of the slash-spelled old name", Cell{Name: "c", Op: OpLink, Path: "rl/", Dest: "out/n"},
			Tree{"out": dirNode, "out/rdl": dirNode, "rl": link("out/rdl"), "out/f": file("x"), "out/n": dirNode}, EffectFailOpen},
	} {
		fx := Fixture{Name: "fx", Cells: []Cell{tc.cell}}
		if e := JudgeEffects(&fx, before, tc.after, map[string]Outcome{"fx/c": refused})["fx/c"]; e.Class != tc.want {
			t.Errorf("%s: %q (%s), want %q", tc.name, e.Class, e.Detail, tc.want)
		}
	}
	if p, ok := before.resolve("rl/", false); !ok || p != "rl" {
		t.Errorf("a name-making end rl/ resolves to %q, %v; want rl itself", p, ok)
	}
	if p, ok := before.resolve("rl/", true); !ok || p != "out/rdl" {
		t.Errorf("a whole lookup of rl/ resolves to %q, %v; want out/rdl, where the slash follows the link", p, ok)
	}
}

// TestSnapshot reads a real tree: a small file's digest, a symlink's target as written, directories, and a file
// above the hashing bound compared by size alone.
func TestSnapshot(t *testing.T) {
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "a/b"), 0o755))
	must(os.WriteFile(filepath.Join(root, "a/f"), []byte("x"), 0o600))
	must(os.WriteFile(filepath.Join(root, "big"), make([]byte, snapshotHashMax+1), 0o644))
	must(os.Symlink("../f", filepath.Join(root, "a/b/l")))
	tr, err := Snapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(tr) != 5 {
		t.Errorf("%d names, want 5: %v", len(tr), tr)
	}
	if n := tr["a/f"]; !n.Mode.IsRegular() || n.Mode.Perm() != 0o600 || n.Size != 1 || n.Sum == "" {
		t.Errorf("a/f: %+v", n)
	}
	if n := tr["big"]; n.Sum != "" || n.Size != snapshotHashMax+1 {
		t.Errorf("big: %+v, want no digest above the bound", n)
	}
	if n := tr["a/b/l"]; n.Link != "../f" {
		t.Errorf("a/b/l: %+v", n)
	}
	if p, ok := tr.resolve("a/b/l", true); !ok || p != "a/f" {
		t.Errorf("resolve(a/b/l) = %q, %v; want a/f", p, ok)
	}
	if p, ok := tr.resolve("a/b/l", false); !ok || p != "a/b/l" {
		t.Errorf("resolve(a/b/l, no follow) = %q, %v; want a/b/l", p, ok)
	}
	if _, ok := tr.resolve("../x", false); ok {
		t.Error("a path above the root resolved")
	}
	// ".." is physical, as the kernel's walk takes it: a/b/l/.. follows the link to a/f's directory first, and a link's
	// body is walked as written. Cleaned first, a/b/l/../g named a/b/g, and a cell whose new name has ".." after a
	// symlink was judged where the kernel never put it.
	must(os.MkdirAll(filepath.Join(root, "a/d"), 0o755))
	must(os.Symlink("../d", filepath.Join(root, "a/b/ld")))
	must(os.Symlink("ld/../b/l", filepath.Join(root, "a/b/lb")))
	tr, err = Snapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		p, want string
		follow  bool
	}{
		{"a/b/ld/../g", "a/g", false},
		{"a/b/ld/../f", "a/f", true},
		{"a/b/lb", "a/f", true},
		{"a/./b/../f", "a/f", true},
	} {
		if p, ok := tr.resolve(c.p, c.follow); !ok || p != c.want {
			t.Errorf("resolve(%q, %v) = %q, %v; want %q", c.p, c.follow, p, ok, c.want)
		}
	}
	if _, ok := tr.resolve("a/b/ld/../../..", false); ok {
		t.Error("a path above the root through a link resolved")
	}
}

// TestFallbackCreateCellsWantTheSupervisorsErrno holds the two cells that make a file under a deny_read nested in a
// write entry, the fs fixture's creat and fsplan's O_CREAT|O_EXCL create, to the mechanism ADR 0021 (5) names: on the
// listener the supervisor refuses each before the kernel acts, and a plane's hook refuses it in the kernel, each with
// EACCES; the listener's own FAN_DENY answers EPERM after the create, so a refusal with that errno is the fallback
// missing, not met.
func TestFallbackCreateCellsWantTheSupervisorsErrno(t *testing.T) {
	want := map[string]bool{"fs/creat-in-deny-read-nested-in-write": true, "fsplan/nested-denied-create": true}
	for _, fx := range Fixtures() {
		for i := range fx.Cells {
			c := &fx.Cells[i]
			if !want[fx.ID(c)] {
				continue
			}
			delete(want, fx.ID(c))
			for _, k := range []Key{{TierCgroup, ModeFanotify}, {TierBPFLSM, ModeLSM}} {
				if w := c.Want[k]; w.Verdict != Refused || w.Errno != int(unix.EACCES) {
					t.Errorf("%s at %v wants %+v, want a refusal with errno %d", fx.ID(c), k, w, unix.EACCES)
				}
			}
		}
	}
	for id := range want {
		t.Errorf("no fixture has the cell %s", id)
	}
}
