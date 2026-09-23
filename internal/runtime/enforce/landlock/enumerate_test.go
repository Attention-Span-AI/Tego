// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// denyTable is a table with one deny_read target and the given write entries.
func denyTable(targets []string, writes ...string) *agent.RuleTable {
	rt := &agent.RuleTable{Contract: contractWith(true, true)}
	for _, w := range writes {
		rt.FS = append(rt.FS, fsRule(agent.FSWrite, w))
	}
	for _, t := range targets {
		rt.FS = append(rt.FS, fsRule(agent.FSDenyRead, t))
	}
	return rt
}

// assertAncestorOnly checks the part of R3 that does not depend on a directory's live contents: the
// ancestor holds READ_DIR only and the on-path child is not held as a sibling. It is used for levels above
// the test's own temp tree (/tmp, /), whose listings change while other packages' tests run in parallel;
// the ruleset is a snapshot taken at build time, so re-reading those directories here would race.
func assertAncestorOnly(t *testing.T, h *Handle, dir string, onPath []string) {
	t.Helper()
	anc, ok := h.entry(dir)
	if !ok || anc.Kind != kindDenyAncestor || anc.Access != accessReadDir {
		t.Errorf("ancestor %s = %+v, %v; want READ_DIR only", dir, anc, ok)
	}
	for _, n := range onPath {
		if got, held := h.entry(filepath.Join(dir, n)); held && got.Kind == kindDenySibling {
			t.Errorf("on-path %s granted as a sibling", filepath.Join(dir, n))
		}
	}
}

// assertLevel checks R3 at one level: the ancestor holds READ_DIR only, every listed sibling holds
// the read set (directories) or READ_FILE (files), and no on-path name is a sibling.
func assertLevel(t *testing.T, h *Handle, dir string, onPath []string) {
	t.Helper()
	anc, ok := h.entry(dir)
	if !ok || anc.Kind != kindDenyAncestor || anc.Access != accessReadDir {
		t.Errorf("ancestor %s = %+v, %v; want READ_DIR only", dir, anc, ok)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		got, held := h.entry(p)
		isOnPath := false
		for _, n := range onPath {
			isOnPath = isOnPath || n == e.Name()
		}
		switch {
		case isOnPath:
			if held && got.Kind == kindDenySibling {
				t.Errorf("on-path %s granted as a sibling", p)
			}
		case e.Type()&os.ModeSymlink != 0:
			if held {
				t.Errorf("symlink sibling %s was held", p)
			}
		case e.IsDir():
			// E8: a sibling that is itself a write or implicit entry unions the read set onto its own
			// rights; only a genuine deny node may lack it.
			if !held || got.Access&readSet != readSet || got.Kind == kindDenyTarget || got.Kind == kindDenyAncestor {
				t.Errorf("sibling dir %s = %+v, %v", p, got, held)
			}
		default:
			if !held || got.Access&accessReadFile == 0 || got.Access&accessReadDir != 0 || got.Kind == kindDenyTarget {
				t.Errorf("sibling file %s = %+v, %v", p, got, held)
			}
		}
	}
}

func TestEnumerateDepth1(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "secret/key", "pub/note", "readme")
	h, _ := prepare(t, 7, denyTable([]string{filepath.Join(root, "secret")}))
	target, ok := h.entry(filepath.Join(root, "secret"))
	if !ok || target.Kind != kindDenyTarget || target.Access != 0 {
		t.Errorf("target = %+v, %v", target, ok)
	}
	if _, held := h.entry(filepath.Join(root, "secret", "key")); held {
		t.Error("contents of the target were held")
	}
	assertLevel(t, h, root, []string{"secret"})
	// The walk reaches "/": it is an ancestor with READ_DIR, never the read root grant.
	slash, _ := h.entry("/")
	if slash.Kind != kindDenyAncestor || slash.Access != accessReadDir {
		t.Errorf("/ = %+v", slash)
	}
	if h.Capabilities().Has(backend.CapReadDeny) != true {
		t.Error("deny_read reported unenforced")
	}
}

func TestEnumerateDepth10(t *testing.T) {
	root := tempDir(t)
	deep := "d0/d1/d2/d3/d4/d5/d6/d7/d8/d9"
	mkTree(t, root, deep+"/secret", deep+"/sib", "d0/d1/other/x")
	h, _ := prepare(t, 7, denyTable([]string{filepath.Join(root, deep, "secret")}))
	cur := filepath.Join(root, deep)
	name := "secret"
	// Inside the test's own tree the listing is stable, so every sibling is checked.
	for cur != root {
		assertLevel(t, h, cur, []string{name})
		name = filepath.Base(cur)
		cur = filepath.Dir(cur)
	}
	// From the temp root upward (/tmp, /) only the ancestor property is checked: those directories change
	// while other packages' tests run, and the ruleset holds the snapshot taken at build time.
	for cur != "/" {
		assertAncestorOnly(t, h, cur, []string{name})
		name = filepath.Base(cur)
		cur = filepath.Dir(cur)
	}
	assertAncestorOnly(t, h, "/", []string{name})
}

// TestEnumerateSiblingCounts asserts docs/p0/enforce-landlock.md E6.
func TestEnumerateSiblingCounts(t *testing.T) {
	for _, n := range []int{0, 1000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			root := tempDir(t)
			paths := []string{"lvl/secret"}
			for i := 0; i < n; i++ {
				paths = append(paths, fmt.Sprintf("lvl/s%04d", i))
			}
			mkTree(t, root, paths...)
			h, fake := prepare(t, 7, denyTable([]string{filepath.Join(root, "lvl", "secret")}))
			if got := h.entriesUnder(filepath.Join(root, "lvl"), kindDenySibling); got != n {
				t.Errorf("%d siblings held, want %d", got, n)
			}
			if len(fake.paths) < n+1 {
				t.Errorf("%d rules for %d siblings", len(fake.paths), n)
			}
		})
	}
}

// TestEnumerateOverlap is E7: two targets under one parent enumerate it once and exclude both.
//
// Spec: docs/p0/enforce-landlock.md E7.
func TestEnumerateOverlap(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "home/.ssh/id", "home/.aws/creds", "home/work/a", "home/note")
	h, _ := prepare(t, 7, denyTable([]string{filepath.Join(root, "home", ".ssh"), filepath.Join(root, "home", ".aws")}))
	assertLevel(t, h, filepath.Join(root, "home"), []string{".ssh", ".aws"})
	n := 0
	for _, e := range h.fds.open {
		if e.Path == filepath.Join(root, "home") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("parent held %d times", n)
	}
	// Two targets whose paths nest: the inner one is dropped before the walk, so the outer target keeps
	// Access 0 exactly (E29) — it no longer picks up READ_DIR from an ancestor union, which is what this
	// assertion allowed before nesting was handled; TestEnumerateNestedTargets covers its contents.
	h2, _ := prepare(t, 7, denyTable([]string{filepath.Join(root, "home"), filepath.Join(root, "home", "work", "a")}))
	e, _ := h2.entry(filepath.Join(root, "home"))
	if e.Access != 0 {
		t.Errorf("nested target got rights: %+v", e)
	}
}

// TestEnumerateSymlinkedAncestor: the declared path goes through a symlink; the walk is over the
// real location and the symlink's own directory is not treated as a parent of the target.
func TestEnumerateSymlinkedAncestor(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "real/dir/secret", "real/dir/sib", "links/")
	if err := os.Symlink(filepath.Join(root, "real", "dir"), filepath.Join(root, "links", "dir")); err != nil {
		t.Fatal(err)
	}
	h, _ := prepare(t, 7, denyTable([]string{filepath.Join(root, "links", "dir", "secret")}))
	assertLevel(t, h, filepath.Join(root, "real", "dir"), []string{"secret"})
	for _, e := range h.fds.open {
		if strings.Contains(e.Path, "/links/dir/") {
			t.Errorf("held a path through the symlink: %+v", e)
		}
	}
	if _, ok := h.entry(filepath.Join(root, "links")); !ok {
		t.Error("the links dir is a sibling of real and should be readable")
	}
}

// TestEnumerateSiblingSymlinkNotFollowed: a sibling symlink pointing into the target grants nothing.
func TestEnumerateSiblingSymlinkNotFollowed(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "d/secret/key")
	if err := os.Symlink(filepath.Join(root, "d", "secret"), filepath.Join(root, "d", "leak")); err != nil {
		t.Fatal(err)
	}
	h, _ := prepare(t, 7, denyTable([]string{filepath.Join(root, "d", "secret")}))
	if _, held := h.entry(filepath.Join(root, "d", "leak")); held {
		t.Error("symlink sibling held")
	}
	for _, e := range h.fds.open {
		if e.Kind == kindDenySibling && e.Access&accessReadFile != 0 && strings.HasPrefix(e.Path, filepath.Join(root, "d")+"/") {
			t.Errorf("unexpected readable entry under d: %+v", e)
		}
	}
}

// TestEnumerateVanishedTarget is E9: a target deleted since compile still drives enumeration.
//
// Spec: docs/p0/enforce-landlock.md E9.
func TestEnumerateVanishedTarget(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "d/sib")
	h, _ := prepare(t, 7, denyTable([]string{filepath.Join(root, "d", "gone")}))
	if _, held := h.entry(filepath.Join(root, "d", "gone")); held {
		t.Error("vanished target held")
	}
	assertLevel(t, h, filepath.Join(root, "d"), []string{"gone"})
}

// TestEnumerateSearchOnlyAncestor is LL-E33: a deny_read target under an ancestor the launcher can
// search but not list (mode 0111) still prepares. The target is sealed, the ancestor holds READ_DIR
// only, and no name at that level is granted as a sibling, since none could be enumerated.
func TestEnumerateSearchOnlyAncestor(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the directory's read permission")
	}
	root := tempDir(t)
	mkTree(t, root, "trav/secret", "trav/other", "pub")
	trav := filepath.Join(root, "trav")
	if err := os.Chmod(trav, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(trav, 0o755) })
	h, _ := prepare(t, 7, denyTable([]string{filepath.Join(trav, "secret")}))
	if target, ok := h.entry(filepath.Join(trav, "secret")); !ok || target.Kind != kindDenyTarget || target.Access != 0 {
		t.Errorf("target = %+v, %v", target, ok)
	}
	assertAncestorOnly(t, h, trav, []string{"secret"})
	if _, held := h.entry(filepath.Join(trav, "other")); held {
		t.Error("a sibling under an unlistable ancestor was granted")
	}
	assertLevel(t, h, root, []string{"trav"})
	if !h.Capabilities().Has(backend.CapReadDeny) {
		t.Error("deny_read reported unenforced")
	}
}

// TestEnumerateRootTarget is LL-E5: deny_read "/" has no parent to walk, so Prepare fails closed with
// ErrRulesetBuild whatever the spelling, rather than granting "/" the read set.
func TestEnumerateRootTarget(t *testing.T) {
	for _, target := range []string{"/", "//", "/.", "/tmp/.."} {
		err := prepareErr(t, 7, denyTable([]string{target}), nil)
		if !errors.Is(err, ErrRulesetBuild) || !strings.Contains(err.Error(), "no parent to enumerate") {
			t.Errorf("deny_read %q: %v, want ErrRulesetBuild naming no parent", target, err)
		}
	}
}

// TestEnumerateRootTargetByResolvedPath: the backstop compares the resolved path, which is what the enumeration
// is about, so a deny_read entry naming a symlink to "/" fails closed as "/" itself does.
func TestEnumerateRootTargetByResolvedPath(t *testing.T) {
	rt := denyTable([]string{"/"})
	rt.FS[len(rt.FS)-1].Path, rt.FS[len(rt.FS)-1].Resolved = filepath.Join(tempDir(t), "to-root"), "/"
	err := prepareErr(t, 7, rt, nil)
	if !errors.Is(err, ErrRulesetBuild) || !strings.Contains(err.Error(), "no parent to enumerate") {
		t.Errorf("deny_read resolving to /: %v, want ErrRulesetBuild naming no parent", err)
	}
}

// TestEnumerateNonUTF8Sibling is LL-E13: a sibling whose name is not UTF-8 is granted under its exact bytes,
// so the level stays complete (R3) and the target's own name is not the only one missing a grant.
//
// Spec: docs/p0/enforce-landlock.md E13.
func TestEnumerateNonUTF8Sibling(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "d/secret")
	odd := filepath.Join(root, "d", "caf\xe9\xff")
	if err := os.WriteFile(odd, nil, 0o644); err != nil {
		t.Skipf("the filesystem refuses a non-UTF-8 name: %v", err)
	}
	h, _ := prepare(t, 7, denyTable([]string{filepath.Join(root, "d", "secret")}))
	got, held := h.entry(odd)
	if !held || got.Kind != kindDenySibling || got.Access == 0 {
		t.Fatalf("sibling %q = %+v, held %v; want a sibling grant under its exact bytes", odd, got, held)
	}
	assertLevel(t, h, filepath.Join(root, "d"), []string{"secret"})
}

// TestUnenforcedPositions is R4 across every relative position of a write entry and a target,
// with the I5 cross-check against compile's flag.
//
// Spec: docs/p0/enforce-landlock.md E8, E26.
func TestUnenforcedPositions(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "w/secret/k", "w/other/", "elsewhere/", "w/secret/sub/")
	target := filepath.Join(root, "w", "secret")
	cases := []struct {
		name  string
		write string
		want  bool
	}{
		{"write above target", filepath.Join(root, "w"), true},
		{"write equals target (E26)", target, true},
		{"write below target", filepath.Join(root, "w", "secret", "sub"), false},
		{"write sibling of target (E8)", filepath.Join(root, "w", "other"), false},
		{"write elsewhere", filepath.Join(root, "elsewhere"), false},
		{"write is /", "/", true},
		{"prefix but not a path component", filepath.Join(root, "w", "sec"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := unenforcedUnder(target, []string{tc.write}); got != tc.want {
				t.Fatalf("unenforcedUnder = %v, want %v", got, tc.want)
			}
			if tc.write == "/" || strings.HasSuffix(tc.write, "sec") {
				return // no real directory to hold
			}
			rt := &agent.RuleTable{Contract: contractWith(true, true), FS: []agent.FSRule{
				fsRule(agent.FSWrite, tc.write),
				{Path: target, Kind: agent.FSDenyRead, Unenforced: tc.want},
			}}
			h, _ := prepare(t, 7, rt)
			if (len(h.unenforced) == 1) != tc.want {
				t.Errorf("Unenforced = %v", h.unenforced)
			}
			if tc.want {
				return
			}
			assertLevel(t, h, filepath.Join(root, "w"), []string{"secret"})
			// Mismatch with compile's flag is refused (I5).
			rt.FS[1].Unenforced = !tc.want
			if err := prepareErr(t, 7, rt, nil); !errors.Is(err, ErrRulesetBuild) {
				t.Errorf("I5 mismatch: %v", err)
			}
		})
	}
	// An ask entry counts as writable too (SEMANTICS §2).
	rt := &agent.RuleTable{Contract: contractWith(true, true), FS: []agent.FSRule{
		fsRule(agent.FSAsk, filepath.Join(root, "w")),
		{Path: target, Kind: agent.FSDenyRead, Unenforced: true},
	}}
	if h, _ := prepare(t, 7, rt); len(h.unenforced) != 1 {
		t.Error("ask parent not treated as writable")
	}
}

// TestEnumerateExecUnrestricted: without an exec section the read sets carry EXECUTE.
func TestEnumerateExecUnrestricted(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "d/secret", "d/sibdir/", "d/sibfile")
	rt := denyTable([]string{filepath.Join(root, "d", "secret")})
	rt.Contract = contractWith(false, true)
	h, _ := prepare(t, 7, rt)
	anc, _ := h.entry(filepath.Join(root, "d"))
	dir, _ := h.entry(filepath.Join(root, "d", "sibdir"))
	file, _ := h.entry(filepath.Join(root, "d", "sibfile"))
	if anc.Access != accessReadDir|accessExecute || dir.Access != readSet|accessExecute || file.Access != accessReadFile|accessExecute {
		t.Errorf("anc %#x dir %#x file %#x", anc.Access, dir.Access, file.Access)
	}
}

// FuzzEnumerate builds an adversarial tree from the fuzz bytes (nested dirs, files, symlinks, odd
// names) and checks the R3 invariants: no ancestor has READ_FILE, the target has no rights, every
// held sibling has exactly the read set for its type, and Close leaks nothing.
func FuzzEnumerate(f *testing.F) {
	f.Add([]byte("a/b/secret\x00a/x\x00a/b/y\x00L:a/b/l>a/b/secret"))
	f.Add([]byte("s\x00"))
	f.Add([]byte("d/e/f/g/secret\x00d/e/f/g/h/\x00\xff\xfe/"))
	f.Fuzz(func(t *testing.T, data []byte) {
		root := tempDir(t)
		parts := strings.Split(string(data), "\x00")
		var target string
		for i, p := range parts {
			if p == "" || strings.Contains(p, "..") || longComponent(p) {
				continue
			}
			if strings.HasPrefix(p, "L:") {
				link, dst, ok := strings.Cut(p[2:], ">")
				if ok && link != "" {
					_ = os.MkdirAll(filepath.Dir(filepath.Join(root, link)), 0o755)
					_ = os.Symlink(filepath.Join(root, dst), filepath.Join(root, link))
				}
				continue
			}
			full := filepath.Join(root, p)
			if strings.HasSuffix(p, "/") {
				_ = os.MkdirAll(full, 0o755)
			} else {
				_ = os.MkdirAll(filepath.Dir(full), 0o755)
				_ = os.WriteFile(full, nil, 0o644)
			}
			if i == 0 {
				target = full
			}
		}
		if target == "" || !strings.HasPrefix(target, root+"/") {
			return
		}
		before := openFDs(t)
		fake := &fakeSyscalls{abi: 7}
		hh, err := New(Options{syscalls: fake}).Prepare(context.Background(), denyTable([]string{target}), Run{})
		if err != nil {
			t.Fatalf("Prepare on %q: %v", data, err)
		}
		h := hh
		for _, e := range h.fds.open {
			switch e.Kind {
			case kindDenyAncestor:
				if e.Access != accessReadDir {
					t.Errorf("ancestor %q access %#x", e.Path, e.Access)
				}
			case kindDenyTarget:
				if e.Access != 0 {
					t.Errorf("target %q access %#x", e.Path, e.Access)
				}
			case kindDenySibling:
				if strings.HasPrefix(e.Path, target+"/") || e.Path == target {
					t.Errorf("sibling %q lies under the target", e.Path)
				}
				if e.IsDir && e.Access != readSet || !e.IsDir && e.Access != accessReadFile {
					t.Errorf("sibling %q access %#x dir=%v", e.Path, e.Access, e.IsDir)
				}
			}
		}
		if err := h.Close(); err != nil {
			t.Error(err)
		}
		if after := openFDs(t); after != before {
			t.Errorf("fd leak %d -> %d", before, after)
		}
	})
}

// longComponent reports a path with a component the filesystem cannot name (NAME_MAX is 255).
func longComponent(p string) bool {
	for _, c := range strings.Split(p, "/") {
		if len(c) > 255 {
			return true
		}
	}
	return false
}

func BenchmarkEnumerate1000(b *testing.B) {
	root := b.TempDir()
	_ = mkdirAll(filepath.Join(root, "lvl"))
	for i := 0; i < 1000; i++ {
		_ = writeFile(filepath.Join(root, "lvl", fmt.Sprintf("s%04d", i)))
	}
	_ = writeFile(filepath.Join(root, "lvl", "secret"))
	rt := denyTable([]string{filepath.Join(root, "lvl", "secret")})
	be := New(Options{syscalls: &fakeSyscalls{abi: 7}})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h, err := be.Prepare(context.Background(), rt, Run{})
		if err != nil {
			b.Fatal(err)
		}
		_ = h.Close()
	}
}

// TestEnumerateNestedTargets is R3 with one deny_read target at or below another. Enumerating the
// inner target walks the levels *inside* the outer one, and every such level grants the read set to
// each of its entries that is not on the path to the inner target. Landlock rules only ever add
// rights and the outer target is denied by having none, so nothing on it takes those grants back.
// Adding a more specific deny_read entry must never make the outer deny weaker, so the inner target
// is dropped before the walk: the outer entry already denies its whole subtree.
func TestEnumerateNestedTargets(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "secrets/prod/app.key", "secrets/staging/db.pem", "secrets/aws.json", "pub/note")
	outer := filepath.Join(root, "secrets")
	cases := []struct {
		name    string
		targets []string
	}{
		{"outer listed first", []string{outer, filepath.Join(outer, "prod", "app.key")}},
		{"inner listed first", []string{filepath.Join(outer, "prod", "app.key"), outer}},
		{"inner is a direct child", []string{outer, filepath.Join(outer, "prod")}},
		{"same target twice", []string{outer, outer}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := prepare(t, 7, denyTable(tc.targets))
			target, ok := h.entry(outer)
			if !ok || target.Kind != kindDenyTarget || target.Access != 0 {
				t.Errorf("deny_read target %s = %+v (held %v), want kind deny_read with access 0", outer, target, ok)
			}
			for _, e := range h.fds.open {
				if strings.HasPrefix(e.Path, outer+"/") && e.Access != 0 {
					t.Errorf("%s lies inside the deny_read target yet holds %#x (%s)", e.Path, e.Access, kindName(e.Kind))
				}
			}
			// The outer target is still enumerated normally at its own level (R3 is not skipped).
			assertLevel(t, h, root, []string{"secrets"})
		})
	}
}

// TestEnumerateHardlinkedTarget: a deny_read target that is a file has an alias at an enumerated
// level. The alias is the same inode, so its sibling grant would union READ_FILE onto the target's
// own Access-0 entry and Landlock, which keys rules by inode, would allow the read through both
// names. A deny_read target's rights stay 0 whatever else names its inode (R3 (1)).
func TestEnumerateHardlinkedTarget(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "secrets/id", "pub/note")
	target := filepath.Join(root, "secrets", "id")
	if err := os.Link(target, filepath.Join(root, "alias")); err != nil {
		t.Skipf("hardlink unsupported here: %v", err)
	}
	h, _ := prepare(t, 7, denyTable([]string{target}))
	e, ok := h.entry(target)
	if !ok || e.Access != 0 {
		t.Errorf("deny_read target %s = %+v (held %v), want access 0", target, e, ok)
	}
	if a, held := h.entry(filepath.Join(root, "alias")); held && a.Access != 0 {
		t.Errorf("hardlink alias holds %#x, the same inode as the deny_read target", a.Access)
	}
}

// TestOutermostMatchesPairwise holds the set-based filter to the pairwise rule it replaced, on generated
// targets: nested, duplicated, sibling and prefix-without-separator shapes, in every order the generator
// makes.
func TestOutermostMatchesPairwise(t *testing.T) {
	pairwise := func(resolved []string) []string {
		out := []string{}
		for i, t := range resolved {
			nested := false
			for j, other := range resolved {
				if i == j || (t == other && j > i) {
					continue
				}
				if t == other || strings.HasPrefix(t, other+"/") {
					nested = true
					break
				}
			}
			if !nested {
				out = append(out, t)
			}
		}
		return out
	}
	names := []string{"a", "a.txt", "ab", "b", ".env", ".env.1"}
	rng := rand.New(rand.NewPCG(1, 2))
	for range 2000 {
		var in []string
		for range 1 + rng.IntN(8) {
			p := ""
			for range 1 + rng.IntN(4) {
				p += "/" + names[rng.IntN(len(names))]
			}
			in = append(in, p)
		}
		if got, want := outermost(in), pairwise(in); !slices.Equal(got, want) {
			t.Fatalf("outermost(%q) = %q, pairwise %q", in, got, want)
		}
	}
}

// TestOutermostScalesLinearly: the filter compared every deny_read target with every other, and the
// built-in .env scan hands it one target per .env file where the agent writes, up to its cap of 50000, so
// 15000 planted .env.<n> files made a run's start take 21 s. At the cap the linear filter takes tens of
// milliseconds and the pairwise one took over a minute; the bound sits far from both, so a loaded machine
// does not fail it and a quadratic filter cannot pass it. The filter runs on its own goroutine so a
// regression fails at the bound rather than after the minute.
//
// Spec: docs/p0/enforce-landlock.md E22 (the deny_read half).
func TestOutermostScalesLinearly(t *testing.T) {
	in := make([]string, 50000)
	for i := range in {
		in[i] = "/home/u/project/.env." + strconv.Itoa(i)
	}
	done := make(chan int, 1)
	start := time.Now()
	go func() { done <- len(outermost(in)) }()
	select {
	case n := <-done:
		if n != len(in) {
			t.Fatalf("outermost kept %d of %d unrelated targets", n, len(in))
		}
		t.Logf("%d targets in %v", len(in), time.Since(start))
	case <-time.After(2 * time.Second):
		t.Fatalf("outermost over %d targets took more than 2 s: superlinear in the number of targets", len(in))
	}
}

// BenchmarkOutermost is the filter over the targets 15000 planted .env.<n> files make.
func BenchmarkOutermost(b *testing.B) {
	in := make([]string, 15000)
	for i := range in {
		in[i] = "/home/u/project/.env." + strconv.Itoa(i)
	}
	for b.Loop() {
		_ = outermost(in)
	}
}

// TestOutermost pins the nesting filter as a pure function, the way TestAncestorSetGolden pins the
// ancestry: which targets survive decides which directories are ever walked, so the rule
// ("a target at or below another target is dropped, duplicates keep their first occurrence, table
// order is preserved") is checked here independently of any filesystem.
func TestOutermost(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"unrelated targets are all kept", []string{"/home/u/.ssh", "/home/u/.aws"}, []string{"/home/u/.ssh", "/home/u/.aws"}},
		{"inner dropped, outer first", []string{"/s", "/s/prod/app.key"}, []string{"/s"}},
		{"inner dropped, inner first", []string{"/s/prod/app.key", "/s"}, []string{"/s"}},
		{"duplicate keeps one", []string{"/s", "/s"}, []string{"/s"}},
		{"three levels collapse to the outermost", []string{"/s/a/b", "/s", "/s/a"}, []string{"/s"}},
		// A path component boundary, not a string prefix: /home/user2 is not inside /home/user.
		{"prefix without a separator is unrelated", []string{"/home/user", "/home/user2/x"}, []string{"/home/user", "/home/user2/x"}},
		// "/a." sorts between "/a" and "/a/x", so a filter that only compared each target with the
		// previously kept one would let /a/x through. Every kept target is compared.
		{"an unrelated name sorting between outer and inner", []string{"/a", "/a.txt", "/a/x"}, []string{"/a", "/a.txt"}},
		{"nothing to enumerate", nil, []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := outermost(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("outermost(%v) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("outermost(%v) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}
