// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package bpf

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// ADR 0043's name entries in the kernel (NAME-BPF; bpf/decide_names.h), on a real kernel in the KVM guest, in each
// build and mode it offers: the name rows, the config row and the scope rows a slot holds decide what the walk
// allows, as ADR 0043 D1 to D5 and D9 say, against rows the test writes into a scratch slot (the fs rows through the
// test-only fill, the name and config rows from here, as userspace writes them: their keys are hashes, never
// addresses). The agent is planeHelper (plane_decide_integration_test.go).

// planeNameCommands are the helper's commands these cells add: renameat2(RENAME_EXCHANGE), and an O_TMPFILE file
// linked to a name.
var planeNameCommands = map[string]func([]string) string{
	"exchange": func(f []string) string {
		return errnoString(unix.Renameat2(unix.AT_FDCWD, f[1], unix.AT_FDCWD, f[2], unix.RENAME_EXCHANGE))
	},
	"tmplink": func(f []string) string {
		fd, err := unix.Open(f[1], unix.O_TMPFILE|unix.O_WRONLY|unix.O_CLOEXEC, 0o600)
		if err != nil {
			return errnoString(err)
		}
		defer unix.Close(fd)
		return errnoString(unix.Linkat(unix.AT_FDCWD, "/proc/self/fd/"+strconv.Itoa(fd), unix.AT_FDCWD, f[2], unix.AT_SYMLINK_FOLLOW))
	},
}

// The name cells' fs rows' rule_idx (positions a row compiler would give; only the scratch value reads them).
const (
	nameRuleRoot = 40 + iota
	nameRuleProj
	nameRuleSrc
	nameRuleKeep
	nameRuleBad
	nameRuleChainA
	nameRuleChainB
	nameRuleSide
	nameRuleInner
)

// The cells' name entries, by their position in RuleTable.NameDeny: the built-in pair over proj (scope bit 0), and a
// declared exact secret.json over bad (scope bit 2, a scope-only row whose identity the test corrupts), and a declared
// exact .env over side and side/inner (scope bits 3 and 4, scope-only rows outside proj: a .env there is a candidate
// of the built-in entry too, whose scope the climb never meets). keep (scope bit 1) is D3's exempt parent of .env.test.
const (
	nameEntryEnv    = 0
	nameEntryEnvDot = 1
	nameEntrySecret = 2
	nameEntrySide   = 3
)

// nameDep16 is a dependency directory's name as long as the config row holds one (PlaneNameDepLen), which the cells'
// config row adds to agent.EnvSkipDirs; nameDep16Long starts with it and is 32 bytes longer, so the two lengths agree
// in their low five bits.
const (
	nameDep16     = "sixteen-byte-dep"
	nameDep16Long = nameDep16 + "-and-thirty-two-bytes-past-it..."
)

// nameCellDeps is the cells' config row's dependency directories.
var nameCellDeps = append(append([]string{}, agent.EnvSkipDirs...), nameDep16)

// nameTree is the cells' tree: root a write entry; proj a write entry and the built-in's scope; out beneath root,
// covered by nothing.
type nameTree struct {
	planeTree
	root, proj, out string
	chainA, chainB  string // proj's chains: a covered .env 64 levels below its scope's level-1 directory, and 65
}

func (n *nameTree) p(rel string) string { return filepath.Join(n.proj, rel) }

func nameRow(gen uint32, rule uint16, kind, scope uint8) planeFillTmpl {
	return planeFillTmpl{Row: PlaneRow{Gen: gen, RuleIdx: rule, Kind: kind, Scope: scope, ExecRule: PlaneRuleNone}}
}

// buildNameTree lays the cells' tree out and holds its rows' directories for the fill.
func buildNameTree(t *testing.T, gen uint32) *nameTree {
	t.Helper()
	root := filepath.Join(t.TempDir(), "n")
	n := &nameTree{planeTree: planeTree{tmpls: map[uint32]planeFillTmpl{}}, root: root, proj: filepath.Join(root, "proj"),
		out: filepath.Join(root, "out")}
	for _, f := range []string{"proj/.env", "proj/a.txt", "proj/b.txt", "proj/c.txt", "proj/keep/.env.test",
		"proj/other/.env.test", "proj/x/.env.example", "proj/py/.env/cfg", "proj/mvdir/f", "proj/dd/f", "proj/src/keep.txt",
		"out/src.txt", "out/indir/f", "out/odir/f", "proj/bound/.env", "bad/secret.json", "bad/other.json",
		"side/.env", "side/inner/.env", "side/inner/mv/f", "side/inner/mv2/f", "proj/" + nameDep16 + "/.env",
		"proj/" + nameDep16Long + "/.env", "proj/d.txt", "out/xdir/f"} {
		mustWrite(t, filepath.Join(root, f), []byte("x\n"), 0o644)
	}
	for _, d := range []string{"proj/later", "proj/node_modules/pkg", "proj/m/node_modules", "proj/mnt", "proj/later2"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// chainA: 63 directories beneath proj (proj/a and 62 below it), so proj is the climb's level 64 from a file in the
	// last; chainB: 64, level 65. Each has a write row eleven directories down, so the walk resolves within its bound
	// and only the climb meets its own.
	n.chainA, n.chainB = planeChain(t, n.proj+"/a", 62), planeChain(t, n.proj+"/b", 63)
	mustWrite(t, filepath.Join(n.chainA, ".env"), []byte("x\n"), 0o644)
	mustWrite(t, filepath.Join(n.chainB, ".env"), []byte("x\n"), 0o644)
	mustWrite(t, filepath.Join(n.chainB, "plain.txt"), []byte("x\n"), 0o644)
	nth := func(base string, k int) string {
		p := base
		for i := 0; i < k; i++ {
			p = filepath.Join(p, "a")
		}
		return p
	}

	n.hold(t, root, nameRow(gen, nameRuleRoot, PlaneRowModifyAllow, 0))
	n.hold(t, n.proj, nameRow(gen, nameRuleProj, PlaneRowModifyAllow, 1<<0))
	n.hold(t, n.p("src"), nameRow(gen, nameRuleSrc, PlaneRowModifyAllow, 0))
	n.hold(t, n.p("keep"), nameRow(gen, nameRuleKeep, PlaneRowScopeOnly, 1<<1))
	bad := nameRow(gen, nameRuleBad, PlaneRowScopeOnly, 1<<2)
	bad.Corrupt = 1
	n.hold(t, filepath.Join(root, "bad"), bad)
	n.hold(t, nth(n.proj+"/a", 10), nameRow(gen, nameRuleChainA, PlaneRowModifyAllow, 0))
	n.hold(t, nth(n.proj+"/b", 10), nameRow(gen, nameRuleChainB, PlaneRowModifyAllow, 0))
	n.hold(t, filepath.Join(root, "side"), nameRow(gen, nameRuleSide, PlaneRowScopeOnly, 1<<3))
	n.hold(t, filepath.Join(root, "side/inner"), nameRow(gen, nameRuleInner, PlaneRowScopeOnly, 1<<4))
	return n
}

// putNameRows writes the cells' name rows and config row of gen into the slot's name map, as Prepare will: the
// config row first, then each row with BPF_NOEXIST.
func putNameRows(t *testing.T, m *ebpf.Map, gen uint32) {
	t.Helper()
	cfg, ok := NewPlaneNameConfig(gen, []uint8{1 << 0, 1 << 0, 1 << 2, 1<<3 | 1<<4}, nameCellDeps)
	if !ok {
		t.Fatal("config row")
	}
	if err := m.Update(uint64(0), cfg, ebpf.UpdateAny); err != nil {
		t.Fatalf("config row: %v", err)
	}
	for _, r := range []struct {
		literal string
		prefix  bool
		arms    []PlaneNameArm
	}{
		{".env", false, []PlaneNameArm{{Scopes: 1 << 0, Rule: nameEntryEnv}, {Scopes: 1<<3 | 1<<4, Rule: nameEntrySide}}},
		{".env.", true, []PlaneNameArm{{Scopes: 1 << 0, Rule: nameEntryEnvDot}}},
		{".env.example", false, []PlaneNameArm{{Scopes: 1 << 0, Flags: PlaneNameArmExempt, Rule: nameEntryEnvDot, RawFrom: 5}}},
		{".env.test", false, []PlaneNameArm{{Scopes: 1 << 1, Depth: 1, Flags: PlaneNameArmExempt, Rule: PlaneNameArmAll}}},
		{"secret.json", false, []PlaneNameArm{{Scopes: 1 << 2, Rule: nameEntrySecret}}},
	} {
		putNameRow(t, m, r.literal, r.prefix, gen, ebpf.UpdateNoExist, r.arms...)
	}
}

func putNameRow(t *testing.T, m *ebpf.Map, literal string, prefix bool, gen uint32, flags ebpf.MapUpdateFlags,
	arms ...PlaneNameArm) {
	t.Helper()
	key, ok := agent.NameKey(literal, prefix)
	row, ok2 := NewPlaneNameRow(literal, prefix, gen, arms)
	if !ok || !ok2 {
		t.Fatalf("name row %q", literal)
	}
	if err := m.Update(key, row, flags); err != nil {
		t.Fatalf("name row %q: %v", literal, err)
	}
}

// TestPlaneNameEntriesDecide is NAME-BPF's root cells (ADR 0043 C10's kernel half), in each build and mode this kernel
// offers. Beneath a scope, a covered name refuses a read, a write-open, its creation (O_CREAT, mknod, symlink, a hard
// link's new name, an O_TMPFILE linked to it), a rename onto it, a rename or link of it, RENAME_EXCHANGE, unlink and
// truncate, each named by its entry's tag (D8), where the walk allowed the question (D1); a directory named like an
// entry, a chmod, a name outside every scope, beneath a dependency directory or under D3's exemption is allowed;
// folding, the built-in exceptions' spelling rule, a nested write entry, a file bind-mounted over a covered name (the
// mountpoint's name), a tmpfs mounted at node_modules and one mounted beneath the scope, a 255-byte name and stale
// inline name bytes are decided as D2 and D4 say; a directory's rename out of the scope, into or onto a dependency
// directory's name, and either way of an exchange is refused (D5) while one within the scope, into it or of the scope
// directory itself is allowed; a refusal, a name's or D5's, names the deciding entry's nearest scope, also when a
// lower candidate's scope is never met; a key collision matches nothing; and a missing name map, config row or one of another
// gen, a corrupted scope row and a climb past its bound refuse and count (D9). It logs each program's verified
// instruction count (TestPlaneLoadsAndAttaches holds the budget).
func TestPlaneNameEntriesDecide(t *testing.T) {
	requireBPF(t)
	ran := 0
	for _, o := range PlaneObjects() {
		t.Run(o.String(), func(t *testing.T) {
			if ok, why := planeReaderUsable(t, o); !ok {
				t.Skip(why)
			}
			for _, mode := range PlaneModes {
				t.Run(string(mode), func(t *testing.T) {
					if ok, why := planeModeUsable(mode); !ok {
						t.Skip(why)
					}
					planeNameCells(t, o, mode)
					ran++
				})
			}
		})
	}
	if ran == 0 {
		t.Fatal("no plane build ran in any mode on this kernel")
	}
}

func planeNameCells(t *testing.T, o Object, mode PlaneMode) {
	const runIdx, gen = 11, 5151
	spec, err := Load(o)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	unpin(spec)
	keep := map[string]bool{}
	for _, p := range PlaneProgramsHere(mode) {
		keep[p] = true
	}
	for name := range spec.Programs {
		if !keep[name] {
			delete(spec.Programs, name)
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("load %s %s: %+v", o, mode, ve)
		}
		t.Fatalf("load %s %s: %v", o, mode, err)
	}
	t.Cleanup(coll.Close)
	inners := map[string]*ebpf.Map{}
	for _, name := range []string{MapPlaneRows, MapPlaneExecRows, MapPlaneNameRows} {
		inner, err := ebpf.NewMap(spec.Maps[name].InnerMap)
		if err != nil {
			t.Fatalf("inner %s: %v", name, err)
		}
		t.Cleanup(func() { _ = inner.Close() })
		if err := coll.Maps[name].Put(uint32(runIdx), inner); err != nil {
			t.Fatalf("outer %s: %v", name, err)
		}
		inners[name] = inner
	}
	tree := buildNameTree(t, gen)
	planeFill(t, coll, runIdx, &tree.planeTree)
	names := inners[MapPlaneNameRows]
	putNameRows(t, names, gen)
	if err := coll.Maps[MapPlaneCounters].Put(uint32(runIdx), PlaneCounts{}); err != nil {
		t.Fatal(err)
	}
	setSlot := func(gen, flags uint32) {
		t.Helper()
		s := PlaneSlot{Gen: gen, Flags: flags}
		if !s.SetLeads([]string{".env", "secret.j"}, []uint8{5}) {
			t.Fatal("leads")
		}
		if err := coll.Maps[MapPlaneSlots].Put(uint32(runIdx), s); err != nil {
			t.Fatal(err)
		}
	}
	setSlot(gen, PlaneSlotNameDecides)

	var links []link.Link
	t.Cleanup(func() {
		for _, l := range links {
			_ = l.Close()
		}
	})
	for _, h := range PlaneHooksHere(mode) {
		p := coll.Programs[h.Program(mode)]
		if info, err := p.Info(); err == nil {
			if n, ok := info.VerifiedInstructions(); ok {
				t.Logf("%s: %d instructions verified", h.Program(mode), n)
			}
		}
		var l link.Link
		if mode == PlaneLSM {
			l, err = link.AttachLSM(link.LSMOptions{Program: p})
		} else {
			l, err = link.AttachTracing(link.TracingOptions{Program: p, AttachType: ebpf.AttachModifyReturn})
		}
		if err != nil {
			t.Fatalf("attach %s: %v", h.Program(mode), err)
		}
		links = append(links, l)
	}

	_, cgfd, cgid := planeChildCgroup(t, "name-"+string(o)+"-"+string(mode))
	helper := startPlaneHelper(t, cgfd)
	runSet := coll.Maps[MapRunSet]
	arm := func(gen uint32) {
		t.Helper()
		if err := runSet.Put(cgid, Run{RunIdx: runIdx, Tier: 3, Plane: RunPlaneOf(mode), Gen: gen}); err != nil {
			t.Fatalf("arm: %v", err)
		}
	}
	arm(gen)
	t.Cleanup(func() { _ = runSet.Delete(cgid) })

	p := tree.p
	ro, wo := strconv.Itoa(unix.O_RDONLY), strconv.Itoa(unix.O_WRONLY)
	create := strconv.Itoa(unix.O_WRONLY | unix.O_CREAT)
	trunc := strconv.Itoa(unix.O_RDONLY | unix.O_TRUNC)
	check := func(name, want string, args ...string) {
		t.Helper()
		if got := helper.do(t, args...); got != want {
			t.Errorf("%s: in the run %v answered %s, want %s", name, args, got, want)
		}
	}
	scratch := func(what string, hook uint16, reason ReasonCode, rule uint32) {
		t.Helper()
		var d PlaneDecision
		if err := coll.Maps[MapPlaneScratch].Lookup(int32(helper.pidfd), &d); err != nil {
			t.Errorf("%s: no scratch value: %v", what, err)
			return
		}
		verdict := uint8(1)
		if reason == ReasonNone {
			verdict = 0
		}
		if d.Hook != hook || d.Verdict != verdict || d.Reason != uint8(reason) || d.RuleIdx != rule {
			t.Errorf("%s: recorded hook %d verdict %d reason %d rule %#x, want %d %d %d %#x", what, d.Hook, d.Verdict,
				d.Reason, d.RuleIdx, hook, verdict, reason, rule)
		}
	}
	tag := func(bit, entry int) uint32 { return uint32(PlaneRuleName) | uint32(bit)<<6 | uint32(entry) }
	exists := func(path string) bool { _, err := os.Lstat(path); return err == nil }
	outside := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Errorf("%s outside the run: %v", what, err)
		}
	}
	const (
		hookOpen, hookRename, hookLink, hookUnlink, hookMknod, hookSymlink, hookTruncate = 1, 3, 4, 5, 9, 11, 12
	)

	// D1: a covered file the walk allows is refused as its own deny_read entry would refuse it.
	check("read a covered .env", eacces, "open", ro, p(".env"))
	scratch("read a covered .env", hookOpen, ReasonReadDenied, tag(0, nameEntryEnv))
	outside("read a covered .env", func() error { _, err := os.ReadFile(p(".env")); return err }())
	check("write-open a covered .env", eacces, "open", wo, p(".env"))
	scratch("write-open a covered .env", hookOpen, ReasonWriteOutsideContract, tag(0, nameEntryEnv))
	check("O_TRUNC a covered .env", eacces, "open", trunc, p(".env"))
	check("read a file no entry names", "0", "open", ro, p("a.txt"))
	scratch("read a file no entry names", hookOpen, ReasonNone, nameRuleProj)
	check("truncate(2) a covered .env", eacces, "truncate", p(".env"))
	scratch("truncate a covered .env", hookTruncate, ReasonWriteOutsideContract, tag(0, nameEntryEnv))
	check("unlink a covered .env", eacces, "unlink", p(".env"))
	scratch("unlink a covered .env", hookUnlink, ReasonDeleteOutsideContract, tag(0, nameEntryEnv))
	check("rename a covered .env away", eacces, "rename", p(".env"), p("plain"))
	scratch("rename a covered .env away", hookRename, ReasonRenameOutsideContract, tag(0, nameEntryEnv))
	check("link a covered .env out (REFER)", eacces, "link", p(".env"), p("alias"))
	scratch("link a covered .env out", hookLink, ReasonRefer, tag(0, nameEntryEnv))
	check("chmod a covered .env (metadata is not decided)", "0", "chmod", p(".env"), "600")
	// A descriptor opened before the run was armed: ftruncate reaches file_truncate (6.2+) or path_truncate, and the
	// name check refuses it there as truncate(2) by path.
	if err := runSet.Delete(cgid); err != nil {
		t.Fatalf("disarm: %v", err)
	}
	check("open a covered .env before the run", "0", "hold", p(".env"))
	arm(gen)
	check("ftruncate a covered .env by a descriptor opened before the run", eacces, "ftruncate", p(".env"))
	if b, err := os.ReadFile(p(".env")); err != nil || string(b) != "x\n" {
		t.Errorf(".env after the refused truncates: %q, %v", b, err)
	}

	// Files created later beneath the scope, by a process outside the run.
	mustWrite(t, p("later/.env.local"), []byte("s\n"), 0o644)
	check("read a .env.local created after the fill", eacces, "open", ro, p("later/.env.local"))
	scratch("read a .env.local created later", hookOpen, ReasonReadDenied, tag(0, nameEntryEnvDot))
	mustWrite(t, p("later/.ENV"), []byte("s\n"), 0o644)
	mustWrite(t, p("later/.Env.Local"), []byte("s\n"), 0o644)
	check("read .ENV (folded)", eacces, "open", ro, p("later/.ENV"))
	check("read .Env.Local (folded)", eacces, "open", ro, p("later/.Env.Local"))
	long := ".env." + strings.Repeat("x", 250)
	mustWrite(t, p("later/"+long), []byte("s\n"), 0o644)
	check("read a 255-byte .env.* name", eacces, "open", ro, p("later/"+long))
	// A short inline name renamed from a longer one keeps the old bytes past its NUL in d_iname: the pass masks them.
	mustWrite(t, p("later2/zzzzzzzzzzzzzzzzzzzzzzzz"), []byte("s\n"), 0o644)
	outside("rename to .env", os.Rename(p("later2/zzzzzzzzzzzzzzzzzzzzzzzz"), p("later2/.env")))
	check("read a .env renamed from a longer inline name", eacces, "open", ro, p("later2/.env"))

	// Creations at a covered name.
	check("O_CREAT .env.new", eacces, "open", create, p("later/.env.new"))
	scratch("O_CREAT .env.new", hookMknod, ReasonWriteOutsideContract, tag(0, nameEntryEnvDot))
	check("mknod .env.fifo", eacces, "mknod", p("later/.env.fifo"))
	check("symlink .env.sym", eacces, "symlink", "a.txt", p("later/.env.sym"))
	scratch("symlink .env.sym", hookSymlink, ReasonWriteOutsideContract, tag(0, nameEntryEnvDot))
	check("link onto .env.link", eacces, "link", p("a.txt"), p("later/.env.link"))
	scratch("link onto .env.link", hookLink, ReasonWriteOutsideContract, tag(0, nameEntryEnvDot))
	check("rename onto .env.moved", eacces, "rename", p("b.txt"), p("later/.env.moved"))
	scratch("rename onto .env.moved", hookRename, ReasonRenameOutsideContract, tag(0, nameEntryEnvDot))
	check("O_TMPFILE linked to .env", eacces, "tmplink", p("later"), p("later/.env"))
	check("RENAME_EXCHANGE with a covered .env", eacces, "exchange", p("c.txt"), p(".env"))
	for _, f := range []string{"later/.env.new", "later/.env.fifo", "later/.env.sym", "later/.env.link", "later/.env.moved", "later/.env"} {
		if exists(p(f)) {
			t.Errorf("a refused creation left %s", f)
		}
	}
	check("create a file no entry names", "0", "open", create, p("later/plain.txt"))

	// What no name entry decides.
	check("mkdir a directory named .env.d", "0", "mkdir", p("later/.env.d"))
	check("rmdir it", "0", "rmdir", p("later/.env.d"))
	check("read beneath a directory named .env", "0", "open", ro, p("py/.env/cfg"))
	// D1 decides no directory at either end of a rename: a verifier that took a rename's negative destination for a
	// positive one asked the name check of this directory in lsm mode on 5.14, 6.8 and 6.12 (bpf/tests
	// TestPlaneTestsADentrysInodeAtRunTime).
	check("rename a directory named .env within the scope", "0", "rename", p("py/.env"), p("py/.env.old"))
	check("read .env.example (a built-in exception)", "0", "open", ro, p("x/.env.example"))
	mustWrite(t, p("x/.env.EXAMPLE"), []byte("s\n"), 0o644)
	check("read .env.EXAMPLE (the scan denies it as spelled)", eacces, "open", ro, p("x/.env.EXAMPLE"))
	mustWrite(t, p("x/.ENV.example"), []byte("s\n"), 0o644)
	check("read .ENV.example (an exception as .env.example is)", "0", "open", ro, p("x/.ENV.example"))
	check("read keep/.env.test (D3's exemption)", "0", "open", ro, p("keep/.env.test"))
	check("write keep/.env.test (D3's exemption)", "0", "open", wo, p("keep/.env.test"))
	check("read other/.env.test (no exemption there)", eacces, "open", ro, p("other/.env.test"))
	mustWrite(t, p("src/.env"), []byte("s\n"), 0o644)
	check("read .env under a nested write entry", eacces, "open", ro, p("src/.env"))
	scratch("read .env under a nested write entry", hookOpen, ReasonReadDenied, tag(0, nameEntryEnv))
	mustWrite(t, filepath.Join(tree.out, ".env"), []byte("s\n"), 0o644)
	check("read .env outside every scope", "0", "open", ro, filepath.Join(tree.out, ".env"))
	mustWrite(t, p("node_modules/pkg/.env"), []byte("s\n"), 0o644)
	check("read .env beneath node_modules", "0", "open", ro, p("node_modules/pkg/.env"))
	check("create .env.local beneath node_modules", "0", "open", create, p("node_modules/pkg/.env.local"))
	// A dependency directory's name is compared whole: one as long as the config row holds is met, and a directory
	// whose longer name starts with it is no dependency directory, whatever its length.
	check("read .env beneath a 16-byte dependency directory", "0", "open", ro, p(nameDep16+"/.env"))
	check("read .env beneath a 48-byte name that starts with one", eacces, "open", ro, p(nameDep16Long+"/.env"))
	scratch("read .env beneath a 48-byte name that starts with one", hookOpen, ReasonReadDenied, tag(0, nameEntryEnv))

	// Mount crossings (D2, D4).
	if err := unix.Mount("tmpfs", p("m/node_modules"), "tmpfs", 0, ""); err != nil {
		t.Fatalf("mount a tmpfs at node_modules: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(p("m/node_modules"), unix.MNT_DETACH) })
	mustWrite(t, p("m/node_modules/pkg/.env.local"), []byte("s\n"), 0o644)
	check("read .env.local on a tmpfs mounted at node_modules", "0", "open", ro, p("m/node_modules/pkg/.env.local"))
	if err := unix.Mount("tmpfs", p("mnt"), "tmpfs", 0, ""); err != nil {
		t.Fatalf("mount a tmpfs beneath the scope: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(p("mnt"), unix.MNT_DETACH) })
	mustWrite(t, p("mnt/.env.local"), []byte("s\n"), 0o644)
	check("read .env.local on a tmpfs mounted beneath the scope", eacces, "open", ro, p("mnt/.env.local"))
	if err := unix.Mount(filepath.Join(tree.out, "src.txt"), p("bound/.env"), "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("bind a file over bound/.env: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(p("bound/.env"), unix.MNT_DETACH) })
	check("read a file bind-mounted over .env (the mountpoint's name)", eacces, "open", ro, p("bound/.env"))
	check("read the bind's source under its own name", "0", "open", ro, filepath.Join(tree.out, "src.txt"))

	// D5: directory renames.
	check("move a directory out of the scope", eacces, "rename", p("mvdir"), filepath.Join(tree.out, "mvdir"))
	scratch("move a directory out of the scope", hookRename, ReasonRefer, tag(0, nameEntryEnv))
	check("rename a directory within the scope", "0", "rename", p("mvdir"), p("mvdir2"))
	check("move a directory into node_modules", eacces, "rename", p("mvdir2"), p("node_modules/mvdir"))
	check("rename a directory to vendor", eacces, "rename", p("dd"), p("vendor"))
	check("move a directory into the scope", "0", "rename", filepath.Join(tree.out, "indir"), p("indir"))
	check("exchange a covered directory with one outside", eacces, "exchange", p("mvdir2"), filepath.Join(tree.out, "odir"))
	check("exchange the other way", eacces, "exchange", filepath.Join(tree.out, "odir"), p("mvdir2"))
	// An exchange of a file with a directory: the file's leaving the scope is D1's (both ends' names, no covered name
	// here), never D5's, and the directory comes into coverage, which D5 allows.
	check("exchange a plain file with a directory outside", "0", "exchange", p("d.txt"), filepath.Join(tree.out, "xdir"))
	check("move the scope directory itself", "0", "rename", tree.proj, filepath.Join(tree.root, "proj2"))
	outside("move the scope back", os.Rename(filepath.Join(tree.root, "proj2"), tree.proj))
	outside("move a directory out, outside the run", os.Rename(p("mvdir2"), filepath.Join(tree.out, "mvdir")))

	// D8: a refusal names the deciding entry's nearest scope. side/inner/.env is a candidate of the built-in entry
	// (lowest, whose scope proj the climb never meets) and of side's (scopes side and side/inner): side's decides, by
	// side/inner, the nearer. D5 names the deciding entry's nearest scope above the old place the same way.
	side := filepath.Join(tree.root, "side")
	check("read .env under two scopes of a higher entry", eacces, "open", ro, filepath.Join(side, "inner/.env"))
	scratch("read .env under two scopes of a higher entry", hookOpen, ReasonReadDenied, tag(4, nameEntrySide))
	check("read .env under the outer scope", eacces, "open", ro, filepath.Join(side, ".env"))
	scratch("read .env under the outer scope", hookOpen, ReasonReadDenied, tag(3, nameEntrySide))
	check("move a directory out of two scopes", eacces, "rename", filepath.Join(side, "inner/mv"), filepath.Join(tree.out, "smv"))
	scratch("move a directory out of two scopes", hookRename, ReasonRefer, tag(4, nameEntrySide))
	check("move a directory to the outer scope", "0", "rename", filepath.Join(side, "inner/mv2"), filepath.Join(side, "mv2"))

	// D4's bound: a covered file whose scope is the climb's level 64 is decided; at 65 the climb cannot decide it.
	check("read a .env 64 levels below the scope", eacces, "open", ro, filepath.Join(tree.chainA, ".env"))
	scratch("read a .env 64 levels below the scope", hookOpen, ReasonReadDenied, tag(0, nameEntryEnv))
	check("read a .env 65 levels below the scope", eacces, "open", ro, filepath.Join(tree.chainB, ".env"))
	scratch("read a .env 65 levels below the scope", hookOpen, ReasonPathUnresolved, uint32(PlaneRuleNone))
	check("read a name no entry matches 65 levels down", "0", "open", ro, filepath.Join(tree.chainB, "plain.txt"))
	counts := func() PlaneCounts {
		t.Helper()
		var c PlaneCounts
		if err := coll.Maps[MapPlaneCounters].Lookup(uint32(runIdx), &c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	if c := counts(); c.Bound != 1 || c.Mismatch != 0 || c.NoRows != 0 || c.Unresolved != 0 {
		t.Errorf("counters after the bound cell: %+v, want one bound", c)
	}

	// D9 and ADR 0025 (4): a scope row whose identity is gone refuses and counts.
	check("read secret.json under a corrupted scope row", eacces, "open", ro, filepath.Join(tree.root, "bad/secret.json"))
	scratch("read secret.json under a corrupted scope row", hookOpen, ReasonIdentityMismatch, uint32(PlaneRuleNone))
	check("read a name no entry matches there", "0", "open", ro, filepath.Join(tree.root, "bad/other.json"))
	if c := counts(); c.Mismatch != 1 {
		t.Errorf("the corrupted scope row did not count a mismatch: %+v", c)
	}

	// A key collision matches nothing: .env's key holding other bytes.
	putNameRow(t, names, ".env", false, gen, ebpf.UpdateAny, PlaneNameArm{Scopes: 1, Rule: nameEntryEnv})
	key, _ := agent.NameKey(".env", false)
	collide, _ := NewPlaneNameRow(".enx", false, gen, []PlaneNameArm{{Scopes: 1, Rule: nameEntryEnv}})
	if err := names.Update(key, collide, ebpf.UpdateExist); err != nil {
		t.Fatal(err)
	}
	check("read .env under a row whose bytes differ (a collision)", "0", "open", ro, p(".env"))
	putNameRow(t, names, ".env", false, gen, ebpf.UpdateExist, PlaneNameArm{Scopes: 1, Rule: nameEntryEnv})
	check("read .env with its row back", eacces, "open", ro, p(".env"))
	// A name row of another gen is a previous run's: absent, as the walk reads an fs row of another gen (D9).
	putNameRow(t, names, ".env", false, gen+1, ebpf.UpdateExist, PlaneNameArm{Scopes: 1, Rule: nameEntryEnv})
	check("read .env under a name row of another gen", "0", "open", ro, p(".env"))
	putNameRow(t, names, ".env", false, gen, ebpf.UpdateExist, PlaneNameArm{Scopes: 1, Rule: nameEntryEnv})
	check("read .env with its own gen's row back", eacces, "open", ro, p(".env"))

	// D9: the header's flag decides whether names are asked; a missing config row, one of another gen and a missing
	// name map refuse a candidate, counted norows; a name no lead admits never reaches them.
	setSlot(gen, 0)
	check("read .env with the header's flag clear", "0", "open", ro, p(".env"))
	setSlot(gen, PlaneSlotNameDecides)
	before := counts().NoRows
	if err := names.Delete(uint64(0)); err != nil {
		t.Fatal(err)
	}
	check("read .env with no config row", eacces, "open", ro, p(".env"))
	scratch("read .env with no config row", hookOpen, ReasonPathUnresolved, uint32(PlaneRuleNone))
	check("read a name no lead admits with no config row", "0", "open", ro, p("a.txt"))
	cfg, _ := NewPlaneNameConfig(gen-1, []uint8{1, 1, 4}, agent.EnvSkipDirs)
	if err := names.Update(uint64(0), cfg, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	check("read .env with a config row of another gen", eacces, "open", ro, p(".env"))
	if err := coll.Maps[MapPlaneNameRows].Delete(uint32(runIdx)); err != nil {
		t.Fatal(err)
	}
	check("read .env with no name map", eacces, "open", ro, p(".env"))
	check("rename a directory with no name map", eacces, "rename", p("indir"), p("indir2"))
	if c := counts(); c.NoRows != before+4 {
		t.Errorf("norows %d after four refusals for a missing name map or config row, want %d", c.NoRows, before+4)
	}
	if err := coll.Maps[MapPlaneNameRows].Put(uint32(runIdx), names); err != nil {
		t.Fatal(err)
	}
	cfg, _ = NewPlaneNameConfig(gen, []uint8{1, 1, 4}, agent.EnvSkipDirs)
	if err := names.Update(uint64(0), cfg, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	check("read .env with the name map back", eacces, "open", ro, p(".env"))

	// The same actions outside the run pass.
	outside("unlink a covered .env", os.Remove(p(".env")))
	outside("create .env.new", os.WriteFile(p("later/.env.new"), []byte("x"), 0o644))
}
