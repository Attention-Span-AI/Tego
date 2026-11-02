// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package bpf

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// TIER3-PLAN T14's root cells: step C's mmap_file and file_mprotect (ADR 0027, enforce-plane R26) of both plane
// builds, in each mode this kernel offers, against rows the test writes into a scratch slot as T3's cells do. The
// helper is planeHelper (plane_decide_integration_test.go) with the mapping commands below.

// planeMapCommands are the helper's step C commands, answered like its others: "0" or an errno number.
//
//	map <prot> <flags> <path>              open path read-only (read-write for a shared writable map) and map a page
//	mprotect <prot0> <prot1> <path> [dirty] map a page private at prot0, write a byte first when dirty, mprotect it
//	memfdmap <prot>                        map a page of a new memfd (flags 0) private at prot
//	shmanon <prot>                         map a page MAP_SHARED|MAP_ANONYMOUS readable, mprotect it to prot
//	rie <command...>                       one command under personality(READ_IMPLIES_EXEC), restored after
var planeMapCommands = map[string]func(f []string) string{
	"map": planeMapMap, "mprotect": planeMapMprotect, "memfdmap": planeMapMemfd, "shmanon": planeMapShmAnon,
	"rie": planeMapRIE,
}

func planeMapMap(f []string) string {
	prot, _ := strconv.Atoi(f[1])
	flags, _ := strconv.Atoi(f[2])
	mode := unix.O_RDONLY
	if prot&unix.PROT_WRITE != 0 && flags&unix.MAP_SHARED != 0 {
		mode = unix.O_RDWR
	}
	fd, err := unix.Open(f[3], mode|unix.O_CLOEXEC, 0)
	if err != nil {
		return "err open " + errnoString(err)
	}
	defer unix.Close(fd)
	b, err := unix.Mmap(fd, 0, os.Getpagesize(), prot, flags)
	if err == nil {
		_ = unix.Munmap(b)
	}
	return errnoString(err)
}

func planeMapMprotect(f []string) string {
	p0, _ := strconv.Atoi(f[1])
	p1, _ := strconv.Atoi(f[2])
	fd, err := unix.Open(f[3], unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "err open " + errnoString(err)
	}
	defer unix.Close(fd)
	b, err := unix.Mmap(fd, 0, os.Getpagesize(), p0, unix.MAP_PRIVATE)
	if err != nil {
		return "err mmap " + errnoString(err)
	}
	defer unix.Munmap(b)
	if len(f) > 4 && f[4] == "dirty" {
		b[0] ^= 1 // a copy-on-write page: the mapping gains an anon_vma
	}
	return errnoString(unix.Mprotect(b, p1))
}

func planeMapMemfd(f []string) string {
	prot, _ := strconv.Atoi(f[1])
	fd, err := unix.MemfdCreate("tego-plane-map-test", 0)
	if err != nil {
		return "err memfd " + errnoString(err)
	}
	defer unix.Close(fd)
	if err := unix.Ftruncate(fd, int64(os.Getpagesize())); err != nil {
		return "err ftruncate " + errnoString(err)
	}
	b, err := unix.Mmap(fd, 0, os.Getpagesize(), prot, unix.MAP_PRIVATE)
	if err == nil {
		_ = unix.Munmap(b)
	}
	return errnoString(err)
}

func planeMapShmAnon(f []string) string {
	prot, _ := strconv.Atoi(f[1])
	b, err := unix.Mmap(-1, 0, os.Getpagesize(), unix.PROT_READ, unix.MAP_SHARED|unix.MAP_ANONYMOUS)
	if err != nil {
		return "err mmap " + errnoString(err)
	}
	defer unix.Munmap(b)
	return errnoString(unix.Mprotect(b, prot))
}

// planeMapRIE runs one map or mprotect command under personality(READ_IMPLIES_EXEC) on the helper's thread (a
// task's personality is its own), and restores the old personality after.
func planeMapRIE(f []string) string {
	const readImpliesExec = 0x0400000
	old, _, errno := unix.RawSyscall(unix.SYS_PERSONALITY, 0xffffffff, 0, 0)
	if errno != 0 {
		return "err personality " + errnoString(errno)
	}
	if _, _, errno := unix.RawSyscall(unix.SYS_PERSONALITY, old|readImpliesExec, 0, 0); errno != 0 {
		return "err personality " + errnoString(errno)
	}
	defer unix.RawSyscall(unix.SYS_PERSONALITY, old, 0, 0)
	switch f[1] {
	case "map":
		return planeMapMap(f[1:])
	case "mprotect":
		return planeMapMprotect(f[1:])
	}
	return "err rie runs map or mprotect, not " + f[1]
}

// TestPlaneStepCHooksDecide is TIER3-PLAN §9's exec-map cells for step C (T14), enforce-plane R26 and ADR 0027 on a
// real kernel: in each build and mode this kernel offers, with an exec: section, a PROT_EXEC map of a file under a
// write row is refused unless an exec.allow directory, its own exec row or a name row covers it, and allowed under
// no write row; the same spelled through mprotect, through READ_IMPLIES_EXEC (PROT_READ map, and PROT_NONE mprotected
// to PROT_READ), and through execmem and execmod (a private writable and executable map; a dirtied private map of a
// system file made executable) is refused; a memfd maps executable only with exec.anonymous; shared anonymous
// memory stays anonymous memory; the ELF loader maps an allowed binary under a write row and a system library; a
// mismatched exec row refuses and counts; no exec: section decides nothing; and the same maps outside the run pass.
func TestPlaneStepCHooksDecide(t *testing.T) {
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
					planeMapCells(t, o, mode)
					ran++
				})
			}
		})
	}
	if ran == 0 {
		t.Fatal("no plane build ran in any mode on this kernel")
	}
}

// The step C rows' rule_idx.
const (
	ruleMapW    = 40
	ruleMapX    = 41
	ruleMapT1   = 42
	ruleMapT4   = 43
	ruleMapName = 44
	ruleMapOvl  = 46
)

func planeMapCells(t *testing.T, o Object, mode PlaneMode) {
	const runIdx, gen = 9, 5151
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
	for _, name := range []string{MapPlaneRows, MapPlaneExecRows} {
		inner, err := ebpf.NewMap(spec.Maps[name].InnerMap)
		if err != nil {
			t.Fatalf("inner %s: %v", name, err)
		}
		t.Cleanup(func() { _ = inner.Close() })
		if err := coll.Maps[name].Put(uint32(runIdx), inner); err != nil {
			t.Fatalf("outer %s: %v", name, err)
		}
	}

	// W is a write entry; W/x an exec.allow directory inside it; W/bin/t1 an exec file entry (t2 its hard link under
	// another name, t4 an entry whose row's identity is gone); W/n/t3 matched by a bare-name entry; O no entry.
	root := t.TempDir()
	w, o2 := filepath.Join(root, "w"), filepath.Join(root, "o")
	trueBin, err := exec.LookPath("true")
	if err != nil {
		t.Skipf("no true(1): %v", err)
	}
	if trueBin, err = filepath.EvalSymlinks(trueBin); err != nil {
		t.Fatal(err)
	}
	bin, err := os.ReadFile(trueBin)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"w/drop.so", "w/x/lib.so", "w/x/t6", "w/bin/t1", "w/bin/t4", "w/n/t3", "o/sys.so"} {
		mustWrite(t, filepath.Join(root, f), bin, 0o755)
	}
	if err := os.Link(filepath.Join(w, "bin/t1"), filepath.Join(w, "bin/t2")); err != nil {
		t.Fatal(err)
	}
	tree := &planeTree{tmpls: map[uint32]planeFillTmpl{}}
	tree.hold(t, w, fsRow(gen, ruleMapW, PlaneRowModifyAllow))
	execDir := fsRow(gen, ruleMapX, PlaneRowModifyAllow|PlaneRowExecDir)
	execDir.Row.ExecRule = ruleMapX
	tree.hold(t, filepath.Join(w, "x"), execDir)
	tree.hold(t, filepath.Join(w, "bin/t1"), execRow(t, gen, ruleMapT1, "t1"))
	bad := execRow(t, gen, ruleMapT4, "t4")
	bad.Corrupt = 1
	tree.hold(t, filepath.Join(w, "bin/t4"), bad)
	planeFill(t, coll, runIdx, tree)
	var execInner *ebpf.Map
	if err := coll.Maps[MapPlaneExecRows].Lookup(uint32(runIdx), &execInner); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = execInner.Close() })
	// The slot's header (enforce-plane R6): this run's gen and an exec: section.
	setSlot := func(gen, flags uint32) {
		t.Helper()
		if err := coll.Maps[MapPlaneSlots].Put(uint32(runIdx), PlaneSlot{Gen: gen, Flags: flags}); err != nil {
			t.Fatal(err)
		}
	}
	setSlot(gen, PlaneSlotExecDecides)
	nameKey, _ := PlaneNameKey("t3")
	nm, nl, _ := PlaneExecName("t3")
	if err := execInner.Put(nameKey, PlaneExecRow{Gen: gen, RuleIdx: ruleMapName, NameLen: nl, Name: nm}); err != nil {
		t.Fatal(err)
	}
	if err := coll.Maps[MapPlaneCounters].Put(uint32(runIdx), PlaneCounts{}); err != nil {
		t.Fatal(err)
	}
	var links []link.Link
	t.Cleanup(func() {
		for _, l := range links {
			_ = l.Close()
		}
	})
	for _, h := range PlaneHooksHere(mode) {
		p := coll.Programs[h.Program(mode)]
		if info, err := p.Info(); err == nil {
			if n, ok := info.VerifiedInstructions(); ok && (h.Name == "mmap_file" || h.Name == "file_mprotect") {
				t.Logf("%s: %d instructions verified", h.Program(mode), n)
				if n > planeBudget(h.Name) {
					t.Errorf("%s: %d instructions verified, over the budget of %d", h.Program(mode), n, planeBudget(h.Name))
				}
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

	_, cgfd, cgid := planeChildCgroup(t, "map-"+string(o)+"-"+string(mode))
	helper := startPlaneHelper(t, cgfd)
	runSet := coll.Maps[MapRunSet]
	if err := runSet.Put(cgid, Run{RunIdx: runIdx, Tier: 3, Plane: RunPlaneOf(mode), Gen: gen}); err != nil {
		t.Fatalf("arm: %v", err)
	}
	t.Cleanup(func() { _ = runSet.Delete(cgid) })

	n := strconv.Itoa
	r, rx, rw, rwx := n(unix.PROT_READ), n(unix.PROT_READ|unix.PROT_EXEC), n(unix.PROT_READ|unix.PROT_WRITE),
		n(unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC)
	private, shared := n(unix.MAP_PRIVATE), n(unix.MAP_SHARED)
	pw := func(p string) string { return filepath.Join(w, p) }
	sys := filepath.Join(o2, "sys.so")
	check := func(name, want string, args ...string) {
		t.Helper()
		if got := helper.do(t, args...); got != want {
			t.Errorf("%s: in the run %v answered %s, want %s", name, args, got, want)
		}
	}
	scratch := func(what string, hook uint16, reason uint8, rule uint32) {
		t.Helper()
		var d PlaneDecision
		if err := coll.Maps[MapPlaneScratch].Lookup(int32(helper.pidfd), &d); err != nil {
			t.Errorf("%s: no scratch value for the helper: %v", what, err)
			return
		}
		verdict := uint8(0)
		if reason != 0 {
			verdict = 1
		}
		if d.Hook != hook || d.Verdict != verdict || d.Reason != reason || d.RuleIdx != rule {
			t.Errorf("%s: recorded hook %d verdict %d reason %d rule %d, want %d %d %d %d", what, d.Hook, d.Verdict,
				d.Reason, d.RuleIdx, hook, verdict, reason, rule)
		}
	}
	const hookMmap, hookMprotect = 21, 22
	notAllowed := uint8(ReasonExecNotAllowed)
	if PlaneHooks[hookMmap-1].Name != "mmap_file" || PlaneHooks[hookMprotect-1].Name != "file_mprotect" {
		t.Fatal("enum tego_plane_hook's step C values are not PlaneHooks' positions plus one")
	}

	// (b): a write row, and what covers a file beneath it.
	check("map a file dropped under a write entry", eacces, "map", rx, private, pw("drop.so"))
	scratch("map a file dropped under a write entry", hookMmap, notAllowed, ruleMapW)
	check("map it readable only", "0", "map", r, private, pw("drop.so"))
	check("map a file under an exec.allow directory", "0", "map", rx, private, pw("x/lib.so"))
	scratch("map a file under an exec.allow directory", hookMmap, 0, ruleMapX)
	check("map an exec file entry", "0", "map", rx, private, pw("bin/t1"))
	scratch("map an exec file entry", hookMmap, 0, ruleMapT1)
	check("map its hard link under another name", eacces, "map", rx, private, pw("bin/t2"))
	check("map a file a bare-name entry matches", "0", "map", rx, private, pw("n/t3"))
	check("map an exec entry whose row's identity is gone", eacces, "map", rx, private, pw("bin/t4"))
	scratch("map an exec entry whose row's identity is gone", hookMmap, uint8(ReasonIdentityMismatch), ruleMapT4)
	check("map a file under no write entry", "0", "map", rx, private, sys)
	// The mprotect spelling.
	check("mprotect a dropped file's map to exec", eacces, "mprotect", r, rx, pw("drop.so"))
	scratch("mprotect a dropped file's map to exec", hookMprotect, notAllowed, ruleMapW)
	check("mprotect a map under an exec.allow directory to exec", "0", "mprotect", r, rx, pw("x/lib.so"))
	check("mprotect a map of a file under no write entry to exec", "0", "mprotect", r, rx, sys)
	// (c): execmem and execmod, whatever the file.
	check("a writable and executable private map (execmem)", eacces, "map", rwx, private, sys)
	scratch("a writable and executable private map (execmem)", hookMmap, notAllowed, uint32(PlaneRuleNone))
	check("mprotect a private map to writable and executable (execmem)", eacces, "mprotect", r, rwx, sys)
	check("a dirtied private map made executable (execmod)", eacces, "mprotect", rw, rx, sys, "dirty")
	scratch("a dirtied private map made executable (execmod)", hookMprotect, notAllowed, uint32(PlaneRuleNone))
	check("an untouched writable private map made executable", "0", "mprotect", rw, rx, sys)
	check("a writable shared map of a write entry's file under an exec.allow directory", "0", "map", rwx, shared,
		pw("x/lib.so"))
	// READ_IMPLIES_EXEC: the effective prot decides.
	check("READ_IMPLIES_EXEC: a readable map of a dropped file", eacces, "rie", "map", r, private, pw("drop.so"))
	scratch("READ_IMPLIES_EXEC: a readable map of a dropped file", hookMmap, notAllowed, ruleMapW)
	check("READ_IMPLIES_EXEC: PROT_NONE mprotected to PROT_READ", eacces, "rie", "mprotect", "0", r, pw("drop.so"))
	scratch("READ_IMPLIES_EXEC: PROT_NONE mprotected to PROT_READ", hookMprotect, notAllowed, ruleMapW)
	check("READ_IMPLIES_EXEC: a readable map of a file under no write entry", "0", "rie", "map", r, private, sys)
	check("personality restored: a readable map of a dropped file", "0", "map", r, private, pw("drop.so"))
	// (a): anonymous files, and anonymous memory.
	check("an executable map of a memfd without exec.anonymous", eacces, "memfdmap", rx)
	scratch("an executable map of a memfd without exec.anonymous", hookMmap, notAllowed, uint32(PlaneRuleNone))
	check("a readable map of a memfd", "0", "memfdmap", r)
	check("shared anonymous memory made executable (GAPS A2)", "0", "shmanon", rx)
	// The ELF loader maps what bprm_check lets run: an exec file entry under a write entry, its system libraries.
	check("exec an exec file entry under a write entry", "0", "exec", pw("bin/t1"))
	check("exec a binary under an exec.allow directory", "0", "exec", pw("x/t6"))
	setSlot(gen, PlaneSlotExecDecides|PlaneSlotExecAnon)
	check("an executable map of a memfd with exec.anonymous", "0", "memfdmap", rx)
	setSlot(gen, 0)
	check("no exec: section: map a dropped file", "0", "map", rx, private, pw("drop.so"))
	check("no exec: section: execmem", "0", "map", rwx, private, sys)
	// A slot with no header of the run's gen refuses every executable mapping, whatever flags it carries. A memfd, which
	// file_open never decides (no path), reaches mmap_file itself: allowed by those flags at the run's gen, refused at
	// gen 0 by the header alone.
	setSlot(0, PlaneSlotExecDecides|PlaneSlotExecAnon)
	check("a cleared header: an executable map of a memfd", eacces, "memfdmap", rx)
	scratch("a cleared header: an executable map of a memfd", hookMmap, uint8(ReasonPathUnresolved), uint32(PlaneRuleNone))
	setSlot(gen, PlaneSlotExecDecides)

	// Outside the run every one of them passes.
	for _, c := range [][]string{{"map", rx, private, pw("drop.so")}, {"mprotect", r, rx, pw("drop.so")},
		{"map", rwx, private, sys}, {"mprotect", rw, rx, sys, "dirty"}, {"memfdmap", rx}} {
		if got := planeMapCommands[c[0]](c); got != "0" {
			t.Errorf("outside the run %v answered %s", c, got)
		}
	}
	var counts PlaneCounts
	if err := coll.Maps[MapPlaneCounters].Lookup(uint32(runIdx), &counts); err != nil {
		t.Fatal(err)
	}
	t.Logf("counters: %+v", counts)
	if counts.Mismatch == 0 {
		t.Error("the exec row whose identity is gone did not count a mismatch")
	}
	// The cleared header's one refusal is the one norows count.
	if counts.Unresolved != 0 || counts.Bound != 0 || counts.NoRows != 1 {
		t.Errorf("fail-closed counts: %+v, want mismatch and one norows (the cleared header) only", counts)
	}
	planeMapOverlayCell(t, coll, runIdx, gen, helper)
}

// planeMapOverlayCell maps an overlayfs file whose merged directory is a write row and mprotects it executable. On
// 6.8+ the mapping's file is overlayfs' backing file, whose f_path is the upper or lower layer's, where no row is;
// the body walks from backing_file_user_path(), meets the write row and refuses, and an exec.allow directory on the
// merged path allows. Before 6.8 the file's f_path is the user's path already.
func planeMapOverlayCell(t *testing.T, coll *ebpf.Collection, runIdx, gen uint32, helper *planeHelper) {
	t.Helper()
	root := t.TempDir()
	lower, upper, work, merged := filepath.Join(root, "l"), filepath.Join(root, "u"), filepath.Join(root, "wk"), filepath.Join(root, "m")
	for _, d := range []string{lower, upper, work, merged} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(t, filepath.Join(lower, "lib.so"), make([]byte, os.Getpagesize()), 0o755)
	mustWrite(t, filepath.Join(lower, "x", "lib.so"), make([]byte, os.Getpagesize()), 0o755)
	opts := "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work
	if err := unix.Mount("overlay", merged, "overlay", 0, opts); err != nil {
		t.Logf("no overlayfs here (%v): the backing-file cell is not run", err)
		return
	}
	t.Cleanup(func() { _ = unix.Unmount(merged, unix.MNT_DETACH) })
	p := &planeTree{tmpls: map[uint32]planeFillTmpl{}}
	p.hold(t, merged, fsRow(gen, ruleMapOvl, PlaneRowModifyAllow))
	execDir := fsRow(gen, ruleMapOvl, PlaneRowModifyAllow|PlaneRowExecDir)
	execDir.Row.ExecRule = ruleMapOvl
	p.hold(t, filepath.Join(merged, "x"), execDir)
	planeFill(t, coll, runIdx, p)
	r, rx := strconv.Itoa(unix.PROT_READ), strconv.Itoa(unix.PROT_READ|unix.PROT_EXEC)
	if got := helper.do(t, "mprotect", r, rx, filepath.Join(merged, "lib.so")); got != eacces {
		t.Errorf("an overlay file under a write row mprotected to exec answered %s, want %s", got, eacces)
	}
	if got := helper.do(t, "mprotect", r, rx, filepath.Join(merged, "x", "lib.so")); got != "0" {
		t.Errorf("an overlay file under an exec.allow directory mprotected to exec answered %s, want 0", got)
	}
}
