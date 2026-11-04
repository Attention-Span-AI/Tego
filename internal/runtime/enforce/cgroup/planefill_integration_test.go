// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
)

// fillBuilds returns the fill builds this kernel can load: the rd build needs bpf_rdonly_cast in the kernel's BTF,
// the pr build a lockdown that admits bpf_probe_read_kernel (ADR 0024 (9); the plane probe makes the same choice).
func fillBuilds(t *testing.T) []ebpfbindings.Object {
	t.Helper()
	var out []ebpfbindings.Object
	if kernel, err := btf.LoadKernelSpec(); err == nil {
		var fn *btf.Func
		if kernel.TypeByName("bpf_rdonly_cast", &fn) == nil {
			out = append(out, ebpfbindings.ObjectPlaneFillRdonly)
		}
	}
	if b, err := os.ReadFile("/sys/kernel/security/lockdown"); err != nil || !strings.Contains(string(b), "[confidentiality]") {
		out = append(out, ebpfbindings.ObjectPlaneFillProbe)
	}
	if len(out) == 0 {
		t.Fatal("this kernel can load neither fill build")
	}
	return out
}

// planeSlot is a slot's plane maps for a test: fresh, unpinned outers declared as the plane declares them, with
// the slot's inner maps inserted (T6 creates them on a slot's first use and keeps them).
type planeSlot struct {
	rows, exec, listen *ebpf.Map
	runIdx             uint32
}

func newPlaneSlot(t *testing.T, fill ebpfbindings.Object, runIdx uint32, rowsMax uint32) *planeSlot {
	t.Helper()
	requireBPFCaps(t)
	spec, err := ebpfbindings.Load(fill)
	if err != nil {
		t.Fatal(err)
	}
	s := &planeSlot{runIdx: runIdx}
	for _, m := range []struct {
		name string
		dst  **ebpf.Map
	}{{ebpfbindings.MapPlaneRows, &s.rows}, {ebpfbindings.MapPlaneExecRows, &s.exec}, {ebpfbindings.MapPlaneListenRows, &s.listen}} {
		ms := spec.Maps[m.name].Copy()
		ms.Pinning = ebpf.PinNone
		outer, err := ebpf.NewMap(ms)
		if err != nil {
			t.Fatalf("create %s: %v", m.name, err)
		}
		t.Cleanup(func() { _ = outer.Close() })
		in := ms.InnerMap.Copy()
		if rowsMax != 0 {
			in.MaxEntries = rowsMax // a HASH_OF_MAPS compares no inner max_entries
		}
		inner, err := ebpf.NewMap(in)
		if err != nil {
			t.Fatalf("create %s's inner map: %v", m.name, err)
		}
		if err := outer.Put(runIdx, inner); err != nil {
			t.Fatalf("insert %s's inner map: %v", m.name, err)
		}
		_ = inner.Close()
		*m.dst = outer
	}
	return s
}

// dump reads every row of the slot's inner maps. It is the one place a key (an inode pointer) reaches userspace,
// and only in this test, which discards it: Prepare never iterates a rows map (ADR 0025 (1)).
func (s *planeSlot) dump(t *testing.T) (fs []ebpfbindings.PlaneRow, exec []ebpfbindings.PlaneExecRow) {
	t.Helper()
	var inner *ebpf.Map
	if err := s.rows.Lookup(s.runIdx, &inner); err != nil {
		t.Fatalf("slot %d rows map: %v", s.runIdx, err)
	}
	defer inner.Close()
	var k uint64
	var v ebpfbindings.PlaneRow
	it := inner.Iterate()
	for it.Next(&k, &v) {
		fs = append(fs, v)
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	var einner *ebpf.Map
	if err := s.exec.Lookup(s.runIdx, &einner); err != nil {
		t.Fatalf("slot %d exec-rows map: %v", s.runIdx, err)
	}
	defer einner.Close()
	var ev ebpfbindings.PlaneExecRow
	eit := einner.Iterate()
	for eit.Next(&k, &ev) {
		exec = append(exec, ev)
	}
	if err := eit.Err(); err != nil {
		t.Fatal(err)
	}
	return fs, exec
}

// heldSet opens paths O_PATH|O_NOFOLLOW, as the Landlock set holds a rule's path, and closes them at the end.
type heldSet map[string]int

func holdPaths(t *testing.T, paths ...string) heldSet {
	t.Helper()
	h := heldSet{}
	for _, p := range paths {
		fd, err := unix.Open(p, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("hold %s: %v", p, err)
		}
		h[p] = fd
	}
	t.Cleanup(func() {
		for _, fd := range h {
			_ = unix.Close(fd)
		}
	})
	return h
}

func (h heldSet) held(p string) (int, bool) { fd, ok := h[p]; return fd, ok }

// makeFiles creates n empty files under dir and returns their paths.
func makeFiles(t *testing.T, dir, prefix string, n int) []string {
	t.Helper()
	out := make([]string, n)
	for i := range out {
		out[i] = filepath.Join(dir, fmt.Sprintf("%s%05d", prefix, i))
		if err := os.WriteFile(out[i], nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// fsTable is a PlaneRows of one fs row per path, each with a kind of its own position's parity.
func fsTable(paths []string) *decide.PlaneRows {
	rows := &decide.PlaneRows{}
	for i, p := range paths {
		k := decide.PlaneModifyAllow
		if i%2 == 1 {
			k = decide.PlaneReadDeny
		}
		rows.FS = append(rows.FS, decide.PlaneRow{Path: p, Kind: k})
	}
	return rows
}

func inoOf(t *testing.T, p string) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}

func raiseNoFile(t *testing.T, n uint64) {
	t.Helper()
	var r unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &r); err != nil {
		t.Fatal(err)
	}
	// Set the limit even when it is already high enough: Go remembers the soft limit it started with and gives it
	// back to every child it execs, until a Setrlimit call clears that memory. Without this, a holder this test starts
	// gets the original low limit (1024 on CI), its inherited descriptors fill every slot, and its dynamic loader
	// fails with EMFILE, so the fill sees none of them. Earlier tests in the package hid this: each calls Setrlimit,
	// and the root suites' shards ran this test without them (2026-11-03, PR 21's cgroup-2 shard).
	old := r
	r.Cur = max(r.Cur, n)
	if r.Max < n {
		r.Max = n
	}
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &r); err != nil {
		t.Skipf("raise RLIMIT_NOFILE to %d: %v", n, err)
	}
	t.Cleanup(func() { _ = unix.Setrlimit(unix.RLIMIT_NOFILE, &old) })
}

// TestPlaneFillWritesTheContractsRows covers enforce-plane R16 as root: a slot filled for a table holds exactly
// its rows, each with the run's gen, its rule_idx and kind, at the inode its path names (i_ino read back), and the
// exec row carries its directory, name and entry; the iteration is task-scoped on 6.1+ (every descriptor it showed
// was this process's).
func TestPlaneFillWritesTheContractsRows(t *testing.T) {
	for _, fill := range fillBuilds(t) {
		t.Run(fill.String(), func(t *testing.T) {
			slot := newPlaneSlot(t, fill, 3, 0)
			dir := t.TempDir()
			files := makeFiles(t, dir, "f", 3)
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			tool := makeFiles(t, bin, "tool", 1)[0]
			table := fsTable(append([]string{dir}, files...))
			table.Exec = []decide.PlaneExecRow{{Path: tool, Parent: bin, Name: filepath.Base(tool), Rule: 7}}
			h := holdPaths(t, append(append([]string{dir}, files...), tool)...)
			plan, err := planPlaneFill(table, slot.runIdx, 41, h.held, hostIdentity{})
			if err != nil {
				t.Fatal(err)
			}
			rep, err := fillPlane(fill, slot.rows, slot.exec, plan, table, planeFillOptions{}, slot.listen)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%+v", rep)
			if rep.Rows != 4 || rep.ExecRows != 1 {
				t.Errorf("report %+v, want 4 rows and 1 exec row", rep)
			}
			if rep.Scoped && rep.Visited != rep.Matched {
				t.Errorf("a scoped fill was shown %d descriptors, %d of them this process's", rep.Visited, rep.Matched)
			}
			fs, exec := slot.dump(t)
			if len(fs) != 4 || len(exec) != 1 {
				t.Fatalf("slot holds %d rows and %d exec rows, want 4 and 1", len(fs), len(exec))
			}
			byIno := map[uint64]ebpfbindings.PlaneRow{}
			for _, r := range fs {
				byIno[r.Ino] = r
			}
			for i, r := range table.FS {
				got, ok := byIno[inoOf(t, r.Path)]
				if !ok {
					t.Errorf("no row at %s's inode", r.Path)
					continue
				}
				if got.Gen != 41 || got.RuleIdx != uint16(i) || got.Kind != uint8(r.Kind) || got.Dev == 0 {
					t.Errorf("%s: row %+v, want gen 41, rule_idx %d, kind %d", r.Path, got, i, r.Kind)
				}
			}
			e := exec[0]
			if e.Ino != inoOf(t, tool) || e.ParentIno != inoOf(t, bin) || e.Gen != 41 || e.RuleIdx != 7 ||
				string(e.Name[:e.NameLen]) != filepath.Base(tool) || e.Parent == 0 || e.Name[e.NameLen] != 0 {
				t.Errorf("exec row %+v", e)
			}
		})
	}
}

// TestPlaneFillFailsOnAReusedDescriptor covers enforce-plane R16's reuse case: a descriptor number the plan
// recorded for one file that names another by the fill (closed and taken by another open, here dup3'd over)
// fails the fill, naming the reuse, whatever row the kernel wrote at the other inode.
func TestPlaneFillFailsOnAReusedDescriptor(t *testing.T) {
	fill := fillBuilds(t)[0]
	slot := newPlaneSlot(t, fill, 4, 0)
	dir := t.TempDir()
	files := makeFiles(t, dir, "f", 2)
	other := makeFiles(t, dir, "other", 1)[0]
	table := fsTable(files)
	h := holdPaths(t, files...)
	plan, err := planPlaneFill(table, slot.runIdx, 5, h.held, hostIdentity{})
	if err != nil {
		t.Fatal(err)
	}
	ofd, err := unix.Open(other, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Dup3(ofd, h[files[1]], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(ofd)
	_, err = fillPlane(fill, slot.rows, slot.exec, plan, table, planeFillOptions{}, slot.listen)
	var pf *ErrPlaneFill
	if !errors.As(err, &pf) || len(pf.Problems) != 1 || !strings.Contains(err.Error(), files[1]) ||
		!strings.Contains(err.Error(), "the number was reused") {
		t.Fatalf("fill over a reused descriptor: %v", err)
	}
}

// TestPlaneFillKeysEachHardLinkOfOneInode covers enforce-plane R16 for a multi-call binary (enforce-plane §6 E15; ADR 0025's
// 2026-09-30 note) as root: three exec entries naming three hard links of one inode (uutils' ls and cat, busybox's
// applets), two in one directory and one under the first's name in another, each held at its own descriptor, get
// one row each, under that link's directory and name and that entry's rule_idx. Before the note the fill refused
// the second as a duplicate and Prepare failed.
func TestPlaneFillKeysEachHardLinkOfOneInode(t *testing.T) {
	for _, fill := range fillBuilds(t) {
		t.Run(fill.String(), func(t *testing.T) {
			slot := newPlaneSlot(t, fill, 5, 0)
			dir := t.TempDir()
			a := makeFiles(t, dir, "a", 1)[0]
			b := filepath.Join(dir, "b")
			if err := os.Link(a, b); err != nil {
				t.Fatal(err)
			}
			other := filepath.Join(dir, "sub")
			if err := os.Mkdir(other, 0o700); err != nil {
				t.Fatal(err)
			}
			c := filepath.Join(other, filepath.Base(a))
			if err := os.Link(a, c); err != nil {
				t.Fatal(err)
			}
			table := &decide.PlaneRows{Exec: []decide.PlaneExecRow{
				{Path: a, Parent: dir, Name: filepath.Base(a), Rule: 0},
				{Path: b, Parent: dir, Name: "b", Rule: 1},
				{Path: c, Parent: other, Name: filepath.Base(a), Rule: 2},
			}}
			h := holdPaths(t, a, b, c)
			plan, err := planPlaneFill(table, slot.runIdx, 6, h.held, hostIdentity{})
			if err != nil {
				t.Fatal(err)
			}
			rep, err := fillPlane(fill, slot.rows, slot.exec, plan, table, planeFillOptions{}, slot.listen)
			if err != nil {
				t.Fatalf("three exec entries on three links of one inode: %v", err)
			}
			if rep.ExecRows != 3 {
				t.Errorf("report %+v, want 3 exec rows", rep)
			}
			_, rows := slot.dump(t)
			if len(rows) != 3 {
				t.Fatalf("slot holds %d exec rows, want 3", len(rows))
			}
			byRule := map[uint16]ebpfbindings.PlaneExecRow{}
			for _, e := range rows {
				byRule[e.RuleIdx] = e
			}
			for _, r := range table.Exec {
				e, ok := byRule[uint16(r.Rule)]
				if !ok {
					t.Errorf("no exec row for entry %d (%s)", r.Rule, r.Path)
					continue
				}
				if e.Ino != inoOf(t, a) || e.ParentIno != inoOf(t, r.Parent) || e.Gen != 6 ||
					string(e.Name[:e.NameLen]) != r.Name || e.Parent == 0 {
					t.Errorf("entry %d (%s): exec row %+v", r.Rule, r.Path, e)
				}
			}
		})
	}
}

// TestPlaneFillRefusesOneLinkTwice covers enforce-plane R16's duplicate as root: two exec entries whose paths are
// two spellings of one link (one directory entry reached twice), held at two descriptors, key one row; the fill
// refuses the second (the first's row of this gen is at its key) instead of one row silently keeping one rule.
func TestPlaneFillRefusesOneLinkTwice(t *testing.T) {
	fill := fillBuilds(t)[0]
	slot := newPlaneSlot(t, fill, 5, 0)
	dir := t.TempDir()
	a := makeFiles(t, dir, "a", 1)[0]
	again := dir + "/./" + filepath.Base(a) // filepath.Join would clean the "."
	table := &decide.PlaneRows{Exec: []decide.PlaneExecRow{
		{Path: a, Parent: dir, Name: filepath.Base(a), Rule: 0},
		{Path: again, Parent: dir, Name: filepath.Base(a), Rule: 1},
	}}
	h := holdPaths(t, a, again)
	plan, err := planPlaneFill(table, slot.runIdx, 6, h.held, hostIdentity{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = fillPlane(fill, slot.rows, slot.exec, plan, table, planeFillOptions{}, slot.listen)
	if err == nil || !strings.Contains(err.Error(), "another entry of this run already keys") {
		t.Fatalf("two exec entries on one link: %v", err)
	}
}

// TestPlaneFillSlotReuseLeavesStaleRowsAbsent covers enforce-plane R6 and ADR 0026 (6) as amended: a slot reused
// by a second run keeps the first run's rows under their own gen (nothing deleted on the run's path); the second
// run's rows are exactly its table, a key both runs name is rewritten with the new gen, and the kernel clear
// removes only the stale rows. A map too full of stale rows to take the new run's makes the fill clear them and
// fill again.
func TestPlaneFillSlotReuseLeavesStaleRowsAbsent(t *testing.T) {
	fill := fillBuilds(t)[0]
	t.Run("walked past", func(t *testing.T) {
		slot := newPlaneSlot(t, fill, 6, 0)
		f, err := newPlaneFiller(fill, slot.rows, slot.exec, slot.listen)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		dir := t.TempDir()
		files := makeFiles(t, dir, "f", 4) // run 1: 0, 1, 2; run 2: 2, 3
		h := holdPaths(t, files...)
		for _, run := range []struct {
			gen   uint32
			paths []string
		}{{100, files[:3]}, {101, files[2:]}} {
			table := fsTable(run.paths)
			plan, err := planPlaneFill(table, slot.runIdx, run.gen, h.held, hostIdentity{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.fill(plan, table, planeFillOptions{}); err != nil {
				t.Fatalf("gen %d: %v", run.gen, err)
			}
		}
		fs, _ := slot.dump(t)
		cur, stale := map[uint64]bool{}, map[uint64]bool{}
		for _, r := range fs {
			switch r.Gen {
			case 101:
				cur[r.Ino] = true
			case 100:
				stale[r.Ino] = true
			default:
				t.Errorf("a row of gen %d", r.Gen)
			}
		}
		if len(cur) != 2 || !cur[inoOf(t, files[2])] || !cur[inoOf(t, files[3])] {
			t.Errorf("gen 101 rows %v, want files 2 and 3", cur)
		}
		if len(stale) != 2 || !stale[inoOf(t, files[0])] || !stale[inoOf(t, files[1])] {
			t.Errorf("gen 100 rows %v, want files 0 and 1 left stale", stale)
		}
		start := time.Now()
		del, edel, err := f.clearSlot(slot.runIdx, 101)
		if err != nil || del != 2 || edel != 0 {
			t.Fatalf("clear: %d %d %v, want the 2 stale rows", del, edel, err)
		}
		t.Logf("clear of 2 stale rows: %v", time.Since(start))
		if fs, _ = slot.dump(t); len(fs) != 2 {
			t.Errorf("%d rows after the clear, want 2", len(fs))
		}
	})
	t.Run("full of stale rows", func(t *testing.T) {
		slot := newPlaneSlot(t, fill, 7, 3)
		dir := t.TempDir()
		files := makeFiles(t, dir, "f", 5) // run 1: 0, 1, 2 fill the map; run 2: 3, 4
		h := holdPaths(t, files...)
		t1 := fsTable(files[:3])
		p1, err := planPlaneFill(t1, slot.runIdx, 200, h.held, hostIdentity{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fillPlane(fill, slot.rows, slot.exec, p1, t1, planeFillOptions{}, slot.listen); err != nil {
			t.Fatal(err)
		}
		t2 := fsTable(files[3:])
		p2, err := planPlaneFill(t2, slot.runIdx, 201, h.held, hostIdentity{})
		if err != nil {
			t.Fatal(err)
		}
		rep, err := fillPlane(fill, slot.rows, slot.exec, p2, t2, planeFillOptions{}, slot.listen)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Cleared != 3 {
			t.Errorf("cleared %d stale rows, want 3", rep.Cleared)
		}
		fs, _ := slot.dump(t)
		if len(fs) != 2 || fs[0].Gen != 201 || fs[1].Gen != 201 {
			t.Errorf("rows %+v, want run 2's two", fs)
		}
	})
}

// TestPlaneFillTiming records what a fill costs at 100, 1000 and 4096 rows (a slot's cap), scoped and unscoped,
// with the filler's one-time load apart from each fill's templates, passes and fdinfo check
// (docs/p0/enforce-plane.md §2.6 keeps the figures). Unscoped is what a kernel before 6.1 (RHEL 9's 5.14) pays:
// every task's descriptors are shown to the program. The slot is cleared between fills, off the timed path, and
// the clear is timed too.
func TestPlaneFillTiming(t *testing.T) {
	raiseNoFile(t, 8192)
	dir := t.TempDir()
	files := makeFiles(t, dir, "f", 4096)
	h := holdPaths(t, files...)
	for _, fill := range fillBuilds(t) {
		slot := newPlaneSlot(t, fill, 9, 0)
		start := time.Now()
		spec, err := ebpfbindings.Load(fill)
		if err != nil || spec == nil {
			t.Fatal(err)
		}
		parse := time.Since(start)
		f, err := newPlaneFiller(fill, slot.rows, slot.exec, slot.listen)
		if err != nil {
			t.Fatal(err)
		}
		if info, err := f.prog.Info(); err == nil {
			if n, ok := info.VerifiedInstructions(); ok {
				t.Logf("fill %s: %d instructions verified", fill, n)
			}
		}
		t.Logf("fill %s: filler load %v (ELF parse %v)", fill, f.Load, parse)
		gen := uint32(1)
		for _, n := range []int{100, 1000, 4096} {
			for _, unscoped := range []bool{false, true} {
				table := fsTable(files[:n])
				plan, err := planPlaneFill(table, slot.runIdx, gen, h.held, hostIdentity{})
				if err != nil {
					t.Fatal(err)
				}
				start := time.Now()
				rep, err := f.fill(plan, table, planeFillOptions{Unscoped: unscoped})
				total := time.Since(start)
				if err != nil {
					t.Fatalf("%d rows: %v", n, err)
				}
				if rep.Rows != n || rep.Cleared != 0 {
					t.Fatalf("%d rows written, %d cleared, want %d and 0", rep.Rows, rep.Cleared, n)
				}
				start = time.Now()
				del, _, err := f.clearSlot(slot.runIdx, 0)
				if err != nil || del != n {
					t.Fatalf("clear: %d, %v, want %d", del, err, n)
				}
				t.Logf("fill %s rows=%d scoped=%v visited=%d matched=%d wants=%v fill=%v check=%v total=%v clear=%v",
					fill, n, rep.Scoped, rep.Visited, rep.Matched, rep.Wants, rep.Fill, rep.Check, total, time.Since(start))
				gen++
			}
		}
		_ = f.Close()
	}
}

// TestPlaneFillUnscopedOnABusyHost records what the unscoped iteration a kernel before 6.1 falls back to costs
// when other processes hold many descriptors (ADR 0025's plan: 2,000 processes and 200k descriptors; here 20
// sleeping children holding 10,000 each, 200k in all): a 100-row fill scoped and unscoped. On 5.14 both are
// unscoped, which the visited count shows.
func TestPlaneFillUnscopedOnABusyHost(t *testing.T) {
	const children, each = 20, 10000
	raiseNoFile(t, each+8192)
	for i := 0; i < children; i++ {
		// Each holder gets its own descriptors, opened here and closed here once it has them.
		extra := make([]*os.File, each)
		for j := range extra {
			f, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal(err)
			}
			extra[j] = f
		}
		cmd := exec.Command("sleep", "600")
		cmd.ExtraFiles = extra
		err := cmd.Start()
		for _, f := range extra {
			_ = f.Close()
		}
		if err != nil {
			t.Fatalf("start a descriptor holder: %v", err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	}
	dir := t.TempDir()
	files := makeFiles(t, dir, "f", 100)
	h := holdPaths(t, files...)
	fill := fillBuilds(t)[0]
	slot := newPlaneSlot(t, fill, 10, 0)
	f, err := newPlaneFiller(fill, slot.rows, slot.exec, slot.listen)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for i, unscoped := range []bool{false, true, false, true} {
		table := fsTable(files)
		plan, err := planPlaneFill(table, slot.runIdx, uint32(i+1), h.held, hostIdentity{})
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		rep, err := f.fill(plan, table, planeFillOptions{Unscoped: unscoped})
		total := time.Since(start)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.clearSlot(slot.runIdx, 0); err != nil {
			t.Fatal(err)
		}
		t.Logf("fill %s rows=100 unscoped-requested=%v scoped=%v visited=%d matched=%d fill=%v total=%v",
			fill, unscoped, rep.Scoped, rep.Visited, rep.Matched, rep.Fill, total)
		if unscoped && rep.Visited < children*each {
			t.Errorf("an unscoped fill was shown %d descriptors, fewer than the %d the holders have", rep.Visited, children*each)
		}
	}
}
