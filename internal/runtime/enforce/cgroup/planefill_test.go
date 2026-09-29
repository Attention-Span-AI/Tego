// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
)

// fakeIdentity is fdIdentity over tables: fds maps a descriptor to (mnt_id, dev, ino), paths a path to (dev, ino).
type fakeIdentity struct {
	fds   map[int][3]uint64
	paths map[string][2]uint64
	// missing are the paths lstat answers ENOENT for.
	missing map[string]bool
}

func (f *fakeIdentity) fd(fd int) (uint64, uint64, uint64, error) {
	v, ok := f.fds[fd]
	if !ok {
		return 0, 0, 0, errors.New("EBADF")
	}
	return v[1], v[2], v[0], nil
}

func (f *fakeIdentity) path(path string) (uint64, uint64, error) {
	if f.missing[path] {
		return 0, 0, os.ErrNotExist
	}
	v, ok := f.paths[path]
	if !ok {
		return 0, 0, errors.New("ENOENT")
	}
	return v[0], v[1], nil
}

// fillFixture is a table of two fs rows and one exec row, held at descriptors 10, 11 and 12, each file its own
// inode on mount 30 (dev 7), the exec file's directory inode 200.
func fillFixture() (*decide.PlaneRows, map[string]int, *fakeIdentity) {
	rows := &decide.PlaneRows{
		FS: []decide.PlaneRow{
			{Path: "/w", Kind: decide.PlaneModifyAllow},
			{Path: "/w/secret", Kind: decide.PlaneReadDeny},
		},
		Exec: []decide.PlaneExecRow{{Path: "/usr/bin/tool", Parent: "/usr/bin", Name: "tool", Rule: 3}},
	}
	held := map[string]int{"/w": 11, "/w/secret": 10, "/usr/bin/tool": 12}
	id := &fakeIdentity{
		fds:   map[int][3]uint64{10: {30, 7, 101}, 11: {30, 7, 100}, 12: {30, 7, 102}},
		paths: map[string][2]uint64{"/w": {7, 100}, "/w/secret": {7, 101}, "/usr/bin/tool": {7, 102}, "/usr/bin": {7, 200}},
	}
	return rows, held, id
}

func heldOf(m map[string]int) heldFD {
	return func(p string) (int, bool) { fd, ok := m[p]; return fd, ok }
}

// TestPlanPlaneFillTemplates covers enforce-plane R16's plan: one entry per fs row and exec row at its held
// descriptor, an fs row's rule_idx its position in PlaneRows.FS and its kind the row's, an exec row's rule_idx its
// entry with the final name, the identity recorded, and the plan ordered by (what, descriptor), which is the order
// the wanted-row keys take.
func TestPlanPlaneFillTemplates(t *testing.T) {
	rows, held, id := fillFixture()
	plan, err := planPlaneFill(rows, 5, 77, heldOf(held), id)
	if err != nil {
		t.Fatal(err)
	}
	if plan.RunIdx != 5 || plan.Gen != 77 || len(plan.Entries) != 3 {
		t.Fatalf("plan %+v", plan)
	}
	want := []planeFillEntry{
		{FD: 10, Path: "/w/secret", What: ebpfbindings.PlaneFillFS, Kind: uint8(decide.PlaneReadDeny), RuleIdx: 1, MntID: 30, Ino: 101, Dev: 7},
		{FD: 11, Path: "/w", What: ebpfbindings.PlaneFillFS, Kind: uint8(decide.PlaneModifyAllow), RuleIdx: 0, MntID: 30, Ino: 100, Dev: 7},
		{FD: 12, Path: "/usr/bin/tool", What: ebpfbindings.PlaneFillExec, RuleIdx: 3, Name: "tool", Parent: "/usr/bin", MntID: 30, Ino: 102, ParentIno: 200, Dev: 7},
	}
	for i, w := range want {
		if plan.Entries[i] != w {
			t.Errorf("entry %d = %+v, want %+v", i, plan.Entries[i], w)
		}
	}
	keys, vals := plan.wants(4242)
	if keys[0] != 4242<<32|1<<30|10 || keys[2] != 4242<<32|2<<30|12 {
		t.Errorf("keys %x: want tgid<<32|what<<30|fd", keys)
	}
	for i, v := range vals {
		if v.Gen != 77 {
			t.Errorf("template %d carries gen %d, want the plan's 77", i, v.Gen)
		}
	}
	if vals[2].What != ebpfbindings.PlaneFillExec || vals[2].NameLen != 4 || string(vals[2].Name[:5]) != "tool\x00" || vals[2].RuleIdx != 3 {
		t.Errorf("exec template %+v", vals[2])
	}
	if vals[0].Status != ebpfbindings.PlaneFillUnseen || vals[1].Kind != uint8(decide.PlaneModifyAllow) {
		t.Errorf("fs templates %+v %+v", vals[0], vals[1])
	}
}

// TestPlaneKeyedIsWhereTheFsRowsAreWritten: the files a fill reports keyed (Handle.PlaneKeyed) are its fs rows, each by
// its path with the device and inode its descriptor had when the plan was made (the identity the check holds the
// written row to); exec rows and a mount-only row are not files an fs rule decides by their inode.
func TestPlaneKeyedIsWhereTheFsRowsAreWritten(t *testing.T) {
	rows, held, id := fillFixture()
	rows.Mounts = []decide.PlaneMountRow{{Path: "/w/mnt", Row: 0}}
	held["/w/mnt"] = 13
	id.fds[13] = [3]uint64{31, 8, 1}
	id.paths["/w/mnt"] = [2]uint64{8, 1}
	plan, err := planPlaneFill(rows, 5, 77, heldOf(held), id)
	if err != nil {
		t.Fatal(err)
	}
	want := []PlaneKeyed{{Path: "/w/secret", Dev: 7, Ino: 101}, {Path: "/w", Dev: 7, Ino: 100}}
	if got := plan.keyed(); !slices.Equal(got, want) {
		t.Errorf("keyed %+v, want %+v", got, want)
	}
	h := &Handle{plane: &fakePlane{}, planeMode: ebpfbindings.PlaneFmodRet}
	if got, ok := h.PlaneKeyed(); ok || got != nil {
		t.Errorf("before a fill: %v %v, want nothing and not ok", got, ok)
	}
	h.planeKeyed, h.planeFilled = want, true
	if got, ok := h.PlaneKeyed(); !ok || !slices.Equal(got, want) {
		t.Errorf("after a fill: %v %v, want %v", got, ok, want)
	}
	if got, ok := (&Handle{planeKeyed: want, planeFilled: true}).PlaneKeyed(); ok || got != nil {
		t.Errorf("a run with no plane: %v %v, want nothing and not ok", got, ok)
	}
}

// TestPlanPlaneFillRefuses covers what the plan refuses before any row is written: a table over the slot's maps,
// gen 0, a keyed path nothing holds, two exec entries on one descriptor (TIER3-PLAN T5's condition 4: two exec
// entries naming one inode refuse Prepare) and two fs rows on one, a name longer than a row holds, and a
// descriptor that no longer names its path (a number reused before the plan). An fs row and an exec row may
// share a descriptor: they go to two maps.
func TestPlanPlaneFillRefuses(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*decide.PlaneRows, map[string]int, *fakeIdentity)
		gen    uint32
		want   string
	}{
		{"over the cap", func(r *decide.PlaneRows, _ map[string]int, _ *fakeIdentity) {
			r.Exec = make([]decide.PlaneExecRow, decide.PlaneExecRowsMax+1)
		}, 1, "1025 exec rows"},
		{"the name rows over the exec cap", func(r *decide.PlaneRows, _ map[string]int, _ *fakeIdentity) {
			r.ExecPolicy = true
			r.Exec = make([]decide.PlaneExecRow, decide.PlaneExecRowsMax-1)
			r.Names = []decide.PlaneExecName{{Name: "tool", Rule: 0}, {Name: "other", Rule: 1}}
		}, 1, "1025 exec rows"},
		{"gen 0", func(*decide.PlaneRows, map[string]int, *fakeIdentity) {}, 0, "gen 0"},
		{"not held", func(_ *decide.PlaneRows, h map[string]int, _ *fakeIdentity) { delete(h, "/w/secret") }, 1, "no descriptor holds it"},
		{"two exec entries, one descriptor", func(r *decide.PlaneRows, h map[string]int, id *fakeIdentity) {
			r.Exec = append(r.Exec, decide.PlaneExecRow{Path: "/usr/bin/alias", Parent: "/usr/bin", Name: "alias", Rule: 4})
			h["/usr/bin/alias"] = 12
			id.paths["/usr/bin/alias"] = [2]uint64{7, 102}
		}, 1, "two exec entries, /usr/bin/tool and /usr/bin/alias, are held at one descriptor"},
		{"two fs rows, one inode", func(r *decide.PlaneRows, h map[string]int, id *fakeIdentity) {
			r.FS = append(r.FS, decide.PlaneRow{Path: "/x"})
			h["/x"] = 10
			id.paths["/x"] = [2]uint64{7, 101}
		}, 1, "two fs rows"},
		{"name too long", func(r *decide.PlaneRows, _ map[string]int, _ *fakeIdentity) {
			r.Exec[0].Name = strings.Repeat("n", ebpfbindings.NameMax)
		}, 1, "final name of 256 bytes"},
		{"rule at the last index", func(r *decide.PlaneRows, _ map[string]int, _ *fakeIdentity) {
			r.Exec[0].Rule = int(ebpfbindings.PlaneRuleMax)
		}, 1, ""},
		{"rule is RULE_NONE", func(r *decide.PlaneRows, _ map[string]int, _ *fakeIdentity) {
			r.Exec[0].Rule = int(ebpfbindings.PlaneRuleNone)
		}, 1, "past a row's rule_idx"},
		{"reused before the plan", func(_ *decide.PlaneRows, _ map[string]int, id *fakeIdentity) {
			id.fds[10] = [3]uint64{30, 7, 999}
		}, 1, "names another file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows, held, id := fillFixture()
			tc.mutate(rows, held, id)
			_, err := planPlaneFill(rows, 0, tc.gen, heldOf(held), id)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one containing %q", err, tc.want)
			}
		})
	}
	t.Run("fs and exec rows share a descriptor", func(t *testing.T) {
		rows, held, id := fillFixture()
		rows.FS = append(rows.FS, decide.PlaneRow{Path: "/usr/bin/tool"})
		if _, err := planPlaneFill(rows, 0, 1, heldOf(held), id); err != nil {
			t.Fatalf("refused: %v", err)
		}
	})
}

// okResults is what a fill that went as planned reports for plan.
func okResults(plan *planeFillPlan) []ebpfbindings.PlaneFillRow {
	got := make([]ebpfbindings.PlaneFillRow, len(plan.Entries))
	for i, e := range plan.Entries {
		got[i] = ebpfbindings.PlaneFillRow{What: e.What, Status: ebpfbindings.PlaneFillOK, MntID: e.MntID, Ino: e.Ino, ParentIno: e.ParentIno}
	}
	return got
}

// TestCheckPlaneFill covers enforce-plane R16's check: a fill passes only when every row is written, at the
// identity the plan recorded, as the kernel reported it at the pass. A descriptor number reused between the plan
// and the fill (the kernel saw another inode there) fails, as does a row the kernel could not write, one it never
// saw, an exec file whose directory changed, and a second row on one inode, which names the first. A number reused
// after the pass is not asked about: its row was written at the planned inode (§2.6, 2026-09-30).
func TestCheckPlaneFill(t *testing.T) {
	rows, held, id := fillFixture()
	plan, err := planPlaneFill(rows, 0, 9, heldOf(held), id)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkPlaneFill(plan, okResults(plan), rows); err != nil {
		t.Fatalf("a fill as planned: %v", err)
	}
	cases := []struct {
		name   string
		mutate func([]ebpfbindings.PlaneFillRow, *fakeIdentity)
		want   string
	}{
		{"reused before the fill", func(g []ebpfbindings.PlaneFillRow, _ *fakeIdentity) { g[0].Ino = 555 }, "named mount 30 inode 555 at the fill"},
		{"another mount", func(g []ebpfbindings.PlaneFillRow, _ *fakeIdentity) { g[1].MntID = 31 }, "the number was reused"},
		{"not open", func(g []ebpfbindings.PlaneFillRow, _ *fakeIdentity) { g[0].Status = ebpfbindings.PlaneFillUnseen }, "not open in the launcher"},
		{"no map", func(g []ebpfbindings.PlaneFillRow, _ *fakeIdentity) { g[2].Status = ebpfbindings.PlaneFillNoMap }, "no rows map"},
		{"full", func(g []ebpfbindings.PlaneFillRow, _ *fakeIdentity) {
			g[0].Status, g[0].Err = ebpfbindings.PlaneFillUpdate, -7
		}, "argument list too long"},
		{"duplicate", func(g []ebpfbindings.PlaneFillRow, _ *fakeIdentity) {
			g[1].Status, g[1].OtherRule = ebpfbindings.PlaneFillDup, 1
		}, "/w: another entry of this run already keys the same inode (fs) or link (exec) (the same inode as /w/secret)"},
		{"duplicate exec", func(g []ebpfbindings.PlaneFillRow, _ *fakeIdentity) {
			g[2].Status, g[2].OtherRule = ebpfbindings.PlaneFillDup, 3
		}, "the same link as /usr/bin/tool"},
		{"exec moved", func(g []ebpfbindings.PlaneFillRow, _ *fakeIdentity) { g[2].ParentIno = 201 }, "it moved"},
		{"name", func(g []ebpfbindings.PlaneFillRow, _ *fakeIdentity) { g[2].Status = ebpfbindings.PlaneFillName }, "not the exec entry's"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, id := fillFixture()
			got := okResults(plan)
			tc.mutate(got, id)
			err := checkPlaneFill(plan, got, rows)
			var pf *ErrPlaneFill
			if !errors.As(err, &pf) || len(pf.Problems) != 1 || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one problem containing %q", err, tc.want)
			}
		})
	}
	if err := checkPlaneFill(plan, okResults(plan)[:2], rows); err == nil {
		t.Error("a short result list passed")
	}
}

// TestErrPlaneFillNamesTheFirstFive keeps a failed fill's message readable at 4096 rows.
func TestErrPlaneFillNamesTheFirstFive(t *testing.T) {
	e := &ErrPlaneFill{Problems: []string{"a", "b", "c", "d", "e", "f", "g"}}
	if got := e.Error(); !strings.HasSuffix(got, "a; b; c; d; e; and 2 more") || !strings.Contains(got, "7 row(s)") {
		t.Errorf("%q", got)
	}
}

// TestParseFDInfo reads the two lines the check compares, from fdinfo as 5.14 and 6.x print it for an O_PATH file.
func TestParseFDInfo(t *testing.T) {
	mnt, ino, err := parseFDInfo([]byte("pos:\t0\nflags:\t012000000\nmnt_id:\t26\nino:\t1837461\n"))
	if err != nil || mnt != 26 || ino != 1837461 {
		t.Fatalf("got %d %d %v", mnt, ino, err)
	}
	if _, _, err := parseFDInfo([]byte("pos:\t0\nflags:\t0\nmnt_id:\t26\n")); err == nil {
		t.Error("no ino line parsed")
	}
	if _, _, err := parseFDInfo([]byte("mnt_id:\tx\nino:\t1\n")); err == nil {
		t.Error("a bad mnt_id parsed")
	}
}

// TestFullRows picks the rows a map refused for want of room (E2BIG), which the fill clears stale rows for and
// fills again, and nothing else.
func TestFullRows(t *testing.T) {
	got := []ebpfbindings.PlaneFillRow{
		{Status: ebpfbindings.PlaneFillOK},
		{Status: ebpfbindings.PlaneFillUpdate, Err: -7},
		{Status: ebpfbindings.PlaneFillUpdate, Err: -12},
		{Status: ebpfbindings.PlaneFillUpdate, Err: -7},
	}
	if f := fullRows(got); len(f) != 2 || f[0] != 1 || f[1] != 3 {
		t.Errorf("fullRows = %v", f)
	}
}

// TestClearOfASlotWithNoRowsMap: the reaper purges every dead slot through every pinned plane of the build, and a
// slot no run of that mode prepared has no rows map (the clear program's status 1). The slot's clear takes that as
// nothing to clear, not an error that fails the purge; the fill's own clear, whose slot it prepared, still fails.
func TestClearOfASlotWithNoRowsMap(t *testing.T) {
	status := int32(1)
	f := &planeFiller{runClear: func(in ebpfbindings.PlaneClearCtx) (ebpfbindings.PlaneClearCtx, error) {
		in.Status = status
		return in, nil
	}}
	p := &bpfPlane{filler: f}
	if err := p.clearSlot(3); err != nil {
		t.Errorf("clearSlot of a slot with no rows map: %v, want nothing to clear", err)
	}
	if _, _, err := f.clearSlot(3, 7); !errors.Is(err, errPlaneNoRows) {
		t.Errorf("the filler's clear of a slot with no rows map: %v, want errPlaneNoRows", err)
	}
	status = 0
	if err := p.clearSlot(3); err != nil {
		t.Errorf("clearSlot of a prepared slot: %v", err)
	}
	f.runClear = func(ebpfbindings.PlaneClearCtx) (ebpfbindings.PlaneClearCtx, error) {
		return ebpfbindings.PlaneClearCtx{}, errors.New("EPERM")
	}
	if err := p.clearSlot(3); err == nil {
		t.Error("clearSlot hid a clear that did not run")
	}
}

// fakeKeys is a fill map for the purges: its keys in order, listed as a hash map lists them (NextKey of a key gives
// the one after it, of nil the first), with uint64 keys (the wants map) or uint32 (the configs).
type fakeKeys struct {
	keys    map[uint64]bool
	nextErr error
}

func (m *fakeKeys) NextKey(key, out any) error {
	if m.nextErr != nil {
		return m.nextErr
	}
	sorted := slices.Sorted(maps.Keys(m.keys))
	i := 0
	if key != nil {
		var k uint64
		switch v := key.(type) {
		case uint64:
			k = v
		case uint32:
			k = uint64(v)
		}
		i, _ = slices.BinarySearch(sorted, k+1)
	}
	if i >= len(sorted) {
		return ebpf.ErrKeyNotExist
	}
	switch o := out.(type) {
	case *uint64:
		*o = sorted[i]
	case *uint32:
		*o = uint32(sorted[i])
	}
	return nil
}

func (m *fakeKeys) Delete(key any) error {
	var k uint64
	switch v := key.(type) {
	case uint64:
		k = v
	case uint32:
		k = uint64(v)
	}
	if !m.keys[k] {
		return ebpf.ErrKeyNotExist
	}
	delete(m.keys, k)
	return nil
}

// TestPurgeStaleWantsRemovesOnlyDeadFillsTemplates: the wants map is shared by every launcher of the build, each
// keying its templates by its tgid. A fill that finds it full removes the templates of launchers that are gone and
// its own process's leftovers, never a live launcher's filling now; the configs likewise, its own kept. A map it
// cannot list fails the fill.
func TestPurgeStaleWantsRemovesOnlyDeadFillsTemplates(t *testing.T) {
	const self, live, dead = 100, 200, 300
	gone := func(tgid uint32) bool { return tgid == dead }
	key := ebpfbindings.PlaneFillKey
	m := &fakeKeys{keys: map[uint64]bool{
		key(self, ebpfbindings.PlaneFillFS, 7): true, key(live, ebpfbindings.PlaneFillFS, 7): true,
		key(live, ebpfbindings.PlaneFillExec, 9): true, key(dead, ebpfbindings.PlaneFillFS, 7): true,
		key(dead, ebpfbindings.PlaneFillExec, 1<<30-1): true,
	}}
	if err := purgeStaleWants(m, self, gone); err != nil {
		t.Fatal(err)
	}
	if want := []uint64{key(live, ebpfbindings.PlaneFillFS, 7), key(live, ebpfbindings.PlaneFillExec, 9)}; !slices.Equal(slices.Sorted(maps.Keys(m.keys)), want) {
		t.Errorf("left %x, want the live launcher's %x", slices.Sorted(maps.Keys(m.keys)), want)
	}
	cfgs := &fakeKeys{keys: map[uint64]bool{self: true, live: true, dead: true}}
	if err := purgeStaleConfigs(cfgs, self, gone); err != nil {
		t.Fatal(err)
	}
	if want := []uint64{self, live}; !slices.Equal(slices.Sorted(maps.Keys(cfgs.keys)), want) {
		t.Errorf("configs left %v, want %v", slices.Sorted(maps.Keys(cfgs.keys)), want)
	}
	m.nextErr = errors.New("EPERM")
	if err := purgeStaleWants(m, self, gone); err == nil {
		t.Error("purgeStaleWants hid a map it could not list")
	}
}

// TestPlaneFillKeyKeepsEachLaunchersTemplates: a wants key carries the tgid, the kind and the descriptor number
// apart, so two launchers' templates at one number, and one descriptor's fs and exec rows, never share a key.
func TestPlaneFillKeyKeepsEachLaunchersTemplates(t *testing.T) {
	seen := map[uint64]bool{}
	for _, tgid := range []uint32{1, 2, 1<<32 - 1} {
		for _, what := range []ebpfbindings.PlaneFillWhat{ebpfbindings.PlaneFillFS, ebpfbindings.PlaneFillExec} {
			for _, fd := range []uint32{0, 3, 1<<30 - 1} {
				k := ebpfbindings.PlaneFillKey(tgid, what, fd)
				if seen[k] || ebpfbindings.PlaneFillKeyTgid(k) != tgid || uint32(k)&(1<<30-1) != fd || ebpfbindings.PlaneFillWhat(uint32(k)>>30) != what {
					t.Errorf("key %x of (%d, %d, %d)", k, tgid, what, fd)
				}
				seen[k] = true
			}
		}
	}
}

// TestPutRoomPurgesThenWaits: a put refused for room purges the dead launchers' leftovers once and tries again,
// then waits for room up to fillRoomWait and fails naming it; any other error fails at once.
func TestPutRoomPurgesThenWaits(t *testing.T) {
	prev := fillRoomWait
	// Long enough for two 5 ms waits on a loaded guest (a 30 ms bound failed on AL2023 with another guest beside it).
	fillRoomWait = 2 * time.Second
	t.Cleanup(func() { fillRoomWait = prev })
	var puts, purges int
	full := func(n int) func() error {
		return func() error {
			puts++
			if puts <= n {
				return unix.E2BIG
			}
			return nil
		}
	}
	purge := func() error { purges++; return nil }
	if err := putRoom(full(3), purge); err != nil || purges != 1 || puts != 4 {
		t.Errorf("putRoom = %v after %d puts and %d purges, want room after the wait and one purge", err, puts, purges)
	}
	puts, purges = 0, 0
	fillRoomWait = 30 * time.Millisecond
	if err := putRoom(full(1<<30), purge); err == nil || !errors.Is(err, unix.E2BIG) || !strings.Contains(err.Error(), "stayed full") {
		t.Errorf("putRoom on a map that stays full = %v", err)
	}
	if err := putRoom(func() error { return unix.EPERM }, purge); !errors.Is(err, unix.EPERM) {
		t.Errorf("putRoom of another error = %v", err)
	}
}

// TestHostIdentityIsOneStatx: the plan's identity of a descriptor is one statx, and it is what fstat and fdinfo
// would have said: st_dev (a btrfs subvolume's own, as lstat of the path gives it), the inode number, and fdinfo's
// mnt_id, the one the fill reads (real_mount(f_path.mnt)->mnt_id).
func TestHostIdentityIsOneStatx(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/f"
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd) //nolint:errcheck // test cleanup
	dev, ino, mnt, err := hostIdentity{}.fd(fd)
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	info, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(fd))
	if err != nil {
		t.Fatal(err)
	}
	fdMnt, fdIno, err := parseFDInfo(info)
	if err != nil {
		t.Fatal(err)
	}
	if dev != st.Dev || ino != st.Ino || ino != fdIno || mnt != fdMnt {
		t.Errorf("statx (%d, %d, mount %d); fstat (%d, %d); fdinfo (ino %d, mount %d)", dev, ino, mnt, st.Dev, st.Ino, fdIno, fdMnt)
	}
	pDev, pIno, err := hostIdentity{}.path(path)
	if err != nil || pDev != dev || pIno != ino {
		t.Errorf("lstat (%d, %d, %v), statx (%d, %d)", pDev, pIno, err, dev, ino)
	}
	if _, _, _, err := (hostIdentity{}).fd(-1); err == nil {
		t.Error("a descriptor not open was identified")
	}
}
