// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf && linux

package runtime

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The live blocks' paths that only unit tests reached before (ADR 0124, amendment 2026-11-21): a row whose key inode
// lost its identity, a walk that cannot reach the root, a block that has not begun, and a name row's key shared or
// taken. Each is driven here in a real root run on the kernel's own plane, and each has its control in the kernel's
// own state: the plane's counters at the run's end (the gap lines plane-identity-mismatch and plane-path-unresolved),
// the rows of the slot's block map read back through the bpffs pin, and the same action before and after the path was
// taken, so a pass cannot be an outcome that matched by another cause. The rows are changed through the same bpffs pins
// the counters test of the contract rows uses (enforce/cgroup plane_counters_e2e_integration_test.go): only root can.

// planePathBPFFS is where the plane's pins live (cgroup.DefaultBPFFS, which a test machine's config leaves as it is).
const planePathBPFFS = "/sys/fs/bpf"

// planeBlockRowAt is one row of a slot's live-block map and the key it is under.
type planeBlockRowAt struct {
	slot uint32
	key  uint64
	row  bpf.PlaneBlockRow
}

// walkPlaneBlockRows calls visit with every row of every slot's live-block map of mode, the inner map for a write back.
func walkPlaneBlockRows(t *testing.T, mode string, visit func(inner *ebpf.Map, at planeBlockRowAt)) {
	t.Helper()
	hash, err := bpf.Hash()
	if err != nil {
		t.Fatalf("this test binary carries no BPF objects: %v", err)
	}
	pin := filepath.Join(planePathBPFFS, "tego", hash+"-"+mode, "maps", bpf.MapPlaneBlocks)
	if _, err := os.Stat(pin); err != nil {
		// The run's binary and this test binary are built from one tree and so carry one hash; if the pin is not under it,
		// the one pin of this mode there is is the run's.
		if m, _ := filepath.Glob(filepath.Join(planePathBPFFS, "tego", "*-"+mode, "maps", bpf.MapPlaneBlocks)); len(m) == 1 {
			pin = m[0]
		}
	}
	outer, err := ebpf.LoadPinnedMap(pin, nil)
	if err != nil {
		t.Fatalf("open the plane's live-block rows at %s: %v", pin, err)
	}
	defer func() { _ = outer.Close() }()
	var slot, id uint32
	it := outer.Iterate()
	for it.Next(&slot, &id) {
		inner, err := ebpf.NewMapFromID(ebpf.MapID(id))
		if err != nil {
			continue
		}
		var key uint64
		var row bpf.PlaneBlockRow
		var keys []uint64
		rows := inner.Iterate()
		for rows.Next(&key, &row) {
			keys = append(keys, key)
		}
		for _, k := range keys {
			if err := inner.Lookup(k, &row); err != nil {
				continue
			}
			visit(inner, planeBlockRowAt{slot: slot, key: k, row: row})
		}
		_ = inner.Close()
	}
	if err := it.Err(); err != nil {
		t.Fatalf("read the plane's live-block rows: %v", err)
	}
}

// planeBlockRows is every row of the slots' live-block maps of mode that match accepts.
func planeBlockRows(t *testing.T, mode string, match func(bpf.PlaneBlockRow) bool) []planeBlockRowAt {
	t.Helper()
	var out []planeBlockRowAt
	walkPlaneBlockRows(t, mode, func(_ *ebpf.Map, at planeBlockRowAt) {
		if match(at.row) {
			out = append(out, at)
		}
	})
	return out
}

// editPlaneBlockRows applies edit to every row match accepts, in the kernel's own map, and returns how many it changed.
func editPlaneBlockRows(t *testing.T, mode string, match func(bpf.PlaneBlockRow) bool, edit func(*bpf.PlaneBlockRow)) int {
	t.Helper()
	changed := 0
	walkPlaneBlockRows(t, mode, func(inner *ebpf.Map, at planeBlockRowAt) {
		if !match(at.row) {
			return
		}
		row := at.row
		edit(&row)
		if err := inner.Update(at.key, row, ebpf.UpdateExist); err != nil {
			t.Fatalf("change slot %d's live-block row: %v", at.slot, err)
		}
		changed++
	})
	return changed
}

// inoOf is the inode number of p.
func inoOf(t *testing.T, p string) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}

// bootNS is CLOCK_BOOTTIME now, the clock a row's from_ns is compared with in the kernel.
func bootNS(t *testing.T) uint64 {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		t.Fatal(err)
	}
	return uint64(ts.Nano())
}

// flipIdentity is the edit that makes a row's key inode no longer carry the identity the row recorded (it is its own
// inverse): what an inode freed and reused under a still-keyed row would look like to the walk.
func flipIdentity(r *bpf.PlaneBlockRow) { r.IIno ^= 1 << 40 }

// planePathPrelude is the probe's helpers: what each action came to as an errno name, reports on stdout (under a
// write overflow the probe can write no file), and CLOCK_BOOTTIME for the dormant cells.
const planePathPrelude = `import errno, json, os, sys, time
P = os.path.join(os.getcwd(), "out")
def wait(word):
    while not os.path.exists(os.path.join(P, word)):
        time.sleep(0.02)
def attempt(res, name, f):
    try:
        r = f()
        res[name] = "ok" if r is None else r
    except OSError as e:
        res[name] = errno.errorcode.get(e.errno, str(e.errno))
def write_open(p, flags=os.O_WRONLY):
    fd = os.open(p, flags, 0o644)
    os.close(fd)
def read_open(p):
    fd = os.open(p, os.O_RDONLY)
    os.close(fd)
def boot():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)
def report(word, res):
    print(word + " " + json.dumps(res), flush=True)
open(os.path.join(P, "ready"), "w").close()
`

// pathScene is one root run of a probe pinned to a tier and a plane, with the live-block overlay of its run directory.
type pathScene struct {
	t      *testing.T
	s      *askReadScene
	tier   string
	plane  string
	ended  chan error
	out    *strings.Builder
	stdout string
	dir    string
	id     string
	// added and removed are the live-block lines the run's ledger holds so far, as the test counts them.
	added, removed int
}

// newPathScene is newPlaneBlockScene's run with probe in place of its probe and files (name relative to the project, under
// out/) added, started and ready: its launcher holds its lock and the probe has written out/ready.
func newPathScene(t *testing.T, bin, tier, plane, python, resolved, probe string, files map[string]string) *pathScene {
	t.Helper()
	s := newPlaneBlockScene(t, bin, tier, plane, python, []string{python, resolved})
	requireStrictPlane(t, s, tier, plane)
	if err := os.WriteFile(filepath.Join(s.f.dir, "probe.py"), []byte(planePathPrelude+probe), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		p := filepath.Join(s.f.dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	agentOwnsTree(t, filepath.Join(s.f.dir, "out"))
	agentOwns(t, filepath.Join(s.f.dir, "probe.py"))
	ps := &pathScene{t: t, s: s, tier: tier, plane: plane, out: &strings.Builder{}}
	cmd := s.tego(t, "run", filepath.Join(s.f.dir, "agent.yaml"), "--", python, "probe.py")
	cmd.Dir = s.f.dir
	ps.stdout = filepath.Join(t.TempDir(), "stdout")
	so, err := os.Create(ps.stdout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = so.Close() })
	cmd.Stdout, cmd.Stderr = so, ps.out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ps.ended = make(chan error, 1)
	go func() { ps.ended <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() }) // a no-op once the run has ended
	ps.dir = liveRunDir(t, s.f.root, ps.ended, time.Now().Add(30*time.Second), 10*time.Millisecond)
	ps.id = filepath.Base(ps.dir)
	awaitFile(t, filepath.Join(s.f.out, "ready"), ps.ended, ps.out)
	return ps
}

// path is out/ and name, the path the probe uses and the blocks name.
func (p *pathScene) path(name ...string) string {
	return filepath.Join(append([]string{p.s.f.out}, name...)...)
}

// block places a block of kind on value through the run's overlay, as `tego block` does, and waits for its line.
func (p *pathScene) block(kind liveblock.Kind, value string) {
	p.t.Helper()
	updateOverlay(p.t, p.dir, p.id, func(o *liveblock.Overlay) error {
		_, _, err := o.Add(kind, value, "uid:0 pid:1 cli", time.Now())
		return err
	})
	p.added++
	awaitGap(p.t, p.dir, record.GapLiveBlockAdded, p.added, p.ended)
}

// unblock removes the block of kind on value, until until (zero: for the rest of the run), and waits for its line.
func (p *pathScene) unblock(kind liveblock.Kind, value string, until time.Time) {
	p.t.Helper()
	updateOverlay(p.t, p.dir, p.id, func(o *liveblock.Overlay) error {
		_, _, err := o.RemoveUntil(kind, value, "uid:0 pid:1 cli", time.Now(), until)
		return err
	})
	p.removed++
	awaitGap(p.t, p.dir, record.GapLiveBlockRemoved, p.removed, p.ended)
}

// phase lets the probe run the phase that waits for word, and returns the line it reports under report.
func (p *pathScene) phase(word, report string) map[string]any {
	p.t.Helper()
	touch(p.t, p.path(word))
	return awaitLine(p.t, p.stdout, report+" ", p.ended)
}

// finish waits for the run to end cleanly and returns its lines, whose decision plane it checks.
func (p *pathScene) finish() []*record.Event {
	p.t.Helper()
	select {
	case err := <-p.ended:
		if code := exitCodeOf(p.t, err); code != 0 {
			p.t.Fatalf("tego run exited %d:\n%s", code, p.out.String())
		}
	case <-time.After(60 * time.Second):
		p.t.Fatalf("tego run did not end:\n%s", p.out.String())
	}
	evs := events(p.t, p.dir)
	if got := runPlane(p.t, evs); got != p.plane {
		p.t.Fatalf("the run's decision plane is %q, want %q", got, p.plane)
	}
	return evs
}

// planeRefusedLine is one refused fs line of a run.
type planeRefusedLine struct {
	path, rule, reason, planeReason string
	ts                              time.Time
}

// planeRefusedLines are the run's refused fs lines the plane made.
func planeRefusedLines(t *testing.T, evs []*record.Event) []planeRefusedLine {
	t.Helper()
	var out []planeRefusedLine
	for _, e := range evs {
		if e.Kind != record.KindFS || e.Verdict != record.VerdictRefused {
			continue
		}
		var p record.FSPayload
		if err := e.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.Mechanism != record.MechanismPlane {
			continue
		}
		out = append(out, planeRefusedLine{path: p.Path, rule: e.Rule, reason: string(e.Reason), planeReason: p.PlaneReason, ts: e.TS})
	}
	return out
}

// planeGapCounts are the plane's counters as the run's end wrote them: the count of each gap why plane-*, with how many
// lines named it.
func planeGapCounts(t *testing.T, evs []*record.Event) (count, lines map[string]int) {
	t.Helper()
	count, lines = map[string]int{}, map[string]int{}
	for _, e := range evs {
		if e.Kind != record.KindGap {
			continue
		}
		var g record.GapPayload
		if err := e.DecodePayload(&g); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(g.Why, "plane-") && g.What == record.GapEnforce {
			count[g.Why] += g.Count
			lines[g.Why]++
		}
	}
	return count, lines
}

// planePathRoot runs body for each plane mode and tier a root run is asked for, as TestRootLiveBlockInPlane does, with
// the python3 the probe needs.
func planePathRoot(t *testing.T, body func(t *testing.T, bin, tier, plane, python, resolved string)) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: tiers cgroup and bpflsm")
	}
	bin := tegoBPFBinary(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range strictPlanes {
		t.Run(tc.tier+"/"+tc.plane, func(t *testing.T) { body(t, bin, tc.tier, tc.plane, python, resolved) })
	}
}

// planeProbeWants checks one phase's results against what each action is wanted to come to ("ok" or an errno name).
func planeProbeWants(t *testing.T, phase string, got map[string]any, want map[string]string) {
	t.Helper()
	t.Logf("%s: %v", phase, got)
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: %s = %v, want %s (all: %v)", phase, k, got[k], w, got)
		}
	}
}

// A row whose key inode no longer carries the identity the row recorded (an inode freed and reused under a row that
// should have kept it pinned) must refuse, whatever the class asked: the walk cannot tell whose row it met. The
// launcher keeps every keyed object open, so the kernel never reaches this by itself in a run; the rows' identity is
// changed here in the slot's own map, as the counters test does for the contract's rows, and the walk, the refusal,
// the line's plane_reason and the plane's counter are the kernel's. A file's row and a name row's directory are both
// driven. The control is the same run before the change (the block's own refusal, naming its rule, and a read of the
// write-blocked file allowed), after the change is undone (the block refuses again, a read is allowed again) and after
// the blocks are removed, and the neighbours of the changed rows (another file in the folder, another name in the
// directory) are never refused: the counter moved for the changed rows only.
func TestRootLiveBlockIdentityMismatch(t *testing.T) {
	const probe = `
B = os.path.join(P, "blk")
N = os.path.join(P, "nb")
F = os.path.join(B, "f.txt")
G = os.path.join(B, "g.txt")
NEW = os.path.join(N, "new.txt")
OTHER = os.path.join(N, "another-length-of-name.txt")
FREE = os.path.join(P, "free.txt")
def rnd():
    res = {}
    attempt(res, "f_write", lambda: write_open(F))
    attempt(res, "f_read", lambda: read_open(F))
    attempt(res, "g_write", lambda: write_open(G))
    attempt(res, "new_create", lambda: write_open(NEW, os.O_WRONLY | os.O_CREAT))
    attempt(res, "other_create", lambda: write_open(OTHER, os.O_WRONLY | os.O_CREAT))
    attempt(res, "free_write", lambda: write_open(FREE))
    res["new_exists"] = os.path.exists(NEW)
    return res
for word, name in (("go1", "R1"), ("go2", "R2"), ("go3", "R3"), ("go4", "R4")):
    wait(word)
    report(name, rnd())
`
	planePathRoot(t, func(t *testing.T, bin, tier, plane, python, resolved string) {
		ps := newPathScene(t, bin, tier, plane, python, resolved, probe, map[string]string{
			"out/blk/f.txt": "f", "out/blk/g.txt": "g", "out/nb/.keep": "", "out/free.txt": "free"})
		f, nb, newName := ps.path("blk", "f.txt"), ps.path("nb"), ps.path("nb", "new.txt")
		ps.block(liveblock.KindWrite, f)
		ps.block(liveblock.KindWrite, newName)
		allowed := map[string]string{"g_write": "ok", "other_create": "ok", "free_write": "ok"}
		withRest := func(w map[string]string) map[string]string {
			for k, v := range allowed {
				w[k] = v
			}
			return w
		}
		// 1: the blocks as placed. Control: they refuse their own object (the file, the missing name) and a read of the
		// write-blocked file passes.
		r1 := ps.phase("go1", "R1")
		planeProbeWants(t, "R1 (blocks placed)", r1, withRest(map[string]string{"f_write": "EACCES", "f_read": "ok", "new_create": "EACCES"}))
		if r1["new_exists"] != false {
			t.Errorf("R1: a refused create left a file: %v", r1)
		}
		// The rows of the file and of the missing name, as the fill wrote them, then their identity lost.
		isFileRow := func(r bpf.PlaneBlockRow) bool {
			return r.IIno == inoOf(t, f) && r.NameKey == 0 && r.IDWrite != 0
		}
		isNameRow := func(r bpf.PlaneBlockRow) bool { return r.NameKey != 0 && r.IIno == inoOf(t, nb) }
		if n := len(planeBlockRows(t, plane, isFileRow)); n != 1 {
			t.Fatalf("the slot holds %d write rows of %s, want 1", n, f)
		}
		if n := len(planeBlockRows(t, plane, isNameRow)); n != 1 {
			t.Fatalf("the slot holds %d name rows of the directory %s, want 1", n, nb)
		}
		if n := editPlaneBlockRows(t, plane, func(r bpf.PlaneBlockRow) bool { return isFileRow(r) || isNameRow(r) }, flipIdentity); n != 2 {
			t.Fatalf("changed %d rows, want the file's and the name's", n)
		}
		// 2: the walk meets a row that is not its inode's: refused whatever was asked, a read included, and only there.
		r2 := ps.phase("go2", "R2")
		planeProbeWants(t, "R2 (identity lost)", r2, withRest(map[string]string{"f_write": "EACCES", "f_read": "EACCES", "new_create": "EACCES"}))
		// 3: the identity restored: the blocks are the blocks again.
		if n := editPlaneBlockRows(t, plane, func(r bpf.PlaneBlockRow) bool {
			return r.IIno == inoOf(t, f)^1<<40 || (r.NameKey != 0 && r.IIno == inoOf(t, nb)^1<<40)
		}, flipIdentity); n != 2 {
			t.Fatalf("restored %d rows, want 2", n)
		}
		r3 := ps.phase("go3", "R3")
		planeProbeWants(t, "R3 (identity restored)", r3, withRest(map[string]string{"f_write": "EACCES", "f_read": "ok", "new_create": "EACCES"}))
		// 4: the blocks removed.
		ps.unblock(liveblock.KindWrite, f, time.Time{})
		ps.unblock(liveblock.KindWrite, newName, time.Time{})
		r4 := ps.phase("go4", "R4")
		planeProbeWants(t, "R4 (blocks removed)", r4, withRest(map[string]string{"f_write": "ok", "f_read": "ok", "new_create": "ok"}))
		evs := ps.finish()
		count, lines := planeGapCounts(t, evs)
		t.Logf("the plane's counters at the run's end: %v (gap lines: %v)", count, lines)
		if count[record.GapPlaneMismatch] < 3 || lines[record.GapPlaneMismatch] != 1 {
			t.Errorf("the identity-mismatch counter reads %d in %d line(s), want at least 3 (the file's write and read and the name's create) in one: %v",
				count[record.GapPlaneMismatch], lines[record.GapPlaneMismatch], count)
		}
		for _, why := range []string{record.GapPlaneUnresolved, record.GapPlaneBound} {
			if count[why] != 0 {
				t.Errorf("the %s counter moved (%d): a refusal that was not the identity's was counted", why, count[why])
			}
		}
		var mismatch, named int
		ruleF, ruleNew := liveblock.Rule(liveblock.KindWrite, f), liveblock.Rule(liveblock.KindWrite, newName)
		seen := map[string]bool{}
		for _, l := range planeRefusedLines(t, evs) {
			switch {
			case l.planeReason == record.PlaneReasonIdentityMismatch:
				mismatch++
				if l.reason != string(record.ReasonPathUnresolved) {
					t.Errorf("an identity-mismatch line has reason %q, want path-unresolved: %+v", l.reason, l)
				}
			case l.rule == ruleF || l.rule == ruleNew:
				named++
				seen[l.rule] = true
			}
		}
		if mismatch == 0 {
			t.Error("no refused line carries plane_reason identity-mismatch")
		}
		if !seen[ruleF] || !seen[ruleNew] || named == 0 {
			t.Errorf("the refusals before the change and after its undoing name %s and %s, saw %v", ruleF, ruleNew, seen)
		}
	})
}

// A walk that cannot reach the namespace root cannot say that no block lies above, and a slot that holds blocks must
// say it: the walk fails closed, path-unresolved. The contract's own walk stops at its row, so a file the contract
// allows more than TEGO_PLANE_WALK_MAX (64) levels from the namespace root, with a row of its own folder's within the
// bound, is allowed with no block in the slot and refused once any block is: the control is the same file before and
// after the block, a file nearer the root while the block stands, and the counters, which name the block walk's
// failure (plane-path-unresolved) and not the contract walk's (plane-walk-bound).
func TestRootLiveBlockPathUnresolved(t *testing.T) {
	const probe = `
DEEP = os.path.join(P, *(["d"] * 62), "f.txt")
NEAR = os.path.join(P, *(["m"] * 12), "f.txt")
BLK = os.path.join(P, "blk", "f.txt")
FREE = os.path.join(P, "free.txt")
def rnd():
    res = {}
    attempt(res, "deep_write", lambda: write_open(DEEP))
    attempt(res, "deep_read", lambda: read_open(DEEP))
    attempt(res, "near_write", lambda: write_open(NEAR))
    attempt(res, "blk_write", lambda: write_open(BLK))
    attempt(res, "free_write", lambda: write_open(FREE))
    return res
for word, name in (("go1", "R1"), ("go2", "R2"), ("go3", "R3")):
    wait(word)
    report(name, rnd())
`
	planePathRoot(t, func(t *testing.T, bin, tier, plane, python, resolved string) {
		deep := "out/" + strings.Repeat("d/", 62) + "f.txt"
		near := "out/" + strings.Repeat("m/", 12) + "f.txt"
		ps := newPathScene(t, bin, tier, plane, python, resolved, probe, map[string]string{
			deep: "d", near: "m", "out/blk/f.txt": "b", "out/free.txt": "free"})
		blk := ps.path("blk", "f.txt")
		// 1: no block in the slot, so no block walk: the deep file is the contract's alone.
		r1 := ps.phase("go1", "R1")
		planeProbeWants(t, "R1 (no block)", r1, map[string]string{"deep_write": "ok", "deep_read": "ok", "near_write": "ok",
			"blk_write": "ok", "free_write": "ok"})
		// 2: a block stands on one file: every open now asks the slot's walk to reach the root, which the deep file's
		// cannot within the bound.
		ps.block(liveblock.KindWrite, blk)
		r2 := ps.phase("go2", "R2")
		planeProbeWants(t, "R2 (a block stands)", r2, map[string]string{"deep_write": "EACCES", "deep_read": "EACCES",
			"near_write": "ok", "blk_write": "EACCES", "free_write": "ok"})
		// 3: the block removed: the slot holds none and the deep file is the contract's alone again.
		ps.unblock(liveblock.KindWrite, blk, time.Time{})
		r3 := ps.phase("go3", "R3")
		planeProbeWants(t, "R3 (block removed)", r3, map[string]string{"deep_write": "ok", "deep_read": "ok", "near_write": "ok",
			"blk_write": "ok", "free_write": "ok"})
		evs := ps.finish()
		count, lines := planeGapCounts(t, evs)
		t.Logf("the plane's counters at the run's end: %v (gap lines: %v)", count, lines)
		if count[record.GapPlaneUnresolved] < 2 || lines[record.GapPlaneUnresolved] != 1 {
			t.Errorf("the path-unresolved counter reads %d in %d line(s), want at least 2 (the deep file's write and read) in one: %v",
				count[record.GapPlaneUnresolved], lines[record.GapPlaneUnresolved], count)
		}
		for _, why := range []string{record.GapPlaneMismatch, record.GapPlaneBound} {
			if count[why] != 0 {
				t.Errorf("the %s counter moved (%d): the refusals were to be the block walk's running out, nothing else", why, count[why])
			}
		}
		unresolved := 0
		for _, l := range planeRefusedLines(t, evs) {
			if l.reason == string(record.ReasonPathUnresolved) {
				unresolved++
				if l.planeReason != "" || strings.HasPrefix(l.rule, "live.block[") {
					t.Errorf("a path-unresolved line carries plane_reason %q and rule %q, want neither: %+v", l.planeReason, l.rule, l)
				}
			}
		}
		if unresolved == 0 {
			t.Error("no refused line has reason path-unresolved")
		}
	})
}

// planeRowID names a row of a slot's live-block map: the slot and the key it is under.
type planeRowID struct {
	slot uint32
	key  uint64
}

// dormantRowsDrift says how the rows held now differ from the first reading of each, by slot and key: a row that
// appeared or went, or one whose from_ns moved. The launcher pins each block's instant on its own, so two rows of one
// run hold from_ns values a clock read apart, and each is only ever compared with its own reading.
func dormantRowsDrift(first map[planeRowID]uint64, held []planeBlockRowAt) []string {
	var out []string
	if len(held) != len(first) {
		out = append(out, fmt.Sprintf("%d rows after the dormant actions, were %d", len(held), len(first)))
	}
	for _, r := range held {
		if was, ok := first[planeRowID{r.slot, r.key}]; !ok {
			out = append(out, fmt.Sprintf("a row appeared during the dormant actions: slot %d key %d", r.slot, r.key))
		} else if r.row.FromNs != was {
			out = append(out, fmt.Sprintf("the row (slot %d, key %d) holds from_ns %d after the dormant actions, was %d", r.slot, r.key, r.row.FromNs, was))
		}
	}
	return out
}

// Two dormant rows of one run hold different from_ns values (each block's instant is pinned on its own), and neither
// has moved: that is no drift. A row that moved, appeared or went is.
func TestDormantRowsAreComparedEachToItsOwnReading(t *testing.T) {
	file, name := planeRowID{1, 10}, planeRowID{1, 11}
	first := map[planeRowID]uint64{file: 5_000_000_000, name: 5_000_000_731}
	at := func(id planeRowID, from uint64) planeBlockRowAt {
		return planeBlockRowAt{slot: id.slot, key: id.key, row: bpf.PlaneBlockRow{FromNs: from}}
	}
	if got := dormantRowsDrift(first, []planeBlockRowAt{at(file, 5_000_000_000), at(name, 5_000_000_731)}); len(got) != 0 {
		t.Errorf("rows that kept their own from_ns drift: %v", got)
	}
	if got := dormantRowsDrift(first, []planeBlockRowAt{at(file, 5_000_000_000), at(name, 5_000_000_000)}); len(got) != 1 {
		t.Errorf("a name row moved to the file row's from_ns: %v, want one drift", got)
	}
	if got := dormantRowsDrift(first, []planeBlockRowAt{at(file, 5_000_000_000)}); len(got) != 1 {
		t.Errorf("a row went: %v, want one drift", got)
	}
	if got := dormantRowsDrift(first, []planeBlockRowAt{at(file, 5_000_000_000), at(name, 5_000_000_731), at(planeRowID{2, 3}, 1)}); len(got) != 2 {
		t.Errorf("a row appeared: %v, want a count and a row", got)
	}
}

// A block that has not begun refuses nothing: the unblock for a while (ADR 0125, decision 4) keeps the block with a
// from, which the launcher gives the rows as the instant on CLOCK_BOOTTIME, and the kernel compares it with its own
// clock at each walk. The cells are the blocked file and a missing name, refused (1), then dormant (2: the rows in the
// slot's map hold a from_ns in the future, read back, and the same actions pass), then past their instant (3: refused
// again, by the same rows, with nothing sent to the kernel in between but time). The ledger shows no refusal by either
// block while it was dormant, and refusals before and after.
func TestRootLiveBlockDormantBlockWaitsForItsInstant(t *testing.T) {
	const probe = `
F = os.path.join(P, "blk", "f.txt")
NEW = os.path.join(P, "blk", "new.txt")
wait("go1")
res = {}
attempt(res, "f_write", lambda: write_open(F))
attempt(res, "new_create", lambda: write_open(NEW, os.O_WRONLY | os.O_CREAT))
report("A", res)
wait("go2")
res = {"boot0": boot(), "wall0": time.time()}
attempt(res, "f_write", lambda: write_open(F))
attempt(res, "new_create", lambda: write_open(NEW, os.O_WRONLY | os.O_CREAT))
res["boot1"] = boot()
res["wall1"] = time.time()
report("B", res)
wait("go3")
res = {"boot": boot()}
attempt(res, "f_write", lambda: write_open(F))
attempt(res, "new_write", lambda: write_open(NEW))
report("C", res)
`
	planePathRoot(t, func(t *testing.T, bin, tier, plane, python, resolved string) {
		ps := newPathScene(t, bin, tier, plane, python, resolved, probe, map[string]string{"out/blk/f.txt": "f"})
		f, newName := ps.path("blk", "f.txt"), ps.path("blk", "new.txt")
		ps.block(liveblock.KindWrite, f)
		ps.block(liveblock.KindWrite, newName)
		a := ps.phase("go1", "A")
		planeProbeWants(t, "A (blocks in force)", a, map[string]string{"f_write": "EACCES", "new_create": "EACCES"})
		// Unblock for a while: the least the overlay takes is a minute (less its slack).
		until := time.Now().Add(58 * time.Second)
		ps.unblock(liveblock.KindWrite, f, until)
		ps.unblock(liveblock.KindWrite, newName, until)
		isFile := func(r bpf.PlaneBlockRow) bool { return r.IIno == inoOf(t, f) && r.NameKey == 0 && r.IDWrite != 0 }
		isName := func(r bpf.PlaneBlockRow) bool { return r.NameKey != 0 && r.IIno == inoOf(t, ps.path("blk")) }
		// Each block's instant is pinned on its own by the launcher (one reading of the clocks per block, the two unblocks
		// landing in different polls), so each row keeps its own from_ns: the rows are compared with their own first reading,
		// by slot and key, never with each other's.
		froms := map[planeRowID]uint64{}
		deadline := time.Now().Add(20 * time.Second)
		for {
			rows := append(planeBlockRows(t, plane, isFile), planeBlockRows(t, plane, isName)...)
			if len(rows) == 2 && rows[0].row.FromNs != 0 && rows[1].row.FromNs != 0 {
				for _, r := range rows {
					froms[planeRowID{r.slot, r.key}] = r.row.FromNs
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no dormant rows in the slot's map 20 s after the unblock (rows: %+v)", rows)
			}
			time.Sleep(100 * time.Millisecond)
		}
		if len(froms) != 2 {
			t.Fatalf("the file row and the name row are not two rows of the slot's map (%d keys)", len(froms))
		}
		// The dormant actions must end before the earlier of the two instants, and the last cell must run after the later.
		var from, earliest uint64
		now := bootNS(t)
		for id, f := range froms {
			if f <= now || f > now+uint64(60*time.Second) {
				t.Fatalf("the row %+v's from_ns %d is not within the next minute of CLOCK_BOOTTIME %d", id, f, now)
			}
			t.Logf("the dormant row %+v: from_ns %d, CLOCK_BOOTTIME now %d: %d ms ahead", id, f, now, (int64(f)-int64(now))/int64(time.Millisecond))
			if f > from {
				from = f
			}
			if earliest == 0 || f < earliest {
				earliest = f
			}
		}
		b := ps.phase("go2", "B")
		planeProbeWants(t, "B (dormant)", b, map[string]string{"f_write": "ok", "new_create": "ok"})
		// The rows the probe's actions met are the same ones, still dormant: the compare was the kernel's.
		for _, msg := range dormantRowsDrift(froms, append(planeBlockRows(t, plane, isFile), planeBlockRows(t, plane, isName)...)) {
			t.Error(msg)
		}
		if boot1, _ := b["boot1"].(float64); uint64(boot1) >= earliest {
			t.Errorf("the dormant actions ended at CLOCK_BOOTTIME %d, not before the earlier row's from_ns %d", uint64(boot1), earliest)
		}
		// Wait past the instant and one launcher poll.
		for bootNS(t) < from+3*uint64(time.Second) {
			time.Sleep(200 * time.Millisecond)
		}
		c := ps.phase("go3", "C")
		planeProbeWants(t, "C (the instant passed)", c, map[string]string{"f_write": "EACCES", "new_write": "EACCES"})
		if boot, _ := c["boot"].(float64); uint64(boot) < from {
			t.Errorf("the last cell ran at CLOCK_BOOTTIME %d, before the rows' from_ns %d", uint64(boot), from)
		}
		evs := ps.finish()
		ruleF, ruleNew := liveblock.Rule(liveblock.KindWrite, f), liveblock.Rule(liveblock.KindWrite, newName)
		w0, _ := b["wall0"].(float64)
		w1, _ := b["wall1"].(float64)
		start, end := time.Unix(0, int64(w0*1e9)), time.Unix(0, int64(w1*1e9))
		before, after := 0, 0
		for _, l := range planeRefusedLines(t, evs) {
			if l.rule != ruleF && l.rule != ruleNew {
				continue
			}
			switch {
			case !l.ts.Before(start) && !l.ts.After(end):
				t.Errorf("a block refused while it was dormant: %+v", l)
			case l.ts.Before(start):
				before++
			default:
				after++
			}
		}
		t.Logf("refusals by the two blocks in the ledger: %d before the dormant window, %d after it", before, after)
		if before == 0 || after == 0 {
			t.Errorf("the ledger holds %d refusals by the blocks before the dormant window and %d after it, want some of each", before, after)
		}
	})
}

// A name row's key is its length and its first 32 bytes, mixed with the directory (bpf.PlaneBlockNameKey): two names of
// one length that agree on those bytes share a key, so the row of a missing name refuses creating the other too, which
// only refuses more. Creating a name that differs in length, or in those bytes, passes. A key taken by another object's
// row is the other path: the fill answers DUP, which the launcher takes as a row the plane could not hold, and the
// class is refused whole until a pass that puts it. Two names' keys over a 63-bit hash do not collide in a test, so the
// kernel is shown the condition the way a collision would show it: the name row's recorded identity is changed in the
// map, and a launcher fill of that key finds a row that names another object. The control is the same fill before the
// change (a second block on the same missing name, which rewrites the row and overflows nothing) and the unrelated
// write that the overflow refuses only after.
func TestRootLiveBlockNameKeys(t *testing.T) {
	long := strings.Repeat("a", 32)
	const probe = `
N = os.path.join(P, "nb")
LONG = "a" * 32
X = os.path.join(N, LONG + "1")
S = os.path.join(N, LONG + "2")
D = os.path.join(N, LONG + "22")
E = os.path.join(N, "b" + "a" * 31 + "1")
FREE = os.path.join(P, "free.txt")
def create(p):
    return write_open(p, os.O_WRONLY | os.O_CREAT)
wait("go0")
res = {}
attempt(res, "s_create", lambda: create(S))
attempt(res, "s_unlink", lambda: os.unlink(S))
report("P0", res)
wait("go1")
res = {}
attempt(res, "x_create", lambda: create(X))
attempt(res, "s_create", lambda: create(S))
attempt(res, "d_create", lambda: create(D))
attempt(res, "e_create", lambda: create(E))
attempt(res, "free_write", lambda: write_open(FREE))
res["x_exists"] = os.path.exists(X)
res["s_exists"] = os.path.exists(S)
report("P1", res)
wait("go2")
res = {}
attempt(res, "x_create", lambda: create(X))
attempt(res, "s_create", lambda: create(S))
attempt(res, "free_write", lambda: write_open(FREE))
report("P2", res)
wait("go3")
res = {}
deadline = time.time() + 20
tries = 0
while True:
    tries += 1
    attempt(res, "free_write", lambda: write_open(FREE))
    if res["free_write"] != "ok" or time.time() > deadline:
        break
    time.sleep(0.1)
attempt(res, "free_read", lambda: read_open(FREE))
res["tries"] = tries
report("P3", res)
`
	planePathRoot(t, func(t *testing.T, bin, tier, plane, python, resolved string) {
		ps := newPathScene(t, bin, tier, plane, python, resolved, probe, map[string]string{"out/nb/.keep": "", "out/free.txt": "free"})
		nb := ps.path("nb")
		x := ps.path("nb", long+"1")
		// 0: before any block the name is creatable (and removed again, so it is missing when the block lands).
		p0 := ps.phase("go0", "P0")
		planeProbeWants(t, "P0 (no block)", p0, map[string]string{"s_create": "ok", "s_unlink": "ok"})
		// 1: a write block on the missing name refuses it and its key's other names, not the names of another length or
		// of other first bytes.
		ps.block(liveblock.KindWrite, x)
		p1 := ps.phase("go1", "P1")
		planeProbeWants(t, "P1 (a name row)", p1, map[string]string{"x_create": "EACCES", "s_create": "EACCES", "d_create": "ok",
			"e_create": "ok", "free_write": "ok"})
		if p1["x_exists"] != false || p1["s_exists"] != false {
			t.Errorf("P1: a refused create left a file: %v", p1)
		}
		// 2: a second block on the same missing name changes its row (it adds the read class), which the fill rewrites:
		// no overflow, the free file still writable. This is the fill's own path with no collision.
		ps.block(liveblock.KindPath, x)
		p2 := ps.phase("go2", "P2")
		planeProbeWants(t, "P2 (the row rewritten)", p2, map[string]string{"x_create": "EACCES", "s_create": "EACCES", "free_write": "ok"})
		// 3: the row's recorded identity changed, so the next fill of this key finds another object's row; the second
		// block removed changes the row again, which asks that fill.
		isName := func(r bpf.PlaneBlockRow) bool { return r.NameKey != 0 && r.IIno == inoOf(t, nb) }
		if n := editPlaneBlockRows(t, plane, isName, flipIdentity); n != 1 {
			t.Fatalf("changed %d name rows of %s, want 1", n, nb)
		}
		ps.unblock(liveblock.KindPath, x, time.Time{})
		p3 := ps.phase("go3", "P3")
		planeProbeWants(t, "P3 (the key taken)", p3, map[string]string{"free_write": "EACCES", "free_read": "ok"})
		evs := ps.finish()
		rule := liveblock.Rule(liveblock.KindWrite, x)
		creates, free := false, false
		for _, l := range planeRefusedLines(t, evs) {
			if l.rule != rule {
				continue
			}
			if strings.HasSuffix(l.path, "/out/free.txt") {
				free = true
			} else if strings.HasPrefix(filepath.Base(l.path), long) {
				creates = true
			}
		}
		if !creates {
			t.Errorf("no refused line names %s for a name of the key", rule)
		}
		if !free {
			t.Errorf("no refused line of out/free.txt names %s: the overflow after the key was taken is to be named by the block", rule)
		}
		if _, lines := planeGapCounts(t, evs); lines[record.GapPlaneMismatch] != 0 {
			t.Errorf("the identity-mismatch counter moved: the changed row is the fill's to meet, never a walk's (%v)", lines)
		}
	})
}
