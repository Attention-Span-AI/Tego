// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestIntegrationABuildWhoseRunSetCannotBeReadIsKeptAndShown is ADR 0022 (5) step 1 test 4, as root on the host's
// bpf filesystem: a build idle past its linger whose run set cannot be read (a map of another key size pinned under
// tego_run_set, holding a row, as a tego of another layout would leave) is kept by the sweep, by gc --builds'
// Force and by a real `tego gc --builds`, and a real `tego doctor --json` shows the build with `kept` naming its
// run set and `kept_cause` what the read met.
func TestIntegrationABuildWhoseRunSetCannotBeReadIsKeptAndShown(t *testing.T) {
	requireRealPrepare(t)
	state := pinState(t)
	hash := fmt.Sprintf("unreadrunset%d", os.Getpid()) // no "-" or ".": a state file names its build up to the first (stateHash)
	pins, err := newPinLayout(DefaultBPFFS, hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := pins.create(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pins.remove() })
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	if err := m.Put(uint32(1), uint32(1)); err != nil {
		t.Fatal(err)
	}
	if err := m.Pin(filepath.Join(pins.Maps, ebpfbindings.MapRunSet)); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(state, "bpf-"+hash+".lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(lock) })
	at := time.Now().Add(-time.Hour)
	if err := os.Chtimes(lock, at, at); err != nil {
		t.Fatal(err)
	}
	mine := func(states []BuildState) BuildState {
		for _, s := range states {
			if s.Hash == hash {
				return s
			}
		}
		t.Fatalf("the sweep did not look at %s: %+v", hash, states)
		return BuildState{}
	}
	for _, force := range []bool{false, true} {
		states, err := SweepBuilds(SweepOptions{StateDir: state, Linger: time.Minute, Force: force})
		t.Logf("force %v: SweepBuilds: %v", force, err) // other builds on this machine are not this test's
		if s := mine(states); s.Removed || s.Why != whyUnread || s.Cause == "" {
			t.Fatalf("force %v: %+v, want the build kept for its unreadable run set with the read's error", force, s)
		}
		if _, err := os.Stat(pins.Root); err != nil {
			t.Fatalf("force %v: the build went: %v", force, err)
		}
	}

	bin := t.TempDir()
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := buildTaggedTego(t, bin)
	if out, err := isolatedTego(t, exe, "gc", "--builds", "--json").CombinedOutput(); err != nil {
		t.Fatalf("tego gc --builds: %v\n%s", err, out)
	}
	if _, err := os.Stat(pins.Root); err != nil {
		t.Fatalf("tego gc --builds removed a build whose run set it cannot read: %v", err)
	}
	doctor := isolatedTego(t, exe, "doctor", "--json")
	out, err := doctor.Output()
	if err != nil && doctor.ProcessState.ExitCode() != 0 && doctor.ProcessState.ExitCode() != 1 {
		t.Fatalf("tego doctor --json: %v\n%s", err, out)
	}
	var rep struct {
		Builds []BuildInfo `json:"builds"`
	}
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatalf("tego doctor --json: %v\n%s", err, out)
	}
	for _, b := range rep.Builds {
		if b.Hash != hash {
			continue
		}
		if b.Kept != KeptUnread || b.KeptCause == "" || b.InUse {
			t.Fatalf("doctor's row: %+v, want kept for its unreadable run set, with the read's error", b)
		}
		t.Logf("doctor's row: kept %q: %s", b.Kept, b.KeptCause)
		return
	}
	t.Fatalf("tego doctor --json lists no build %s: %s", hash, out)
}

// TestIntegrationBuildMemlockIsBpftoolsSum is ADR 0022 (8)'s memlock row, as root: a real lingering build's
// BuildInfo.MemlockBytes is more than 0 and equals what bpftool reports for the same objects, found by bpftool's own
// reading of the pins (every map and program pinned under the build and its plane directories, the program of every
// pinned link, every map those programs use), each id once. Every object's fdinfo reports a memlock, an empty LPM
// trie's 0 among them, so none is unreported. It needs bpftool, which the KVM guest image carries. The build with a
// plane, whose maps the build shares, is TestIntegrationPlaneBuildMemlockIsBpftoolsSum.
func TestIntegrationBuildMemlockIsBpftoolsSum(t *testing.T) {
	requireRealPrepare(t)
	checkBuildMemlock(t, "memlock", PlaneSetup{}, nil)
}

// checkBuildMemlock prepares and closes one run of a build named name and the test's pid, with plane and whatever
// setup adds to its backend, rule table and run, and compares the build's listed memlock with bpftool's sum.
func checkBuildMemlock(t *testing.T, name string, plane PlaneSetup, setup func(*Backend, *agent.RuleTable, *Run)) {
	t.Helper()
	bpftool, err := exec.LookPath("bpftool")
	if err != nil {
		t.Skipf("bpftool is the reference this test compares with: %v", err)
	}
	state := pinState(t)
	hash := fmt.Sprintf("%s%d", name, os.Getpid())
	pins, err := newPinLayout(DefaultBPFFS, hash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pins.remove() })
	b := New(Options{Machine: machineLinger(time.Hour), StateDir: state, Hash: hash, Events: &sink{}, Plane: plane,
		startTimer: func(string) error { return nil }})
	rel, cid := runCgroup(t, name)
	table := &agent.RuleTable{Net: []agent.NetRule{}, Tier: backend.TierCgroup, Record: agent.RecordSummary}
	run := Run{ID: name, Agent: "a", CgroupID: cid, CgroupPath: rel}
	if setup != nil {
		setup(b, table, &run)
	}
	h, err := b.Prepare(context.Background(), table, run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	builds, err := ListBuilds(SweepOptions{StateDir: state}, nil)
	if err != nil {
		t.Logf("ListBuilds: %v", err)
	}
	var row *BuildInfo
	for i := range builds {
		if builds[i].Hash == hash {
			row = &builds[i]
		}
	}
	if row == nil {
		t.Fatalf("ListBuilds lists no build %s: %+v", hash, builds)
	}
	roots := []string{row.Path}
	for _, m := range row.Planes {
		roots = append(roots, filepath.Join(pins.Base, planeDirName(hash, ebpfbindings.PlaneMode(m))))
	}
	want, objects := bpftoolMemlock(t, bpftool, roots)
	t.Logf("memlock %d B over %d objects (%d unreported, %d programs, %d links, planes %v); bpftool: %d B",
		row.MemlockBytes, objects, row.MemlockUnreported, row.Programs, row.Links, row.Planes, want)
	if row.MemlockBytes == 0 || row.MemlockBytes != want {
		t.Fatalf("the build's memlock is %d B; bpftool reports %d B for the same objects", row.MemlockBytes, want)
	}
	if row.MemlockUnreported != 0 {
		t.Errorf("%d objects of the build are unreported; every one's fdinfo has a memlock line", row.MemlockUnreported)
	}
	if plane.Mode != "" && (len(row.Planes) != 1 || row.Planes[0] != string(plane.Mode)) {
		t.Errorf("the build lists planes %v, want its %s plane", row.Planes, plane.Mode)
	}
}

// TestIntegrationALingeringBuildALiveRunNeedsIsListedKept is ADR 0022 (1) in doctor's row, as root: a real build inside
// its linger whose run set names a cgroup that exists (an orphan's run, whose launcher died and whose reaper has not
// purged it) is listed kept by a live run, as gc --builds' Force would keep it, though the sweep that ran first left
// it for its linger; the listing changes nothing, so the row of a cgroup that is gone stays in the run set.
func TestIntegrationALingeringBuildALiveRunNeedsIsListedKept(t *testing.T) {
	requireRealPrepare(t)
	state := pinState(t)
	hash := fmt.Sprintf("lingerlive%d", os.Getpid())
	pins, err := newPinLayout(DefaultBPFFS, hash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pins.remove() })
	b := New(Options{Machine: machineLinger(time.Hour), StateDir: state, Hash: hash, Events: &sink{},
		startTimer: func(string) error { return nil }})
	rel, cid := runCgroup(t, "lingerlive")
	table := &agent.RuleTable{Net: []agent.NetRule{}, Tier: backend.TierCgroup, Record: agent.RecordSummary}
	h, err := b.Prepare(context.Background(), table, Run{ID: "lingerlive", Agent: "a", CgroupID: cid, CgroupPath: rel})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	set, err := ebpf.LoadPinnedMap(filepath.Join(pins.Maps, ebpfbindings.MapRunSet), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = set.Close() }()
	const gone = uint64(1) << 62 // no cgroup has this id
	for _, id := range []uint64{cid, gone} {
		if err := set.Put(id, make([]byte, set.ValueSize())); err != nil {
			t.Fatalf("put the run-set row of %d: %v", id, err)
		}
	}
	states, err := SweepBuilds(SweepOptions{StateDir: state, Linger: time.Hour})
	t.Logf("SweepBuilds: %v", err) // other builds on this machine are not this test's
	var swept bool
	for _, s := range states {
		if s.Hash == hash {
			swept = true
			if s.Removed || s.Why != whyLingering {
				t.Fatalf("the sweep: %+v, want the build left for its linger", s)
			}
		}
	}
	if !swept {
		t.Fatalf("the sweep did not look at %s: %+v", hash, states)
	}
	builds, err := ListBuilds(SweepOptions{StateDir: state}, states)
	if err != nil {
		t.Logf("ListBuilds: %v", err)
	}
	var row *BuildInfo
	for i := range builds {
		if builds[i].Hash == hash {
			row = &builds[i]
		}
	}
	if row == nil {
		t.Fatalf("ListBuilds lists no build %s: %+v", hash, builds)
	}
	if row.InUse || row.Kept != KeptLive || row.KeptCause != "" {
		t.Fatalf("the row: in use %v, kept %q (%q); want kept by a live run", row.InUse, row.Kept, row.KeptCause)
	}
	var v []byte
	if err := set.Lookup(gone, &v); err != nil {
		t.Fatalf("the listing deleted the run-set row of a cgroup that is gone: %v", err)
	}
	t.Logf("the row: idle %v, kept %q", row.Idle, row.Kept)
}

// bpftoolMemlock sums bpftool's bytes_memlock over what the pins under roots hold, each id once, reading every pin
// with bpftool as a map, a program or a link, and following links to their programs and programs to their maps.
func bpftoolMemlock(t *testing.T, bpftool string, roots []string) (total uint64, objects int) {
	t.Helper()
	var failed []string
	show := func(kind string, args ...string) (map[string]any, bool) {
		cmd := exec.Command(bpftool, append([]string{"-j", kind, "show"}, args...)...)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		var v map[string]any
		// bpftool 7.7 prints a raw_tracepoint link whole and still exits 255 (seen in the 6.17 guest): an object it
		// printed with its id and no error is read, whatever its exit status.
		if jerr := json.Unmarshal(out, &v); jerr != nil || v["error"] != nil || v["id"] == nil {
			failed = append(failed, fmt.Sprintf("%s show %v: %v: %s%s", kind, args, err, out, stderr.String()))
			return nil, false
		}
		return v, true
	}
	maps, progs := map[uint64]bool{}, map[uint64]bool{}
	var linked, used []uint64
	addMap := func(v map[string]any) {
		id := uint64(v["id"].(float64))
		if !maps[id] {
			maps[id] = true
			n, _ := v["bytes_memlock"].(float64)
			total += uint64(n)
		}
	}
	addProg := func(v map[string]any) {
		id := uint64(v["id"].(float64))
		if progs[id] {
			return
		}
		progs[id] = true
		n, _ := v["bytes_memlock"].(float64)
		total += uint64(n)
		ids, _ := v["map_ids"].([]any)
		for _, m := range ids {
			used = append(used, uint64(m.(float64)))
		}
	}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return err
			}
			failed = failed[:0]
			if v, ok := show("map", "pinned", path); ok {
				addMap(v)
			} else if v, ok := show("prog", "pinned", path); ok {
				addProg(v)
			} else if v, ok := show("link", "pinned", path); ok {
				linked = append(linked, uint64(v["prog_id"].(float64)))
			} else {
				t.Fatalf("bpftool reads %s as no map, program or link:\n%s", path, strings.Join(failed, "\n"))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	for _, id := range linked {
		if v, ok := show("prog", "id", fmt.Sprint(id)); ok {
			addProg(v)
		}
	}
	for _, id := range used {
		if v, ok := show("map", "id", fmt.Sprint(id)); ok {
			addMap(v)
		}
	}
	return total, len(maps) + len(progs)
}
