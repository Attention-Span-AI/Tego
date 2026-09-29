// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// pinFiles creates empty files standing in for pins in a directory of a build laid out on plain directories.
func pinFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestListBuildsShowsWhatEachBuildHoldsAndWhetherARunHoldsIt is doctor's view of ADR 0022 (8) and ADR 0026
// (7): every build under the bpf filesystem, with its programs, links and capture probes per library, a build
// a launcher holds as in use, and an idle one with its idle time from the build lock's mtime. It changes
// nothing: the idle build's lock is not held, and its mtime is not moved, after the listing.
func TestListBuildsShowsWhatEachBuildHoldsAndWhetherARunHoldsIt(t *testing.T) {
	t.Parallel()
	bpffs, state := t.TempDir(), t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	for _, hash := range []string{"idle", "held"} {
		p, err := newPinLayout(bpffs, hash)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.create(); err != nil {
			t.Fatal(err)
		}
		pinFiles(t, p.Progs, "a", "b", "tego_ssl_write")
		pinFiles(t, p.Links, "a")
		if err := os.WriteFile(filepath.Join(state, "bpf-"+hash+".lock"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	idle, _ := newPinLayout(bpffs, "idle")
	pinFiles(t, filepath.Join(idle.Root, uprobePins, "2-1497-abc"), "0", "1", "2")
	pinFiles(t, filepath.Join(idle.Root, uprobePins, "detaching-2-1497-abc-x"), "0")
	lock := filepath.Join(state, "bpf-idle.lock")
	at := now.Add(-90 * time.Second)
	if err := os.Chtimes(lock, at, at); err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(filepath.Join(state, "bpf-held.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := unix.Flock(int(held.Fd()), unix.LOCK_SH); err != nil {
		t.Fatal(err)
	}

	builds, err := ListBuilds(SweepOptions{BPFFS: bpffs, StateDir: state, Now: func() time.Time { return now }}, nil)
	if err != nil {
		t.Fatalf("ListBuilds: %v", err)
	}
	got := map[string]BuildInfo{}
	for _, b := range builds {
		got[b.Hash] = b
	}
	if len(got) != 2 {
		t.Fatalf("builds %+v, want idle and held", builds)
	}
	i := got["idle"]
	if i.InUse || i.Idle != 90*time.Second || i.IdleS != 90 || i.Programs != 3 || i.Links != 1 ||
		i.CaptureProbes != 4 || len(i.CaptureLibraries) != 2 || i.Path != idle.Root {
		t.Errorf("idle build: %+v", i)
	}
	if h := got["held"]; !h.InUse || h.Idle != 0 || h.CaptureProbes != 0 {
		t.Errorf("held build: %+v", h)
	}
	st, err := os.Stat(lock)
	if err != nil {
		t.Fatal(err)
	}
	if !st.ModTime().Equal(at) {
		t.Errorf("the listing moved the idle build's lock mtime to %s", st.ModTime())
	}
	f, err := os.Open(lock)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Errorf("the listing left the idle build's lock held: %v", err)
	}
}

// TestRemovingABuildRemovesItsCaptureProbes: the build's removal (the sweep, gc --builds, the last launcher
// out at linger 0) takes the capture probes pinned per library with it, a directory being detached included,
// so nothing of tego stays attached once its build is gone (ADR 0026 (7)).
func TestRemovingABuildRemovesItsCaptureProbes(t *testing.T) {
	t.Parallel()
	p, err := newPinLayout(t.TempDir(), "h")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.create(); err != nil {
		t.Fatal(err)
	}
	pinFiles(t, filepath.Join(p.Root, uprobePins, "2-1497-abc"), "0", "1")
	pinFiles(t, filepath.Join(p.Root, uprobePins, "detaching-2-1497-abc-x"), "0")
	if err := p.remove(); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(p.Root); !os.IsNotExist(err) {
		t.Fatalf("the build's pin directory is still there: %v", err)
	}
}

// TestListBuildsSaysWhyABuildIsKeptWhetherItsTimerRunsAndWhatItCharges is ADR 0022 (5) and (8)'s doctor row: a build
// the sweep that ran before the listing kept past its linger says why (a live run, an unreadable run set with what
// the read met), a build whose timer file names a live timer shows that timer's pid, and every build sums the memlock
// of its pinned programs and maps, of its plane directories' and of every program its links attach and map its
// programs use, each object once (a map the build and its plane share counted once), with the objects whose memlock
// the kernel did not report, or whose pin could not be opened, counted apart rather than as 0; a memlock the kernel
// reported as 0 (an empty LPM trie) is a 0, not unreported. A build the sweep left
// inside its linger, or did not name, is asked of its run set at the listing, since gc --builds' Force keeps it just
// the same while a run it enforces is alive or its run set cannot be read: doctor never says gc removes a build gc
// keeps.
func TestListBuildsSaysWhyABuildIsKeptWhetherItsTimerRunsAndWhatItCharges(t *testing.T) {
	t.Parallel()
	bpffs, state := t.TempDir(), t.TempDir()
	for _, hash := range []string{"dup", "live", "unread", "lingerlive", "lingerunread", "unswept"} {
		p, err := newPinLayout(bpffs, hash)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.create(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(state, "bpf-"+hash+".lock"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dup, _ := newPinLayout(bpffs, "dup")
	pinFiles(t, dup.Progs, "a", "b", "bad")
	pinFiles(t, dup.Maps, "m")
	pinFiles(t, dup.Links, "l")
	pinFiles(t, filepath.Join(dup.Links, runLinksPrefix+"r-1"), "l2")
	plane := newPlaneLayout(dup, "dup", planeModes[0])
	pinFiles(t, plane.Maps, "m2")
	pinFiles(t, plane.Progs, "b")
	prog := func(id uint32, memlock uint64, maps ...ebpf.MapID) bpfObject {
		return bpfObject{kind: objProgram, id: id, memlock: memlock, reported: true, maps: maps}
	}
	objects := map[string]bpfObject{
		filepath.Join(dup.Progs, "a"):                        prog(1, 4096, 10, 11),
		filepath.Join(dup.Progs, "b"):                        prog(2, 8192, 10),
		filepath.Join(dup.Maps, "m"):                         {kind: objMap, id: 10, memlock: 1000, reported: true},
		filepath.Join(dup.Links, "l"):                        {kind: objLink, id: 1},
		filepath.Join(dup.Links, runLinksPrefix+"r-1", "l2"): {kind: objLink, id: 3},
		filepath.Join(plane.Maps, "m2"):                      {kind: objMap, id: 11, memlock: 500, reported: true},
		filepath.Join(plane.Progs, "b"):                      prog(2, 8192, 10),
		// An empty LPM trie: its fdinfo says memlock 0, which is reported, not missing.
		filepath.Join(plane.Maps, "trie"): {kind: objMap, id: 13, reported: true},
	}
	pinFiles(t, plane.Maps, "trie")
	read := &bpfObjects{
		pinned: func(path string) (bpfObject, error) {
			o, ok := objects[path]
			if !ok {
				return bpfObject{}, fmt.Errorf("%s: not a bpf object", path)
			}
			return o, nil
		},
		program: func(id ebpf.ProgramID) (bpfObject, error) {
			if id != 3 {
				t.Errorf("program %d, pinned under the build, was looked up again by id", id)
			}
			return prog(3, 100, 12, 13), nil
		},
		mapByID: func(id ebpf.MapID) (bpfObject, error) {
			if id != 12 {
				t.Errorf("map %d, pinned under the build, was looked up again by id", id)
			}
			return bpfObject{kind: objMap, id: 12}, nil // its fdinfo has no memlock line
		},
	}
	if err := os.WriteFile(filepath.Join(state, "bpf-live.timer"), []byte("4242\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "bpf-unread.timer"), []byte("4243\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	swept := []BuildState{
		{Hash: "live", Why: whyLive},
		{Hash: "unread", Why: whyUnread, Cause: "map key size 4, want 8"},
		{Hash: "dup", Why: whyLingering},
		{Hash: "lingerlive", Why: whyLingering},
		{Hash: "lingerunread", Why: whyLingering},
	}
	var mu sync.Mutex
	asked := map[string]bool{}
	runSet := func(path, mount string) (bool, error) {
		hash := filepath.Base(filepath.Dir(filepath.Dir(path)))
		mu.Lock()
		asked[hash] = true
		mu.Unlock()
		if mount != identity.SystemCgroupRoot {
			t.Errorf("the run set of %s was read under %q, want the system's cgroup mount", hash, mount)
		}
		switch hash {
		case "lingerlive", "unswept":
			return true, nil
		case "lingerunread":
			return false, errors.New("map key size 4, want 8")
		}
		return false, fmt.Errorf("open its run set: %w", os.ErrNotExist)
	}
	builds, err := ListBuilds(SweepOptions{BPFFS: bpffs, StateDir: state, objects: read, runSetLive: runSet,
		timerProcess: func(pid int, hash string) bool { return pid == 4242 && hash == "live" }}, swept)
	if err != nil {
		t.Fatalf("ListBuilds: %v", err)
	}
	got := map[string]BuildInfo{}
	for _, b := range builds {
		got[b.Hash] = b
	}
	if d := got["dup"]; d.MemlockBytes != 4096+8192+100+1000+500 || d.MemlockUnreported != 2 || d.Kept != "" ||
		d.Timer || d.TimerPID != 0 {
		t.Errorf("dup: memlock %d (%d unreported), kept %q, timer %v pid %d; want 13888 with 2 unreported, not kept, "+
			"no timer", d.MemlockBytes, d.MemlockUnreported, d.Kept, d.Timer, d.TimerPID)
	}
	if l := got["live"]; l.Kept != KeptLive || l.KeptCause != "" || !l.Timer || l.TimerPID != 4242 {
		t.Errorf("live: %+v, want kept by a live run with its timer pid 4242", l)
	}
	if u := got["unread"]; u.Kept != KeptUnread || u.KeptCause != "map key size 4, want 8" || u.Timer || u.TimerPID != 0 {
		t.Errorf("unread: %+v, want kept for its unreadable run set, with the read's error, and no live timer", u)
	}
	if l := got["lingerlive"]; l.Kept != KeptLive || l.KeptCause != "" {
		t.Errorf("lingerlive: kept %q (%q), want kept by a live run although the sweep left it inside its linger",
			l.Kept, l.KeptCause)
	}
	if u := got["lingerunread"]; u.Kept != KeptUnread || u.KeptCause != "map key size 4, want 8" {
		t.Errorf("lingerunread: kept %q (%q), want kept for its unreadable run set", u.Kept, u.KeptCause)
	}
	if u := got["unswept"]; u.Kept != KeptLive {
		t.Errorf("unswept: kept %q, want kept by a live run: a build no sweep state names is asked as well", u.Kept)
	}
	for _, hash := range []string{"live", "unread"} {
		if asked[hash] {
			t.Errorf("%s: its run set was read again, though the sweep already said why it kept it", hash)
		}
	}
	for _, hash := range []string{"dup", "lingerlive", "lingerunread", "unswept"} {
		if !asked[hash] {
			t.Errorf("%s: its run set was not read", hash)
		}
	}
}

// TestASweepKeepsABuildWhoseRunSetCannotBeReadAndSaysWhy is ADR 0022 (5): a build past its linger whose run set
// cannot be read (a map of another layout pinned under its name) is never removed, by the sweep or by gc --builds'
// Force, and the state names the read's error so doctor can show it.
func TestASweepKeepsABuildWhoseRunSetCannotBeReadAndSaysWhy(t *testing.T) {
	t.Parallel()
	bpffs, state := t.TempDir(), t.TempDir()
	p, err := newPinLayout(bpffs, "unread")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.create(); err != nil {
		t.Fatal(err)
	}
	pinFiles(t, p.Maps, "tego_run_set")
	lock := filepath.Join(state, "bpf-unread.lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatal(err)
	}
	for _, force := range []bool{false, true} {
		states, err := SweepBuilds(SweepOptions{BPFFS: bpffs, StateDir: state, Linger: time.Minute, Force: force,
			runSetLive: func(string, string) (bool, error) { return false, errors.New("map key size 4, want 8") }})
		if err == nil {
			t.Errorf("force %v: the sweep kept a build it cannot read and reported no error", force)
		}
		if len(states) != 1 || states[0].Removed || states[0].Why != whyUnread || states[0].Cause != "map key size 4, want 8" {
			t.Fatalf("force %v: states %+v, want the build kept for its unreadable run set, with the read's error", force, states)
		}
		if _, err := os.Stat(p.Root); err != nil {
			t.Fatalf("force %v: the build went: %v", force, err)
		}
	}
}
