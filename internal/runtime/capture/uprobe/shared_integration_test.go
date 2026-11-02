// SPDX-License-Identifier: Apache-2.0

//go:build integration

package uprobe

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// pinnedLinkIDs lists the link id of every probe pinned for every library of a build, by library directory.
func pinnedLinkIDs(t *testing.T, buildRoot string) map[string][]link.ID {
	t.Helper()
	out := map[string][]link.ID{}
	libs, err := os.ReadDir(filepath.Join(buildRoot, UprobePinDir))
	if os.IsNotExist(err) {
		return out
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, lib := range libs {
		dir := filepath.Join(buildRoot, UprobePinDir, lib.Name())
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			l, err := link.LoadPinnedLink(filepath.Join(dir, e.Name()), nil)
			if err != nil {
				t.Fatalf("pinned probe %s/%s: %v", dir, e.Name(), err)
			}
			info, err := l.Info()
			_ = l.Close()
			if err != nil {
				t.Fatal(err)
			}
			out[lib.Name()] = append(out[lib.Name()], info.ID)
		}
		sort.Slice(out[lib.Name()], func(i, j int) bool { return out[lib.Name()][i] < out[lib.Name()][j] })
	}
	return out
}

// TestIntegrationSharedProbesAreAdoptedAndCaptureOnce is ADR 0026 (7) on a real kernel: a run places the host
// libssl's probes and pins them under the build, with its programs; leaving last it hands them to the detacher
// and removes nothing itself; the build's next run adopts the same links and loads no program, and still
// captures its client's exchange exactly once; a detacher that finds a run holding the library keeps the
// probes; and once no run holds it, the detacher unpins them and nothing of them is left.
func TestIntegrationSharedProbesAreAdoptedAndCaptureOnce(t *testing.T) {
	requireObjects(t)
	requireRoot(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	if len(systemLibraries("/", nil)) == 0 {
		t.Skip("this host has no libssl for pre-attach to find")
	}
	const hash = "integration"
	root, maps := bpffsPinRoot(t, hash)
	build := filepath.Join(root, hash)
	if err := os.Mkdir(filepath.Join(build, progDir), 0o700); err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	cg := selfCgroupID(t)
	seedRunSet(t, maps, map[uint64]uint32{cg: 1})
	var mu sync.Mutex
	var handed []detachJob
	detach := func(j detachJob) { mu.Lock(); handed = append(handed, j); mu.Unlock() }
	newSource := func(id string, sink *fakeSink) *Uprobe {
		u, err := New(Options{Kernel: true, PinRoot: root, StateDir: state, Detach: detach,
			Logger: testLogger(t)})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		u.FollowKernel(hash)
		if err := u.Start(context.Background(), source.RunRef{ID: id, Agent: "a", CgroupID: cg}, sink); err != nil {
			t.Fatalf("Start: %v", err)
		}
		t.Cleanup(func() { _ = u.Stop() })
		if gaps := u.Gaps(); len(gaps) != 0 {
			t.Fatalf("the source did not come up: %+v", gaps)
		}
		return u
	}

	first := newSource("r-int-shared-1", &fakeSink{})
	placed := pinnedLinkIDs(t, build)
	if len(placed) == 0 {
		t.Fatalf("the first run pinned no probe under %s", build)
	}
	progs, _ := os.ReadDir(filepath.Join(build, progDir))
	if len(progs) == 0 {
		t.Fatal("the first run pinned no capture program for the next to adopt")
	}
	if err := first.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := pinnedLinkIDs(t, build); len(got) != len(placed) {
		t.Fatalf("the leaving run removed probes itself (%v, then %v): that is the detacher's, off its path", placed, got)
	}
	mu.Lock()
	if len(handed) != len(placed) {
		t.Fatalf("the last run out handed %d libraries to the detacher, want %d", len(handed), len(placed))
	}
	mu.Unlock()

	// The next run adopts the same links.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	served := make(chan error, 1)
	go func() { served <- serveOne(ln) }()
	sink := &fakeSink{}
	second := newSource("r-int-shared-2", sink)
	adopted := pinnedLinkIDs(t, build)
	for lib, ids := range placed {
		if len(adopted[lib]) != len(ids) {
			t.Fatalf("library %s: pinned %v then %v", lib, ids, adopted[lib])
		}
		for i := range ids {
			if adopted[lib][i] != ids[i] {
				t.Fatalf("library %s: the second run placed new probes %v instead of adopting %v", lib, adopted[lib], ids)
			}
		}
	}
	// A detacher that runs while the second run holds the library keeps the probes.
	mu.Lock()
	job := handed[0]
	mu.Unlock()
	if err := detachAfter(job, 0); err != nil {
		t.Fatal(err)
	}
	if got := pinnedLinkIDs(t, build); len(got) != len(placed) {
		t.Fatalf("the detacher removed probes a run holds: %v", got)
	}
	out, err := exec.Command(python, "-c", eagerClient, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)).CombinedOutput()
	if err != nil {
		t.Fatalf("python3: %v: %s", err, out)
	}
	if err := <-served; err != nil {
		t.Fatalf("server: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && len(sink.events()) < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if err := second.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	var kinds []record.Kind
	for _, ev := range sink.events() {
		kinds = append(kinds, ev.Kind)
	}
	if len(kinds) != 2 || kinds[0] != record.KindSSLRequest || kinds[1] != record.KindSSLResponse {
		t.Fatalf("events %v, want the client's request and its response once each through the adopted probes; gaps %+v",
			kinds, second.Gaps())
	}

	// Nobody holds the library now: the detacher unpins the probes and leaves nothing.
	mu.Lock()
	jobs := append([]detachJob(nil), handed...)
	mu.Unlock()
	for _, j := range jobs {
		if err := detachAfter(j, 0); err != nil {
			t.Fatal(err)
		}
	}
	left, _ := os.ReadDir(filepath.Join(build, UprobePinDir))
	if len(left) != 0 {
		t.Fatalf("left under %s: %v", filepath.Join(build, UprobePinDir), left)
	}
}

// TestIntegrationProbesOverRecreatedMapsArePlacedAgain is shared probe adoption after the build's maps are
// re-created, on a real kernel, as root. A run places the host libssl's individual probes, pins them under the
// build and leaves; the build's maps and programs are then removed and made again with the probes' pins left (a
// build removal that failed part way at them, or one made by hand), so those probes run the old programs over the
// old run set. The build's next run finds their pins complete. Adopted on their count, as they were, they wrote its
// client's exchange to the old maps' ring, which no run reads, and the run recorded neither the exchange nor a gap.
// The run places its own instead, the old probes leave the kernel, and the exchange is captured once.
func TestIntegrationProbesOverRecreatedMapsArePlacedAgain(t *testing.T) {
	requireObjects(t)
	requireRoot(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	if len(systemLibraries("/", nil)) == 0 {
		t.Skip("this host has no libssl for pre-attach to find")
	}
	const hash = "integration"
	root, maps := bpffsPinRoot(t, hash)
	build := filepath.Join(root, hash)
	progs := filepath.Join(build, progDir)
	if err := os.Mkdir(progs, 0o700); err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	cg := selfCgroupID(t)
	seedRunSet(t, maps, map[uint64]uint32{cg: 1})
	// Each run's collection is without the multi dispatchers, as a kernel without uprobe_multi loads it, so the
	// probes are individual ones whatever this kernel offers.
	individual := func() *ebpf.Collection {
		t.Helper()
		coll, err := LoadCollection(root, hash)
		if err != nil {
			t.Fatalf("LoadCollection: %v", err)
		}
		for _, n := range []string{bpf.ProgSSLMultiEnter, bpf.ProgSSLMultiReturn} {
			if p := coll.Programs[n]; p != nil {
				_ = p.Close()
				delete(coll.Programs, n)
			}
		}
		return coll
	}
	// The detacher does nothing: a run that leaves keeps its probes pinned, for the next run to find.
	detach := func(detachJob) {}
	start := func(id string, coll *ebpf.Collection, sink *fakeSink) *Uprobe {
		t.Helper()
		att := &sharedAttacher{EBPFAttacher: NewAttacher(coll), root: build, state: state, hash: hash, detach: detach,
			logf: t.Logf}
		// Every library is pre-attached, however long the replaced probes take to go: one left to its open would
		// leave the comparison below nothing to compare.
		u, err := New(Options{Kernel: true, PinRoot: root, StateDir: state, Attacher: att, Detach: detach,
			PreattachBudget: time.Minute, Logger: testLogger(t)})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		u.FollowKernel(hash)
		if err := u.Start(context.Background(), source.RunRef{ID: id, Agent: "a", CgroupID: cg}, sink); err != nil {
			t.Fatalf("Start: %v", err)
		}
		t.Cleanup(func() { _ = u.Stop() })
		if gaps := u.Gaps(); len(gaps) != 0 {
			t.Fatalf("the source did not come up: %+v", gaps)
		}
		return u
	}

	first := individual()
	one := start("r-int-recreated-1", first, &fakeSink{})
	placed := pinnedLinkIDs(t, build)
	if len(placed) == 0 {
		t.Fatalf("the first run pinned no probe under %s", build)
	}
	for lib, ids := range placed {
		for _, id := range ids {
			l, err := link.NewFromID(id)
			if err != nil {
				t.Fatalf("library %s: link %d: %v", lib, id, err)
			}
			info, err := l.Info()
			_ = l.Close()
			if err != nil || info.Type != link.PerfEventType {
				t.Fatalf("library %s: link %d is not a single probe's (%v)", lib, id, err)
			}
		}
	}
	if err := one.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	first.Close()
	// The build's maps and programs go and are made again; the probes' pins stay.
	for _, dir := range []string{maps, progs} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
	seedRunSet(t, maps, map[uint64]uint32{cg: 1})
	second := individual()
	defer second.Close()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	served := make(chan error, 1)
	go func() { served <- serveOne(ln) }()
	sink := &fakeSink{}
	two := start("r-int-recreated-2", second, sink)
	again := pinnedLinkIDs(t, build)
	for lib, ids := range placed {
		if len(again[lib]) != len(ids) {
			t.Fatalf("library %s: pinned %v, then %v", lib, ids, again[lib])
		}
		for _, id := range ids {
			if slices.Contains(again[lib], id) {
				t.Fatalf("library %s: the second run adopted link %d, whose program reads the maps since re-created",
					lib, id)
			}
		}
	}
	for lib, ids := range placed {
		for _, id := range ids {
			gone := false
			for deadline := time.Now().Add(5 * time.Second); !gone && time.Now().Before(deadline); {
				l, err := link.NewFromID(id)
				if gone = err != nil; !gone {
					_ = l.Close()
					time.Sleep(10 * time.Millisecond)
				}
			}
			if !gone {
				t.Errorf("library %s: the replaced link %d is still in the kernel beside the run's own", lib, id)
			}
		}
	}
	out, err := exec.Command(python, "-c", eagerClient, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)).CombinedOutput()
	if err != nil {
		t.Fatalf("python3: %v: %s", err, out)
	}
	if err := <-served; err != nil {
		t.Fatalf("server: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && len(sink.events()) < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if err := two.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	var kinds []record.Kind
	for _, ev := range sink.events() {
		kinds = append(kinds, ev.Kind)
	}
	if len(kinds) != 2 || kinds[0] != record.KindSSLRequest || kinds[1] != record.KindSSLResponse {
		t.Fatalf("events %v, want the client's request and its response once each through the run's own probes; gaps %+v",
			kinds, two.Gaps())
	}
	for lib := range again {
		if err := detachAfter(detachJob{root: build, state: state, hash: hash, key: lib}, 0); err != nil {
			t.Fatal(err)
		}
	}
	if left, _ := os.ReadDir(filepath.Join(build, UprobePinDir)); len(left) != 0 {
		t.Fatalf("left under %s: %v", filepath.Join(build, UprobePinDir), left)
	}
}

// TestIntegrationProbesWhoseDetacherDiedGoAtTheNextStart is round 7's M4 (b) on a real kernel, as root: the last
// run out hands a library's probes to a detacher, and the detacher is gone (killed with the launcher's cgroup,
// or by anyone) before it removes them. Once ProbeGrace has passed, the next run's source removes them as it
// starts: the old links no longer exist in the kernel, and that run places its own.
func TestIntegrationProbesWhoseDetacherDiedGoAtTheNextStart(t *testing.T) {
	requireObjects(t)
	requireRoot(t)
	if len(systemLibraries("/", nil)) == 0 {
		t.Skip("this host has no libssl for pre-attach to find")
	}
	const hash = "integration"
	root, maps := bpffsPinRoot(t, hash)
	build := filepath.Join(root, hash)
	if err := os.Mkdir(filepath.Join(build, progDir), 0o700); err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	cg := selfCgroupID(t)
	seedRunSet(t, maps, map[uint64]uint32{cg: 1})
	start := func(id string, detach func(detachJob)) *Uprobe {
		t.Helper()
		u, err := New(Options{Kernel: true, PinRoot: root, StateDir: state, Detach: detach, Logger: testLogger(t)})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		u.FollowKernel(hash)
		if err := u.Start(context.Background(), source.RunRef{ID: id, Agent: "a", CgroupID: cg}, &fakeSink{}); err != nil {
			t.Fatalf("Start: %v", err)
		}
		t.Cleanup(func() { _ = u.Stop() })
		return u
	}
	first := start("r-int-died-1", func(detachJob) {}) // the detacher dies before it does anything
	placed := pinnedLinkIDs(t, build)
	if len(placed) == 0 {
		t.Fatalf("the first run pinned no probe under %s", build)
	}
	if err := first.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	time.Sleep(ProbeGrace + 1500*time.Millisecond) // past the grace by more than the lock mtime's second

	start("r-int-died-2", func(detachJob) {})
	for lib, ids := range placed {
		for _, id := range ids {
			if l, err := link.NewFromID(id); err == nil {
				_ = l.Close()
				t.Errorf("library %s: link %d, whose detacher died, is still in the kernel after the next start", lib, id)
			}
		}
	}
}
