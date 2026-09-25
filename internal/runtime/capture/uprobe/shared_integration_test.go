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
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"

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
