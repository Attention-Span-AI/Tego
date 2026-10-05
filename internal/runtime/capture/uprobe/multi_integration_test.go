// SPDX-License-Identifier: Apache-2.0

//go:build integration

package uprobe

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
)

// Each mode uses actual OpenSSL TLS in two concurrent governed cgroups and a
// third no-ring cgroup. The individual mode removes only optional dispatchers
// from the actual loaded collection, exercising the production fallback branch.
// The separate mode is two cold runs of one build that each load their own
// programs, as a lost program-pin race leaves them: the second run's dispatchers
// have other program IDs than the pair the first placed, and it adopts the pair
// all the same (capture-1).
func TestIntegrationTLSMultiDispatchAndFallback(t *testing.T) {
	requireObjects(t)
	requireRoot(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("needs python3 and OpenSSL TLS: %v", err)
	}
	if len(systemLibraries("/", nil)) == 0 {
		t.Skip("needs a system libssl for real TLS capture")
	}
	for _, mode := range []string{"multi", "separate", "individual"} {
		t.Run(mode, func(t *testing.T) {
			if mode != "individual" {
				if err := features.HaveBPFLinkUprobeMulti(); err != nil {
					t.Skipf("actual kernel has no available uprobe_multi: %v", err)
				}
			}
			tlsMultiLifecycle(t, python, mode)
		})
	}
}

func tlsMultiLifecycle(t *testing.T, python, mode string) {
	const hash = "integration"
	root, maps := bpffsPinRoot(t, hash)
	build := filepath.Join(root, hash)
	// Without the build's program directory no run pins its programs for the next to adopt, so every
	// LoadCollection below loads programs of its own.
	separate := mode == "separate"
	if !separate {
		if err := os.Mkdir(filepath.Join(build, progDir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	_, firstFD, firstCG := childCgroupOf(t, "multi-first")
	_, secondFD, secondCG := childCgroupOf(t, "multi-second")
	_, offFD, offCG := childCgroupOf(t, "multi-off")
	seedRuns(t, maps, map[uint64]uint32{firstCG: 1, secondCG: 2, offCG: 3}, map[uint32]bool{3: true})
	coll, err := LoadCollection(root, hash)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	if mode != "individual" && (coll.Programs[bpf.ProgSSLMultiEnter] == nil || coll.Programs[bpf.ProgSSLMultiReturn] == nil) {
		t.Fatal("feature probe passed but complete multi programs did not load")
	}
	if mode == "individual" {
		for _, n := range []string{bpf.ProgSSLMultiEnter, bpf.ProgSSLMultiReturn} {
			if p := coll.Programs[n]; p != nil {
				_ = p.Close()
				delete(coll.Programs, n)
			}
		}
	}
	state := t.TempDir()
	var mu sync.Mutex
	var jobs []detachJob
	detach := func(j detachJob) { mu.Lock(); jobs = append(jobs, j); mu.Unlock() }
	attacher := func(coll *ebpf.Collection) *sharedAttacher {
		return &sharedAttacher{EBPFAttacher: NewAttacher(coll), root: build, state: state, hash: hash, detach: detach, logf: t.Logf}
	}
	makeSource := func(id string, cg uint64, sink *fakeSink, coll *ebpf.Collection) *Uprobe {
		att := attacher(coll)
		u, err := New(Options{Kernel: true, PinRoot: root, StateDir: state, Attacher: att, Detach: detach, Logger: testLogger(t)})
		if err != nil {
			t.Fatal(err)
		}
		u.FollowKernel(hash)
		if err := u.Start(t.Context(), source.RunRef{ID: id, Agent: "multi", CgroupID: cg}, sink); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = u.Stop() })
		if gaps := u.Gaps(); len(gaps) != 0 {
			t.Fatalf("source unavailable: %+v", gaps)
		}
		return u
	}
	firstSink, secondSink := &fakeSink{}, &fakeSink{}
	first := makeSource("r-multi-first", firstCG, firstSink, coll)
	placed := pinnedLinkIDs(t, build)
	if len(placed) == 0 {
		t.Fatal("no shared TLS links pinned")
	}
	for library, ids := range placed {
		if mode != "individual" && len(ids) != 2 {
			t.Fatalf("%s has%d links, need actual multi pair", library, len(ids))
		}
		for i := range ids {
			l, err := link.LoadPinnedLink(filepath.Join(build, UprobePinDir, library, strconv.Itoa(i)), nil)
			if err != nil {
				t.Fatal(err)
			}
			info, err := l.Info()
			_ = l.Close()
			if err != nil {
				t.Fatal(err)
			}
			if (info.Type == link.UprobeMultiType) != (mode != "individual") {
				t.Fatalf("%s wrong actual link type%d for%s", library, info.Type, mode)
			}
		}
	}
	secondColl := coll
	if separate {
		if secondColl, err = LoadCollection(root, hash); err != nil {
			t.Fatal(err)
		}
		defer secondColl.Close()
		for _, n := range []string{bpf.ProgSSLMultiEnter, bpf.ProgSSLMultiReturn} {
			if programID(t, coll, n) == programID(t, secondColl, n) {
				t.Fatalf("separate loads share %s; the second run would not prove adoption across loads", n)
			}
		}
	}
	second := makeSource("r-multi-second", secondCG, secondSink, secondColl)
	assertLinks := func() {
		got := pinnedLinkIDs(t, build)
		if len(got) != len(placed) {
			t.Fatalf("shared link directories changed: %v ->%v", placed, got)
		}
		for lib, ids := range placed {
			if !slices.Equal(ids, got[lib]) {
				t.Fatalf("shared links replaced while held: %v ->%v", placed, got)
			}
		}
	}
	assertLinks()
	if separate {
		// A run without the dispatchers cannot tell the pair is this build's; individual probes of its own beside
		// it would capture every TLS call of the run set twice (ADR 0026 (7)), so it refuses the library.
		bare, err := LoadCollection(root, hash)
		if err != nil {
			t.Fatal(err)
		}
		defer bare.Close()
		for _, n := range []string{bpf.ProgSSLMultiEnter, bpf.ProgSSLMultiReturn} {
			_ = bare.Programs[n].Close()
			delete(bare.Programs, n)
		}
		refused := 0
		for _, path := range systemLibraries("/", nil) {
			id, err := candidateIdentity(path)
			if err != nil || placed[libKey(id)] == nil {
				continue
			}
			bin, err := readBinary(path)
			if err != nil {
				t.Fatal(err)
			}
			links, err := attacher(bare).AttachBinary(path, id, probesFor(bin))
			if !errors.Is(err, ErrAttachFailed) {
				closeProbes(links)
				t.Fatalf("%s: a run without the dispatchers did not refuse the pair: %v", path, err)
			}
			refused++
		}
		if refused == 0 {
			t.Fatal("no placed library was found to refuse")
		}
		assertLinks()
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	served := make(chan error, 3)
	for range 3 {
		go func() { served <- serveOne(ln) }()
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	type result struct {
		pid int
		out []byte
		err error
	}
	clients := make([]*exec.Cmd, 3)
	results := make(chan result, 3)
	for i, fd := range []int{firstFD, secondFD, offFD} {
		cmd := exec.CommandContext(t.Context(), python, "-c", eagerClient, port)
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
		clients[i] = cmd
		go func() {
			out, err := cmd.CombinedOutput()
			pid := 0
			if cmd.Process != nil {
				pid = cmd.Process.Pid
			}
			results <- result{pid, out, err}
		}()
	}
	for range 3 {
		r := <-results
		if r.err != nil {
			t.Fatalf("real TLS pid%d: %v %s", r.pid, r.err, r.out)
		}
	}
	for range 3 {
		if err := <-served; err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for (len(firstSink.events()) < 2 || len(secondSink.events()) < 2) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := first.Stop(); err != nil {
		t.Fatal(err)
	}
	assertLinks()
	mu.Lock()
	handed := len(jobs)
	mu.Unlock()
	if handed != 0 {
		t.Fatal("first holder scheduled detach while second was live")
	}
	// A synchronous sweep sees the actual shared hold and must leave the pair.
	for lib := range placed {
		if err := detachAfter(detachJob{root: build, state: state, hash: hash, key: lib}, 0); err != nil {
			t.Fatal(err)
		}
	}
	assertLinks()
	if err := second.Stop(); err != nil {
		t.Fatal(err)
	}
	for i, sink := range []*fakeSink{firstSink, secondSink} {
		events := sink.events()
		cg := firstCG
		if i == 1 {
			cg = secondCG
		}
		if len(events) != 2 || events[0].Kind != record.KindSSLRequest || events[1].Kind != record.KindSSLResponse {
			t.Fatalf("run%d capture not exactly once: %+v", i, events)
		}
		for _, ev := range events {
			if ev.Cgroup != cg || ev.PID != clients[i].Process.Pid {
				t.Fatalf("cross-run TLS delivery: %+v expected cgroup%d pid%d", ev, cg, clients[i].Process.Pid)
			}
		}
		var response record.SSLResponsePayload
		if err := json.Unmarshal(events[1].Payload, &response); err != nil {
			t.Fatal(err)
		}
		if response.Status != 200 || response.Truncated {
			t.Fatalf("actual TLS response was incomplete or unsuccessful: %+v", response)
		}
	}
	miss, err := ebpf.LoadPinnedMap(filepath.Join(maps, bpf.MapCaptureMiss), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer miss.Close()
	if count, err := bpf.SlotCount(miss, 3); err != nil || count == 0 {
		t.Fatalf("no-ring TLS calls did not reach filtered shared probes: %d %v", count, err)
	}
	mu.Lock()
	pending := append([]detachJob(nil), jobs...)
	mu.Unlock()
	if len(pending) != len(placed) {
		t.Fatalf("last holder handed%d jobs, want%d", len(pending), len(placed))
	}
	for _, j := range pending {
		if err := detachAfter(j, 0); err != nil {
			t.Fatal(err)
		}
	}
	if left := pinnedLinkIDs(t, build); len(left) != 0 {
		t.Fatalf("idle TLS links remain: %v", left)
	}
	t.Logf("actual%s: %d libraries, two isolated exchanges, no-ring miss counted, adoption/lifetime/cleanup proved", mode, len(placed))
}

// programID is the kernel's id of one program of a loaded collection.
func programID(t *testing.T, coll *ebpf.Collection, name string) ebpf.ProgramID {
	t.Helper()
	info, err := coll.Programs[name].Info()
	if err != nil {
		t.Fatal(err)
	}
	id, ok := info.ID()
	if !ok {
		t.Fatalf("%s: the kernel reports no program id", name)
	}
	return id
}
