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
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The TLS probes' activity stamp on a real kernel (limits R4, capture-derive R4 and R9, A-REC-1, A-REC-3, A-REC-5):
// a record: off run with a stall budget has the shared probes placed for it, and its client's TLS calls stamp its
// slot of tego_activity and nothing else of it is read or written: no chunk, no scratch row, no chunk number, no
// miss. A recording run's calls stamp its own slot too, beside its capture.

// activityRow is a run-set row of the given record mode carrying TEGO_RUN_ACTIVITY, as the backend writes for a
// stall-bounded run.
func activityRow(slot uint32, mode bpf.RecordMode) bpf.Run {
	return bpf.Run{RunIdx: slot, Descendants: 1, Tier: 2, Record: uint8(mode), Gen: 7, Flags: bpf.RunActivity}
}

// seedActivityRuns pins the build's run set, capture ring outer, capture counters and activity stamps where the
// tier-2 backend pins them, writes each cgroup's row and gives a capture ring to the slots ring names, which is
// what Prepare has done by the time a capture source starts.
func seedActivityRuns(t *testing.T, maps string, rows map[uint64]bpf.Run, ring map[uint32]bool) map[string]*ebpf.Map {
	t.Helper()
	spec, err := bpf.Load(bpf.ObjectUprobeSSL)
	if err != nil {
		t.Fatalf("load %s: %v", bpf.ObjectUprobeSSL, err)
	}
	pinned := map[string]*ebpf.Map{}
	for _, name := range []string{bpf.MapRunSet, bpf.MapCaptureEvents, bpf.MapCaptureLost, bpf.MapCaptureMiss, bpf.MapActivity} {
		ms := spec.Maps[name]
		if ms == nil {
			t.Fatalf("%s declares no %s", bpf.ObjectUprobeSSL, name)
		}
		m, err := ebpf.NewMapWithOptions(ms.Copy(), ebpf.MapOptions{PinPath: maps})
		if err != nil {
			t.Fatalf("pin %s: %v", name, err)
		}
		t.Cleanup(func() { _ = m.Close() })
		pinned[name] = m
	}
	for cg, row := range rows {
		if ring[row.RunIdx] {
			r, err := bpf.NewRing(bpf.RingCapture, 4<<20)
			if err != nil {
				t.Fatal(err)
			}
			if err := bpf.InsertRing(pinned[bpf.MapCaptureEvents], row.RunIdx, r); err != nil {
				t.Fatal(err)
			}
			_ = r.Close()
		}
		if err := pinned[bpf.MapRunSet].Update(&cg, &row, ebpf.UpdateAny); err != nil {
			t.Fatalf("insert cgroup %d into the run set: %v", cg, err)
		}
	}
	return pinned
}

// tlsServer answers each connection's one request with captureResponse until the test ends.
func tlsServer(t *testing.T) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for serveOne(ln) == nil {
		}
	}()
	return strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
}

// clientIn runs offRunClient, one exchange, as a process of the cgroup fd names, and returns its pid.
func clientIn(t *testing.T, python string, fd int, port string) int {
	t.Helper()
	cmd := exec.Command(python, "-c", offRunClient, port)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("python3: %v: %s", err, out)
	}
	return cmd.Process.Pid
}

func activityMonoNow(t *testing.T) uint64 {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatal(err)
	}
	return uint64(ts.Nano())
}

// sslKeysOf reports whether one of the capture maps keyed by (pid_tgid, ssl_ptr), or by pid_tgid, holds a key of
// process pid.
func sslKeysOf(t *testing.T, maps string, pid int) []string {
	t.Helper()
	var found []string
	for _, name := range []string{bpf.MapSSLScratch, bpf.MapSSLSeq} {
		m, err := ebpf.LoadPinnedMap(filepath.Join(maps, name), nil)
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		var key bpf.SSLKey
		var val []byte
		it := m.Iterate()
		for it.Next(&key, &val) {
			if int(key.PidTgid>>32) == pid {
				found = append(found, name)
			}
		}
		_ = m.Close()
	}
	m, err := ebpf.LoadPinnedMap(filepath.Join(maps, bpf.MapSSLCurrent), nil)
	if err != nil {
		t.Fatalf("open %s: %v", bpf.MapSSLCurrent, err)
	}
	defer m.Close()
	var id, ptr uint64
	it := m.Iterate()
	for it.Next(&id, &ptr) {
		if int(id>>32) == pid {
			found = append(found, bpf.MapSSLCurrent)
		}
	}
	return found
}

func TestIntegrationRecordOffStampsWithoutCapture(t *testing.T) {
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
	_, offFD, offID := childCgroupOf(t, "off")
	pinned := seedActivityRuns(t, maps, map[uint64]bpf.Run{offID: activityRow(2, bpf.RecordOff)}, nil)
	port := tlsServer(t)
	var mu sync.Mutex
	var handed []detachJob
	u, err := New(Options{Kernel: true, PinRoot: root, StateDir: t.TempDir(), Logger: testLogger(t),
		Rules:  &agent.RuleTable{Record: agent.RecordOff, Limits: agent.ResolvedLimits{StallAfter: 3 * time.Second, Set: agent.BudgetStallAfter}},
		Detach: func(j detachJob) { mu.Lock(); handed = append(handed, j); mu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	u.FollowKernel(hash)
	if err := u.Start(context.Background(), source.RunRef{ID: "r-int-off", Agent: "a", CgroupID: offID}, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = u.Stop() })
	if gaps := u.Gaps(); len(gaps) != 1 || gaps[0].Why != GapMechanismUnavailable {
		t.Fatalf("gaps %+v, want the mechanism-unavailable gap alone: an off run keeps no capture", gaps)
	}
	if libs := pinnedLinkIDs(t, filepath.Join(root, hash)); len(libs) == 0 {
		t.Fatal("no probe was placed for a record: off run with a stall budget")
	}
	before := activityMonoNow(t)
	pid := clientIn(t, python, offFD, port)
	after := activityMonoNow(t)
	got, err := bpf.ActivityAt(pinned[bpf.MapActivity], 2)
	if err != nil {
		t.Fatal(err)
	}
	if got < before || got > after {
		t.Fatalf("tego_activity[2] = %d after the off run's TLS exchange, want a stamp in [%d, %d]", got, before, after)
	}
	if n, err := bpf.SlotCount(pinned[bpf.MapCaptureMiss], 2); err != nil || n != 0 {
		t.Errorf("tego_capture_miss[2] = %d (%v): an off run's call went past its record: off return", n, err)
	}
	if _, ok, err := bpf.RingOf(pinned[bpf.MapCaptureEvents], 2); err != nil || ok {
		t.Errorf("a capture ring at the off run's slot (%v, %v)", ok, err)
	}
	if keys := sslKeysOf(t, maps, pid); len(keys) != 0 {
		t.Errorf("the off run's client left keys in %v: a scratch row or chunk number of a run that captures nothing", keys)
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	mu.Lock()
	jobs := append([]detachJob(nil), handed...)
	mu.Unlock()
	if len(jobs) == 0 {
		t.Fatal("the activity-only run, the library's last holder, handed nothing to the detacher")
	}
	for _, j := range jobs {
		if err := detachAfter(j, 0); err != nil {
			t.Fatal(err)
		}
	}
	if left, _ := os.ReadDir(filepath.Join(root, hash, UprobePinDir)); len(left) != 0 {
		t.Fatalf("left under the build's uprobes directory after the last holder: %v", left)
	}
}

// TestIntegrationRecordOffActivityIsIsolated: an off run that talks TLS beside a summary run that is idle stamps
// only its own slot, and the summary run then captures its own exchange unchanged, its calls stamping its own slot
// (A-REC-5: the stamp in every mode). Each source's probes are the build's shared ones.
func TestIntegrationRecordOffActivityIsIsolated(t *testing.T) {
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
	_, offFD, offID := childCgroupOf(t, "off")
	_, sumFD, sumID := childCgroupOf(t, "sum")
	pinned := seedActivityRuns(t, maps, map[uint64]bpf.Run{offID: activityRow(2, bpf.RecordOff),
		sumID: activityRow(1, bpf.RecordSummary)}, map[uint32]bool{1: true})
	port := tlsServer(t)
	state := t.TempDir()
	stall := agent.ResolvedLimits{StallAfter: 3 * time.Second, Set: agent.BudgetStallAfter}
	start := func(id string, cg uint64, mode agent.RecordMode, sink *fakeSink) *Uprobe {
		u, err := New(Options{Kernel: true, PinRoot: root, StateDir: state, Logger: testLogger(t), Detach: func(detachJob) {},
			Rules: &agent.RuleTable{Record: mode, Limits: stall}})
		if err != nil {
			t.Fatal(err)
		}
		u.FollowKernel(hash)
		if err := u.Start(context.Background(), source.RunRef{ID: id, Agent: "a", CgroupID: cg}, sink); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = u.Stop() })
		return u
	}
	sumSink := &fakeSink{}
	summary := start("r-int-sum", sumID, agent.RecordSummary, sumSink)
	if gaps := summary.Gaps(); len(gaps) != 0 {
		t.Fatalf("the summary run's source did not come up: %+v", gaps)
	}
	off := start("r-int-off", offID, agent.RecordOff, &fakeSink{})
	clientIn(t, python, offFD, port)
	if v, _ := bpf.ActivityAt(pinned[bpf.MapActivity], 2); v == 0 {
		t.Fatal("the off run's exchange stamped nothing at its slot")
	}
	if v, _ := bpf.ActivityAt(pinned[bpf.MapActivity], 1); v != 0 {
		t.Fatalf("the idle summary run's slot reads %d after the off run's exchange", v)
	}
	before := activityMonoNow(t)
	clientIn(t, python, sumFD, port)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && len(sumSink.events()) < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if v, _ := bpf.ActivityAt(pinned[bpf.MapActivity], 1); v < before {
		t.Fatalf("the summary run's own exchange left its slot at %d, before %d: the probes stamp in every mode", v, before)
	}
	if err := off.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := summary.Stop(); err != nil {
		t.Fatal(err)
	}
	evs := sumSink.events()
	if len(evs) != 2 || evs[0].Kind != record.KindSSLRequest || evs[1].Kind != record.KindSSLResponse {
		t.Fatalf("the summary run recorded %d events, want its own exchange once: %+v", len(evs), evs)
	}
	for _, ev := range evs {
		if ev.Cgroup != sumID {
			t.Errorf("the summary run recorded %s of cgroup %d, the off run's", ev.Kind, ev.Cgroup)
		}
	}
}
