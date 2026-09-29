// SPDX-License-Identifier: Apache-2.0

//go:build integration

package observe

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationAReusedRingHidesThePreviousRun is ADR 0026 (6) as amended on the real objects, as root: a slot's
// record ring outlives its run and is reused by the slot's next run. What the previous run's processes left in
// it (records written after its reader stopped) is consumed by the drain Prepare does before the next run's row
// exists; and were any left, or written by a program that found the previous run's row just before it went, the
// next run's recorder drops it by its generation. The next run's record holds its own processes only.
func TestIntegrationAReusedRingHidesThePreviousRun(t *testing.T) {
	if !bpf.Available() {
		t.Skipf("needs the compiled objects: %v", bpf.ErrNotGenerated)
	}
	const hash, slot = "reuse1", uint32(1)
	root, maps := pinRoot(t, hash)
	coll := loadTraceProc(t, maps)
	runSet := coll.Maps[bpf.MapRunSet]
	ring, err := bpf.NewRing(bpf.RingRecord, uint32(config.DefaultRingbuf))
	if err != nil {
		t.Fatal(err)
	}
	defer ring.Close()
	if err := bpf.InsertRing(coll.Maps[bpf.MapEvents], slot, ring); err != nil {
		t.Fatal(err)
	}
	available := func() int {
		t.Helper()
		rd, err := ringbuf.NewReader(ring)
		if err != nil {
			t.Fatal(err)
		}
		defer rd.Close()
		return rd.AvailableBytes()
	}
	_, fdA, cgA := childCgroup(t, "reuse-a")
	_, fdB, cgB := childCgroup(t, "reuse-b")
	execIn := func(fd int, argv ...string) {
		t.Helper()
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v: %s", argv, err, out)
		}
	}
	// The previous run: its row, a process whose records no reader takes, and its row gone when it ends.
	previous := func() {
		t.Helper()
		row := bpf.Run{RunIdx: slot, Descendants: 1, Tier: 2, Record: uint8(bpf.RecordFull), Gen: uint32(cgA)}
		if err := runSet.Update(&cgA, &row, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		execIn(fdA, "/bin/true")
		if err := runSet.Delete(&cgA); err != nil {
			t.Fatal(err)
		}
		if available() == 0 {
			t.Fatal("the previous run left nothing in the ring: the test would prove nothing")
		}
	}

	previous()
	n, err := bpf.DrainRing(ring)
	if err != nil || n == 0 {
		t.Fatalf("DrainRing = %d, %v: want the previous run's records consumed", n, err)
	}
	if left := available(); left != 0 {
		t.Fatalf("%d bytes in the ring after the drain", left)
	}

	// Left undrained this time: the generation alone keeps it out of the next run's record.
	previous()
	row := bpf.Run{RunIdx: slot, Descendants: 1, Tier: 2, Record: uint8(bpf.RecordFull), Gen: uint32(cgB)}
	if err := runSet.Update(&cgB, &row, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	rules := &agent.RuleTable{Record: agent.RecordFull, Tier: backend.TierCgroup}
	rec, err := New(Options{Rules: rules, BPFHash: hash, PinRoot: root, FlushInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	hook := &hookLog{}
	if err := rec.AddProcessHook(hook); err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if err := rec.Start(context.Background(), source.RunRef{ID: "r-B", Agent: "a", CgroupID: cgB}, sink); err != nil {
		t.Fatal(err)
	}
	execIn(fdB, "/bin/sh", "-c", "exit 0")
	waitDrained(t, rec)
	if err := rec.Stop(); err != nil {
		t.Fatal(err)
	}
	execs := sink.byKind(record.KindExec)
	if len(execs) == 0 {
		t.Fatal("the next run recorded no exec of its own")
	}
	for _, ev := range sink.all() {
		if ev.Cgroup == cgA {
			t.Errorf("the next run recorded %s of the previous run's cgroup %d", ev.Kind, cgA)
		}
	}
	for _, call := range hook.all() {
		if strings.Contains(call, " "+strconv.FormatUint(cgA, 10)+" ") {
			t.Errorf("the next run's hooks were fed %q, a process of the previous run", call)
		}
	}
}
