// SPDX-License-Identifier: Apache-2.0

//go:build integration

package observe

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// TestMissCountersFollowAttachedPrograms recreates independent winners of the program-pin and link-pin
// races: progs/tego_file_open is inactive, while links/tego_file_open executes another instance.
func TestMissCountersFollowAttachedPrograms(t *testing.T) {
	root, active, inactive := differingMissInstances(t)
	refs := programReferences(t)
	r := &Recorder{opts: Options{PinRoot: root, BPFHash: "miss-instances"}}
	counter, err := r.openMisses()
	if err != nil {
		t.Fatal(err)
	}
	defer counter.Close() //nolint:errcheck // descriptor cleanup
	got := programReferences(t)
	if got[active]-refs[active] != 1 || got[inactive] != refs[inactive] {
		t.Fatalf("retained refs to active/inactive program IDs %d/%d: delta %d/%d, want 1/0",
			active, inactive, got[active]-refs[active], got[inactive]-refs[inactive])
	}
}

func TestMissingActiveMissInstanceIsUncertain(t *testing.T) {
	root, _, _ := differingMissInstances(t)
	if err := os.Remove(filepath.Join(root, "miss-instances", "links", bpf.ProgFileOpen)); err != nil {
		t.Fatal(err)
	}
	f := newFixture(t)
	r, err := New(Options{Rules: f.rules, Reader: newFakeRing(), PinRoot: root, BPFHash: "miss-instances"})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(t.Context(), source.RunRef{ID: "r-unknown-active-program"}, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	for _, gap := range r.Gaps() {
		if gap.Why == GapTrampolineCounterUnavailable {
			return
		}
	}
	t.Fatalf("the inactive program's zero counter claimed complete coverage: %+v", r.Gaps())
}

func differingMissInstances(t *testing.T) (string, ebpf.ProgramID, ebpf.ProgramID) {
	t.Helper()
	if !bpf.Available() {
		t.Skipf("needs the compiled objects: %v", bpf.ErrNotGenerated)
	}
	root, maps := pinRoot(t, "miss-instances")
	coll := loadTraceProc(t, maps)
	activeInfo, err := coll.Programs[bpf.ProgFileOpen].Info()
	if err != nil {
		t.Fatal(err)
	}
	active, _ := activeInfo.ID()
	inactive, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.SocketFilter, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inactive.Close() })
	info, err := inactive.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := info.ID()
	path := filepath.Join(root, "miss-instances", "progs", bpf.ProgFileOpen)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := inactive.Pin(path); err != nil {
		t.Fatal(err)
	}
	return root, active, id
}

// programReferences counts retained program descriptors, not link descriptors (which also name a prog_id).
// The assertion observes which kernel object the recorder holds without depending on its counter wrapper type.
func programReferences(t *testing.T) map[ebpf.ProgramID]int {
	t.Helper()
	paths, err := filepath.Glob("/proc/self/fdinfo/*")
	if err != nil {
		t.Fatal(err)
	}
	counts := map[ebpf.ProgramID]int{}
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if os.IsNotExist(err) { // the descriptor used to list fdinfo has closed
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "\nprog_type:") {
			continue
		}
		for _, line := range strings.Split(string(body), "\n") {
			if s, ok := strings.CutPrefix(line, "prog_id:"); ok {
				id, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
				if err != nil {
					t.Fatal(err)
				}
				counts[ebpf.ProgramID(id)]++
			}
		}
	}
	return counts
}
