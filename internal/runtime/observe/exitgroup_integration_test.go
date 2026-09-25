// SPDX-License-Identifier: Apache-2.0

//go:build integration

package observe

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestIntegrationExitIsTheThreadGroups is sched_process_exit on the real objects, as root:
// a process whose thread-group leader exits first and whose other thread then opens a file and ends the
// process. trace_proc reported the leader's exit as the process's, so the recorder told its hook the process
// had exited, and flushed its reads as final, while it went on to open the file; the exit is the group's last
// thread's, after that open, and it is reported once.
func TestIntegrationExitIsTheThreadGroups(t *testing.T) {
	if !bpf.Available() {
		t.Skipf("needs the compiled objects: %v", bpf.ErrNotGenerated)
	}
	const hash = "exitgroup"
	root, maps := pinRoot(t, hash)
	coll := loadTraceProc(t, maps)
	_, fd, cg := childCgroup(t, "exitgroup")
	row := bpf.Run{RunIdx: 1, Descendants: 1, Tier: 2, Record: uint8(bpf.RecordSummary)}
	placeRunRings(t, coll, row.RunIdx)
	if err := coll.Maps[bpf.MapRunSet].Update(&cg, &row, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	rec, err := New(Options{Rules: &agent.RuleTable{Record: agent.RecordSummary, Tier: backend.TierCgroup},
		BPFHash: hash, PinRoot: root, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	hook := &hookLog{}
	if err := rec.AddProcessHook(hook); err != nil {
		t.Fatal(err)
	}
	if err := rec.Start(context.Background(), source.RunRef{ID: "r-exit", Agent: "a", CgroupID: cg}, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	marker := filepath.Join(t.TempDir(), "marker")
	if err := os.WriteFile(marker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "-test.run=^$")
	cmd.Env = append(os.Environ(), leaderExitsEnv+"="+marker, "GOGC=off", "GOMAXPROCS=4")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the helper: %v: %s", err, out)
	}
	pid := cmd.Process.Pid
	waitDrained(t, rec)
	if err := rec.Stop(); err != nil {
		t.Fatal(err)
	}
	calls := hook.all()
	open := slices.Index(calls, "open "+strconv.Itoa(pid)+" "+strconv.FormatUint(cg, 10)+" "+marker)
	exit := slices.Index(calls, "exit "+strconv.Itoa(pid))
	exits := 0
	for _, c := range calls {
		if c == "exit "+strconv.Itoa(pid) {
			exits++
		}
	}
	if open < 0 || exit < 0 || exit < open || exits != 1 {
		t.Errorf("hook calls for pid %d %q: want its open of the marker, then its one exit", pid, calls)
	}
}
