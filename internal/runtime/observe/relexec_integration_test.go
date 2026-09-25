// SPDX-License-Identifier: Apache-2.0

//go:build integration

package observe

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationRelativeExecIsResolved is an execve of a relative name on the real objects, as root: a shell
// in the run's cgroup changes to a directory and runs ./prog there. bprm->filename is "./prog",
// and the record must name <dir>/prog and stamp the entry declared for it, from the working directory the exec
// record carries and /proc/<pid>/cwd agreeing, with nothing left unresolved.
func TestIntegrationRelativeExecIsResolved(t *testing.T) {
	if !bpf.Available() {
		t.Skipf("needs the compiled objects: %v", bpf.ErrNotGenerated)
	}
	const hash = "relexec"
	root, maps := pinRoot(t, hash)
	coll := loadTraceProc(t, maps)
	_, fd, cg := childCgroup(t, "relexec")
	row := bpf.Run{RunIdx: 1, Descendants: 1, Tier: 2, Record: uint8(bpf.RecordSummary)}
	placeRunRings(t, coll, row.RunIdx)
	if err := coll.Maps[bpf.MapRunSet].Update(&cg, &row, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	prog := filepath.Join(dir, "prog")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(self, prog); err != nil {
		t.Fatal(err)
	}
	rules := &agent.RuleTable{Record: agent.RecordSummary, Tier: backend.TierCgroup, Exec: []agent.ExecRule{
		{Raw: "./prog", Path: prog, Basename: "prog", Verdict: agent.VerdictAllow},
	}}
	rec, err := New(Options{Rules: rules, BPFHash: hash, PinRoot: root, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if err := rec.Start(context.Background(), source.RunRef{ID: "r-relexec", Agent: "a", CgroupID: cg}, sink); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()
	cmd := exec.Command("/bin/sh", "-c", "cd "+dir+" && ./prog -test.run=^$")
	cmd.Env = append(os.Environ(), sleepEnv+"=300ms")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sh in the run's cgroup: %v: %s", err, out)
	}
	waitDrained(t, rec)
	if err := rec.Stop(); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, ev := range sink.byKind(record.KindExec) {
		p := payload[record.ExecPayload](t, ev)
		t.Logf("exec path=%s rule=%s verdict=%s", p.Path, ev.Rule, ev.Verdict)
		if p.Path == prog {
			found = true
			if ev.Rule != "exec[./prog]" || ev.Verdict != record.VerdictAllow {
				t.Errorf("./prog was recorded %s %s, want the entry declared for %s and allow", ev.Rule, ev.Verdict, prog)
			}
		}
	}
	if !found {
		t.Errorf("no exec record named %s", prog)
	}
	if n := gapCount(rec.Gaps())[GapExecUnresolved]; n != 0 {
		t.Errorf("exec-unresolved %d for a process alive in its directory: %+v", n, rec.Gaps())
	}
}
