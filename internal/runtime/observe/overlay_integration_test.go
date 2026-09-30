// SPDX-License-Identifier: Apache-2.0

//go:build integration

package observe

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// overlayEnv makes the test binary overlayChild: the merged file it writes to.
const overlayEnv = "TEGO_OBSERVE_OVERLAY_CHILD"

func init() {
	if path := os.Getenv(overlayEnv); path != "" {
		if err := openClose(path, unix.O_WRONLY|unix.O_APPEND, 0); err != nil {
			os.Exit(4)
		}
		os.Exit(0)
	}
}

// TestIntegrationOverlayCopyUpIsOneLine is ADR 0016 (3)'s one action, one line on an overlayfs: the agent's first
// write to a lower file is its own open of the merged path and nothing else. The copy-up that write starts opens
// the lower file and the new upper one with a plain dentry_open, in the agent's task, on overlayfs' private clones
// of the layers' mounts (mnt_ns MNT_NS_INTERNAL); recorded, they were two more open lines, named relative to the
// clone's root (the lower file's "/lf", the work directory's temporary "#NN"). It runs under each build of
// trace_proc this kernel loads, and skips where overlayfs is not (root-suites loads it: VM_MODULES).
func TestIntegrationOverlayCopyUpIsOneLine(t *testing.T) {
	if !bpf.Available() {
		t.Skipf("needs the compiled objects: %v", bpf.ErrNotGenerated)
	}
	eachTraceReader(t, func(t *testing.T, r bpf.Reader) { overlayCopyUpIsOneLine(t, r) })
}

func overlayCopyUpIsOneLine(t *testing.T, r bpf.Reader) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lower, upper, work, merged := filepath.Join(base, "l"), filepath.Join(base, "u"), filepath.Join(base, "wk"),
		filepath.Join(base, "m")
	for _, d := range []string{lower, upper, work, merged} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(lower, "lf"), []byte("lower\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	opts := "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work
	if err := unix.Mount("overlay", merged, "overlay", 0, opts); err != nil {
		t.Skipf("no overlayfs here (%v): root-suites loads it with VM_MODULES=overlay", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(merged, unix.MNT_DETACH) })

	hash := "ovl-" + string(r)
	root, maps := pinRoot(t, hash)
	coll := loadTraceProcWhereItLoads(t, maps, r)
	_, fd, cg := childCgroup(t, "ovl")
	row := bpf.Run{RunIdx: 21, Descendants: 1, Tier: 2, Record: uint8(bpf.RecordFull)}
	placeRunRings(t, coll, row.RunIdx)
	if err := coll.Maps[bpf.MapRunSet].Update(&cg, &row, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = coll.Maps[bpf.MapRunSet].Delete(&cg) })
	rt := &agent.RuleTable{Record: agent.RecordFull, Tier: backend.TierCgroup, FS: []agent.FSRule{
		{Path: merged, Kind: agent.FSWrite, Raw: "./m"},
	}}
	rec, err := New(Options{Rules: rt, BPFHash: hash, PinRoot: root, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if err := rec.Start(context.Background(), source.RunRef{ID: "r-ovl", Agent: "a", CgroupID: cg}, sink); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(merged, "lf")
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), overlayEnv+"="+target)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("overlay child: %v: %s", err, b)
	}
	if _, err := os.Stat(filepath.Join(upper, "lf")); err != nil {
		t.Fatalf("the lower file was not copied up: %v: the cell is not what it says", err)
	}

	waitDrained(t, rec)
	if err := rec.Stop(); err != nil {
		t.Fatal(err)
	}
	var user int
	for _, ev := range sink.byKind(record.KindFS) {
		p := payload[record.FSPayload](t, ev)
		t.Logf("%s op=%s flags=%#x verdict=%s errno=%d", p.Path, p.Op, p.Flags, ev.Verdict, p.Errno)
		switch {
		case p.Path == target:
			if p.Op == record.FSOpen && p.Flags&unix.O_ACCMODE == unix.O_WRONLY {
				user++
			}
		case filepath.Base(p.Path) == "lf", strings.Contains(p.Path, "#"):
			t.Errorf("an open line for %q (op %s, flags %#x): the copy-up's own open on a layer's private clone",
				p.Path, p.Op, p.Flags)
		}
	}
	if user != 1 {
		t.Errorf("%d write-open lines for %s, want the agent's one", user, target)
	}
}
