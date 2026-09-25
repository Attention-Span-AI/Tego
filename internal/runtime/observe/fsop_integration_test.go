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

// TestIntegrationFSOpsResolveThroughTheDirectoryIndex is R9 on the real objects, as root, on the filesystem the
// test's temporary directory is on: a child in the run's cgroup removes a file in a declared
// write directory and makes a directory there. Both parents are the entry itself, so both resolve through the
// directory index, where stat names the entry by its super block's device. Where it does not (btrfs, an overlayfs
// of one filesystem) the run says so with dir-unindexed, and both stay unresolved rather than guessed.
func TestIntegrationFSOpsResolveThroughTheDirectoryIndex(t *testing.T) {
	if !bpf.Available() {
		t.Skipf("needs the compiled objects: %v", bpf.ErrNotGenerated)
	}
	out := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(out, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "x"), []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	const hash = "fsops"
	root, maps := pinRoot(t, hash)
	coll := loadTraceProc(t, maps)
	_, fd, cg := childCgroup(t, "fsops")
	row := bpf.Run{RunIdx: 1, Descendants: 1, Tier: 2, Record: uint8(bpf.RecordFull)}
	placeRunRings(t, coll, row.RunIdx)
	if err := coll.Maps[bpf.MapRunSet].Update(&cg, &row, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	rt := &agent.RuleTable{Record: agent.RecordFull, Tier: backend.TierCgroup,
		FS: []agent.FSRule{{Path: out, Kind: agent.FSWrite, Raw: "./out"}}}
	rec, err := New(Options{Rules: rt, BPFHash: hash, PinRoot: root, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if err := rec.Start(context.Background(), source.RunRef{ID: "r-fs", Agent: "a", CgroupID: cg}, sink); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()
	cmd := exec.Command("/bin/sh", "-c", "rm "+filepath.Join(out, "x")+" && mkdir "+filepath.Join(out, "d"))
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	waitDrained(t, rec)
	if err := rec.Stop(); err != nil {
		t.Fatal(err)
	}
	unindexed := gapCount(rec.Gaps())[GapDirUnindexed] != 0
	ops := map[string]string{}
	for _, ev := range sink.byKind(record.KindFS) {
		p := payload[record.FSPayload](t, ev)
		if p.Op == record.FSOpen {
			continue
		}
		t.Logf("%s path=%s rule=%s verdict=%s", p.Op, p.Path, ev.Rule, ev.Verdict)
		ops[p.Op] = ev.Rule
		want, wantPath := "fs.write[./out]", ""
		switch p.Op {
		case record.FSUnlink:
			wantPath = filepath.Join(out, "x")
		case record.FSMkdir:
			wantPath = filepath.Join(out, "d")
		}
		if unindexed {
			want, wantPath = RuleUnmatched, p.Path
		}
		if ev.Rule != want || p.Path != wantPath {
			t.Errorf("%s recorded %s path=%s, want %s path=%s (dir-unindexed: %v)", p.Op, ev.Rule, p.Path, want,
				wantPath, unindexed)
		}
	}
	if len(ops) != 2 {
		t.Errorf("fs operations recorded %v, want the unlink and the mkdir", ops)
	}
	t.Logf("gaps %+v", rec.Gaps())
}

// TestIntegrationSymlinkTargetOf255BytesIsWhole is the symlink target's cut mark at its boundary, on the real
// objects: a 255-byte target and its NUL fill the program's 256-byte buffer exactly as a longer target's cut read
// does, so only the 256th source byte tells them apart. The 255-byte target is recorded whole; the 256-byte one is
// recorded as TruncatedPath. Before, both were marked cut.
func TestIntegrationSymlinkTargetOf255BytesIsWhole(t *testing.T) {
	if !bpf.Available() {
		t.Skipf("needs the compiled objects: %v", bpf.ErrNotGenerated)
	}
	out := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(out, 0o777); err != nil {
		t.Fatal(err)
	}
	// Each target is one component per 51 bytes ("/" and 50 letters), so no name in it passes NAME_MAX; the link
	// need not resolve.
	target := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = 'a' + byte(i%26)
			if i%51 == 0 {
				b[i] = '/'
			}
		}
		return string(b)
	}
	whole, cut := target(255), target(256)
	const hash = "symlnk"
	root, maps := pinRoot(t, hash)
	coll := loadTraceProc(t, maps)
	_, fd, cg := childCgroup(t, "symlnk")
	row := bpf.Run{RunIdx: 1, Descendants: 1, Tier: 2, Record: uint8(bpf.RecordFull)}
	placeRunRings(t, coll, row.RunIdx)
	if err := coll.Maps[bpf.MapRunSet].Update(&cg, &row, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	rt := &agent.RuleTable{Record: agent.RecordFull, Tier: backend.TierCgroup,
		FS: []agent.FSRule{{Path: out, Kind: agent.FSWrite, Raw: "./out"}}}
	rec, err := New(Options{Rules: rt, BPFHash: hash, PinRoot: root, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if err := rec.Start(context.Background(), source.RunRef{ID: "r-sl", Agent: "a", CgroupID: cg}, sink); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()
	cmd := exec.Command("/bin/ln", "-s", whole, filepath.Join(out, "w"))
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	cmd = exec.Command("/bin/ln", "-s", cut, filepath.Join(out, "c"))
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	waitDrained(t, rec)
	if err := rec.Stop(); err != nil {
		t.Fatal(err)
	}
	got := map[int]string{}
	for _, ev := range sink.byKind(record.KindFS) {
		p := payload[record.FSPayload](t, ev)
		if p.Op != record.FSSymlink {
			continue
		}
		t.Logf("symlink path=%s path2 len %d", p.Path, len(p.Path2))
		switch p.Path2 {
		case whole:
			got[255] = p.Path2
		case TruncatedPath:
			got[256] = p.Path2
		default:
			t.Errorf("symlink recorded target %q, want the 255-byte target whole or %s", p.Path2, TruncatedPath)
		}
	}
	if got[255] == "" {
		t.Errorf("the 255-byte symlink target was not recorded whole")
	}
	if got[256] == "" {
		t.Errorf("the 256-byte symlink target was not recorded as %s", TruncatedPath)
	}
}
