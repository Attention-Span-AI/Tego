// SPDX-License-Identifier: Apache-2.0

//go:build integration

package observe

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/attention-span-ai/tego/internal/bpf"
)

// TestIntegrationEveryRecordNamesItsProcessStart is the start time every record carries, read off the real ring
// as root: an open, an unlink and a mkdir of a process carry the start time its exec record carries, which is
// its thread group leader's start_boottime, and a child's exec carries its parent's. It is what lets the
// recorder tell a process from an earlier one of its pid when an exit record was lost.
func TestIntegrationEveryRecordNamesItsProcessStart(t *testing.T) {
	if !bpf.Available() {
		t.Skipf("needs the compiled objects: %v", bpf.ErrNotGenerated)
	}
	_, maps := pinRoot(t, "starttime")
	coll := loadTraceProc(t, maps)
	_, fd, cg := childCgroup(t, "starttime")
	row := bpf.Run{RunIdx: 1, Descendants: 1, Tier: 2, Record: uint8(bpf.RecordFull)}
	ring := placeRunRings(t, coll, row.RunIdx)
	if err := coll.Maps[bpf.MapRunSet].Update(&cg, &row, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	rd, err := ringbuf.NewReader(ring)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", "cat /etc/hostname >/dev/null; rm "+filepath.Join(dir, "x")+"; mkdir "+
		filepath.Join(dir, "d"))
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sh in the run's cgroup: %v: %s", err, out)
	}

	execStart := map[uint32]uint64{} // pid -> the start time its exec record carries
	var recs []Record
	rd.SetDeadline(time.Now().Add(2 * time.Second))
	for {
		s, err := rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		r, err := Decode(s.RawSample)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if r.Kind == KindExec {
			execStart[r.PID] = r.Exec.StartBootNS
		}
		recs = append(recs, r)
		if s.Remaining == 0 {
			rd.SetDeadline(time.Now().Add(200 * time.Millisecond))
		}
	}
	checked := map[Kind]int{}
	for _, r := range recs {
		if r.StartNS == 0 && r.Kind != KindCgroupMkdir && r.Kind != KindCgroupRmdir {
			t.Errorf("%s of pid %d carries no start time", r.Kind, r.PID)
		}
		start, ok := execStart[r.PID]
		if !ok {
			continue // a record the process made before its exec in the run's cgroup
		}
		if r.StartNS != start {
			t.Errorf("%s of pid %d carries start %d, its exec %d", r.Kind, r.PID, r.StartNS, start)
		}
		if r.Kind == KindExec {
			if parent, ok := execStart[r.PPID]; ok && r.Exec.ParentStartNS != parent {
				t.Errorf("exec of pid %d names its parent %d's start %d, the parent's exec %d", r.PID, r.PPID,
					r.Exec.ParentStartNS, parent)
			}
		}
		checked[r.Kind]++
	}
	for _, k := range []Kind{KindExec, KindExit, KindOpen, KindUnlink, KindMkdir} {
		if checked[k] == 0 {
			t.Errorf("no %s record to check among %d: %v", k, len(recs), checked)
		}
	}
	t.Logf("records checked by kind: %v", checked)
}
