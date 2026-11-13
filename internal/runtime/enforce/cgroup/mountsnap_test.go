// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
)

func TestPrepareSharesOneMountSnapshot(t *testing.T) {
	saved := acquireMountSnapshot
	t.Cleanup(func() { acquireMountSnapshot = saved })
	for _, mode := range []ebpfbindings.PlaneMode{"", ebpfbindings.PlaneFmodRet, ebpfbindings.PlaneLSM} {
		t.Run(string(mode), func(t *testing.T) {
			count := 0
			var prepared *MountSnapshot
			acquireMountSnapshot = func(path string) *mountSnapshot {
				count++
				if count > 1 {
					return newMountSnapshot(nil, nil, errors.New("second acquisition"), nil)
				}
				prepared = readMountSnapshot(path)
				return prepared
			}
			var f *fixture
			if mode == "" {
				f = newFixture(t)
			} else {
				f, _ = planeFixture(t, mode)
			}
			h, err := f.backend.Prepare(context.Background(), f.table, f.run)
			if err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			defer h.Close()
			if h.planeRows != nil {
				if err := PlaneHoldableAt(h.planeRows, prepared); err != nil {
					t.Fatalf("holdability: %v", err)
				}
			}
			mt, err := h.MountTable()
			if err != nil || mt != prepared.mt || h.run.Mounts != prepared {
				t.Fatalf("recorder facts differ: %p, %v", mt, err)
			}
			if count != 1 {
				t.Fatalf("snapshot acquisitions = %d, want exactly one", count)
			}
		})
	}
}

func TestMountSnapshotFollowsSymlinkSpelling(t *testing.T) {
	dir := t.TempDir()
	actual := filepath.Join(dir, "var", "home")
	if err := os.MkdirAll(actual, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "home")
	if err := os.Symlink(actual, link); err != nil {
		t.Fatal(err)
	}
	table := "22 1 8:1 / / rw - ext4 /dev/root rw\n30 22 8:2 / " + filepath.Join(dir, "var") + " rw - ext4 /dev/var rw\n"
	snap := mountSnapshotOf(table)
	snap.live = func(path string) (int, error) {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return 0, err
		}
		if resolved == actual {
			return 30, nil
		}
		return 22, nil
	}
	aliases, err := snap.aliases(filepath.Join(link, "alice", ".ssh"))
	if err != nil || len(aliases) != 0 {
		t.Fatalf("symlink spelling: %v, %v", aliases, err)
	}
	if dev, ok := snap.device(filepath.Join(link, "alice", ".ssh")); !ok || dev != unix.Mkdev(8, 2) {
		t.Fatalf("marked symlink device = %d, %v; want var device %d", dev, ok, unix.Mkdev(8, 2))
	}
}
