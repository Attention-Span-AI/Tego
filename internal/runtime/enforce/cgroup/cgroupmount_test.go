// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// The package's unit tests list cgroups under plain directories standing in for the cgroup2 mount, which the real
// check refuses; they keep its other half, that the mount must be there.
func init() {
	cgroupMountCheck = func(mount string) error {
		st, err := os.Stat(mount)
		if err != nil {
			return err
		}
		if !st.IsDir() {
			return errors.New("not a directory")
		}
		return nil
	}
}

// TestCgroupIDsFailsClosedOnAMissingMount: a missing mount listed as an empty tree made two listings 50 ms apart
// agree that every run-set row's cgroup was gone, so a sweep (tego doctor or gc as root where /sys/fs/cgroup is
// not the host's tree) deleted every live run's row and removed its build, fail-open. A mount that cannot be
// listed is an error, and nothing is deleted.
func TestCgroupIDsFailsClosedOnAMissingMount(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "no-cgroup2")
	if ids, err := cgroupIDs(missing); err == nil {
		t.Fatalf("cgroupIDs of a missing mount = %v, nil; want an error", ids)
	}
	m := &walkingRunSet{keys: []uint64{101, 102}}
	if _, err := runSetLiveIn(m, missing); err == nil {
		t.Error("runSetLiveIn under a missing mount returned no error")
	}
	if len(m.deleted) != 0 {
		t.Errorf("deleted %v under a missing mount: live runs' rows dropped", m.deleted)
	}
	bpffs, state := t.TempDir(), t.TempDir()
	links := reapBuild(t, bpffs, state, "h1", "r1")
	res, err := PurgeRun(PurgeOptions{BPFFS: bpffs, StateDir: state, CgroupMount: missing, Hash: "h1", RunID: "r1",
		CgroupID: 1})
	if err == nil {
		t.Errorf("PurgeRun under a missing mount: %+v, nil; want an error", res)
	}
	if _, err := os.Stat(links); err != nil {
		t.Errorf("PurgeRun under a missing mount removed the run's links: %v", err)
	}
}

// TestCheckCgroup2MountRefusesAnotherFilesystem is the real check: a plain directory is not the cgroup tree.
func TestCheckCgroup2MountRefusesAnotherFilesystem(t *testing.T) {
	t.Parallel()
	if err := checkCgroup2Mount(t.TempDir()); err == nil {
		t.Error("checkCgroup2Mount accepted a directory that is not cgroup2")
	}
	if err := checkCgroup2Mount(filepath.Join(t.TempDir(), "gone")); err == nil {
		t.Error("checkCgroup2Mount accepted a missing mount")
	}
	if err := checkCgroup2Mount(identity.SystemCgroupRoot); err != nil {
		t.Skipf("this host's %s is not cgroup2: %v", identity.SystemCgroupRoot, err)
	}
}

// TestCgroupIDsFailsClosedOnAStatError: a directory whose stat failed with anything but ENOENT was left out of the
// listing, so a live run's cgroup looked gone and its run-set row and build could be removed under it, fail-open.
// Only a directory removed mid-walk is skipped; any other stat error fails the listing.
func TestCgroupIDsFailsClosedOnAStatError(t *testing.T) {
	t.Parallel()
	mount := t.TempDir()
	live := filepath.Join(mount, "tego", "run-1")
	gone := filepath.Join(mount, "tego", "run-2")
	for _, d := range []string{live, gone} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	failing := func(fail string, errno error) func(string, *unix.Stat_t) error {
		return func(path string, st *unix.Stat_t) error {
			if path == fail {
				return errno
			}
			return unix.Lstat(path, st)
		}
	}
	if ids, err := cgroupIDsWith(mount, failing(live, unix.ENOMEM)); err == nil {
		t.Fatalf("cgroupIDs with ENOMEM on a live cgroup = %v, nil; want an error", ids)
	}
	ids, err := cgroupIDsWith(mount, failing(gone, unix.ENOENT))
	if err != nil {
		t.Fatalf("cgroupIDs with a cgroup removed mid-walk: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(live, &st); err != nil {
		t.Fatal(err)
	}
	if !ids[st.Ino] {
		t.Errorf("cgroupIDs with a cgroup removed mid-walk left out the live one: %v", ids)
	}
	if _, err := cgroupIDsWith(mount, failing(mount, unix.ENOENT)); err == nil {
		t.Error("cgroupIDs whose root stat fails ENOENT returned no error")
	}
}
