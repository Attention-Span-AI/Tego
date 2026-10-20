// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestExecImageAutomountPointFailureIsNoMiss on the real kernel: the walk took only an
// autofs directory for an automount point, and under any other one it missed a file that exists. A fresh debugfs
// mount's tracing directory is an S_AUTOMOUNT stub, the class NFS crossmnt and referral submounts, CIFS DFS links and
// FUSE submounts belong to: tracefs is mounted there by the first lookup that crosses it as an intermediate component.
// The supervisor's walk opens each component O_PATH as a final lookup, so it lands on the empty stub without mounting
// anything, and tracing/README, a file the kernel's own walk finds, failed ENOENT and was answered as a miss with no
// line, where the kernel answers the task EACCES (the file has no execute bit). Such a failure is now no miss
// (automountLookup): it keeps its errno and is decided and recorded as before R16b (0). The walk still mounts nothing,
// and once a lookup of the kernel's own has mounted tracefs there, the same path reaches the file.
func TestExecImageAutomountPointFailureIsNoMiss(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: mounts a debugfs (root-suites.sh)")
	}
	tid := selfTask(t)
	mnt := filepath.Join(t.TempDir(), "debug")
	if err := os.Mkdir(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("none", mnt, "debugfs", 0, "mode=0755"); err != nil {
		t.Fatalf("mount a debugfs at %s: %v", mnt, err)
	}
	t.Cleanup(func() { _ = unix.Unmount(mnt, unix.MNT_DETACH) })
	tracing := filepath.Join(mnt, "tracing")
	mntID := func(p string) uint64 {
		t.Helper()
		var stx unix.Statx_t
		if err := unix.Statx(unix.AT_FDCWD, p, unix.AT_NO_AUTOMOUNT|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &stx); err != nil {
			t.Fatalf("statx %s: %v", p, err)
		}
		return stx.Mnt_id
	}
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, tracing, unix.AT_NO_AUTOMOUNT|unix.AT_SYMLINK_NOFOLLOW, 0, &stx); err != nil {
		t.Fatalf("statx %s: %v (a kernel built without tracing has no such stub)", tracing, err)
	}
	if stx.Attributes&unix.STATX_ATTR_AUTOMOUNT == 0 {
		t.Fatalf("%s: attributes %#x carry no STATX_ATTR_AUTOMOUNT: the case proves nothing", tracing, stx.Attributes)
	}
	debugID := mntID(mnt)
	readme := filepath.Join(tracing, "README")
	// The control: the detection before this fix, autofs alone, calls the failure under this stub a miss.
	prev := atAutomount
	atAutomount = func(fd int) bool {
		var sfs unix.Statfs_t
		return unix.Fstatfs(fd, &sfs) == nil && uint32(sfs.Type) == unix.AUTOFS_SUPER_MAGIC
	}
	_, err := sysKernel{}.ExecImage(pathQuery{tid: tid, dirfd: atFDCWD, path: readme, joined: readme})
	atAutomount = prev
	if !execMissing(err) {
		t.Fatalf("%s with autofs alone taken for an automount point: %v, not a miss: the case proves nothing", readme, err)
	}
	for _, name := range []string{"README", "trace", "tego-no-such-name", "README/x"} {
		p := filepath.Join(tracing, name)
		_, err := sysKernel{}.ExecImage(pathQuery{tid: tid, dirfd: atFDCWD, path: p, joined: p})
		var a automountLookup
		if !errors.As(err, &a) || execMissing(err) {
			t.Errorf("%s: %v (at an automount point %v, a miss %v): want a failure at an automount point, no miss",
				p, err, errors.As(err, &a), execMissing(err))
		}
		if lookupErrno(err) != unix.ENOENT || !execLookupFailure(err) {
			t.Errorf("%s: answered %v, a lookup failure %v; want ENOENT, true", p, lookupErrno(err), execLookupFailure(err))
		}
	}
	if id := mntID(tracing); id != debugID {
		t.Fatalf("%s is another mount (%d, the debugfs is %d) after the walk: the walk mounted it", tracing, id, debugID)
	}
	// The kernel's own walk crosses the stub as an intermediate component and mounts tracefs there.
	if _, err := os.Stat(readme); err != nil {
		t.Fatalf("the kernel's own lookup of %s: %v", readme, err)
	}
	if id := mntID(tracing); id == debugID {
		t.Fatalf("%s is still the debugfs stub after the kernel's lookup: the case proves nothing", tracing)
	}
	img, err := sysKernel{}.ExecImage(pathQuery{tid: tid, dirfd: atFDCWD, path: readme, joined: readme})
	if err != nil || !img.regular {
		t.Errorf("%s once mounted: %v (regular %v), want the walk to reach the file", readme, err, img.regular)
	}
}
