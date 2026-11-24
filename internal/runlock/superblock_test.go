// SPDX-License-Identifier: Apache-2.0

package runlock

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSignalsOnlyItself: the gate of the superblock proof. A caller that is not root, holds neither CAP_KILL nor
// CAP_SYS_PTRACE (effective or permitted) and whose target's four uids are all its own may use it; any other caller
// keeps the exact device and the descriptors.
func TestSignalsOnlyItself(t *testing.T) {
	const kill, ptrace = 1 << unix.CAP_KILL, 1 << unix.CAP_SYS_PTRACE
	own := []byte("Name:\tx\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n")
	for _, tc := range []struct {
		name       string
		ruid, euid int
		eff, perm  uint64
		status     string
		want       bool
	}{
		{"an ordinary user and its own process", 1000, 1000, 0, 0, string(own), true},
		{"other capabilities", 1000, 1000, 1 << unix.CAP_NET_BIND_SERVICE, 1 << unix.CAP_NET_BIND_SERVICE, string(own), true},
		{"root", 0, 0, 0, 0, "Uid:\t0\t0\t0\t0\n", false},
		{"effective root", 1000, 0, 0, 0, "Uid:\t0\t0\t0\t0\n", false},
		{"real root", 0, 1000, 0, 0, string(own), false},
		{"CAP_KILL effective", 1000, 1000, kill, 0, string(own), false},
		{"CAP_KILL permitted", 1000, 1000, 0, kill, string(own), false},
		{"CAP_SYS_PTRACE effective", 1000, 1000, ptrace, 0, string(own), false},
		{"CAP_SYS_PTRACE permitted", 1000, 1000, 0, ptrace, string(own), false},
		{"another user's launcher", 1000, 1000, 0, 0, "Uid:\t1001\t1001\t1001\t1001\n", false},
		{"a real uid that is another's", 1000, 1000, 0, 0, "Uid:\t1001\t1000\t1000\t1000\n", false},
		{"a saved uid that is another's", 1000, 1000, 0, 0, "Uid:\t1000\t1000\t0\t1000\n", false},
		{"a filesystem uid that is another's", 1000, 1000, 0, 0, "Uid:\t1000\t1000\t1000\t0\n", false},
		{"no Uid line", 1000, 1000, 0, 0, "Name:\tx\n", false},
		{"a short Uid line", 1000, 1000, 0, 0, "Uid:\t1000\t1000\n", false},
		{"a Uid line that is not numbers", 1000, 1000, 0, 0, "Uid:\ta\tb\tc\td\n", false},
	} {
		if got := signalsOnlyItself(tc.ruid, tc.euid, tc.eff, tc.perm, []byte(tc.status)); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// onAnotherDevice is a table in which the stand-in launcher's flock row prints a device other than stat's, as a btrfs
// subvolume does: the real row with its major:minor replaced by sbMajor:sbMinor.
func onAnotherDevice(t *testing.T, table []byte, pid int, ino uint64, sbMajor, sbMinor uint32) []byte {
	t.Helper()
	var out []string
	changed := false
	for _, line := range strings.Split(string(table), "\n") {
		f := strings.Fields(line)
		if len(f) >= 6 && f[1] == "FLOCK" && f[4] == fmt.Sprint(pid) && strings.HasSuffix(f[5], fmt.Sprintf(":%d", ino)) {
			f[5] = fmt.Sprintf("%02x:%02x:%d", sbMajor, sbMinor, ino)
			line = strings.Join(f, " ")
			changed = true
		}
		out = append(out, line)
	}
	if !changed {
		t.Fatal("no row of the stand-in's flock in the table")
	}
	return []byte(strings.Join(out, "\n"))
}

// TestSuperblockProof: a launcher that is undumpable (descriptors hidden) on a filesystem whose /proc/locks prints the
// superblock's device, not stat's (a btrfs subvolume, described here by fakes over the real stand-in), is proved to a
// caller that cannot signal beyond itself, by the row on the device of the mount that holds the lock file; and to no
// other caller, on no other device, for no other pid, and when the mount moved.
func TestSuperblockProof(t *testing.T) {
	dir := t.TempDir()
	_, st, pid, _ := undumpableHolder(t, dir)
	real := listedTable(t, pid, uint64(st.Ino))
	const sbMajor, sbMinor = 0, 43
	table := onAnotherDevice(t, real, pid, st.Ino, sbMajor, sbMinor)
	oldTable, oldSelf, oldGate, oldBackoff, oldMount := readLocksTable, readSelfProc, callerSignalsOnlyItself, lockProofBackoff, mountIDOf
	t.Cleanup(func() {
		readLocksTable, readSelfProc, callerSignalsOnlyItself, lockProofBackoff, mountIDOf = oldTable, oldSelf, oldGate, oldBackoff, oldMount
	})
	lockProofBackoff = 0

	// mountIDs is what statx says of the file's mount, one value per read; the last repeats.
	prove := func(t *testing.T, tbl []byte, gate bool, mountinfo string, mountIDs ...int) error {
		t.Helper()
		reads := 0
		readLocksTable = func() []byte { return tbl }
		callerSignalsOnlyItself = func(int) bool { return gate }
		mountIDOf = func(*os.File) int {
			id := mountIDs[min(reads, len(mountIDs)-1)]
			reads++
			return id
		}
		readSelfProc = func(name string) ([]byte, error) {
			if name == "mountinfo" {
				return []byte(mountinfo), nil
			}
			return nil, syscall.ENOENT
		}
		return requireLockHolder(Dir{Path: dir}, pid)
	}
	btrfs := "26 1 0:25 / / rw,relatime - btrfs /dev/vda5 rw\n77 26 0:43 /home /home rw,relatime shared:3 - btrfs /dev/vda5 rw,subvol=/home\n"

	t.Run("the superblock's device on the mount of the file", func(t *testing.T) {
		if err := prove(t, table, true, btrfs, 77); err != nil {
			t.Fatalf("a caller that signals only itself: %v", err)
		}
	})
	t.Run("a caller that may signal others keeps the exact proof", func(t *testing.T) {
		err := prove(t, table, false, btrfs, 77)
		if !errors.Is(err, ErrNotLockHolder) || errors.Is(err, ErrStale) || !strings.Contains(err.Error(), "CAP_SYS_PTRACE") {
			t.Fatalf("root, CAP_KILL, CAP_SYS_PTRACE or another user's launcher: %v, want ErrNotLockHolder naming CAP_SYS_PTRACE", err)
		}
	})
	t.Run("another device", func(t *testing.T) {
		other := onAnotherDevice(t, real, pid, st.Ino, 0, 44)
		if err := prove(t, other, true, btrfs, 77); !errors.Is(err, ErrNotLockHolder) {
			t.Fatalf("a row on 0:44 while the mount is 0:43: %v", err)
		}
	})
	t.Run("another pid", func(t *testing.T) {
		if err := prove(t, table, true, btrfs, 77); err != nil {
			t.Fatal(err)
		}
		other := strings.ReplaceAll(string(table), fmt.Sprintf(" %d ", pid), fmt.Sprintf(" %d ", pid+1))
		if err := prove(t, []byte(other), true, btrfs, 77); !errors.Is(err, ErrNotLockHolder) {
			t.Fatalf("a row of another pid: %v", err)
		}
	})
	t.Run("another inode", func(t *testing.T) {
		other := strings.ReplaceAll(string(table), fmt.Sprintf(":%d ", st.Ino), fmt.Sprintf(":%d ", st.Ino+1))
		if err := prove(t, []byte(other), true, btrfs, 77); !errors.Is(err, ErrNotLockHolder) {
			t.Fatalf("a row of another inode: %v", err)
		}
	})
	t.Run("no table", func(t *testing.T) {
		if err := prove(t, nil, true, btrfs, 77); !errors.Is(err, ErrNotLockHolder) {
			t.Fatalf("no row: %v", err)
		}
	})
	t.Run("the mount is not in mountinfo", func(t *testing.T) {
		if err := prove(t, table, true, "26 1 0:25 / / rw - btrfs /dev/vda5 rw\n", 77); !errors.Is(err, ErrNotLockHolder) {
			t.Fatalf("no mountinfo row for mount 77: %v", err)
		}
	})
	t.Run("a mountinfo row that is not a device", func(t *testing.T) {
		if err := prove(t, table, true, "77 26 x:y /home /home rw - btrfs /dev/vda5 rw\n", 77); !errors.Is(err, ErrNotLockHolder) {
			t.Fatalf("a bad device: %v", err)
		}
	})
	t.Run("the file's mount cannot be read", func(t *testing.T) {
		if err := prove(t, table, true, btrfs, -1); !errors.Is(err, ErrNotLockHolder) {
			t.Fatalf("mnt_id -1: %v", err)
		}
	})
	t.Run("the mount moved while the table was read", func(t *testing.T) {
		if err := prove(t, table, true, btrfs, 77, 78); !errors.Is(err, ErrNotLockHolder) {
			t.Fatalf("mount 77 then 78: %v", err)
		}
	})
}

// superblockDiagnostics describes what the superblock proof saw of the lock file in dir for pid: for a failing test to log.
func superblockDiagnostics(t *testing.T, dir string, pid int, table []byte) {
	t.Helper()
	f, err := os.Open(lockPath(dir))
	if err != nil {
		t.Logf("diagnostics: open: %v", err)
		return
	}
	defer func() { _ = f.Close() }()
	var st syscall.Stat_t
	_ = syscall.Fstat(int(f.Fd()), &st)
	dev, mnt, ok := superblockProof(f, pid)
	var rows []string
	for _, line := range strings.Split(string(table), "\n") {
		if row := fdInfoFlockRow([]byte("lock: "+line), pid, st.Ino); row != "" {
			rows = append(rows, row)
		}
	}
	mi, _ := readSelfProc("mountinfo")
	var mrow string
	for _, l := range strings.Split(string(mi), "\n") {
		if strings.HasPrefix(l, fmt.Sprint(mnt)+" ") {
			mrow = l
		}
	}
	t.Logf("diagnostics: gate=%v mountIDOf=%d superblockProof dev=%d:%d mnt=%d ok=%v; stat dev=%d:%d ino=%d; table rows of pid %d: %q; mountinfo row %q",
		callerSignalsOnlyItself(pid), mountIDOf(f), unix.Major(dev), unix.Minor(dev), mnt, ok, unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)), st.Ino, pid, rows, mrow)
}

// TestSuperblockDeviceIsWhatProcLocksPrints: on the real filesystem under the test (btrfs in a guest, where stat's device
// is not the superblock's), a flock this process holds is printed by /proc/locks with the device mountinfo gives for the
// mount that holds the file, which is the claim the superblock proof stands on. On ext4 the two devices and stat's agree.
func TestSuperblockDeviceIsWhatProcLocksPrints(t *testing.T) {
	f, st := heldProofFile(t, lockPath(t.TempDir()))
	dev, mnt, ok := superblockProof(f, os.Getpid())
	if !callerSignalsOnlyItself(os.Getpid()) {
		// rootskips:ignore skips when the caller CAN signal other processes (root or CAP_KILL): the root run's skip
		t.Skip("run as a user without CAP_KILL or CAP_SYS_PTRACE")
	}
	if !ok {
		t.Fatalf("no superblock proof for a file of this filesystem (mount %d, device %d:%d)", mnt, unix.Major(dev), unix.Minor(dev))
	}
	table := listedTable(t, os.Getpid(), st.Ino)
	if !rowOnDevice(table, os.Getpid(), st, dev) {
		t.Fatalf("/proc/locks does not print this file's lock on mountinfo's device %d:%d (stat's is %d:%d)",
			unix.Major(dev), unix.Minor(dev), unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)))
	}
	t.Logf("fs: stat device %d:%d, mountinfo device %d:%d, mount %d, and /proc/locks prints the mountinfo one",
		unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)), unix.Major(dev), unix.Minor(dev), mnt)
}
