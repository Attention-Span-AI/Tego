// SPDX-License-Identifier: Apache-2.0

package runlock

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func heldProofFile(t *testing.T, path string) (*os.File, syscall.Stat_t) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	return f, st
}

// listedTable reads /proc/locks until a read lists pid's flock on inode ino, at most 100 reads, and returns that read;
// it fails t when none does, since then the kernel does not list the lock. One read can leave out a flock held all
// along: /proc/locks is a seq_file read a page of lines a pass, and a lock another process takes or lets go between
// two passes moves the lines after it, so the next pass starts past one of them (the omission
// TestLockHolderProofAfterRealProcPaginationOmission stages). A table longer than a page, which that test builds on
// purpose, is read in several passes whatever the buffer, and a host's other processes (a CI runner's other test
// binaries) take and let go flocks all the time. Each read asks for 256 KiB at a time, more than any page, so a table
// that fits a page is read in one pass.
func listedTable(t *testing.T, pid int, ino uint64) []byte {
	t.Helper()
	var last []byte
	for range 100 {
		b, err := readProcLocks()
		if err != nil {
			t.Fatalf("read /proc/locks: %v", err)
		}
		if flockHeldBy(b, pid, ino) {
			return b
		}
		last = b
	}
	t.Fatalf("no read of /proc/locks in 100 lists pid %d's flock on inode %d; the last read:\n%s", pid, ino, last)
	return nil
}

// readProcLocks reads /proc/locks whole, 256 KiB a read(2).
func readProcLocks() ([]byte, error) {
	f, err := os.Open("/proc/locks")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []byte
	buf := make([]byte, 256<<10)
	for {
		n, err := f.Read(buf)
		out = append(out, buf[:n]...)
		if errors.Is(err, io.EOF) || (n == 0 && err == nil) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func TestLockHolderProofWithMissingGlobalRow(t *testing.T) {
	dir := t.TempDir()
	f, st := heldProofFile(t, lockPath(dir))
	pid := os.Getpid()
	info, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%d", pid, f.Fd()))
	if err != nil || fdInfoFlockRow(info, pid, uint64(st.Ino)) == "" {
		t.Fatalf("real granted descriptor proof: %q, %v", info, err)
	}
	for _, table := range [][]byte{nil, []byte("1: FLOCK ADVISORY WRITE 1 00:01:1 0 EOF\n")} {
		if flockHeldBy(table, pid, uint64(st.Ino)) {
			t.Fatal("fixture unexpectedly supplies the former global proof")
		}
		if err := requireLockHolderFromSnapshot(table, pid, st); err != nil {
			t.Fatalf("still-held lock omitted from global table: %v", err)
		}
	}
	if err := requireLockHolder(pathDir(dir), pid); err != nil {
		t.Fatalf("production proof: %v", err)
	}
}

// /proc/locks resumes its seq iterator by ordinal position. Removing unrelated earlier rows after
// the first buffer fill can hide our still-held row; the descriptor proof must recover that case.
func TestLockHolderProofAfterRealProcPaginationOmission(t *testing.T) {
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()
	var prior unix.CPUSet
	if err := unix.SchedGetaffinity(0, &prior); err != nil {
		t.Fatal(err)
	}
	var one unix.CPUSet
	cpu := -1
	for i := 0; i < 1024; i++ {
		if prior.IsSet(i) {
			one.Set(i)
			cpu = i
			break
		}
	}
	if cpu < 0 {
		t.Fatal("no allowed fixture CPU")
	}
	if err := unix.SchedSetaffinity(0, &one); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.SchedSetaffinity(0, &prior); err != nil {
			t.Errorf("restore fixture thread affinity: %v", err)
		}
	}()

	dir := t.TempDir()
	f, st := heldProofFile(t, lockPath(dir))
	noise, err := os.OpenFile(filepath.Join(dir, "noise"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = noise.Close() }()
	// Sparse POSIX ranges generate independent unrelated table rows on one descriptor. Scale past
	// the kernel's page-size buffer (including 64KiB ARM64 pages) without requiring thousands of FDs.
	noiseCount := max(400, os.Getpagesize()/32+200)
	for i := 0; i < noiseCount; i++ {
		region := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: io.SeekStart, Start: int64(i) * 2, Len: 1}
		if err := syscall.FcntlFlock(noise.Fd(), syscall.F_SETLK, &region); err != nil {
			t.Fatal(err)
		}
	}
	pid := os.Getpid()
	// The real table lists the held target (listedTable: a read another process's lock splits may not).
	listedTable(t, pid, uint64(st.Ino))
	stream, err := os.Open("/proc/locks")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	first := make([]byte, 512)
	n, err := stream.Read(first)
	if err != nil {
		t.Fatal(err)
	}
	first = first[:n]
	firstContainsTarget := flockHeldBy(first, pid, uint64(st.Ino))
	if err := noise.Close(); err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	omitted := append(first, rest...)
	observedOmission := !flockHeldBy(omitted, pid, uint64(st.Ino))
	// A fresh table still lists the target: the omission was the read's, not the kernel's.
	listedTable(t, pid, uint64(st.Ino))
	probe, err := os.OpenFile(lockPath(dir), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = probe.Close() }()
	probeErr := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if !errors.Is(probeErr, syscall.EWOULDBLOCK) {
		t.Fatalf("independent LOCK_EX|LOCK_NB must prove lock remains held: %v", probeErr)
	}
	info, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%d", pid, f.Fd()))
	if err != nil || fdInfoFlockRow(info, pid, uint64(st.Ino)) == "" {
		t.Fatalf("target fdinfo must retain exact owner: %q, %v", info, err)
	}
	kernel, kernelErr := os.ReadFile("/proc/sys/kernel/osrelease")
	if kernelErr != nil {
		kernel = []byte("unavailable: " + kernelErr.Error())
	}
	t.Logf("controlled pagination: observed_omission=%t first_contains_target=%t arch=%s kernel=%s pid=%d inode=%d cpu=%d noise=%d streamed=%d bytes independent errno=%d (%v) fdinfo=%q", observedOmission, firstContainsTarget, goruntime.GOARCH, strings.TrimSpace(string(kernel)), pid, st.Ino, cpu, noiseCount, len(omitted), probeErr, probeErr, info)
	if !observedOmission {
		t.Log("kernel iterator did not exhibit the omission; this run is valid held-lock coverage, not an omission reproduction")
	}
	if err := requireLockHolderFromSnapshot(omitted, pid, st); err != nil {
		t.Fatalf("real held lock with captured paginated table: %v", err)
	}
	if err := requireLockHolderFromSnapshot(nil, pid, st); err != nil {
		t.Fatalf("real held lock with explicitly missing global proof: %v", err)
	}
	if err := requireFDLockHolder(pid, st); err != nil {
		t.Fatalf("actual descriptor proof must accept the still-held file: %v", err)
	}
}

func TestLockHolderProofRejectsOtherFilesystem(t *testing.T) {
	_, st := heldProofFile(t, lockPath(t.TempDir()))
	pid := os.Getpid()
	table := listedTable(t, pid, uint64(st.Ino)) // the actual inode-only row
	// A second filesystem with the same inode was separately demonstrated with two real private
	// tmpfs mounts. This unit case varies only the expected device, preserving actual kernel records.
	foreign := st
	foreign.Dev = unix.Mkdev(unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev))+1)
	if err := requireLockHolderFromSnapshot(table, pid, foreign); !errors.Is(err, ErrNotLockHolder) {
		t.Fatalf("same actual owner/inode but different expected filesystem: %v", err)
	}
	if sameLockFile(st, foreign) {
		t.Fatal("descriptor stat must reject foreign device")
	}
}

func TestLockHolderProofRejectsInheritedLockOwner(t *testing.T) {
	f, st := heldProofFile(t, lockPath(t.TempDir()))
	child := exec.Command("/bin/sleep", "30")
	child.ExtraFiles = []*os.File{f}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	info, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/3", child.Process.Pid))
	if err != nil || fdInfoFlockRow(info, os.Getpid(), uint64(st.Ino)) == "" {
		t.Fatalf("borrowed descriptor must retain the parent's actual lock owner: %q, %v", info, err)
	}
	if err := requireLockHolderFromSnapshot(nil, child.Process.Pid, st); !errors.Is(err, ErrNotLockHolder) {
		t.Fatalf("having the descriptor is not owning its flock: %v", err)
	}
}

func TestLockHolderProofRejectsUnlockedAndReplacedFiles(t *testing.T) {
	dir := t.TempDir()
	f, st := heldProofFile(t, lockPath(dir))
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := requireLockHolderFromSnapshot(nil, os.Getpid(), st); !errors.Is(err, ErrNotLockHolder) {
		t.Fatalf("unlocked descriptor: %v", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(lockPath(dir)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath(dir), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := requireLockHolder(pathDir(dir), os.Getpid()); !errors.Is(err, ErrNotLockHolder) {
		t.Fatalf("still-held deleted descriptor does not own replacement lock path: %v", err)
	}
}

func TestFDInfoFlockRowRequiresGrantedFullFileOwner(t *testing.T) {
	valid := "lock:\t1: FLOCK ADVISORY WRITE 42 08:01:99 0 EOF\n"
	for _, tc := range []struct {
		name string
		in   string
		ok   bool
	}{
		{"write", valid, true},
		{"read", strings.Replace(valid, "WRITE", "READ", 1), true},
		{"posix", strings.Replace(valid, "FLOCK", "POSIX", 1), false},
		{"ofd", strings.Replace(valid, "FLOCK", "OFDLCK", 1), false},
		{"waiter", strings.Replace(valid, "1:", "1: ->", 1), false},
		{"foreign owner", strings.Replace(valid, " 42 ", " 43 ", 1), false},
		{"no owner", strings.Replace(valid, " 42 ", " -1 ", 1), false},
		{"foreign inode", strings.Replace(valid, ":99 ", ":100 ", 1), false},
		{"partial range", strings.Replace(valid, " 0 EOF", " 1 EOF", 1), false},
		{"finite range", strings.Replace(valid, " 0 EOF", " 0 50", 1), false},
		{"missing colon", strings.Replace(valid, "1:", "1", 1), false},
		{"invalid index", strings.Replace(valid, "1:", "x:", 1), false},
		{"mandatory", strings.Replace(valid, "ADVISORY", "MANDATORY", 1), false},
		{"inode metadata only", "ino:\t99\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := fdInfoFlockRow([]byte(tc.in), 42, 99); (got != "") != tc.ok {
				t.Fatalf("row=%q, want granted=%v", got, tc.ok)
			}
		})
	}
}

func TestLockHolderSnapshotRequiresExactDeviceAndCompleteRow(t *testing.T) {
	// The unavailable PID ensures malformed/foreign global evidence cannot be rescued by fdinfo.
	const pid = 2147483647
	st := syscall.Stat_t{Dev: unix.Mkdev(8, 1), Ino: 99, Mode: syscall.S_IFREG | 0o600}
	valid := fmt.Sprintf("1: FLOCK ADVISORY WRITE %d 08:01:99 0 EOF\n", pid)
	for _, tc := range []struct {
		name string
		in   string
		ok   bool
	}{
		{"exact", valid, true},
		{"foreign major", strings.Replace(valid, "08:01", "09:01", 1), false},
		{"foreign minor", strings.Replace(valid, "08:01", "08:02", 1), false},
		{"malformed major", strings.Replace(valid, "08:01", "gg:01", 1), false},
		{"missing device", strings.Replace(valid, "08:01:99", "01:99", 1), false},
		{"extra device", strings.Replace(valid, "08:01:99", "00:08:01:99", 1), false},
		{"waiter", strings.Replace(valid, "1:", "1: ->", 1), false},
		{"partial range", strings.Replace(valid, "0 EOF", "1 EOF", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := requireLockHolderFromSnapshot([]byte(tc.in), pid, st)
			if (err == nil) != tc.ok {
				t.Fatalf("proof err=%v, want accepted=%v", err, tc.ok)
			}
		})
	}
}

func TestReadFDLockRowBoundsAndRegularStat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "info")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", lockProofInfoLimit+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readFDLockRow(path, os.Getpid(), 1); err == nil {
		t.Fatal("oversized descriptor metadata must fail closed")
	}
	want := syscall.Stat_t{Dev: 1, Ino: 2, Mode: syscall.S_IFREG}
	for _, mode := range []uint32{syscall.S_IFDIR, syscall.S_IFIFO, syscall.S_IFSOCK, syscall.S_IFCHR} {
		got := want
		got.Mode = mode
		if sameLockFile(got, want) {
			t.Fatalf("nonregular mode %#o accepted", mode)
		}
	}
}

func TestGlobalLockProofReadBoundDiscardsPositivePrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "table")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	const pid = 2147483647
	st := syscall.Stat_t{Dev: unix.Mkdev(8, 1), Ino: 99, Mode: syscall.S_IFREG | 0o600}
	prefix := fmt.Sprintf("1: FLOCK ADVISORY WRITE %d 08:01:99 0 EOF\n", pid)
	if _, err := io.WriteString(f, prefix); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(int64(lockProofTableLimit)); err != nil {
		t.Fatal(err)
	}
	atLimit, err := readLockProofFile(path, lockProofTableLimit)
	if err != nil || len(atLimit) != lockProofTableLimit {
		t.Fatalf("exact table payload boundary: bytes=%d err=%v", len(atLimit), err)
	}
	if err := requireLockHolderFromSnapshot(atLimit, pid, st); err != nil {
		t.Fatalf("test boundary file must contain a complete exact positive prefix: %v", err)
	}
	if err := f.Truncate(int64(lockProofTableLimit + 1)); err != nil {
		t.Fatal(err)
	}
	tooLarge, err := readLockProofFile(path, lockProofTableLimit)
	if err == nil || tooLarge != nil {
		t.Fatalf("overflow must discard all bytes, including the positive prefix: bytes=%d err=%v", len(tooLarge), err)
	}
	if err := requireLockHolderFromSnapshot(tooLarge, pid, st); !errors.Is(err, ErrNotLockHolder) {
		t.Fatalf("discarded prefix must not authorize the unavailable test PID: %v", err)
	}
	if raw, err := readLockProofFile(path+"-missing", lockProofTableLimit); err == nil || raw != nil {
		t.Fatalf("unavailable table must supply no global evidence: bytes=%d err=%v", len(raw), err)
	}
}

func TestLockHolderProofNonDumpableHelper(t *testing.T) {
	if os.Getenv("TEGO_LOCK_NONDUMPABLE_HELPER") != "1" {
		return
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(3, syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("TEGO_LOCK_HELPER_READY"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Second)
	}
}

func TestLockHolderProofForNonDumpableLauncher(t *testing.T) {
	dir := t.TempDir()
	f, err := os.OpenFile(lockPath(dir), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	ready := filepath.Join(dir, "ready")
	child := exec.Command(os.Args[0], "-test.run=^TestLockHolderProofNonDumpableHelper$", "-test.timeout=30s")
	child.Env = append(os.Environ(), "TEGO_LOCK_NONDUMPABLE_HELPER=1", "TEGO_LOCK_HELPER_READY="+ready)
	child.ExtraFiles = []*os.File{f}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("non-dumpable helper did not obtain private lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
	_, descriptorErr := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/3", child.Process.Pid))
	if descriptorErr != nil {
		t.Logf("descriptor proof unavailable for actual non-dumpable helper: %v", descriptorErr)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	// The parent's inherited open file description exposes the child's real flock row even when
	// the child's proc directory is inaccessible. Some btrfs subvolumes print a superblock device
	// differing from st.Dev; with inaccessible target descriptors that is explicitly unavailable proof.
	parentInfo, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%d", os.Getpid(), f.Fd()))
	row := fdInfoFlockRow(parentInfo, child.Process.Pid, uint64(st.Ino))
	if err != nil || row == "" {
		t.Fatalf("shared description must expose actual child's lock: %q, %v", parentInfo, err)
	}
	wantID := fmt.Sprintf("%02x:%02x:%d", unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)), st.Ino)
	deviceMatches := strings.Fields(row)[5] == wantID
	// Exercise the positive global-proof path with a read that actually contains the row.
	// A fresh read in OpenStopTarget may omit it when unrelated locks change between seq_file
	// fills. With inaccessible target descriptors that is unavailable proof, correctly refused;
	// neither the child's ready file nor the parent's fdinfo makes that new table read stable.
	table := listedTable(t, child.Process.Pid, uint64(st.Ino))
	err = requireLockHolderFromSnapshot(table, child.Process.Pid, st)
	if !deviceMatches && descriptorErr != nil {
		if !errors.Is(err, ErrNotLockHolder) {
			t.Fatalf("inaccessible descriptor plus printed-device mismatch must fail closed: %v", err)
		}
		t.Logf("explicit unavailable-proof limit: kernel=%s actual=%s", strings.Fields(row)[5], wantID)
		return
	}
	if err != nil {
		t.Fatalf("exact global device/owner/inode proof must preserve non-dumpable launcher control: %v", err)
	}
	if err := requireLockHolderFromSnapshot(nil, child.Process.Pid, st); descriptorErr != nil && !errors.Is(err, ErrNotLockHolder) {
		t.Fatalf("no global row and inaccessible descriptors must fail closed: %v", err)
	}
	start, err := StartBootNS(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	target, err := openPidfdTarget(child.Process.Pid, start)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = target.Close() }()
	if err := target.Signal(0); err != nil {
		t.Fatalf("verified non-dumpable launcher remains signalable: %v", err)
	}
}
