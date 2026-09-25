// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationEnforcementOutlivesItsLauncher is runtime-launch.md I7: Landlock and the cgroup limits stay
// enforced on the agent's tree after the launcher is SIGKILLed, because they live in the kernel (the
// process's Landlock domain, the cgroup's control files) and not in a userspace loop. The ENOSYS half, a
// notified syscall with its listener gone, is TestIntegrationADaemonOutlivingItsLauncherGetsENOSYS; this
// test is the other two, each reached by a syscall the seccomp filter does not notify, so the only thing
// that can refuse it is the kernel state the launcher left behind:
//
//   - a unix bind(2) at a path outside fs.write, which the filter never notifies: Landlock refuses the socket
//     inode it would make with EACCES (LANDLOCK_ACCESS_FS_MAKE_SOCK, every ABI). A write-open, a mknod(2) of a
//     FIFO and a truncate(2) beside it, which the filter does notify (mknod from 2026-09-29, for R15c; truncate
//     from ABI 3, so the supervisor records it; below ABI 3 the filter refuses it with EPERM), are ENOSYS: the
//     two layers answer side by side;
//   - fork(2) past the contract's pids: the cgroup's pids.max refuses it, pids.events' max counter moves, and
//     pids.current never passes the cap.
//
// Both actors are descendants that double-forked away from the agent, so the launcher's PDEATHSIG does not
// end them, and each waits on a FIFO the test opens only after the launcher is dead and its lock free.
func TestIntegrationEnforcementOutlivesItsLauncher(t *testing.T) {
	bin := tegoBinary(t)
	const pidsCap = 24
	helper := helperCopy(t)
	f := newFixture(t, strings.Replace(
		contractFor("ioutlive", []string{"/bin/sh"}, []string{"/bin/sh", "/bin/sleep", helper}),
		"  pids: 128", "  pids: "+strconv.Itoa(pidsCap), 1))
	cfg := writeMachineConfig(t, f)

	// A directory and a file outside fs.write that the agent's own uid owns and may write, so no mode bit
	// refuses what the helper tries there: only Landlock can.
	other := filepath.Join(f.dir, "other")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(other, "outside.txt")
	if err := os.WriteFile(outside, []byte("the launcher's contract never granted this file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outsideFIFO := filepath.Join(other, "outside.fifo")
	goTrunc := filepath.Join(f.dir, "go-truncate")
	goFork := filepath.Join(f.dir, "go-fork")
	hold := filepath.Join(f.dir, "hold")
	for _, p := range []string{goTrunc, goFork, hold} {
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Fatalf("mkfifo: %v", err)
		}
	}
	script := filepath.Join(f.dir, "outlive.sh")
	// The helper's TestMain makes its temporary parent under TMPDIR, which must be a directory the contract
	// lets it write; the forker's children each block opening the hold FIFO, which nothing ever writes.
	body := fmt.Sprintf(`#!/bin/sh
( TMPDIR=%q exec %q -test.run='^TestOutlivesLauncherHelper$' %q %q %q & )
( /bin/sh -c '
	echo "forker ready pid=$$"
	read line < "$0"
	i=0
	while [ $i -lt 64 ]; do
		( read l < "$1" ) &
		i=$((i+1))
		echo "forked $i"
	done
	echo "forker done"
' %q %q & )
exec /bin/sleep 120
`, f.out, helper, goTrunc, outside, outsideFIFO, goFork, hold)
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, script, other, outside, goTrunc, goFork, hold)

	outFile := filepath.Join(t.TempDir(), "stdout")
	errFile := filepath.Join(t.TempDir(), "stderr")
	stdout, err := os.Create(outFile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdout.Close() }()
	stderr, err := os.Create(errFile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stderr.Close() }()

	cmd := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"), "--", "/bin/sh", script)
	cmd.Dir = f.dir
	cmd.Env = append(os.Environ(), "TEGO_CONFIG="+cfg)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start launcher: %v", err)
	}
	dir := waitForStartedRun(t, f.root, 20*time.Second)
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = Sweep(context.Background(), f.root, KeepForever)
	})
	helperPID := pidOf(t, waitForLine(t, outFile, errFile, "helper ready"))
	forkerPID := pidOf(t, waitForLine(t, outFile, errFile, "forker ready"))
	scope := cgroupDirOf(t, forkerPID)
	if got := readTrim(t, filepath.Join(scope, "pids.max")); got != strconv.Itoa(pidsCap) {
		t.Fatalf("the run's pids.max is %q, want %d", got, pidsCap)
	}
	maxBefore := pidsEventsMax(t, scope)

	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("kill launcher: %v", err)
	}
	_ = cmd.Wait()
	waitLockFree(t, dir)
	if !alive(helperPID) || !alive(forkerPID) {
		t.Fatalf("the descendants did not survive their launcher (helper %v, forker %v); the test proves nothing",
			alive(helperPID), alive(forkerPID))
	}

	// Landlock: the filesystem half.
	release(t, goTrunc)
	waitForLine(t, outFile, errFile, "helper done")
	// bind(2) is notified too: the contract has no net: section, so the run is in ADR 0070's unix-only state and the
	// filter notifies every bind for the supervisor's record of the run's own sockets (enforce-landlock R11c). With the
	// supervisor gone the notification answers ENOSYS before Landlock's MAKE_SOCK check is reached; no socket is
	// made either way (checked below).
	want := map[string]syscall.Errno{"truncate": syscall.ENOSYS, "mknod": syscall.ENOSYS, "open-write": syscall.ENOSYS,
		"bind": syscall.ENOSYS}
	if abi, err := sys.LandlockABI(); err == nil && abi < 3 {
		want["truncate"] = syscall.EPERM // below ABI 3 the filter refuses truncate(2) itself (enforce-landlock R2)
	}
	for op, errno := range want {
		line := waitForLine(t, outFile, errFile, "helper "+op+" ")
		if !strings.HasSuffix(line, " errno="+errnoName(errno)) {
			t.Errorf("after the launcher died, %s outside fs.write: %q, want errno=%s", op, line, errnoName(errno))
		}
	}
	if b, err := os.ReadFile(outside); err != nil || len(b) == 0 {
		t.Errorf("the file outside fs.write was changed (%d bytes, %v)", len(b), err)
	}
	for _, p := range []string{outsideFIFO, outsideSocket(outsideFIFO)} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s outside fs.write was made (%v)", p, err)
		}
	}

	// The cgroup: pids.max.
	release(t, goFork)
	deadline := time.Now().Add(20 * time.Second)
	for pidsEventsMax(t, scope) == maxBefore && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if pidsEventsMax(t, scope) == maxBefore {
		t.Fatalf("no fork was refused after the launcher died: pids.events max stayed %d\nstdout:\n%s", maxBefore,
			readFileString(outFile))
	}
	cur, err := strconv.Atoi(readTrim(t, filepath.Join(scope, "pids.current")))
	if err != nil || cur > pidsCap {
		t.Fatalf("pids.current %d (%v) over the cap %d", cur, err, pidsCap)
	}
	if strings.Contains(readFileString(outFile), "forker done") {
		t.Fatalf("all 64 forks succeeded under pids.max=%d:\n%s", pidsCap, readFileString(outFile))
	}
	t.Logf("after the launcher died: %d forks made, pids.current %d of %d", strings.Count(readFileString(outFile), "forked "),
		cur, pidsCap)

	res, err := Sweep(context.Background(), f.root, KeepForever)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if res.Orphaned != 1 {
		t.Fatalf("swept %d/%d run(s), want 1 (errs %v)", res.Orphaned, res.Scanned, res.Errs)
	}
	if got := lastReason(t, dir); got != record.RunEndOrphaned {
		t.Fatalf("run ended with %q, want orphaned", got)
	}
	assertCgroupRemoved(t, f, filepath.Base(dir), "ioutlive")
}

// TestOutlivesLauncherHelper is TestIntegrationEnforcementOutlivesItsLauncher's filesystem actor: started by the
// agent with the release FIFO, a file outside fs.write and a FIFO path beside it, it reports its pid, waits for
// the release, and then prints the errno of each attempt. It does nothing in a normal run.
func TestOutlivesLauncherHelper(t *testing.T) {
	args := flag.Args()
	if len(args) != 3 {
		t.Skip("helper process only")
	}
	release, outside, fifo := args[0], args[1], args[2]
	fmt.Printf("helper ready pid=%d\n", os.Getpid())
	// A read-open of a FIFO is not notified: the filter lets it through with or without a listener.
	fd, err := unix.Open(release, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		fmt.Printf("helper release open errno=%s\n", errnoName(err))
		return
	}
	var b [64]byte
	_, _ = unix.Read(fd, b[:])
	_ = syscall.Close(fd)
	fmt.Printf("helper truncate errno=%s\n", errnoName(unix.Truncate(outside, 0)))
	fmt.Printf("helper mknod errno=%s\n", errnoName(unix.Mknod(fifo, unix.S_IFIFO|0o600, 0)))
	sfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		// Relative to its directory: the test's temporary path can be longer than sun_path holds.
		if err = os.Chdir(filepath.Dir(fifo)); err == nil {
			err = unix.Bind(sfd, &unix.SockaddrUnix{Name: filepath.Base(outsideSocket(fifo))})
		}
		_ = syscall.Close(sfd)
	}
	fmt.Printf("helper bind errno=%s\n", errnoName(err))
	wfd, err := unix.Open(outside, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err == nil {
		_ = syscall.Close(wfd)
	}
	fmt.Printf("helper open-write errno=%s\n", errnoName(err))
	fmt.Println("helper done")
	_ = os.Stdout.Sync()
}

// outsideSocket is the socket path the helper binds beside the FIFO path it is given.
func outsideSocket(fifo string) string { return filepath.Join(filepath.Dir(fifo), "outside.sock") }

// helperCopy copies this test binary where the dropped agent of a root run can execute it, and returns its path.
func helperCopy(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return reachableCopy(t, self, "helper")
}

// reachableCopy copies the executable src into a directory of its own that the dropped agent of a root run can
// pass through, as name, and returns the copy's path.
func reachableCopy(t *testing.T, src, name string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, name)
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	agentReaches(t, dst)
	return dst
}

// errnoName is an error's errno as its symbolic name ("ok" for nil), so a report line is unambiguous.
func errnoName(err error) string {
	if err == nil {
		return "ok"
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return err.Error()
	}
	if name := unix.ErrnoName(errno); name != "" {
		return name
	}
	return strconv.Itoa(int(errno))
}

// pidOf reads the pid=N field of a report line.
func pidOf(t *testing.T, line string) int {
	t.Helper()
	_, v, ok := strings.Cut(line, "pid=")
	if !ok {
		t.Fatalf("no pid in %q", line)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		t.Fatal(err)
	}
	return pid
}

// cgroupDirOf is the cgroup v2 directory pid is in.
func cgroupDirOf(t *testing.T, pid int) string {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if rest, ok := strings.CutPrefix(l, "0::"); ok {
			return filepath.Join("/sys/fs/cgroup", rest)
		}
	}
	t.Fatalf("no cgroup v2 line in %q", b)
	return ""
}

// pidsEventsMax is the max counter of a cgroup's pids.events: the forks pids.max refused.
func pidsEventsMax(t *testing.T, dir string) uint64 {
	t.Helper()
	for _, l := range strings.Split(readTrim(t, filepath.Join(dir, "pids.events")), "\n") {
		if v, ok := strings.CutPrefix(l, "max "); ok {
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
	}
	t.Fatalf("no max line in %s/pids.events", dir)
	return 0
}

// readTrim is a file's contents without the trailing newline, failing the test when it cannot be read.
func readTrim(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}
