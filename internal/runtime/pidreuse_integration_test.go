// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestIntegrationStopAfterPidReuseSignalsNothing is runtime-launch.md §6 cases 15, 29 and 32 and R22 against
// the kernel: a run's launcher is SIGKILLed and reaped, its pid is issued again to an unrelated process, and a
// process of no launcher holds the run's lock, so the lock line still names the dead launcher's pid. `tego
// stop` of the run, the sweep it makes first, and a direct OpenStopTarget all find the pid alive with another
// start time: nothing is signalled, and the unrelated process lives on with the same start time.
//
// Case 29 describes spinning until the pid allocator wraps. The kernel reissues a pid number the same way
// whichever path leads to it, so the test sets /proc/sys/kernel/ns_last_pid to the pid before the one it wants
// (CONFIG_CHECKPOINT_RESTORE, which every matrix kernel has) and forks, retrying when another fork took the pid
// first: the reuse is exact and takes milliseconds, where a wrap through pid_max takes minutes. Root only: the
// sysctl needs CAP_SYS_ADMIN (or CAP_CHECKPOINT_RESTORE) over the pid namespace.
//
// Also pins runtime-launch.md E15, E29, E32: a reused pid is detected by start time and nothing is signaled.
func TestIntegrationStopAfterPidReuseSignalsNothing(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("reissuing a chosen pid through ns_last_pid needs root: run as `sudo go test -tags integration` or `make vm-root-test`")
	}
	if _, err := os.Stat(nsLastPID); err != nil {
		t.Skipf("no %s (a kernel without CONFIG_CHECKPOINT_RESTORE): %v", nsLastPID, err)
	}
	bin := tegoBinary(t)
	f := newFixture(t, contractFor("ipidreuse", []string{"/bin/sleep"}, []string{"/bin/sleep"}))
	cfg := writeMachineConfig(t, f)
	env := append(os.Environ(), "TEGO_CONFIG="+cfg)

	launcher := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"), "--", "/bin/sleep", "120")
	launcher.Dir = f.dir
	launcher.Env = env
	if err := launcher.Start(); err != nil {
		t.Fatalf("start launcher: %v", err)
	}
	t.Cleanup(func() {
		_ = launcher.Process.Kill()
		_, _ = Sweep(context.Background(), f.root, KeepForever)
	})
	dir := waitForStartedRun(t, f.root, 20*time.Second)
	held, info, err := ProbeLock(dir)
	if err != nil || !held || info.PID != launcher.Process.Pid || info.StartBootNS == 0 {
		t.Fatalf("the live run's lock: held %v, %+v, %v; want held by launcher %d", held, info, err, launcher.Process.Pid)
	}

	if err := launcher.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = launcher.Wait() // reaped: the pid is free for the allocator
	waitLockFree(t, dir)
	holdLock(t, lockPath(dir)) // a process of no launcher keeps the lock, and the lock line keeps its pid

	stranger := reissuePID(t, info.PID)
	strangerStart, err := StartBootNS(info.PID)
	if err != nil {
		t.Fatal(err)
	}
	if strangerStart == info.StartBootNS {
		t.Fatalf("the reissued pid %d has the dead launcher's start time %d; the test proves nothing", info.PID, strangerStart)
	}
	// A process just forked is running until it reaches its sleep: wait for that, so the state checks below
	// tell a signalled stranger from one still starting.
	for deadline := time.Now().Add(10 * time.Second); procState(t, info.PID) != "S" && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	untouched := func(what string) {
		t.Helper()
		if !alive(info.PID) {
			t.Fatalf("%s: the process that reuses the dead launcher's pid %d was killed", what, info.PID)
		}
		if got, err := StartBootNS(info.PID); err != nil || got != strangerStart {
			t.Fatalf("%s: pid %d now started at %d (%v), want the stranger's %d", what, info.PID, got, err, strangerStart)
		}
		if st := procState(t, info.PID); st != "S" {
			t.Fatalf("%s: the stranger is in state %q, want S (asleep, not stopped or dying)", what, st)
		}
	}

	if _, err := OpenStopTarget(dir, info.PID, info.StartBootNS); !errors.Is(err, ErrStale) {
		t.Fatalf("OpenStopTarget of the reissued pid with the lock's start time: %v, want ErrStale", err)
	}
	untouched("OpenStopTarget")

	stop := exec.Command(bin, "stop", "--grace", "1s", filepath.Base(dir))
	stop.Env = env
	out, err := stop.CombinedOutput()
	if err != nil {
		t.Fatalf("tego stop: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "not running") {
		t.Errorf("tego stop of a run whose launcher's pid was reissued said %q, want not running", out)
	}
	untouched("tego stop")
	if _, err := os.Stat(filepath.Join(dir, StopRequestFile)); err == nil {
		t.Log("stop left its marker; harmless without a launcher (case 12)")
	}

	if _, err := Sweep(context.Background(), f.root, KeepForever); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	untouched("Sweep")
	_ = stranger.Process.Kill()
	_ = stranger.Wait()
}

// nsLastPID is the pid the calling pid namespace issued last; the next fork gets the next free one after it.
const nsLastPID = "/proc/sys/kernel/ns_last_pid"

// reissuePID starts `sleep` with exactly pid, which must be free, and returns it.
func reissuePID(t *testing.T, pid int) *exec.Cmd {
	t.Helper()
	for try := 0; try < 2000; try++ {
		if err := os.WriteFile(nsLastPID, []byte(strconv.Itoa(pid-1)), 0); err != nil {
			t.Fatalf("write %s: %v", nsLastPID, err)
		}
		c := exec.Command("/bin/sleep", "300")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		if c.Process.Pid == pid {
			t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
			return c
		}
		_ = c.Process.Kill()
		_ = c.Wait()
	}
	t.Fatalf("pid %d was never reissued to a new process", pid)
	return nil
}

// procState is the one-letter state of pid in /proc/<pid>/stat.
func procState(t *testing.T, pid int) string {
	t.Helper()
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		t.Fatalf("stat %q", s)
	}
	return s[i+2 : i+3]
}
