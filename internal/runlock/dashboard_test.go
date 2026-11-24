// SPDX-License-Identifier: Apache-2.0

package runlock

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

const dashboardHelperEnv = "TEGO_TEST_DASHBOARD_LOCK_HELPER"

// TestDashboardLockHelper is the stand-in dashboard the tests below start: a process that made itself undumpable, as
// tego-control serve does, holds the dashboard's lock under the home it is given, says so, and lives until its input
// ends. It returns at once when it is not a helper (a plain run of this package's tests).
func TestDashboardLockHelper(t *testing.T) {
	home := os.Getenv(dashboardHelperEnv)
	if home == "" {
		return
	}
	if err := sys.MakeUndumpable(); err != nil {
		t.Fatal(err)
	}
	f, err := HoldDashboard(home)
	if err != nil {
		os.Stdout.WriteString("error " + err.Error() + "\n")
		return
	}
	defer func() { _ = f.Close() }()
	os.Stdout.WriteString("held " + strconv.Itoa(os.Getpid()) + "\n")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// dashboardHelper starts the stand-in dashboard under home and returns its pid and a function that ends it.
func dashboardHelper(t *testing.T, home string) (pid int, end func()) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestDashboardLockHelper$", "-test.timeout=60s")
	cmd.Env = append(os.Environ(), dashboardHelperEnv+"="+home)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ended := false
	end = func() {
		if !ended {
			ended = true
			_ = in.Close()
			_ = cmd.Wait()
		}
	}
	t.Cleanup(end)
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatalf("the stand-in dashboard said nothing: %v", err)
	}
	word, ok := strings.CutPrefix(strings.TrimSpace(line), "held ")
	got, err := strconv.Atoi(word)
	if !ok || err != nil {
		t.Fatalf("the stand-in dashboard did not take the lock: %q", line)
	}
	return got, end
}

// TestDashboardPIDNamesAnUndumpableDashboard: a dashboard that made itself undumpable hides its descriptors and program
// from this user, and is named all the same by the lock it holds, proved as a launcher is (the kernel's lock table and
// the pid's start time). Once it ends, no pid is named, and nothing the file still says brings one back.
func TestDashboardPIDNamesAnUndumpableDashboard(t *testing.T) {
	home := t.TempDir()
	if pid, ok := DashboardPID(home); ok || pid != 0 {
		t.Fatalf("with no dashboard lock the pid is %d, %v; want none", pid, ok)
	}
	pid, end := dashboardHelper(t, home)
	if _, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/environ"); err == nil && os.Geteuid() != 0 {
		t.Fatal("the stand-in dashboard's environment is readable by this user; it is not undumpable") // root reads every process's
	}
	got, ok := DashboardPID(home)
	if !ok || got != pid {
		t.Fatalf("DashboardPID = %d, %v; want %d, true", got, ok, pid)
	}
	end()
	if got, ok := DashboardPID(home); ok || got != 0 {
		t.Fatalf("after the dashboard ended DashboardPID = %d, %v; want none (the file still names it)", got, ok)
	}
}

// TestDashboardLockIsOneAtATime: a second dashboard cannot take the lock the first holds, and a lock the first
// released is free.
func TestDashboardLockIsOneAtATime(t *testing.T) {
	home := t.TempDir()
	first, err := HoldDashboard(home)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := HoldDashboard(home); !errors.Is(err, ErrDashboardHeld) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatalf("a second HoldDashboard = %v; want ErrDashboardHeld", err)
	}
	if pid, ok := DashboardPID(home); !ok || pid != os.Getpid() {
		t.Fatalf("DashboardPID = %d, %v; want this process %d", pid, ok, os.Getpid())
	}
	_ = first.Close()
	if pid, ok := DashboardPID(home); ok {
		t.Fatalf("after the lock was released DashboardPID = %d, true", pid)
	}
	again, err := HoldDashboard(home)
	if err != nil {
		t.Fatalf("a released lock is free: %v", err)
	}
	_ = again.Close()
}

// TestDashboardPIDIsNotTheLine: the line in the file is advisory text anyone with the file can write. A line that names
// another live process, this one, or a pid reused with another start time names nobody while a different process holds
// the lock; and a lock nobody holds names nobody whatever the line says.
func TestDashboardPIDIsNotTheLine(t *testing.T) {
	home := t.TempDir()
	holder, end := dashboardHelper(t, home)
	defer end()
	file := filepath.Join(DashboardDir(home), "lock")
	start, err := StartBootNS(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	for name, info := range map[string]LockInfo{
		"another live process, which holds nothing": {PID: os.Getppid(), StartBootNS: mustStart(t, os.Getppid()), PIDNS: OwnPIDNS()},
		"this process, which holds nothing":         {PID: os.Getpid(), StartBootNS: start, PIDNS: OwnPIDNS()},
		"the holder at another start time":          {PID: holder, StartBootNS: mustStart(t, holder) + 1, PIDNS: OwnPIDNS()},
	} {
		if err := os.WriteFile(file, []byte(info.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		if pid, ok := DashboardPID(home); ok {
			t.Errorf("%s: DashboardPID = %d, true; want none", name, pid)
		}
	}
	end()
	if err := os.WriteFile(file, []byte(LockInfo{PID: os.Getppid(), StartBootNS: mustStart(t, os.Getppid()), PIDNS: OwnPIDNS()}.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if pid, ok := DashboardPID(home); ok {
		t.Errorf("a lock nobody holds: DashboardPID = %d, true; want none", pid)
	}
}

func mustStart(t *testing.T, pid int) uint64 {
	t.Helper()
	n, err := StartBootNS(pid)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestDashboardLockRefusesWhatIsNotAPlainOwnFile: a link or a folder under the lock's name is refused, never followed.
func TestDashboardLockRefusesWhatIsNotAPlainOwnFile(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(DashboardDir(home), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "elsewhere")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(DashboardDir(home), "lock")); err != nil {
		t.Fatal(err)
	}
	if f, err := HoldDashboard(home); err == nil {
		_ = f.Close()
		t.Fatal("HoldDashboard followed a link planted under the lock's name")
	}
	if b, _ := os.ReadFile(target); len(b) != 0 {
		t.Fatalf("the link's target was written: %q", b)
	}
}

// TestDashboardLockWantsAnAbsoluteHome: no home names no lock, and a relative one is never read from the working
// directory.
func TestDashboardLockWantsAnAbsoluteHome(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, home := range []string{"", ".", "home"} {
		if f, err := HoldDashboard(home); err == nil {
			_ = f.Close()
			t.Errorf("HoldDashboard(%q) held a lock", home)
		}
		if pid, ok := DashboardPID(home); ok {
			t.Errorf("DashboardPID(%q) = %d, true", home, pid)
		}
	}
	if _, err := os.Stat(".tego"); err == nil {
		t.Error("a relative home made .tego in the working directory")
	}
}
