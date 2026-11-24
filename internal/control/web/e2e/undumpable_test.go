// SPDX-License-Identifier: Apache-2.0

//go:build integration

package e2e

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runlock"
)

// requireUndumpableDashboard looks at the running tego-control serve (pid) as the other processes of its user can, and
// fails unless the dashboard is closed to every one of them: it holds the sign-in token, the CSRF and acknowledgement
// keys and a Vault page value, and a process of the same user, such as the agent of a run with no Landlock domain on a
// host whose Yama ptrace_scope is 0, must not read them (ADR 0100 (7), amended 2026-11-22). The test process is the
// dashboard's parent, which Yama lets attach to a child, so only the dumpable flag stands in its way, as it does for a
// sibling. What the processes that read the dashboard need (stat, status, cmdline, cgroup, a pidfd) must still answer.
func requireUndumpableDashboard(t *testing.T, pid int) {
	t.Helper()
	root := fmt.Sprintf("/proc/%d/", pid)
	for _, name := range []string{"environ", "maps", "mem", "fd", "exe", "cwd", "root", "ns/cgroup", "ns/user", "io", "syscall"} {
		f, err := os.Open(root + name)
		if err == nil {
			_ = f.Close()
			t.Errorf("the dashboard's %s opens for its own user: it is dumpable", root+name)
			continue
		}
		if !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM) {
			t.Errorf("open %s: %v, want a permission error", root+name, err)
		}
	}
	for _, name := range []string{"environ", "maps"} { // a sibling, which is what the agent of a run is
		var out, errb bytes.Buffer
		c := exec.Command("cat", root+name)
		c.Stdout, c.Stderr = &out, &errb
		if err := c.Run(); err == nil || !strings.Contains(errb.String(), "Permission denied") || out.Len() != 0 {
			t.Errorf("a sibling reads %s: %v %q (%d bytes)", root+name, err, errb.String(), out.Len())
		}
	}
	if attached(pid) {
		t.Error("PTRACE_ATTACH to the dashboard succeeded")
	}
	pfd, err := sys.PidfdOpenProcess(pid)
	if err != nil {
		t.Fatalf("pidfd_open of the dashboard: %v", err)
	}
	defer func() { _ = unix.Close(pfd) }()
	if fd, err := sys.PidfdGetfd(pfd, 1); err == nil {
		_ = unix.Close(fd)
		t.Error("pidfd_getfd took a descriptor of the dashboard")
	}
	if err := sys.PidfdSendSignal(pfd, 0); err != nil {
		t.Errorf("signal 0 through the dashboard's pidfd: %v", err)
	}
	for _, name := range []string{"stat", "status", "cmdline", "cgroup", "comm", "mountinfo"} {
		if b, err := os.ReadFile(root + name); err != nil || len(b) == 0 {
			t.Errorf("read %s: %d bytes, %v; the readers of the dashboard (tego scan, doctor, the manager) need it", root+name, len(b), err)
		}
	}
}

// attached tries PTRACE_ATTACH to pid and, when it works, waits for the stop and detaches, so the process is not left
// stopped. ptrace requests belong to the thread that attached, so the whole exchange runs on one.
func attached(pid int) bool {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.PtraceAttach(pid); err != nil {
		return false
	}
	var ws unix.WaitStatus
	_, _ = unix.Wait4(pid, &ws, unix.WALL, nil)
	_ = unix.PtraceDetach(pid)
	return true
}

// requireDashboardNamedToTheScan: the dashboard (pid) is non-dumpable, so a scan of its user's processes cannot read its
// program file, and it would count it among the unreadable programs, which makes `tego scan --check` exit 3 on every
// machine where it runs. It holds the dashboard's lock instead (under the world's test home), the lock proves it the way
// a launcher's proves it, and the real tego, built with the test hooks over the same home, leaves that pid out of the
// unreadable programs it lists. Other unreadable programs of this user (the manager, a keyring) stay in the list, so
// the exit code is not asserted here.
func requireDashboardNamedToTheScan(t *testing.T, w *world, pid int) {
	t.Helper()
	home := ""
	for _, kv := range w.env {
		if v, ok := strings.CutPrefix(kv, "TEGO_TEST_OWN_LOG_HOME="); ok {
			home = v
		}
	}
	if got, ok := runlock.DashboardPID(home); !ok || got != pid {
		t.Fatalf("DashboardPID(%q) = %d, %v; want the dashboard %d", home, got, ok, pid)
	}
	c := exec.Command(w.tego, "scan", "--check", "--json")
	c.Env = w.env
	var out bytes.Buffer
	c.Stdout = &out
	if err := c.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) { // 3, 1 and 125 are answers; a scan that did not start is not
			t.Fatalf("tego scan --check --json: %v", err)
		}
	}
	var s struct {
		Pids  []int `json:"unreadable_program_pids"`
		Check string
	}
	if err := json.Unmarshal(out.Bytes(), &s); err != nil {
		t.Fatalf("tego scan --check --json printed %q: %v", out.String(), err)
	}
	for _, p := range s.Pids {
		if p == pid {
			t.Errorf("the scan lists the dashboard (pid %d) among the unreadable programs %v", pid, s.Pids)
		}
	}
	t.Logf("scan: unreadable programs %v (the dashboard is %d), check %q", s.Pids, pid, s.Check)
}
