// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package testutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

// sysTraceFileEnv names, to TestSysTraceFollowsAGoExecChild's traced child, the file its own child reads.
const sysTraceFileEnv = "TEGO_SYSTRACE_TEST_FILE"

// TestSysTraceCommandFollowsChildren: a program that starts a helper makes the helper's syscalls too, so the audit
// of a program a test built records them, and the program's fork shows as a call that Spawns (a hook whose child
// read a file outside its set, or made bpf(2), passed an audit that followed threads only). The
// shell forks for cat, since another command follows it.
func TestSysTraceCommandFollowsChildren(t *testing.T) {
	file := sysTraceFile(t)
	cmd := exec.Command("/bin/sh", "-c", `cat "$1" >/dev/null; exit 0`, "sh", file)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	calls, status := SysTraceCommand(t, cmd)
	if !status.Exited() || status.ExitStatus() != 0 {
		t.Fatalf("sh: status %#x", int(status))
	}
	checkFollowed(t, calls, file)
}

// TestSysTraceFollowsAGoExecChild is the same for SysTrace and for the way a Go program starts one: os/exec's
// clone(CLONE_VM|CLONE_VFORK), which the kernel reports as a vfork.
func TestSysTraceFollowsAGoExecChild(t *testing.T) {
	if InSysTraceChild() {
		MarkBegin()
		err := exec.Command("/bin/cat", os.Getenv(sysTraceFileEnv)).Run()
		MarkEnd()
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	file := sysTraceFile(t)
	checkFollowed(t, SysTrace(t, t.Name(), sysTraceFileEnv+"="+file), file)
}

func sysTraceFile(t *testing.T) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "read-by-the-child")
	if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

// checkFollowed fails unless calls hold a call that Spawns and the child's own open of file.
func checkFollowed(t *testing.T, calls []Syscall, file string) {
	t.Helper()
	var spawned, opened bool
	for _, c := range calls {
		spawned = spawned || c.Spawns()
		for _, p := range c.Paths {
			opened = opened || (p == file && (c.Nr == SysOpen || c.Nr == SysOpenat || c.Nr == SysOpenat2))
		}
	}
	if !spawned {
		t.Error("no recorded call starts a process or runs a program")
	}
	if !opened {
		t.Errorf("the child's open of %s is not recorded: the trace does not follow the children", file)
	}
}

// TestSpawnsTellsAThreadFromAProcess: a clone with CLONE_THREAD (each Go runtime thread) is not a spawn; one
// without it, fork, vfork and the two execs are.
func TestSpawnsTellsAThreadFromAProcess(t *testing.T) {
	const thread = syscall.CLONE_VM | syscall.CLONE_FS | syscall.CLONE_FILES | syscall.CLONE_SIGHAND | syscall.CLONE_THREAD
	for _, tc := range []struct {
		s    Syscall
		want bool
	}{
		{Syscall{Nr: SysClone, Flags: thread}, false},
		{Syscall{Nr: SysClone3, Flags: thread}, false},
		{Syscall{Nr: SysClone, Flags: syscall.CLONE_VM | syscall.CLONE_VFORK | uint64(syscall.SIGCHLD)}, true},
		{Syscall{Nr: SysClone3, Flags: syscall.CLONE_PIDFD}, true},
		{Syscall{Nr: SysFork}, true},
		{Syscall{Nr: SysVfork}, true},
		{Syscall{Nr: SysExecve}, true},
		{Syscall{Nr: SysExecveat}, true},
		{Syscall{Nr: SysOpenat}, false},
	} {
		if got := tc.s.Spawns(); got != tc.want {
			t.Errorf("Syscall{Nr: %d, Flags: %#x}.Spawns() = %v, want %v", tc.s.Nr, tc.s.Flags, got, tc.want)
		}
	}
}
