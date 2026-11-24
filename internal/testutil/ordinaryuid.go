// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"bytes"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// ordinaryUID is the uid and gid RerunAsOrdinaryUser gives the test: the conventional "nobody".
const ordinaryUID = 65534

// ordinaryRerunEnv marks the process RerunAsOrdinaryUser started, with the name of the test it was started for.
const ordinaryRerunEnv = "TEGO_TESTUTIL_ORDINARY_RERUN"

// RerunAsOrdinaryUser is the first call of a test that proves a barrier only a process of an ordinary uid meets: a
// process of the same user that holds no capability. Root passes every one of those (CAP_SYS_PTRACE reads
// /proc/<pid>/mem, attaches, and takes descriptors of an undumpable process), so a root suite, which runs the test as
// root, would find the barrier open and say the hold failed. As root it runs this test binary again as uid and gid
// 65534, with no capability and no supplementary group, for this test alone, in a temporary directory that every uid
// may write, reports the child's output when it fails, and returns true: the caller returns. The child, and a test
// that is not root, get false and go on, so the same body proves the property in both. A child that did not run the
// test to a pass (its exit, or a missing PASS line: a skipped test, a -test.run that matched nothing) fails the test.
// A subtest may call it too: it reruns that subtest alone, under its parent (the parent's own body runs as the child's uid).
func RerunAsOrdinaryUser(t *testing.T) bool {
	t.Helper()
	if os.Getenv(ordinaryRerunEnv) == t.Name() || os.Geteuid() != 0 {
		return false
	}
	tmp, err := os.MkdirTemp("", "tego-ordinary-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmp) })
	if err := os.Chmod(tmp, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	self := ExecutableForAnyUID(t)
	cmd := exec.Command(self, "-test.run="+rerunPattern(t.Name()), "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), ordinaryRerunEnv+"="+t.Name(), "TMPDIR="+tmp, "HOME="+tmp)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: ordinaryUID, Gid: ordinaryUID}}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s as uid %d: %v\n%s", t.Name(), ordinaryUID, err, out.String())
	}
	if !strings.Contains(out.String(), "--- PASS: "+t.Name()+" ") {
		t.Fatalf("%s as uid %d did not pass:\n%s", t.Name(), ordinaryUID, out.String())
	}
	return true
}

// rerunPattern is the -test.run pattern that selects the one test, or the one subtest, named name: each element of the
// name (a subtest's name follows its parent's after a slash) matches exactly. -test.run reads its elements as regular
// expressions, so a subtest called "... is exit 125 [io], and nothing is written" must be quoted, or its brackets read
// as a character class that matches no name and the child runs nothing.
func rerunPattern(name string) string {
	parts := strings.Split(name, "/")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	return "^" + strings.Join(parts, "/") + "$"
}

// PtraceAttachSucceeds reports whether PTRACE_ATTACH to pid, a child of this process, succeeds. When it does, the
// tracee is not left held: attach and detach run on one locked thread (a tracer is a thread, so a detach from another
// is refused), the stop the attach caused is waited for before it, and the group stop it left is ended with SIGCONT,
// so the tracee runs on and holds no stop that a Wait of its parent would report in place of its exit.
func PtraceAttachSucceeds(pid int) bool {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.PtraceAttach(pid); err != nil {
		return false
	}
	var ws unix.WaitStatus
	_, _ = unix.Wait4(pid, &ws, unix.WALL, nil)
	_ = unix.PtraceDetach(pid)
	// The attach's SIGSTOP is a group stop, and a detach leaves the group stopped: SIGCONT ends it.
	_ = unix.Kill(pid, unix.SIGCONT)
	return true
}
