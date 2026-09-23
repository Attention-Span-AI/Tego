// SPDX-License-Identifier: Apache-2.0

//go:build integration

package launch

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

const (
	// blockedClone3Env puts this test binary in the role of a launcher running inside a sandbox whose
	// seccomp profile refuses clone3. It has to be a re-exec: a seccomp filter cannot be removed once
	// installed, so doing this in-process would take every later test in the package down with it.
	blockedClone3Env = "TEGO_LAUNCH_CLONE3_BLOCKED"
	// blockedClone3Marker prefixes the child's single result line so go test's own output can never be
	// mistaken for it.
	blockedClone3Marker = "tego-clone3-blocked: "
)

// TestStartUnderOuterSeccompProfileNamesTheFilter is moby#42680 (berrange, 2021-07-27) run against Start:
// a container runtime's default profile answers an unlisted clone3 with EPERM on a perfectly modern kernel,
// which is how curl and docker build broke on Fedora 35. Case 20 only ever framed a failing clone3 as an
// old kernel, so the operator of a containerized tego was told to check a kernel version that is fine.
// The assertion is therefore about the diagnosis, not the failure: the error must say a filter is in force
// (proved by this process's own /proc/self/status Seccomp: 2) and must not blame the kernel.
//
// Behind the integration tag because it installs a process-wide seccomp filter. It needs no root: seccomp
// with no_new_privs is unprivileged.
//
// Also pins runtime-launch.md E20: an outer seccomp profile is named as the cause.
func TestStartUnderOuterSeccompProfileNamesTheFilter(t *testing.T) {
	arch := auditArch(t) // both roles check this first, so the child never has to report an arch skip
	if os.Getenv(blockedClone3Env) == "1" {
		fmt.Println(blockedClone3Marker + blockedClone3Result(arch))
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), blockedClone3Env+"=1")
	out, err := cmd.CombinedOutput()
	line := markerLine(string(out))
	if line == "" {
		t.Fatalf("child wrote no %q line (exit: %v); output:\n%s", blockedClone3Marker, err, out)
	}
	if rest, ok := strings.CutPrefix(line, "skip: "); ok {
		t.Skipf("this box cannot stage a clone3-blocking profile: %s", rest)
	}
	// "Seccomp: 2" is the whole point: the launcher proved the filter rather than guessing at it.
	for _, want := range []string{"launch: clone3 failed", "operation not permitted", "Seccomp: 2", "moby#42680"} {
		if !strings.Contains(line, want) {
			t.Errorf("Start error under a clone3-blocking profile = %q, want it to contain %q", line, want)
		}
	}
	if strings.Contains(line, "kernel itself has no") {
		t.Errorf("Start error = %q: blamed kernel age on a kernel whose clone3 is merely filtered (case 20)", line)
	}
}

// blockedClone3Result is the child role: become a process whose clone3 is refused, then run Start and
// report the error verbatim. A "skip: " prefix means the reproduction could not be staged at all.
func blockedClone3Result(arch uint32) string {
	// A cgo binary cannot stage it: a thread its runtime starts after the filter is in goes through
	// pthread_create, whose clone3 gets EPERM, and glibc aborts the process before Start is reached. That
	// failed this test whenever the child needed a thread at the wrong moment. The launcher it stands in for is
	// the shipped tego, which is never built with cgo.
	if testBinaryUsesCgo {
		return "skip: this test binary is built with cgo, whose pthread_create aborts on a filtered clone3 " +
			"(glibc 2.34+); the shipped tego is CGO_ENABLED=0, and CGO_ENABLED=0 go test runs this case"
	}
	dir, err := ownCgroupDir()
	if err != nil {
		return fmt.Sprintf("skip: %v", err)
	}
	// Start only reaches clone3 when UseCgroupFD is set: CLONE_INTO_CGROUP lives in struct clone_args and
	// nowhere else (clone(2)), so a real cgroup fd is what makes this a test about clone3.
	fd, err := sys.Own(unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		return fmt.Sprintf("skip: open %s: %v", dir, err)
	}
	defer func() { _ = fd.Close() }()
	if err := sys.SetNoNewPrivs(); err != nil {
		return fmt.Sprintf("skip: no_new_privs: %v", err)
	}
	if err := blockClone3(arch, unix.EPERM); err != nil {
		return fmt.Sprintf("skip: install clone3 filter: %v", err)
	}
	if _, err := (&Launcher{}).Start(context.Background(), validSpec(), fd); err != nil {
		return err.Error()
	}
	// os/exec has no clone3 -> clone(2) fallback (syscall.forkAndExecInChild1 picks one and reports its
	// errno), so a success here can only mean the filter did not reach the forking thread.
	return "clone3 succeeded: the filter never reached the thread Start forked from"
}

// blockClone3 installs, on every thread of this process, the filter a container runtime's default profile
// effectively applies to a syscall missing from its allow list: answer __NR_clone3 with errno, let
// everything else through. Docker's profile used EPERM (moby#42680), which glibc 2.34+ treats as fatal
// rather than falling back to clone(2); runtimes later switched the default to ENOSYS.
//
// TSYNC is required, not cosmetic: Start clone3s from whichever thread startOnKeptThread locks, which is
// not the thread that installed the filter, and a plain per-thread filter would make this a coin flip.
// TSYNC is refused together with NEW_LISTENER (case 7) but is fine on its own.
func blockClone3(arch uint32, errno unix.Errno) error {
	prog, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 4, Size: 4}, // seccomp_data.arch
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: arch, SkipTrue: 1},
		bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW}, // a test prop, not a sandbox: never kill a foreign ABI
		bpf.LoadAbsolute{Off: 0, Size: 4},            // seccomp_data.nr
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(unix.SYS_CLONE3), SkipTrue: 1},
		bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW},
		bpf.RetConstant{Val: unix.SECCOMP_RET_ERRNO | uint32(errno)},
	})
	if err != nil {
		return err
	}
	filter := make([]unix.SockFilter, len(prog))
	for i, in := range prog {
		filter[i] = unix.SockFilter{Code: in.Op, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if _, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&fprog))); e != 0 {
		return e
	}
	return nil
}

// ownCgroupDir is this process's own cgroup v2 directory, read from the unified ("0::") line of
// /proc/self/cgroup. Cloning into the cgroup we are already in needs no delegation rights, so the only
// thing that can fail the clone3 in this test is the filter.
func ownCgroupDir() (string, error) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		rel, ok := strings.CutPrefix(line, "0::")
		if !ok {
			continue
		}
		return filepath.Join("/sys/fs/cgroup", strings.TrimSpace(rel)), nil
	}
	return "", fmt.Errorf("no unified (0::) line in /proc/self/cgroup: not a cgroup v2 host")
}

func markerLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(line, blockedClone3Marker); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}
