// SPDX-License-Identifier: Apache-2.0

//go:build integration && linux && amd64

package claudecode

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/reason"
)

// buildReleaseTego builds cmd/tego as the Makefile's release does (static, tegobpf), so with the set of packages, and
// of init functions, the shipped hook runs; and with tegotesthooks, which only lets a test move tego's own state
// (its chain anchor, its own log) out of the invoking user's ~/.tego, as every test-built tego must (isocheck GO-3).
func buildReleaseTego(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "tego")
	cmd := exec.Command("go", "build", "-buildmode=exe", "-tags", "tegobpf tegotesthooks", "-trimpath", "-o", bin,
		"github.com/attention-span-ai/tego/cmd/tego")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, out)
	}
	return bin
}

// TestHookMakesOnlyItsDocumentedSyscalls is the syscall half of acceptance (7), over every system call of the whole
// tego process from its exec to its exit, those of every init function linked into cmd/tego included: the hook
// names no path but its own process's (the /proc/self entries of hookProcSelf), the Go runtime's own reads (the
// transparent-huge-page size and its cgroup's CPU limit), the reason file and hook-state, and it makes no bpf(2)
// call, opens no socket, connects nowhere and starts no process. The trace follows any child the hook started, so
// a helper's calls count as the hook's. A run at tier cgroup or bpflsm answers bpf(2) with EPERM, so one there would
// be a refusal on
// every tool call (ADR 0063 (7)); tier landlock's run (TestHookUnderTegoRunIsRefusedNothing) could not see it.
func TestHookMakesOnlyItsDocumentedSyscalls(t *testing.T) {
	bin := buildReleaseTego(t)
	f := newFixture(t)
	f.refusals(t, 2)
	nohome := filepath.Join(t.TempDir(), "nohome")
	if err := os.Mkdir(nohome, 0); err != nil {
		t.Fatal(err)
	}
	for _, event := range []string{"session-start", "post-tool-use-bash", "stop"} {
		t.Run(event, func(t *testing.T) {
			dir := t.TempDir()
			stdin, err := os.Open(filepath.Join("testdata", "payloads", event+".json"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stdin.Close() }()
			stdout, err := os.Create(filepath.Join(dir, "out"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stdout.Close() }()
			stderr, err := os.Create(filepath.Join(dir, "err"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stderr.Close() }()
			cmd := exec.Command(bin, Verb, Harness)
			// A small environment, so the trace is the hook's own; the test-hook variables keep tego's own state in
			// the test's directory should the hook ever reach it.
			cmd.Env = []string{"HOME=" + nohome, envReason + "=" + f.reasonFile, envRuntimeDir + "=" + f.xdg,
				"TEGO_TEST_CHAIN_ANCHOR=" + filepath.Join(dir, "chain.log"), "TEGO_TEST_OWN_LOG_HOME=" + dir}
			cmd.Dir = "/"
			cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
			calls, status := testutil.SysTraceCommand(t, cmd)
			out, _ := os.ReadFile(stdout.Name())
			errOut, _ := os.ReadFile(stderr.Name())
			if !status.Exited() || status.ExitStatus() != 0 || len(errOut) != 0 || (event != "stop" && len(out) == 0) {
				t.Fatalf("hook: status %#x, stdout %q, stderr %q; want exit 0, a note and no warning", int(status), out, errOut)
			}
			for _, c := range calls {
				switch {
				case c.Nr == testutil.SysBPF, c.Nr == testutil.SysSocket, c.Nr == testutil.SysConnect:
					t.Errorf("the hook made %s(%#x, ...)", c.Name, c.Args[0])
				case c.Spawns():
					// The trace follows children, so a child's own calls are judged below too; starting one at all
					// is outside the set (exec form only, no other tego subcommand: a helper would need grants).
					t.Errorf("the hook started a process: %s", c)
				}
				for _, p := range c.Paths {
					if !hookMayName(p, bin, f.dir) {
						t.Errorf("the hook named %s: %s", p, c)
					}
				}
			}
		})
	}
}

// hookProcSelf is every /proc/self entry the hook's process may name: its executable's link (os.Executable), its
// user namespace's uid_map (cli.GuardPrivilege, which runs before every verb), and what the Go runtime reads at
// start (its cgroup and the mounts that place it, for GOMAXPROCS; auxv when the stack does not carry it). Not the
// directory's links into the file system (root, cwd, a descriptor's path below fd/N), which reach any file.
var hookProcSelf = map[string]bool{
	"/proc/self": true, "/proc/self/exe": true, "/proc/self/uid_map": true, "/proc/self/cgroup": true,
	"/proc/self/mountinfo": true, "/proc/self/auxv": true,
}

// hookCgroupCPU is the base name of every cgroup file the Go runtime reads for GOMAXPROCS: cgroup v2's cpu.max,
// and on a cgroup v1 cpu controller cpu.cfs_quota_us and cpu.cfs_period_us
// (internal/runtime/cgroup/cgroup_linux.go).
var hookCgroupCPU = map[string]bool{"cpu.max": true, "cpu.cfs_quota_us": true, "cpu.cfs_period_us": true}

// hookMayName is the documented set of paths the hook's process names (ADR 0063 (7), REASON-CHANNEL §3). A path
// with a "." or ".." element, or a doubled slash, is none of them: the prefixes below would otherwise admit a way
// out of the directory they name.
func hookMayName(p, bin, runDir string) bool {
	if filepath.Clean(p) != p {
		return false
	}
	state := filepath.Join(runDir, StateDirName)
	switch {
	case p == bin, hookProcSelf[p]:
		return true
	case strings.HasPrefix(p, "/proc/self/fd/") && !strings.Contains(strings.TrimPrefix(p, "/proc/self/fd/"), "/"):
		return true
	case strings.HasPrefix(p, "/sys/kernel/mm/transparent_hugepage/"): // the Go runtime's huge-page size
		return true
	case strings.HasPrefix(p, "/sys/fs/cgroup/") && hookCgroupCPU[filepath.Base(p)]: // the Go runtime's GOMAXPROCS
		return true
	case p == filepath.Join(runDir, reason.FileName):
		return true
	case p == state || strings.HasPrefix(p, state+"/"):
		return true
	}
	return false
}

// TestHookMayNameIsTheDocumentedSet pins hookMayName to ADR 0063 (7): the Go runtime's CPU-limit reads on both
// cgroup versions are in it (a cgroup v1 host failed the audit of a correct hook), and the
// /proc/self links that reach the whole file system, and a way out of an admitted directory, are not (N1).
func TestHookMayNameIsTheDocumentedSet(t *testing.T) {
	const bin, run = "/opt/t/tego", "/run/user/1000/tego/run-1"
	state := filepath.Join(run, StateDirName)
	for _, tc := range []struct {
		p    string
		want bool
	}{
		{bin, true},
		{"/proc/self", true},
		{"/proc/self/exe", true},
		{"/proc/self/uid_map", true},
		{"/proc/self/cgroup", true},
		{"/proc/self/mountinfo", true},
		{"/proc/self/fd/3", true},
		{"/sys/kernel/mm/transparent_hugepage/hpage_pmd_size", true},
		{"/sys/fs/cgroup/user.slice/cpu.max", true},
		{"/sys/fs/cgroup/cpu,cpuacct/user.slice/cpu.cfs_quota_us", true},
		{"/sys/fs/cgroup/cpu,cpuacct/user.slice/cpu.cfs_period_us", true},
		{filepath.Join(run, reason.FileName), true},
		{state, true},
		{filepath.Join(state, "state.json"), true},

		{"/proc/self/root/etc/hostname", false},
		{"/proc/self/cwd/x", false},
		{"/proc/self/fd/3/x", false},
		{"/proc/self/environ", false},
		{"/proc/self/../1/environ", false},
		{"/sys/fs/cgroup/user.slice/cpu.weight", false},
		{"/sys/fs/cgroup/../../etc/cpu.max", false},
		{state + "/../../../etc/hostname", false},
		{state + "x", false},
		{"/etc/hostname", false},
		{filepath.Join(run, "out"), false},
	} {
		if got := hookMayName(tc.p, bin, run); got != tc.want {
			t.Errorf("hookMayName(%q) = %v, want %v", tc.p, got, tc.want)
		}
	}
}
