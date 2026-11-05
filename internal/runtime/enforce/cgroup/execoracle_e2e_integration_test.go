// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// planeOracleContracts are the two contracts the oracle tests below run their agent under: one with no exec: section
// (every exec continued to the kernel) and one whose images are restricted (an exec no entry grants refused here).
func planeOracleContracts(name string) map[string]string {
	return map[string]string{
		"no exec section": `version: 0
name: ` + name + `
command: ["/bin/sh", "./agent.sh"]
fs:
  write: ["./out/", "/dev/null"]
env:
  pass: ["PATH", "HOME"]
record: summary
`,
		"restricted": `version: 0
name: ` + name + `-restricted
command: ["/bin/sh", "./agent.sh"]
fs:
  write: ["./out/", "/dev/null"]
exec:
  allow: ["/bin/sh", "/usr/bin/ls"]
env:
  pass: ["PATH", "HOME"]
record: summary
`,
	}
}

// planeExecMissing is run_end.supervisor.exec_missing of a run's events, nil when the run had no miss.
func planeExecMissing(events []map[string]any) any {
	for _, e := range events {
		if e["kind"] == "run_end" {
			if sup, ok := e["supervisor"].(map[string]any); ok {
				return sup["exec_missing"]
			}
		}
	}
	return nil
}

// TestPlaneExecProcDirOracle at tier cgroup, on procfs: /proc/<pid>/fdinfo is 0555, and on kernels with its
// directory permission hook it asks ptrace_may_access, which the sudo caller fails for root's pid 1.
// RHEL 9 allows that listing, so there the fixture uses pid 1's private fd directory instead.
// The supervisor's walk, as root, took fdinfo's bits as sure and looked the name up
// itself: a descriptor pid 1 holds open was decided (126), one it does not hold was a miss (127, no line), so the agent
// learned which descriptors another user's process has open. Another process's procfs directory is now an unsure step,
// so both are EACCES (126), the kernel's own answer, in every plane mode and on the fanotify listener, under a
// contract with no exec: section and under a restricted one.
func TestPlaneExecProcDirOracle(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	dir := "/proc/1/fdinfo"
	probe := exec.Command("ls", dir)
	probe.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	if err := probe.Run(); err == nil {
		dir = "/proc/1/fd"
		t.Log("kernel permits the caller to list /proc/1/fdinfo; exercise the inaccessible /proc/1/fd directory (DAC coverage)")
	} else {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("probe caller's procfs visibility: %v", err)
		}
	}
	agent := fmt.Sprintf("ls %[1]s/ >/dev/null 2>&1; echo \"RESULT ls $?\"\n"+
		"%[1]s/0; echo \"RESULT present $?\"\n"+
		"%[1]s/tego-no-such-fd; echo \"RESULT absent $?\"\n"+
		"%[1]s/0/x; echo \"RESULT presentx $?\"\n", dir)
	for _, mode := range append(modes, PlaneFanotify) {
		for name, c := range planeOracleContracts("plane-procdir") {
			t.Run(mode+"/"+name, func(t *testing.T) {
				p := newPlaneProject(t, uid, gid, map[string]string{"agent.sh": agent, "agent.yaml": c}, []string{"out"}, nil)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				var out bytes.Buffer
				err := p.runAt(ctx, bin, "cgroup", "agent.yaml", mode, &out).Run()
				t.Logf("tego run (%s): %v\n%s", mode, err, out.String())
				res := agentResults(t, out.String())
				if res["ls"] == "0" {
					t.Fatalf("the agent can list %s: the case proves nothing", dir)
				}
				for _, k := range []string{"present", "absent", "presentx"} {
					if res[k] != "126" {
						t.Errorf("%s: exit %q in a procfs directory of a root process the agent may not look into: want 126 (EACCES), as for every name there", k, res[k])
					}
				}
				if m := planeExecMissing(runEvents(t, p.ledger)); m != nil {
					t.Errorf("run_end.supervisor.exec_missing %v: an exec in a directory the task may not look into is no miss", m)
				}
			})
		}
	}
}

// TestPlaneExecAutomountIsNoMiss at tier cgroup: only autofs was taken for an automount point, so
// an exec under any other idle one (here a debugfs's tracing stub, the class of NFS crossmnt and referral submounts,
// CIFS DFS links and FUSE submounts) failed the supervisor's walk, which mounts nothing, and was answered as a miss:
// ENOENT, exit 127, no line, though the kernel's own walk mounts tracefs there and finds the file. It is now decided
// as before R16b (0). Under a contract with no exec: section it is continued and the kernel answers (ELOOP on
// 6.1, EACCES on newer kernels). Under a restricted one it is recorded, and answered as
// that run answers any exec whose walk failed: in a plane mode it is handed to the kernel, whose plane decides the floor
// on the file the kernel loads, and the kernel's own walk refuses it as in the native control; on the fanotify listener
// the supervisor refuses it with its walk's ENOENT (127). The README exec is the agent's first, made while the stub is
// idle, in a fresh debugfs per run.
func TestPlaneExecAutomountIsNoMiss(t *testing.T) {
	const controlEnv = "TEGO_TEST_AUTOMOUNT_CONTROL"
	if path := os.Getenv(controlEnv); path != "" {
		// A native exec, with no supervisor or run membership, but in a Landlock domain as the agent is. On 6.1
		// tracefs' automount swallows a failed submount, and the VFS eventually returns ELOOP. An
		// unconstrained control instead mounts it and reaches EACCES, so it is not the same kernel case.
		runtime.LockOSThread()
		fd, err := sys.LandlockCreateRuleset(&sys.LandlockRulesetAttr{Handled_access_fs: unix.LANDLOCK_ACCESS_FS_WRITE_FILE}, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd) //nolint:errcheck // ruleset descriptor, closed on exec too
		if err := sys.SetNoNewPrivs(); err != nil {
			t.Fatal(err)
		}
		if err := sys.LandlockRestrictSelf(fd, 0); err != nil {
			t.Fatal(err)
		}
		if err := unix.Exec("/bin/sh", []string{"sh", "-c", path}, os.Environ()); err != nil {
			t.Fatal(err)
		}
		return
	}
	bin, uid, gid, modes := planePreconditions(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range append(modes, PlaneFanotify) {
		for name, c := range planeOracleContracts("plane-automount") {
			t.Run(mode+"/"+name, func(t *testing.T) {
				// A separate idle stub: probing the tested one could mount it and erase the condition.
				native := exec.Command(self, "-test.run=^TestPlaneExecAutomountIsNoMiss$")
				native.Env = append(os.Environ(), controlEnv+"="+automountReadme(t))
				native.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
				controlOut, controlErr := native.CombinedOutput()
				if native.ProcessState == nil {
					t.Fatalf("native automount exec: %v: %s", controlErr, controlOut)
				}
				want := strconv.Itoa(native.ProcessState.ExitCode())
				if want != "126" && want != "127" {
					t.Fatalf("native automount exec: exit %s: %v: %s", want, controlErr, controlOut)
				}
				t.Logf("native automount exec as uid %d: exit %s: %s", uid, want, controlOut)
				readme := automountReadme(t)
				agent := readme + "; echo \"RESULT readme $?\"\n"
				p := newPlaneProject(t, uid, gid, map[string]string{"agent.sh": agent, "agent.yaml": c}, []string{"out"}, nil)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				var out bytes.Buffer
				err := p.runAt(ctx, bin, "cgroup", "agent.yaml", mode, &out).Run()
				t.Logf("tego run (%s): %v\n%s", mode, err, out.String())
				res := agentResults(t, out.String())
				events := runEvents(t, p.ledger)
				lines := 0
				for _, e := range events {
					if e["kind"] == "exec" && e["path"] == readme {
						lines++
					}
				}
				switch {
				case name == "no exec section":
					if res["readme"] != want {
						t.Errorf("%s: exit %q, want native exit %s: continued to the kernel's own walk", readme, res["readme"], want)
					}
				case mode == PlaneFanotify:
					if res["readme"] != "127" || lines == 0 {
						t.Errorf("%s: exit %q with %d exec lines, want 127 (refused with its ENOENT) and the refusal recorded", readme, res["readme"], lines)
					}
				default:
					if res["readme"] != want || lines == 0 {
						t.Errorf("%s: exit %q with %d exec lines, want native exit %s and the exec recorded", readme, res["readme"], lines, want)
					}
				}
				if m := planeExecMissing(events); m != nil {
					t.Errorf("run_end.supervisor.exec_missing %v: an exec under an automount point is no miss", m)
				}
			})
		}
	}
}

func automountReadme(t *testing.T) string {
	t.Helper()
	base, err := os.MkdirTemp("", "tego-automount-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	mnt := filepath.Join(base, "debug")
	if err := os.Mkdir(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("none", mnt, "debugfs", 0, "mode=0755"); err != nil {
		t.Fatalf("mount a debugfs at %s: %v", mnt, err)
	}
	t.Cleanup(func() { _ = unix.Unmount(mnt, unix.MNT_DETACH) })
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, filepath.Join(mnt, "tracing"), unix.AT_NO_AUTOMOUNT|unix.AT_SYMLINK_NOFOLLOW, 0, &stx); err != nil ||
		stx.Attributes&unix.STATX_ATTR_AUTOMOUNT == 0 {
		t.Fatalf("%s/tracing is no automount stub (%v, attributes %#x)", mnt, err, stx.Attributes)
	}
	return filepath.Join(mnt, "tracing", "README")
}
