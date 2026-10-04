// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestIntegrationAHelperOutlivesItsLaunchersCgroup is round 7's M4 (a) as root: a helper the launcher starts
// (the build's linger timer, a library's probe removal) is in tego.slice/helpers.scope, not the launcher's
// cgroup, so killing the launcher's cgroup, which is what stopping its systemd unit, CI job or
// `systemd-run --scope` does, leaves the helper running. Started in the launcher's cgroup, as before, it died
// with it, and the probes and programs it was to remove stayed attached host-wide.
func TestIntegrationAHelperOutlivesItsLaunchersCgroup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("placing a helper beside the agents' slices needs root")
	}
	mount := identity.SystemCgroupRoot
	if err := checkCgroup2(mount); err != nil {
		t.Skipf("no cgroup2 at %s: %v", mount, err)
	}
	own, err := os.ReadFile(procSelfCgroup)
	if err != nil {
		t.Fatal(err)
	}
	rel, ok := unifiedPath(own)
	if !ok {
		t.Skipf("no unified cgroup in %q", own)
	}
	orig := filepath.Join(mount, rel)
	// The launcher's cgroup: this process moves into a scratch cgroup, starts the helper there, and moves back,
	// so killing the scratch cgroup kills whatever of the launcher's is still in it.
	launcher := filepath.Join(mount, fmt.Sprintf("tego-helper-it-%d.scope", os.Getpid()))
	if err := os.Mkdir(launcher, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(launcher) })
	move := func(dir string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
			t.Fatalf("move this process into %s: %v", dir, err)
		}
	}
	pidFile := filepath.Join(t.TempDir(), "pid")
	move(launcher)
	why, err := StartHelper(func(extra []string) *exec.Cmd {
		cmd := exec.Command("/bin/sh", "-c", `echo $$ > "$PIDFILE"; exec sleep 300`)
		cmd.Env = append([]string{"PIDFILE=" + pidFile, "PATH=/usr/bin:/bin"}, extra...)
		return cmd
	})
	move(orig)
	if err != nil {
		t.Fatalf("StartHelper: %v", err)
	}
	if why != "" {
		t.Fatalf("the helper was not placed in %s: %s", HelperScope, why)
	}
	var pid int
	for deadline := time.Now().Add(5 * time.Second); pid == 0 && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		b, _ := os.ReadFile(pidFile)
		pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	if pid == 0 {
		t.Fatal("the helper never wrote its pid")
	}
	t.Cleanup(func() { _ = unix.Kill(pid, unix.SIGKILL) })

	if err := os.WriteFile(filepath.Join(launcher, "cgroup.kill"), []byte("1"), 0); err != nil {
		t.Fatalf("kill the launcher's cgroup: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if err := unix.Kill(pid, 0); err != nil {
		t.Fatalf("the helper died with its launcher's cgroup: %v", err)
	}
	cg, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		t.Fatal(err)
	}
	if want := "/" + identity.TopSlice + "/" + HelperScope; !strings.Contains(string(cg), want) {
		t.Errorf("the helper is in %q, want %s", strings.TrimSpace(string(cg)), want)
	}
}
