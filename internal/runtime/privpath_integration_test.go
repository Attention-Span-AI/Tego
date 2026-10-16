// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Capability numbers these tests grant (linux/capability.h).
const (
	capNetBindService = 10
	capSysAdmin       = 21
	capPerfmon        = 38
	capBPF            = 39
)

// fileCapabilityCopy copies bin into a fresh tmpfs mounted without nosuid (the guest's /tmp and a runner's may be
// nosuid, and the kernel ignores file capabilities there) and gives the copy security.capability for
// cap_bpf,cap_perfmon,cap_sys_admin+ep, written with Setxattr since a guest has no setcap: the withdrawn
// "file capability instead of setuid" install (ADR 0042 (3)). The directory is root's 0755, the copy root's 0755.
func fileCapabilityCopy(t *testing.T, bin string) string {
	t.Helper()
	dir := t.TempDir()
	if err := unix.Mount("tmpfs", dir, "tmpfs", unix.MS_NODEV, "mode=0755"); err != nil {
		t.Fatalf("mount a tmpfs without nosuid at %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = unix.Unmount(dir, unix.MNT_DETACH) })
	agentReaches(t, filepath.Join(dir, "x"))
	copyPath := filepath.Join(dir, "tego")
	src, err := os.Open(bin)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.OpenFile(copyPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
	// struct vfs_cap_data, VFS_CAP_REVISION_2 with VFS_CAP_FLAGS_EFFECTIVE: magic_etc, then permitted and
	// inheritable for capabilities 0-31 and 32-63, little-endian.
	low, high := uint32(1)<<capSysAdmin, uint32(1)<<(capPerfmon-32)|uint32(1)<<(capBPF-32)
	xattr := binary.LittleEndian.AppendUint32(nil, 0x02000000|0x000001)
	xattr = binary.LittleEndian.AppendUint32(xattr, low)
	xattr = binary.LittleEndian.AppendUint32(xattr, 0)
	xattr = binary.LittleEndian.AppendUint32(xattr, high)
	xattr = binary.LittleEndian.AppendUint32(xattr, 0)
	if err := unix.Setxattr(copyPath, "security.capability", xattr, 0); err != nil {
		t.Fatalf("set security.capability on %s: %v", copyPath, err)
	}
	return copyPath
}

// listNames lists dir, or nothing when it does not exist.
func listNames(dir string) []string {
	entries, _ := os.ReadDir(dir)
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// asUser runs cmd as the invoking user sudo names, with no supplementary group and the given ambient capabilities,
// in leaf (a cgroup delegated to that user) when leaf >= 0.
func asUser(cmd *exec.Cmd, uid, gid, leaf int, ambient ...uintptr) *exec.Cmd {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential:  &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}},
		AmbientCaps: ambient,
	}
	if leaf >= 0 {
		cmd.SysProcAttr.UseCgroupFD, cmd.SysProcAttr.CgroupFD = true, leaf
	}
	return cmd
}

// TestFileCapabilityCopyIsRefused is ADR 0042 (3)(a): a copy of tego holding cap_bpf, cap_perfmon and cap_sys_admin
// as file capabilities, run by an unprivileged user, is refused with exit 125 and [privileged-path-unsupported] for
// every command but version, before it creates anything: no run directory, no cgroup under tego.slice, no entry in
// /run/tego, no change under /sys/fs/bpf/tego. Before the change the copy ran, with the three capabilities, at
// tier landlock (the root gates refused it tier cgroup).
func TestFileCapabilityCopyIsRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: setting security.capability and mounting a tmpfs need it")
	}
	uid, gid, ok := agentUID(t)
	if !ok {
		t.Skip("needs SUDO_UID naming the invoking user, as `sudo go test` and test/vm/root-suites.sh give")
	}
	copyPath := fileCapabilityCopy(t, tegoBinary(t))
	c := newPrivpathCase(t, uid, gid)
	contract := filepath.Join(c.dir, "agent.yaml")
	state := map[string][]string{}
	for _, d := range []string{hoststate.Path, "/sys/fs/cgroup/tego.slice", "/sys/fs/bpf/tego"} {
		state[d] = listNames(d)
	}

	code, out := c.exec(t, asUser(exec.Command(copyPath, "version"), uid, gid, -1))
	if code != 0 {
		t.Errorf("the copy's version: exit %d, want 0:\n%s", code, out)
	}
	for _, args := range [][]string{
		{"run", "--tier", "cgroup", contract, "--", "/bin/sh", "-c", "touch out/ran"},
		{"run", contract, "--", "/bin/sh", "-c", "touch out/ran"},
		{"doctor"},
		{"compile", contract},
		{"status"},
		{"__reap"},
	} {
		code, out := c.exec(t, asUser(exec.Command(copyPath, args...), uid, gid, -1))
		if code != identity.ExitLauncher || !strings.Contains(out, "["+identity.CodePrivilegedPathUnsupported+"]") ||
			!strings.Contains(out, "AT_SECURE") {
			t.Errorf("the copy's %v: exit %d, want 125 [%s] naming AT_SECURE:\n%s", args, code,
				identity.CodePrivilegedPathUnsupported, out)
		}
	}
	if c.ran() {
		t.Error("an agent of the capability copy ran")
	}
	if dirs := runDirs(t, c.root); len(dirs) != 0 {
		t.Errorf("the copy left run directories %v", dirs)
	}
	for d, before := range state {
		if after := listNames(d); !slices.Equal(before, after) {
			t.Errorf("the copy changed %s: %v, was %v", d, after, before)
		}
	}
}

// TestAmbientIncidentalCapabilityRunsLandlock is (3)(a)'s other half. A launcher that inherited only an incidental
// ambient set (a unit's AmbientCapabilities=CAP_NET_BIND_SERVICE) has every set cleared on every thread, says so
// once, and runs at tier landlock as before: neither the agent nor any thread of the launcher, its parent, holds a
// capability. The same with cap_sys_admin ambient is refused (before the change it ran).
func TestAmbientIncidentalCapabilityRunsLandlock(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: handing a user an ambient capability needs it")
	}
	uid, gid, ok := agentUID(t)
	if !ok {
		t.Skip("needs SUDO_UID naming the invoking user, as `sudo go test` and test/vm/root-suites.sh give")
	}
	bin := tegoBinary(t)
	agentReaches(t, bin)
	leaf := userLeaf(t, uid, gid)
	c := newPrivpathCase(t, uid, gid)
	contract := filepath.Join(c.dir, "agent.yaml")
	report := `grep -H '^Cap' /proc/self/status /proc/$PPID/task/*/status > out/caps; touch out/ran`

	code, out := c.exec(t, asUser(exec.Command(bin, "run", contract, "--", "/bin/sh", "-c", report), uid, gid, leaf, capNetBindService))
	if code != 0 || !c.ran() {
		t.Fatalf("a run with cap_net_bind_service ambient: exit %d, ran %v, want 0:\n%s", code, c.ran(), out)
	}
	if !strings.Contains(out, "tego run: note: cleared the inherited capabilities cap_net_bind_service") {
		t.Errorf("no note naming the cleared set:\n%s", out)
	}
	caps, err := os.ReadFile(filepath.Join(c.out, "caps"))
	if err != nil {
		t.Fatal(err)
	}
	launcherLines := 0
	for _, line := range strings.Split(strings.TrimSpace(string(caps)), "\n") {
		file, field, _ := strings.Cut(line, ":")
		name, value, _ := strings.Cut(field, ":")
		if name == "CapBnd" {
			continue
		}
		if strings.Trim(strings.TrimSpace(value), "0") != "" {
			t.Errorf("%s holds %s %s", file, name, strings.TrimSpace(value))
		}
		if file != "/proc/self/status" {
			launcherLines++
		}
	}
	if launcherLines == 0 {
		t.Errorf("the agent could not read its launcher's threads:\n%s", caps)
	}

	code, out = c.exec(t, asUser(exec.Command(bin, "run", contract, "--", "/bin/sh", "-c", "true"), uid, gid, leaf, capSysAdmin))
	if code != identity.ExitLauncher || !strings.Contains(out, "["+identity.CodePrivilegedPathUnsupported+"]") ||
		!strings.Contains(out, "cap_sys_admin") {
		t.Errorf("a run with cap_sys_admin ambient: exit %d, want 125 [%s] naming cap_sys_admin:\n%s", code,
			identity.CodePrivilegedPathUnsupported, out)
	}
}
