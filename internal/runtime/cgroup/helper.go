// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// HelperScope is the cgroup tego's detached helpers run in, beside the agents' slices under tego.slice at
// the cgroup2 mount root: the build's linger timer (enforce/cgroup's LingerCommand), its ring trimmer
// (RingTrimCommand), a library's probe removal (capture/uprobe's DetachCommand) and a run's reaper. Its name cannot be an agent's slice (tego-<agent>.slice).
//
// A helper outlives the launcher that starts it, and must: it is what removes the probes attached host-wide
// on a libssl and the build's pinned programs once nothing uses them. Left in the launcher's cgroup it went
// with that cgroup: stopping the systemd unit, the CI job or the `systemd-run --scope` the launcher ran in
// killed it, and the probes stayed attached to every process on the host until the next gc. In a cgroup of its
// own under tego.slice, which no unit owns, it survives them.
const HelperScope = "helpers.scope"

// HelperEnvUnplaced is set in a helper's environment when the launcher could not start it in HelperScope, to
// say why: root sees it in /proc/<pid>/environ beside the cgroup the helper did land in.
const HelperEnvUnplaced = "TEGO_HELPER_UNPLACED"

// StartHelper starts the command build returns, without waiting for it (reapHelper), in HelperScope when this process can
// make and enter it (root of the initial user namespace, config.InitNSRoot, with the cgroup2 mount at
// identity.SystemCgroupRoot), and in this process's own cgroup otherwise, as before. why is "" when the helper is in HelperScope and names the reason when it is not;
// build is called once per attempt, with the environment entries to add, since an exec.Cmd is not started twice.
func StartHelper(build func(extraEnv []string) *proc.Cmd) (why string, err error) {
	data, _ := os.ReadFile(procSelfCgroup)
	return startHelperIn(identity.SystemCgroupRoot, config.InitNSRoot(), data, os.Getpid(), build)
}

// StartHelperExec is StartHelper for the plain helper: exe with args, from /, with only a PATH (and the reason it
// is not in HelperScope, if it is not) in its environment, its streams on /dev/null, in a session of its own. The
// build's linger timer, its ring trimmer and a library's probe removal all start this way.
func StartHelperExec(exe string, args ...string) (why string, err error) {
	return StartHelper(func(extra []string) *proc.Cmd {
		cmd := proc.Command(exe, args...)
		cmd.Dir = "/"
		cmd.Env = append([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}, extra...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		return cmd
	})
}

// startHelperIn is StartHelper under an explicit mount, /proc/self/cgroup content and pid, for a caller that is
// root or not.
func startHelperIn(mount string, root bool, procCgroup []byte, pid int, build func(extraEnv []string) *proc.Cmd) (string, error) {
	why := ""
	if !root {
		why = "not root: this launcher may make no cgroup outside its own subtree"
	} else if fd, dir, err := openHelperScope(mount, procCgroup, pid); err != nil {
		why = err.Error()
	} else {
		cmd := build(nil)
		attr := syscall.SysProcAttr{}
		if cmd.SysProcAttr != nil {
			attr = *cmd.SysProcAttr
		}
		cmd.SysProcAttr = &attr
		err := sys.CloneIntoCgroup(fd, &attr, func() error {
			_, err := proc.Start(cmd)
			return err
		})
		_ = fd.Close()
		if err == nil {
			reapHelper(cmd)
			return "", nil
		}
		why = fmt.Sprintf("clone3 into %s: %v", dir, err)
	}
	cmd := build([]string{HelperEnvUnplaced + "=" + why})
	if _, err := proc.Start(cmd); err != nil {
		return why, err
	}
	reapHelper(cmd)
	return why, nil
}

// reapHelper waits for a started helper in a goroutine of its own, so the caller does not wait and the helper, once
// it exits, leaves no zombie child of the caller: a launcher starts another build's linger timer from Prepare, at
// the start of a run that can last hours (ADR 0022, note 2026-10-17), and a helper released instead stayed a zombie
// of `tego run` until the run ended. A caller that exits first leaves the helper to init, as before.
func reapHelper(cmd *proc.Cmd) {
	go func() { _ = cmd.Wait() }()
}

// openHelperScope makes <mount>/tego.slice/helpers.scope when it does not exist and opens it for clone3. A
// mount that is not cgroup2 is refused: on any other filesystem the directory would be no cgroup. So is a
// mount that does not agree with procCgroup (case 39, requireMountAgreement, asked as Detect asks it for root):
// root in a cgroupns-private container handed the host's /sys/fs/cgroup would otherwise make tego.slice in the
// host's tree. Both are asked before any mkdir.
func openHelperScope(mount string, procCgroup []byte, pid int) (*sys.FD, string, error) {
	if err := checkCgroup2(mount); err != nil {
		return nil, "", err
	}
	if err := requireMountAgreement(mount, procCgroup, pid); err != nil {
		return nil, "", err
	}
	top := filepath.Join(mount, identity.TopSlice)
	dir := filepath.Join(top, HelperScope)
	for _, d := range []string{top, dir} {
		if err := unix.Mkdir(d, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, "", fmt.Errorf("mkdir(%s): %w", d, err)
		}
	}
	fd, err := sys.Own(unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		return nil, "", fmt.Errorf("open(%s): %w", dir, err)
	}
	return fd, dir, nil
}
