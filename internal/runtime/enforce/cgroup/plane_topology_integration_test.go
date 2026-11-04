// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

const planeTopologyEnv = "TEGO_TEST_PLANE_TOPOLOGY"

func init() {
	if os.Getenv(planeTopologyEnv) == "" {
		return
	}
	// These are already-running root processes, with no Landlock or seccomp.
	// Their private mount namespaces keep successful control cases in the guest.
	runtime.LockOSThread()
	if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		panic(err)
	}
	if err := unix.Unshare(unix.CLONE_FS); err != nil {
		panic(err)
	}
	dir, op := os.Args[1], os.Args[2]
	ns, err := unix.Open("/proc/self/ns/mnt", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		panic(err)
	}
	if err := unix.Mount("tmpfs", dir, "tmpfs", 0, ""); err != nil {
		panic(err)
	}
	if op == "pivot_root" {
		// The guest's initramfs rootfs cannot itself be pivoted away. Use a
		// tmpfs root containing a second tmpfs as the new root, before adoption.
		if err := os.Mkdir(filepath.Join(dir, "new"), 0o755); err != nil {
			panic(err)
		}
		if err := unix.Chroot(dir); err != nil {
			panic(err)
		}
		if err := unix.Chdir("/"); err != nil {
			panic(err)
		}
		dir = "/new"
		if err := unix.Mount("tmpfs", dir, "tmpfs", 0, ""); err != nil {
			panic(err)
		}
	}
	for _, name := range []string{"old", "upper", "work"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			panic(err)
		}
	}
	tree, err := unix.OpenTree(unix.AT_FDCWD, dir, unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC)
	if err != nil {
		panic(err)
	}
	fmt.Println("ready")
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		panic(err)
	}
	switch op {
	case "bind":
		err = unix.Mount(filepath.Dir(dir), dir, "", unix.MS_BIND, "")
	case "overlay":
		// The lower layer is on this helper's tmpfs, including in a new user
		// namespace; initramfs rootfs is not a supported overlay layer.
		err = unix.Mount("overlay", dir, "overlay", 0, "lowerdir="+filepath.Join(dir, "old")+
			",upperdir="+filepath.Join(dir, "upper")+",workdir="+filepath.Join(dir, "work")+",userxattr")
	case "umount":
		err = unix.Unmount(dir, unix.MNT_DETACH)
	case "remount":
		err = unix.Mount("", dir, "", unix.MS_REMOUNT|unix.MS_RDONLY, "")
	case "move_mount":
		err = unix.MoveMount(tree, "", unix.AT_FDCWD, dir, unix.MOVE_MOUNT_F_EMPTY_PATH)
	case "open_tree":
		var fd int
		fd, err = unix.OpenTree(unix.AT_FDCWD, dir, unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC)
		if err == nil {
			_ = unix.Close(fd)
		}
	case "mount_setattr":
		err = unix.MountSetattr(unix.AT_FDCWD, dir, 0, &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY})
	case "pivot_root":
		err = unix.PivotRoot(dir, filepath.Join(dir, "old"))
	case "unshare":
		err = unix.Unshare(unix.CLONE_NEWNS)
	case "setns":
		// A runtime thread created since setup may have shared this fs_struct.
		if err = unix.Unshare(unix.CLONE_FS); err == nil {
			err = unix.Setns(ns, unix.CLONE_NEWNS)
		}
	default:
		panic(op)
	}
	if err != nil && op == "overlay" && !errors.Is(err, unix.EPERM) {
		log := make([]byte, 8192)
		if n, _ := unix.Klogctl(3, log); n > 0 {
			fmt.Fprintf(os.Stderr, "overlay mount %v; kernel log: %s\n", err, log[:n])
		}
	}
	var errno syscall.Errno
	if err != nil && !errors.As(err, &errno) {
		panic(err)
	}
	fmt.Printf("errno=%d\n", errno)
	os.Exit(0)
}

// TestPlaneAdoptedProcessCannotChangeMountTopology moves a live root process
// into an armed scope, exactly the kernel seam both adoption callers use. Each
// operation must succeed outside the run and fail inside it; syscall errors
// caused by missing privileges or invalid fixtures cannot pass as enforcement.
func TestPlaneAdoptedProcessCannotChangeMountTopology(t *testing.T) {
	requireBPFCaps(t)
	mode, build := hostPlane(t)
	dir := t.TempDir()
	hash := fmt.Sprintf("t6topology%09d", os.Getpid())
	b := New(Options{Machine: machineLinger(time.Hour), BPFFS: DefaultBPFFS, StateDir: pinState(t), Hash: hash,
		Plane: PlaneSetup{Mode: mode, Build: build}})
	t.Cleanup(func() {
		if pins, err := newPinLayout(DefaultBPFFS, hash); err == nil {
			_ = pins.remove()
		}
	})
	rel, _, id := runCgroupUnderSelf(t, "topology")
	rt := &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordFull, Contract: &agent.Contract{},
		FS: []agent.FSRule{{Path: dir, Kind: agent.FSWrite}}}
	rows, err := decide.CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	b.opts.planeHeld = holdPaths(t, rows.Keyed...).held
	h, err := b.Prepare(context.Background(), rt, Run{ID: "t6-topology", CgroupID: id, CgroupPath: rel,
		CgroupMount: "/sys/fs/cgroup", PlaneRows: rows})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	if err := h.Arm(); err != nil {
		t.Fatal(err)
	}
	for _, userns := range []bool{false, true} {
		for _, op := range []string{"bind", "overlay", "umount", "remount", "move_mount", "open_tree", "mount_setattr", "pivot_root", "unshare", "setns"} {
			t.Run(fmt.Sprintf("%s/userns=%t", op, userns), func(t *testing.T) {
				for _, governed := range []bool{false, true} {
					target := filepath.Join(dir, fmt.Sprintf("%s-%t-%t", op, governed, userns))
					if err := os.Mkdir(target, 0o755); err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, os.Args[0], target, op)
					cmd.Env = append(os.Environ(), planeTopologyEnv+"=1")
					cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
					if userns {
						cmd.SysProcAttr.Cloneflags |= unix.CLONE_NEWUSER
						cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}}
						cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}}
					}
					cmd.Stderr = os.Stderr
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
					defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
					r := bufio.NewReader(out)
					if line, err := r.ReadString('\n'); err != nil || line != "ready\n" {
						t.Fatalf("helper not ready: %q, %v", line, err)
					}
					if governed {
						if err := os.WriteFile(filepath.Join("/sys/fs/cgroup", rel, "cgroup.procs"), []byte(fmt.Sprint(cmd.Process.Pid)), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					if _, err := fmt.Fprintln(in, "go"); err != nil {
						t.Fatal(err)
					}
					line, err := r.ReadString('\n')
					if !governed && op == "overlay" && err == nil && line == "errno=19\n" {
						t.Skip("this kernel has no overlayfs (the host-row guest loads VM_MODULES=overlay)")
					}
					want := "errno=0\n"
					if governed {
						want = "errno=1\n" // ns_capable translates a capability refusal to EPERM.
					}
					if err != nil || line != want {
						t.Errorf("governed=%t: %q, %v; want %q", governed, line, err, want)
					}
					if err := cmd.Wait(); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}
