// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The mount namespace helper (ADR 0017 space 5). A fixture with Mounts runs its tego run under this test binary
// started again with mountnsEnv naming a mountnsSpec: in a mount namespace of its own (CLONE_NEWNS, which Go's
// os/exec makes private, so nothing propagates back to the host), it makes the mounts, snapshots the project tree,
// runs tego as its child, snapshots the tree again and exits with tego's status. The run's launcher reads the
// namespace's mountinfo, so the plane keys its mounted-root rows on these mounts, and the snapshots see the tree
// the agent saw; the mounts go with the namespace when its last process exits, whatever the runner did.

// mountnsEnv names the spec file of a helper run; TestMain hands such a process to mountnsMain.
const mountnsEnv = "TEGO_CONFORMANCE_MOUNTNS"

// FSRequireEnv lists the filesystems a run must be able to mount, space-separated ("overlay btrfs"): root-suites.sh
// names those its guests load (VM_MODULES). A fixture whose mount the kernel has no filesystem for fails the run when
// the list names it, and is logged MOUNTS-ABSENT and not run when it does not.
const FSRequireEnv = "TEGO_CONFORMANCE_FS_REQUIRE"

// mountnsSetupFailed is the helper's exit status when a mount could not be made; its stderr says which, after
// mountnsSetupTag. mountnsNoFS is the status when the kernel has no such filesystem (ENODEV from mount(2)).
const (
	mountnsSetupFailed = 120
	mountnsNoFS        = 121
	mountnsSetupTag    = "MOUNTNS: "
)

// mountnsSpec is what a helper run does.
type mountnsSpec struct {
	Project string
	// Scratch is a directory outside the project for the btrfs image file.
	Scratch  string
	UID, GID int
	Mounts   []Mount
	// Before and After are where the helper writes the project tree's snapshots (Tree as JSON).
	Before, After string
	// Argv, Env and Dir are the tego run's.
	Argv []string
	Env  []string
	Dir  string
}

// mountnsCommand is the helper's command for spec, written to path: this test binary in a new mount namespace.
func mountnsCommand(path string, spec mountnsSpec) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, err
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), mountnsEnv+"="+path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS, Pdeathsig: syscall.SIGKILL}
	return cmd, nil
}

// mountnsMain is the helper process: it never returns.
func mountnsMain(specPath string) {
	fail := func(code int, format string, a ...any) {
		fmt.Fprintf(os.Stderr, mountnsSetupTag+format+"\n", a...)
		os.Exit(code)
	}
	data, err := os.ReadFile(specPath)
	if err != nil {
		fail(mountnsSetupFailed, "read the spec: %v", err)
	}
	var spec mountnsSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		fail(mountnsSetupFailed, "decode the spec: %v", err)
	}
	for i, m := range spec.Mounts {
		if err := mountOne(&spec, i, m); err != nil {
			code := mountnsSetupFailed
			if errors.Is(err, unix.ENODEV) {
				code = mountnsNoFS // the message starts with the kind, which the runner reads
			}
			fail(code, "%s mount at %s: %v", m.Kind, m.At, err)
		}
	}
	snap := func(path string) {
		t, err := Snapshot(spec.Project)
		if err == nil {
			var out []byte
			if out, err = json.Marshal(t); err == nil {
				err = os.WriteFile(path, out, 0o600)
			}
		}
		if err != nil {
			fail(mountnsSetupFailed, "snapshot: %v", err)
		}
	}
	snap(spec.Before)
	runtime.LockOSThread() // Pdeathsig follows the thread that started the child: this one, to the helper's exit
	cmd := exec.Command(spec.Argv[0], spec.Argv[1:]...)
	cmd.Env, cmd.Dir = spec.Env, spec.Dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	runErr := cmd.Run()
	snap(spec.After)
	var ee *exec.ExitError
	switch {
	case runErr == nil:
		os.Exit(0)
	case errors.As(runErr, &ee) && ee.ExitCode() >= 0:
		os.Exit(ee.ExitCode())
	}
	fail(mountnsSetupFailed, "run: %v", runErr)
}

// mountOne makes the spec's i-th mount and its files.
func mountOne(spec *mountnsSpec, i int, m Mount) error {
	at := filepath.Join(spec.Project, m.At)
	p := func(rel string) string { return filepath.Join(spec.Project, rel) }
	const flags = unix.MS_NOSUID | unix.MS_NODEV
	switch m.Kind {
	case MountBind:
		if err := unix.Mount(p(m.From), at, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return err
		}
	case MountTmpfs:
		opts := fmt.Sprintf("mode=0755,uid=%d,gid=%d,size=4m", spec.UID, spec.GID)
		if err := unix.Mount("tmpfs", at, "tmpfs", flags, opts); err != nil {
			return err
		}
	case MountOverlay:
		opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", p(m.Lower), p(m.Upper), p(m.Work))
		if err := unix.Mount("overlay", at, "overlay", flags, opts); err != nil {
			return err
		}
	case MountBtrfs:
		if err := mountBtrfs(filepath.Join(spec.Scratch, "btrfs-"+strconv.Itoa(i)+".img"), at, m.Subvolumes); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown kind")
	}
	if m.Kind != MountBind && m.Kind != MountOverlay {
		if err := os.Chown(at, spec.UID, spec.GID); err != nil {
			return err
		}
	}
	for rel, content := range m.Files {
		f := filepath.Join(at, rel)
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
			return err
		}
		for q := f; q != at; q = filepath.Dir(q) {
			if err := os.Lchown(q, spec.UID, spec.GID); err != nil {
				return err
			}
		}
	}
	return nil
}

// btrfsImage is an empty 16 MiB btrfs, gzipped (internal/runtime/enforce/cgroup's fixture, which says how it was
// made), so a btrfs mount needs no btrfs-progs: only root, a loop device and the kernel's btrfs, which
// root-suites.sh's guests load (VM_MODULES).
//
//go:embed testdata/btrfs-mixed-16m.img.gz
var btrfsImage []byte

// The btrfs ioctls: _IOW(BTRFS_IOCTL_MAGIC, n, struct btrfs_ioctl_vol_args), whose size is 4096 (linux/btrfs.h).
const (
	btrfsIocForgetDev    = 0x50009405
	btrfsIocSubvolCreate = 0x5000940e
)

// btrfsVolArgs is struct btrfs_ioctl_vol_args.
type btrfsVolArgs struct {
	FD   int64
	Name [4088]byte
}

// mountBtrfs writes the empty image to img, loop-mounts it at at and makes the subvolumes at its root.
func mountBtrfs(img, at string, subvolumes []string) error {
	zr, err := gzip.NewReader(bytes.NewReader(btrfsImage))
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		return err
	}
	if err := os.WriteFile(img, raw, 0o600); err != nil {
		return err
	}
	// Every mount of this image has one fsid. A kernel that keeps an unmounted single-device btrfs registered refuses
	// the next copy on another loop device when the last one's generation is higher; forgetting the unmounted devices
	// first (an empty name) leaves only this copy. Without the ioctl (before 5.16) there is nothing to forget.
	if ctl, err := unix.Open("/dev/btrfs-control", unix.O_RDWR|unix.O_CLOEXEC, 0); err == nil {
		var args btrfsVolArgs
		_, _, _ = unix.Syscall(unix.SYS_IOCTL, uintptr(ctl), btrfsIocForgetDev, uintptr(unsafe.Pointer(&args)))
		_ = unix.Close(ctl)
	}
	if out, err := exec.Command("mount", "-t", "btrfs", "-o", "loop,nosuid,nodev", img, at).CombinedOutput(); err != nil {
		var fs unix.Statfs_t
		if bytes.Contains(out, []byte("unknown filesystem type")) || unix.Statfs("/sys/fs/btrfs", &fs) != nil {
			return fmt.Errorf("%w: %s", unix.ENODEV, bytes.TrimSpace(out))
		}
		return fmt.Errorf("mount: %v: %s", err, bytes.TrimSpace(out))
	}
	parent, err := unix.Open(at, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(parent) //nolint:errcheck // a directory fd
	for _, name := range subvolumes {
		var args btrfsVolArgs
		copy(args.Name[:], name)
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(parent), btrfsIocSubvolCreate, uintptr(unsafe.Pointer(&args))); errno != 0 {
			return fmt.Errorf("subvolume %s: %w", name, errno)
		}
	}
	return nil
}
