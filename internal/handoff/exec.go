// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// Exec replaces this process with the sealed tego-control, with argv [tego-control, args...] and env (nil: this
// process's environment). It returns only on failure. A kernel or a security module that refuses to run the memfd
// is [memfd-noexec].
//
// The exec is syscall.Exec of /proc/self/fd/<n>, n an owned close-on-exec duplicate of the memfd held under its
// lease: the magic link names the sealed memfd's own open file, so what runs is the verified copy, as with
// execveat(memfd, "", AT_EMPTY_PATH). Going through syscall.Exec is what gives tego-control the soft RLIMIT_NOFILE
// tego started with, which Go raised in this process at start and keeps only inside package syscall, and takes the
// runtime's exec lock; a raw execveat skips both, so tego-control and every child it starts would run under Go's
// raise. Open already needs /proc (os.Executable reads /proc/self/exe), and Spawn execs the same form.
//
// The memfd and the duplicate are close-on-exec: the kernel has opened the file for the new image before it closes
// the descriptors, so tego-control inherits no copy of itself, and its /proc/self/exe is the sealed memfd, which its
// own children re-exec.
func Exec(b *Binary, args []string, env []string) error {
	if env == nil {
		env = os.Environ()
	}
	// A close-on-exec duplicate owns the number the path names, so nothing can close or reuse it before the exec.
	dup, err := sys.DupFile(b.mem, 3)
	if err != nil {
		return fmt.Errorf("exec %s: %w", Name, err)
	}
	defer func() { _ = dup.Close() }()
	argv := append([]string{Name}, args...)
	return execRefused(dup.ProcPath(func(path string) error { return syscall.Exec(path, argv, env) }))
}

// execRefused is the error of a failed exec of the sealed copy.
func execRefused(err error) error {
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
		return &Error{Code: CodeMemfdNoexec, What: "the kernel refused to run the sealed copy of " + Name,
			Fix: "check the security module's policy for memfd execution; `cat " + memfdNoexec + "` shows the memfd setting " +
				"(as root, `sysctl vm.memfd_noexec=1` or 0 allows an executable memfd)", Err: err}
	}
	return fmt.Errorf("exec %s: %w", Name, err)
}

// Child is what Spawn starts tego-control with: its arguments after argv[0], its environment (nil: this
// process's), its standard streams (nil: the null device, as os/exec gives), and the files it gets at descriptors
// 3, 4 and so on. The descriptor after the last of them, 3+len(ExtraFiles), is the child's own image: a read-only
// descriptor of the sealed memfd, which the child may close.
type Child struct {
	Args       []string
	Env        []string
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	ExtraFiles []*os.File
}

// Spawn starts the sealed tego-control as a child and returns the started command, which the caller waits for.
// The child gets a read-only descriptor of the sealed memfd after its
// extra files and execs it as /proc/self/fd/<that slot>, the form doctor's plane probe starts its image in, so
// what runs is the sealed copy and nothing the caller's descriptor numbers could move.
func Spawn(b *Binary, c Child) (*proc.Cmd, proc.Identity, error) {
	img, err := readOnly(b.mem)
	if err != nil {
		return nil, proc.Identity{}, fmt.Errorf("spawn %s: %w", Name, err)
	}
	defer func() { _ = img.Close() }()
	cmd := proc.Command("/proc/self/fd/"+strconv.Itoa(3+len(c.ExtraFiles)), c.Args...)
	cmd.Args[0] = Name
	cmd.Env = c.Env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.Stdin, c.Stdout, c.Stderr
	cmd.ExtraFiles = append(slices.Clip(c.ExtraFiles), img)
	id, err := proc.Start(cmd)
	if err != nil {
		return nil, proc.Identity{}, execRefused(err)
	}
	return cmd, id, nil
}

// readOnly reopens the sealed memfd read-only through its /proc/self/fd link: the child's copy can neither write
// nor, the seals being set, change it.
func readOnly(mem *os.File) (*os.File, error) {
	dup, err := sys.DupFile(mem, 3)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dup.Close() }()
	var ro *sys.FD
	if err := dup.ProcPath(func(path string) error {
		var err error
		ro, err = sys.Own(unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0))
		return err
	}); err != nil {
		return nil, err
	}
	return ro.Release(Name + " (image)")
}
