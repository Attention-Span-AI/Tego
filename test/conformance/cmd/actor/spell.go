// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The exec space's spellings (ADR 0017 space 2; test/conformance cells.go names each op): ways to run or map code
// other than an execve of a path. An op that changes the process for good (an exec that replaces it, a
// personality) runs in a stage of its own, `actor spell <op> <path>`, whose exit reports the errno.

const (
	// spellStage is the actor's stage for a spelling that replaces or marks the process.
	spellStage = "spell"
	// stageErrnoBase is added to an errno for the stage's exit status, above any status a stage's own failure
	// (log.Fatal's 1) or a noop target (0) exits with.
	stageErrnoBase = 64
	// readImpliesExec is personality(2)'s READ_IMPLIES_EXEC.
	readImpliesExec = 0x0400000
	// memfdName names every memfd the actor makes; the kernel shows it as /memfd:<name>.
	memfdName = "tego-conformance"
)

// performSpelling performs an exec-space op, or hands any other to performAttr.
func performSpelling(a Action) error {
	switch a.Op {
	case "exec-loader": // Path is the loader, Dest the program it loads: allowed once the loader started
		cmd := exec.Command(a.Path, a.Dest)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
		err := cmd.Run()
		var pe *os.PathError
		if errors.As(err, &pe) {
			return pe.Err
		}
		var ee *exec.ExitError
		if err != nil && !errors.As(err, &ee) {
			return err
		}
		return nil
	case "execveat-fd", "exec-proc-fd", "map-exec-rie", "mprotect-rie":
		return runStage(exec.Command("/proc/self/exe", spellStage, a.Op, a.Path))
	case "memfd-create":
		fd, err := unix.MemfdCreate(memfdName, unix.MFD_CLOEXEC)
		if err != nil {
			return err
		}
		return unix.Close(fd)
	case "memfd-exec": // the actor's own image in a memfd, run by /proc/self/fd/N
		fd, err := unix.MemfdCreate(memfdName, 0) // inherited by the child, whose /proc/self/fd/N it is
		if err != nil {
			return err
		}
		defer unix.Close(fd) //nolint:errcheck // the memfd is the actor's own
		image, err := os.ReadFile("/proc/self/exe")
		if err != nil {
			return err
		}
		for len(image) > 0 {
			n, err := unix.Write(fd, image)
			if err != nil {
				return err
			}
			image = image[n:]
		}
		return runStage(exec.Command(fmt.Sprintf("/proc/self/fd/%d", fd), "noop"))
	case "memfd-map-exec":
		fd, err := unix.MemfdCreate(memfdName, unix.MFD_CLOEXEC)
		if err != nil {
			return err
		}
		defer unix.Close(fd) //nolint:errcheck // the memfd is the actor's own
		if err := unix.Ftruncate(fd, int64(os.Getpagesize())); err != nil {
			return err
		}
		return mapPage(fd, unix.PROT_READ|unix.PROT_EXEC)
	case "mprotect-exec":
		return mapFile(a.Path, unix.O_RDONLY, unix.PROT_READ, unix.PROT_READ|unix.PROT_EXEC, false)
	case "execmod": // a private copy of the page, written, then made executable
		return mapFile(a.Path, unix.O_RDONLY, unix.PROT_READ|unix.PROT_WRITE, unix.PROT_READ|unix.PROT_EXEC, true)
	case "execmem":
		return mapFile(a.Path, unix.O_RDONLY, unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC, 0, false)
	}
	return performAttr(a)
}

// runStage runs cmd with the actor's descriptors and reads its exit: 0 is done, stageErrnoBase+errno the errno; an
// exec it could not start is the exec's errno.
func runStage(cmd *exec.Cmd) error {
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() > stageErrnoBase {
		return syscall.Errno(ee.ExitCode() - stageErrnoBase)
	}
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// stageMain is `actor spell <op> <path>`: it performs the op and exits stageErrnoBase+errno on a refusal; an exec
// that succeeds is the target's (a noop actor's) exit.
func stageMain(op, path string) {
	var err error
	switch op {
	case "execveat-fd", "exec-proc-fd":
		var fd int
		if fd, err = unix.Open(path, unix.O_PATH, 0); err != nil {
			break
		}
		argv, envv := []string{path, "noop"}, os.Environ()
		if op == "exec-proc-fd" {
			err = unix.Exec(fmt.Sprintf("/proc/self/fd/%d", fd), argv, envv)
			break
		}
		err = execveatEmpty(fd, argv, envv)
	case "map-exec-rie", "mprotect-rie":
		if err = setReadImpliesExec(); err != nil {
			break
		}
		if op == "map-exec-rie" {
			err = mapFile(path, unix.O_RDONLY, unix.PROT_READ, 0, false)
		} else {
			err = mapFile(path, unix.O_RDONLY, unix.PROT_NONE, unix.PROT_READ, false)
		}
	default:
		log.Fatalf("actor %s: unknown op %q", spellStage, op)
	}
	var en syscall.Errno
	if errors.As(err, &en) && int(en) < 256-stageErrnoBase {
		os.Exit(stageErrnoBase + int(en))
	}
	if err != nil {
		log.Fatalf("actor %s %s: %v", spellStage, op, err)
	}
	os.Exit(0)
}

// execveatEmpty is execveat(fd, "", argv, envv, AT_EMPTY_PATH); it returns only on failure.
func execveatEmpty(fd int, argv, envv []string) error {
	empty, err := unix.BytePtrFromString("")
	if err != nil {
		return err
	}
	av, err := cstrings(argv)
	if err != nil {
		return err
	}
	ev, err := cstrings(envv)
	if err != nil {
		return err
	}
	_, _, en := unix.Syscall6(unix.SYS_EXECVEAT, uintptr(fd), uintptr(unsafe.Pointer(empty)), uintptr(unsafe.Pointer(&av[0])),
		uintptr(unsafe.Pointer(&ev[0])), unix.AT_EMPTY_PATH, 0)
	return en
}

// cstrings is ss as a NULL-terminated array of C strings.
func cstrings(ss []string) ([]*byte, error) {
	out := make([]*byte, 0, len(ss)+1)
	for _, s := range ss {
		p, err := unix.BytePtrFromString(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return append(out, nil), nil
}

// setReadImpliesExec adds READ_IMPLIES_EXEC to the process's personality.
func setReadImpliesExec() error {
	cur, _, en := unix.Syscall(unix.SYS_PERSONALITY, 0xffffffff, 0, 0)
	if en != 0 {
		return en
	}
	if _, _, en = unix.Syscall(unix.SYS_PERSONALITY, cur|readImpliesExec, 0, 0); en != 0 {
		return en
	}
	return nil
}

// mapFile maps the first page of path MAP_PRIVATE with prot, writes a byte of it first when write is set, then
// mprotects it to reprot unless reprot is 0.
func mapFile(path string, flags, prot, reprot int, write bool) error {
	fd, err := unix.Open(path, flags|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd) //nolint:errcheck // read-only fd
	b, err := unix.Mmap(fd, 0, os.Getpagesize(), prot, unix.MAP_PRIVATE)
	if err != nil {
		return err
	}
	defer unix.Munmap(b) //nolint:errcheck // the actor's own map
	if write {
		b[0] ^= 0xff
	}
	if reprot != 0 {
		return unix.Mprotect(b, reprot)
	}
	return nil
}

// mapPage maps the first page of fd MAP_PRIVATE with prot.
func mapPage(fd, prot int) error {
	b, err := unix.Mmap(fd, 0, os.Getpagesize(), prot, unix.MAP_PRIVATE)
	if err != nil {
		return err
	}
	return unix.Munmap(b)
}
