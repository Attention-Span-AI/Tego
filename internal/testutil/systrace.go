// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package testutil

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
)

// The syscall audit: a strace-equivalent for tests, over ptrace(2), with no privilege. SysTrace re-runs this
// test binary with only one test selected, as a traced child; the test, finding InSysTraceChild true, brackets
// the code under audit with MarkBegin and MarkEnd; SysTrace returns every syscall any thread of the child, or of
// any process it starts (they are its syscalls too: a helper it runs reaches what it reaches), entered between the
// two. The parent tracing its own child is what Yama's scope 1 (the Ubuntu default)
// allows. amd64 only: the register names and the syscall numbers below are that ABI's.

// sysTraceEnv marks the traced child.
const sysTraceEnv = "TEGO_SYSTRACE_CHILD"

// The markers are write(2) calls no program makes: fd -1 and these counts. They fail with EBADF and change
// nothing.
const (
	markBegin = 0x5eed0001
	markEnd   = 0x5eed0002
)

// InSysTraceChild reports whether this process is the child SysTrace started.
func InSysTraceChild() bool { return os.Getenv(sysTraceEnv) == "1" }

// MarkBegin starts the audited window in the traced child.
func MarkBegin() { _, _, _ = syscall.Syscall(syscall.SYS_WRITE, ^uintptr(0), 0, markBegin) }

// MarkEnd ends the audited window in the traced child.
func MarkEnd() { _, _, _ = syscall.Syscall(syscall.SYS_WRITE, ^uintptr(0), 0, markEnd) }

// Syscall is one syscall entry the audited code made.
type Syscall struct {
	TID  int
	Nr   uint64
	Name string
	Args [6]uint64
	// Paths are the path arguments, made absolute against the dirfd or the working directory when relative.
	Paths []string
	// FD is the file descriptor argument of a call that writes through one, and FDPath what /proc says it is.
	FD     int
	FDPath string
	// Flags are open's flags for open, openat, openat2 and creat (creat: O_CREAT|O_WRONLY|O_TRUNC), and the clone
	// flags for clone and clone3 (clone3: struct clone_args's flags).
	Flags uint64
}

func (s Syscall) String() string {
	if s.FDPath != "" {
		return fmt.Sprintf("%s(fd %d = %s)", s.Name, s.FD, s.FDPath)
	}
	return fmt.Sprintf("%s(%q flags=%#o)", s.Name, s.Paths, s.Flags)
}

// pathArg describes where a syscall's path arguments are: argument index, and the dirfd index (-1 for none).
type pathArg struct{ arg, dirfd int }

// sysInfo is what this file knows of a syscall: its name, its path arguments, and which argument is a written
// file descriptor (-1 for none).
type sysInfo struct {
	name  string
	paths []pathArg
	fdArg int
}

// amd64Syscalls is every syscall the audits look at: the ones that name a path and the ones that write through
// a descriptor. Anything else is recorded by number with no decoding.
var amd64Syscalls = map[uint64]sysInfo{
	2:   {"open", []pathArg{{0, -1}}, -1},
	4:   {"stat", []pathArg{{0, -1}}, -1},
	6:   {"lstat", []pathArg{{0, -1}}, -1},
	21:  {"access", []pathArg{{0, -1}}, -1},
	59:  {"execve", []pathArg{{0, -1}}, -1},
	76:  {"truncate", []pathArg{{0, -1}}, -1},
	80:  {"chdir", []pathArg{{0, -1}}, -1},
	82:  {"rename", []pathArg{{0, -1}, {1, -1}}, -1},
	83:  {"mkdir", []pathArg{{0, -1}}, -1},
	84:  {"rmdir", []pathArg{{0, -1}}, -1},
	85:  {"creat", []pathArg{{0, -1}}, -1},
	86:  {"link", []pathArg{{0, -1}, {1, -1}}, -1},
	87:  {"unlink", []pathArg{{0, -1}}, -1},
	88:  {"symlink", []pathArg{{1, -1}}, -1},
	89:  {"readlink", []pathArg{{0, -1}}, -1},
	90:  {"chmod", []pathArg{{0, -1}}, -1},
	92:  {"chown", []pathArg{{0, -1}}, -1},
	94:  {"lchown", []pathArg{{0, -1}}, -1},
	133: {"mknod", []pathArg{{0, -1}}, -1},
	161: {"chroot", []pathArg{{0, -1}}, -1},
	165: {"mount", []pathArg{{1, -1}}, -1},
	166: {"umount2", []pathArg{{0, -1}}, -1},
	188: {"setxattr", []pathArg{{0, -1}}, -1},
	189: {"lsetxattr", []pathArg{{0, -1}}, -1},
	254: {"inotify_add_watch", []pathArg{{1, -1}}, -1},
	257: {"openat", []pathArg{{1, 0}}, -1},
	258: {"mkdirat", []pathArg{{1, 0}}, -1},
	259: {"mknodat", []pathArg{{1, 0}}, -1},
	260: {"fchownat", []pathArg{{1, 0}}, -1},
	262: {"newfstatat", []pathArg{{1, 0}}, -1},
	263: {"unlinkat", []pathArg{{1, 0}}, -1},
	264: {"renameat", []pathArg{{1, 0}, {3, 2}}, -1},
	265: {"linkat", []pathArg{{1, 0}, {3, 2}}, -1},
	266: {"symlinkat", []pathArg{{2, 1}}, -1},
	267: {"readlinkat", []pathArg{{1, 0}}, -1},
	268: {"fchmodat", []pathArg{{1, 0}}, -1},
	269: {"faccessat", []pathArg{{1, 0}}, -1},
	280: {"utimensat", []pathArg{{1, 0}}, -1},
	316: {"renameat2", []pathArg{{1, 0}, {3, 2}}, -1},
	332: {"statx", []pathArg{{1, 0}}, -1},
	437: {"openat2", []pathArg{{1, 0}}, -1},
	439: {"faccessat2", []pathArg{{1, 0}}, -1},
	452: {"fchmodat2", []pathArg{{1, 0}}, -1},

	56:  {"clone", nil, -1},
	57:  {"fork", nil, -1},
	58:  {"vfork", nil, -1},
	322: {"execveat", []pathArg{{1, 0}}, -1},
	435: {"clone3", nil, -1},

	41:  {"socket", nil, -1},
	42:  {"connect", nil, -1},
	321: {"bpf", nil, -1},

	1:   {"write", nil, 0},
	18:  {"pwrite64", nil, 0},
	20:  {"writev", nil, 0},
	40:  {"sendfile", nil, 0},
	77:  {"ftruncate", nil, 0},
	91:  {"fchmod", nil, 0},
	93:  {"fchown", nil, 0},
	190: {"fsetxattr", nil, 0},
	275: {"splice", nil, 2},
	285: {"fallocate", nil, 0},
	296: {"pwritev", nil, 0},
	326: {"copy_file_range", nil, 2},
	328: {"pwritev2", nil, 0},
}

// Syscall numbers the audits name.
const (
	SysOpen     = 2
	SysCreat    = 85
	SysOpenat   = 257
	SysOpenat2  = 437
	SysSocket   = 41
	SysConnect  = 42
	SysBPF      = 321
	SysClone    = 56
	SysFork     = 57
	SysVfork    = 58
	SysExecve   = 59
	SysExecveat = 322
	SysClone3   = 435
)

// Spawns reports whether s starts a process or runs a program: fork, vfork, execve and execveat, and a clone or
// clone3 that makes a process rather than a thread of this one (no CLONE_THREAD). The Go runtime's own threads
// are clones with CLONE_THREAD, so a Go program that starts nothing makes no call Spawns admits.
func (s Syscall) Spawns() bool {
	switch s.Nr {
	case SysFork, SysVfork, SysExecve, SysExecveat:
		return true
	case SysClone, SysClone3:
		return s.Flags&syscall.CLONE_THREAD == 0
	}
	return false
}

// Written reports whether s creates, removes, renames, links or changes a file, or opens one for writing:
// the mutating half of the file syscalls. A write-family call through a descriptor counts unless the
// descriptor is stdin, stdout or stderr, or an anonymous kernel object (an eventfd, a pipe the runtime keeps),
// none of which is a file.
func (s Syscall) Written() bool {
	switch s.Name {
	case "open", "openat", "openat2", "creat":
		return s.Flags&(syscall.O_WRONLY|syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC) != 0
	case "truncate", "rename", "renameat", "renameat2", "mkdir", "mkdirat", "rmdir", "link", "linkat",
		"symlink", "symlinkat", "unlink", "unlinkat", "chmod", "fchmodat", "fchmodat2", "chown", "lchown",
		"fchownat", "mknod", "mknodat", "utimensat", "setxattr", "lsetxattr", "mount", "umount2", "chroot":
		return true
	}
	if info, ok := amd64Syscalls[s.Nr]; ok && info.fdArg >= 0 {
		if s.FD >= 0 && s.FD <= 2 {
			return false
		}
		p := s.FDPath
		return !(len(p) > 0 && p[0] != '/') // "anon_inode:[eventfd]", "pipe:[..]", "socket:[..]" are not files
	}
	return false
}

// SysTrace runs the test called name in a traced copy of this test binary, with env added, and returns the
// syscalls the child entered between MarkBegin and MarkEnd. The test fails when the child does: a child that
// never reached MarkEnd, or whose own test failed.
func SysTrace(t testing.TB, name string, env ...string) []Syscall {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.CreateTemp("", "tego-systrace-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close(); _ = os.Remove(out.Name()) }()

	type result struct {
		calls  []Syscall
		ended  bool
		status syscall.WaitStatus
		err    error
	}
	ch := make(chan result, 1)
	go func() {
		// Every ptrace request must come from the thread that is the tracer, and the child's threads attach to
		// the thread that started it. The thread is never unlocked: it exits with this goroutine.
		runtime.LockOSThread()
		var r result
		defer func() { ch <- r }()
		cmd := exec.Command(self, "-test.run=^"+name+"$", "-test.count=1")
		cmd.Env = append(append(os.Environ(), sysTraceEnv+"=1"), env...)
		cmd.Stdout, cmd.Stderr = out, out
		cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true, Pdeathsig: syscall.SIGKILL}
		if r.err = cmd.Start(); r.err != nil {
			return
		}
		r.calls, r.ended, r.status, r.err = traceLoop(cmd.Process.Pid, false)
	}()
	r := <-ch
	log, _ := os.ReadFile(out.Name())
	if r.err != nil {
		t.Fatalf("systrace: %v\n%s", r.err, log)
	}
	if !r.status.Exited() || r.status.ExitStatus() != 0 {
		t.Fatalf("systrace: the traced child %s failed (status %#x):\n%s", name, int(r.status), log)
	}
	if !r.ended {
		t.Fatalf("systrace: the traced child never reached MarkEnd (does %s call MarkBegin/MarkEnd when InSysTraceChild?):\n%s", name, log)
	}
	return r.calls
}

// SysTraceCommand runs cmd, which has not been started, traced from its exec to its exit, and returns every syscall
// any thread of it, or of any process it starts, entered, those its runtime makes before main included (an init
// function's are the reason to trace a whole program): the audit of a program a test built rather than of code in
// the test binary. It is SysTrace's tracer with recording on from the start. A process it starts shows as a call
// that Spawns, and that process's own calls follow it, so an audit can refuse either. The exit status is
// returned, not judged.
func SysTraceCommand(t testing.TB, cmd *exec.Cmd) ([]Syscall, syscall.WaitStatus) {
	t.Helper()
	type result struct {
		calls  []Syscall
		status syscall.WaitStatus
		err    error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread() // as in SysTrace: the tracer is this thread, and it exits with the goroutine
		var r result
		defer func() { ch <- r }()
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		cmd.SysProcAttr.Ptrace, cmd.SysProcAttr.Pdeathsig = true, syscall.SIGKILL
		if r.err = cmd.Start(); r.err != nil {
			return
		}
		r.calls, _, r.status, r.err = traceLoop(cmd.Process.Pid, true)
		// The child is reaped by traceLoop's wait; Wait still closes the pipes and copies stdio.
		_ = cmd.Wait()
	}()
	r := <-ch
	if r.err != nil {
		t.Fatalf("systrace %s: %v", cmd.Path, r.err)
	}
	return r.calls, r.status
}

// traceLoop follows pid, every thread it clones and every process it or they fork, vfork or clone, to pid's exit,
// recording between the markers, or from the start when all is true. A process still running when pid exits is
// killed with the tracer thread (PTRACE_O_EXITKILL).
func traceLoop(pid int, all bool) ([]Syscall, bool, syscall.WaitStatus, error) {
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		return nil, false, ws, fmt.Errorf("wait for the exec stop: %w", err)
	}
	const opts = syscall.PTRACE_O_TRACESYSGOOD | syscall.PTRACE_O_TRACECLONE | syscall.PTRACE_O_TRACEFORK |
		syscall.PTRACE_O_TRACEVFORK | 0x100000 // PTRACE_O_EXITKILL
	if err := syscall.PtraceSetOptions(pid, opts); err != nil {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		return nil, false, ws, fmt.Errorf("PTRACE_SETOPTIONS: %w", err)
	}
	if err := syscall.PtraceSyscall(pid, 0); err != nil {
		return nil, false, ws, fmt.Errorf("PTRACE_SYSCALL: %w", err)
	}
	var calls []Syscall
	inSys := map[int]bool{}
	recording, ended := all, false
	for {
		tid, err := syscall.Wait4(-1, &ws, syscall.WALL, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return calls, ended, ws, fmt.Errorf("wait: %w", err)
		}
		if ws.Exited() || ws.Signaled() {
			delete(inSys, tid)
			if tid == pid {
				return calls, ended, ws, nil
			}
			continue
		}
		if !ws.Stopped() {
			continue
		}
		sig := ws.StopSignal()
		deliver := 0
		switch sig {
		case syscall.SIGTRAP | 0x80:
			entering := !inSys[tid]
			inSys[tid] = entering
			if entering {
				var regs syscall.PtraceRegs
				if err := syscall.PtraceGetRegs(tid, &regs); err == nil {
					args := [6]uint64{regs.Rdi, regs.Rsi, regs.Rdx, regs.R10, regs.R8, regs.R9}
					switch {
					case regs.Orig_rax == syscall.SYS_WRITE && args[0] == ^uint64(0) && args[2] == markBegin:
						recording = true
					case regs.Orig_rax == syscall.SYS_WRITE && args[0] == ^uint64(0) && args[2] == markEnd:
						recording, ended = false, true
					case recording:
						calls = append(calls, decode(tid, regs.Orig_rax, args))
					}
				}
			}
		case syscall.SIGTRAP, syscall.SIGSTOP:
			// An event stop (clone, fork, vfork), the SIGTRAP after an exec, or a new thread's or process's first
			// stop: nothing to deliver.
		default:
			deliver = int(sig)
		}
		_ = syscall.PtraceSyscall(tid, deliver)
	}
}

// decode reads what the audits need of one syscall entry out of the stopped thread.
func decode(tid int, nr uint64, args [6]uint64) Syscall {
	s := Syscall{TID: tid, Nr: nr, Args: args, FD: -1}
	info, ok := amd64Syscalls[nr]
	if !ok {
		s.Name = "sys_" + strconv.FormatUint(nr, 10)
		return s
	}
	s.Name = info.name
	for _, p := range info.paths {
		path := peekString(tid, uintptr(args[p.arg]))
		if !filepath.IsAbs(path) {
			base := readlink(fmt.Sprintf("/proc/%d/cwd", tid))
			if p.dirfd >= 0 && int32(args[p.dirfd]) != -100 { // AT_FDCWD
				base = readlink(fmt.Sprintf("/proc/%d/fd/%d", tid, int32(args[p.dirfd])))
			}
			path = filepath.Join(base, path)
		}
		s.Paths = append(s.Paths, path)
	}
	switch nr {
	case SysOpen:
		s.Flags = args[1]
	case SysOpenat:
		s.Flags = args[2]
	case SysOpenat2:
		s.Flags = peekUint64(tid, uintptr(args[2])) // struct open_how's first member, u64 flags
	case SysCreat:
		s.Flags = syscall.O_CREAT | syscall.O_WRONLY | syscall.O_TRUNC
	case SysClone:
		s.Flags = args[0]
	case SysClone3:
		s.Flags = peekUint64(tid, uintptr(args[0])) // struct clone_args's first member, u64 flags
	}
	if info.fdArg >= 0 {
		s.FD = int(int32(args[info.fdArg]))
		s.FDPath = readlink(fmt.Sprintf("/proc/%d/fd/%d", tid, s.FD))
	}
	return s
}

// peekUint64 reads a little-endian u64 out of the tracee, 0 when it cannot.
func peekUint64(tid int, addr uintptr) uint64 {
	var b [8]byte
	if n, err := syscall.PtracePeekData(tid, addr, b[:]); err != nil || n != len(b) {
		return 0
	}
	return binary.LittleEndian.Uint64(b[:])
}

// peekString reads a NUL-terminated string out of the tracee, at most 4096 bytes.
func peekString(tid int, addr uintptr) string {
	var out []byte
	buf := make([]byte, 64)
	for len(out) < 4096 {
		n, err := syscall.PtracePeekData(tid, addr, buf)
		if err != nil || n == 0 {
			break
		}
		if i := bytes.IndexByte(buf[:n], 0); i >= 0 {
			return string(append(out, buf[:i]...))
		}
		out = append(out, buf[:n]...)
		addr += uintptr(n)
	}
	return string(out)
}

func readlink(p string) string {
	s, err := os.Readlink(p)
	if err != nil {
		return p
	}
	return s
}
