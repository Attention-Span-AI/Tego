// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ErrCredentials is a task's credentials that the calling process cannot read, or cannot take on for one
// call (RunAs).
var ErrCredentials = errors.New("sys: task credentials")

// TaskCreds is the part of a task's credentials a unix connect(2) is judged by. The DAC checks of the path
// walk and of the socket inode read the filesystem ids and the supplementary groups; a stream listener's
// SO_PEERCRED reports the effective ids; and CAP_DAC_OVERRIDE and CAP_DAC_READ_SEARCH in the effective set
// bypass the DAC checks. The real and saved ids take part in none of those, which is what lets RunAs keep
// them (see there).
type TaskCreds struct {
	EUID, EGID   uint32
	FSUID, FSGID uint32
	// Groups is the supplementary group list, sorted.
	Groups []uint32
	// CapEff is the effective capability set.
	CapEff uint64
}

// Equal reports whether c and o are judged alike by a unix connect.
func (c TaskCreds) Equal(o TaskCreds) bool {
	return c.EUID == o.EUID && c.EGID == o.EGID && c.FSUID == o.FSUID && c.FSGID == o.FSGID &&
		c.CapEff == o.CapEff && slices.Equal(c.Groups, o.Groups)
}

// ReadTaskCreds reads /proc/<tid>/status. tid may name any thread, not only a thread-group leader:
// credentials are per thread, and the one that trapped is the one whose connect is being judged. The file
// is keyed by an id the task may have given up by the time it is read, so the caller brackets it.
func ReadTaskCreds(tid int) (TaskCreds, error) {
	return readStatusCreds("/proc/" + strconv.Itoa(tid) + "/status")
}

// ThreadCreds reads the calling thread's credentials from /proc/thread-self/status.
func ThreadCreds() (TaskCreds, error) { return readStatusCreds("/proc/thread-self/status") }

func readStatusCreds(name string) (TaskCreds, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return TaskCreds{}, fmt.Errorf("%w: %w", ErrCredentials, err)
	}
	c, err := ParseStatusCreds(b)
	if err != nil {
		return TaskCreds{}, fmt.Errorf("%s: %w", name, err)
	}
	return c, nil
}

// ParseStatusCreds is ReadTaskCreds' pure half: the Uid, Gid, Groups and CapEff lines of a
// /proc/<tid>/status. Uid and Gid carry real, effective, saved and filesystem ids in that order
// (fs/proc/array.c task_state). A missing or malformed line is an error, never a zero id: a zero read as
// "root" would be the one wrong answer that grants.
func ParseStatusCreds(b []byte) (TaskCreds, error) {
	var c TaskCreds
	var seen int
	for _, line := range bytes.Split(b, []byte("\n")) {
		key, val, ok := strings.Cut(string(line), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(val)
		switch key {
		case "Uid", "Gid":
			if len(fields) != 4 {
				return TaskCreds{}, fmt.Errorf("%w: %s line %q", ErrCredentials, key, val)
			}
			var ids [4]uint32
			for i, f := range fields {
				n, err := strconv.ParseUint(f, 10, 32)
				if err != nil {
					return TaskCreds{}, fmt.Errorf("%w: %s line %q: %w", ErrCredentials, key, val, err)
				}
				ids[i] = uint32(n)
			}
			if key == "Uid" {
				c.EUID, c.FSUID = ids[1], ids[3]
			} else {
				c.EGID, c.FSGID = ids[1], ids[3]
			}
			seen |= map[string]int{"Uid": 1, "Gid": 2}[key]
		case "Groups":
			c.Groups = make([]uint32, 0, len(fields))
			for _, f := range fields {
				n, err := strconv.ParseUint(f, 10, 32)
				if err != nil {
					return TaskCreds{}, fmt.Errorf("%w: Groups line %q: %w", ErrCredentials, val, err)
				}
				c.Groups = append(c.Groups, uint32(n))
			}
			slices.Sort(c.Groups)
			seen |= 4
		case "CapEff":
			n, err := strconv.ParseUint(strings.TrimSpace(val), 16, 64)
			if err != nil {
				return TaskCreds{}, fmt.Errorf("%w: CapEff line %q: %w", ErrCredentials, val, err)
			}
			c.CapEff = n
			seen |= 8
		}
	}
	if seen != 15 {
		return TaskCreds{}, fmt.Errorf("%w: status lacks one of Uid, Gid, Groups, CapEff", ErrCredentials)
	}
	return c, nil
}

// RunAs calls fn with the calling process's authority narrowed to want for everything a unix connect is
// judged by (TaskCreds), and returns once fn has returned. When the process's own credentials already are
// want, fn runs on the caller's goroutine and nothing changes. Otherwise fn runs on a goroutine locked to a
// fresh OS thread that takes want's supplementary groups and effective ids, and that goroutine exits
// without unlocking, so the Go runtime destroys the thread rather than hand it to another goroutine with
// credentials that are not the process's. A thread whose credentials could not be taken in full never runs
// fn; the error wraps ErrCredentials. A panic in fn is re-raised on the caller's goroutine.
//
// Credentials are per thread in Linux, and these are raw setgroups/setresgid/setresuid calls, which change
// only the calling thread; the syscall package's Setuid family applies to every thread of the process
// instead, and must not be used here. The real and saved ids are left as they were (-1). Nothing a connect
// checks reads them, and while either is one the target does not share, the target can neither signal
// this thread (kill_ok_by_cred) nor ptrace it (ptrace_may_access): a thread holding only the target's uid
// could otherwise be sent SIGKILL by the target, and the whole process with it.
//
// A euid change from 0 clears the effective capability set and keeps the permitted one, since a saved id is
// still 0 (capabilities(7), "Effect of user ID changes on capabilities"); what the thread still holds in
// its effective set is then narrowed to want.CapEff with capset. The kernel also resets the process's
// dumpable flag to fs.suid_dumpable when a thread's effective or filesystem ids change (commit_creds), which
// makes the whole process undumpable for good; that closes /proc/<pid> and ptrace to anyone but root, and
// nothing in this process reads its own /proc through a path the flag guards. A filesystem id that differs
// from the effective one is not reproduced: it is refused.
func RunAs(want TaskCreds, fn func()) error {
	have, err := ThreadCreds()
	if err != nil {
		return err
	}
	if have.Equal(want) {
		fn()
		return nil
	}
	done := make(chan runResult, 1)
	go runLockedAs(want, fn, done)
	res := <-done
	if res.panicked != nil {
		panic(res.panicked)
	}
	return res.err
}

// runResult is what the thread RunAs used hands back.
type runResult struct {
	err      error
	panicked any
}

// runLockedAs is RunAs's thread: it locks the goroutine to its OS thread, takes want and runs fn there,
// and exits still locked. A goroutine that exits locked takes its thread with it (runtime.LockOSThread),
// so a thread whose credentials are not the process's is never handed to another goroutine; threads the
// runtime starts meanwhile are cloned from its template thread, not from this one.
//
// The main thread is the exception, and is never the one switched. The runtime does not destroy it when
// its locked goroutine exits but parks it for good, and it is the thread group leader, whose credentials
// /proc/<pid>/status reports as the process's. Landing on it, the goroutine hands the work to another
// goroutine — which cannot be scheduled on the main thread while this one holds it locked — and gives the
// main thread back unchanged. Found as root in the KVM guest: the switched main thread outlived RunAs,
// and /proc/<pid>/status went on reporting uid 1000 for the whole process.
func runLockedAs(want TaskCreds, fn func(), done chan<- runResult) {
	runtime.LockOSThread()
	if unix.Gettid() == unix.Getpid() {
		inner := make(chan runResult, 1)
		go runLockedAs(want, fn, inner)
		res := <-inner
		runtime.UnlockOSThread()
		done <- res
		return
	}
	var res runResult
	defer func() {
		if p := recover(); p != nil {
			res.panicked = p
		}
		done <- res
	}()
	if res.err = assume(want); res.err == nil {
		fn()
	}
}

// assume gives the calling, locked thread want's groups and effective ids, narrows its effective
// capabilities to want's, and reads the result back rather than trusting the calls' return values.
func assume(want TaskCreds) error {
	if want.FSUID != want.EUID || want.FSGID != want.EGID {
		return fmt.Errorf("%w: fsuid %d / fsgid %d differ from euid %d / egid %d", ErrCredentials,
			want.FSUID, want.FSGID, want.EUID, want.EGID)
	}
	have, err := ThreadCreds()
	if err != nil {
		return err
	}
	// Groups and gids first: both need CAP_SETGID, which the uid change below takes away.
	if !slices.Equal(have.Groups, want.Groups) {
		if err := setThreadGroups(want.Groups); err != nil {
			return err
		}
	}
	const keep = ^uintptr(0) // (uid_t)-1: leave the real and saved ids as they are
	if have.EGID != want.EGID {
		if _, _, errno := unix.RawSyscall(unix.SYS_SETRESGID, keep, uintptr(want.EGID), keep); errno != 0 {
			return fmt.Errorf("%w: setresgid(-1, %d, -1): %w", ErrCredentials, want.EGID, errno)
		}
	}
	if have.EUID != want.EUID {
		if _, _, errno := unix.RawSyscall(unix.SYS_SETRESUID, keep, uintptr(want.EUID), keep); errno != 0 {
			return fmt.Errorf("%w: setresuid(-1, %d, -1): %w", ErrCredentials, want.EUID, errno)
		}
	}
	if err := narrowEffective(want.CapEff); err != nil {
		return err
	}
	got, err := ThreadCreds()
	if err != nil {
		return err
	}
	if got.EUID != want.EUID || got.EGID != want.EGID || got.FSUID != want.FSUID || got.FSGID != want.FSGID ||
		!slices.Equal(got.Groups, want.Groups) || got.CapEff&^want.CapEff != 0 {
		return fmt.Errorf("%w: the thread holds %+v after taking %+v", ErrCredentials, got, want)
	}
	return nil
}

// setThreadGroups is setgroups(2) on the calling thread only. gid_t is 32 bits on both supported
// architectures, which is the element type the kernel reads.
func setThreadGroups(groups []uint32) error {
	list := groups
	if len(list) == 0 {
		list = []uint32{0} // a valid pointer for a zero-length list; the kernel reads none of it
	}
	_, _, errno := unix.RawSyscall(unix.SYS_SETGROUPS, uintptr(len(groups)), uintptr(unsafe.Pointer(&list[0])), 0)
	if errno != 0 {
		return fmt.Errorf("%w: setgroups(%v): %w", ErrCredentials, groups, errno)
	}
	return nil
}

// narrowEffective drops from the calling thread's effective set every capability keep does not hold. The
// permitted and inheritable sets are left alone: lowering the effective set alone needs no privilege, and a
// capability that is only permitted grants nothing until something raises it again.
func narrowEffective(keep uint64) error {
	hdr := unix.CapUserHeader{Version: capabilityVersion3, Pid: 0}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("%w: capget: %w", ErrCredentials, err)
	}
	eff := uint64(data[1].Effective)<<32 | uint64(data[0].Effective)
	if eff&^keep == 0 {
		return nil
	}
	eff &= keep
	data[0].Effective, data[1].Effective = uint32(eff), uint32(eff>>32)
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("%w: capset(effective %#x): %w", ErrCredentials, eff, err)
	}
	return nil
}

// DropThreadCreds switches the calling thread alone to gid, with gid as its only supplementary group, and then
// to uid, all three of each id (real, effective, saved). Unlike x/sys/unix's Setgroups, Setresgid and
// Setresuid, which apply to every thread of the process through the Go runtime's all-threads path, it makes
// raw per-thread syscalls: that path signals every other thread with tgkill from the calling one, and a
// thread that has installed a seccomp filter which hands tgkill to a supervisor not yet running blocks there
// for good (the child stage below Landlock ABI 6, R7). A process that execve's from this
// thread gets exactly these credentials: execve ends every other thread. A negative id leaves it unchanged.
func DropThreadCreds(uid, gid int) error {
	if gid >= 0 {
		if err := setThreadGroups([]uint32{uint32(gid)}); err != nil {
			return err
		}
		if _, _, errno := unix.RawSyscall(unix.SYS_SETRESGID, uintptr(gid), uintptr(gid), uintptr(gid)); errno != 0 {
			return fmt.Errorf("setresgid(%d): %w", gid, errno)
		}
	}
	if uid >= 0 {
		if _, _, errno := unix.RawSyscall(unix.SYS_SETRESUID, uintptr(uid), uintptr(uid), uintptr(uid)); errno != 0 {
			return fmt.Errorf("setresuid(%d): %w", uid, errno)
		}
	}
	return nil
}
