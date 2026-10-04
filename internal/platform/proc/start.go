// SPDX-License-Identifier: Apache-2.0

package proc

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
)

// ErrArmed is Start refusing a process start while this process is armed: a fanotify permission group of its
// own holds marks (ADR 0021 (3)). A start then is the vfork window E39's freeze was made of: the forking
// thread holds its scheduler slot until the child's execve is past its point of no return, the execve opens
// its file on a marked mount, and only this process answers that open.
var ErrArmed = errors.New("proc: no process is started while this process's fanotify marks exist (ADR 0021 (3))")

// ErrIdentity is a started process whose start identity could not be read. Start has killed and reaped it: a
// process nobody can name across time is not handed to a caller that would keep its pid.
var ErrIdentity = errors.New("proc: the started process's start time could not be read")

// Cmd is os/exec's command, named here so that a package building a command needs no import of os/exec, which
// lint allows in this package only (ADR 0021 (3), .golangci.yml): every process start goes through Start.
type Cmd = exec.Cmd

// Command is exec.Command. The command it returns is started with Start, never with its own Start, Run, Output
// or CombinedOutput, which lint refuses outside this package.
func Command(name string, arg ...string) *Cmd { return exec.Command(name, arg...) }

// gate is the process-wide armed count. Start holds the read side across the fork and the child's execve, and
// Arm takes the write side, so a start that passed the check has finished its exec before the first mark can
// exist, and no start begins while one does.
var gate struct {
	sync.RWMutex
	armed int
}

// Arm marks this process armed until the returned disarm is called; the arms nest, and a start is refused while
// any is held. The caller arms before it places its first fanotify mark and disarms once the last one is gone
// (enforce/cgroup's listener). Arm waits for a start already past its check to finish. disarm is idempotent.
func Arm() (disarm func()) {
	gate.Lock()
	gate.armed++
	gate.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			gate.Lock()
			gate.armed--
			gate.Unlock()
		})
	}
}

// Armed reports whether a process start would be refused now.
func Armed() bool {
	gate.RLock()
	defer gate.RUnlock()
	return gate.armed > 0
}

// Identity names one process across time: its pid and its start time (StartBootNS). A pid alone names whichever
// process holds the number now, and the kernel reissues it once its holder is reaped; a pid kept past that point
// is compared by its start as well (SameProcess). Start never returns an identity whose start it could not read:
// that start is undone as ErrIdentity.
type Identity struct {
	PID         int
	StartBootNS uint64
}

// Identity reads pid's start identity from /proc/<pid>/stat. A pid with no process is ErrGone.
func (f *FS) Identity(pid int) (Identity, error) {
	st, err := f.Stat(pid)
	if err != nil {
		return Identity{}, err
	}
	return Identity{PID: pid, StartBootNS: st.StartBootNS()}, nil
}

// Start is the one process start of non-test code (ADR 0021 (3)): it refuses with ErrArmed while this process is
// armed, and otherwise starts cmd and returns the started process's Identity. The identity is read before the
// caller can reap the child, so the pid cannot have been reissued yet: an exited child stays a zombie, whose
// stat is still there. A start whose identity cannot be read is undone (ErrIdentity). On success the caller owns
// cmd.Process exactly as after cmd.Start. After ErrIdentity the command must not be reused: when caller-supplied
// non-file I/O is blocked, its command cleanup finishes once that I/O returns. The child is already reaped.
//
// Every call is a reviewed site (ADR 0021 (6)): a file that calls Start needs an exclusion in .golangci.yml and
// a row in sites_test.go saying when the start runs against Arm, and an unexported function that calls it is
// followed in turn: each call of that function is a row too.
func Start(cmd *Cmd) (Identity, error) {
	return startWithIdentity(cmd, New().Identity)
}

// startWithIdentity keeps identity refusal testable independently of the host's proc mount.
func startWithIdentity(cmd *Cmd, readIdentity func(int) (Identity, error)) (Identity, error) {
	if err := startGated(cmd); err != nil {
		return Identity{}, err
	}
	pid := cmd.Process.Pid
	id, err := readIdentity(pid)
	if err != nil {
		_ = cmd.Process.Kill()
		if commandCopiesIO(cmd) {
			// Caller-owned Read/Write can block indefinitely, even with WaitDelay. Reap before
			// returning the refusal, then let Cmd join its copier and release its own pipes when
			// that I/O returns. The second Process.Wait inside Cmd.Wait sees an already-reaped
			// process; only this goroutine uses Cmd after the failed start.
			_, _ = cmd.Process.Wait()
			go func() { _ = cmd.Wait() }()
		} else {
			// With only nil/file streams no copier can block. Cmd.Wait also closes the parent
			// pipe ends it owns, which Process.Wait alone would leave open.
			_ = cmd.Wait()
		}
		return Identity{}, fmt.Errorf("%w: pid %d: %w", ErrIdentity, pid, err)
	}
	return id, nil
}

func commandCopiesIO(cmd *Cmd) bool {
	if cmd.Stdin != nil {
		if _, ok := cmd.Stdin.(*os.File); !ok {
			return true
		}
	}
	for _, writer := range []any{cmd.Stdout, cmd.Stderr} {
		if writer != nil {
			if _, ok := writer.(*os.File); !ok {
				return true
			}
		}
	}
	return false
}

// startGated is Start's check and fork, under the gate's read side.
func startGated(cmd *Cmd) error {
	gate.RLock()
	defer gate.RUnlock()
	if gate.armed > 0 {
		return fmt.Errorf("%w: refused %s", ErrArmed, cmd.Path)
	}
	return cmd.Start()
}
