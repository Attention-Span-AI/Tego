// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/reason"
)

const (
	// StateDirName is the agent-writable directory beside the reason file that the launcher makes for the hook
	// (ADR 0062: internal/runtime's hookStateName, granted as fs.harness-state). The hook never makes it: in a run
	// whose launcher made none, a mkdir there is a refusal.
	StateDirName = "hook-state"
	// StateFileName is the hook's state in StateDirName.
	StateFileName = "state.json"
	// MaxStateBytes bounds the state file: a longer one is refused, as the launcher refuses it at run end.
	MaxStateBytes = 4 << 10
	// StateVersion is the state file's own version.
	StateVersion = 1
	// LockBudget is how long the hook waits for the state lock before it gives up and prints nothing (Claude Code's
	// hook timeout is ten seconds in the settings tego writes; a hook holds the lock for well under a millisecond).
	LockBudget = 2 * time.Second

	stateTmpName = StateFileName + ".tmp"
	lockPoll     = 2 * time.Millisecond
)

// The state errors, each a reason the hook prints nothing.
var (
	errLockTimeout = errors.New("hook state lock not taken within its budget")
	errStateLink   = errors.New("hook state is a symbolic link")
	errState       = errors.New("unusable hook state")
)

// State is hook-state/state.json: the claim-once cursor every hook process of the run shares, and the counts the
// launcher reads into run_end's reason_delivery at the run's end (reported_by: hook). It lives where the agent can
// write, so it is the agent's own account: a forged cursor only hides refusals from the agent itself, and the
// ledger stays authoritative.
type State struct {
	V   int    `json:"v"`
	Run string `json:"run"`
	// Cursor is the highest seq any hook of the run has shown, 0 for none.
	Cursor uint64 `json:"cursor"`
	// Sessions is how many SessionStart events the hook answered.
	Sessions uint64 `json:"sessions"`
	// Deliveries is how many notes of refusals the hook printed.
	Deliveries uint64 `json:"deliveries"`
	// RefusalsDelivered is how many of the run's refusals those notes told, each by its sentence or in a count of
	// those no longer listed: the reason file's refusals when the last note was claimed (reason.File.Since's cursor).
	RefusalsDelivered uint64 `json:"refusals_delivered"`
}

// stateDir is hook-state/, opened without following a link: the lock is held on it, and the state file in it is
// read and replaced by its path. The path is the agent's own to change (the hook runs as the agent), so no other
// user's file can stand in for it; what a link could still redirect, the run's own rules bound.
type stateDir struct {
	dir  *os.File
	path string
}

// openStateDir opens dir/hook-state.
func openStateDir(dir string) (*stateDir, error) {
	path := filepath.Join(dir, StateDirName)
	fh, err := os.OpenFile(path, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	switch {
	case errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR):
		return nil, fmt.Errorf("%w: %s is not a directory", errState, StateDirName)
	case err != nil:
		return nil, fmt.Errorf("%w: %w", errState, err)
	}
	return &stateDir{dir: fh, path: path}, nil
}

// lock takes the exclusive lock on the directory within budget, polling. Closing the directory releases it.
func (d *stateDir) lock(budget time.Duration) error {
	rc, err := d.dir.SyscallConn()
	if err != nil {
		return fmt.Errorf("%w: %w", errState, err)
	}
	deadline := time.Now().Add(budget)
	for {
		var ferr error
		if err := rc.Control(func(fd uintptr) { ferr = unix.Flock(int(fd), unix.LOCK_EX|unix.LOCK_NB) }); err != nil {
			return fmt.Errorf("%w: %w", errState, err)
		}
		switch {
		case ferr == nil:
			return nil
		case errors.Is(ferr, unix.EINTR):
			continue
		case !errors.Is(ferr, unix.EWOULDBLOCK):
			return fmt.Errorf("%w: flock: %w", errState, ferr)
		case time.Now().After(deadline):
			return fmt.Errorf("%w (%v)", errLockTimeout, budget)
		}
		time.Sleep(lockPoll)
	}
}

// close closes the directory and so releases the lock.
func (d *stateDir) close() { _ = d.dir.Close() } // a read-only directory: nothing to flush

// read is the state file of run: the zero state of run when there is none yet; refused when it is a link, not a
// regular file, longer than MaxStateBytes, not a v1 state, or another run's.
func (d *stateDir) read(run string) (State, error) {
	fh, err := openRegular(filepath.Join(d.path, StateFileName))
	switch {
	case errors.Is(err, unix.ENOENT):
		return State{V: StateVersion, Run: run}, nil
	case errors.Is(err, unix.ELOOP):
		return State{}, errStateLink
	case err != nil:
		return State{}, fmt.Errorf("%w: %w", errState, err)
	}
	defer func() { _ = fh.Close() }() // read-only: nothing to flush
	b, err := io.ReadAll(io.LimitReader(fh, MaxStateBytes+1))
	if err != nil {
		return State{}, fmt.Errorf("%w: %w", errState, err)
	}
	if len(b) > MaxStateBytes {
		return State{}, fmt.Errorf("%w: %s is more than %d bytes", errState, StateFileName, MaxStateBytes)
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}, fmt.Errorf("%w: %s: %w", errState, StateFileName, err)
	}
	if s.V != StateVersion || s.Run != run {
		return State{}, fmt.Errorf("%w: %s is v %d of run %q, not v %d of %q", errState, StateFileName, s.V, s.Run, StateVersion, run)
	}
	return s, nil
}

// write replaces the state file with s: written whole to a temporary name and renamed over it, so a hook killed
// mid-write leaves the old state, never a torn one.
func (d *stateDir) write(s State) error {
	b, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("%w: %w", errState, err)
	}
	tmp := filepath.Join(d.path, stateTmpName)
	fh, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|unix.O_NOFOLLOW, 0o600)
	if errors.Is(err, unix.ELOOP) {
		return errStateLink
	}
	if err != nil {
		return fmt.Errorf("%w: %w", errState, err)
	}
	if _, err := fh.Write(b); err != nil {
		_ = fh.Close() // the write failed already; the temporary file is truncated next time
		return fmt.Errorf("%w: %w", errState, err)
	}
	if err := fh.Close(); err != nil {
		return fmt.Errorf("%w: %w", errState, err)
	}
	if err := os.Rename(tmp, filepath.Join(d.path, StateFileName)); err != nil {
		return fmt.Errorf("%w: %w", errState, err)
	}
	return nil
}

// errNotRegular is a file the hook reads that is not a regular file.
var errNotRegular = errors.New("not a regular file")

// openRegular opens path to read without following a link at its last element or blocking on a FIFO, and refuses
// anything but a regular file.
func openRegular(path string) (*os.File, error) {
	fh, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	st, err := fh.Stat()
	if err == nil && !st.Mode().IsRegular() {
		err = fmt.Errorf("%s: %w", path, errNotRegular)
	}
	if err != nil {
		_ = fh.Close() // read-only and refused: nothing to flush
		return nil, err
	}
	return fh, nil
}

// claim returns the entries of f above s's cursor, the ones the file still lists at
// or below its cursor, and how many more the file no longer lists. When there are any, s accounts for every
// refusal of f afterwards and counts the note; when there are none, s is unchanged.
func claim(f *reason.File, s *State) (entries []reason.Entry, notListed uint64) {
	if f == nil || f.Seq <= s.Cursor {
		return nil, 0
	}
	entries, notListed = f.Since(s.RefusalsDelivered)
	for len(entries) > 0 && entries[0].Seq <= s.Cursor {
		entries = entries[1:]
	}
	if len(entries) == 0 && notListed == 0 {
		return nil, 0
	}
	s.Cursor, s.RefusalsDelivered = f.Seq, f.Refusals
	s.Deliveries++
	return entries, notListed
}
