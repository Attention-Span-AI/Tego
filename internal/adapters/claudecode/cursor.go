// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
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
	// StateVersion is the state file's own version: 2 holds a cursor for each harness and the claims not yet printed
	// (ADR 0063, D46). A v1 file is refused, as any other version is; a run's directory is made for the run.
	StateVersion = 2
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

// State is hook-state/state.json: the cursors every hook process of the run shares, the claims whose note is not yet
// marked printed, and the counts the launcher is meant to read into run_end's reason_delivery at the run's end
// (reported_by: hook). It lives where the agent can write, so it is the agent's own account: any process of the run can
// rewrite it, another session's included, so it can raise a cursor or leave a claim pending to hide that session's notes.
// Ownership separates honest hooks, not a hostile process of the run; the ledger stays authoritative.
type State struct {
	V   int    `json:"v"`
	Run string `json:"run"`
	// Cursor is the highest seq claimed among the refusals nobody owns (the writer did not know the refused
	// process's ancestry), 0 for none; later-start previews do not advance it.
	Cursor uint64 `json:"cursor"`
	// Owned is, for each harness (its "pid:start" identity), the highest seq claimed among the refusals its
	// processes drew: one cursor per session. Bounded by what fits MaxStateBytes (the lowest are dropped first).
	Owned map[string]uint64 `json:"owned,omitempty"`
	// Harnesses are the harnesses whose hooks ran and are still there (each hook adds its own and drops the ones that
	// are gone): a refusal whose owners name none of them is shared, told by the shared cursor as before ownership. The
	// nearest of these in a refusal's owners owns it (ADR 0063, D46).
	Harnesses []string `json:"harnesses,omitempty"`
	// Sessions is how many SessionStart events the hook answered.
	Sessions uint64 `json:"sessions"`
	// Deliveries counts the notes marked printed: a hook's output was written to the harness without error. It is not
	// a count of notes the model received; Tego cannot see that.
	Deliveries uint64 `json:"deliveries"`
	// RefusalsDelivered is the refusal count at the last claim (reason.File.Since's cursor), including those no
	// longer listed; it accounts for refusals the file stopped listing once, to whichever hook claimed first. Later-start
	// previews leave it unchanged.
	RefusalsDelivered uint64 `json:"refusals_delivered"`
	// Pending are the claims whose hook has not yet marked its note printed, at most maxPending.
	Pending []Claim `json:"pending,omitempty"`
}

// Claim is one hook's claim on refusals, made under the lock before it prints and removed under the lock after its
// output was written without error. A hook that dies or fails in between leaves it, and the next hook of the same
// harness (any hook, for a claim made by a hook with no harness) tells the refusals again: at least once.
type Claim struct {
	// Owner is the harness identity the claim was made for, "" for a hook with none.
	Owner string `json:"owner"`
	// By is the claiming hook process's "pid:start" identity.
	By string `json:"by"`
	// At is when it claimed, in Unix seconds.
	At int64 `json:"at"`
	// Seqs are the refusals the claim took, oldest first.
	Seqs []uint64 `json:"seqs,omitempty"`
	// NotListed is how many refusals the file no longer listed that the claim reported.
	NotListed uint64 `json:"not_listed,omitempty"`
}

const (
	// maxPending bounds Pending; a hook that would pass it prints nothing and claims nothing, so the refusals stay
	// for a later hook.
	maxPending = 8
	// claimStale is how old a claim may get before another hook of its owner tells its refusals again though the
	// claimer is still there: past the hook timeout Claude Code ends a hook, so none prints after it.
	claimStale = (HookTimeout + 1) * time.Second
)

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

// claim takes the refusals of f the hook of harness owner has not claimed, and returns them oldest first with how
// many more the file no longer lists. It is, in order: those listed with no owners above the shared cursor (every
// refusal, for owner ""); those the harness owns above its own cursor; and the redo seqs, refusals an earlier claim of this
// owner took that were never marked printed (a seq the file no longer lists is counted as not listed). carry is the
// not-listed count of those claims. When there are any, s accounts for every refusal of f afterwards and the caller
// records the claim; when there are none, s is unchanged.
func claim(f *reason.File, s *State, owner string, redo map[uint64]bool, carry uint64) (entries []reason.Entry, notListed uint64) {
	if f == nil {
		return nil, 0
	}
	_, notListed = f.Since(s.RefusalsDelivered)
	notListed += carry
	listed := make(map[uint64]bool, len(f.Recent))
	ownedClaimed := false
	for _, e := range f.Recent {
		listed[e.Seq] = true
		switch {
		case redo[e.Seq]:
		default:
			nearest := ""
			if owner != "" {
				nearest = e.Nearest(s.Harnesses)
			}
			switch {
			case e.Owners == "" || owner == "" || nearest == "":
				// Nobody's; or the hook found no harness (it cannot tell whose an owned refusal is, and a note told to
				// the wrong session beats a note told to none); or none of the refusal's owners is a harness that has a
				// hook (a process reparented away from its harness, a session that is gone): the shared cursor, as
				// before ownership.
				if e.Seq <= s.Cursor {
					continue
				}
			case nearest == owner:
				if e.Seq <= s.Owned[owner] {
					continue
				}
				ownedClaimed = true
			default:
				continue // another session's: the nearest harness with a hook owns it
			}
		}
		entries = append(entries, e)
	}
	for seq := range redo {
		if !listed[seq] {
			notListed++
		}
	}
	if len(entries) == 0 && notListed == 0 {
		return nil, 0
	}
	s.Cursor = max(s.Cursor, f.Seq)
	if ownedClaimed {
		if s.Owned == nil {
			s.Owned = map[string]uint64{}
		}
		s.Owned[owner] = max(s.Owned[owner], f.Seq)
	}
	s.RefusalsDelivered = max(s.RefusalsDelivered, f.Refusals)
	return entries, notListed
}

// reap takes from s.Pending the claims this hook (harness owner) tells again: its owner's, or a claim of a hook with
// no harness, whose claimer is gone or whose claim is older than claimStale. It returns their seqs and not-listed
// counts. A claim of another harness is left for that harness's next hook, however old, and dropped only when that
// harness is gone (its pid and start time no longer name a process), so a session that runs no hook for a while does not
// lose a note.
func reap(s *State, owner string, p procs) (redo map[uint64]bool, carry uint64) {
	now := p.now()
	kept := s.Pending[:0:0]
	for _, c := range s.Pending {
		age := now.Sub(time.Unix(c.At, 0))
		gone := age > claimStale || !p.alive(c.By)
		switch {
		case gone && (c.Owner == owner || c.Owner == ""):
			if redo == nil {
				redo = map[uint64]bool{}
			}
			for _, q := range c.Seqs {
				redo[q] = true
			}
			carry += c.NotListed
		case gone && c.Owner != "" && !p.alive(c.Owner):
		default:
			kept = append(kept, c)
		}
	}
	s.Pending = kept
	if len(s.Pending) == 0 {
		s.Pending = nil
	}
	return redo, carry
}

// fit makes s small enough for MaxStateBytes by dropping the lowest cursors of harnesses other than keep, and says
// whether it is.
func fit(s *State, keep string) bool {
	for {
		b, err := json.Marshal(s)
		if err != nil {
			return false
		}
		if len(b) <= MaxStateBytes {
			return true
		}
		low, lowSeq := "", ^uint64(0)
		for k, v := range s.Owned {
			if k != keep && v < lowSeq {
				low, lowSeq = k, v
			}
		}
		if low == "" {
			return false
		}
		delete(s.Owned, low)
	}
}

// maxHarnesses bounds State.Harnesses: a run with more live sessions than this has the oldest ones' refusals told as
// shared (before ownership, every refusal was).
const maxHarnesses = 16

// recordHarness is harnesses with the ones that are gone left out and owner, this hook's harness, added at the end
// when it has one and is not there.
func recordHarness(harnesses []string, owner string, p procs) []string {
	out := make([]string, 0, len(harnesses)+1)
	for _, h := range harnesses {
		if h == owner || p.alive(h) {
			out = append(out, h)
		}
	}
	if owner != "" && !slices.Contains(out, owner) {
		out = append(out, owner)
	}
	if len(out) > maxHarnesses {
		out = out[len(out)-maxHarnesses:]
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
