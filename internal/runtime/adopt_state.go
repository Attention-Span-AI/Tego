// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
)

// An adoption's state outside its ledger (ADR 0055): a record of what it moved and where from, and a
// lock on the process it adopts, both in a directory under the host state directory that root alone can write. The
// ledger cannot hold them: a root launcher hands the run directory to the invoking user, and what the adoption's
// reaper and `tego adopt --release` act on as root (which cgroup to move processes back to, which build to purge)
// must not be a file that user can rewrite.
//
//	/run/tego/adopted/<run id>.json           the record, written whole by rename, removed when the adoption ends
//	/run/tego/adopted/<run id>.release        a release request (ReleaseAdoption), who asked; removed with the record
//	/run/tego/adopted/target-<pid>-<start>    the adopted process's lock, held (flock) by whoever acts on the
//	                                           adoption: its adopter for its life, then a reaper or a release

// AdoptStateDir is the host's adoption records.
var AdoptStateDir = filepath.Join(hoststate.Path, "adopted")

// adoptStateOwner is the uid the records' directory and files must be owned by: root. A variable so a test can keep
// records in a directory of its own.
var adoptStateOwner = 0

// adoptStateParent makes and verifies the host state directory the records live in (hoststate.Open). A variable so a
// test can keep its records elsewhere.
var adoptStateParent = func() error {
	d, err := hoststate.Open()
	if err != nil {
		return err
	}
	return d.Close()
}

// ErrAlreadyAdopting is a process another adoption on this machine holds already.
var ErrAlreadyAdopting = errors.New("runtime: another tego is adopting this process")

// adoptRecord is what an adoption's reaper and a later release need, fixed by the adopter itself.
type adoptRecord struct {
	Run   string `json:"run"`
	Agent string `json:"agent"`
	// Dir is the run directory and Anchor the chain.log its head is anchored in.
	Dir    string `json:"dir"`
	Anchor string `json:"anchor"`
	// Mount is the cgroup2 mount; Scope the adoption's cgroup (absolute) and ScopeID its id; From the cgroup the agent
	// was found in, relative to the mount as /proc names it.
	Mount   string `json:"mount"`
	Scope   string `json:"scope"`
	ScopeID uint64 `json:"scope_id"`
	From    string `json:"from"`
	// Root is the adopted process; Adopter the tego that adopted it.
	Root    adopt.Identity `json:"root"`
	Adopter adopt.Identity `json:"adopter"`
	// Target is the tier-2 build and slot the run's programs live in, once Prepare has made them.
	Target *cgroupenforce.ReapTarget `json:"target,omitempty"`
	// Released says the run has ended and released its tree, but a process no cgroup took back stays in the scope
	// (gap adoption-left-in-scope): the record, and the scope, stay until a later release (`tego adopt --release`,
	// the reaper) moves it out, so that release has what to act on and nothing asks the ended adoption.
	Released bool `json:"released,omitempty"`
	// Left is how many processes that release left in the scope; Unstarted says the adoption failed before run_start
	// (its run directory was removed as a run that never started is), so a later release has no run_end to write.
	Left      int  `json:"left,omitempty"`
	Unstarted bool `json:"unstarted,omitempty"`
}

// adoptStore is the records' directory, verified as root's alone.
type adoptStore struct {
	dir string
}

// openAdoptStore makes dir (0700) under a verified host state directory and verifies it.
func openAdoptStore(dir string) (*adoptStore, error) {
	if dir == "" {
		dir = AdoptStateDir
	}
	if dir == AdoptStateDir {
		if err := adoptStateParent(); err != nil {
			return nil, fmt.Errorf("runtime: adoption records: %w", err)
		}
	}
	if err := unix.Mkdir(dir, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("runtime: adoption records: %w", &os.PathError{Op: "mkdir", Path: dir, Err: err})
	}
	s := &adoptStore{dir: dir}
	fd, err := s.open()
	if err != nil {
		return nil, err
	}
	_ = unix.Close(fd)
	return s, nil
}

// open opens the directory O_PATH, never through a link, and only when root alone can write it.
func (s *adoptStore) open() (int, error) {
	fd, err := unix.Open(s.dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("runtime: adoption records: %w", &os.PathError{Op: "open", Path: s.dir, Err: err})
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || int(st.Uid) != adoptStateOwner || st.Mode&0o077 != 0 {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("runtime: adoption records: %s is not root's alone (want uid %d, mode 0700)", s.dir,
			adoptStateOwner)
	}
	return fd, nil
}

// targetName is the lock file of one adopted process.
func targetName(id adopt.Identity) string { return fmt.Sprintf("target-%d-%d", id.PID, id.Start) }

// recordName is the record file of one run, refusing a name that is no run id.
func recordName(run string) (string, error) {
	if !ledger.IsRunID(run) {
		return "", fmt.Errorf("runtime: %q is not a run id", run)
	}
	return run + ".json", nil
}

// claim takes the lock of id, without waiting: ErrAlreadyAdopting when another adoption holds it. The lock is the
// file's flock, held through the returned file, and the file is checked to be the one the name still names after
// the lock is taken, since a holder that ended removes its file: a lock taken on a removed file is no lock.
func (s *adoptStore) claim(id adopt.Identity) (*os.File, error) {
	dfd, err := s.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(dfd) }()
	name := targetName(id)
	for range 3 {
		fd, err := unix.Openat(dfd, name, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err != nil {
			return nil, fmt.Errorf("runtime: adoption lock: %w", &os.PathError{Op: "open", Path: filepath.Join(s.dir, name), Err: err})
		}
		f := os.NewFile(uintptr(fd), filepath.Join(s.dir, name))
		if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			_ = f.Close()
			if errors.Is(err, unix.EWOULDBLOCK) {
				return nil, fmt.Errorf("%w (pid %d)", ErrAlreadyAdopting, id.PID)
			}
			return nil, fmt.Errorf("runtime: adoption lock: %w", err)
		}
		var held, named unix.Stat_t
		if unix.Fstat(fd, &held) == nil && unix.Fstatat(dfd, name, &named, unix.AT_SYMLINK_NOFOLLOW) == nil &&
			held.Dev == named.Dev && held.Ino == named.Ino && int(held.Uid) == adoptStateOwner {
			return f, nil
		}
		_ = f.Close() // the previous holder removed it between our open and our lock: take the new one
	}
	return nil, fmt.Errorf("%w (pid %d): its lock file keeps changing", ErrAlreadyAdopting, id.PID)
}

// unclaim removes id's lock file, then releases the lock: in that order, so no one can take the lock of a file that
// is about to be removed and believe it holds it.
func (s *adoptStore) unclaim(f *os.File, id adopt.Identity) {
	if f == nil {
		return
	}
	if dfd, err := s.open(); err == nil {
		_ = unix.Unlinkat(dfd, targetName(id), 0)
		_ = unix.Close(dfd)
	}
	_ = f.Close()
}

// write replaces run's record whole: a temporary file renamed over the name, so a reader never meets half of one.
func (s *adoptStore) write(rec adoptRecord) error {
	name, err := recordName(rec.Run)
	if err != nil {
		return err
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	dfd, err := s.open()
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(dfd) }()
	tmp := "." + name + ".tmp"
	_ = unix.Unlinkat(dfd, tmp, 0)
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("runtime: adoption record: %w", &os.PathError{Op: "create", Path: filepath.Join(s.dir, tmp), Err: err})
	}
	f := os.NewFile(uintptr(fd), tmp)
	_, werr := f.Write(b)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = unix.Renameat(dfd, tmp, dfd, name)
	}
	if werr != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return fmt.Errorf("runtime: adoption record: %w", werr)
	}
	return nil
}

// read reads run's record; os.ErrNotExist when there is none (the adoption ended and removed it).
func (s *adoptStore) read(run string) (adoptRecord, error) {
	name, err := recordName(run)
	if err != nil {
		return adoptRecord{}, err
	}
	dfd, err := s.open()
	if err != nil {
		return adoptRecord{}, err
	}
	defer func() { _ = unix.Close(dfd) }()
	fd, err := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return adoptRecord{}, &os.PathError{Op: "open", Path: filepath.Join(s.dir, name), Err: err}
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != adoptStateOwner ||
		st.Mode&0o077 != 0 {
		return adoptRecord{}, fmt.Errorf("runtime: adoption record %s is not root's alone", name)
	}
	var rec adoptRecord
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return adoptRecord{}, fmt.Errorf("runtime: adoption record %s: %w", name, err)
	}
	if rec.Run != run {
		return adoptRecord{}, fmt.Errorf("runtime: adoption record %s names run %q", name, rec.Run)
	}
	if !strings.HasSuffix(rec.Scope, "/"+adopt.ScopeName(run)) {
		return adoptRecord{}, fmt.Errorf("runtime: adoption record %s names scope %q, not the run's", name, rec.Scope)
	}
	return rec, nil
}

// remove removes run's record and its release request.
func (s *adoptStore) remove(run string) {
	name, err := recordName(run)
	if err != nil {
		return
	}
	if dfd, err := s.open(); err == nil {
		_ = unix.Unlinkat(dfd, name, 0)
		_ = unix.Unlinkat(dfd, run+releaseSuffix, 0)
		_ = unix.Close(dfd)
	}
}

// clearRequest removes run's release request alone: a request the adoption answered by releasing its tree, though
// processes stay in the scope with the record kept.
func (s *adoptStore) clearRequest(run string) {
	if _, err := recordName(run); err != nil {
		return
	}
	if dfd, err := s.open(); err == nil {
		_ = unix.Unlinkat(dfd, run+releaseSuffix, 0)
		_ = unix.Close(dfd)
	}
}

// AdoptionRecorded reports whether run has an adoption record in stateDir ("" is the host's), without making the
// directory: `tego stop` asks it to tell an adoption, which it releases, from a launched run, which it stops.
func AdoptionRecorded(stateDir, run string) bool {
	if stateDir == "" {
		stateDir = AdoptStateDir
	}
	name, err := recordName(run)
	if err != nil {
		return false
	}
	s := &adoptStore{dir: stateDir}
	dfd, err := s.open()
	if err != nil {
		return false
	}
	defer func() { _ = unix.Close(dfd) }()
	var st unix.Stat_t
	return unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG
}

// releaseSuffix names a run's release request: <run id>.release.
const releaseSuffix = ".release"

// maxReleaseBy bounds who-asked in a release request: one short sentence for run_end.
const maxReleaseBy = 200

// requestRelease asks run's adopter to release its agent (ReleaseAdoption): a file the adoption looks for while it
// waits (adoption.await), naming who asked. It is a file in the records' directory rather than a signal because one
// adopter can hold many adoptions (the guard), and a signal would end them all. Written whole by rename, as a record.
func (s *adoptStore) requestRelease(run, by string) error {
	if _, err := recordName(run); err != nil {
		return err
	}
	by = sanitizeReleaseBy(by)
	dfd, err := s.open()
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(dfd) }()
	name := run + releaseSuffix
	tmp := "." + name + ".tmp"
	_ = unix.Unlinkat(dfd, tmp, 0)
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("runtime: release request: %w", &os.PathError{Op: "create", Path: filepath.Join(s.dir, tmp), Err: err})
	}
	f := os.NewFile(uintptr(fd), tmp)
	_, werr := f.WriteString(by)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = unix.Renameat(dfd, tmp, dfd, name)
	}
	if werr != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return fmt.Errorf("runtime: release request: %w", werr)
	}
	return nil
}

// releaseRequested reads run's release request: who asked, and whether one is there. A request that is not root's
// alone (or no regular file) is no request.
func (s *adoptStore) releaseRequested(run string) (string, bool) {
	if _, err := recordName(run); err != nil {
		return "", false
	}
	dfd, err := s.open()
	if err != nil {
		return "", false
	}
	defer func() { _ = unix.Close(dfd) }()
	fd, err := unix.Openat(dfd, run+releaseSuffix, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", false
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != adoptStateOwner ||
		st.Mode&0o077 != 0 {
		return "", false
	}
	buf := make([]byte, maxReleaseBy)
	n, _ := unix.Read(fd, buf)
	return sanitizeReleaseBy(string(buf[:max(n, 0)])), true
}

// sanitizeReleaseBy keeps who-asked one printable line of at most maxReleaseBy bytes.
func sanitizeReleaseBy(by string) string {
	by = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, by)
	by = strings.TrimSpace(by)
	if len(by) > maxReleaseBy {
		by = strings.ToValidUTF8(by[:maxReleaseBy], "")
	}
	if by == "" {
		by = "root"
	}
	return by
}

// claimWait is claim, waiting while another holds the lock, up to wait: a release of an adoption whose adopter is
// gone (its reaper's, or `tego adopt --release`'s) takes the process's lock first, so two never release one
// adoption at once.
func (s *adoptStore) claimWait(ctx context.Context, id adopt.Identity, wait time.Duration) (*os.File, error) {
	deadline := time.Now().Add(wait)
	for {
		f, err := s.claim(id)
		if !errors.Is(err, ErrAlreadyAdopting) || !time.Now().Before(deadline) {
			return f, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(claimPoll):
		}
	}
}

// claimPoll is how often claimWait tries the lock again.
const claimPoll = 50 * time.Millisecond

// movesLockName is the host-wide lock every adopter holds while it rechecks its process and moves its tree
// (lockMoves). It is never removed: one root-owned file in the records' directory.
const movesLockName = "moves.lock"

// movesLockWait bounds how long an adopter waits for another adopter's move to finish. A move is a bounded number of
// passes over /proc (adopt.MaxRounds), tens of milliseconds; a holder this slow is refused, never waited on for ever.
var movesLockWait = 10 * time.Second

// ErrMovesBusy is an adoption that could not take the move lock within movesLockWait.
var ErrMovesBusy = errors.New("runtime: another adoption is moving processes")

// lockMoves takes the host-wide move lock (flock on movesLockName), waiting up to movesLockWait, and returns it held.
// Two adoptions whose trees overlap (the guard adopting an agent and, at once, an agent that agent started) would
// otherwise each check a shared process in its cgroup and each write it, the last write winning while both ledgers
// said it was theirs. Under the lock the second adopter's recheck sees the process already governed and refuses it,
// and its walk sees a moved member in another cgroup and skips it.
func (s *adoptStore) lockMoves(ctx context.Context) (*os.File, error) {
	dfd, err := s.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(dfd) }()
	fd, err := unix.Openat(dfd, movesLockName, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("runtime: adoption move lock: %w", &os.PathError{Op: "open", Path: filepath.Join(s.dir, movesLockName), Err: err})
	}
	f := os.NewFile(uintptr(fd), filepath.Join(s.dir, movesLockName))
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != adoptStateOwner {
		_ = f.Close()
		return nil, fmt.Errorf("runtime: adoption move lock: %s is not root's regular file", f.Name())
	}
	deadline := time.Now().Add(movesLockWait)
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			_ = f.Close()
			return nil, fmt.Errorf("runtime: adoption move lock: %w", err)
		}
		if !time.Now().Before(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("%w (waited %s)", ErrMovesBusy, movesLockWait)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-time.After(movesPoll):
		}
	}
}

// movesPoll is how often lockMoves tries the lock again.
const movesPoll = 5 * time.Millisecond
