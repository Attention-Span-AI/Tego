// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// The overlay's files in the run directory.
const (
	// FileName is the overlay: <ledger_root>/<run>/live-block.json.
	FileName = "live-block.json"
	// LockName is the writers' lock, flocked for each read-modify-write so two writers (the CLI and the
	// dashboard) never lose each other's change.
	LockName = "live-block.lock"
	// ControlName is the launcher's mark that it reads a pause and a resume (OpPause, OpResume): an empty file it
	// makes once its live-block poll runs over a run cgroup it can freeze (MarkControl). A writer asks a pause only of
	// a run whose directory has it (TakesControl). A launcher from before the pause refuses the whole overlay once
	// it lists one, so a pause written to it would never take and every later live block of the run would stay
	// waiting; an adopted run, or one with no cgroup of its own, has no poll or nothing to freeze. None of them
	// makes the mark. It is a mark of capability, not of authority: a same-uid process could make it, as it could
	// write the overlay itself (ADR 0123).
	ControlName = "live-control"
	// RealName is the launcher's mark that it reads a block's real path (Entry.Real, VersionReal): an empty file it
	// makes once its live-block poll runs (MarkReal). A writer stores a real path only for a run whose directory has
	// it (TakesReal). A launcher from before the real path refuses the whole overlay once it is VersionReal, keeps the
	// blocks it last read and ignores every later change, so a real path written to it would undo every later block.
	// Like ControlName it is a mark of capability, not of authority.
	RealName = "live-real"
	// LinkName is the launcher's mark that it reads a block that matches by link (Entry.Match, VersionLink): an empty
	// file it makes once its live-block poll runs (MarkLink). A writer places such a block only on a run whose
	// directory has it (TakesLink), and the whole-file block otherwise: a launcher from before it refuses the whole
	// overlay once it is VersionLink, keeps the blocks it last read and ignores every later change. Like ControlName it
	// is a mark of capability, not of authority.
	LinkName = "live-link"
	// WordsName is the launcher's mark that it reads a command-word block (an exec entry whose value has words, IsWords,
	// VersionWords, ADR 0171): an empty file it makes once its live-block poll runs (MarkWords). A writer places such a
	// block only on a run whose directory has it (TakesWords) and refuses the run otherwise, in words: a launcher from
	// before it refuses the whole overlay once it is VersionWords, keeps the blocks it last read and ignores every
	// later change, and a whole-program block placed instead would refuse more than the rules the person changed do.
	// Like ControlName it is a mark of capability, not of authority.
	WordsName = "live-words"
	// NoteName is the launcher's mark that it reads a lift's note (Change.Note, LiftMAC's second domain): an empty file it
	// makes once its live-block poll runs (MarkNote). A writer signs and writes a note only for a run whose directory
	// has it (TakesNote): a launcher from before the note checks the lift's MAC without it and refuses the lift
	// (refused mac), so a note written to it would undo the lift itself. Like ControlName it is a mark of capability, not
	// of authority.
	NoteName = "live-note"
	// PlaneName is the launcher's mark that its run's kernel decision plane holds the run's path, read and write blocks
	// too (MarkPlane): an empty file it makes once its live-block poll runs over a plane that decides file changes.
	PlaneName = "live-plane"
)

// lockWait bounds how long a writer waits for another writer's lock.
const lockWait = 3 * time.Second

// ErrUntrusted is an overlay file the launcher does not read: not a regular file, not owned by the launcher's user
// (or root), or writable by its group or others.
var ErrUntrusted = errors.New("liveblock: overlay file not trusted")

// Signature is what a poll compares to tell that the overlay changed: the writer replaces the file by a rename, so
// every write is a new inode. The zero value is no file.
type Signature struct {
	Dev, Ino        uint64
	Size            int64
	MtimeNS, CtNS   int64
	Exists, Errored bool
}

// Stat is the overlay's signature in dir, without opening it. A file that is not there is the zero Signature; one
// that cannot be stat'ed for another reason is Errored.
func Stat(dir string) Signature {
	var st unix.Stat_t
	if err := unix.Lstat(filepath.Join(dir, FileName), &st); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return Signature{}
		}
		return Signature{Errored: true}
	}
	return Signature{Dev: st.Dev, Ino: st.Ino, Size: st.Size, MtimeNS: st.Mtim.Nano(), CtNS: st.Ctim.Nano(), Exists: true}
}

// MarkControl makes dir's ControlName, the launcher's mark that it reads a pause (0600, no symlink followed); one
// already there is kept.
func MarkControl(dir string) error { return mark(dir, ControlName) }

// mark makes dir's name, an empty mark file (0600, no symlink followed); one already there is kept.
func mark(dir, name string) error {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

// TakesControl reports whether the launcher of the run in dir reads a pause: dir holds ControlName as a regular
// file (no symlink followed) owned by this process's effective user or root, as MarkControl makes it.
func TakesControl(dir string) bool { return marked(dir, ControlName) }

// marked reports whether dir holds name as a regular file (no symlink followed) owned by this process's effective
// user or root, as mark makes it.
func marked(dir, name string) bool {
	var st unix.Stat_t
	if err := unix.Lstat(filepath.Join(dir, name), &st); err != nil {
		return false
	}
	return st.Mode&unix.S_IFMT == unix.S_IFREG && (st.Uid == uint32(os.Geteuid()) || st.Uid == 0)
}

// MarkPlane makes dir's PlaneName, the launcher's mark that it puts path, read and write blocks in force in the run's
// kernel decision plane too (ADR 0124, amendment 2026-11-21), so a writer may say such a block is in force on a run
// whose plane decides file changes.
func MarkPlane(dir string) error { return mark(dir, PlaneName) }

// TakesPlane reports whether the launcher of the run in dir puts file blocks in force in its plane: dir holds PlaneName
// as MarkPlane made it.
func TakesPlane(dir string) bool { return marked(dir, PlaneName) }

// MarkNote makes dir's NoteName, the launcher's mark that it reads a lift's note (0600, no symlink followed); one
// already there is kept.
func MarkNote(dir string) error { return mark(dir, NoteName) }

// TakesNote reports whether the launcher of the run in dir reads a lift's note: dir holds NoteName as MarkNote makes
// it (as TakesControl checks ControlName).
func TakesNote(dir string) bool { return marked(dir, NoteName) }

// MarkReal makes dir's RealName, the launcher's mark that it reads a block's real path (0600, no symlink followed);
// one already there is kept.
func MarkReal(dir string) error { return mark(dir, RealName) }

// TakesReal reports whether the launcher of the run in dir reads a block's real path: dir holds RealName as MarkReal
// makes it (as TakesControl checks ControlName).
func TakesReal(dir string) bool { return marked(dir, RealName) }

// MarkLink makes dir's LinkName, the launcher's mark that it reads a block that matches by link (0600, no symlink
// followed); one already there is kept.
func MarkLink(dir string) error { return mark(dir, LinkName) }

// TakesLink reports whether the launcher of the run in dir reads a block that matches by link: dir holds LinkName as
// MarkLink makes it (as TakesControl checks ControlName).
func TakesLink(dir string) bool { return marked(dir, LinkName) }

// MarkWords makes dir's WordsName, the launcher's mark that it reads a command-word block (0600, no symlink followed);
// one already there is kept.
func MarkWords(dir string) error { return mark(dir, WordsName) }

// TakesWords reports whether the launcher of the run in dir reads a command-word block: dir holds WordsName as
// MarkWords makes it (as TakesControl checks ControlName).
func TakesWords(dir string) bool { return marked(dir, WordsName) }

// Read is the overlay in dir, decoded and validated against run. A file that is not there is os.ErrNotExist (no live
// blocks). A file is read only when it is a regular file, reached with no symlink followed, owned by this process's
// effective user or root, and not writable by group or others (ErrUntrusted).
func Read(dir, run string) (*Overlay, error) {
	f, err := os.OpenFile(filepath.Join(dir, FileName), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%w: %s is a symlink", ErrUntrusted, FileName)
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := sys.FstatFile(f, &st); err != nil {
		return nil, err
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrUntrusted, FileName)
	case st.Uid != uint32(os.Geteuid()) && st.Uid != 0:
		return nil, fmt.Errorf("%w: %s is owned by uid %d", ErrUntrusted, FileName, st.Uid)
	case st.Mode&0o022 != 0:
		return nil, fmt.Errorf("%w: %s is writable by its group or others", ErrUntrusted, FileName)
	case st.Size > MaxFileBytes:
		return nil, fmt.Errorf("%w: overlay of %d bytes, more than %d", ErrInvalid, st.Size, MaxFileBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	return Decode(b, run)
}

// Update is the one read-modify-write of the overlay in dir: under the writers' lock it reads the overlay (a new one
// when there is none), hands it to fn, and, when fn reports a change, writes it by an atomic rename (a temporary file
// in dir, fsync'ed, renamed over FileName, the directory fsync'ed). An overlay that is there but unreadable is an
// error, never replaced: the launcher keeps the last good one in force, and a new file written over it would drop
// those blocks. It returns the overlay as it now stands.
func Update(ctx context.Context, dir, run string, fn func(*Overlay) (bool, error)) (*Overlay, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	unlock, err := lock(ctx, dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	o, err := Read(dir, run)
	switch {
	case errors.Is(err, os.ErrNotExist):
		o = New(run)
	case err != nil:
		return nil, fmt.Errorf("the run's %s cannot be read, so it is not replaced (remove it to start over): %w", FileName, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := readClock()
	o.dropEnded(now)
	held := o.untilPins()
	changed, err := fn(o)
	o.pinUntils(held, now)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil || !changed {
		return o, err
	}
	b, err := o.Encode()
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(ctx, dir, b); err != nil {
		return nil, err
	}
	return o, nil
}

// endedKeep is how long a block stays in the file once its limit has ended. The launcher writes its expiry line from
// the file it last read, on the poll after the end, and the pages say "ended at" of an entry still listed, so an
// ended entry is kept a day; dropping it then keeps ended blocks from filling MaxBlocks over a long run.
const endedKeep = 24 * time.Hour

// dropEnded removes the blocks whose limit ended more than endedKeep before now, recording no change. Ended is the
// launcher's own rule (Ended, ADR 0125 decision 4, amendment 2026-11-18), asked endedKeep later on the same clocks:
//
//   - an entry pinned in this boot (Entry.UntilPin) is gone only when BOTH clocks are endedKeep past its limit, the
//     pin the launcher holds it by. The wall clock alone decided before, so a wall clock stepped forward more than a
//     day let a writer drop a block the launcher still refused by; a wall clock stepped back keeps it longer, as it
//     keeps the block itself in force longer;
//   - an entry pinned in another boot is gone by the wall clock alone: its launcher did not outlive that boot, and
//     its BOOTTIME instant counts from a start that is gone;
//   - an entry with no pin (written by a tego from before pins, or where the boot could not be named) is gone by the
//     wall clock alone, as it always was;
//   - where this boot cannot be named now, a pinned entry is kept: nothing says which of the two cases it is.
func (o *Overlay) dropEnded(now Clock) {
	o.Blocks = slices.DeleteFunc(o.Blocks, func(e Entry) bool {
		if e.Until.IsZero() {
			return false
		}
		gone := e.Until.Add(endedKeep)
		pin, pinned := e.UntilPin(now)
		switch {
		case pinned:
			return Ended(gone, pin+endedKeep, true, now) && now.Wall.After(gone)
		case e.Boot != "" && now.BootID == "":
			return false
		}
		return now.Wall.After(gone)
	})
}

// untilPins is the pin each limit of o's blocks carries now, by DeadlineKey: what pinUntils keeps for a limit that
// stood before a write. A limit with no pin is listed too, with none.
func (o *Overlay) untilPins() map[string]Entry {
	held := map[string]Entry{}
	for _, e := range o.Blocks {
		if !e.Until.IsZero() {
			held[DeadlineKey(e.Key(), e.Until)] = e
		}
	}
	return held
}

// pinUntils settles the pin of every block's limit after a write's change: a limit that stood before the write
// (held) keeps the pin it had, or none; a limit the write made is pinned at now, the write's own reading, in now's
// boot. A pin is made once, with its limit, and never again: the launcher holds the limit by the pin it first read,
// so a pin made later, after a clock step, would be another instant than the launcher's.
func (o *Overlay) pinUntils(held map[string]Entry, now Clock) {
	for i := range o.Blocks {
		e := &o.Blocks[i]
		e.Boot, e.UntilBoot = "", 0
		if e.Until.IsZero() {
			continue
		}
		if was, ok := held[DeadlineKey(e.Key(), e.Until)]; ok {
			e.Boot, e.UntilBoot = was.Boot, was.UntilBoot
			continue
		}
		if pin := now.Pin(e.Until); now.BootID != "" && now.Boot > 0 && pin > 0 {
			e.Boot, e.UntilBoot = now.BootID, pin
		}
	}
}

// lock flocks dir's LockName, waiting at most lockWait, and returns its release.
func lock(ctx context.Context, dir string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, LockName), os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("live-block lock: %w", err)
	}
	deadline := time.Now().Add(lockWait)
	for {
		if err := ctx.Err(); err != nil {
			_ = f.Close()
			return nil, err
		}
		err := sys.Flock(f, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { _ = f.Close() }, nil // closing the file drops the flock
		}
		if !errors.Is(err, unix.EWOULDBLOCK) || time.Now().After(deadline) || ctx.Err() != nil {
			_ = f.Close()
			if errors.Is(err, unix.EWOULDBLOCK) {
				err = errors.New("another writer holds it")
			}
			return nil, fmt.Errorf("live-block lock: %w", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// writeAtomic replaces dir's FileName with b: a new 0600 file, synced, renamed over it, and the directory synced.
func writeAtomic(ctx context.Context, dir string, b []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+FileName+"."+hex.EncodeToString(rnd[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		// A prior read or fsync may outlive a request. Never submit a new
		// overlay rename once that request's context has expired.
		werr = ctx.Err()
	}
	if werr == nil {
		werr = os.Rename(tmp, filepath.Join(dir, FileName))
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return werr
	}
	d, err := os.Open(dir)
	if err != nil {
		return nil // the rename is done; only its durability across a crash is not proved
	}
	_ = d.Sync()
	return d.Close()
}

// By is the by of a change this process makes, via "cli" or "dashboard": "uid:<uid> pid:<pid> <via>", the form
// an answer line's by has.
func By(via string) string {
	return fmt.Sprintf("uid:%d pid:%d %s", os.Getuid(), os.Getpid(), via)
}
