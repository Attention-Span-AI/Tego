// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// The journal's layout under a ledger root (doc.go has the line format).
const (
	// JournalDirName is the journal's directory: <ledger_root>/.rule-changes, 0700.
	JournalDirName = ".rule-changes"
	// JournalFile is the journal itself, one JSON object per line, appended.
	JournalFile = "journal.jsonl"
	// BlobsDir holds each text a change replaced or wrote, as <sha256>.yaml.
	BlobsDir = "blobs"
	// LocksDir holds the per-contract lock files, <sha256 of the resolved path>.lock, journal.lock and prune.lock.
	LocksDir = "locks"
	// JournalVersion is the "v" this package writes.
	JournalVersion = 1
)

// maxLine is the longest journal line a reader takes.
const maxLine = 4 << 20

// The journal's ops.
const (
	OpChange = "change" // a contract was replaced with new text
	OpRevert = "revert" // a change (or a revert) was undone: the contract got back its old text
	OpLive   = "live"   // what "also apply now" (or an Undo's lift) did for the change named by of, recorded after it
)

// lockWait bounds how long a writer waits for another writer's lock on the same contract.
const lockWait = 3 * time.Second

// ErrJournal is a contract that was written but whose change could not be recorded: the file holds the new text,
// and the error says where the old one is.
var ErrJournal = errors.New("rulefile: the change was written but not journaled")

// ErrSame is a write of the text the file already holds: nothing to change, nothing written.
var ErrSame = errors.New("rulefile: the new text is what the contract already holds")

// ErrNoChange is a Revert of an id the journal does not hold as a change or revert, or an Undo with nothing left to
// undo.
var ErrNoChange = errors.New("rulefile: no such change")

// Change is what the journal records about a write beyond its bytes: who made it, from where, and what it means.
type Change struct {
	// Via is the writer, "cli" or "dashboard"; "" is read from the program's name (tego-control is the dashboard,
	// tego the command line).
	Via string
	// Run and Line are the run and its line the change was made from; "" and 0 for a change made from no event.
	Run  string
	Line uint64
	// Summary is the change in words (internal/check/rule's Result.Summary).
	Summary string
	// Sentences are the rules' sentences the change adds or removes, "before → after", when known.
	Sentences []string
	// Direction is narrows, widens or mixed, when known.
	Direction string
	// Live are the outcomes of "also apply now" done before the write; AppendLive records ones done after.
	Live []Live
}

// SentenceLine is one of a change's sentences as Change.Sentences records it: "before → after", with "(nothing)" for a
// rule the file did not have before. `tego rule` and the dashboard both journal their sentences in this form, and the
// dashboard reads the after half back to say what an undo undid.
func SentenceLine(before, after string) string {
	if before == "" {
		before = "(nothing)"
	}
	return before + " → " + after
}

// Live is one live block "also apply now" placed (or failed to place) on a running run, or, with Lift, one an Undo
// lifted (or failed to lift) from it.
type Live struct {
	Run   string `json:"run"`
	Block string `json:"block"` // the live block, as liveblock spells it: exec:git, net:h:443, path:/abs
	OK    bool   `json:"ok"`
	Err   string `json:"err,omitempty"`
	// Lift marks a removal: an Undo lifted the block the change it undid had placed (recorded on the revert).
	Lift bool `json:"lift,omitempty"`
}

// Placed reports whether l records a live block placed on its run: done, and not a lift.
func (l Live) Placed() bool { return l.OK && !l.Lift && l.Block != "" }

// Entry is one journal line (doc.go).
type Entry struct {
	V         int       `json:"v"`
	ID        string    `json:"id"`
	Op        string    `json:"op"`
	At        time.Time `json:"at"`
	Via       string    `json:"via,omitempty"`
	UID       int       `json:"uid"`
	PID       int       `json:"pid"`
	Contract  string    `json:"contract,omitempty"`
	OldSHA256 string    `json:"old_sha256,omitempty"`
	NewSHA256 string    `json:"new_sha256,omitempty"`
	Bak       string    `json:"bak,omitempty"`
	Run       string    `json:"run,omitempty"`
	Line      uint64    `json:"line,omitempty"`
	Summary   string    `json:"summary,omitempty"`
	Sentences []string  `json:"sentences,omitempty"`
	Direction string    `json:"direction,omitempty"`
	Reverts   string    `json:"reverts,omitempty"`
	Of        string    `json:"of,omitempty"`
	Live      []Live    `json:"live,omitempty"`
	// UndoneBy is the id of the revert that undid this entry and is not itself undone; History sets it.
	UndoneBy string `json:"-"`
}

// now is the journal's clock; a test replaces it.
var now = time.Now

// Replace writes text over the contract at path when the file still holds base (a sha256 from Read or Sum of the text
// a change was planned on), under the contract's lock and through every guard of Read, keeps <file>.bak, and records
// the change in g.LedgerRoot's journal with the old and new text as blobs. A file that holds something else is
// ErrStale and nothing is written.
func Replace(ctx context.Context, g Guard, path, base string, text []byte, c Change) (*Entry, error) {
	return replace(ctx, g, path, base, text, c, OpChange, "")
}

func replace(ctx context.Context, g Guard, path, base string, text []byte, c Change, op, reverts string) (*Entry, error) {
	if g.LedgerRoot == "" {
		return nil, errors.New("rulefile: no ledger root to journal the change in, so nothing is written")
	}
	if len(text) > agent.MaxContractSize {
		return nil, fmt.Errorf("%w: the new text is %d bytes, more than a contract may be (%d)", ErrGuard, len(text), agent.MaxContractSize)
	}
	p, err := pin(path, g)
	if err != nil {
		return nil, err
	}
	defer p.close()
	j, err := openJournal(g.LedgerRoot)
	if err != nil {
		return nil, err
	}
	defer j.close()
	unlock, err := j.lock(ctx, Sum([]byte(p.path))+".lock")
	if err != nil {
		return nil, err
	}
	defer unlock()
	cur, err := p.read()
	if err == nil {
		err = step("read")
	}
	if err != nil {
		return nil, err
	}
	if cur.SHA256 != base {
		return nil, fmt.Errorf("%w: %s holds other text than the change was made from; nothing was written, look again", ErrStale, p.path)
	}
	next := Sum(text)
	if next == cur.SHA256 {
		return nil, ErrSame
	}
	unshare, err := j.share(ctx)
	if err != nil {
		return nil, err
	}
	defer unshare()
	// The blobs go first: a change that lands is always one that can be undone.
	if err := j.putBlob(cur.Text, cur.SHA256); err != nil {
		return nil, fmt.Errorf("journal the old text: %w", err)
	}
	if err := j.putBlob(text, next); err != nil {
		return nil, fmt.Errorf("journal the new text: %w", err)
	}
	bak, err := p.replace(cur, text)
	if err != nil {
		return nil, err
	}
	e := &Entry{V: JournalVersion, ID: newID(), Op: op, At: now().UTC(), Via: c.Via, UID: geteuid(), PID: os.Getpid(),
		Contract: p.path, OldSHA256: cur.SHA256, NewSHA256: next, Bak: bak, Run: c.Run, Line: c.Line, Summary: c.Summary,
		Sentences: c.Sentences, Direction: c.Direction, Reverts: reverts, Live: c.Live}
	if e.Via == "" {
		e.Via = progVia()
	}
	if err := step("journal"); err != nil {
		return e, fmt.Errorf("%w: %s holds the new text, the old text is %s: %v", ErrJournal, p.path, bak, err)
	}
	if err := j.append(ctx, e); err != nil {
		return e, fmt.Errorf("%w: %s holds the new text, the old text is %s: %v", ErrJournal, p.path, bak, err)
	}
	return e, nil
}

// RevertOptions are a revert's: what the journal records of it, and the compiler.
type RevertOptions struct {
	Change Change
	// Check is the compiler: nil when the old text still compiles as the contract. A nil Check writes it unchecked;
	// a caller that can compile passes one, since a profile the old text extends may have changed since.
	Check func([]byte) error
}

// Revert gives the contract of the change id its old text back, only while the file holds the text that change
// wrote (ErrStale otherwise: something changed it since, and a revert would lose that). The old text comes from the
// change's blob, checked against its sha256. It is journaled as a revert of id.
func Revert(ctx context.Context, g Guard, id string, o RevertOptions) (*Entry, error) {
	es, err := ReadJournal(g.LedgerRoot)
	if err != nil {
		return nil, err
	}
	for i := len(es) - 1; i >= 0; i-- {
		if es[i].ID == id && (es[i].Op == OpChange || es[i].Op == OpRevert) {
			return revert(ctx, g, &es[i], o)
		}
	}
	return nil, fmt.Errorf("%w: the journal holds no change %q", ErrNoChange, id)
}

// Undo reverts the newest change of the contract at path that is not undone yet and wrote what the file holds now,
// so repeated Undos walk back through every change the journal holds: all of them inside the retention, and at least
// the newest KeepChanges that stand beyond it while the file is there (Prune). ErrNoChange when there is none.
func Undo(ctx context.Context, g Guard, path string, o RevertOptions) (*Entry, error) {
	cur, err := Read(path, g)
	if err != nil {
		return nil, err
	}
	hist, err := History(g.LedgerRoot, cur.Path)
	if err != nil {
		return nil, err
	}
	for i := range hist {
		e := &hist[i]
		if e.Op == OpChange && e.UndoneBy == "" && e.NewSHA256 == cur.SHA256 {
			return revert(ctx, g, e, o)
		}
	}
	return nil, fmt.Errorf("%w: nothing to undo for %s", ErrNoChange, cur.Path)
}

func revert(ctx context.Context, g Guard, e *Entry, o RevertOptions) (*Entry, error) {
	old, err := Blob(g.LedgerRoot, e.OldSHA256)
	if err != nil {
		return nil, fmt.Errorf("the text before change %s: %w", e.ID, err)
	}
	if o.Check != nil {
		if err := o.Check(old); err != nil {
			return nil, fmt.Errorf("the text before change %s no longer compiles, so it is not put back: %w", e.ID, err)
		}
	}
	c := o.Change
	if c.Summary == "" {
		c.Summary = "undid " + e.ID
		if e.Summary != "" {
			c.Summary += ": " + e.Summary
		}
	}
	r, err := replace(ctx, g, e.Contract, e.NewSHA256, old, c, OpRevert, e.ID)
	if errors.Is(err, ErrStale) {
		return nil, fmt.Errorf("%w: %s was changed after %s, so it is not undone (that would lose the later change)",
			ErrStale, e.Contract, e.ID)
	}
	return r, err
}

// AppendLive records what "also apply now" did for the change of, when it ran after the write.
func AppendLive(ctx context.Context, root, of string, live []Live) error {
	j, err := openJournal(root)
	if err != nil {
		return err
	}
	defer j.close()
	return j.append(ctx, &Entry{V: JournalVersion, ID: newID(), Op: OpLive, At: now().UTC(), Via: progVia(), UID: geteuid(),
		PID: os.Getpid(), Of: of, Live: live})
}

// ReadJournal is every line of root's journal, oldest first; none when there is no journal yet. A line that does not
// decode (a torn last line after a crash, a newer version's) is skipped.
func ReadJournal(root string) ([]Entry, error) {
	j, err := openJournalRead(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer j.close()
	f, err := j.openFile(JournalFile, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only
	var es []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.V != JournalVersion || e.ID == "" {
			continue
		}
		es = append(es, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", JournalFile, err)
	}
	return es, nil
}

// History is the creation, changes and reverts of the contract at path (resolved, as Read's File.Path and the journal
// spell it), newest first, each with the live outcomes recorded after it and UndoneBy set.
func History(root, path string) ([]Entry, error) {
	es, err := ReadJournal(root)
	if err != nil {
		return nil, err
	}
	return Fold(es, func(e Entry) bool { return e.Contract == path }), nil
}

// Fold is the creations, changes and reverts of es (a whole journal, oldest first, as ReadJournal reads it) that keep
// accepts, newest first, each with the live outcomes recorded after it merged into its Live and UndoneBy set: History
// for one contract, or every contract's for a feed of the journal (a nil keep keeps every one). A revert and the entry
// it undid are always of one contract, so keep takes or leaves whole contracts.
func Fold(es []Entry, keep func(Entry) bool) []Entry {
	live := map[string][]Live{}
	byID := map[string]int{}
	var out []Entry
	for _, e := range es {
		switch {
		case e.Op == OpLive:
			live[e.Of] = append(live[e.Of], e.Live...)
		case (e.Op == OpChange || e.Op == OpRevert || e.Op == OpCreate) && (keep == nil || keep(e)):
			byID[e.ID] = len(out)
			out = append(out, e)
		}
	}
	for i := range out {
		out[i].Live = append(slices.Clip(out[i].Live), live[out[i].ID]...)
	}
	// A revert undoes its target unless it is undone itself: walk newest first, so a revert's own state is known
	// before the entry it reverts is looked at.
	for i := len(out) - 1; i >= 0; i-- {
		if out[i].Op == OpRevert && out[i].UndoneBy == "" {
			if k, ok := byID[out[i].Reverts]; ok && k < i && out[k].UndoneBy == "" {
				out[k].UndoneBy = out[i].ID
			}
		}
	}
	slices.Reverse(out)
	return out
}

// Blob is the text whose sha256 is sum, from root's journal, checked against sum.
func Blob(root, sum string) ([]byte, error) {
	if !hexSum(sum) {
		return nil, fmt.Errorf("%w: %q is not a sha256", ErrNoChange, sum)
	}
	j, err := openJournalRead(root)
	if err != nil {
		return nil, err
	}
	defer j.close()
	return j.readBlob(sum)
}

// journal is the open journal directory and its two subdirectories, each opened with no symlink followed and
// checked: owned by this user and writable by no one else, since a revert writes back what a blob holds. root is the
// ledger root they are in, which a Prune lists the runs of.
type journal struct {
	root, dir, blobs, locks *sys.FD
}

// openJournal opens root's journal, making its directories (0700) when they are not there yet.
func openJournal(root string) (*journal, error) { return openJournalMode(root, true) }

// openJournalRead opens root's journal and makes nothing: os.ErrNotExist when there is none.
func openJournalRead(root string) (*journal, error) { return openJournalMode(root, false) }

func openJournalMode(root string, create bool) (*journal, error) {
	if root == "" {
		return nil, errors.New("rulefile: no ledger root")
	}
	r, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("ledger root: %w", err)
	}
	top, err := openDir(r)
	if err != nil {
		return nil, fmt.Errorf("ledger root %s: %w", r, err)
	}
	j := &journal{root: top}
	if j.dir, err = subdir(top, JournalDirName, create); err != nil {
		j.close()
		return nil, err
	}
	if j.blobs, err = subdir(j.dir, BlobsDir, create); err == nil {
		j.locks, err = subdir(j.dir, LocksDir, create)
	}
	if err != nil {
		j.close()
		return nil, err
	}
	return j, nil
}

func (j *journal) close() {
	for _, d := range []*sys.FD{j.root, j.dir, j.blobs, j.locks} {
		_ = d.Close() // directories opened read-only; a nil one answers ErrClosed
	}
}

// subdir opens name in parent (making it 0700 with create), refusing a symlink and one this user does not own or
// that its group or others may write.
func subdir(parent *sys.FD, name string, create bool) (*sys.FD, error) {
	if create {
		err := parent.Borrow(func(n int) error { return unix.Mkdirat(n, name, 0o700) })
		if err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, fmt.Errorf("make %s: %w", name, err)
		}
	}
	d, err := parent.Openat2(name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH})
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	var st unix.Stat_t
	if err := d.Fstat(&st); err != nil {
		_ = d.Close() // the fstat's error is the one to report
		return nil, err
	}
	if st.Uid != uint32(geteuid()) || st.Mode&0o022 != 0 {
		_ = d.Close() // the refusal is the error to report
		return nil, fmt.Errorf("%w: the journal's %s is owned by uid %d with mode %o; it must be yours and writable by "+
			"no one else", ErrGuard, name, st.Uid, st.Mode&0o777)
	}
	return d, nil
}

// openFile opens name in the journal directory and checks it as subdir does, plus a regular file with one link.
func (j *journal) openFile(name string, flags int) (*os.File, error) {
	return openChecked(j.dir, name, flags)
}

func openChecked(dir *sys.FD, name string, flags int) (*os.File, error) {
	var fd *sys.FD
	var err error
	if flags&unix.O_CREAT != 0 {
		fd, err = dir.Openat(name, unix.O_RDWR|unix.O_APPEND|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	} else {
		fd, err = dir.Openat(name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	var st unix.Stat_t
	if err := fd.Fstat(&st); err != nil {
		_ = fd.Close() // the fstat's error is the one to report
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(geteuid()) || st.Mode&0o022 != 0 {
		_ = fd.Close() // the refusal is the error to report
		return nil, fmt.Errorf("%w: the journal's %s is not a regular file of yours, with one link, writable by no one else",
			ErrGuard, name)
	}
	return fd.Release(name)
}

// lock flocks locks/name exclusively, waiting at most lockWait, and returns its release.
func (j *journal) lock(ctx context.Context, name string) (func(), error) {
	return j.flock(ctx, name, unix.LOCK_EX, "another change of this contract is being written; try again")
}

// share holds prune.lock shared for a write, from its first blob to its journal line: Prune holds it exclusively, so
// it never takes a blob a line is about to name for one no line names.
func (j *journal) share(ctx context.Context) (func(), error) {
	return j.flock(ctx, pruneLock, unix.LOCK_SH, "the rule-change journal is being pruned; try again")
}

// flock takes locks/name (made when it is not there) with how, LOCK_EX or LOCK_SH, waiting at most lockWait, and
// returns its release; busy is the error when another holder kept it all that time. Prune removes a contract's lock
// file while it holds its flock, so a lock is held only once the file locked is still the one at the name: a writer
// that opened the file before it went and locked it after would hold a lock no later writer sees, and it locks the
// name again instead.
func (j *journal) flock(ctx context.Context, name string, how int, busy string) (func(), error) {
	deadline := time.Now().Add(lockWait)
	for {
		l, err := sys.Strict(j.locks.Openat(name, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600))
		if err != nil {
			return nil, fmt.Errorf("lock: %w", err)
		}
		if err := step("lock"); err != nil {
			_ = l.Close() // the step's error is the one to report
			return nil, err
		}
		err = l.Flock(how | unix.LOCK_NB)
		if err == nil && j.holds(l, name) {
			return func() { _ = l.Close() }, nil // closing the file drops the flock
		}
		_ = l.Close() // not locked, or locked on a file Prune removed meanwhile: the next turn opens the name again
		if err == nil {
			err = unix.EWOULDBLOCK
		}
		if !errors.Is(err, unix.EWOULDBLOCK) || time.Now().After(deadline) || ctx.Err() != nil {
			if errors.Is(err, unix.EWOULDBLOCK) {
				err = errors.New(busy)
			}
			return nil, fmt.Errorf("lock: %w", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// holds is whether the lock file l is still locks/name.
func (j *journal) holds(l *sys.FD, name string) bool {
	var have, there unix.Stat_t
	return l.Fstat(&have) == nil && j.locks.Fstatat(name, &there, unix.AT_SYMLINK_NOFOLLOW) == nil &&
		have.Dev == there.Dev && have.Ino == there.Ino
}

// append writes e as one line at the end of the journal, under the journal's own lock, and syncs it.
func (j *journal) append(ctx context.Context, e *Entry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	unlock, err := j.lock(ctx, "journal.lock")
	if err != nil {
		return err
	}
	defer unlock()
	f, err := j.openFile(JournalFile, unix.O_CREAT)
	if err != nil {
		return err
	}
	line := slices.Concat(b, []byte{'\n'})
	// A crash mid-append leaves a torn last line with no newline: start on a line of our own, so the torn one
	// costs only itself.
	if st, err := f.Stat(); err == nil && st.Size() > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, st.Size()-1); err == nil && last[0] != '\n' {
			line = append([]byte{'\n'}, line...)
		}
	}
	_, werr := f.Write(line)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// putBlob keeps b as blobs/<sum>.yaml, unless a good copy is there already.
func (j *journal) putBlob(b []byte, sum string) error {
	if have, err := j.readBlob(sum); err == nil && bytes.Equal(have, b) {
		return nil
	}
	return writeFile(j.blobs, "."+sum+".", sum+".yaml", b)
}

// writeFile puts b in dir as name through a new file, prefix and random hex (O_EXCL, O_NOFOLLOW, 0600, fsync'ed),
// renamed over it, then fsyncs dir: a reader sees the old file or the new one, never part of one.
func writeFile(dir *sys.FD, prefix, name string, b []byte) error {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := prefix + hex.EncodeToString(rnd[:])
	fd, err := dir.Openat(tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	unlink := func() { _ = dir.Borrow(func(n int) error { return unix.Unlinkat(n, tmp, 0) }) }
	f, err := fd.Release(tmp)
	if err != nil {
		_ = fd.Close() // Release failed, so the owner still holds the number; its error is the one to report
		unlink()
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
		werr = dir.Borrow(func(n int) error { return unix.Renameat(n, tmp, n, name) })
	}
	if werr != nil {
		unlink() // werr is the one to report
		return werr
	}
	return dir.Fsync()
}

// readBlob is blobs/<sum>.yaml, checked against sum.
func (j *journal) readBlob(sum string) ([]byte, error) {
	f, err := openChecked(j.blobs, sum+".yaml", unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only
	b, err := io.ReadAll(io.LimitReader(f, agent.MaxContractSize+1))
	if err != nil {
		return nil, err
	}
	if Sum(b) != sum {
		return nil, fmt.Errorf("%w: the journal's blob %s does not hold the text it names", ErrGuard, sum)
	}
	return b, nil
}

// newID is a journal line's id: rc-<UTC time>-<8 random hex digits>, which sorts by time.
func newID() string {
	var rnd [4]byte
	_, _ = rand.Read(rnd[:]) // crypto/rand never fails on Linux (Go 1.24+ panics rather than return an error)
	return "rc-" + now().UTC().Format("20060102T150405.000000Z") + "-" + hex.EncodeToString(rnd[:])
}

// progVia is the Via of a writer that named none: the dashboard for tego-control, the command line for tego, else
// the program's own name.
func progVia() string {
	switch b := filepath.Base(os.Args[0]); b {
	case "tego-control":
		return "dashboard"
	case "tego":
		return "cli"
	default:
		return b
	}
}

func hexSum(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
