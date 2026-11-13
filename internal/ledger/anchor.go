// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"github.com/attention-span-ai/tego/pkg/spec/record/chaincheck"
)

// ChainAnchor records each run's final event id outside its run directory (§3 chain anchor), so a run's chain
// has a root of trust that deleting or editing the run directory cannot move.
type ChainAnchor interface {
	// Append records "<run> <head>" as one line; one write(2), then fsync.
	Append(run, head string) error
	// Head returns the anchored head of run; ok is false when none is recorded. Verification tooling only.
	Head(run string) (head string, ok bool, err error)
}

// DefaultAnchorPath is the anchor a Writer uses when its caller names none: the chain.log next to the
// ledger root (<ledger_root>/<run>/ → <ledger_root>/../chain.log). The product always names one — the
// invoking user's ~/.tego/chain.log whatever ledger_root is, and this same file only for an account
// with no home (AnchorPath, P0-DESIGN §3.3) — so this default is what tests and fixtures get; for the
// default ledger_root the two coincide.
func DefaultAnchorPath(runDir string) string {
	return filepath.Join(filepath.Dir(filepath.Clean(runDir)), "..", ChainLogFile)
}

// NewFileChainAnchor returns the anchor stored in the file at path, created 0600 on first Append.
func NewFileChainAnchor(path string) ChainAnchor { return &fileChainAnchor{path: path} }

type fileChainAnchor struct {
	path string
}

// Append writes one "<run> <head>\n" line with a single write(2) on O_APPEND (the R4 atomicity argument) and
// fsyncs it, as part of the run's Close.
//
// The file is opened without following a symlink and must be a regular file (with one link, for root):
// chain.log sits in the invoking user's ~/.tego, and a root launcher appending through a link that user
// planted would write "<run> <head>" into any file on the machine. For the same reason root reaches the
// directory through openDir, which refuses a link where the user could have made one — ~/.tego itself
// replaced by a symlink. A chain.log (or ~/.tego) root creates there is handed to the directory's owner
// before the line is written (handover.go), because a root-owned one would refuse every later unprivileged
// run's append; if that fails nothing is written and the error says why, rather than leave an anchor the
// user's next run cannot extend. A chain.log that already exists keeps its owner (openAnchor).
func (a *fileChainAnchor) Append(run, head string) error {
	if !IsRunID(run) || !record.IsID(head) {
		return fmt.Errorf("ledger: anchor: bad run %q or head %q", run, head)
	}
	f, err := openAnchorForAppend(a.path)
	if err != nil {
		return err
	}
	// Every appender holds the file's flock, so a tail without "\n" seen under it is a line an earlier
	// append left torn (a full disk, a crash), never one in flight: cut it before writing, or this line
	// would be glued onto it and the malformed result would fail Head for every run in the file (E28).
	werr := lockAndRepairTail(f)
	if werr == nil {
		line := run + " " + head + "\n"
		_, werr = f.Write([]byte(line))
	}
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("ledger: write anchor: %w", werr)
	}
	return nil
}

// ProbeAnchor opens the anchor at path for append exactly as Append will — its directory made if
// missing, chain.log created empty if missing, and only what it created handed over, as Append would —
// and writes nothing.
// `tego run` calls it before the agent starts, so an anchor the run could not extend at Close (an
// unwritable home, a planted link, a hard-linked chain.log) refuses the run instead of failing it after
// the agent already ran.
func ProbeAnchor(path string) error {
	f, err := openAnchorForAppend(path)
	if err != nil {
		return err
	}
	return f.Close()
}

// openAnchorForAppend opens the anchor at path for append, creating its directory and the file as needed.
func openAnchorForAppend(path string) (*os.File, error) {
	return openAnchor(filepath.Dir(path), filepath.Base(path), unix.O_RDWR|unix.O_CREAT|unix.O_APPEND)
}

// lockAndRepairTail takes f's exclusive flock (released when f is closed) and truncates an unterminated
// tail back to the last "\n".
func lockAndRepairTail(f *os.File) error {
	if err := sys.Flock(f, unix.LOCK_EX); err != nil {
		return fmt.Errorf("flock: %w", err)
	}
	st, err := f.Stat()
	if err != nil || st.Size() == 0 {
		return err
	}
	size := st.Size()
	buf := make([]byte, 4096)
	end := size
	for end > 0 {
		off := max(end-int64(len(buf)), 0)
		n, err := f.ReadAt(buf[:end-off], off)
		if err != nil && n < int(end-off) {
			return err
		}
		if end == size && buf[end-off-1] == '\n' {
			return nil
		}
		if i := bytes.LastIndexByte(buf[:end-off], '\n'); i >= 0 {
			return f.Truncate(off + int64(i) + 1)
		}
		end = off
	}
	return f.Truncate(0)
}

// Head scans the file for run's line. A trailing line without "\n" is skipped, never an error (E28); a
// malformed terminated line is ErrCorruptLedger. The file is opened as Append opens it, never through a
// symlink. A run is anchored once, at Close, so two lines for it can only be a re-anchor, of a ledger cut
// back and closed again for one: two that name different heads are ErrCorruptLedger, which Verify reports
// as unverified. The last line used to win, so appending a line re-anchored a truncated ledger; a line
// repeated with the same head is the same anchor.
func (a *fileChainAnchor) Head(run string) (string, bool, error) {
	f, err := openAnchor(filepath.Dir(a.path), filepath.Base(a.path), unix.O_RDONLY)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	defer func() { _ = f.Close() }()
	h := anchorHeads(f, []string{run})[run]
	return h.Head, h.OK, h.Err
}

// AnchorHead is what chain.log says of one run (chaincheck.AnchorHead): the head it anchors (OK), no line for it, or
// Err, which wraps ErrCorruptLedger when the file is not an anchor.
type AnchorHead = chaincheck.AnchorHead

// AnchorHeads is Head for many runs from one read of the chain anchor at path: for each of runs, what
// NewFileChainAnchor(path).Head(run) returns, read from the same bytes and opened the same way. fi is the
// file as fstat'ed before it was read: a caller that keeps the answers can stat path later and, finding the
// same file at the same size, mtime and ctime, know they still stand without reading it again. It is nil
// when there is no file or it could not be opened (each answer then says what Head says), and when the
// fstat failed (the answers are read all the same, and the caller cannot keep them). The dashboard keeps its
// chain verdicts that way (internal/control/ledgerview).
func AnchorHeads(path string, runs []string) (heads map[string]AnchorHead, fi os.FileInfo) {
	f, err := openAnchor(filepath.Dir(path), filepath.Base(path), unix.O_RDONLY)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
		heads = make(map[string]AnchorHead, len(runs))
		for _, r := range runs {
			heads[r] = AnchorHead{Err: err}
		}
		return heads, nil
	}
	defer func() { _ = f.Close() }()
	if fi, err = f.Stat(); err != nil {
		fi = nil
	}
	return anchorHeads(f, runs), fi
}

// anchorHeads reads chain.log for each of runs (chaincheck.AnchorHeads, CHAIN.md §7).
func anchorHeads(f io.ReaderAt, runs []string) map[string]AnchorHead {
	return chaincheck.AnchorHeads(f, runs)
}

// openAnchor opens name in dir with flags, never following a symlink at name and never blocking on a FIFO
// planted there, and returns it only when it is a regular file — with one link, when this process is root:
// a hard link is the other way to aim root's append at a file the directory's owner does not own. The
// directory is reached through openDir, created when flags has O_CREAT. With O_CREAT the file is created by
// an O_CREAT|O_EXCL open, and only a file this call created is handed to the directory's owner
// (openFileAt): a chain.log that was already there keeps its owner, since the user could have renamed a
// file of root's to that name, and chowning it would give them its contents (record-ledger.md §3).
func openAnchor(dir, name string, flags int) (*os.File, error) {
	create := flags&unix.O_CREAT != 0
	d, err := openDir(dir, create)
	if err != nil {
		return nil, fmt.Errorf("ledger: open anchor dir: %w", err)
	}
	defer func() { _ = d.Close() }()
	f, created, err := openFileAt(d, dir, name, flags&^unix.O_CREAT, create)
	if err != nil {
		return nil, fmt.Errorf("ledger: open anchor: %w", err)
	}
	if created {
		// The new entry in the anchor's directory, which the file's own fsync does not promise to persist
		// (R6): created once per machine and user. d is an O_PATH descriptor, which fsync refuses, so it is
		// synced through a readable one.
		if err := syncDirAt(d); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("ledger: fsync anchor dir: %w", err)
		}
	}
	return f, nil
}

// syncDirAt fsyncs the directory open at at, which may be O_PATH, through a readable descriptor of it, strict
// (a durability path: fsync first, and the close's error is reported). A filesystem that cannot fsync a
// directory (EINVAL, EROFS) is not a failure, as in syncDirs.
func syncDirAt(at *sys.FD) error {
	d, err := sys.Strict(at.Openat(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		return err
	}
	err = fsyncDir(d)
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EROFS) {
		return nil
	}
	return err
}

// AnchoredRuns lists run ids from complete, validated anchor lines, including runs whose
// directories disappeared. Verification uses these names to resolve abbreviations before
// it checks the selected head. A torn final line has never committed an anchor.
func AnchoredRuns(path string) ([]string, error) {
	f, err := openAnchor(filepath.Dir(path), filepath.Base(path), unix.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	seen := map[string]string{}
	var ids []string
	for l, err := range scanLines(f) {
		if err != nil {
			return nil, fmt.Errorf("ledger: read anchor: %w", err)
		}
		if !l.terminated {
			break
		}
		r, h, ok := bytes.Cut(l.data, []byte{' '})
		if !ok || !IsRunID(string(r)) || !record.IsID(string(h)) {
			return nil, fmt.Errorf("%w: invalid anchor line", ErrCorruptLedger)
		}
		id, head := string(r), string(h)
		if old, exists := seen[id]; exists {
			if old != head {
				return nil, fmt.Errorf("%w: chain.log holds two heads for %s", ErrCorruptLedger, id)
			}
			continue
		}
		seen[id] = head
		ids = append(ids, id)
	}
	return ids, nil
}
