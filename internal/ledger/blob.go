// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// BlobThreshold is the R10 split threshold: a payload field whose JSON value exceeds it is stored as a blob.
const BlobThreshold = 4096

// BlobRepository is a run's content-addressed store (R11: per run, never host-wide).
type BlobRepository interface {
	// Put stores b and returns its sha256 hex; identical content is stored once.
	Put(b []byte) (sha string, err error)
	// PutStream stores r's bytes in bounded memory and returns the sha256 hex and the size.
	PutStream(r io.Reader) (sha string, size int64, err error)
	// Get opens a blob for reading; os.ErrNotExist when absent.
	Get(sha string) (io.ReadCloser, error)
	// Has reports whether a blob is present.
	Has(sha string) (bool, error)
}

// NewBlobRepository returns the repository over runDir/blobs. It is the read side's constructor, and a
// uprobe source's store beside its run's Writer; a Writer exposes its own store through Blob and BlobFrom.
func NewBlobRepository(runDir string) BlobRepository {
	return &blobStore{dir: filepath.Join(runDir, BlobsDir)}
}

// blobStore is the only BlobRepository in P0: one directory of files named by their sha256.
type blobStore struct {
	dir string

	// fd is the blobs directory the store's Writer holds open from Open to Close, so every blob it
	// writes lands in the directory Open checked, whatever is renamed above it meanwhile
	// (record-ledger.md §3); nil for a store over a path. closed is set by the Writer's Close, after which
	// every operation is ErrClosed. fdMu keeps Close from closing the descriptor under an operation still
	// using it, so an operation's several calls on it all name the directory Open checked.
	fdMu   sync.RWMutex
	fd     *sys.FD
	closed bool

	mu      sync.Mutex
	pending []string // blob names written since the last Sync (fsync-at-close policy, §3)
	// overflow says more than maxPendingBlobs were written since the last Sync: their names are no longer
	// kept, and Sync flushes the whole filesystem instead (syncfs).
	overflow bool
}

// maxPendingBlobs bounds the names a store keeps for Close's fsyncs. An agent that execs a distinct argv over
// 4 KiB every second added one name, and one fsync at Close, for each without end (R15); past the bound one
// syncfs(2) of the blobs' filesystem makes all of them durable at once.
const maxPendingBlobs = 4096

// IsSHA reports whether s is 64 lowercase hex characters, the only shape a blob name may have. It also keeps a
// caller-supplied name from escaping the blobs directory.
func IsSHA(s string) bool { return record.IsID(s) }

func (s *blobStore) path(sha string) (string, error) {
	if !IsSHA(sha) {
		return "", fmt.Errorf("%w: %q", ErrBadSHA, sha)
	}
	return filepath.Join(s.dir, sha), nil
}

// withDir runs op on a descriptor of the blobs directory: the Writer's own, or, for a store over a path,
// one reached afresh by the walk of the hand-over rule (openDir), which as root refuses a symlink in a
// directory another user can change. Either way op resolves only single names relative to it, so what it
// writes lands in the directory that was checked, not wherever the path leads a moment later.
func (s *blobStore) withDir(op func(at *sys.FD) error) error {
	s.fdMu.RLock()
	defer s.fdMu.RUnlock()
	switch {
	case s.closed:
		return ErrClosed
	case s.fd != nil:
		return op(s.fd)
	}
	d, err := openDir(s.dir, false)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return op(d)
}

// close closes a Writer's directory descriptor; every later operation is ErrClosed.
func (s *blobStore) close() {
	s.fdMu.Lock()
	defer s.fdMu.Unlock()
	_ = s.fd.Close()
	s.closed = true
}

// Has reports whether blobs/<sha> exists.
func (s *blobStore) Has(sha string) (bool, error) {
	p, err := s.path(sha)
	if err != nil {
		return false, err
	}
	var st unix.Stat_t
	s.fdMu.RLock()
	switch {
	case s.closed:
		// A closed Writer's store never falls back to the path: the run directory may have moved since.
		s.fdMu.RUnlock()
		return false, ErrClosed
	case s.fd != nil:
		err = s.fd.Fstatat(sha, &st, 0)
	default:
		err = unix.Stat(p, &st)
	}
	s.fdMu.RUnlock()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("ledger: stat blob: %w", &os.PathError{Op: "stat", Path: p, Err: err})
	}
	return true, nil
}

// Get opens blobs/<sha>. Content is not re-verified on read (E16).
func (s *blobStore) Get(sha string) (io.ReadCloser, error) {
	p, err := s.path(sha)
	if err != nil {
		return nil, err
	}
	s.fdMu.RLock()
	defer s.fdMu.RUnlock()
	if s.closed {
		return nil, ErrClosed
	}
	if s.fd != nil {
		f, err := openRegularAt(s.fd, sha, p)
		if err != nil {
			return nil, fmt.Errorf("ledger: open blob: %w", err)
		}
		return f, nil
	}
	f, err := openRegular(p)
	if err != nil {
		return nil, fmt.Errorf("ledger: open blob: %w", err)
	}
	return f, nil
}

// Put hashes b first so a repeat write costs one stat (R11 dedup), then stores it.
func (s *blobStore) Put(b []byte) (string, error) {
	sum := sha256.Sum256(b)
	sha := hex.EncodeToString(sum[:])
	if ok, err := s.Has(sha); err != nil || ok {
		return sha, err
	}
	// b was hashed just now, so store writes it without hashing it again: sha256 was 69% of a blob's CPU,
	// and Put paid it twice.
	_, _, err := s.store(bytes.NewReader(b), sha)
	return sha, err
}

// PutStream streams r through sha256 into a temp file and links it under its hash.
func (s *blobStore) PutStream(r io.Reader) (string, int64, error) {
	return s.store(r, "")
}

// store copies r into blobs/.tmp-* (O_CREAT|O_EXCL, 0600) while hashing, then renames onto blobs/<sha> with
// RENAME_NOREPLACE. When the target exists by the time of the rename, a duplicate is already there and the
// temp file is discarded, the target left in place (its inode, its fsync state) and not re-read (R14). expect, when set, is r's sha256 the caller has already computed from the bytes
// r reads (Put), and r is written unhashed; "" hashes what is streamed (I8). Both files are
// named relative to the blobs directory's descriptor (withDir): the temp file is created O_EXCL|O_NOFOLLOW, so a
// name already there is never opened, and the rename never follows or replaces what sits at the content
// address.
func (s *blobStore) store(r io.Reader, expect string) (sha string, n int64, err error) {
	err = s.withDir(func(at *sys.FD) error {
		tmp, name, err := createTempAt(at, s.dir, tmpPrefix)
		if err != nil {
			return fmt.Errorf("ledger: blob temp: %w", err)
		}
		discard := func() { _ = tmp.Close(); _ = unlinkAt(at, name) }
		var dst io.Writer = tmp
		h := sha256.New()
		if expect == "" {
			dst = io.MultiWriter(tmp, h)
		}
		if n, err = io.Copy(dst, r); err != nil {
			discard()
			return fmt.Errorf("ledger: blob write: %w", err)
		}
		sha = expect
		if sha == "" {
			sha = hex.EncodeToString(h.Sum(nil))
		}
		if err := tmp.Close(); err != nil {
			_ = unlinkAt(at, name)
			return fmt.Errorf("ledger: blob close: %w", err)
		}
		err = at.Borrow(func(n int) error {
			err := unix.Renameat2(n, name, n, sha, unix.RENAME_NOREPLACE)
			if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) {
				// A filesystem without RENAME_NOREPLACE: plain rename, which replaces (last writer wins).
				err = unix.Renameat(n, name, n, sha)
			}
			return err
		})
		if err != nil {
			_ = unlinkAt(at, name)
			var st unix.Stat_t
			if at.Fstatat(sha, &st, unix.AT_SYMLINK_NOFOLLOW) == nil {
				return nil // R14: the content address is taken; the target stays, accepted, not verified
			}
			return fmt.Errorf("ledger: blob rename: %w", &os.LinkError{Op: "rename", Old: filepath.Join(s.dir, name),
				New: filepath.Join(s.dir, sha), Err: err})
		}
		s.mu.Lock()
		if len(s.pending) < maxPendingBlobs && !s.overflow {
			s.pending = append(s.pending, sha)
		} else {
			s.pending, s.overflow = nil, true
		}
		s.mu.Unlock()
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	return sha, n, nil
}

// tmpPrefix names the partial files store creates before renaming onto the content address. A process that
// dies inside store leaves one behind.
const tmpPrefix = ".tmp-"

// sweepTemp removes partial blobs left by a writer that died mid-store. It runs from Open, which has just
// taken the run's exclusive lock: no other Writer for this directory can exist, and the read side never
// stores, so every .tmp- file present is abandoned. Without this they survive until retention removes the run
// directory whole, holding as much disk as the bodies that were being written.
func (s *blobStore) sweepTemp() int {
	n := 0
	_ = s.withDir(func(at *sys.FD) error {
		names, err := readDirNames(at, s.dir)
		if err != nil {
			return err
		}
		for _, name := range names {
			if !strings.HasPrefix(name, tmpPrefix) {
				continue
			}
			if unlinkAt(at, name) == nil {
				n++
			}
		}
		return nil
	})
	return n
}

// readDirNames lists the directory open at at, through a descriptor of its own so at's offset and
// lifetime stay the caller's.
func readDirNames(at *sys.FD, path string) ([]string, error) {
	fd, err := at.Openat(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	d, err := fd.Release(path)
	if err != nil {
		_ = fd.Close()
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer func() { _ = d.Close() }()
	return d.Readdirnames(-1)
}

// Sync fsyncs every blob written since the last Sync and the blobs directory (the run's fsync-at-close
// policy, §3). It is idempotent and safe on a store with nothing pending.
func (s *blobStore) Sync() error {
	s.mu.Lock()
	pending, overflow := s.pending, s.overflow
	s.pending, s.overflow = nil, false
	s.mu.Unlock()
	if overflow {
		err := s.withDir(func(at *sys.FD) error {
			// syncfs(2) refuses an O_PATH descriptor (EBADF), which is what a path store's walk returns, so
			// it goes through a readable descriptor of the same directory.
			fd, err := sys.Strict(at.Openat(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
			if err != nil {
				return &os.PathError{Op: "open", Path: s.dir, Err: err}
			}
			err = fd.Borrow(syncfs)
			if cerr := fd.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return &os.PathError{Op: "syncfs", Path: s.dir, Err: err}
			}
			return nil
		})
		if err != nil {
			// Nothing was made durable: keep the flag so a later Sync tries again.
			s.mu.Lock()
			s.overflow = true
			s.mu.Unlock()
		}
		return err
	}
	if len(pending) == 0 {
		return nil
	}
	return s.withDir(func(at *sys.FD) error {
		// One blob that cannot be synced must not leave every blob after it unsynced.
		var errs []error
		for _, sha := range pending {
			if err := fsyncAt(at, sha, filepath.Join(s.dir, sha)); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(append(errs, fsyncAt(at, ".", s.dir))...)
	})
}

// fsyncAt fsyncs name in the directory open at at, never through a symlink at name. The descriptor is strict
// (ADR 0023: a durability path's close reports its error, synchronously).
func fsyncAt(at *sys.FD, name, path string) error {
	fd, err := sys.Strict(at.Openat(name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0))
	if err != nil {
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	err = fd.Fsync()
	if cerr := fd.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return &os.PathError{Op: "fsync", Path: path, Err: err}
	}
	return nil
}

// SplitBlobsStage is the R10 pipeline stage: every top-level payload field whose JSON value exceeds
// BlobThreshold is stored through Blob and replaced by its sha256, except a reserved-revision field
// (record.IsMVPField), which stays on its line and is bounded by the record instead. A string value is stored as its decoded
// bytes (so Reader.Blob returns the body as captured), any other value as its compact JSON. The field "body"
// lands under the key §2.2 already names, "blob"; any other field f lands under "f_blob". Fields at or under
// the threshold stay inline. An ssl_request body that is a JSON object holding a conversation array is the
// one exception: it is stored as a splice so its messages are stored by their own hash rather than once per
// request (R11, messages.go). It gets no "blob", which names a file holding the body whole and none does;
// "body_sha256" is its sha256, and "frame" and "messages" name the splice. Reader.Body reads every form back.
func (w *Writer) SplitBlobsStage(next Sink) Sink {
	return func(e *record.Event) error {
		if err := w.splitBlobs(e); err != nil {
			return err
		}
		return next(e)
	}
}

func (w *Writer) splitBlobs(e *record.Event) error {
	if len(e.Payload) <= BlobThreshold {
		return nil // no single field can exceed the threshold
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(e.Payload, &m); err != nil {
		return fmt.Errorf("ledger: split blobs: %w", err)
	}
	changed := false
	// The keys are taken once, sorted, before any split, and a split's new key is checked against every key
	// the payload had and every key a split has added: ranging over the map as it was rewritten let a split's
	// own key be iterated, and made {"x", "x_blob"} refused or split depending on which the map yielded first
	// (R10).
	keys := slices.Sorted(maps.Keys(m))
	held := make(map[string]bool, len(m))
	for _, k := range keys {
		held[k] = true
	}
	for _, k := range keys {
		v := m[k]
		if len(v) <= BlobThreshold || record.IsMVPField(e.Kind, k) {
			// A reserved-revision field stays on its line whatever its size: in a blob neither the Writer's check nor
			// Verify would read it, and a reader would find the field absent, which says the run was granted none.
			// The record bounds its size instead (record.MaxShares and the rest), within MaxLineBytes.
			continue
		}
		content := []byte(v)
		if v[0] == '"' {
			var s string
			if err := json.Unmarshal(v, &s); err != nil {
				return fmt.Errorf("ledger: split blobs: field %q: %w", k, err)
			}
			content = []byte(s)
		}
		// A split writes its sha under a different key, and that key may already hold something: a payload
		// carrying both "body" and "blob", or both "x" and "x_blob". Overwriting would destroy a recorded
		// value with no trace, so the split refuses instead. The pipeline reports the error and drops the
		// event, which becomes a gap: a visible loss rather than a silent rewrite.
		key := blobKey(k)
		if held[key] {
			return fmt.Errorf("ledger: split blobs: field %q would overwrite %q", k, key)
		}
		if k == "body" && e.Kind == record.KindSSLRequest {
			// A request carries its whole conversation, so its messages are stored by their own hash
			// (R11, messages.go). blob is left unset: in v1 it names blobs/<blob>, the body whole, and
			// no such file is written, so the whole body's sha256 goes under body_sha256 instead.
			for _, extra := range []string{fieldBodySHA256, fieldFrame, fieldMessages} {
				if held[extra] {
					return fmt.Errorf("ledger: split blobs: field %q would overwrite %q", k, extra)
				}
			}
			stored, ok, err := w.splitRequest(content)
			if err != nil {
				return fmt.Errorf("ledger: split blobs: field %q: %w", k, err)
			}
			if ok {
				delete(m, k)
				m[fieldBodySHA256] = json.RawMessage(`"` + stored.whole + `"`)
				m[fieldFrame] = json.RawMessage(`"` + stored.frame + `"`)
				m[fieldMessages] = json.RawMessage(`"` + stored.messages + `"`)
				held[fieldBodySHA256], held[fieldFrame], held[fieldMessages] = true, true, true
				changed = true
				continue
			}
		}
		sha, err := w.Blob(content)
		if err != nil {
			return fmt.Errorf("ledger: split blobs: field %q: %w", k, err)
		}
		delete(m, k)
		m[key] = json.RawMessage(`"` + sha + `"`)
		held[key] = true
		changed = true
	}
	if !changed {
		return nil
	}
	b, err := marshalPayload(m)
	if err != nil {
		return fmt.Errorf("ledger: split blobs: %w", err)
	}
	e.Payload = b
	return nil
}

// The ssl_request fields a request body stored as a splice carries in place of blob (messages.go).
const (
	fieldBodySHA256 = "body_sha256"
	fieldFrame      = "frame"
	fieldMessages   = "messages"
)

// blobKey names the field that carries a split field's sha256 (R10).
func blobKey(field string) string {
	if field == "body" {
		return "blob"
	}
	return field + "_blob"
}

// syncfs is syncfs(2) on the filesystem the lent number n is open on: Sync's callback, a function of this module
// so that fdcheck follows what it does with the number.
func syncfs(n int) error { return unix.Syncfs(n) }
