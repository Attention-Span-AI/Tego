// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
)

// The ledger writer moves any payload field over its blob threshold (4 KiB) into <run>/blobs/<sha256> and leaves
// <field>_blob on the line (internal/ledger/blob.go, R10). A long command line is the usual case: Codex starts its
// shell through `/proc/self/exe --codex-run-as-process-setup … /bin/bash -c "<script>"`, so the exec line keeps only
// its path and argv_blob, and a row that read the path alone said "/proc/self/exe" where the agent ran curl. This
// file reads those blobs back for the read model: the argv of an exec line and the command of run_start.
//
// A blob is the agent's own bytes in a directory the dashboard does not own, read under the Store's mutex, so it is
// opened read-only without following a symlink, without blocking on a FIFO, only as a regular file of at most
// MaxBlobBytes, and only when its content hashes to its name: the ledger's blob store does not re-verify on read
// (E16), and a row must never show text the chain does not vouch for. The line page's download opens a blob with the
// same checks under its own, larger bound and streams it (OpenBlob); both read through Blob, the one copy of them.

// MaxBlobBytes is the largest blob ReadBlob reads: a command line far past any kernel's ARG_MAX of text a row could
// show, and small enough that a read under the Store's mutex stays short.
const MaxBlobBytes = 256 << 10

// MaxTargetBytes caps the Target a blob's argv gives a row: a row and the Logs text search keep this much of the
// command, and the line page reads the blob whole (BlobCommand).
const MaxTargetBytes = 8 << 10

// ErrBlob is a blob ReadBlob or OpenBlob refuses: a malformed name, a file that is not a regular one, one too big, or
// content that does not hash to its name.
var ErrBlob = errors.New("ledgerview: blob refused")

// ErrBlobTooBig and ErrBlobHash are the refusals a page tells apart in words; both are ErrBlob. ErrBlobTooBig is a
// file over the bound it is read under. ErrBlobHash is content that does not hash to the blob's name: the file
// changed after it was written, or changed size as it was read.
var (
	ErrBlobTooBig = fmt.Errorf("%w: too big", ErrBlob)
	ErrBlobHash   = fmt.Errorf("%w: content does not hash to its name", ErrBlob)
)

// ReadBlob reads <runDir>/blobs/<sha> whole, checked: sha is 64 lower-case hex digits, the file is opened with
// O_NOFOLLOW|O_NONBLOCK, is a regular file of at most max bytes (MaxBlobBytes when max is 0 or larger), and its
// sha256 is sha. Any failure is an error wrapping ErrBlob or the open's own error.
func ReadBlob(runDir, sha string, max int64) ([]byte, error) {
	if max <= 0 || max > MaxBlobBytes {
		max = MaxBlobBytes
	}
	b, err := openBlob(runDir, sha, max)
	if err != nil {
		return nil, err
	}
	defer func() { _ = b.Close() }()
	out, err := io.ReadAll(b)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// OpenBlob opens <runDir>/blobs/<sha> to stream it, with ReadBlob's checks under the caller's own bound (MaxBlobBytes
// when max is 0 or less): the line page's download serves blobs far past what ReadBlob holds in memory. The hash is
// checked before OpenBlob returns (it reads the file through the hash once), so a caller refuses a blob that does not
// hash to its name before it sends a byte of it; Read checks it again as it streams (Blob), since the file can change
// in between. Any failure is an error wrapping ErrBlob or the file system's own error.
func OpenBlob(runDir, sha string, max int64) (*Blob, error) {
	if max <= 0 {
		max = MaxBlobBytes
	}
	b, err := openBlob(runDir, sha, max)
	if err != nil {
		return nil, err
	}
	if _, err = io.Copy(io.Discard, b); err == nil {
		_, err = b.f.Seek(0, io.SeekStart)
	}
	if err != nil {
		_ = b.Close()
		return nil, err
	}
	b.n, b.whole = 0, false
	b.sum.Reset()
	return b, nil
}

// openBlob opens <runDir>/blobs/<sha> with every check but the hash, which Read makes: sha is 64 lower-case hex
// digits, the blobs folder is a real directory, the file is opened read-only with O_NOFOLLOW|O_NONBLOCK (no link
// followed, no FIFO waited on) and is a regular file of at most max bytes.
func openBlob(runDir, sha string, max int64) (*Blob, error) {
	if !validSHA(sha) {
		return nil, fmt.Errorf("%w: %q is not a sha256 name", ErrBlob, sha)
	}
	dir := filepath.Join(runDir, "blobs")
	if fi, err := os.Lstat(dir); err != nil {
		return nil, err
	} else if !fi.IsDir() {
		return nil, fmt.Errorf("%w: %s is not a directory", ErrBlob, dir)
	}
	f, err := os.OpenFile(filepath.Join(dir, sha), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err == nil {
		switch {
		case !fi.Mode().IsRegular():
			err = fmt.Errorf("%w: blob %s is not a regular file", ErrBlob, sha[:12])
		case fi.Size() > max:
			err = fmt.Errorf("%w: blob %s is %d bytes, over %d", ErrBlobTooBig, sha[:12], fi.Size(), max)
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Blob{f: f, sha: sha, size: fi.Size(), sum: sha256.New()}, nil
}

// Blob is a blob file opened with ReadBlob's checks (OpenBlob), read as a stream of its Size bytes. Read hashes the
// bytes as it hands them out and hands out the ones that complete the blob only once the whole file hashes to its name
// and holds no byte more; when it does not, Read returns an error wrapping ErrBlobHash instead of them, and the same
// error on every later call. Whoever reads a Blob to io.EOF has read exactly the content its name vouches for, holding
// no more of it at a time than their own buffer; a blob changed as it is read stops short of its Size.
type Blob struct {
	f     *os.File
	sha   string
	size  int64
	n     int64     // bytes handed out
	sum   hash.Hash // sha256 of those bytes
	whole bool      // all Size bytes are out and hashed to sha: Read says io.EOF
	err   error     // what ended the stream short, returned by every Read after it
}

// Size is the blob file's size when it was opened: the bytes Read hands out.
func (b *Blob) Size() int64 { return b.size }

// Close closes the blob file.
func (b *Blob) Close() error { return b.f.Close() }

// Read hands out the blob's next bytes; see Blob.
func (b *Blob) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	n := 0
	if b.n < b.size {
		if len(p) == 0 {
			return 0, nil
		}
		if left := b.size - b.n; int64(len(p)) > left {
			p = p[:left]
		}
		var err error
		if n, err = b.f.Read(p); err != nil || n == 0 {
			if err == nil || err == io.EOF {
				err = fmt.Errorf("%w: blob %s shrank as it was read", ErrBlobHash, b.sha[:12])
			}
			b.err = err
			return 0, err
		}
		b.sum.Write(p[:n])
		b.n += int64(n)
		if b.n < b.size {
			return n, nil
		}
	} else if b.whole {
		return 0, io.EOF
	}
	// p[:n] completes the blob (or it is empty): hand it out only once the whole file hashes to the name.
	if err := b.check(); err != nil {
		b.err = err
		return 0, err
	}
	b.whole = true
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

// check is nil when the bytes read hash to the blob's name and the file holds no byte past them.
func (b *Blob) check() error {
	var one [1]byte
	if n, err := b.f.Read(one[:]); n > 0 {
		return fmt.Errorf("%w: blob %s grew as it was read", ErrBlobHash, b.sha[:12])
	} else if err != nil && err != io.EOF {
		return err
	}
	if hex.EncodeToString(b.sum.Sum(nil)) != b.sha {
		return fmt.Errorf("%w: blob %s", ErrBlobHash, b.sha[:12])
	}
	return nil
}

func validSHA(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// blobArgv reads the blob sha of runDir as a JSON array of strings (an argv or a command) and joins it with spaces.
func blobArgv(runDir, sha string) (string, error) {
	b, err := ReadBlob(runDir, sha, MaxBlobBytes)
	if err != nil {
		return "", err
	}
	var argv []string
	if err := json.Unmarshal(b, &argv); err != nil {
		return "", fmt.Errorf("%w: blob %s is not a list of strings: %v", ErrBlob, sha[:12], err)
	}
	return strings.Join(argv, " "), nil
}

// capTarget is s cut to MaxTargetBytes on a character boundary, ending "… (N bytes more, on the line page)".
func capTarget(s string) string {
	if len(s) <= MaxTargetBytes {
		return s
	}
	cut := MaxTargetBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "… (" + strconv.Itoa(len(s)-cut) + " bytes more, on the line page)"
}

// resolveBlob gives an exec line whose argv went to a blob, and a run_start whose command did, their command as
// Target (capped, capTarget), reading the blob once as the line is taken. A blob that cannot be read leaves the
// target as it was (the exec's path) and marks the line (Event.ArgvMissing).
func resolveBlob(runDir string, ev *Event) {
	sha := ev.blob
	ev.blob = ""
	if sha == "" || runDir == "" {
		return
	}
	s, err := blobArgv(runDir, sha)
	if err != nil {
		ev.argvMissing = true
		return
	}
	ev.Target = capTarget(s)
}

// BlobCommand is the whole command a line's payload (Event.Raw) moved to a blob (argv_blob on an exec line,
// command_blob on run_start), read from root's run directory, checked as ReadBlob checks it; ok is false when the
// line has none or it cannot be read. The line page shows it in full where a row shows MaxTargetBytes.
func BlobCommand(root, run, raw string) (string, bool) {
	if !validRunID(run) || raw == "" {
		return "", false
	}
	var p struct {
		Argv        []string `json:"argv"`
		ArgvBlob    string   `json:"argv_blob"`
		Command     []string `json:"command"`
		CommandBlob string   `json:"command_blob"`
	}
	if json.Unmarshal([]byte(raw), &p) != nil {
		return "", false
	}
	sha := p.ArgvBlob
	if len(p.Argv) > 0 || sha == "" {
		sha = ""
		if len(p.Command) == 0 {
			sha = p.CommandBlob
		}
	}
	if sha == "" {
		return "", false
	}
	s, err := blobArgv(filepath.Join(root, run), sha)
	return s, err == nil
}
