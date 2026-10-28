// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
// (E16), and a row must never show text the chain does not vouch for.

// MaxBlobBytes is the largest blob ReadBlob reads: a command line far past any kernel's ARG_MAX of text a row could
// show, and small enough that a read under the Store's mutex stays short.
const MaxBlobBytes = 256 << 10

// MaxTargetBytes caps the Target a blob's argv gives a row: a row and the Logs text search keep this much of the
// command, and the line page reads the blob whole (BlobCommand).
const MaxTargetBytes = 8 << 10

// ErrBlob is a blob ReadBlob refuses: a malformed name, a file that is not a regular one, one too big, or content
// that does not hash to its name.
var ErrBlob = errors.New("ledgerview: blob refused")

// ReadBlob reads <runDir>/blobs/<sha>, checked: sha is 64 lower-case hex digits, the file is opened with
// O_NOFOLLOW|O_NONBLOCK, is a regular file of at most max bytes (MaxBlobBytes when max is 0 or larger), and its
// sha256 is sha. Any failure is an error wrapping ErrBlob or the open's own error.
func ReadBlob(runDir, sha string, max int64) ([]byte, error) {
	if max <= 0 || max > MaxBlobBytes {
		max = MaxBlobBytes
	}
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
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: blob %s is not a regular file", ErrBlob, sha[:12])
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("%w: blob %s is %d bytes, over %d", ErrBlob, sha[:12], fi.Size(), max)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%w: blob %s grew past %d bytes", ErrBlob, sha[:12], max)
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != sha {
		return nil, fmt.Errorf("%w: blob %s does not hash to its name", ErrBlob, sha[:12])
	}
	return b, nil
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
