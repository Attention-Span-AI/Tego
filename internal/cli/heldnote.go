// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// heldNoteFile is the marker the held-label note leaves in the ledger root: the key of the machine state whose note
// was shown last.
const heldNoteFile = ".held-label-note"

// heldNoteKey is the machine state a held-label note describes: the kernel release and the note's own words, which
// name the security modules that label tasks and the contract keys that hold opens. A new kernel, another module list
// or another contract key is another state, so the note is shown again.
func heldNoteKey(release, note string) string {
	sum := sha256.Sum256([]byte(release + "\n" + note))
	return hex.EncodeToString(sum[:])
}

// heldNoteShown reports whether the note of this machine state was already shown from this ledger root, and marks it
// shown when it was not. The note says how held file opens are decided on this host; on WSL, whose kernel lists SELinux
// with no policy behind it, it was printed on every run and read as a fault (2026-11-19 Windows walkthrough). Anything
// uncertain (no root, a marker that is a link, someone else's or unreadable, a write that fails) answers false: a
// disclosure is repeated before it is hidden.
func heldNoteShown(root, release, note string) bool {
	if root == "" {
		return false
	}
	path := filepath.Join(root, heldNoteFile)
	key := heldNoteKey(release, note)
	if b, ok := readOwnSmallFile(path); ok && strings.TrimSpace(string(b)) == key {
		return true
	}
	// Written whole to the one name, never through a link: the marker is a hint to hide a repeat, not a record.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return false
	}
	_, werr := f.WriteString(key + "\n")
	if cerr := f.Close(); werr != nil || cerr != nil {
		return false
	}
	return false
}

// readOwnSmallFile reads at most 256 bytes of a regular file this user owns, opened without following a link.
func readOwnSmallFile(path string) ([]byte, bool) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 256 {
		return nil, false
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); !ok || sys.Uid != uint32(os.Geteuid()) {
		return nil, false
	}
	b := make([]byte, 256)
	n, err := f.Read(b)
	if err != nil && n == 0 {
		return nil, false
	}
	return b[:n], true
}

// kernelRelease is the running kernel's release string, "" when it cannot be read.
var kernelRelease = func() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
