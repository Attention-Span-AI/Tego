// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// TrustMode says what a failed trust check does: abort the whole Load (tego run) or warn and skip
// that layer entirely (compile, doctor). Both call sites share the one check below (I11).
type TrustMode int

// TrustMode values.
const (
	// TrustAbort returns *UntrustedError from Load before any later layer is read (R14).
	TrustAbort TrustMode = iota
	// TrustWarn records a warning diagnostic and skips the layer; it is never partially applied (R20).
	TrustWarn
)

// MaxLayerSize is the largest layer file Load reads. The normative docs state no cap (E27, Q4);
// this bound only keeps a misdirected multi-gigabyte redirect from being read into memory.
const MaxLayerSize = 16 << 20

// ErrUntrusted is the sentinel every failed trust check wraps.
var ErrUntrusted = errors.New("config: untrusted layer file")

// UntrustedError is a layer file (or its directory) that failed the trust check (R20).
type UntrustedError struct {
	Path   string      // the path as opened
	Owner  int         // uid of the failing file or directory
	Mode   fs.FileMode // its mode, permission bits and type
	Reason string      // one clause: what failed
	Names  uint64      // the file's names (st_nlink) when a second one is what failed (manyNamesReason), else 0
}

// Error renders "machine config untrusted: <path> <owner> <mode>" plus the reason.
func (e *UntrustedError) Error() string {
	return fmt.Sprintf("machine config untrusted: %s uid=%d mode=%04o (%s)", e.Path, e.Owner, e.Mode&fs.ModePerm, e.Reason)
}

// Unwrap returns ErrUntrusted so callers use errors.Is.
func (e *UntrustedError) Unwrap() error { return ErrUntrusted }

// Fix is the one command that would make the file trusted, for the diagnostic.
func (e *UntrustedError) Fix() string {
	if e.Names > 1 {
		return fmt.Sprintf("Give it one name: remove its other hard link (find / -xdev -samefile %s lists them), "+
			"or replace it with a copy (cp -p %[1]s %[1]s.new && mv %[1]s.new %[1]s).", e.Path)
	}
	return "Make it a regular file owned by root or you, chmod g-w,o-w on it and its directory."
}

// groupOtherWrite are the mode bits R20 forbids.
const groupOtherWrite = syscall.S_IWGRP | syscall.S_IWOTH

// readTrusted opens path, checks it against R20 and returns its bytes. absent is true (with nil
// data and error) when the path does not exist. The file is opened O_NONBLOCK first so a FIFO
// without a writer cannot hang the caller (E26); the fstat then refuses anything but a regular
// file. The directory checked is that of the resolved target, so a symlink out of /etc is judged
// by where it points (E10). No fd escapes this function.
func readTrusted(path string, invokingUID int) (data []byte, absent bool, err error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	st, err := fstat(f)
	if err != nil {
		return nil, false, fmt.Errorf("config: fstat %s: %w", path, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, false, untrusted(path, st, "not a regular file")
	}
	if reason := ownerModeReason(st, invokingUID); reason != "" {
		return nil, false, untrusted(path, st, reason)
	}
	if err := oneName(path, st, invokingUID); err != nil {
		return nil, false, err
	}
	if err := checkDirectory(f, path, invokingUID); err != nil {
		return nil, false, err
	}
	if st.Size > MaxLayerSize {
		return nil, false, fmt.Errorf("config: %s: %w", path, errTooLarge)
	}
	data, err = io.ReadAll(io.LimitReader(f, MaxLayerSize+1))
	if err != nil {
		return nil, false, fmt.Errorf("config: read %s: %w", path, err)
	}
	if len(data) > MaxLayerSize {
		return nil, false, fmt.Errorf("config: %s: %w", path, errTooLarge)
	}
	return data, false, nil
}

// errTooLarge is wrapped when a layer exceeds MaxLayerSize.
var errTooLarge = fmt.Errorf("layer file exceeds %d bytes", MaxLayerSize)

// checkDirectory applies R20's owner/mode rule to the directory that contains the file behind f.
//
// The directory is *named* from the open descriptor's own link (/proc/self/fd/<n>), never by walking the
// caller's path string again: re-resolving the symlink chain would judge a different object than the one
// whose bytes are about to be read, which is the race R20 closes for the file itself. If procfs is
// unavailable, resolving the path is the documented fallback.
//
// Naming it is not enough, because the name still has to be opened. Between reading the link and that
// open, an ancestor can be renamed away and a trusted-looking directory moved into its place, so the
// directory that passes the rule need not be the one the file lives in. checkContains closes that
// window: after the directory passes, the file is reopened through that directory's own descriptor and
// must be the same inode as f. A swap is then a mismatch (or a vanished name) and the layer is refused,
// which also makes the procfs-unavailable fallback sound.
//
// Stepping straight from f's dentry to its parent via "/proc/self/fd/<n>/.." would avoid the second
// resolution entirely, but it cannot work here: readTrusted has already established that f is S_ISREG,
// and Linux answers ENOTDIR to ".." under a non-directory — TestProcFDDotDotOnFileIsENOTDIR pins that
// kernel behaviour so the dead branch is not reintroduced.
func checkDirectory(f *os.File, path string, invokingUID int) error {
	fst, err := fstat(f) // f is pinned, so this is the same identity readTrusted approved (R20's fstat-the-fd rule)
	if err != nil {
		return fmt.Errorf("config: fstat %s: %w", path, err)
	}
	resolved, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(f.Fd())))
	if err != nil || !filepath.IsAbs(resolved) {
		resolved, err = filepath.EvalSymlinks(path)
		if err != nil {
			return fmt.Errorf("config: resolve %s: %w", path, err)
		}
	}
	dir, base := filepath.Dir(resolved), filepath.Base(resolved)
	d, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("config: open directory %s: %w", dir, err)
	}
	defer func() { _ = d.Close() }()
	st, err := fstat(d)
	if err != nil {
		return fmt.Errorf("config: fstat %s: %w", dir, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return untrusted(dir, st, "not a directory")
	}
	if reason := ownerModeReason(st, invokingUID); reason != "" {
		return untrusted(dir, st, "directory "+reason)
	}
	return checkContains(d, dir, base, fst)
}

// checkContains requires the directory just approved to be the one holding the file the caller is about
// to read: base is reopened *relative to d* (so no path component is resolved a second time) and must be
// the same device and inode as fst. Anything else — the name gone, a symlink or another inode in its
// place — means the pair drifted apart while it was being checked, and R20's directory half cannot be
// said to hold for these bytes, so the layer is refused rather than trusted on a directory that does not
// contain it. An inode reachable under a directory that passed the owner/mode rule can only have been
// linked there by root or the invoking uid, so matching identity is the whole property.
//
// No object outside R20's scope is opened: this is the layer path itself, reached through the directory
// R20 already requires be checked (I10). The flags are load-bearing: O_CLOEXEC because a raw openat,
// unlike os.OpenFile, does not set it and readTrusted lets no descriptor escape, O_NOFOLLOW because base
// names an already resolved regular file so a symlink appearing there is itself the swap being looked
// for, and O_NONBLOCK so a FIFO moved into its place cannot hang the check (E26, I8).
func checkContains(d *os.File, dir, base string, fst *syscall.Stat_t) error {
	name := filepath.Join(dir, base)
	fd, err := syscall.Openat(int(d.Fd()), base,
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
			return untrusted(name, fst, reasonReplaced)
		}
		return fmt.Errorf("config: reopen %s in its directory: %w", name, err)
	}
	defer func() { _ = syscall.Close(fd) }()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fmt.Errorf("config: fstat %s: %w", name, err)
	}
	if st.Dev != fst.Dev || st.Ino != fst.Ino {
		return untrusted(name, fst, reasonReplaced)
	}
	return nil
}

// reasonReplaced names the failure when the file stopped being the one in the directory checked.
const reasonReplaced = "file was replaced or removed while it was being checked"

// ownerModeReason returns "" when st is owned by root or invokingUID and not group/other writable.
func ownerModeReason(st *syscall.Stat_t, invokingUID int) string {
	if st.Uid != 0 && int(st.Uid) != invokingUID {
		return fmt.Sprintf("owned by uid %d, not root or uid %d", st.Uid, invokingUID)
	}
	if st.Mode&groupOtherWrite != 0 {
		return "group or other writable"
	}
	return ""
}

// fstat stats an open file through its descriptor (never a separate stat of the path).
func fstat(f *os.File) (*syscall.Stat_t, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("no Stat_t in FileInfo")
	}
	return st, nil
}

func untrusted(path string, st *syscall.Stat_t, reason string) error {
	return &UntrustedError{Path: path, Owner: int(st.Uid), Mode: fs.FileMode(st.Mode & 0o7777), Reason: reason}
}

// ReadTrusted reads a file the machine config names outside its layer list — the price table — under the
// rule its layers follow (R20, readTrusted): a regular file owned by root or invokingUID, neither it nor the
// directory of the file it resolves to group- or other-writable, the directory re-checked against the open
// descriptor. A failed check is *UntrustedError; an absent path is an error wrapping fs.ErrNotExist.
func ReadTrusted(path string, invokingUID int) ([]byte, error) {
	data, absent, err := readTrusted(path, invokingUID)
	if absent {
		return nil, fmt.Errorf("config: %s: %w", path, fs.ErrNotExist)
	}
	return data, err
}

// CheckTrusted applies R20's owner and mode rule to an open file or directory: owned by root or invokingUID
// and not group- or other-writable; and to a regular file the one-name rule (CheckOneName). It is for a reader
// that opens its own files and walks its own directories (the profiles directory and the registries, read through
// os.Root), and returns *UntrustedError naming path.
func CheckTrusted(f *os.File, path string, invokingUID int) error {
	st, err := fstat(f)
	if err != nil {
		return fmt.Errorf("config: fstat %s: %w", path, err)
	}
	if reason := ownerModeReason(st, invokingUID); reason != "" {
		return untrusted(path, st, reason)
	}
	return oneName(path, st, invokingUID)
}

// CheckOneName applies the one-name rule alone to an open file, for a policy file the owner and mode rule does not
// cover (a contract given by its path): *UntrustedError naming path when manyNamesReason refuses it.
func CheckOneName(f *os.File, path string, invokingUID int) error {
	st, err := fstat(f)
	if err != nil {
		return fmt.Errorf("config: fstat %s: %w", path, err)
	}
	return oneName(path, st, invokingUID)
}

// oneName is *UntrustedError, with Names set, when manyNamesReason refuses st; nil otherwise.
func oneName(path string, st *syscall.Stat_t, invokingUID int) error {
	reason := manyNamesReason(st, invokingUID)
	if reason == "" {
		return nil
	}
	// Stat_t.Nlink is uint64 on amd64 and uint32 on arm64.
	return &UntrustedError{Path: path, Owner: int(st.Uid), Mode: fs.FileMode(st.Mode & 0o7777), Reason: reason, Names: uint64(st.Nlink)}
}

// manyNamesReason is the one-name rule (agent-contract.md R10, ADR 0059): a policy file tego loads for a run (a
// layer, the price table, a profile, a registry entry, a contract) has one name, or no run of invokingUID could write
// it by any name. R10 keeps every write entry off each name tego reads such a file by, and the other name of a hard
// link is compared with nothing, so a run whose write entry held it could rewrite the file the runs after it load. A
// run cannot add a name (link(2) reparents, and Landlock grants REFER only beneath a write entry), so the count read
// here holds while the run runs. Spared: a file owned by someone other than invokingUID that is not group- or
// other-writable, when invokingUID is not root (a root-owned store that deduplicates by hard links), and anything that
// is not a regular file (a directory's count is its subdirectories'). "" when spared, else the clause that refuses.
func manyNamesReason(st *syscall.Stat_t, invokingUID int) string {
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink <= 1 {
		return ""
	}
	if invokingUID != 0 && int(st.Uid) != invokingUID && st.Mode&groupOtherWrite == 0 {
		return ""
	}
	return fmt.Sprintf("it has %d names (hard links), and a run of uid %d could rewrite it through one no write entry is compared with",
		st.Nlink, invokingUID)
}
