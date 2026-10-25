// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Name is tego-control's file name beside tego, and the argv[0] it runs under.
const Name = "tego-control"

// maxSize bounds the copy. tego-control is tens of megabytes; a larger file is not the pinned one, and copying it
// into memory before the hash says so would only fill memory.
const maxSize = 256 << 20

// controlSHA256 is the SHA-256 of the tego-control this build ships with, lowercase hex, set at link time:
// -X github.com/attention-span-ai/tego/internal/handoff.controlSHA256=<64 hex digits> (Makefile build, .goreleaser.yaml).
// Empty is an unpinned build, which refuses every handoff [control-unpinned]. Nothing assigns it at run time.
var controlSHA256 string

// Pin is the SHA-256 this build pinned for tego-control, or "" for an unpinned build. tego version prints it.
func Pin() string { return controlSHA256 }

// The reason codes of a refused handoff, in the bracketed suffix of its one stderr line. Each maps to an exit
// code of pkg/spec/identity (Exit).
const (
	// CodeNotInstalled is no tego-control beside the running tego (PATH and the working directory are never
	// searched).
	CodeNotInstalled = "control-not-installed"
	// CodeUnpinned is a tego built without tego-control's hash: it cannot tell the shipped tego-control from any
	// other, so it runs none.
	CodeUnpinned = "control-unpinned"
	// CodeMismatch is a tego-control whose SHA-256 is not the one this tego pinned: another build, or a changed file.
	CodeMismatch = "control-mismatch"
	// CodeUntrusted is a tego-control that is a symbolic link, not a regular file, owned by someone other than
	// root or the caller, writable by its group or by others, not executable by the caller, or on a mount that
	// forbids exec: the sealed copy would run whatever the file's mode or mount, so the handoff refuses where the
	// kernel would refuse to run the file itself.
	CodeUntrusted = "control-untrusted"
	// CodeAsRoot is a handoff asked for at euid 0, or a tego-control started at euid 0 or with an effective
	// capability: the dashboard runs as the user, never as root (ADR 0100 (1b)).
	CodeAsRoot = "control-as-root"
	// CodeMemfdNoexec is a kernel that refuses an executable memfd (vm.memfd_noexec=2, or a security module), so
	// the sealed copy cannot run.
	CodeMemfdNoexec = "memfd-noexec"
)

// exits is each reason code's exit (TestReasonCodesMapToIdentityExits): every refusal is Tego's own error, 125,
// as RUN-IDENTITY.md gives for a subcommand other than run.
var exits = map[string]int{
	CodeNotInstalled: identity.ExitError,
	CodeUnpinned:     identity.ExitError,
	CodeMismatch:     identity.ExitError,
	CodeUntrusted:    identity.ExitError,
	CodeAsRoot:       identity.ExitError,
	CodeMemfdNoexec:  identity.ExitError,
}

// Exit is the exit code of a refusal with this reason code; an unknown code is Tego's own error too.
func Exit(code string) int {
	if c, ok := exits[code]; ok {
		return c
	}
	return identity.ExitError
}

// Error is a refused handoff: one sentence saying what is wrong, its reason code, and the one sentence that fixes it.
type Error struct {
	Code string
	What string
	Fix  string
	Err  error
}

// Error is the sentence, the cause when there is one, and the fix: "<what>[: <cause>]; <fix>", the form the
// command line prints before the bracketed code.
func (e *Error) Error() string {
	s := e.What
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	if e.Fix != "" {
		s += "; " + e.Fix
	}
	return s
}

func (e *Error) Unwrap() error { return e.Err }

// Binary is a verified copy of tego-control in a sealed memfd: nothing can write, grow or shrink it, and its
// SHA-256 is the pinned one. It is what Exec and Spawn run. Close releases it.
type Binary struct {
	mem  *os.File
	sum  string
	from string
}

// Close releases the sealed copy. A Spawned child keeps running from its own reference.
func (b *Binary) Close() error { return b.mem.Close() }

// config is what Open reads from the host, injectable for tests.
type config struct {
	dir  string // the directory tego-control must be in: the running tego's own
	pin  string // the hash the build pinned
	euid int
	// groups are the caller's effective group and supplementary groups, for the execute check.
	groups []int
}

// Open verifies tego-control beside the running tego and returns its sealed copy (ADR 0100 (1b)). A refusal is an
// *Error with its reason code.
func Open() (*Binary, error) { return openAs(os.Geteuid()) }

// openAs is Open for a caller of euid (a test's seam: the suite also runs as root).
func openAs(euid int) (*Binary, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, &Error{Code: CodeNotInstalled, What: "cannot name the running tego's own file, beside which " + Name + " must be",
			Fix: "run tego from its installed path", Err: err}
	}
	groups, err := unix.Getgroups()
	if err != nil {
		return nil, &Error{Code: CodeUntrusted, What: "cannot read your groups, which decide whether you may execute " + Name,
			Fix: "retry", Err: err}
	}
	return config{dir: filepath.Dir(exe), pin: controlSHA256, euid: euid, groups: append(groups, os.Getegid())}.open()
}

// open is Open over c. Root is refused before anything is opened; then a missing tego-control, the refusal a
// tego installed alone meets, comes before an unpinned build's, and the pin before anything is read or copied.
func (c config) open() (*Binary, error) {
	if c.euid == 0 {
		return nil, &Error{Code: CodeAsRoot, What: Name + " runs as the user and never as root, so tego does not hand off to it at euid 0",
			Fix: "run this command as yourself, without sudo"}
	}
	path := filepath.Join(c.dir, Name)
	// O_NONBLOCK so a FIFO planted at the path cannot hang the open; it is refused as not a regular file below.
	src, err := sys.Own(unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0))
	switch {
	case errors.Is(err, unix.ENOENT):
		return nil, &Error{Code: CodeNotInstalled, What: Name + " is not installed beside tego at " + path,
			Fix: "install " + Name + " from the same release into " + c.dir}
	case errors.Is(err, unix.ELOOP):
		return nil, &Error{Code: CodeUntrusted, What: path + " is a symbolic link, which the handoff never follows",
			Fix: "replace the link with the " + Name + " file from the same release"}
	case err != nil:
		return nil, &Error{Code: CodeUntrusted, What: "cannot open " + path, Fix: "check the file's permissions", Err: err}
	}
	defer func() { _ = src.Close() }()
	if !validPin(c.pin) {
		return nil, &Error{Code: CodeUnpinned, What: "this tego was built without " + Name + "'s hash, so it runs no " + Name,
			Fix: "build both binaries with `make build`, or install a release"}
	}
	var st unix.Stat_t
	if err := src.Fstat(&st); err != nil {
		return nil, &Error{Code: CodeUntrusted, What: "cannot stat " + path, Fix: "check the file", Err: err}
	}
	if err := trusted(path, &st, c.euid, c.groups); err != nil {
		return nil, err
	}
	switch noexec, err := mountNoexec(src); {
	case err != nil:
		return nil, &Error{Code: CodeUntrusted, What: "cannot read the mount flags of " + path, Fix: "check the file", Err: err}
	case noexec:
		return nil, &Error{Code: CodeUntrusted, What: path + " is on a mount that forbids exec (noexec), so it is not run",
			Fix: "install tego and " + Name + " on a mount that allows exec"}
	}
	mem, err := sealedCopy(src, st.Size)
	if err != nil {
		return nil, err
	}
	sum, err := hashOf(mem)
	if err != nil {
		_ = mem.Close()
		return nil, &Error{Code: CodeMismatch, What: "cannot hash the sealed copy of " + path, Fix: "retry", Err: err}
	}
	if sum != c.pin {
		_ = mem.Close()
		return nil, &Error{Code: CodeMismatch, What: path + " has SHA-256 " + sum + ", not the " + c.pin + " this tego was built with",
			Fix: "install the " + Name + " from the same release or build as this tego"}
	}
	return &Binary{mem: mem, sum: sum, from: path}, nil
}

// validPin reports whether p is a SHA-256 in lowercase hex.
func validPin(p string) bool {
	if len(p) != 2*sha256.Size {
		return false
	}
	for _, r := range p {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// trusted is the file check: a regular file, owned by root or the caller, with no group or world write, that the
// caller (euid, in groups) could execute itself.
func trusted(path string, st *unix.Stat_t, euid int, groups []int) error {
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return &Error{Code: CodeUntrusted, What: path + " is not a regular file", Fix: "install the " + Name + " file from the same release"}
	}
	if st.Uid != 0 && int64(st.Uid) != int64(euid) {
		return &Error{Code: CodeUntrusted, What: fmt.Sprintf("%s is owned by uid %d, neither root nor you", path, st.Uid),
			Fix: "install " + Name + " as root or as yourself"}
	}
	if st.Mode&0o022 != 0 {
		return &Error{Code: CodeUntrusted, What: fmt.Sprintf("%s is writable by its group or by others (mode %04o)", path, st.Mode&0o7777),
			Fix: "chmod go-w " + path}
	}
	if !executable(st, euid, groups) {
		return &Error{Code: CodeUntrusted, What: fmt.Sprintf("%s has no execute permission for you (mode %04o), so it is not run",
			path, st.Mode&0o7777), Fix: "if " + Name + " is meant to run, `chmod a+x " + path + "`"}
	}
	return nil
}

// executable reports whether the caller (euid, in groups) could execute a file of st's owner, group and mode, as the
// kernel's mode check does for a file without an ACL: the owner's bit for its owner, else the group's for a member of
// its group, else the others'. An ACL's named entries and a security module's exec rule are not read (ADR 0100's
// review-round-1 note).
func executable(st *unix.Stat_t, euid int, groups []int) bool {
	switch {
	case int64(st.Uid) == int64(euid):
		return st.Mode&0o100 != 0
	case slices.Contains(groups, int(st.Gid)):
		return st.Mode&0o010 != 0
	default:
		return st.Mode&0o001 != 0
	}
}

// mountNoexec reports whether src is on a mount that forbids exec (fstatfs's ST_NOEXEC): the kernel would refuse to
// run the file, and the memfd copy would not be. A variable so a test can answer as a noexec mount.
var mountNoexec = func(src *sys.FD) (bool, error) {
	var sfs unix.Statfs_t
	if err := src.Borrow(func(n int) error { return unix.Fstatfs(n, &sfs) }); err != nil {
		return false, err
	}
	return sfs.Flags&unix.ST_NOEXEC != 0, nil
}

// memfdCreate makes the memfd for the copy, close-on-exec and sealable, with MFD_EXEC when exec is set (mainline 6.3,
// backported by some distributions, RHEL 9's 5.14 among them: executable even where vm.memfd_noexec=1 would seal it
// non-executable). A variable so a test can answer as a kernel with vm.memfd_noexec=2 does.
var memfdCreate = func(exec bool) (*sys.FD, error) {
	if exec {
		return sys.Own(unix.MemfdCreate(Name, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_EXEC))
	}
	return sys.Own(unix.MemfdCreate(Name, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING))
}

// seals are the seals the copy carries once written: no write, no shrink, no grow, and no seal change.
const seals = unix.F_SEAL_WRITE | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_SEAL

// sealedCopy copies size bytes of src into a new memfd and seals it. A kernel without MFD_EXEC (mainline before 6.3)
// does not know the flag (EINVAL), and its memfds are executable anyway; one that refuses the flag (EACCES:
// vm.memfd_noexec=2) is [memfd-noexec].
func sealedCopy(src *sys.FD, size int64) (*os.File, error) {
	if size > maxSize {
		return nil, &Error{Code: CodeMismatch, What: fmt.Sprintf("%s is %d bytes, larger than any %s", Name, size, Name),
			Fix: "install the " + Name + " from the same release as this tego"}
	}
	fd, err := memfdCreate(true)
	if errors.Is(err, unix.EINVAL) {
		fd, err = memfdCreate(false)
	}
	if err != nil {
		return nil, memfdRefused(err)
	}
	mem, err := fd.Release(Name)
	if err != nil {
		_ = fd.Close()
		return nil, &Error{Code: CodeMemfdNoexec, What: "cannot hold the memfd for " + Name, Fix: "retry", Err: err}
	}
	in, err := src.Release(Name + " (source)")
	if err != nil {
		_ = mem.Close()
		return nil, &Error{Code: CodeUntrusted, What: "cannot read " + Name, Fix: "retry", Err: err}
	}
	defer func() { _ = in.Close() }()
	n, err := io.Copy(mem, io.LimitReader(in, maxSize+1))
	if err == nil && n > maxSize {
		err = fmt.Errorf("grew past %d bytes while it was copied", maxSize)
	}
	if err == nil {
		err = sys.FileDo(mem, func(n int) error {
			_, err := unix.FcntlInt(uintptr(n), unix.F_ADD_SEALS, seals)
			return err
		})
	}
	if err != nil {
		_ = mem.Close()
		return nil, &Error{Code: CodeMismatch, What: "cannot make the sealed copy of " + Name, Fix: "retry", Err: err}
	}
	return mem, nil
}

// memfdNoexec is the sysctl that refuses executable memfds, which a [memfd-noexec] fix names: any user can read it
// (mode 0644), and each pid namespace has its own, at least its parent's. tego doctor reads it only as root, and the
// handoff refuses root, so the fix names the file rather than doctor.
const memfdNoexec = "/proc/sys/vm/memfd_noexec"

// memfdRefused is the refusal for a memfd the kernel would not create.
func memfdRefused(err error) error {
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
		return &Error{Code: CodeMemfdNoexec, What: "the kernel refuses an executable memfd, so the sealed copy of " + Name + " cannot run",
			Fix: "`cat " + memfdNoexec + "` shows the setting (2 refuses); as root, `sysctl vm.memfd_noexec=1` (or 0) allows it",
			Err: err}
	}
	return &Error{Code: CodeMemfdNoexec, What: "cannot create the memfd for " + Name, Fix: "retry", Err: err}
}

// hashOf is the SHA-256 of the sealed copy, read from its start: the bytes that will run, whatever wrote the memfd
// between the copy and the seal.
func hashOf(mem *os.File) (string, error) {
	var st unix.Stat_t
	if err := sys.FstatFile(mem, &st); err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(mem, 0, st.Size)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
