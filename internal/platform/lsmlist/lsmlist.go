// SPDX-License-Identifier: Apache-2.0

package lsmlist

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/platform/tomoyo"
)

// Format is the first line of a list file an entrypoint writes: a name and a version, so a file of another shape is
// refused rather than guessed at. The file is exactly three lines:
//
//	tego-lsm-list 1
//	boot_id <the contents of /proc/sys/kernel/random/boot_id>
//	lsm <the kernel's list, as /sys/kernel/security/lsm prints it>
const Format = "tego-lsm-list 1"

const (
	bootIDLine = "boot_id "
	lsmLine    = "lsm "
	// readLimit bounds a list file: the kernel's own list is a few hundred bytes. A longer file is refused, never cut.
	readLimit = 4096
	// maxModules bounds the names in a list, as the syscall's reader does.
	maxModules = 64
)

// Kind says which of the two shapes a file passed as.
type Kind string

const (
	// KindKernel is a read-only bind of the host's /sys/kernel/security/lsm: the kernel's own bytes, read now.
	KindKernel Kind = "the host's /sys/kernel/security/lsm, bound read-only"
	// KindHandedIn is a file root wrote in this boot (the container's entrypoint, before it dropped its privileges).
	KindHandedIn Kind = "the list the container's entrypoint wrote as root at this boot"
)

// ErrNotConfigured is Read with no lsm.list_file set: no third way is offered.
var ErrNotConfigured = errors.New("lsmlist: no lsm.list_file is set")

// Unusable is a list file Tego does not believe, or cannot read. Why says what is wrong, in words for the person who
// can fix it; nothing is read from the file in that case.
type Unusable struct {
	Path string
	Why  string
	Err  error // the underlying error, when there is one
}

func (e *Unusable) Error() string { return "lsm.list_file " + e.Path + " " + e.Why }
func (e *Unusable) Unwrap() error { return e.Err }

func unusable(p, why string, err error) *Unusable { return &Unusable{Path: p, Why: why, Err: err} }

// file is the setting in force, set once when a command loads the machine config.
var file struct {
	mu   sync.RWMutex
	path string
	err  error
}

// SetFile makes p the list file ("" restores no file). A p that is not a clean absolute path is returned as an error
// and kept: every read then refuses, and a bad setting never falls back to another way.
func SetFile(p string) error {
	file.mu.Lock()
	defer file.mu.Unlock()
	file.path, file.err = "", nil
	if p == "" {
		return nil
	}
	file.path = p
	if !strings.HasPrefix(p, "/") || p == "/" || path.Clean(p) != p || strings.ContainsRune(p, 0) {
		file.err = unusable(p, "is not a clean absolute path", nil)
		return file.err
	}
	return nil
}

// File is the configured path, "" when none is set.
func File() string {
	file.mu.RLock()
	defer file.mu.RUnlock()
	return file.path
}

// Configured reports whether a list file was set (a bad value counts: it refuses, it is not absent).
func Configured() bool { return File() != "" }

func current() (string, error) {
	file.mu.RLock()
	defer file.mu.RUnlock()
	return file.path, file.err
}

// The kernel facts the checks read, variables so tests can stand in for them without root.
var (
	// trustedUID is the owner a handed-in file and every directory above it must have.
	trustedUID uint32 = 0
	// walkRoot is where the walk down to the file starts; its own owner and mode are checked like any directory's.
	walkRoot = "/"
	// ownerOf is the owner the file's check reads from its stat; a variable so a test can name another owner than a
	// directory it made (the directories above it are checked by their own stat).
	ownerOf = func(st *unix.Stat_t) uint32 { return st.Uid }
	// bootIDPath is the kernel's boot id, the same in every container of one boot.
	bootIDPath = "/proc/sys/kernel/random/boot_id"
	// fsMagic is the filesystem type of the open file.
	fsMagic = func(f *os.File) (uint32, error) {
		var st unix.Statfs_t
		if err := sys.FileDo(f, func(fd int) error { return unix.Fstatfs(fd, &st) }); err != nil {
			return 0, err
		}
		return uint32(st.Type), nil //nolint:gosec // the magic numbers are 32 bits
	}
	// checkBind is the securityfs bind check of internal/platform/tomoyo.
	checkBind = tomoyo.CheckSecurityfsBind
)

// refusedFS are filesystems whose owner and mode a program other than the kernel can choose, or whose server can change
// the file under a reader: FUSE (including virtiofs), network filesystems and 9p. A list file on one is not believed.
var refusedFS = map[uint32]string{
	0x65735546: "FUSE", 0x6969: "NFS", 0xFF534D42: "CIFS", 0xFE534D42: "SMB2", 0x01021997: "9p",
	0x00C36400: "Ceph", 0x5346414F: "AFS", 0x786F4256: "vboxsf",
}

// Dangerous capabilities of a task that reads the list for: with any of them it can write a root-owned file, change
// who owns it, or mount over it, so a list read on its behalf is not protected from it.
var taskCaps = []struct {
	bit  uint
	name string
}{{0, "CAP_CHOWN"}, {1, "CAP_DAC_OVERRIDE"}, {3, "CAP_FOWNER"}, {21, "CAP_SYS_ADMIN"}}

// Read returns the active security-module list from the configured file, as /sys/kernel/security/lsm prints it
// ("capability,landlock,yama"), and which shape the file passed as. tid names the task the list is read for (a held
// open's trapped thread): its credentials must not be able to rewrite the file, and are read with readProc
// (/proc/<tid>/status), which may be nil only when tid <= 0, for a reader that has no task (tego doctor, the launch
// note). Every error is ErrNotConfigured or an *Unusable.
func Read(tid int, readProc func(string) ([]byte, error)) (string, Kind, error) {
	p, setErr := current()
	if p == "" {
		return "", "", ErrNotConfigured
	}
	if setErr != nil {
		return "", "", setErr
	}
	f, err := openChecked(p)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = f.Close() }()
	magic, err := fsMagic(f)
	if err != nil {
		return "", "", unusable(p, "has a filesystem type that cannot be read: "+err.Error(), err)
	}
	if name, bad := refusedFS[magic]; bad {
		return "", "", unusable(p, "is on a "+name+" filesystem, whose owner, mode and content a program other than the kernel can choose; keep the list on the container's own filesystem or a read-only bind of securityfs", nil)
	}
	kind := KindHandedIn
	if magic == unix.SECURITYFS_MAGIC {
		kind = KindKernel
		if err := checkBind(p, f, "/lsm"); err != nil {
			return "", "", unusable(p, "is not the kernel's /sys/kernel/security/lsm bound read-only: "+strings.TrimPrefix(err.Error(), p+" "), err)
		}
	} else if err := checkHandedInFile(p, f); err != nil {
		return "", "", err
	}
	b, err := io.ReadAll(io.LimitReader(f, readLimit+1))
	if err != nil {
		return "", "", unusable(p, "cannot be read: "+err.Error(), err)
	}
	if len(b) > readLimit {
		return "", "", unusable(p, fmt.Sprintf("is longer than %d bytes", readLimit), nil)
	}
	var list string
	if kind == KindKernel {
		list = strings.TrimSuffix(string(b), "\n")
	} else if list, err = parseHandedIn(p, b); err != nil {
		return "", "", err
	}
	if err := validList(p, list); err != nil {
		return "", "", err
	}
	if tid > 0 {
		if err := checkTask(p, tid, kind, readProc); err != nil {
			return "", "", err
		}
	}
	return list, kind, nil
}

// openChecked opens p for reading with every directory above it checked, one openat at a time without following a
// link, so no component of the path is another file's name: each must be a directory its trusted owner alone can write.
// The file itself is opened without following a link and without blocking. Every descriptor is an owner (ADR 0023).
func openChecked(p string) (*os.File, error) {
	base := strings.TrimSuffix(walkRoot, "/")
	if !strings.HasPrefix(p, base+"/") {
		return nil, unusable(p, "is not under "+walkRoot, nil)
	}
	parts := strings.Split(strings.TrimPrefix(p, base+"/"), "/")
	dir, err := sys.Own(unix.Open(walkRoot, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		return nil, unusable(p, "cannot be reached: "+err.Error(), err)
	}
	defer func() { _ = dir.Close() }() // the loop replaces dir, and the deferred close sees the one it holds then
	cur := walkRoot
	for i := -1; i < len(parts)-1; i++ {
		if i >= 0 {
			next, err := dir.Openat(parts[i], unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return nil, notThere(p, strings.TrimSuffix(cur, "/")+"/"+parts[i], err)
			}
			_ = dir.Close()
			dir, cur = next, strings.TrimSuffix(cur, "/")+"/"+parts[i]
		}
		var st unix.Stat_t
		if err := dir.Fstat(&st); err != nil {
			return nil, unusable(p, "cannot be checked: "+err.Error(), err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			why := "has a component that is not a directory: " + cur
			if st.Mode&unix.S_IFMT == unix.S_IFLNK {
				why = "has a link in its path (" + cur + "); name the real path"
			}
			return nil, unusable(p, why, nil)
		}
		if why := notTrusted(cur, st.Uid, st.Mode); why != "" {
			return nil, unusable(p, "is in a directory that is not root's alone: "+why, nil)
		}
	}
	file, err := dir.Openat(parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, unusable(p, "is a link; name the real path", err)
		}
		return nil, notThere(p, p, err)
	}
	f, err := file.Release(p)
	if err != nil {
		return nil, unusable(p, "cannot be opened ("+err.Error()+")", err)
	}
	return f, nil
}

func notThere(p, at string, err error) *Unusable {
	switch {
	case errors.Is(err, unix.ENOENT):
		return unusable(p, "is not there ("+at+" does not exist): the container's entrypoint writes it at start, or the host's /sys/kernel/security/lsm is bound read-only at this path", err)
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
		return unusable(p, "cannot be opened (permission denied at "+at+")", err)
	}
	return unusable(p, "cannot be opened ("+at+": "+err.Error()+")", err)
}

// notTrusted is why a file or directory owned by uid with mode is not one only the trusted owner can change.
func notTrusted(name string, uid, mode uint32) string {
	switch {
	case uid != trustedUID:
		return fmt.Sprintf("%s is owned by uid %d, not %d", name, uid, trustedUID)
	case mode&0o022 != 0:
		return fmt.Sprintf("%s is writable by its group or by others (mode %04o)", name, mode&0o7777)
	}
	return ""
}

// checkHandedInFile is what the file an entrypoint wrote must be: a regular file, root's, that only root can write.
func checkHandedInFile(p string, f *os.File) error {
	var st unix.Stat_t
	if err := sys.FileDo(f, func(fd int) error { return unix.Fstat(fd, &st) }); err != nil {
		return unusable(p, "cannot be checked: "+err.Error(), err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return unusable(p, "is not a regular file", nil)
	}
	if why := notTrusted(p, ownerOf(&st), st.Mode); why != "" {
		return unusable(p, "can be written by someone other than root: "+why, nil)
	}
	return nil
}

// nameOK is a module name as the kernel prints it: lower-case letters, digits and an underscore.
var nameOK = regexp.MustCompile(`^[a-z0-9_]+$`)

// parseHandedIn is the list in an entrypoint's file: the three lines of Format, the boot id equal to this boot's.
func parseHandedIn(p string, b []byte) (string, error) {
	want, err := os.ReadFile(bootIDPath)
	if err != nil {
		return "", unusable(p, "cannot be matched to this boot: "+bootIDPath+" cannot be read ("+err.Error()+")", err)
	}
	list, why := ParseHandedIn(b, strings.TrimSpace(string(want)))
	if why != "" {
		return "", unusable(p, why, nil)
	}
	return list, nil
}

// ParseHandedIn is the list in the bytes of an entrypoint's file read in the boot bootID names, or why they are not one:
// the three lines of Format, the second naming that boot. It checks the shape, not the list's names (validList does).
func ParseHandedIn(b []byte, bootID string) (list, why string) {
	if !bytes.HasSuffix(b, []byte("\n")) {
		return "", "is cut short (no newline at its end)"
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 3 || lines[0] != Format || !strings.HasPrefix(lines[1], bootIDLine) || !strings.HasPrefix(lines[2], lsmLine) {
		return "", "is not a list file of this version (want three lines: " + Format + ", boot_id <id>, lsm <list>)"
	}
	if got := strings.TrimPrefix(lines[1], bootIDLine); got == "" || got != bootID {
		return "", "was written in another boot (its boot id is " + strconv.Quote(got) + ", this boot's is " + strconv.Quote(bootID) + "): it is stale, so the entrypoint must write it again at start"
	}
	return strings.TrimPrefix(lines[2], lsmLine), ""
}

// validList refuses a list that cannot be the kernel's (ListProblem).
func validList(p, list string) error {
	if why := ListProblem(list); why != "" {
		return unusable(p, why, nil)
	}
	return nil
}

// ListProblem is why list cannot be the kernel's active list, or "" when it can: names the kernel prints, none twice, at
// most maxModules, and capability, which every kernel has active.
func ListProblem(list string) string {
	if list == "" {
		return "lists no module"
	}
	names := strings.Split(list, ",")
	if len(names) > maxModules {
		return fmt.Sprintf("lists more than %d modules", maxModules)
	}
	for i, n := range names {
		if !nameOK.MatchString(n) {
			return fmt.Sprintf("has a module name that is not one the kernel prints (%q)", n)
		}
		if slices.Contains(names[:i], n) {
			return fmt.Sprintf("names %q twice", n)
		}
	}
	if !slices.Contains(names, "capability") {
		return "does not list capability, which every kernel has active, so it is not a complete list"
	}
	return ""
}

// checkTask refuses a list read for a task that could rewrite it: one that is root (any of its four user ids, since a
// saved id of 0 lets it take 0 back) when the file is root's own, and one holding a capability that overrides the file's
// mode, its owner or its mount. The permitted set is read, not the effective one: a task that holds one of them
// permitted can rewrite the file and then clear its effective set (capset) before the open that is trapped, as
// peer.go's check does; the permitted set contains the effective and the ambient sets. tid's status is read with
// readProc.
func checkTask(p string, tid int, kind Kind, readProc func(string) ([]byte, error)) error {
	if readProc == nil {
		return unusable(p, "cannot be used for a task: no way to read its credentials", nil)
	}
	name := "/proc/" + strconv.Itoa(tid) + "/status"
	b, err := readProc(name)
	if err != nil {
		return unusable(p, "cannot be used for the task: its credentials cannot be read ("+err.Error()+")", err)
	}
	uids, caps, err := parseStatus(b)
	if err != nil {
		return unusable(p, "cannot be used for the task: "+err.Error(), err)
	}
	for _, c := range taskCaps {
		if caps&(1<<c.bit) != 0 {
			return unusable(p, "cannot be used for a task that holds "+c.name+": it could rewrite or replace the file", nil)
		}
	}
	if kind == KindHandedIn {
		for _, u := range uids {
			if u == trustedUID {
				return unusable(p, "cannot be used for a task that is root (a user id of 0): it could rewrite the file", nil)
			}
		}
	}
	return nil
}

// parseStatus is the real, effective, saved and filesystem user ids and the permitted capability set of a
// /proc/<tid>/status. A missing or malformed line is an error, never a zero.
func parseStatus(b []byte) (uids [4]uint32, caps uint64, err error) {
	var haveUID, haveCap bool
	for _, line := range strings.Split(string(b), "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(val)
		switch key {
		case "Uid":
			if len(f) != 4 {
				return uids, 0, fmt.Errorf("its Uid line %q is malformed", val)
			}
			for i := range f {
				n, e := strconv.ParseUint(f[i], 10, 32)
				if e != nil {
					return uids, 0, fmt.Errorf("its Uid line %q is malformed", val)
				}
				uids[i] = uint32(n)
			}
			haveUID = true
		case "CapPrm":
			if len(f) != 1 {
				return uids, 0, fmt.Errorf("its CapPrm line %q is malformed", val)
			}
			n, e := strconv.ParseUint(f[0], 16, 64)
			if e != nil {
				return uids, 0, fmt.Errorf("its CapPrm line %q is malformed", val)
			}
			caps, haveCap = n, true
		}
	}
	if !haveUID || !haveCap {
		return uids, 0, errors.New("its status has no Uid or CapPrm line")
	}
	return uids, caps, nil
}
