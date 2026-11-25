// SPDX-License-Identifier: Apache-2.0

package tomoyo

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"golang.org/x/sys/unix"
)

// factsState is the facts directory in force: dir "" is the kernel's own (/sys/kernel/security/tomoyo), err a configured
// directory that cannot be used, which refuses every fact.
var factsState struct {
	mu  sync.RWMutex
	dir string
	err error
}

// SetFactsDir makes dir the directory TOMOYO's three facts are read from, in place of the kernel's
// /sys/kernel/security/tomoyo ("" restores it): the machine config's tomoyo.facts_dir, which only the administrator's
// /etc/tego/config.yaml sets (ADR 0041, 2026-11-22). It is set once when a command loads the machine config. A dir
// that is not a clean absolute path is returned as an error, and every fact is then refused, so a bad setting never
// falls back to the kernel's path.
func SetFactsDir(dir string) error {
	factsState.mu.Lock()
	defer factsState.mu.Unlock()
	factsState.dir, factsState.err = "", nil
	if dir == "" {
		return nil
	}
	factsState.dir = dir
	if !strings.HasPrefix(dir, "/") || dir == "/" || path.Clean(dir) != dir || strings.ContainsRune(dir, 0) {
		factsState.err = fmt.Errorf("TOMOYO facts_dir %q is not a clean absolute path; held file opens are refused on this machine", dir)
		return factsState.err
	}
	return nil
}

// FactsDir is the directory the facts are read from: the configured one, or the kernel's path when none is set.
func FactsDir() string {
	if dir, _ := currentFacts(); dir != "" {
		return dir
	}
	return strings.TrimSuffix(dir, "/")
}

// Configured reports whether a facts directory other than the kernel's was set.
func Configured() bool {
	dir, _ := currentFacts()
	return dir != ""
}

func currentFacts() (string, error) {
	factsState.mu.RLock()
	defer factsState.mu.RUnlock()
	return factsState.dir, factsState.err
}

// factNames are the three files a facts directory holds.
var factNames = [...]string{"self_domain", "stat", "profile"}

// factsRead is read with the kernel's TOMOYO paths answered from the facts directory when one is set.
func factsRead(read func(string) ([]byte, error)) func(string) ([]byte, error) {
	cfg, err := currentFacts()
	if cfg == "" && err == nil {
		return read
	}
	return func(p string) ([]byte, error) {
		if !strings.HasPrefix(p, dir) {
			return read(p)
		}
		if err != nil {
			return nil, err
		}
		real := cfg + "/" + p[len(dir):]
		b, e := read(real)
		if e != nil {
			e = fmt.Errorf("read as %s: %w", real, e)
		}
		return b, e
	}
}

// checkOpened is the check for f opened at p when p is a TOMOYO fact (a configured directory's or the kernel's).
func checkOpened(p string, f *os.File) error {
	if cfg, _ := currentFacts(); cfg != "" && strings.HasPrefix(p, cfg+"/") {
		return checkFactsDirFile(p, cfg, f)
	}
	return CheckSecurityfs(f)
}

// refuseFact is the refusal of a facts-directory file p, in the words every TOMOYO refusal ends with.
func refuseFact(p, why string) error {
	return fmt.Errorf("TOMOYO fact %s %s; held file opens are refused on this machine; the facts directory must be a read-only bind of the host's /sys/kernel/security/tomoyo (tomoyo.facts_dir)", p, why)
}

// mountinfoLimit bounds the mountinfo read for one check: a larger table is refused, never cut.
const mountinfoLimit = 4 << 20

// checkFactsDirFile is the check of f, opened at p under the configured facts directory cfg. The file must be on
// securityfs (the same magic check the kernel's path gets), and its mount, found by the mount id statx reports for
// the descriptor and read in /proc/self/mountinfo, must be a securityfs mount that is read-only and whose file is
// exactly /tomoyo/<name>: the root of the bind, joined with the path below its mount point. Another securityfs file
// (AppArmor's, the LSM list) bound in a fact's place has another path and is refused; so is a bind that can write
// self_domain, which TOMOYO takes domain transitions from. The descriptor's own path (/proc/self/fd) must be the one
// opened, so no link in the path stands for another file.
func checkFactsDirFile(p, cfg string, f *os.File) error {
	name := strings.TrimPrefix(p, cfg+"/")
	if !slices.Contains(factNames[:], name) {
		return refuseFact(p, "is not one of TOMOYO's files (self_domain, stat, profile)")
	}
	if err := CheckSecurityfs(f); err != nil {
		return err
	}
	if why := securityfsBindWhy(p, f, "/tomoyo/"+name); why != "" {
		return refuseFact(p, why)
	}
	return nil
}

// CheckSecurityfsBind is the check a securityfs file bound into a container gets (the facts directory's, and the
// security-module list's, which is /lsm): f, opened at p, must be on securityfs (the filesystem magic), on a mount that
// is read-only, whose file is exactly wantInFS (the root of the bind joined with the path below its mount point, so
// another securityfs file bound in its place is refused), and p must be the path the kernel resolved for the descriptor
// (no link in it). Securityfs is one kernel instance and mounting it needs CAP_SYS_ADMIN in the initial user
// namespace, so what passes is the kernel's own file. The error says what is wrong and nothing about what it is for.
func CheckSecurityfsBind(p string, f *os.File, wantInFS string) error {
	typ, err := statfsType(f)
	if err != nil {
		return fmt.Errorf("%s: cannot tell what filesystem it is on: %w", p, err)
	}
	if typ != uint32(unix.SECURITYFS_MAGIC) {
		return fmt.Errorf("%s is not on securityfs (filesystem type %#x)", p, typ)
	}
	if why := securityfsBindWhy(p, f, wantInFS); why != "" {
		return fmt.Errorf("%s %s", p, why)
	}
	return nil
}

// securityfsBindWhy is why f, opened at p, is not the securityfs file wantInFS on a read-only mount, or "" when it
// is. The magic check is the caller's.
func securityfsBindWhy(p string, f *os.File, wantInFS string) string {
	link, err := fdPath(f)
	if err != nil {
		return "has no path of its own the check can read: " + err.Error()
	}
	if link != p {
		return "is reached through a link (the descriptor's path is " + link + ")"
	}
	id, err := statxMountID(f)
	if err != nil {
		return "has a mount id that cannot be read: " + err.Error()
	}
	raw, err := readMountinfo()
	if err != nil {
		return "cannot be placed: mountinfo cannot be read: " + err.Error()
	}
	m, err := findMount(raw, id)
	if err != nil {
		return err.Error()
	}
	if m.fstype != "securityfs" {
		return "is on a mount mounted as " + m.fstype + ", not securityfs"
	}
	if !slices.Contains(strings.Split(m.options, ","), "ro") {
		return "is on a writable mount (" + m.options + ")"
	}
	rel, err := filepath.Rel(m.point, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return "is not under the mount point " + m.point + " mountinfo names for it"
	}
	if inFS := filepath.Join(m.root, rel); inFS != wantInFS {
		return "is at path " + inFS + " in its filesystem, not " + wantInFS
	}
	return ""
}

// mount is the fields of one mountinfo line the check reads.
type mount struct {
	root, point, options, fstype string
}

// errMountinfoLine is a mountinfo line of the wanted mount that this check cannot read.
var errMountinfoLine = errors.New("has a mountinfo line this check does not parse")

// findMount is the line of raw (a /proc/self/mountinfo) whose mount id is id: "id parent major:minor root point
// options [optional fields] - fstype source super-options".
func findMount(raw []byte, id uint64) (mount, error) {
	want := strconv.FormatUint(id, 10)
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Split(line, " ")
		if fields[0] != want {
			continue
		}
		if len(fields) < 10 {
			return mount{}, errMountinfoLine
		}
		dash := slices.Index(fields[6:], "-")
		if dash < 0 || len(fields[6+dash+1:]) < 3 {
			return mount{}, errMountinfoLine
		}
		root, ok1 := unescapeMount(fields[3])
		point, ok2 := unescapeMount(fields[4])
		if !ok1 || !ok2 {
			return mount{}, errMountinfoLine
		}
		return mount{root: root, point: point, options: fields[5], fstype: fields[6+dash+1]}, nil
	}
	return mount{}, fmt.Errorf("has no mountinfo line for mount id %s", want)
}

// unescapeMount decodes the octal escapes the kernel writes in a mountinfo path (\040 space, \011 tab, \012 newline,
// \134 backslash), and reports false for any other backslash.
func unescapeMount(s string) (string, bool) {
	if !strings.Contains(s, `\`) {
		return s, true
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+3 >= len(s) {
			return "", false
		}
		switch s[i : i+4] {
		case `\040`:
			b.WriteByte(' ')
		case `\011`:
			b.WriteByte('\t')
		case `\012`:
			b.WriteByte('\n')
		case `\134`:
			b.WriteByte('\\')
		default:
			return "", false
		}
		i += 3
	}
	return b.String(), true
}

// The kernel facts the mountinfo check reads, variables so tests can stand in for them without root.
var (
	// statxMountID is the mount id statx(2) reports for the open file (STATX_MNT_ID, Linux 5.8: the numbering
	// mountinfo's first field uses, which names this very mount and no other at the same point).
	statxMountID = func(f *os.File) (uint64, error) {
		var stx unix.Statx_t
		if err := sys.FileDo(f, func(fd int) error {
			return unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &stx)
		}); err != nil {
			return 0, err
		}
		if stx.Mask&unix.STATX_MNT_ID == 0 {
			return 0, errors.New("the kernel does not report mount ids (statx STATX_MNT_ID, Linux 5.8)")
		}
		return stx.Mnt_id, nil
	}
	// readMountinfo is this process's /proc/self/mountinfo, refused when longer than mountinfoLimit.
	readMountinfo = func() ([]byte, error) {
		fh, err := os.Open("/proc/self/mountinfo")
		if err != nil {
			return nil, err
		}
		defer func() { _ = fh.Close() }()
		b, err := io.ReadAll(io.LimitReader(fh, mountinfoLimit+1))
		if err == nil && len(b) > mountinfoLimit {
			err = fmt.Errorf("longer than %d bytes", mountinfoLimit)
		}
		return b, err
	}
	// fdPath is what /proc/self/fd/<n> names for the open file: the path the kernel resolved, with no link in it.
	fdPath = func(f *os.File) (string, error) {
		var link string
		err := sys.FileDo(f, func(fd int) error {
			var err error
			link, err = os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
			return err
		})
		return link, err
	}
)
