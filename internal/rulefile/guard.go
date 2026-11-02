// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// ErrGuard is a contract file this package will not read for a change or write: a symlink, a hard link, a file or
// directory someone other than this user could have written, one too large to be a contract, or one under the
// ledger root or tego's home. The error text names which and why.
var ErrGuard = errors.New("rulefile: refused")

// ErrStale is a write whose base is no longer what the file holds: someone changed it since it was read. Nothing
// was written.
var ErrStale = errors.New("rulefile: the contract changed since it was read")

// Guard is where a contract may not be: the ledger root, which also holds the journal (journal.go), and tego's own
// directories. A contract inside one of them would let a change from the dashboard rewrite what a run records or
// what tego trusts (a governance log, a chain anchor, a profile), so it is refused even when every file check passes.
type Guard struct {
	// LedgerRoot is the ledger root whose .rule-changes/ journals each write; "" journals nothing (a write is
	// refused: no change goes unrecorded).
	LedgerRoot string
	// Refuse are more directories no contract may be under: tego's home (~/.tego) as the passwd database and $HOME
	// name it (DefaultGuard).
	Refuse []string
}

// DefaultGuard is the guard for the runs under ledgerRoot: it refuses that root and tego's home, ~/.tego, both as the
// passwd database names the home (the engine's rule, R21) and as $HOME does, when they differ.
func DefaultGuard(ledgerRoot string) Guard {
	g := Guard{LedgerRoot: ledgerRoot}
	if h, err := config.PasswdHome(geteuid()); err == nil {
		g.Refuse = append(g.Refuse, filepath.Join(h, ".tego"))
	}
	if h := os.Getenv("HOME"); h != "" && filepath.IsAbs(h) {
		if p := filepath.Join(h, ".tego"); len(g.Refuse) == 0 || g.Refuse[0] != p {
			g.Refuse = append(g.Refuse, p)
		}
	}
	return g
}

// File is a contract file read through the guards: its path as resolved once, its bytes and their sha256, and its
// permission bits, which a write keeps.
type File struct {
	// Path is the file's absolute path with every symlink in its directory resolved: the path the write pins.
	Path string
	Text []byte
	// SHA256 is the hex sha256 of Text: the base a change carries so that it lands only on the text it was made from.
	SHA256 string
	Mode   os.FileMode
}

// Sum is the hex sha256 of b, the form a base, a journal line and a blob name use.
func Sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Test seams, nil or the real call in a product build. geteuid and getegid let a test play another user; hook runs
// at each named step of a guarded open and write ("resolved", "read", "bak", "temp", "rename", "journal", and "lock"
// between a lock file's open and its flock) and a non-nil error from it fails that step, as a disk would.
var (
	geteuid = os.Geteuid
	getegid = os.Getegid
	hook    func(string) error
	// groupFile and passwdFile are the databases the private-group test reads.
	groupFile  = "/etc/group"
	passwdFile = "/etc/passwd"
)

func step(name string) error {
	if hook == nil {
		return nil
	}
	return hook(name)
}

// Read reads the contract at path through the guards: see pinned.open. Nothing is written.
func Read(path string, g Guard) (*File, error) {
	p, err := pin(path, g)
	if err != nil {
		return nil, err
	}
	defer p.close()
	f, err := p.read()
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("the contract %s is gone: %w", p.path, err) // the openat below knows only the errno
	}
	return f, err
}

// pinned is a contract's directory, opened once with no symlink followed and checked, and the file's name in it.
// Every later open, rename and sync is relative to dir, so a directory swapped for a symlink after the pin changes
// nothing this package touches.
type pinned struct {
	dir  *sys.FD
	path string // the resolved absolute path, for messages and the journal
	name string // the file's name in dir
}

// pin resolves path once (so a home reached through a symlink still works), refuses one under the ledger root or a
// Refuse directory, opens the resolved directory with RESOLVE_NO_SYMLINKS and checks it: owned by this user or root,
// and not writable by others unless sticky.
func pin(path string, g Guard) (*pinned, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: %s is not an absolute path", ErrGuard, path)
	}
	path = filepath.Clean(path)
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	name := filepath.Base(path)
	if name == "." || name == ".." || name == "/" {
		return nil, fmt.Errorf("%w: %s names no file", ErrGuard, path)
	}
	full := filepath.Join(dir, name)
	for _, r := range append([]string{g.LedgerRoot}, g.Refuse...) {
		if r == "" {
			continue
		}
		if under(full, resolved(r)) {
			return nil, fmt.Errorf("%w: %s is under %s, which is tego's own (the ledger root or tego's home): a "+
				"contract there is not changed from here; move it out and run it from there", ErrGuard, full, r)
		}
	}
	if err := step("resolved"); err != nil {
		return nil, err
	}
	d, err := openDir(dir)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) {
			return nil, fmt.Errorf("%w: a directory of %s became a symlink after it was resolved", ErrGuard, full)
		}
		return nil, fmt.Errorf("open %s: %w", dir, err)
	}
	var st unix.Stat_t
	if err := d.Fstat(&st); err != nil {
		_ = d.Close() // the fstat's error is the one to report
		return nil, fmt.Errorf("stat %s: %w", dir, err)
	}
	euid := uint32(geteuid())
	switch {
	case st.Uid != euid && st.Uid != 0:
		err = fmt.Errorf("%w: %s's folder %s is owned by uid %d, not by you (uid %d) or root", ErrGuard, name, dir, st.Uid, euid)
	case st.Mode&0o002 != 0 && st.Mode&unix.S_ISVTX == 0:
		err = fmt.Errorf("%w: %s's folder %s is writable by every user and not sticky, so another user could swap "+
			"the file; chmod o-w %s", ErrGuard, name, dir, dir)
	}
	if err != nil {
		_ = d.Close() // the refusal is the error to report
		return nil, err
	}
	return &pinned{dir: d, path: full, name: name}, nil
}

func (p *pinned) close() { _ = p.dir.Close() } // read-only and relative opens only: nothing to flush

// openDir opens dir for reading (so it can be fsync'ed) with no symlink followed on the way.
func openDir(dir string) (*sys.FD, error) {
	for {
		d, err := sys.Own(unix.Openat2(unix.AT_FDCWD, dir, &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_NO_SYMLINKS,
		}))
		if !errors.Is(err, unix.EINTR) && !errors.Is(err, unix.EAGAIN) {
			return d, err
		}
	}
}

// read opens the file in the pinned directory with O_NOFOLLOW and checks what fstat says of the descriptor it read:
// a regular file, owned by this user, one link, not writable by others, writable by its group only when that group
// is the user's private group, and at most agent.MaxContractSize bytes.
func (p *pinned) read() (*File, error) {
	fd, err := p.dir.Openat(p.name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%w: %s is a symlink; change the file it points to and run that", ErrGuard, p.path)
		}
		return nil, err
	}
	var st unix.Stat_t
	if err := fd.Fstat(&st); err != nil {
		_ = fd.Close() // the fstat's error is the one to report
		return nil, err
	}
	if err := fileOK(p.path, &st); err != nil {
		_ = fd.Close() // the refusal is the error to report
		return nil, err
	}
	f, err := fd.Release(p.path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only
	b, err := io.ReadAll(io.LimitReader(f, agent.MaxContractSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > agent.MaxContractSize {
		return nil, fmt.Errorf("%w: %s grew past %d bytes while it was read", ErrGuard, p.path, agent.MaxContractSize)
	}
	return &File{Path: p.path, Text: b, SHA256: Sum(b), Mode: os.FileMode(st.Mode & 0o777)}, nil
}

// fileOK is the file checks of read.
func fileOK(path string, st *unix.Stat_t) error {
	euid := uint32(geteuid())
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return fmt.Errorf("%w: %s is not a regular file", ErrGuard, path)
	case st.Uid != euid:
		return fmt.Errorf("%w: %s is owned by uid %d, not by you (uid %d); only your own contracts are changed from "+
			"here", ErrGuard, path, st.Uid, euid)
	case st.Nlink != 1:
		return fmt.Errorf("%w: %s has %d hard links, so a change would also change another file; copy it to a file of "+
			"its own and run that", ErrGuard, path, st.Nlink)
	case st.Mode&0o002 != 0:
		return fmt.Errorf("%w: %s is writable by every user; chmod o-w %s", ErrGuard, path, path)
	case st.Mode&0o020 != 0 && !privateGroup(st.Gid, euid):
		return fmt.Errorf("%w: %s is writable by group %d, which is not your private group; chmod g-w %s", ErrGuard,
			path, st.Gid, path)
	case st.Size > agent.MaxContractSize:
		return fmt.Errorf("%w: %s is %d bytes, more than a contract may be (%d)", ErrGuard, path, st.Size, agent.MaxContractSize)
	}
	return nil
}

// privateGroup is whether gid is uid's user private group: the effective group of this process, named in the group
// database with no member but the user, and the primary group of no other user. A group the files databases do not
// name (NSS, LDAP) is not one: the check fails closed.
func privateGroup(gid, uid uint32) bool {
	if gid != uint32(getegid()) {
		return false
	}
	g, err := os.ReadFile(groupFile)
	if err != nil {
		return false
	}
	p, err := os.ReadFile(passwdFile)
	if err != nil {
		return false
	}
	want := strconv.FormatUint(uint64(gid), 10)
	me := ""
	for _, f := range rows(p, 7) {
		switch {
		case f[2] == strconv.FormatUint(uint64(uid), 10):
			me = f[0]
		case f[3] == want:
			return false // another user's primary group too
		}
	}
	named := false
	for _, f := range rows(g, 4) {
		if f[2] != want {
			continue
		}
		named = true
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" && m != me {
				return false
			}
		}
	}
	return named && me != ""
}

// rows splits a colon-separated database into rows of at least n fields, skipping blank and # lines and NIS compat
// rows (+, -).
func rows(b []byte, n int) [][]string {
	var out [][]string
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == '+' || line[0] == '-' {
			continue
		}
		if f := strings.SplitN(line, ":", n); len(f) >= n {
			out = append(out, f)
		}
	}
	return out
}

// resolved is p with its symlinks resolved, or cleaned when it cannot be (it may not exist yet).
func resolved(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// under is whether p is dir or inside it.
func under(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}
