// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// entryKind classifies why an fd is held; it drives the access mask the entry carries (§2).
type entryKind uint8

// Entry kinds. Every kind is switched exhaustively in kindName with no default arm, so a new kind
// without a name fails the build.
const (
	kindWrite        entryKind = iota // fs.write: full read+write+create+remove set (masked by ABI)
	kindAsk                           // fs.ask: identity only, Access 0 (SEMANTICS §3.1)
	kindWatch                         // fs.watch: identity only, Access 0 (SEMANTICS §7)
	kindDenyTarget                    // deny_read node itself: Access 0
	kindDenyAncestor                  // enumerated ancestor: READ_DIR only (R3)
	kindDenySibling                   // enumerated sibling: the tier read set (R3)
	kindReadRoot                      // "/" read grant when nothing is denied (SEMANTICS §1: reads allowed)
	kindExecBinary                    // exec.allow file: EXECUTE|READ_FILE (R5)
	kindExecDir                       // exec.allow directory: EXECUTE|READ_FILE|READ_DIR beneath (R5)
	kindExecLoader                    // PT_INTERP loader: EXECUTE|READ_FILE (R5)
	kindExecInterp                    // #! interpreter granted by compile: EXECUTE|READ_FILE (R5)
	kindMCPCommand                    // mcp[].command[0]: EXECUTE|READ_FILE (R5)
	kindAgentCommand                  // the agent command: EXECUTE|READ_FILE (R5)
	kindUnixSocket                    // net.allow unix:<path>: RESOLVE_UNIX, ABI 9+ (R21)
	kindImplicitDeny                  // run dir, contract, /sys/fs/cgroup, /sys/fs/bpf: Access 0 (R8)
	kindPlaneKey                      // a path the decision plane keys: its neutral read rights, or identity only (enforce-plane R16, R17)
	kindDeputy                        // tego's own binary, the open deputy's exec: EXECUTE|READ_FILE (ADR 0041 D2)
)

// kindName is the exhaustive name table used by diagnostics and tests.
func kindName(k entryKind) string {
	switch k {
	case kindWrite:
		return "write"
	case kindAsk:
		return "ask"
	case kindWatch:
		return "watch"
	case kindDenyTarget:
		return "deny_read"
	case kindDenyAncestor:
		return "deny_read ancestor"
	case kindDenySibling:
		return "deny_read sibling"
	case kindReadRoot:
		return "read root"
	case kindExecBinary:
		return "exec binary"
	case kindExecDir:
		return "exec directory"
	case kindExecLoader:
		return "exec loader"
	case kindExecInterp:
		return "exec interpreter"
	case kindMCPCommand:
		return "mcp command"
	case kindAgentCommand:
		return "agent command"
	case kindUnixSocket:
		return "unix socket"
	case kindImplicitDeny:
		return "implicit"
	case kindPlaneKey:
		return "plane key"
	case kindDeputy:
		return "open deputy"
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

// openPath is one held O_PATH fd with the rights its rule grants; Access 0 means identity only.
type openPath struct {
	FD     int
	Path   string
	Kind   entryKind
	Access accessFS
	IsDir  bool
	id     devIno // what FD named when it was opened: owns asks whether the number still does
}

// devIno is the transient (st_dev, st_ino) key of a held fd. It is never persisted, and never used as a
// rule's identity (ADR 0010). It answers two questions. During Prepare only: whether an inode is held
// already under some name (the E7 dedupe in add, which seal's E32 alias check reads through, and
// holdLoader's E29 check that a loader is not a deny_read target's inode). For the fd set's whole life,
// from Prepare through Handle.Close: whether a number this set holds still names the file it was opened
// on (owns), asked after the last rule or a refused one (verify), by closeAll in Prepare's
// cleanup on a failed build, and by closeAll again at Handle.Close, at run end.
// Over that longer window an overlayfs copy-up can renumber a non-directory (ADR 0010); owns cannot tell
// that from a reused number, so its error names both causes and the fd is left open (I12).
type devIno struct {
	dev uint64
	ino uint64
}

// fdSet owns every fd Prepare opens: one owner, one release path (§9). Entries are appended in open
// order and released in reverse by closeAll.
type fdSet struct {
	open  []openPath
	ids   map[devIno]int                       // index into open, for E7 dedupe
	paths map[string]int                       // index into open by every path held, a deduped one included (PlaneHeld)
	statx func(fd int, sx *unix.Statx_t) error // owns' identity query; tests stand in one that fails
	// budget is what the set may hold (fdbudget.go), when budgeted: Prepare reads it before the first open.
	budget   FDBudget
	budgeted bool
}

func newFDSet() *fdSet {
	return &fdSet{ids: map[devIno]int{}, paths: map[string]int{}, statx: statxHeld}
}

// statxHeld is statx(2) on the number itself, asked with AT_STATX_DONT_SYNC so a network or FUSE
// filesystem answers from the inode the open already holds, with no round trip to a server that could
// stall Close.
func statxHeld(fd int, sx *unix.Statx_t) error {
	return unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_STATX_DONT_SYNC, unix.STATX_INO, sx)
}

// sealed reports the kinds whose rights R3 fixes: a deny_read target (none, R3 (1)) and an enumerated
// ancestor (listing only, R3 (3)). Landlock keys its rules by inode and a rule only ever adds rights, so
// a union onto either would grant, under whatever other name reaches the same inode, what the
// enumeration withholds from the target (I11).
func (k entryKind) sealed() bool { return k == kindDenyTarget || k == kindDenyAncestor }

// add takes ownership of fd. When the same inode is already held, the rights union onto the existing
// entry, fd is closed, and the existing index is returned (E7, E17) — except on a sealed entry, whose
// rights stay what walk gave it. The refusal is silent here because what it costs depends on the
// caller: an enumerated sibling that is a deny node under another name (a hardlink of a target, a bind
// mount of an ancestor) is the same content, and leaving it with the node's rights is the deny itself;
// a declared exec or unix-socket grant would be lost, so holdGrant fails the build instead; a loader is
// refused before it gets here (holdLoader). The other direction — a deny node whose inode an earlier
// stage already holds — is not this guard's: the entry found is not sealed yet, so seal re-marks it or
// fails the build (E32).
//
// The one union a sealed entry takes is a plane key's neutral rule (ADR 0025 (3), enforce-plane §2.4 condition 5):
// read rights the domain already grants at that inode, computed by decide.CompilePlane and proven there to leave the
// union at every path unchanged (TestNeutralRulesKeepTheUnion), so the domain holds the deny node's inode for the
// plane's row without granting anything new under any name.
func (s *fdSet) add(fd int, path string, kind entryKind, access accessFS, st *unix.Stat_t) int {
	key := devIno{dev: st.Dev, ino: st.Ino}
	if i, dup := s.ids[key]; dup {
		_ = unix.Close(fd)
		if !s.open[i].Kind.sealed() || kind == kindPlaneKey {
			s.open[i].Access |= access
		}
		s.paths[path] = i
		return i
	}
	s.open = append(s.open, openPath{FD: fd, Path: path, Kind: kind, Access: access, IsDir: st.Mode&unix.S_IFMT == unix.S_IFDIR, id: key})
	s.ids[key] = len(s.open) - 1
	s.paths[path] = len(s.open) - 1
	return len(s.open) - 1
}

// link takes ownership of fd, a descriptor held at one hard link of an inode entry i already holds under another
// name, for the decision plane's fill alone (enforce-plane R16, §6 E15): an exec row is keyed by the link an entry
// names, which the fill reads from the descriptor's own dentry, so each exec row's path needs a descriptor opened at
// that path. The entry is identity only (Access 0, no rule: Landlock's rule is on the inode, which entry i carries),
// is not an E7 dedupe target (ids keeps pointing at i), and is released and checked (owns) like every other.
func (s *fdSet) link(fd int, path string, st *unix.Stat_t) int {
	s.open = append(s.open, openPath{FD: fd, Path: path, Kind: kindPlaneKey, IsDir: st.Mode&unix.S_IFMT == unix.S_IFDIR,
		id: devIno{dev: st.Dev, ino: st.Ino}})
	s.paths[path] = len(s.open) - 1
	return len(s.open) - 1
}

// owns reports whether entry i's number still names the file it was opened on. This set is the
// only closer of the numbers it holds (§9), but a number is process-wide: when something else in the
// process closes one, the kernel hands it to the next open anywhere, and a landlock_add_rule through it
// then lands on that file, as does closeAll's close. The check cannot see a number that has been closed
// and reopened on this same file by the time it looks.
//
// Only two answers show the number is not this entry's any more, and only those disown it (FD -1): EBADF,
// where nothing is left to close (statx on the number sees O_PATH files, so unlike the ruleset probe's
// EBADF this one means closed), and another (dev, ino), where closing the number would close its new
// owner's descriptor. Any other failure (ENOMEM, a filesystem's EIO, a seccomp profile refusing statx)
// leaves the number held and the question open: it fails the check, so Prepare fails closed, and closeAll
// asks again and closes the number only if the answer is then its own file.
func (s *fdSet) owns(i int) error {
	e := &s.open[i]
	var sx unix.Statx_t
	err := s.statx(e.FD, &sx)
	was := fmt.Sprintf("dev %d:%d ino %d", unix.Major(e.id.dev), unix.Minor(e.id.dev), e.id.ino)
	var lost string
	switch {
	case err == nil && unix.Mkdev(sx.Dev_major, sx.Dev_minor) == e.id.dev && sx.Ino == e.id.ino:
		return nil
	case err == nil:
		// An overlayfs whose layers sit on different filesystems without xino can renumber a non-directory
		// when it is copied up (ADR 0010), which reads the same as a reused number; the message says both.
		lost = fmt.Sprintf("now names dev %d:%d ino %d, not %s as when it was opened: something else in this process closed that number and it was reused (or an overlayfs copy-up renumbered the file), so it is not closed again here",
			sx.Dev_major, sx.Dev_minor, sx.Ino, was)
	case errors.Is(err, unix.EBADF):
		lost = fmt.Sprintf("is not open any more (%v): something else in this process closed it", err)
	default:
		return fmt.Errorf("fd %d held for %s %q: statx failed, so whether it still names %s, as when it was opened, is unknown, and it is not closed while that is so: %w",
			e.FD, kindName(e.Kind), e.Path, was, err)
	}
	fd := e.FD
	e.FD = -1
	return fmt.Errorf("fd %d held for %s %q %s", fd, kindName(e.Kind), e.Path, lost)
}

// verify is owns over every entry still held, errors joined.
func (s *fdSet) verify() error {
	var errs []error
	for i := range s.open {
		if s.open[i].FD < 0 {
			continue
		}
		if err := s.owns(i); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// closeAll releases every fd exactly once (best effort, errors joined) and empties the set. A number
// owns does not recognise as the entry's own is reported and left open rather than closed: one it shows
// lost may be another owner's by now, and one whose identity is unknown might be (I12).
func (s *fdSet) closeAll() error {
	var errs []error
	for i := len(s.open) - 1; i >= 0; i-- {
		if s.open[i].FD < 0 {
			continue
		}
		if err := s.owns(i); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := unix.Close(s.open[i].FD); err != nil {
			errs = append(errs, fmt.Errorf("close %q: %w", s.open[i].Path, err))
		}
		s.open[i].FD = -1
	}
	s.open = nil
	s.ids = map[devIno]int{}
	s.paths = map[string]int{}
	return errors.Join(errs...)
}

// openAt opens name relative to dirfd as O_PATH|O_CLOEXEC (E12: identity fixed now, not at compile)
// and fstats it. follow=false adds O_NOFOLLOW so an enumerated sibling that is a symlink never grants
// its target. Errors are classified: ENOENT/ELOOP/ENOTDIR/ENAMETOOLONG (a name that cannot exist) are
// ErrPathVanished, EMFILE/ENFILE are ErrFDExhausted, anything else is wrapped verbatim. An open past s's budget is
// not made: it is an FDCapError naming the cap (fdbudget.go).
func openAt(dirfd int, name string, follow bool, s *fdSet) (int, unix.Stat_t, error) {
	held := 0
	if s != nil {
		held = len(s.open)
	}
	var st unix.Stat_t
	if err := s.room(name); err != nil {
		return -1, st, err
	}
	flags := unix.O_PATH | unix.O_CLOEXEC
	if !follow {
		flags |= unix.O_NOFOLLOW
	}
	fd, err := unix.Openat(dirfd, name, flags, 0)
	if err != nil {
		return -1, st, classifyOpenErr(name, held, err)
	}
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, st, fmt.Errorf("fstat %q: %w", name, err)
	}
	return fd, st, nil
}

// Preserve the open origin separately from errno: an EACCES/ENOENT while
// inspecting an already-open descriptor is uncertainty, not traversal failure.
type pathOpenError struct{ error }

func (e *pathOpenError) Unwrap() error { return e.error }

func classifyOpenErr(name string, held int, err error) error {
	var classified error
	switch {
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.ENAMETOOLONG):
		classified = fmt.Errorf("%w: %q: %w", ErrPathVanished, name, err)
	case errors.Is(err, unix.EMFILE), errors.Is(err, unix.ENFILE):
		classified = fmt.Errorf("%w: %d fds held when opening %q: %w", ErrFDExhausted, held, name, err)
	default:
		classified = fmt.Errorf("open %q: %w", name, err)
	}
	return &pathOpenError{classified}
}
