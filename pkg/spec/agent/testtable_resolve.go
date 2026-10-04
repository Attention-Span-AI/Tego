// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Lookup is how the kernel looks one end of a syscall up: the one statement of it that compile --test's rows and the
// run's own handlers share (ADR 0019's design note). The supervisor builds the
// walk of every end it decides from it (internal/runtime/supervisor's pathQuery.as), compile lands each end of a row with
// the Lookup of the syscall the row stands for (ActionKind.Lookups), and a test holds each of the run's handlers to that
// table, so the two cannot ask different walks of one end. Each value is one of the kernel's own lookups, and differs
// from the others for some pathname: a final symlink, a final "." or "..", or a dangling final symlink.
type Lookup uint8

const (
	// LookupFollow is path_lookupat with LOOKUP_FOLLOW: the whole pathname, a final symlink followed. open(2) without
	// O_CREAT or O_NOFOLLOW, execve(2), chmod(2), chown(2), setxattr(2), truncate(2), linkat(2)'s old name with
	// AT_SYMLINK_FOLLOW, connect(2).
	LookupFollow Lookup = iota
	// LookupCreate is open(2) with O_CREAT and without O_EXCL or O_NOFOLLOW: LookupFollow, save that a dangling final
	// symlink is followed to the name the open then creates.
	LookupCreate
	// LookupNoFollow is path_lookupat without LOOKUP_FOLLOW: the whole pathname, a final symlink the end itself, and a
	// final "." or ".." resolved physically where the walk lands, since neither is ever a symlink. open(2) with
	// O_NOFOLLOW or O_CREAT|O_EXCL, every AT_SYMLINK_NOFOLLOW form, lchown(2), lsetxattr(2), and the old name of link(2)
	// and of linkat(2) without AT_SYMLINK_FOLLOW.
	LookupNoFollow
	// LookupParent is filename_parentat and filename_create: only the directory of the final component is looked up,
	// and the syscall makes, removes or renames the final name in it, so it refuses a final "." or ".." before a lookup
	// of its own (EEXIST, EBUSY, EISDIR, EINVAL, ENOTEMPTY), and a trailing slash, which it strips, never has it follow
	// a final symlink: the name is looked up in its directory as it is (mkdir of "lk/" is EEXIST, an rmdir ENOTDIR).
	// unlink(2), rmdir(2), mkdir(2), mknod(2), symlink(2)'s new name, both ends of rename(2), the new name of link(2)
	// and linkat(2), a unix bind(2).
	LookupParent
)

// Lookups are how the kernel looks a row's ends up, by the syscall each kind of row stands for (limits-check-doctor-cli
// R28): path is the row's path's lookup, dest its dest's (a rename's or a link's new name). An fs.read row is an
// open(2) for reading, an fs.write row an open(2) with O_CREAT, an fs.attr row a chmod(2), an exec row an execve(2) and
// its #! interpreter's open, an exec.map row the open of the file it maps, an fs.delete row an unlink(2), an fs.mkdir
// row a mkdir(2), an fs.rename row a rename(2), an fs.link row a link(2), which does not follow its old name's final
// symlink and looks that name up whole, and a pathname net.bind row a bind(2). This is the one table of them:
// RunResolved lands each end with it, and the supervisor's TestEveryRowEndIsWalkedAsItsSyscall drives the run's own
// handler of each syscall and holds the walk it asks to this answer.
func (k ActionKind) Lookups() (path, dest Lookup) {
	switch k {
	case ActionFSWrite:
		return LookupCreate, LookupParent
	case ActionFSLink:
		return LookupNoFollow, LookupParent
	case ActionFSDelete, ActionFSMkdir, ActionFSRename, ActionNetBind:
		return LookupParent, LookupParent
	}
	return LookupFollow, LookupParent
}

// A Lander is where the kernel's walk of the absolute pathname p leads for a syscall end looked up as how says
// (Lookup): compile --test passes the run's own walk (internal/runtime/supervisor.Land), so a row and the run's line
// land a path with one resolver (ADR 0019's 2026-10-17 design note) asked the same question. p is as the agent's
// syscall would spell it, uncleaned, since the walk takes "lk/.." physically. err is a walk that fails as the agent's
// own lookup fails (ENOTDIR, ELOOP, EACCES, ENAMETOOLONG, EINVAL), or ErrUnwalked for one the Lander could not make;
// the row's path is then evaluated as written, cleaned, save a bind's, which the run refuses when its walk fails.
type Lander func(p string, how Lookup) (at string, err error)

// A UnixLander is where the run's walk of a connect's or a datagram's absolute unix pathname p takes it, what that walk
// met, and whether what it reaches is a socket (UnixLanding): compile --test passes the run's own unix walk
// (internal/runtime/supervisor.LandUnix), so a row and the run's line decide the name on one walk. err is ErrUnwalked, a
// walk the UnixLander could not make: the name is then decided on its spelling alone.
type UnixLander func(p string) (UnixLanding, error)

// UnixLanding is a UnixLander's answer for one name, asked before the agent runs, of the tree the agent calls in (ADR
// 0019's design note): the tree as it is, every directory the name's walk needs
// made, and the socket the agent binds at a final name that names nothing yet and that nothing needs as a directory.
type UnixLanding struct {
	// At is where the walk lands (Action.Landed), "" when it does not.
	At string
	// Walk is what the walk met (Action.Walk).
	Walk UnixWalk
	// NoSocket says At is no socket in that tree (Action.NoSocket): a directory, or a file that is not a socket.
	NoSocket bool
}

// Landers are the run's walks RunResolved lands a row's paths with: Path for filesystem and exec paths and a bind's
// socket name (the run's FSTarget, which bindUnix decides on), Unix for a connect's or a datagram's unix pathname (the
// run's unixWalk). Either may be nil: the paths it would land are evaluated as written.
type Landers struct {
	Path Lander
	Unix UnixLander
}

// ErrUnwalked is a Lander's or a UnixLander's answer for a walk it could not make at all (no /proc, its own descriptors
// exhausted), as opposed to one that fails as the agent's own lookup fails: the path is evaluated as written.
var ErrUnwalked = errors.New("agent: the path could not be walked")

// resolveAction lands a row's filesystem and exec paths, and a unix pathname's, with land (RunResolved) and reports
// each one that landed elsewhere than its cleaned spelling. a's paths are spelled as written (TestRow.build with
// spelled set); every filesystem path that comes back is absolute and clean, or a bare command name, and a unix name
// keeps its spelling beside the socket it landed on (Action.Landed, Action.Walk).
func resolveAction(a Action, land Landers) (Action, ResolvedPaths) {
	var rp ResolvedPaths
	pathHow, destHow := a.Kind.Lookups()
	switch a.Kind {
	case ActionNetConnect, ActionNetSend:
		// The run decides a unix pathname twice (supervisor R11, R11a; SEMANTICS §5 as amended 2026-10-16): on the
		// name the connect or the datagram passes, then on what its own unix walk of that name meets. Path keeps the
		// name, Landed is what the walk reaches (connect(2) and sendto(2) follow a final symlink), NoSocket says that is
		// no socket, and Walk what it met; a name the UnixLander could not walk is decided on its spelling alone.
		if p := strings.TrimPrefix(a.Path, "unix:"); land.Unix != nil && a.Host == "" && filepath.IsAbs(p) {
			if l, err := land.Unix(p); err == nil {
				a.Landed, a.Walk, a.NoSocket = l.At, l.Walk, l.NoSocket
				if l.At != "" && l.At != filepath.Clean(p) {
					rp.Path = l.At
				}
			}
		}
		return a, rp
	case ActionNetHTTP, ActionNetSocket, ActionExecAnon:
		return a, rp // no filesystem path: a net.http row's path is the request's
	case ActionNetBind:
		// Bind creates the final socket entry, so it does not follow it: a missing or dangling socket name lies in its
		// directory as the walk reaches it, and a walk that fails as the agent's lookup fails is refused
		// path-unreliable, as the run's bindUnix refuses it (UnixWalkUnreliable). Abstract names and literal IP binds
		// have no filesystem walk.
		if a.Proto == ProtoUnix {
			if p := strings.TrimPrefix(a.Path, "unix:"); filepath.IsAbs(p) {
				var err error
				a.Path, rp.Path, err = landed(p, pathHow, land.Path)
				if err != nil && !errors.Is(err, ErrUnwalked) {
					a.Walk = UnixWalkUnreliable
				}
			}
		}
		return a, rp
	case ActionExec:
		// The #! interpreter is opened as the exec's own image is (open_exec, LOOKUP_FOLLOW): the row's path's lookup.
		a.Script, rp.Script, _ = landed(a.Script, pathHow, land.Path)
	case ActionFSRename, ActionFSLink:
		a.DestPath, rp.Dest, _ = landed(a.DestPath, destHow, land.Path)
	}
	a.Path, rp.Path, _ = landed(a.Path, pathHow, land.Path)
	// An object that exists is a directory or not as the kernel finds it (ADR 0043: a name entry never decides a
	// directory, and a directory rename is asked D5); a row's `dir: true` speaks for one that does not exist yet.
	switch a.Kind {
	case ActionFSRead, ActionFSWrite, ActionFSDelete, ActionFSRename:
		var st unix.Stat_t
		if !a.Dir && filepath.IsAbs(a.Path) && unix.Lstat(a.Path, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR {
			a.Dir = true
		}
	}
	return a, rp
}

// ResolveAction lands an action's paths with land as RunResolved lands a compile --test row's, and reports each one that
// landed elsewhere: compile --exec evaluates its command line as such a row is evaluated. a's paths are spelled as
// written, uncleaned.
func ResolveAction(a Action, land Landers) (Action, ResolvedPaths) {
	return resolveAction(a, land)
}

// landed is where the walk of the spelled path p leads (Lander), and that answer again when it differs from p
// cleaned ("" otherwise), with the walk's error. A path that is not absolute (a bare command name, a row with no cwd),
// and one the walk cannot land, is p cleaned. Nothing is cleaned before the walk: the kernel resolves "lk/.."
// physically, so a row's out/lk/../x, cleaned first to out/x, was answered on a directory other than the kernel's.
func landed(p string, how Lookup, land Lander) (string, string, error) {
	if p == "" {
		return "", "", nil
	}
	clean := filepath.Clean(p)
	if land == nil || !filepath.IsAbs(p) {
		return clean, "", nil
	}
	at, err := land(p, how)
	if err != nil {
		return clean, "", err
	}
	if at == clean {
		return clean, "", nil
	}
	return at, at, nil
}
