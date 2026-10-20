// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"os"
	"path"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// Land is where the kernel's walk of the absolute pathname p leads for a syscall end looked up as how says
// (agent.Lookup), in this process's own view: compile --test's question of a row's path (ADR 0019's 2026-10-17 design
// note), asked with the Lookup of the syscall the row stands for (agent.ActionKind.Lookups). It is FSTarget's walk, the
// one every run's fs line is decided on (R15b), of the query the run's own handler of that syscall builds (pathQuery.as),
// so compile --test and the run land a path with one resolver asked one question (the design note). p is walked as
// written: no lexical clean, each ".." physical against the directory reached so
// far, every symlink on the way followed with the kernel's limit of 40, the final one only where how follows it; a final
// "." or ".." is resolved physically unless how makes a name (agent.LookupParent), which refuses it (EINVAL) and lands a
// name ending in "/" in its directory, its final symlink not followed. Asked
// before the agent runs, a component that does not exist yet is taken as a directory the agent makes later
// (pathQuery.predict): the answer is where the run's walk lands once it exists, a dangling symlink followed to its target
// as the kernel follows it. A walk that fails as the task's own lookup would (ENOTDIR, ELOOP, EACCES, ENAMETOOLONG,
// EINVAL) answers its errno, and so does one this process cannot make (no /proc, EMFILE).
func Land(p string, how agent.Lookup) (string, error) {
	if !strings.HasPrefix(p, "/") {
		return "", unix.EINVAL
	}
	at, err := sysKernel{}.FSTarget(landQuery(p, how))
	return at.at, err
}

// landQuery is Land's question as a pathQuery: the one the run's handler of the syscall an end of this process with no
// dirfd stands for would walk (pathQuery.as), asked as compile --test's (predict).
func landQuery(p string, how agent.Lookup) pathQuery {
	q := pathQuery{tid: os.Getpid(), dirfd: atFDCWD, path: p, joined: cleanPath(p)}.as(how)
	q.predict = true
	return q
}

// LandUnix is where the run's walk of the absolute unix pathname p takes it, what that walk met, and whether what it
// reaches is a socket, in this process's own view: compile --test's question of a connect's or a datagram's name
// (agent.UnixLander). It is unixWalk, the one walk a relayed connect and a datagram's decision make (R11, R11a): one
// openat2(2) beneath the root with RESOLVE_NO_MAGICLINKS, then, where that lookup fails as the task's may, a walk a
// component at a time that refuses every magic link; a landing on procfs is refused. It is asked before the agent runs,
// of the tree the agent calls in (ADR 0019's design note): the tree as it is,
// with every directory the name's walk needs made and, at a final name that names nothing yet and that nothing needs
// as a directory, the socket the agent binds (predictUnix). What is already there is what it is: a socket is taken as
// the run's (R11a cannot be asked before the run), and a directory or a file that is not a socket is no socket
// (NoSocket), as is every directory the name makes. What the walk met is classed by the run's own answers to it
// (unixWalkOf). err is a walk this process could not make: no /proc, its own descriptors exhausted.
func LandUnix(p string) (agent.UnixLanding, error) {
	if !strings.HasPrefix(p, "/") {
		return agent.UnixLanding{}, unix.EINVAL
	}
	task, err := openTaskView(os.Getpid(), false)
	if err != nil {
		return agent.UnixLanding{}, err
	}
	defer sysKernel{}.CloseFD(task.root) //nolint:errcheck // an O_PATH descriptor openTaskView opened
	l, walked, err := landUnix(task, p)
	if err != nil {
		walk, ok := unixWalkOf(err)
		if !ok {
			return agent.UnixLanding{}, err
		}
		return agent.UnixLanding{Walk: walk}, nil
	}
	if walked {
		l.Walk = agent.UnixWalkStepwise
	}
	return l, nil
}

// landUnix is LandUnix's walk: unixWalk and unixPlaceOf, as UnixTarget walks a datagram's name and connectUnixAs a
// connect's, with what the walk reached told a socket or not (isSocketFD), and predictUnix for a name that names
// nothing yet.
func landUnix(task taskView, p string) (l agent.UnixLanding, walked bool, err error) {
	fd, walked, err := unixWalk(task, unixQuery{tid: task.tid, path: p})
	if errors.Is(err, unix.ENOENT) {
		return predictUnix(task, p)
	}
	if err != nil {
		return agent.UnixLanding{}, false, err
	}
	defer sysKernel{}.CloseFD(fd) //nolint:errcheck // an O_PATH descriptor unixWalk opened
	place, err := unixPlaceOf(fd)
	if err != nil {
		return agent.UnixLanding{}, false, err
	}
	return agent.UnixLanding{At: place.at, NoSocket: !isSocketFD(fd)}, walked, nil
}

// predictUnix is unixWalk's answer once every directory p's walk needs, and the socket p names, exist
// (pathQuery.predict, which fs rows are asked by too): the walk a component at a time, a dangling symlink followed to
// its target as the kernel follows it, every magic link refused as RESOLVE_NO_MAGICLINKS refuses it, and a landing on
// procfs refused. The part that does not exist yet is made as the name needs it: a directory where the walk goes
// beneath it or the name ends in "/", "/." or "/.." (in its spelling or its final link's body), and otherwise, at the
// name's final part, the socket the agent binds there. A landing on a directory, made or already there, or on a file
// that is not a socket is NoSocket: the run's write entry admits only a socket a process of the run bound (R11a), and
// what the name reaches there is none (design, which replaces round 3's answer, naming nothing, for a missing name
// ending in "/" or "/.", and its landing on the directory as a socket for every other one). A name whose missing
// part lies on procfs is refused as a landing there
// (errUnixProcfs): what appears on procfs while the agent runs (/proc/<pid>/fd/N as it opens N, /proc/<pid> and
// task/<tid> as it starts processes and threads) is a magic link or a procfs directory, which the run's walk refuses
// either way, and this process's own entries there are not the agent's. Each link it follows is held to what the
// kernel's lookup holds it to (followFacts:
// fs.protected_symlinks, a nosymfollow mount), since unixWalk's first lookup is the kernel's; a landing that only a
// walk reading each link rather than following it makes is walked, as unixWalk reports one only its own fallback walk
// made.
func predictUnix(task taskView, p string) (l agent.UnixLanding, walked bool, err error) {
	q := pathQuery{tid: task.tid, dirfd: atFDCWD, path: p, joined: cleanPath(p), predict: true}
	w := &execWalk{q: q, root: task.root, noMagic: true, follow: landFollowFacts()}
	fd, err := w.walk(task.root)
	if errors.Is(err, unix.EACCES) {
		w = &execWalk{q: q, root: task.root, noMagic: true}
		fd, err = w.walk(task.root)
		walked = true
	}
	if err != nil {
		return agent.UnixLanding{}, false, err
	}
	defer sysKernel{}.CloseFD(fd) //nolint:errcheck // an O_PATH descriptor the walk opened
	if w.madeOnProcfs || onProcfs(fd) {
		return agent.UnixLanding{}, false, errUnixProcfs
	}
	place, err := unixPlaceOf(fd)
	if err != nil {
		return agent.UnixLanding{}, false, err
	}
	if w.missing == "" {
		// The walk climbed back out of what it made, to a place that exists: that place is what the name reaches.
		return agent.UnixLanding{At: place.at, NoSocket: !isSocketFD(fd)}, walked, nil
	}
	return agent.UnixLanding{At: path.Join(place.at, w.missing), NoSocket: w.madeDir}, walked, nil
}

// isSocketFD reports whether the O_PATH descriptor fd is a socket file; one that cannot be told is taken as none, which
// only refuses (the run's R11a finds no socket of the run's there).
func isSocketFD(fd int) bool {
	var st unix.Stat_t
	return unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFSOCK
}

// landFollowFacts are the facts predictUnix holds each link it follows to: this process's (currentFollowFacts). A test
// sets another follower's, as fs.protected_symlinks refuses a link to a follower that owns neither it nor its sticky
// directory, which an unprivileged test cannot make the kernel do.
var landFollowFacts = currentFollowFacts

// unixWalkOf classes a failed unix walk by the run's own two answers to it: a datagram's refusal (unixLandedRefusal:
// unix-absent for a name that names nothing, path-unreliable for every other failure) and a relayed connect's outcome
// (unixWalkOutcome: unresolved, the name's verdict with the lookup's errno, or unreliable). An errno no lookup of the
// task's fails with (EMFILE, ENOMEM, EIO) is this process's own: ok is false.
func unixWalkOf(err error) (walk agent.UnixWalk, ok bool) {
	var errno unix.Errno
	if errors.As(err, &errno) && errno != unix.ENOENT && errno != unix.ENOTDIR && errno != unix.ELOOP &&
		errno != unix.EACCES && errno != unix.ENAMETOOLONG {
		return agent.UnixWalkLookup, false
	}
	switch {
	case unixLandedRefusal(err).rule == ruleUnixAbsent:
		return agent.UnixWalkAbsent, true
	case unixWalkOutcome(err) == unixUnresolved:
		return agent.UnixWalkFailed, true
	}
	return agent.UnixWalkUnreliable, true
}
