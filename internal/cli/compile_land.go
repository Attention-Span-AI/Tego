// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// land and landUnix are the walks compile --test and compile --exec land a row's paths with: the run's own
// (supervisor.Land, the walk of every fs line, and supervisor.LandUnix, the walk of a connect's and a datagram's unix
// name), so a row and the run's line land a path with one resolver (ADR 0019's 2026-10-17 design note). Tests replace
// them.
var (
	land     = supervisor.Land
	landUnix = supervisor.LandUnix
)

// rowCwd is the directory a row's relative path is joined to: compile's working directory as getcwd(2) reports it,
// every symlink resolved, which is where the agent's own relative names start and what the run joins them to
// (readlink /proc/<pid>/cwd, supervisor.md R6). os.Getwd answers $PWD whenever $PWD names that directory, which may
// spell it through a symlink; the run matches a unix name's spelling against the unix: entries (R11), so a relative
// unix row joined to $PWD named an entry the run's join never names. "" when getcwd fails: the table then joins its
// own default.
func rowCwd() string {
	wd, err := unix.Getwd()
	if err != nil {
		return ""
	}
	return wd
}

// landers are compile's agent.Landers, each failure of compile's own said once on stderr under file.
func landers(stderr io.Writer, file string) agent.Landers {
	warned := false
	warn := func(err error) {
		if !warned {
			warned = true
			message(stderr, file, 0, 0, "tego compile: a row's path could not be walked as the kernel walks it ("+err.Error()+
				"); every such path is evaluated as written", agent.CodeUnenforced)
		}
	}
	return agent.Landers{Path: rowLander(warn), Unix: unixLander(warn)}
}

// rowLander is compile's agent.Lander. A walk that fails as the agent's own lookup would fail (ENOTDIR, ELOOP,
// ENAMETOOLONG, EACCES, EINVAL, an empty symlink's ENOENT) answers that errno: the run's syscall fails the same way, and
// its line keeps the spelling's verdict (supervisor.md R15b), or for a bind refuses it path-unreliable (bindUnix). A walk
// that fails for another reason (no /proc, this process's EMFILE, a place with no name in this view) is
// agent.ErrUnwalked, an answer that rests on the spelling alone, and is said (warn).
func rowLander(warn func(error)) agent.Lander {
	return func(p string, how agent.Lookup) (string, error) {
		at, err := land(p, how)
		if err == nil || lookupErrno(err) {
			return at, err
		}
		warn(err)
		return "", fmt.Errorf("%w: %w", agent.ErrUnwalked, err)
	}
}

// unixLander is compile's agent.UnixLander: supervisor.LandUnix, whose error is a walk compile could not make (no
// /proc, this process's EMFILE), said (warn), after which the name is answered on its spelling.
func unixLander(warn func(error)) agent.UnixLander {
	return func(p string) (agent.UnixLanding, error) {
		l, err := landUnix(p)
		if err != nil {
			warn(err)
			return agent.UnixLanding{}, fmt.Errorf("%w: %w", agent.ErrUnwalked, err)
		}
		return l, nil
	}
}

// lookupErrno reports whether err is an errno the agent's own lookup of a path fails with. ENOENT is one only while
// this process can walk at all: without /proc no walk opens the root it starts from.
func lookupErrno(err error) bool {
	for _, e := range []error{unix.ENOTDIR, unix.ELOOP, unix.ENAMETOOLONG, unix.EACCES, unix.EINVAL} {
		if errors.Is(err, e) {
			return true
		}
	}
	return errors.Is(err, unix.ENOENT) && unix.Access("/proc/self/root", unix.F_OK) == nil
}
