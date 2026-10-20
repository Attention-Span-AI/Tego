// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// as is q looked up as how says (agent.Lookup, R15b): the one place a query's lookup is set. Every fs handler builds
// the walk of each end it decides through it, and so does compile --test's Land, from the row's agent.ActionKind.Lookups,
// so the run and compile ask one walk of one end, and a lookup the kernel makes cannot be stated twice and drift apart
// (ADR 0019's design note: round 3 taught the run's handlers that a link's old
// name is looked up whole, unfollowed, not as a name-making end, while compile kept asking it as one).
func (q pathQuery) as(how agent.Lookup) pathQuery {
	q.nofollow = how == agent.LookupNoFollow || how == agent.LookupParent
	q.create = how == agent.LookupCreate
	q.parent = how == agent.LookupParent
	return q
}

// openLookup is how an open of flags looks its pathname up, or a mknod (mknod) its new name: a mknod makes its name in
// its directory (filename_create); an O_NOFOLLOW open, and an O_CREAT|O_EXCL one, whose final symlink is EEXIST, look the
// whole path up with the final symlink not followed; an O_CREAT open follows a dangling final symlink to the name it
// creates; any other open follows the whole path (open(2)).
func openLookup(flags int, mknod bool) agent.Lookup {
	switch {
	case mknod:
		return agent.LookupParent
	case flags&unix.O_NOFOLLOW != 0 || flags&(unix.O_CREAT|unix.O_EXCL) == unix.O_CREAT|unix.O_EXCL:
		return agent.LookupNoFollow
	case flags&unix.O_CREAT != 0:
		return agent.LookupCreate
	}
	return agent.LookupFollow
}

// followLookup is how a syscall that follows a final symlink unless told not to looks its pathname up: the whole path,
// followed, or with nofollow (AT_SYMLINK_NOFOLLOW for an attribute change or an execveat; linkat's old name without
// AT_SYMLINK_FOLLOW, and link(2)'s) not followed. Neither refuses a final "." or "..": path_lookupat resolves it.
func followLookup(nofollow bool) agent.Lookup {
	if nofollow {
		return agent.LookupNoFollow
	}
	return agent.LookupFollow
}
