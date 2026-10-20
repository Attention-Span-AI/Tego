// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestEveryRowEndIsWalkedAsItsSyscall holds compile --test's one table of how a row's ends are looked up
// (agent.ActionKind.Lookups, which RunResolved lands each end with through Land) to the run's own handler of the
// syscall each kind of row stands for, with the flags a row means: the walk the handler asks of each end is that
// lookup's (pathQuery.lookup). Compile and the run then land one end with one walk asked one question, so they agree on
// where it lands by construction, and a handler or a row kind that changes its lookup alone fails here. The two were
// written apart: a fix taught the run that a link's old name is looked up whole and
// unfollowed (filename_lookup, which walks a final "." or ".."), while compile kept asking it as an end the syscall
// makes in its directory, which refuses one before a lookup; compile then evaluated out/lk/. at the symlink out/lk and
// answered allow for a link the run records refused and the kernel refuses EXDEV (-3c4-2). An exec.map row has no
// pathname walk in the run (mmap(2) of a descriptor).
//
// Spec: docs/p0/supervisor.md R15b; docs/p0/limits-check-doctor-cli.md R28.
func TestEveryRowEndIsWalkedAsItsSyscall(t *testing.T) {
	const pathAddr, destAddr, sockAddr = 0x10000, 0x20000, 0x30000
	type rowCase = struct {
		kind    agent.ActionKind
		syscall string
		args    []uint64 // after the syscall's number and the task
	}
	rows := []rowCase{
		{agent.ActionFSRead, "openat", []uint64{argCWD, pathAddr, unix.O_RDONLY}},
		{agent.ActionFSWrite, "openat", []uint64{argCWD, pathAddr, unix.O_WRONLY | unix.O_CREAT, 0o644}},
		{agent.ActionFSAttr, "fchmodat", []uint64{argCWD, pathAddr, 0o644}},
		{agent.ActionFSDelete, "unlinkat", []uint64{argCWD, pathAddr, 0}},
		{agent.ActionFSMkdir, "mkdirat", []uint64{argCWD, pathAddr, 0o755}},
		{agent.ActionFSRename, "renameat", []uint64{argCWD, pathAddr, argCWD, destAddr}},
		{agent.ActionFSLink, "linkat", []uint64{argCWD, pathAddr, argCWD, destAddr, 0}},
		{agent.ActionNetBind, "bind", []uint64{5, sockAddr, uint64(len(sockaddrUn("/w/out/lk/f")))}},
		{agent.ActionExec, "execve", []uint64{pathAddr, 0, 0}},
	}
	// Each end is also spelled with a trailing slash, which has no handler ask another lookup: a name-making end is still
	// the name in its directory. A bind's name ending in "/" has
	// no final component a socket file can take, and the run refuses it before any walk (errNoFinal).
	for _, slash := range []string{"", "/"} {
		path, dest := "/w/out/lk/f"+slash, "/w/out/lk/g"+slash
		for _, tc := range rows {
			if slash != "" && tc.kind == agent.ActionNetBind {
				continue
			}
			t.Run(string(tc.kind)+slash, func(t *testing.T) {
				f := newFake()
				f.put(pathAddr, cstr(path))
				f.put(destAddr, cstr(dest))
				f.put(sockAddr, sockaddrUn(path))
				pol := testPolicy(nil, []agent.FSRule{{Path: "/w", Resolved: "/w", Kind: agent.FSWrite, Raw: "./w", Access: agent.AccessWriteSet}}, nil)
				pol.Rules.Listen = []agent.ListenRule{{Raw: "unix:/w/s.sock", Proto: agent.ProtoUnix, UnixPath: "/w/s.sock"}}
				l, _ := newTestLoop(t, f, pol)
				l.handle(notifFor(nrFor(t, tc.syscall), 42, tc.args...))
				wantPath, wantDest := tc.kind.Lookups()
				asked := map[string][]agent.Lookup{}
				for _, q := range append(append([]pathQuery(nil), f.fsQueries...), f.execQueries...) {
					asked[q.path] = append(asked[q.path], q.lookup())
				}
				want := map[string]agent.Lookup{path: wantPath}
				if tc.kind == agent.ActionFSRename || tc.kind == agent.ActionFSLink {
					want[dest] = wantDest
				}
				for p, how := range want {
					if len(asked[p]) == 0 {
						t.Errorf("%s: the run never walked %s; walks %v", tc.syscall, p, asked)
					}
					for _, got := range asked[p] {
						if got != how {
							t.Errorf("%s walked %s as lookup %d; the row's table says %d", tc.syscall, p, got, how)
						}
					}
				}
				// Land asks the same query, save that compile's question is asked of the tree before the agent runs.
				for p, how := range want {
					lq := landQuery(p, how)
					if lq.lookup() != how || !lq.predict {
						t.Errorf("Land's query of %s is lookup %d (predict %v), want %d", p, lq.lookup(), lq.predict, how)
					}
				}
			})
		}
	}
}

// lookup is the agent.Lookup q is walked as (pathQuery.as's inverse), read back from the bits a handler's query holds.
func (q pathQuery) lookup() agent.Lookup {
	switch {
	case q.parent:
		return agent.LookupParent
	case q.nofollow:
		return agent.LookupNoFollow
	case q.create:
		return agent.LookupCreate
	}
	return agent.LookupFollow
}

// TestLookupBitsRoundTrip: pathQuery.as sets every lookup bit from one agent.Lookup and lookup reads it back, so a
// query's lookup is the one it was built with whatever it held before.
//
// Spec: docs/p0/supervisor.md R15b.
func TestLookupBitsRoundTrip(t *testing.T) {
	for _, how := range []agent.Lookup{agent.LookupFollow, agent.LookupCreate, agent.LookupNoFollow, agent.LookupParent} {
		for _, start := range []pathQuery{{}, {nofollow: true, create: true, parent: true}} {
			if got := start.as(how).lookup(); got != how {
				t.Errorf("as(%d) from %+v reads back %d", how, start, got)
			}
		}
	}
	for _, tc := range []struct {
		flags int
		mknod bool
		want  agent.Lookup
	}{
		{unix.O_RDONLY, false, agent.LookupFollow},
		{unix.O_WRONLY | unix.O_TRUNC, false, agent.LookupFollow},
		{unix.O_WRONLY | unix.O_CREAT, false, agent.LookupCreate},
		{unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL, false, agent.LookupNoFollow},
		{unix.O_RDONLY | unix.O_NOFOLLOW, false, agent.LookupNoFollow},
		{unix.O_WRONLY | unix.O_CREAT | unix.O_NOFOLLOW, false, agent.LookupNoFollow},
		{unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL, true, agent.LookupParent},
	} {
		if got := openLookup(tc.flags, tc.mknod); got != tc.want {
			t.Errorf("openLookup(%#x, %v) = %d, want %d", tc.flags, tc.mknod, got, tc.want)
		}
	}
}
