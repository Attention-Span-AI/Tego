// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// fsEntries holds one fd per fs rule that is not a deny_read (those are enumerated by denyRead):
// write entries with their masked rights, ask/watch entries for identity, implicit entries for
// identity with no rights (R8). The FSKind switch refuses unknown kinds explicitly.
func (bd *builder) fsEntries() error {
	for _, r := range bd.rt.FS {
		var err error
		switch r.Kind {
		case agent.FSWrite:
			err = bd.writeEntry(r)
		case agent.FSAsk:
			_, err = bd.hold(r.Path, kindAsk, 0) // SEMANTICS §3.1: an ask entry carries no rights
		case agent.FSWatch:
			_, err = bd.hold(r.Path, kindWatch, 0) // SEMANTICS §7: recording only
		case agent.FSImplicit:
			err = bd.implicit(r.Path)
		case agent.FSDenyRead:
			continue
		default:
			return fmt.Errorf("%w: unknown fs rule kind %q for %q", ErrRulesetBuild, r.Kind, r.Path)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// writeEntry holds a write entry with the full read+write+create+remove set masked by the ABI. A
// declared directory that does not exist yet is created here (§7: "write: created by run"); any
// other vanished entry fails closed. At a root launch the directory is made with the credentials the
// child drops to (Run.Drop), so the agent owns it and DAC lets it create inside; the mkdir is then also
// judged as that user's, so a parent the user may not write into refuses it.
func (bd *builder) writeEntry(r agent.FSRule) error {
	idx, err := bd.hold(r.Path, kindWrite, bd.writeMask(r))
	if err == nil && r.RuntimeIno != 0 {
		return bd.sameRuntimeDir(idx, r)
	}
	if err == nil || !r.Missing || !errors.Is(err, ErrPathVanished) {
		return err
	}
	if merr := bd.mkdirWrite(r.Path); merr != nil && !errors.Is(merr, os.ErrExist) {
		return fmt.Errorf("%w: creating write entry %q: %w", ErrPathVanished, r.Path, merr)
	}
	_, err = bd.hold(r.Path, kindWrite, bd.writeMask(r))
	return err
}

// sameRuntimeDir refuses a runtime grant (the run's own CODEX_HOME, agent-contract.md R10a) whose held descriptor is
// not the directory the runtime made: hold opens the path following links, so a link swapped in for it, or for a
// directory above it, after the runtime checked it would otherwise move the grant where it pointed.
// The comparison reads the descriptor that is granted, so nothing can be swapped in after it.
func (bd *builder) sameRuntimeDir(idx int, r agent.FSRule) error {
	var st unix.Stat_t
	if err := unix.Fstat(bd.fds.open[idx].FD, &st); err != nil {
		return fmt.Errorf("%w: runtime grant %q: %w", ErrRulesetBuild, r.Path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(st.Dev) != r.RuntimeDev || st.Ino != r.RuntimeIno {
		return fmt.Errorf("%w: runtime grant %q is no longer the directory the run made", ErrRulesetBuild, r.Path)
	}
	return nil
}

// mkdirWrite creates a missing write directory: as this process when there is nothing to drop to, and
// otherwise on a thread holding the dropped uid and gid and no capabilities (mkdirAs). Creating it as the
// agent rather than chowning it afterwards leaves no window in which a path the user controls could be
// swapped for a link, and a chown through it hand root's file to the user.
func (bd *builder) mkdirWrite(path string) error {
	if !bd.run.Drop {
		return os.Mkdir(path, 0o755)
	}
	return mkdirAs(path, bd.run.DropUID, bd.run.DropGID)
}

// mkdirAs is sys.RunAs around os.Mkdir; a test replaces it to see which credentials were asked for.
var mkdirAs = func(path string, uid, gid int) error {
	var merr error
	want := sys.TaskCreds{EUID: uint32(uid), EGID: uint32(gid), FSUID: uint32(uid), FSGID: uint32(gid), Groups: []uint32{uint32(gid)}}
	if err := sys.RunAs(want, func() { merr = os.Mkdir(path, 0o755) }); err != nil {
		return err
	}
	return merr
}

// writeMask is the rights a write entry grants: the compiler's write set plus the read set (a write
// directory is fully usable), EXECUTE only while exec is unrestricted, IOCTL_DEV only under /dev
// (R2, ABI-5 row), and RESOLVE_UNIX whenever the ruleset handles it — ABI ≥ 9 under a net: section
// (newBuilder) — because a socket the run binds under a write path is allowed implicitly (SEMANTICS §5). Landlock
// cannot tell who bound a socket, so this grant is a name-level backstop: the supervisor, deciding first, refuses a
// socket there the run did not bind (supervisor R11a, R21). fitAccess then masks by ABI and by file-ness.
func (bd *builder) writeMask(r agent.FSRule) accessFS {
	a := accessFS(r.Access) | readSet
	if bd.execUnrestricted {
		a |= accessExecute
	}
	if !underDev(r.Path) {
		a &^= accessIoctlDev
	}
	if bd.profile.FS&accessResolveUnix != 0 {
		a |= accessResolveUnix
	}
	return a
}

func underDev(p string) bool { return p == "/dev" || strings.HasPrefix(p, "/dev/") }

// implicit holds an identity-only fd (R8); a missing node (the ledger root before the first run,
// /sys/fs/bpf on a kernel without bpffs) is fine because omission already denies it.
func (bd *builder) implicit(path string) error {
	_, err := bd.hold(path, kindImplicitDeny, 0)
	if errors.Is(err, ErrPathVanished) {
		return nil
	}
	return err
}

// implicitRun holds the run directory itself (R8): the table's implicit entry is the ledger root,
// because the run id does not exist at compile time.
func (bd *builder) implicitRun() error {
	if bd.run.Dir == "" {
		return nil
	}
	return bd.implicit(bd.run.Dir)
}

// resolvedOr is a rule's symlink-resolved path, falling back to the declared one.
//
// Containment has to be asked of the resolved subtree, because the run opens each entry O_PATH without
// O_NOFOLLOW and so pins the link's target rather than the link (agent.FSRule.Resolved, E8). Comparing
// the names the author typed would let a write entry that is a symlink into a vault look disjoint from a
// deny_read target it actually encloses, which is the shape compile now rejects: this side has to ask
// the same question the same way or I5's cross-check fires on a contract that is merely unusual.
//
// The fallback covers a table built by hand in a test, where Resolved was never filled.
func resolvedOr(resolved, declared string) string {
	if resolved != "" {
		return resolved
	}
	return declared
}
