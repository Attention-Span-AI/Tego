// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// isWriteOpen reports whether open flags make an open a write (decide.IsWriteOpen): what the filter notifies
// on (R15, and enforce-landlock R12).
func isWriteOpen(flags int) bool { return decide.IsWriteOpen(flags) }

// creatFlags are the flags creat(2) implies; the syscall carries a mode, not a flags argument.
const creatFlags = unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC

// handleOpenAt records a write-open reached through a dirfd and continues it (R15). Landlock decides the
// continued syscall; the verdict here is advisory, which is exactly what source: seccomp says
// (P0-DESIGN §4.3), save a write that reaches a built-in deny_write target, which this loop refuses itself
// (R15c). Under record: full the filter also notifies read-opens, and those are recorded the same way with
// their own flags.
func handleOpenAt(l *Loop, n *notif) {
	l.recordOpen(n, int32(n.args[0]), n.args[1], int(int32(n.args[2])), record.FSOpen)
}

// handleOpen records a write-open of an absolute or cwd-relative path (x86-64's legacy form).
func handleOpen(l *Loop, n *notif) {
	l.recordOpen(n, atFDCWD, n.args[0], int(int32(n.args[1])), record.FSOpen)
}

// handleCreat records a creat, which implies O_WRONLY|O_CREAT|O_TRUNC (x86-64 only).
func handleCreat(l *Loop, n *notif) {
	l.recordOpen(n, atFDCWD, n.args[0], creatFlags, record.FSOpen)
}

// mknodFlags are the flags a mknod(2) is recorded with. record v1 has no mknod op, so a mknod — a regular
// file, a FIFO, a unix socket's inode or a device node — is recorded as the open that creates the same name:
// op open, O_CREAT|O_EXCL, which is how tier 2's kernel record writes one (observe handleFSOp) and so how its
// line is handed over (R7a). O_EXCL is mknod's own semantics: an existing name is EEXIST, and a final symlink
// is not followed. It is a modification, so R15c refuses one that reaches a deny_write target. It is decided
// as the create it is, not as an open (decide.OpMknod): tier 2's fanotify listener never sees a mknod, so the
// listener's write-open rule neither refuses it nor takes its line (R7a, R15).
const mknodFlags = unix.O_CREAT | unix.O_EXCL

// handleMknodAt records a mknodat(dirfd, path, mode, dev) and continues it, or refuses it under R15c.
func handleMknodAt(l *Loop, n *notif) {
	l.recordOpen(n, int32(n.args[0]), n.args[1], mknodFlags, decide.OpMknod)
}

// handleMknod records a legacy mknod(path, mode, dev) (x86-64 only).
func handleMknod(l *Loop, n *notif) {
	l.recordOpen(n, atFDCWD, n.args[0], mknodFlags, decide.OpMknod)
}

// handleUnlinkAt records an unlink or rmdir reached through a dirfd and continues it (R17).
func handleUnlinkAt(l *Loop, n *notif) {
	l.recordPath(n, record.FSUnlink, int32(n.args[0]), n.args[1], 0, n.args[2]&unix.AT_REMOVEDIR != 0, mutationArgs{flags: int(int32(n.args[2]))})
}

// handleUnlink records a legacy unlink (x86-64 only).
func handleUnlink(l *Loop, n *notif) {
	l.recordPath(n, record.FSUnlink, atFDCWD, n.args[0], 0, false, mutationArgs{})
}

// handleRmdir records a legacy rmdir (x86-64 only), which glibc's rmdir(3), Python's os.rmdir and
// coreutils' rmdir all reach on x86-64 instead of unlinkat(AT_REMOVEDIR). record v1 has no rmdir op
// (record-ledger.md: open|unlink|rename|mkdir|symlink|truncate), so it is recorded exactly as that
// unlinkat is: op unlink, the directory's path, no flags.
func handleRmdir(l *Loop, n *notif) {
	l.recordPath(n, record.FSUnlink, atFDCWD, n.args[0], 0, true, mutationArgs{flags: unix.AT_REMOVEDIR})
}

// handleMkdirAt records a mkdir reached through a dirfd.
func handleMkdirAt(l *Loop, n *notif) {
	l.recordPath(n, record.FSMkdir, int32(n.args[0]), n.args[1], 0, true, mutationArgs{mode: uint32(n.args[2])})
}

// handleMkdir records a legacy mkdir (x86-64 only).
func handleMkdir(l *Loop, n *notif) {
	l.recordPath(n, record.FSMkdir, atFDCWD, n.args[0], 0, true, mutationArgs{mode: uint32(n.args[1])})
}

// handleRenameAt records a rename or renameat2 with both of its paths, each resolved through its own
// dirfd (R17). The advisory verdict is Landlock's at both ends: the source's parent, the destination's, and
// REFER's no-gain rule between them (decideMoveDest).
func handleRenameAt(l *Loop, n *notif) {
	// renameat2's flags are args[4]; renameat has none, and its args[4] is whatever the register held.
	var flags uint32
	if n.nr == nrX86RenameAt2 || n.nr == nrARMRenameAt2 {
		flags = uint32(n.args[4])
	}
	l.recordRename(n, int32(n.args[0]), n.args[1], int32(n.args[2]), n.args[3], flags)
}

// handleRename records a legacy rename (x86-64 only).
func handleRename(l *Loop, n *notif) {
	l.recordRename(n, atFDCWD, n.args[0], atFDCWD, n.args[1], 0)
}

// handleSymlinkAt records a symlink creation reached through a dirfd. The created link is the path the
// verdict is taken on; the link's target is a string the kernel stores verbatim and never resolves here.
func handleSymlinkAt(l *Loop, n *notif) {
	l.recordSymlink(n, n.args[0], int32(n.args[1]), n.args[2])
}

// handleSymlink records a legacy symlink creation (x86-64 only).
func handleSymlink(l *Loop, n *notif) {
	l.recordSymlink(n, n.args[0], atFDCWD, n.args[1])
}

// handleLinkAt records a hard link reached through dirfds: linkat(olddirfd, oldpath, newdirfd, newpath,
// flags). A hard link is a path mutation like the rest of the notify set (R11 "inherently mutating"): it
// gives existing content a second name, and without this the record would show a symlink to a file but not
// a hard link to the same one.
func handleLinkAt(l *Loop, n *notif) {
	l.recordLink(n, int32(n.args[0]), n.args[1], int32(n.args[2]), n.args[3], int(int32(n.args[4])))
}

// handleLink records a legacy hard link, link(oldpath, newpath) (x86-64 only), which does not follow a
// final symlink in oldpath (link(2)) and has no AT_EMPTY_PATH form.
func handleLink(l *Loop, n *notif) {
	l.recordLink(n, atFDCWD, n.args[0], atFDCWD, n.args[1], 0)
}

// handleTruncate records a truncate(2), which follows a final symlink, and continues it: Landlock's TRUNCATE
// right decides it from ABI 3, below which the filter refuses it and nothing is notified (enforce-landlock R2).
// A truncate that reaches a deny_write target is refused here (R15c), as a write-open with O_TRUNC is.
func handleTruncate(l *Loop, n *notif) {
	r := l.newReader(n)
	p, raw := r.pathRaw(atFDCWD, n.args[0])
	if n.gone {
		return
	}
	q := pathQuery{tid: n.pid, dirfd: atFDCWD, path: raw, joined: p}.as(agent.LookupFollow)
	d := l.decideFS(n, record.FSTruncate, p, q, 0, false)
	if n.gone {
		return
	}
	d = l.denyWrite(n, r, d, record.FSTruncate, 0, fsEnd{p: p, q: q})
	if n.gone {
		return
	}
	l.settleFS(n, r, record.FSTruncate, fsEnd{p: p, q: q}, fsEnd{}, 0, d)
}

// handleChmod records a legacy chmod(2) (x86-64 only), which follows a final symlink.
func handleChmod(l *Loop, n *notif) { l.recordChmod(n, atFDCWD, n.args[0], 0, false) }

// handleFchmod records an fchmod(2): the file its descriptor holds.
func handleFchmod(l *Loop, n *notif) { l.recordChmod(n, int32(n.args[0]), 0, 0, true) }

// handleFchmodAt records an fchmodat(2), which has no flags argument and follows a final symlink.
func handleFchmodAt(l *Loop, n *notif) { l.recordChmod(n, int32(n.args[0]), n.args[1], 0, false) }

// handleFchmodAt2 records an fchmodat2(2) (6.6+), whose flags carry AT_SYMLINK_NOFOLLOW and AT_EMPTY_PATH.
func handleFchmodAt2(l *Loop, n *notif) {
	l.recordChmod(n, int32(n.args[0]), n.args[1], int(int32(n.args[3])), false)
}

// handleSetxattr records a setxattr(2) or removexattr(2), which follow a final symlink: an attribute change, which
// reaches this loop under an fs.write gate only (enforce-landlock R11).
func handleSetxattr(l *Loop, n *notif) {
	l.recordAttr(n, record.FSXattr, atFDCWD, n.args[0], 0, false, false)
}

// handleLsetxattr records an lsetxattr(2) or lremovexattr(2), which act on a final symlink itself.
func handleLsetxattr(l *Loop, n *notif) {
	l.recordAttr(n, record.FSXattr, atFDCWD, n.args[0], unix.AT_SYMLINK_NOFOLLOW, false, false)
}

// handleFsetxattr records an fsetxattr(2) or fremovexattr(2): the file its descriptor holds.
func handleFsetxattr(l *Loop, n *notif) {
	l.recordAttr(n, record.FSXattr, int32(n.args[0]), 0, 0, true, false)
}

// handleXattrAt records a setxattrat(2) or removexattrat(2) (6.13+): (dirfd, pathname, at_flags, name, ...), whose
// at_flags carry AT_SYMLINK_NOFOLLOW and AT_EMPTY_PATH. With AT_EMPTY_PATH a NULL pathname, as an empty one, names
// the descriptor's own file (the kernel's getname_maybe_null).
func handleXattrAt(l *Loop, n *notif) {
	l.recordAttr(n, record.FSXattr, int32(n.args[0]), n.args[1], int(int32(n.args[2])), false, true)
}

// handleChown records a legacy chown(2) (x86-64 only), which follows a final symlink.
func handleChown(l *Loop, n *notif) {
	l.recordAttr(n, record.FSChown, atFDCWD, n.args[0], 0, false, false)
}

// handleLchown records a legacy lchown(2) (x86-64 only), which changes a final symlink itself.
func handleLchown(l *Loop, n *notif) {
	l.recordAttr(n, record.FSChown, atFDCWD, n.args[0], unix.AT_SYMLINK_NOFOLLOW, false, false)
}

// handleFchown records an fchown(2): the file its descriptor holds.
func handleFchown(l *Loop, n *notif) {
	l.recordAttr(n, record.FSChown, int32(n.args[0]), 0, 0, true, false)
}

// handleFchownAt records an fchownat(2): (dirfd, pathname, owner, group, flags), the flags carrying
// AT_SYMLINK_NOFOLLOW and AT_EMPTY_PATH.
func handleFchownAt(l *Loop, n *notif) {
	l.recordAttr(n, record.FSChown, int32(n.args[0]), n.args[1], int(int32(n.args[4])), false, false)
}

// recordChmod records one mode change, notified under record: full or an fs.write gate (R17), and continues it unless
// that gate refuses it (settleFS's gateFS scores it as a write).
func (l *Loop) recordChmod(n *notif, dirfd int32, addr uint64, flags int, byFD bool) {
	l.recordAttr(n, record.FSChmod, dirfd, addr, flags, byFD, false)
}

// recordAttr records one attribute change: a mode change (op chmod), an extended attribute set or removed (op xattr;
// a POSIX ACL is one, system.posix_acl_access, and rewrites the mode bits as a chmod does) or an owner change (op
// chown). A chmod is notified under record: full or an fs.write gate, the xattr and chown families under an fs.write
// gate only (R17, enforce-landlock R11). Each is continued unless that gate refuses it (settleFS's gateFS scores it as
// a write on the file it lands on). The attribute's name is never read: a sibling thread could rewrite it between this
// loop's read and the kernel's, so every name is scored as the write it may be. No Landlock ABI has a chmod, chown or
// xattr right and no tier-1 or tier-2 mechanism refuses one (CAPABILITIES fs.deny_chmod), so the model's line reads
// allow, named as a modification of the path where it lands is (the write entry that covers it, else the nearest
// entry, else unmatched): what the kernel did, under the entry the contract would have had decide it.
// byFD is the f- forms' descriptor, and AT_EMPTY_PATH's with an empty pathname: the file it holds, never walked.
// nullEmpty says AT_EMPTY_PATH also takes a NULL pathname as the descriptor (the *xattrat forms).
func (l *Loop) recordAttr(n *notif, op string, dirfd int32, addr uint64, flags int, byFD, nullEmpty bool) {
	r := l.newReader(n)
	var p, raw string
	if !byFD && nullEmpty && addr == 0 && flags&unix.AT_EMPTY_PATH != 0 {
		byFD = true
	}
	if !byFD {
		p, raw = r.pathRaw(dirfd, addr)
		byFD = flags&unix.AT_EMPTY_PATH != 0 && raw == "" && !r.failed
	}
	if byFD && !n.gone {
		p, raw = r.heldFile(dirfd), ""
	}
	if n.gone {
		return
	}
	q := pathQuery{tid: n.pid, dirfd: dirfd, path: raw, empty: byFD, joined: p}.as(followLookup(flags&unix.AT_SYMLINK_NOFOLLOW != 0))
	d := l.decideFS(n, op, p, q, 0, false)
	if n.gone {
		return
	}
	// With a plane deciding the run (tier bpflsm, and tier cgroup in a plane mode), its path_chmod, path_chown and
	// xattr and ACL hooks refuse an attribute change beneath a deny_write target in the kernel (enforce-plane R12,
	// TIER3-PLAN T13): refused here first by the same predicate (R15c's), the kernel never sees it, and the action's
	// one line is this refusal rather than an allow the kernel then overturns. Nothing refuses any other attribute
	// change at any tier (no Landlock ABI governs one, and the plane protects deny_write targets only), so the model's
	// other refusals read allow.
	if l.planeAttrs {
		d = l.denyWrite(n, r, d, op, 0, fsEnd{p: p, q: q})
	}
	if d.verdict == record.VerdictRefused && !d.enforce {
		d.verdict, d.reason = record.VerdictAllow, ""
	}
	l.settleFS(n, r, op, fsEnd{p: p, q: q}, fsEnd{}, 0, d)
}

// recordLink reads both paths of a hard link, answers it (CONTINUE, or R15c's refusal) and records one fs
// event. The created name is
// recorded second, matching rename's from/to order: Landlock decides a link on both ends, needing MAKE_REG
// on the destination directory and REFER on both when they differ (ABI 2). flags is linkat's own.
func (l *Loop) recordLink(n *notif, olddirfd int32, oldAddr uint64, newdirfd int32, newAddr uint64, flags int) {
	r := l.newReader(n)
	var from, raw string
	byFD := flags&unix.AT_EMPTY_PATH != 0 && oldAddr == 0
	if !byFD {
		from, raw = r.pathRaw(olddirfd, oldAddr)
		// AT_EMPTY_PATH names the old end by descriptor only when its pathname is empty, as it does for
		// execveat (recordExec): a non-empty one is resolved as usual.
		byFD = flags&unix.AT_EMPTY_PATH != 0 && raw == "" && !r.failed
	}
	if byFD && !n.gone {
		// linkat(fd, "", ..., AT_EMPTY_PATH) is how an O_TMPFILE written anywhere in the worktree becomes a
		// named hook, and how a descriptor opened on a target gets a second name: with no pathname to
		// match, the old end is the file the descriptor holds (R15c).
		from = r.heldFile(olddirfd)
	}
	to, rawTo := r.pathRaw(newdirfd, newAddr)
	if n.gone {
		return
	}
	// A descriptor's end has no pathname for a walk to follow: its /proc link already names where the file
	// is, so the query carries no path and neither decideFS nor denyWrite walks it again.
	// The old name is looked up whole (filename_lookup), its final symlink followed only with AT_SYMLINK_FOLLOW; the new
	// name is made in its directory (filename_create).
	old := pathQuery{tid: n.pid, dirfd: olddirfd, path: raw, empty: byFD, joined: from}.as(followLookup(flags&unix.AT_SYMLINK_FOLLOW == 0))
	newQ := pathQuery{tid: n.pid, dirfd: newdirfd, path: rawTo, joined: to}.as(agent.LookupParent)
	d := l.decideFS(n, record.FSLink, from, old, 0, false)
	if n.gone {
		return
	}
	d = l.decideMoveDest(n, d, record.FSLink, fsEnd{p: from, q: old}, fsEnd{p: to, q: newQ}, false, false)
	if n.gone {
		return
	}
	// A new name inside a deny_write target writes the target; a second name for a file inside one is a
	// path to it that no target names, so a write through it would reach the file unrefused (R15c).
	d = l.denyWrite(n, r, d, record.FSLink, 0, fsEnd{p: from, q: old}, fsEnd{p: to, q: newQ})
	if n.gone {
		return
	}
	d = l.denyReadMove(n, d, record.FSLink, fsEnd{p: from, q: old})
	if n.gone {
		return
	}
	if !byFD && l.askMutation(n, r, mutationQuery{op: record.FSLink, tid: n.pid, ends: []mutationEndQuery{{olddirfd, raw}, {newdirfd, rawTo}}, args: mutationArgs{flags: flags}}, d) {
		return
	}
	l.settleFS(n, r, record.FSLink, fsEnd{p: from, q: old}, fsEnd{p: to, q: newQ}, 0, d)
}

// heldFile is the file a task's descriptor holds, spelled as its /proc/<pid>/fd link names it (the cwd's for
// AT_FDCWD): the old end of linkat's AT_EMPTY_PATH form, which has no pathname to join (R6). An O_TMPFILE's
// link ends in " (deleted)"; the marker is dropped and the path marked unreliable, as R6 treats a dirfd's
// (E8), unless the file is live and that is its name. A link that cannot be read leaves the end unnamed, which matches no target.
func (r *reader) heldFile(fd int32) string {
	p, _ := r.heldFileErr(fd)
	return p
}

// heldFileErr is heldFile with the error its link's read met: EBADF for a negative descriptor other than AT_FDCWD,
// which names no link, the readlink's own error where it failed (ENOENT: the task holds no such descriptor; EACCES: a
// non-dumpable task's links are ptrace-guarded at tier 1), and nil where the link was read, whatever it named, or the
// notification went stale (n.gone says so). A watch of the descriptor's own file (watch.go) refuses one it could not
// read, since it cannot tell whether that file is a target.
func (r *reader) heldFileErr(fd int32) (string, error) {
	var link string
	switch {
	case fd == atFDCWD:
		link = "/proc/" + strconv.Itoa(r.n.pid) + "/cwd"
	case fd >= 0:
		link = "/proc/" + strconv.Itoa(r.n.pid) + "/fd/" + strconv.Itoa(int(fd))
	default:
		r.mark(rulePathUnreliable)
		return "", unix.EBADF
	}
	if !r.l.valid(r.n) {
		return "", nil
	}
	held, err := r.l.k.Readlink(link)
	// A live file may be named "<x> (deleted)" too: only a link count of zero says the marker is the kernel's
	// (reader.resolve).
	unlinked := false
	if err == nil && strings.HasSuffix(held, deletedSuffix) {
		gone, serr := r.l.k.Unlinked(link)
		unlinked = gone || serr != nil
	}
	// R2: the links are keyed by a pid, so only an ID_VALID after them says the pid was still this task (E3).
	if !r.l.valid(r.n) {
		return "", nil
	}
	if err != nil || !strings.HasPrefix(held, "/") {
		r.mark(rulePathUnreliable) // gone, or not a file on a path: socket:[...], anon_inode:...
		return "", err
	}
	if unlinked {
		held = strings.TrimSuffix(held, deletedSuffix)
		r.mark(rulePathUnreliable)
	}
	return cleanPath(held), nil
}

// recordOpen reads the path of an open-family syscall, answers it (CONTINUE, or R15c's refusal) and records
// one fs event. decideOp is what the verdict is taken as: record.FSOpen, or decide.OpMknod for a mknod, which
// is recorded as an open but is none. A mknod's verdict is never the listener's read-denied (AdvisoryFS), so
// listenerRefuses never takes its line.
func (l *Loop) recordOpen(n *notif, dirfd int32, addr uint64, flags int, decideOp string) {
	r := l.newReader(n)
	p, raw := r.pathRaw(dirfd, addr)
	if n.gone {
		return
	}
	if decideOp == record.FSOpen && l.ptyOpen(n, r, p, raw, flags) {
		return
	}
	// The open follows its final component unless O_NOFOLLOW says not to or O_CREAT|O_EXCL makes a final symlink an
	// EEXIST (open(2)); a mknod makes its name as a mkdir does (openLookup).
	q := pathQuery{tid: n.pid, dirfd: dirfd, path: raw, joined: p}.as(openLookup(flags, decideOp == decide.OpMknod))
	if decideOp == record.FSOpen && flags&unix.O_PATH == 0 && l.builtinTTYOpen(n, r, p, q, flags) {
		return
	}
	if decideOp == record.FSOpen && l.heldDirect(flags) && !walkNamed(raw) {
		// A held open is decided where the deputy's pin lands (heldOpen): this loop's own walk of the name would only
		// repeat it, so the copied name is decided as spelled, and R15c's early refusal is the spelling's. A spelling
		// the walk names (a ".." or a final ".") is not: its lexical clean names a file the open never reaches, which
		// R15c refused under a target on a line naming the file reached, so it takes this loop's
		// walk below, as an open held under an ask entry does.
		d := l.heldSpelling(r, p, flags)
		// A live block refuses the open here, before the deputy completes anything (liveFS).
		d = l.liveFS(n, r, record.FSOpen, flags, d, fsEnd{p: p, q: q})
		if n.gone {
			return
		}
		if !d.enforce && l.heldOpen(n, r, q, flags, d) {
			return
		}
		l.settleFS(n, r, record.FSOpen, fsEnd{p: p, q: q}, fsEnd{}, flags, d)
		return
	}
	d := l.decideFS(n, decideOp, p, q, flags, flags&unix.O_DIRECTORY != 0)
	if n.gone {
		return
	}
	d = l.denyWrite(n, r, d, record.FSOpen, flags, fsEnd{p: p, q: q})
	if n.gone {
		return
	}
	// A live block refuses the open before any ask, held completion or gate could take it (liveFS).
	live := l.liveFS(n, r, decideOp, flags, d, fsEnd{p: p, q: q})
	if n.gone {
		return
	}
	if live.enforce && !d.enforce {
		live.mknod = decideOp == decide.OpMknod
		l.settleFS(n, r, record.FSOpen, fsEnd{p: p, q: q}, fsEnd{}, flags, live)
		return
	}
	// A read the ruleset refuses because the deny_read enumeration froze at launch is refused here, before an ask, a
	// held completion or a gate could take it as allowed (snapshotRead).
	if decideOp == record.FSOpen {
		if d = l.snapshotRead(n, flags, d, fsEnd{p: p, q: q}); n.gone {
			return
		}
	}
	// With an open deputy (ADR 0041 Stage B) a person's ask scopes come first, then the held completion of every open
	// of an escalating gate kind, which answers whatever an ask scope did not take: neither is ever continued on the
	// copied name. Without one, gateOpen holds only an open its copied name scored into the ask range.
	if decideOp == record.FSOpen && l.deputy != nil {
		if l.askOpen(n, r, q, flags, d) || l.askReadOpen(n, r, q, flags, d) || l.heldOpen(n, r, q, flags, d) {
			return
		}
	}
	if decideOp == record.FSOpen {
		var handled bool
		handled, d = l.gateOpen(n, r, q, flags, d)
		if handled {
			return
		}
	}
	if decideOp == record.FSOpen && l.deputy == nil && d.gate == nil && l.askOpen(n, r, q, flags, d) {
		return
	}
	if decideOp == record.FSOpen && l.deputy == nil && d.gate == nil && l.askReadOpen(n, r, q, flags, d) {
		return
	}
	if decideOp == record.FSOpen && l.quietRead(flags, d) {
		l.answerFS(n, d)
		return
	}
	d.mknod = decideOp == decide.OpMknod
	l.settleFS(n, r, record.FSOpen, fsEnd{p: p, q: q}, fsEnd{}, flags, d)
}

// recordPath reads the single path of an unlink or mkdir, answers it (CONTINUE, or R15c's refusal) and
// records one fs event.
func (l *Loop) recordPath(n *notif, op string, dirfd int32, addr uint64, flags int, dir bool, args mutationArgs) {
	r := l.newReader(n)
	p, raw := r.pathRaw(dirfd, addr)
	if n.gone {
		return
	}
	q := pathQuery{tid: n.pid, dirfd: dirfd, path: raw, joined: p}.as(agent.LookupParent)
	d := l.decideFS(n, op, p, q, flags, dir)
	if n.gone {
		return
	}
	d = l.denyWrite(n, r, d, op, flags, fsEnd{p: p, q: q})
	if n.gone {
		return
	}
	if l.askMutation(n, r, mutationQuery{op: op, tid: n.pid, ends: []mutationEndQuery{{dirfd, raw}}, args: args}, d) {
		return
	}
	l.settleFS(n, r, op, fsEnd{p: p, q: q}, fsEnd{}, flags, d)
}

// recordRename reads both paths of a rename, answers it (CONTINUE, or R15c's refusal) and records one fs
// event.
func (l *Loop) recordRename(n *notif, olddirfd int32, oldAddr uint64, newdirfd int32, newAddr uint64, flags uint32) {
	exchange := flags&unix.RENAME_EXCHANGE != 0
	r := l.newReader(n)
	from, raw := r.pathRaw(olddirfd, oldAddr)
	to, rawTo := r.pathRaw(newdirfd, newAddr)
	if n.gone {
		return
	}
	old := pathQuery{tid: n.pid, dirfd: olddirfd, path: raw, joined: from}.as(agent.LookupParent)
	newEnd := fsEnd{p: to, q: pathQuery{tid: n.pid, dirfd: newdirfd, path: rawTo, joined: to}.as(agent.LookupParent)}
	// What moves, to the name entries (ADR 0043 D1, D5): a file is decided at both names, a directory by what its move
	// does to the coverage of the files beneath it. Under RENAME_EXCHANGE both objects move, so either name is a file's
	// unless both are directories.
	srcDir, srcUnknown := l.movedKind(n, fsEnd{p: from, q: old})
	dstDir, dstUnknown := srcDir, srcUnknown
	if exchange {
		dstDir, dstUnknown = l.movedKind(n, newEnd)
	}
	endsDir := srcDir && (!exchange || dstDir)
	d := l.decideFS(n, record.FSRename, from, old, 0, endsDir)
	if n.gone {
		return
	}
	d = l.decideMoveDest(n, d, record.FSRename, fsEnd{p: from, q: old}, newEnd, exchange, endsDir)
	if n.gone {
		return
	}
	// Both ends, and either one as a directory above a target: a rename moves whatever lies beneath it
	// (R15c, agent.RuleTable.DenyWriteTarget).
	d = l.denyWrite(n, r, d, record.FSRename, 0, fsEnd{p: from, q: old}, newEnd)
	if n.gone {
		return
	}
	d = l.nameMove(n, d, fsEnd{p: from, q: old}, newEnd, srcDir || srcUnknown, exchange && (dstDir || dstUnknown))
	if n.gone {
		return
	}
	// The source leaves its name, and so does the destination under RENAME_EXCHANGE.
	moved := []fsEnd{{p: from, q: old}}
	if exchange {
		moved = append(moved, newEnd)
	}
	d = l.denyReadMove(n, d, record.FSRename, moved...)
	if n.gone {
		return
	}
	d.exchange = exchange
	if l.askMutation(n, r, mutationQuery{op: record.FSRename, tid: n.pid, ends: []mutationEndQuery{{olddirfd, raw}, {newdirfd, rawTo}}, args: mutationArgs{flags: int(flags)}}, d) {
		return
	}
	l.settleFS(n, r, record.FSRename, fsEnd{p: from, q: old}, newEnd, 0, d)
}

// recordSymlink reads the created link path and the link's target, answers the syscall (CONTINUE, or R15c's
// refusal) and records one fs event with the created path first: that is the path the kernel's path_symlink
// hook decides on.
func (l *Loop) recordSymlink(n *notif, targetAddr uint64, dirfd int32, linkAddr uint64) {
	r := l.newReader(n)
	link, raw := r.pathRaw(dirfd, linkAddr)
	if !l.valid(n) {
		return
	}
	target, targetCut := r.cstring(targetAddr, pathMax)
	if !l.valid(n) {
		return // R2: the link target is only trustworthy if the notification is still the same one
	}
	q := pathQuery{tid: n.pid, dirfd: dirfd, path: raw, joined: link}.as(agent.LookupParent)
	d := l.decideFS(n, record.FSSymlink, link, q, 0, false)
	if n.gone {
		return
	}
	d = l.denyWrite(n, r, d, record.FSSymlink, 0, fsEnd{p: link, q: q})
	if n.gone {
		return
	}
	if !targetCut && l.askMutation(n, r, mutationQuery{op: record.FSSymlink, tid: n.pid, ends: []mutationEndQuery{{dirfd, raw}}, target: target}, d) {
		return
	}
	l.settleFS(n, r, record.FSSymlink, fsEnd{p: link, q: q}, fsEnd{p: target}, 0, d)
}

// fsDecided is one fs event's verdict: advisory, which Landlock makes good on the continued syscall, unless
// enforce says this loop answers the refusal itself (a deny_write target, R15c).
type fsDecided struct {
	rule        string
	verdict     record.Verdict
	reason      record.Reason
	enforce     bool
	gate        *gate.Decision
	unsupported bool
	// exchange marks a rename under RENAME_EXCHANGE, whose destination leaves its name too: gateFS scores it
	// as a source (ADR 0041 Step 4).
	exchange bool
	// mknod marks a mknod, recorded as op open with O_CREAT|O_EXCL (mknodFlags) but no open: its access mode reads
	// O_RDONLY and it reads nothing, so gateFS scores it with the write predicates only.
	mknod bool
	// srcNotDir and dstNotDir mark a move's end stat'ed as no directory (finalNotDir), which no path lies beneath:
	// gateFS hands them to the gate (gate.Action.PathNotDir, DestNotDir).
	srcNotDir, dstNotDir bool
	// floor marks a refusal a supervisor floor made on the copied names (denyWrite's R15c, denyReadMove's R15d): it is
	// final, and no person is asked to lift it (ADR 0041 D3 (1), ADR 0047).
	floor bool
}

// answerFS answers an fs notification: CONTINUE for an advisory verdict, R10's errno for a refusal this loop
// makes itself. An observe run's respond turns the latter into CONTINUE too (R30).
func (l *Loop) answerFS(n *notif, d fsDecided) {
	if d.enforce {
		l.respond(n, respErrno(refusalErrno))
		return
	}
	l.respond(n, respContinue())
}

// settleFS answers an fs notification and writes its line, unless another producer's line is the action's one
// (R7a): at tier 2 a continued action the kernel recorder's hooks see is recorded by the recorder, with the
// verdict the LSM chain returned (KernelFS), so this loop hands the recorder its naming (handOver) and writes
// none; and an open the fanotify listener refuses after the Landlock ruleset let it through is the listener's
// line (listenerRefuses). A refusal this loop answers itself (R15c, R15d, R5, and at tier 2 with no plane mode
// the listener fallback's, fallbackMutation) never reaches the kernel, and a mode change or an O_PATH open reaches
// no hook of the recorder nor the listener: each keeps this loop's line. The naming is handed over before the
// answer, so it is there when the recorder reads the kernel's record of the continued syscall.
//
// e2 is a rename's or a link's new name, a symlink's stored target (a string, never walked), or none.
func (l *Loop) settleFS(n *notif, r *reader, op string, e, e2 fsEnd, flags int, d fsDecided) {
	p, p2 := e.p, e2.p
	// A live block refuses what it names of the action's ends: both of a rename or a link, a symlink's own name but
	// never its stored target, which is a string no walk follows (liveFS).
	moved := []fsEnd{e}
	if op == record.FSRename || op == record.FSLink {
		moved = append(moved, e2)
	}
	if d = l.liveFS(n, r, op, flags, d, moved...); n.gone {
		return
	}
	c := l.table.Load()
	at, at2 := l.landed(n, e), l.landed(n, e2)
	if (op == record.FSRename || op == record.FSLink) && c.pol != nil && c.pol.Rules != nil && c.pol.Rules.Gate.ScoresBeneath() {
		// A read rule's path pattern matches a path beneath a moved directory, and only a directory has one: an end
		// stat'ed as no directory is matched by its own name. The name could only become a
		// directory the pattern reaches through the move of that directory, which this gate scores where it stands.
		d.srcNotDir = l.finalNotDir(at)
		d.dstNotDir = d.exchange && l.finalNotDir(at2)
	}
	d = c.gateFS(op, at, at2, flags, d, r.ok() && !unnamedFS(r, op, p, p2) && !l.gateFactsIncomplete(n, op, e, e2, flags))
	// The line's names are walked before the answer, which ends the notification (lineName).
	name, name2 := l.lineName(n, e), l.lineName(n, e2)
	if n.gone {
		return
	}
	// An O_PATH open reaches none of the recorder's hooks (do_dentry_open returns before security_file_open), so its
	// line is this loop's even while a recorder reads, as an attribute change's is.
	oPath := op == record.FSOpen && flags&unix.O_PATH != 0
	kernel := !d.enforce && !decide.IsAttrOp(op) && !oPath && l.kernelFS != nil && l.kernelFS()
	if kernel {
		l.handOver(n, r, op, e, e2, name, name2, d)
	} else if (d.enforce || oPath) && l.kernelFS != nil && l.kernelFS() {
		// A refusal executes no hook, and nor does an O_PATH open. Tombstone the
		// thread's earlier naming so a later unrelated kernel sample cannot inherit
		// it; older samples still find the action preceding their own timestamp.
		l.handed.put(handed{tid: n.pid, op: op, at: l.mono()})
	}
	l.answerFS(n, d)
	if kernel || (op == record.FSOpen && l.listenerRefuses(n, e, flags, d)) {
		return
	}
	l.emitFS(n, r, op, name, name2, flags, d)
}

// listenerRefuses reports whether this open is one tier 2's fanotify listener refuses after the Landlock ruleset
// let it through: a read under a deny_read the ruleset leaves unenforced or an exec grant reopens, a write-open
// under a deny_read nested in a write entry (R15). The listener writes that refusal's line itself, the
// mechanism's own answer, so this loop writes none and the open has one line (R7a; enforce-cgroup-observe R8).
// A refusal Landlock makes first never reaches the listener and keeps this loop's line, and so does an O_PATH open,
// for which fanotify sends no permission event.
func (l *Loop) listenerRefuses(n *notif, e fsEnd, flags int, d fsDecided) bool {
	c := l.table.Load()
	if d.enforce || d.verdict != record.VerdictRefused || d.reason != record.ReasonReadDenied || e.p == "" ||
		c.tier() != backend.TierCgroup || flags&unix.O_PATH != 0 {
		return false
	}
	kind := agent.ActionFSWrite
	if decide.IsRead(record.FSOpen, flags) {
		kind = agent.ActionFSRead
	}
	a := agent.Action{Kind: kind, Path: l.landed(n, e)}
	return decide.LandlockRuleset(c.pol.Rules, a).Verdict == agent.VerdictAllow
}

// fsEnd is one path an fs syscall modifies: the joined spelling the record carries and the query that walks
// it as the task's lookup does.
type fsEnd struct {
	p string
	q pathQuery
}

// denyWrite: a modification that reaches a built-in deny_write target (agent.RuleTable.DenyWrite,
// agent-contract R20) is refused by this loop, since Landlock unions the enclosing write entry's rights over
// the whole subtree and would allow it. Each end is matched as spelled and, when the spelling does not
// match, again where the task's own lookup lands (FSTarget: a symlink into a target, a /proc/<pid>/fd magic
// link, a dangling link an O_CREAT open follows), by the one predicate Evaluate asks
// (agent.RuleTable.DenyWriteTarget, asked through the table's index), with a rename's ends matched as directories above a target too. A read
// is not a modification and keeps its verdict, as does any end that matches nothing.
//
// A modification whose pathname could not be read whole (reader.unreadPath) is refused too, under that
// marker, once the set is non-empty: with a target to protect, this is a decision kind, and R5 fails a
// decision closed. Continued, it went wherever the kernel's own read of the name led, and one prctl
// (PR_SET_DUMPABLE 0, which denies an unprivileged process_vm_readv) would have let every write past the
// set. A name the kernel cannot read either costs nothing, since its answer would be EFAULT or
// ENAMETOOLONG; the cost is a tier-1 target that made itself non-dumpable, which then may modify nothing
// the filter notifies. So is one whose walk failed other than as the task's lookup fails (matchEnds'
// unwalked: EMFILE, ENOMEM, EIO here), under path-unreliable: where it lands is unknown, and may be a target.
//
// This check alone is not a closure. Where a kernel decision plane decides the run it is an early refusal and
// recording path backed by the plane; at tier landlock and on tier cgroup's listener it is the targets' only
// refusal, best effort, which compile warns per target and run_start records (best_effort deny_write/default),
// unless the contract says fs.assurance: kernel, which refuses such a run before it starts (ADR 0041 D1 (a)).
// Without a plane the kernel reads the pathname again, and resolves it again, after this loop answers
// CONTINUE. A sibling thread or CLONE_VM child that rewrites the string in the target's memory
// between the two reads needs no filesystem write at all — it defeats the AT_EMPTY_PATH reading too, an old
// name read as "" and then made ".git/config" — and a peer that repoints a symlink or swaps a directory
// between the two lookups lands a write this walk decided elsewhere; a hard link to a target made before the
// run is a name no target spells, as is another case of a target's name on a case-insensitive file system
// (vfat, exfat, ntfs, a casefold directory), since targets are matched by string; the socket inode a unix
// bind(2) creates is not refused; and a chmod, chown or xattr write is refused here only where a decision plane
// decides the run (Options.PlaneAttrs, recordAttr, R17), never at tiers 1 and 2, where a chmod is recorded under
// record: full and an fs.write gate scores all three. Tier 3's nearest-wins walk decides on the inode and is the race-free enforcement
// (SEMANTICS §2, agent-contract R20), also available at tier cgroup through lsm/fmod_ret.
func (l *Loop) denyWrite(n *notif, r *reader, d fsDecided, op string, flags int, ends ...fsEnd) fsDecided {
	c := l.table.Load()
	rt := c.pol.Rules
	if rt == nil || (len(rt.DenyWrite) == 0 && rt.Builtins == nil) || isRead(op, flags) {
		return d
	}
	ancestors, names := op == record.FSRename, makesName(op, flags)
	target, ok, unwalked := l.matchEnds(n, ends, func(i int, p string) (agent.FSRule, bool) {
		// A made name (a link's new name is its second end) is asked as one: the reopening write
		// entry's own name in an fs.deny_write directory is the entry's.
		if names || (op == record.FSLink && i == 1) {
			return c.denyWriteName(p)
		}
		return c.denyWriteTarget(p, ancestors)
	})
	if ok {
		return fsDecided{rule: target.RuleName(), verdict: record.VerdictRefused, reason: reasonFor(op), enforce: true, floor: true}
	}
	if unwalked {
		rule := rulePathUnreliable
		if rt.Builtins != nil {
			rule = agent.BuiltinHostIPC
		}
		return fsDecided{rule: rule, verdict: record.VerdictRefused, reason: reasonFor(op), enforce: true, floor: true}
	}
	if r.unreadPath != "" {
		return fsDecided{rule: r.unreadPath, verdict: record.VerdictRefused, reason: reasonFor(op), enforce: true, floor: true}
	}
	return d
}

// denyReadMove: at tier 2 a hard link or a rename that would give a file beneath a deny_read entry the
// Landlock ruleset leaves unenforced (one nested in a write entry) a name no entry denies is refused. Tier 2
// enforces such an entry with its fanotify listener, which matches the path of each open, so link(key, hl) or
// rename(secret/, notsecret/) moved the file out of the rule and it was read with no refusal, while the
// ledger said refused; SEMANTICS §2 says a hard link or a rename cannot move a file out
// of a rule. Each end is matched as spelled and where the task's lookup lands, like denyWrite, and a rename's
// ends as directories above an entry too. At tier 1 the entry refuses no read at all (compile says so), so
// nothing is refused here; tier 3's walk decides on the inode.
//
// Best effort, as denyWrite is: the kernel reads and resolves the names again after this loop answers.
func (l *Loop) denyReadMove(n *notif, d fsDecided, op string, ends ...fsEnd) fsDecided {
	c := l.table.Load()
	rt := c.pol.Rules
	if rt == nil || c.tier() != backend.TierCgroup || !c.hasDenyReadMove() {
		return d
	}
	ancestors := op == record.FSRename
	target, ok, unwalked := l.matchEnds(n, ends, func(_ int, p string) (agent.FSRule, bool) { return c.denyReadMoveTarget(p, ancestors) })
	if ok {
		return fsDecided{rule: target.RuleName(), verdict: record.VerdictRefused, reason: reasonFor(op), enforce: true, floor: true}
	}
	if unwalked {
		return fsDecided{rule: rulePathUnreliable, verdict: record.VerdictRefused, reason: reasonFor(op), enforce: true, floor: true}
	}
	return d
}

// movedKind is what a rename moves from the end e, to the name entries (R15f; ADR 0043 D1, D5), asked only at tier 2
// of a table with name entries, so no other run stats anything: whether it is a directory, by an fstatat of where the
// end's walk lands (not followed: a rename moves a symlink itself), and whether that could not be told, when the
// caller asks both a file's question and a directory's (fail closed). Any failed stat is unknown, a missing name
// (ENOENT) included: the task's rename then fails with ENOENT unless the name appears first, and asking both
// questions costs only that. Best effort, as R15d is: the kernel looks the name up again after this loop answers.
func (l *Loop) movedKind(n *notif, e fsEnd) (dir, unknown bool) {
	c := l.table.Load()
	if c.tier() != backend.TierCgroup || !c.fsIx.HasNames() || e.p == "" || n.gone {
		return false, false
	}
	if e.q.path != "" {
		l.fsWalk(n, e.q)
	}
	isDir, err := l.k.FinalIsDir(l.landed(n, e))
	return isDir && err == nil, err != nil
}

// nameMove is R15f's ADR 0043 D5 at tier 2, beside R15d (decide.FSIndex.NameMoveRefused, interface 1): a rename that
// moves a directory so that files beneath it leave a name entry's coverage (out of every scope of the entry, beneath
// a dependency directory, or by taking a dependency directory's name) is refused by this loop, under the entry's rule,
// or path-unresolved when a climb cannot decide; fromDir says the source moves a directory, toDir the destination
// (RENAME_EXCHANGE). The ends are asked where the task's lookups land; one whose walk failed other than as the task's
// lookup fails is refused path-unreliable, as R15d refuses it. Asked after denyWrite and before denyReadMove, so the
// line names what Evaluate's tier-2 rename names first. Best effort, as R15d is: the kernel looks the names up again
// after this loop answers, and a plane mode's path_rename decides D5 on the dentries (enforce-plane). Its refusal is a
// floor, as R15d's is: no person's answer lifts it (askMutation, ADR 0047).
func (l *Loop) nameMove(n *notif, d fsDecided, from, to fsEnd, fromDir, toDir bool) fsDecided {
	c := l.table.Load()
	if c.tier() != backend.TierCgroup || !c.fsIx.HasNames() || (!fromDir && !toDir) || to.p == "" || n.gone {
		return d
	}
	for _, e := range [2]fsEnd{from, to} {
		if e.q.path != "" {
			l.fsWalk(n, e.q)
		}
	}
	if n.gone {
		return d
	}
	if l.walkIncomplete(n, from, to) {
		return fsDecided{rule: rulePathUnreliable, verdict: record.VerdictRefused, reason: reasonFor(record.FSRename), enforce: true, floor: true}
	}
	src, dst := l.landed(n, from), l.landed(n, to)
	if rule, reason, refused := c.fsIx.NameMoveRefused(src, dst, fromDir); refused {
		return fsDecided{rule: rule, verdict: record.VerdictRefused, reason: reason, enforce: true, floor: true}
	}
	if rule, reason, refused := c.fsIx.NameMoveRefused(dst, src, toDir); refused {
		return fsDecided{rule: rule, verdict: record.VerdictRefused, reason: reason, enforce: true, floor: true}
	}
	return d
}

// matchEnds is the match denyWrite and denyReadMove share: every end by the name its line gives it first (lineName:
// its spelling, or for an end the walk names, a ".." or a final ".", the walk's name), then each end whose name matched
// nothing, or that has no spelling, where the task's own lookup lands (fsTarget); the first entry match finds. An end
// the walk names is never matched by R6's lexical clean, which names a file no mechanism decides on (the kernel,
// Landlock, the listener and the plane all reach the physical one): matched so, out/lk/../f with out/lk -> ../b/sub was
// refused under the target out/f, on a line naming b/f, a file that rule never covered. unwalked reports an end
// whose walk failed other than as the task's own lookup fails
// (lookupFailure): EMFILE, ENFILE, ENOMEM or EIO in this process, or EXDEV (a procfs instance whose pid
// numbers it cannot translate). Where that end lands is then unknown, so the caller refuses under
// path-unreliable (R15c, R5): a decision that cannot be finished fails closed, and an agent that pushed this
// process toward fd exhaustion would otherwise have its write continued wherever the spelling led. A walk
// that reached a file with no path in this process's view (errOtherView: a pipe behind /dev/stdout, an
// unlinked file behind /proc/self/fd/N) reached nothing a target names, and keeps the verdict.
//
// match is asked with the end's index, which says what the modification does there (a link's new name, denyWrite).
func (l *Loop) matchEnds(n *notif, ends []fsEnd, match func(i int, p string) (agent.FSRule, bool)) (target agent.FSRule, ok, unwalked bool) {
	for i, e := range ends {
		if target, ok := match(i, l.lineName(n, e)); ok {
			return target, true, false
		}
	}
	for i, e := range ends {
		// An end with no R6 spelling (a join over PATH_MAX) is walked too: the walk resolves q.path from the
		// task's own cwd or dirfd, as its lookup does.
		if e.q.path == "" || n.gone {
			continue
		}
		at, err := l.fsTarget(n, e.q)
		if n.gone {
			continue
		}
		if err != nil {
			unwalked = unwalked || !(lookupFailure(err) || errors.Is(err, errOtherView) || errors.Is(err, errGone))
			continue
		}
		if at == l.lineName(n, e) {
			continue
		}
		if target, ok := match(i, at); ok {
			return target, true, false
		}
	}
	return agent.FSRule{}, false, unwalked && !n.gone
}

// makesName reports whether the modification op, with its open flags, makes the name it is asked of: a mkdir, a
// symlink, an exclusive create (a mknod is recorded as one, mknodFlags). An open that may create (O_CREAT alone) is a
// write of what the name holds where it exists, and is asked as one.
func makesName(op string, flags int) bool {
	return op == record.FSMkdir || op == record.FSSymlink ||
		(op == record.FSOpen && flags&(unix.O_CREAT|unix.O_EXCL) == unix.O_CREAT|unix.O_EXCL)
}

// decideFS is the advisory verdict of one fs syscall (R15, R17, R15b), taken before the syscall is
// continued, on the file or directory the kernel decides on: Landlock and tier 2's listener decide the
// continued syscall on where the spelling lands, not on the spelling. A write through another spelling of a
// write entry — a /proc/<pid>/fd magic link or /dev/fd alias of a descriptor under it, a symlink into it, a
// system symlink such as /var/run — runs, and a read or a write through a symlink the contract does not
// declare, planted in a write entry and pointing into a deny_read entry or outside every write entry, is
// refused, so every verdict is taken again where the path lands, walked as the task's own lookup walks it.
// The walk is inside the ID_VALID bracket like every /proc read (R2, E3). A walk that fails as the task's
// own lookup would (the name is missing, not a directory, a loop) keeps the spelling's verdict: the syscall
// fails the same way. The spelling is the line's name (lineName): for an end the walk names that is the walk's name
// where the walk got that far, never R6's lexical clean of a ".." spelling. One that cannot say where the path lands (another mount view) keeps a refusal, and
// turns anything else into observed under path-unreliable, since the kernel may have decided either way; it
// never reaches fallbackMutation, so its syscall is continued at every tier (a nameless object's write-open
// must run; R15's 2026-10-17 amendment, TestFallbackMutationWalkFailures).
func (l *Loop) decideFS(n *notif, op, p string, q pathQuery, flags int, dir bool) fsDecided {
	c := l.table.Load()
	rule, v, reason := c.fsVerdict(p, op, flags, dir)
	d := fsDecided{rule: rule, verdict: v, reason: reason}
	if p == "" || q.path == "" || n.gone {
		return l.fallbackMutation(c, op, flags, d)
	}
	w := l.fsWalk(n, q)
	at, err := w.at, w.err
	if n.gone {
		return d
	}
	if err != nil {
		if w.name != "" {
			// A walk the line is named by (lineName: a ".." or a final ".") that failed past the directory of the final
			// component names the end there, so the verdict is taken there too, never on the lexical clean, which names
			// another file.
			rule, v, reason = c.fsVerdictIn(c.fsResolved, w.name, op, flags, dir)
			d = fsDecided{rule: rule, verdict: v, reason: reason}
		}
		if errors.Is(err, errOtherView) {
			// A private view, such as pipe:[inode], has no governed pathname.
			// Keep a lexical refusal advisory; otherwise report the missing
			// attribution rather than claim the global spelling was allowed.
			if v == record.VerdictRefused {
				return d
			}
			return fsDecided{rule: rulePathUnreliable, verdict: record.VerdictObserved}
		}
		if v == record.VerdictRefused || lookupFailure(err) {
			return l.fallbackMutation(c, op, flags, d)
		}
		return l.fallbackMutation(c, op, flags, fsDecided{rule: rulePathUnreliable, verdict: record.VerdictObserved})
	}
	if at == p {
		// A path that lands on its own spelling passes no link that still exists, so an entry it matched by a declared
		// link's spelling is one whose link the agent replaced with a real directory: Landlock bound that entry's rule to
		// the link target's inode, and it grants nothing here. The line is named by the entries where
		// they are bound, when that answers the same; a path-matching mechanism (tier 2's listener) may still decide by
		// the declared spelling, so a different answer keeps the spelling's.
		if c.linkedFS[rule] {
			if r2, v2, reason2 := c.fsVerdictIn(c.fsResolved, at, op, flags, dir); v2 == v && reason2 == reason {
				d.rule = r2
			}
		}
		return l.fallbackMutation(c, op, flags, d)
	}
	rule, v, reason = c.fsVerdictIn(c.fsResolved, at, op, flags, dir)
	return l.fallbackMutation(c, op, flags, fsDecided{rule: rule, verdict: v, reason: reason})
}

// fallbackMutation supplies ADR0021(5)'s root mutation refusal while fanotify
// decides opens and execs. It uses the task's resolved lookup above, refuses a
// walk that failed other than as the task's lookup fails (path-unreliable) once the
// table has a deny_read, and retains the documented CONTINUE pathname race.
// A selected kernel plane owns these decisions; chmod remains its separate
// attribute contract rather than an invented Landlock filesystem right.
func (l *Loop) fallbackMutation(c *compiled, op string, flags int, d fsDecided) fsDecided {
	if c.tier() != backend.TierCgroup || l.planeAttrs || isRead(op, flags) || decide.IsAttrOp(op) {
		return d
	}
	if d.verdict == record.VerdictObserved && d.rule == rulePathUnreliable && c.fsBoth.HasDenyRead() {
		d.verdict, d.reason = record.VerdictRefused, reasonFor(op)
	}
	if d.verdict == record.VerdictRefused {
		d.enforce = true
	}
	return d
}

// errGone is fsTarget's answer for a notification that went stale around its walk (n.gone is set).
var errGone = errors.New("supervisor: notification gone")

// fsTarget is the kernel's FSTarget for one end of this notification, walked once: the verdict, the
// deny_write and the deny_read-move checks all ask where the same end lands (reader.walked). A path whose
// directory the walk cache holds, and which lands on its spelling there, is answered without a lookup
// (cachedTarget), and without the ID_VALID bracket the walk needs. An end whose spelling was joined to a
// " (deleted)" directory link goes to the walk (pathQuery.deletedBase).
func (l *Loop) fsTarget(n *notif, q pathQuery) (string, error) {
	w := l.fsWalk(n, q)
	return w.at, w.err
}

// fsWalk is fsTarget's walk of q with the name it gives a ".." spelling (fsLanding), memoized: the walk is made once per
// end, and every verdict, check and name of the end reads that one walk.
func (l *Loop) fsWalk(n *notif, q pathQuery) walkMemo {
	r := n.r
	if r != nil {
		q.deletedBase = q.deletedBase || r.joinedToDeleted(q)
		for i := 0; i < r.nwalked; i++ {
			if r.walked[i].q == q {
				return r.walked[i]
			}
		}
	}
	w := walkMemo{q: q}
	var ok bool
	if w.at, ok = l.cachedTarget(q); !ok {
		// The walk reads /proc/<tid>, so only an ID_VALID on each side of it says the tid was the task that
		// trapped (R2, E3); a gone notification's answer is never kept. The cache reads nothing of the task's, and
		// answers no spelling with a "..", which alone is named.
		if !l.valid(n) {
			return walkMemo{q: q, err: errGone}
		}
		var at fsLanding
		at, w.err = l.k.FSTarget(q)
		w.at, w.name = at.at, at.name
		if !l.valid(n) {
			return walkMemo{q: q, err: errGone}
		}
	}
	if r != nil && r.nwalked < len(r.walked) {
		r.walked[r.nwalked] = w
		r.nwalked++
	}
	return w
}

// lookupFailure reports whether a walk failed the way the task's own lookup of the same name fails, so the
// syscall reaches no decision of Landlock's or the listener's either.
func lookupFailure(err error) bool {
	for _, e := range []error{unix.ENOENT, unix.ENOTDIR, unix.ELOOP, unix.ENAMETOOLONG, unix.EACCES, unix.EBADF, unix.EINVAL} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// decideMoveDest is the destination half of a rename's or a link's advisory verdict (R15, R17): Landlock
// decides both ends, the right to make the entry in the destination directory as well as the source's, and
// REFER's rule that a file moved or linked across directories gains no right it did not have where it was
// (decide.RenameGainedBy and ReferRefuses, the rule Evaluate's rename answers by, checked both ways under RENAME_EXCHANGE: the rights at
// the new name's directory against the moved object's own, never a rule on the name it replaces, nothing within one
// directory, and the file rights only for an object that is no directory; for a link decide.LinkGainsBy, the file
// rights at the new name's directory, as hook_path_link compares them). A
// source already refused keeps its verdict; otherwise a refused destination is the verdict. Each end is
// decided where it lands (decideFS), as the moved object (dir: a directory, which no name entry decides). At tier 3
// as at tier 2: the plane does not refuse a rename whose destination no write entry covers (the Landlock floor does,
// and its line was the recorder's "observed"), so this loop refuses it with the line tier cgroup's plane runs get
// (TIER3-PLAN T11, conformance fs/rename-out-of-write-entry).
func (l *Loop) decideMoveDest(n *notif, d fsDecided, op string, from, to fsEnd, exchange, dir bool) fsDecided {
	if d.verdict != record.VerdictAllow || to.p == "" {
		return d
	}
	c := l.table.Load()
	if c.pol == nil || c.pol.Rules == nil {
		return d
	}
	dst := l.decideFS(n, op, to.p, to.q, 0, dir)
	if n.gone || dst.verdict != record.VerdictAllow {
		return dst
	}
	// Each end where its own walk landed it: a new name such as out/lk/../x cleans to the source's out/x, but the kernel
	// walks out/lk/.. physically, so a lookup by the cleaned spelling found the source's walk.
	src, at := l.landed(n, from), l.landed(n, to)
	exec := l.execGrants(c)
	var gains bool
	if op == record.FSLink {
		gains = c.linkGains(src, at, exec)
	} else {
		gains = l.referRefuses(c.renameGained(src, at, exec), src) || (exchange && l.referRefuses(c.renameGained(at, src, exec), at))
	}
	if gains {
		return fsDecided{rule: d.rule, verdict: record.VerdictRefused, reason: reasonFor(op)}
	}
	return d
}

// finalNotDir reports whether p's final component, not followed, is known to be no directory (FinalIsDir: another
// type, or no object, which fails the task's own move). A stat that fails otherwise leaves the object unknown, and it
// is taken to be a directory, the stricter reading, as referRefuses takes it.
func (l *Loop) finalNotDir(p string) bool {
	dir, err := l.k.FinalIsDir(p)
	return err == nil && !dir
}

// referRefuses is decide.ReferRefuses for the object at p, which a rename moves and which gains the rights gained
// (no_more_access): a gained file right refuses whatever the object is, and a gain of directory rights alone refuses
// only a directory, so p is stat'ed only then (fstatat, not followed: a rename moves a symlink itself). A stat that
// fails for another reason than a missing name leaves the object unknown, and it is compared as a directory, the
// stricter reading; a missing name fails the task's own rename, with ENOENT, before REFER.
func (l *Loop) referRefuses(gained agent.AccessSet, p string) bool {
	if gained == 0 {
		return false
	}
	if decide.ReferRefuses(gained, false) {
		return true
	}
	dir, err := l.k.FinalIsDir(p)
	return err != nil || dir
}

// walkIncomplete reports whether this notification's walk of one of the ends failed so that landed
// answers the spelling for an end that does not land there: an errno the task's own lookup would not have
// failed with (this process's EMFILE, ENFILE, ENOMEM, EIO, a procfs it cannot translate: EXDEV), or a linked
// file whose path this process cannot see (errLinkedElsewhere). A gate has no facts for such an end, and refuses
// it as gate.unreadable rather than score the spelling and continue (gate.md R1, ADR 0041 D4, finding
// failopen-3). A lookup failure fails the task's syscall the same way, and a nameless object (errOtherView: a
// pipe, a socket, an unlinked file) has no name a predicate could match, so both leave the facts complete.
func (l *Loop) walkIncomplete(n *notif, ends ...fsEnd) bool {
	for _, e := range ends {
		w := l.walkOf(n, e)
		if w == nil || w.err == nil {
			continue
		}
		if errors.Is(w.err, errLinkedElsewhere) ||
			!(lookupFailure(w.err) || errors.Is(w.err, errOtherView) || errors.Is(w.err, errGone)) {
			return true
		}
	}
	return false
}

// gateFactsIncomplete reports whether the gate has no complete facts for an op on the ends e and e2 with
// flags: walkIncomplete, or an open that reads (O_RDONLY, O_RDWR, an O_CREAT or O_TRUNC open that is not O_WRONLY)
// whose walk reached a regular file with no name left on a filesystem with names (errUnlinkedFile). Such a file had a
// name an fs.read predicate may have matched, and lost it: a read gate scores neither a write-only open nor an
// unlink, so a file the gate refuses by name could be opened write-only, unlinked, and reopened for reading through
// /proc/self/fd, scored on the descriptor's procfs spelling. Its read is gate.unreadable
// (gate.md R1). A write-only reopen keeps its facts: a write gate scored the unlink that removed the name.
func (l *Loop) gateFactsIncomplete(n *notif, op string, e, e2 fsEnd, flags int) bool {
	if l.walkIncomplete(n, e, e2) {
		return true
	}
	if op != record.FSOpen || (isWriteOpen(flags) && !openReads(flags)) {
		return false
	}
	w := l.walkOf(n, e)
	return w != nil && errors.Is(w.err, errUnlinkedFile)
}

// walkOf is this notification's walk of the end e's own query (fsTarget's memo), or nil when none was made. It is
// found by the query, never by the end's cleaned spelling: two ends can share a spelling and land apart, as a new
// name out/lk/../x and a source out/x do when out/lk is a symlink.
func (l *Loop) walkOf(n *notif, e fsEnd) *walkMemo {
	r := n.r
	if r == nil || e.q.path == "" {
		return nil
	}
	q := e.q
	q.deletedBase = q.deletedBase || r.joinedToDeleted(q)
	for i := 0; i < r.nwalked; i++ {
		if r.walked[i].q == q {
			return &r.walked[i]
		}
	}
	return nil
}

// landed is where the end e was found to land by this notification's walk of its own query (walkOf); where that walk
// failed, the name it gave the end (lineName's, decideFS's verdict's), or its spelling when no walk of it was made or
// it named nothing. A gate never scores the lexical clean of a ".." end that names another file.
func (l *Loop) landed(n *notif, e fsEnd) string {
	if w := l.walkOf(n, e); w != nil {
		if w.err == nil {
			return w.at
		}
		if w.name != "" {
			return w.name
		}
	}
	return e.p
}

// memoName is lineName for a line written after the answer, which ends the notification: the name the decision's walk
// kept (walkOf), and no walk of its own, which would have no task to vouch for it; the spelling when no walk named the
// end.
func (l *Loop) memoName(n *notif, e fsEnd) string {
	if w := l.walkOf(n, e); w != nil && w.name != "" {
		return w.name
	}
	return e.p
}

// lineName is the name a line gives the end e: its joined spelling (R6), except where that spelling holds a ".."
// component. R6 cleans the join lexically, and a ".." after a symlink cleans onto another file than the one the task's
// lookup reaches: with out/lk -> realbin/sub, out/lk/../e cleans to out/e and the kernel removes out/realbin/e. Such
// an end is named where the physical walk of its parent directory lands, joined with its final component as spelled,
// the name the syscall reached: its final component is never followed for the name, whatever the syscall does with
// it, so a ".." the clean resolves as the kernel does names what the spelling names, a final symlink included (R15b;
// 2c6-1). A final "." or ".." has no name of its own, and
// is named where the whole walk lands.
//
// The name is the decision's own walk's (fsWalk's memo, execWalk.named), never another walk's: an agent that moves a
// symlink between two walks of one notification had a second walk name a file the verdict and rule were never taken
// on, "allow b/f, rule fs.write[./out/]" for a file outside every write entry. An end no decision walked (a refused
// rename's or link's new name: decideMoveDest returns before it) is walked here, once, and that walk is the end's.
// The memo of a refusal made after a person's
// wait is the walk made before it. A walk made here must be asked before the notification is answered: after the
// answer the walk has no task to vouch for (fsWalk answers errGone). An end whose walk did not reach the directory of
// its final component, or could not name it in this process's view, keeps the spelling, and so do a symlink's target
// and a descriptor's end, which carry no query path.
func (l *Loop) lineName(n *notif, e fsEnd) string {
	if e.p == "" || !walkNamed(e.q.path) {
		return e.p
	}
	if w := l.fsWalk(n, e.q); w.name != "" {
		return w.name
	}
	return e.p
}

// emitFS records one filesystem event with the verdict decideFS and denyWrite took. record: off keeps these
// out of the ledger entirely unless refused.
func (l *Loop) emitFS(n *notif, r *reader, op, p, p2 string, flags int, d fsDecided) {
	c := l.table.Load()
	rule, verdict, reason := d.rule, d.verdict, d.reason
	if verdict != record.VerdictRefused && !c.recording() {
		// record: off keeps the ledger to what was refused. A refusal is never suppressed: it is the
		// reason channel's second guarantee (spec/reason/REASON-CHANNEL.md §1), and this package is the
		// only producer of the write/delete/rename/mkdir-outside-contract codes.
		return
	}
	// A refusal this loop answered itself (R15c) happened whatever else could not be read: the agent got
	// R10's errno, so the line says refused under the target's rule, or under the marker of the pathname it
	// could not read, never observed, and is written under record: off too. An end that matched is all it
	// rests on; an unread or empty other end names nothing.
	if unnamedFS(r, op, p, p2) && !d.enforce {
		// R5: a record-only path never fails closed. The event still lands, with the marker in rule and
		// no verdict this loop could honestly claim (E19, E20).
		rule, verdict, reason = noteOr(r, unreadMarker(r)), record.VerdictObserved, record.Reason("")
		if !c.recording() {
			return // nothing was decided, so there is no refusal to guarantee
		}
	}
	ev := action(l.event(n, record.KindFS, record.SourceSeccomp), rule, verdict, reason)
	if d.gate != nil && d.gate.Verdict != gate.Allow {
		ev.Authority = record.AuthorityGate
	}
	l.emitFor(n, ev, struct {
		record.FSPayload
		GateFields
	}{record.FSPayload{Op: op, Path: p, Path2: p2, Flags: flags, Mechanism: c.readMechanism(op, flags, verdict, reason, d)},
		fsGatePayload(d)})
}

// fsGatePayload is an fs line's gate fields: the gate's decision, and completion_unsupported also for a held mutation
// refused as unsupported with no gate decision (ADR 0047 (3): its ends lie in different entries).
func fsGatePayload(d fsDecided) GateFields {
	if d.gate == nil {
		return GateFields{CompletionUnsupported: d.unsupported}
	}
	return gatePayload(d.gate, d.unsupported)
}

// unnamedFS reports whether an fs action has an end this loop could not name: its first path empty, a read
// that failed, a pathname read cut or joined over PATH_MAX (reader.unreadPath), or a rename's or a link's
// second end empty. decideMoveDest decides no destination it has no spelling for, so the source's verdict
// would stand for an action whose other end Landlock decides somewhere this loop cannot say (R5).
func unnamedFS(r *reader, op, p, p2 string) bool {
	return p == "" || r.failed || r.unreadPath != "" || ((op == record.FSRename || op == record.FSLink) && p2 == "")
}

// unreadMarker is the marker an unnamed end is recorded under when the reader noted none.
func unreadMarker(r *reader) string {
	if r.unreadPath != "" {
		return r.unreadPath
	}
	return ruleArgsUnreadable
}

// fsVerdict is the advisory verdict of one path (decide.AdvisoryFS): nearest entry wins (SEMANTICS §2), in
// the model of the run's tier (R15, R17).
//
// The path is matched against each entry's resolved and declared spellings (c.fsBoth): a relative path comes
// joined to the task's canonical cwd, and matched against the declared spellings alone it named no entry under
// a project reached through a symlink (R15b).
func (c *compiled) fsVerdict(p, op string, flags int, dir bool) (string, record.Verdict, record.Reason) {
	return c.fsVerdictIn(c.fsBoth, p, op, flags, dir)
}

// fsVerdictIn is fsVerdict against one ordered table: c.fsBoth for the spelling a target passed, c.fsResolved
// for where a walk found it lands (decideFS).
func (c *compiled) fsVerdictIn(rules *decide.AdvisoryList, p, op string, flags int, dir bool) (string, record.Verdict, record.Reason) {
	return decide.AdvisoryFS(c.ruleTable(), rules, p, op, flags, dir)
}

// ruleTable is the run's table, nil when the loop has none.
func (c *compiled) ruleTable() *agent.RuleTable {
	if c.pol == nil {
		return nil
	}
	return c.pol.Rules
}

// tier is the tier the run's table was selected for.
func (c *compiled) tier() backend.Tier {
	if c.pol == nil || c.pol.Rules == nil {
		return ""
	}
	return c.pol.Rules.Tier
}

// rootTier reports whether the table was compiled for a tier whose kernel side decides every open (tier cgroup's
// listener or plane, tier bpflsm's plane over the same backend): the lines this loop writes for an open the
// kernel refuses are the same at both.
func (c *compiled) rootTier() bool {
	t := c.tier()
	return t == backend.TierCgroup || t == backend.TierBPFLSM
}

// isRead reports whether an operation only reads (decide.IsRead): an open whose flags carry no write bit.
func isRead(op string, flags int) bool { return decide.IsRead(op, flags) }

// nearestFS returns the nearest declared entry that is p or an ancestor of it. The compiled list is
// ordered longest path first, so the first hit is the nearest one. Both spellings of each entry are
// matched, as fsVerdict matches them.
func (c *compiled) nearestFS(p string) *decide.AdvisoryRule { return decide.NearestIn(c.fsBoth, p) }

// reasonFor maps an fs operation to its refusal reason code (decide.OpReason).
func reasonFor(op string) record.Reason { return decide.OpReason(op) }
