// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A watch — inotify_add_watch(2), fanotify_mark(2) adding a mark, or fcntl(2)'s F_NOTIFY (dnotify) — opens nothing:
// the kernel asks only DAC's MAY_READ of the object (dnotify, on a descriptor already open, not even that) and
// security_path_notify, a hook neither Landlock nor the decision plane implements. So a watch on a deny_read
// directory succeeded at every tier and reported which of its files were opened, read, written and closed, and when,
// while every read of them was refused (GAPS A10). Every enforcing run's filter notifies all three (enforce-landlock
// R11e), and this loop refuses a watch whose object a read would be refused for (R36).

// The fanotify_mark(2) flag fields a watch is decided by (linux/fanotify.h): the command, one of add, remove and flush,
// and the mark's type, an inode's unless the mount or filesystem bit is set (FAN_MARK_MNTNS sets both).
const (
	fanMarkCommand = unix.FAN_MARK_ADD | unix.FAN_MARK_REMOVE | unix.FAN_MARK_FLUSH
	fanMarkWhole   = unix.FAN_MARK_MOUNT | unix.FAN_MARK_FILESYSTEM
)

// dnMultishot is dnotify's DN_MULTISHOT (linux/fcntl.h), which golang.org/x/sys/unix does not define: it keeps a watch
// after its first event and names no event itself, so a mask of it alone adds no watch.
const dnMultishot = 0x80000000

// ruleWatchWhole names a fanotify mark of a whole mount, filesystem or mount namespace, refused in every enforcing run
// wherever it is placed: such a mark reports every file it covers, so whatever path names it, it can report what the
// run withholds a read of on that mount (tego's own state at least, which every run withholds, agent-contract R6a),
// and no one entry is what it reaches. The reason is read-denied, as an inode watch's at or beneath a target is, whose
// rule is the target's entry. The errno is EPERM, the kernel's own answer to a caller without CAP_SYS_ADMIN, which
// every agent but a root one under setuid: true is: a program that probes for a privileged mark and falls back to
// inode marks sees what it sees with no run around it.
const ruleWatchWhole = "deny-read-watch"

// handleInotifyAddWatch decides an inotify_add_watch(fd, pathname, mask) (R36): the object the pathname names from the
// task's cwd, its final symlink followed unless the mask carries IN_DONT_FOLLOW. The mask is a register the kernel
// reads as it is here.
func handleInotifyAddWatch(l *Loop, n *notif) {
	l.decideWatch(n, "inotify_add_watch", atFDCWD, n.args[1], false, uint32(n.args[2])&unix.IN_DONT_FOLLOW != 0)
}

// handleFanotifyMark decides a fanotify_mark(fd, flags, mask, dirfd, pathname) (R36) on its flags, an unsigned int in a
// register that the kernel reads as it is here. An inode mark added is decided as an inotify watch is, on the object
// dirfd and pathname name (dirfd's own file when pathname is NULL), its final symlink followed unless
// FAN_MARK_DONT_FOLLOW says not to. A mount, filesystem or mount-namespace mark added is refused, EPERM, under
// ruleWatchWhole wherever it is placed. A removal and a flush add no mark and report nothing, and a call whose command
// is none of the three, or that names a negative descriptor with no pathname, fails in the kernel (EINVAL, EBADF): each
// is continued.
func handleFanotifyMark(l *Loop, n *notif) {
	flags := uint32(n.args[1])
	dirfd, addr := int32(n.args[3]), n.args[4]
	switch {
	case flags&fanMarkCommand != unix.FAN_MARK_ADD, addr == 0 && dirfd < 0:
		l.respond(n, respContinue())
	case flags&fanMarkWhole != 0:
		r := l.newReader(n)
		var target string
		if addr == 0 {
			target = r.heldFile(dirfd)
		} else {
			target = r.path(dirfd, addr)
		}
		if n.gone {
			return
		}
		l.refuseWatch(n, "fanotify_mark", target, ruleWatchWhole, record.ReasonReadDenied, unix.EPERM)
	default:
		l.decideWatch(n, "fanotify_mark", dirfd, addr, addr == 0, flags&unix.FAN_MARK_DONT_FOLLOW != 0)
	}
}

// handleDnotify decides a dnotify watch, fcntl(fd, F_NOTIFY, mask) (R36; handleFcntl dispatches it): a watch of the
// directory fd holds, decided on that descriptor's own file (its /proc link), as a fanotify mark of a descriptor is,
// and reported under op fcntl. dnotify needs a descriptor that reads, which a tier-1 ruleset gives the agent of a
// deny_read directory on the READ_DIR it inherits (SEMANTICS §1), and from it it reported every access, change,
// creation and rename inside the target. The kernel reads fd as an unsigned int and mask as one (fcntl_dirnotify): a
// mask with no event bit, 0 or DN_MULTISHOT alone, removes the descriptor's watches (dnotify_flush) and adds none, and
// a descriptor number past INT_MAX names none (EBADF); each is continued. A descriptor that is no directory is decided
// all the same, so one beneath a target is refused here before the kernel's ENOTDIR: whether it is one is a stat of a
// name this loop does not hold, and a failed stat may hide a directory.
func handleDnotify(l *Loop, n *notif) {
	fd := int32(n.args[0])
	if uint32(n.args[2])&^dnMultishot == 0 || fd < 0 {
		l.respond(n, respContinue())
		return
	}
	l.decideWatch(n, "fcntl", fd, 0, true, false)
}

// decideWatch answers a watch of the object dirfd and the pathname at addr name (byFD: dirfd's own file, from its /proc
// link), looked up as nofollow says: refused with R10's errno where this run withholds a read of that object
// (watchDenied), continued otherwise. The object is matched by the name its line gives it and, where that matches
// nothing, where the task's own lookup lands (matchEnds, as denyWrite matches an end), so a symlink, a /proc/self/fd
// link or a ".." that leads into a target is refused under the target's rule. As R15c's check it fails closed: a
// pathname that could not be read whole (reader.unreadPath), a descriptor whose link this process may not read
// (fd-unreadable: a non-dumpable task at tier 1), or a walk that failed other than as the task's own lookup fails
// (path-unreliable) is refused under that marker, since where the watch lands is unknown and may be a target.
//
// Best effort, as R15c is: after CONTINUE the kernel reads the pathname and resolves it again, so a sibling thread
// that rewrites the name, or a process that repoints a symlink or swaps the descriptor in between, places the watch
// where this loop did not decide. A watch of a directory that holds a target is not refused: it reports a target
// file's own activity, and a target directory's own entry, as a listing of that directory shows their names
// (SEMANTICS §1).
func (l *Loop) decideWatch(n *notif, op string, dirfd int32, addr uint64, byFD, nofollow bool) {
	r := l.newReader(n)
	var p, raw, unread string
	if byFD {
		var err error
		p, err = r.heldFileErr(dirfd)
		if err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.EBADF) {
			unread = ruleFDUnreadable // a descriptor the task does not hold is the kernel's EBADF, and names nothing
		}
	} else {
		p, raw = r.pathRaw(dirfd, addr)
		unread = r.unreadPath
	}
	if n.gone {
		return
	}
	e := fsEnd{p: p, q: pathQuery{tid: n.pid, dirfd: dirfd, path: raw, empty: byFD, joined: p}.as(followLookup(nofollow))}
	c := l.table.Load()
	var rule string
	reason := record.ReasonReadDenied
	_, ok, unwalked := l.matchEnds(n, []fsEnd{e}, func(_ int, at string) (agent.FSRule, bool) {
		denied, why, refused := l.watchDenied(c, at)
		if refused {
			rule, reason = denied, why
		}
		return agent.FSRule{}, refused
	})
	switch {
	case n.gone:
		return
	case ok:
	case unwalked:
		rule = rulePathUnreliable
	case unread != "":
		rule = unread
	default:
		l.respond(n, respContinue())
		return
	}
	name := l.lineName(n, e) // walked already (matchEnds): the line names what the decision did
	if n.gone {
		return
	}
	l.refuseWatch(n, op, name, rule, reason, refusalErrno)
}

// watchDenied reports the rule and reason under which this run withholds a read of the object at p, wherever a
// read-open of p is refused:
//
//   - the read verdict (fsVerdict): the nearest entry deciding a read is a deny_read the run's tier enforces (an
//     fs.ask_read entry's own included: a watch has no answer to wait for), an absent built-in row, or at tier cgroup a
//     name entry, whose climb refuses path-unresolved, rule unmatched, where it cannot decide, as the listener does;
//   - at tier bpflsm a name entry too, which the plane's name check refuses whatever the verdict says (ADR 0043 D7),
//     asked where the declared links lead, as fsVerdict asks it at tier cgroup;
//   - in a run that holds its reads, the held-read floor of heldReadFloors: a target nested in a write entry or a
//     deny_read name rule (decide.HeldReadIndex, ADR 0069 D3 (a) and (c)), and tego's own state (heldOwnState, (d));
//   - a live read or path block, or an Adjustable run's read fence entry not lifted (the live Set), as liveFS and
//     heldReadFloors refuse the reads they see. A block is asked of every watch this loop is notified of, also where
//     the run's direct reads never reach the Set (OPERATIONS "Live blocks"): it only tightens.
//
// A read only the deny_read snapshot refuses (snapshotRead) is not one: nothing there is a target. A read gate's score
// is not asked either: a gate scores actions, and a watch is none it scores. A directory is told by a stat of its final
// name, since a name entry or name rule covers files alone; a stat that fails reads as no directory, the stricter
// answer. A relative name (a cwd this loop could not read) matches no entry, and is never stat'ed from this process's
// own cwd.
func (l *Loop) watchDenied(c *compiled, p string) (string, record.Reason, bool) {
	if p == "" || p[0] != '/' {
		return "", "", false
	}
	dir, err := l.k.FinalIsDir(p)
	dir = dir && err == nil
	if rule, v, reason := c.fsVerdict(p, record.FSOpen, unix.O_RDONLY, dir); v == record.VerdictRefused {
		return rule, reason, true
	}
	if c.tier() == backend.TierBPFLSM && !dir && c.fsIx.HasNames() {
		if rule, reason, refused := c.fsIx.NameRefused(c.fsIx.Canonical(p), record.ReasonReadDenied); refused {
			return rule, reason, true
		}
	}
	if c.heldReads != nil {
		if rule, refused := c.heldReads.Refusal(c.fsResolved, p, dir); refused {
			return rule, record.ReasonReadDenied, true
		}
		if own := l.heldOwnState(c, p); own != "" {
			return "fs." + string(agent.FSDenyRead) + "[" + own + "]", record.ReasonReadDenied, true
		}
	}
	if e, ok := c.blocks().MatchPath(p, liveblock.AccessRead); ok {
		return e.Rule(), record.ReasonReadDenied, true
	}
	return "", "", false
}

// refuseWatch refuses a watch with errno and records it: a refused line, op the syscall, target the watched object's
// name, rule the entry or marker that refused it and reason the one a read of the object is refused with (read-denied;
// path-unresolved where a name entry's climb could not decide). errno is R10's for a watch of an object (the EACCES a
// read of it meets, and the kernel's own answer to a watch of a file its caller may not read) and EPERM for a
// whole-mount mark (ruleWatchWhole). Record v1 has no watch action kind, so the line is the refused kind's own, as the
// keyring's is (R32), and it is written under record: off too. An observe run's respond continues the call (R30):
// nothing was refused, so no line.
func (l *Loop) refuseWatch(n *notif, op, target, rule string, reason record.Reason, errno unix.Errno) {
	l.respond(n, respErrno(errno))
	if l.observing() {
		return
	}
	ev := l.event(n, record.KindRefused, record.SourceSupervisor)
	ev.Rule, ev.Reason = rule, reason
	l.emitFor(n, ev, record.RefusedPayload{Op: op, Target: target, Reason: reason, Rule: rule})
}
