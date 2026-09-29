// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"cmp"
	"errors"
	"path"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// taskView is what a relayed unix connect needs to be made as the task that trapped (R11): the
// credentials the kernel judges its connect by, and O_PATH descriptors of its root and cwd, so that a
// pathname resolves from the task's own directories and never from this process's. sameRoot says the
// task's root is this process's own, the one case in which an absolute symlink met while resolving a
// relative path lands where it would for the task.
type taskView struct {
	tid       int
	creds     sys.TaskCreds
	root, cwd int
	sameRoot  bool
}

// unixOutcome is what one relayed unix connect came to.
type unixOutcome int

const (
	// unixConnected: the resolved socket was admitted and the connect made on the duplicate; the error is
	// its real result (I3).
	unixConnected unixOutcome = iota
	// unixRefused: the socket the path resolves to is one the policy does not admit; nothing was
	// connected.
	unixRefused
	// unixUnresolved: resolving the path as the task failed, with the errno the task's own connect would
	// have met in the same lookup (ENOENT, EACCES, ENOTDIR); nothing was connected.
	unixUnresolved
	// unixOtherRoot: a relative path, from a task whose root is not this process's; nothing was connected.
	unixOtherRoot
	// unixUnreliable: the walk cannot be vouched for in this process's own view, which is the view every
	// policy path is written in; nothing was connected. Either it met ELOOP — a magic link, which
	// unixWalk refuses to follow because resolved here "self" would be this process, and which the
	// task's own lookup would have followed, or a symlink loop this loop cannot tell from one — or it ended
	// on procfs (errUnixProcfs), or the socket it reached is not the inode its path names here: the task's
	// mount tree is not this process's, and the path string the kernel reports for the inode says nothing
	// about where it lies in this view (sameInodeHere).
	unixUnreliable
	// unixNoCredentials: no thread could take the task's credentials; nothing was connected.
	unixNoCredentials
)

// errOtherRoot is unixWalk's answer for a relative path from a task with a root of its own.
var errOtherRoot = errors.New("supervisor: relative unix path from a task whose root is not this process's")

// errOtherView is connectUnixAs's answer for a socket whose path, looked up in this process's own view,
// names another inode or none (sameInodeHere).
var errOtherView = errors.New("supervisor: the socket's path names another inode in this process's view")

// TaskOf reads a task's credentials and opens its root and cwd O_PATH. The caller owns the descriptors
// once this returns without an error, and nothing is left open when it returns one.
func (k sysKernel) TaskOf(tid int) (taskView, error) {
	creds, err := sys.ReadTaskCreds(tid)
	if err != nil {
		return taskView{}, err
	}
	task, err := openTaskDirs(tid)
	if err != nil {
		return taskView{}, err
	}
	task.creds = creds
	return task, nil
}

// sameAsOwnRoot reports whether fd names this process's own root: the same mount and the same inode.
// Anything it cannot tell is "no", which only ever refuses a relative path (unixWalk).
func sameAsOwnRoot(fd int) bool {
	const mask = unix.STATX_INO | unix.STATX_MNT_ID
	var theirs, ours unix.Statx_t
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH, mask, &theirs) != nil || unix.Statx(unix.AT_FDCWD, "/", 0, mask, &ours) != nil {
		return false
	}
	if theirs.Mask&ours.Mask&mask != mask {
		return false
	}
	return theirs.Mnt_id == ours.Mnt_id && theirs.Ino == ours.Ino &&
		theirs.Dev_major == ours.Dev_major && theirs.Dev_minor == ours.Dev_minor
}

// ConnectUnixAs makes a relayed unix connect on fd the way the task would make it (R11). It runs on a
// thread holding the task's credentials (sys.RunAs), so the DAC checks of the path walk and of the socket
// inode are the task's, and a stream listener's SO_PEERCRED names the task's effective ids, not this
// process's — which at tier 2 is root. A pathname is resolved O_PATH on that same thread from the task's
// root or cwd (unixWalk, the one walk every unix name takes), admit is asked about the socket the path
// actually resolves to, and the connect names that inode through /proc/self/fd/<n>: a symlink the task
// controls cannot make the decision and the connect name two different sockets, and a rename after the
// decision moves the name, not the inode. admit is also handed that inode's identity, which R11a's implicit
// admit matches against the sockets the run bound. An abstract name has no filesystem half: admit is asked
// with "" and the connect uses the task's own bytes.
func (k sysKernel) ConnectUnixAs(fd int, task taskView, sa []byte, sunPath string, admit func(string, unixFile) bool) (unixOutcome, error) {
	out, err := unixConnected, error(nil)
	if cerr := sys.RunAs(task.creds, func() {
		out, err = unixAs(task, sa, sunPath, admit, func(to []byte) error { return connectRaw(fd, to) })
	}); cerr != nil {
		return unixNoCredentials, cerr
	}
	return out, err
}

// SendUnixAs is ConnectUnixAs for an addressed datagram the unix-only state relays (ADR 0070, relayUnix): the same
// thread with the task's credentials, the same walk and admit, and a sendto on fd to the inode admitted, through
// /proc/self/fd/<n> for a pathname and with the task's own bytes for an abstract name. The receiver reads the task's
// uid and gid in SCM_CREDENTIALS, and this process's pid, which no unprivileged sender can set to another's.
func (k sysKernel) SendUnixAs(fd int, task taskView, sa []byte, sunPath string, p []byte, flags int, admit func(string, unixFile) bool) (unixOutcome, int, error) {
	out, sent, err := unixConnected, 0, error(nil)
	if cerr := sys.RunAs(task.creds, func() {
		out, err = unixAs(task, sa, sunPath, admit, func(to []byte) error {
			var serr error
			sent, serr = k.SendToRaw(fd, p, flags, to)
			return serr
		})
	}); cerr != nil {
		return unixNoCredentials, 0, cerr
	}
	return out, sent, err
}

// SendToRawAs is SendToRaw on a thread holding the task's credentials (relayRouteQuery). Only the credentials are
// taken: the call resolves no name, so the task's root and cwd are not used.
func (k sysKernel) SendToRawAs(fd int, task taskView, p []byte, flags int, sa []byte) (int, error) {
	sent, err := 0, error(nil)
	if cerr := sys.RunAs(task.creds, func() { sent, err = k.SendToRaw(fd, p, flags, sa) }); cerr != nil {
		return 0, cerr
	}
	return sent, err
}

// unixAs is ConnectUnixAs and SendUnixAs on the thread that already holds the task's credentials: op connects or
// sends to the sockaddr it is handed, which names the inode admit admitted.
func unixAs(task taskView, sa []byte, sunPath string, admit func(string, unixFile) bool, op func(to []byte) error) (unixOutcome, error) {
	if sunPath == "" {
		if !admit("", unixFile{}) {
			return unixRefused, nil
		}
		return unixConnected, op(sa)
	}
	pfd, walked, err := unixWalk(task, unixQuery{tid: task.tid, path: sunPath})
	if err != nil {
		return unixWalkOutcome(err), err
	}
	defer unix.Close(pfd) //nolint:errcheck // an O_PATH descriptor this call opened
	if walked {
		// Only the walk a component at a time landed, where the task's own lookup may not (errWalkedOnly): refused,
		// since this connect would be made to what it reached.
		return unixUnreliable, errWalkedOnly
	}
	// Unlinked since the walk, or an inode the kernel names with no path at all ("socket:[N]" and the like): no
	// lookup the task makes reaches it any more, so ENOENT is the answer its own connect would get (unixPlaceOf). A
	// "/"-prefixed name is no proof of the opposite: d_path builds one for an inode on a mount this process's tree
	// does not hold too, from that mount's own tree, which is what sameInodeHere is for.
	place, err := unixPlaceOf(pfd)
	if err != nil {
		return unixWalkOutcome(err), err
	}
	if !admit(place.at, place.file) {
		return unixRefused, nil
	}
	return unixConnected, op(unixSockaddr("/proc/self/fd/" + strconv.Itoa(pfd)))
}

// unixWalkOutcome is what a relayed connect whose walk failed came to: a relative name from a task with a root of
// its own (errOtherRoot), a walk the loop cannot vouch for in its own view (a magic link or a symlink loop, ELOOP; a
// place on procfs or in another mount tree, errOtherView), and otherwise the errno the task's own lookup met
// (ENOENT, EACCES, ENOTDIR), which is its connect's answer.
func unixWalkOutcome(err error) unixOutcome {
	switch {
	case errors.Is(err, errOtherRoot):
		return unixOtherRoot
	case errors.Is(err, unix.ELOOP), errors.Is(err, errOtherView):
		return unixUnreliable
	}
	return unixUnresolved
}

// sameInodeHere reports whether p, looked up in this process's own view, is the inode st describes. The
// policy's paths are this process's view (the launcher compiled them here), and decideResolved matches the
// path readlink reports for the inode the task's walk reached. That path is the inode's place in this view
// only when the task's mount tree is this process's: from a task in another mount namespace — a container,
// or a bind mount it made in one of its own — d_path builds the string from the task's mounts, and the same
// string here can name another file, under a write entry, while the inode lies anywhere. So the path is
// walked again here, following no symlink (the reported path has none where it is this view's), and the
// decision is made on it only when it reaches the same device and inode. The walk runs on the thread that
// holds the task's credentials, so a directory the task cannot search refuses too: fail closed.
func sameInodeHere(p string, st *unix.Stat_t) bool {
	_, same := fileHere(p, st)
	return same
}

// fileHere is sameInodeHere returning the file it reached as R11a matches it, with the id of the mount it lies on in
// this view (unixFile): a relayed unix connect's socket file.
func fileHere(p string, st *unix.Stat_t) (unixFile, bool) {
	how := unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_NO_SYMLINKS}
	var fd int
	var err error
	for tries := 0; ; tries++ {
		fd, err = unix.Openat2(unix.AT_FDCWD, p, &how)
		if (err == unix.EAGAIN && tries < 8) || err == unix.EINTR {
			continue
		}
		break
	}
	if err != nil {
		return unixFile{}, false
	}
	defer unix.Close(fd) //nolint:errcheck // an O_PATH descriptor this call opened
	var here unix.Statx_t
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH, unixFileMask, &here) != nil {
		return unixFile{}, false
	}
	f := unixFileOf(&here)
	return f, f.dev == st.Dev && f.ino == st.Ino
}

// readlinkRaw is readlink(2) returning the bare errno, which is what a relayed result carries (respResult).
func readlinkRaw(name string) (string, error) {
	buf := make([]byte, pathMax)
	n, err := unix.Readlink(name, buf)
	if err != nil {
		return "", err
	}
	if n >= len(buf) {
		return "", unix.ENAMETOOLONG
	}
	return string(buf[:n]), nil
}

// unixSockaddr is a sockaddr_un naming p, NUL-terminated.
func unixSockaddr(p string) []byte {
	sa := make([]byte, sunPathOff+len(p)+1)
	sa[0], sa[1] = byte(unix.AF_UNIX), byte(unix.AF_UNIX>>8)
	copy(sa[sunPathOff:], p)
	return sa
}

// closeTask releases a taskView's descriptors.
func (l *Loop) closeTask(v taskView) {
	l.closeDup(v.root)
	l.closeDup(v.cwd)
}

// unixDecision is what a relayed unix connect's admit decided, handed from the relay goroutine to the
// handler.
type unixDecision struct {
	dec verdictOf
}

// relayUnix performs an admitted unix connect (R9, R11). decideUnix admitted the name the target passed;
// the relay then resolves that name as the task, admits the socket it resolves to against the same
// entries (decideResolved) — through the implicit write-entry admit only when a process of the run bound that
// socket (R11a, boundByRun) — and connects to that inode, all on a thread holding the task's credentials
// (ConnectUnixAs). The handler owns the taskView until the relay starts, and the relay goroutine owns it
// from then on, like the duplicate.
//
// approved is the net.ask unix: scope a person approved the connect under (askUnix), nil for every other connect: a
// pathname the approval admits only at the scope's place, the path it resolved to when the loop was built, and decided
// there as any connect is when the agent repointed its name elsewhere during the wait (R11c); an abstract name, which
// has no filesystem half, on the approval alone.
func (l *Loop) relayUnix(n *notif, c *compiled, t *target, d dest, raw []byte, approved *unixRule) {
	l.relayUnixAs(n, c, t, d, raw, approved, nil)
}

// relayUnixDatagram performs an addressed unix datagram the unix-only state admitted (ADR 0070, relayUnixOnly) as
// relayUnix performs a connect: resolved as the task, the socket it reaches admitted, and the datagram sent to that
// inode on the duplicate (SendUnixAs), so neither a sibling's rewrite of the address nor a descriptor swapped in after
// the duplicate reaches a host socket. An address or payload the kernel fails before any lookup gets that answer, and
// nothing is sent (I3).
func (l *Loop) relayUnixDatagram(n *notif, c *compiled, t *target, d dest, raw []byte, args sendArgs) {
	if err := cmp.Or(args.addrErr, args.sendErr); err != nil {
		l.respond(n, respResult(0, err))
		l.emitNet(n, c, d, t.proto, t.dec, netVerdict(d, t.dec), netMarks{})
		return
	}
	l.relayUnixAs(n, c, t, d, raw, nil, &args)
}

// relayUnixAs is relayUnix's body, a connect when send is nil and the datagram send carries otherwise.
func (l *Loop) relayUnixAs(n *notif, c *compiled, t *target, d dest, raw []byte, approved *unixRule, send *sendArgs) {
	if !l.valid(n) {
		return
	}
	task, err := l.k.TaskOf(n.pid)
	// R2: /proc/<tid> is keyed by a tid the target may have given up, so what was read is trusted only
	// if the notification is still live after it.
	if !l.valid(n) {
		if err == nil {
			l.closeTask(task)
		}
		return
	}
	if err != nil {
		l.log.Debug("supervisor: the task's credentials or directories could not be read", "tid", n.pid, "err", err)
		l.refuseNet(n, d, t.proto, refuse(ruleRelayCredentials))
		return
	}
	decided := make(chan unixDecision, 1)
	outcome := make(chan unixOutcome, 1)
	named := t.dec
	res, out := l.relay(n, t, func(dup int) resp {
		defer l.closeTask(task)
		admit := func(resolved string, file unixFile) bool {
			dec := named
			// An abstract name ("") has no filesystem half: the name's decision, a declared entry's or a person's, is
			// the whole of it (unixAdmit keeps named). A pathname a person approved is admitted at the scope's place
			// only; anywhere else the approval says nothing, and the socket reached is decided as any connect's is.
			if approved == nil || resolved != approved.resolved {
				dec = c.unixAdmit(named, resolved, file, func(f unixFile, dec verdictOf) verdictOf {
					return l.boundByRun(n, f, dec, needConnect(t.sockType))
				})
			}
			if c.hostSockets {
				dec = hostSocketsRule(dec) // the unix-only state names a socket no process of the run bound (ADR 0070)
			}
			// A live block names the socket where this walk landed too, whatever name reached it (liveUnixLanded).
			dec = c.liveUnixLanded(dec, resolved)
			if resolved != "" {
				dec.sockPath = resolved // the name the task's walk reached, which the refused line's what is read from
			}
			decided <- unixDecision{dec: dec}
			return dec.allowed
		}
		var o unixOutcome
		var sent int
		var err error
		if send != nil {
			o, sent, err = l.k.SendUnixAs(dup, task, raw, d.unixPath, send.payload, send.flags, admit)
		} else {
			o, err = l.k.ConnectUnixAs(dup, task, raw, d.unixPath, admit)
		}
		outcome <- o
		switch o {
		case unixConnected, unixUnresolved:
			return respResult(sent, err) // the kernel's own answer to the task: I3
		case unixNoCredentials:
			l.log.Warn("supervisor: no thread could take the task's credentials", "tid", n.pid, "err", err)
		}
		return respErrno(refusalErrno)
	})
	switch out {
	case relayDone:
		var ud unixDecision
		select {
		case ud = <-decided:
		default:
		}
		l.finishUnix(n, c, d, t, <-outcome, ud, res)
	case relayOrphaned:
		// E35. The goroutine may still be resolving or connecting, so only a decision it has already
		// published is read. A refusal it published performed nothing: no line. Before any decision the
		// name's own is the best there is.
		select {
		case ud := <-decided:
			if ud.dec.allowed {
				l.emitNet(n, c, d, t.proto, ud.dec, netVerdict(d, ud.dec), netMarks{resultUnknown: true})
			}
		default:
			l.emitNet(n, c, d, t.proto, t.dec, netVerdict(d, t.dec), netMarks{resultUnknown: true})
		}
	case relayLimited:
		l.closeTask(task)
		l.refuseNet(n, d, t.proto, refuse(ruleRelayLimit))
	}
	// relayCancelled: nothing is answered or recorded (handleConnect says why), and the relay goroutine
	// closes the taskView itself once the kernel returns.
}

// finishUnix answers and records a relayed unix connect whose relay returned, with its line's verdict
// (unixConnectLine).
func (l *Loop) finishUnix(n *notif, c *compiled, d dest, t *target, o unixOutcome, ud unixDecision, res resp) {
	line := unixConnectLine(o, t.dec, ud.dec)
	switch o {
	case unixConnected, unixUnresolved:
		l.respond(n, res)
		v := netVerdict(d, line)
		if o == unixConnected {
			v = l.grantedUnixVerdict(d, line, res) // an approved abstract name's connect the kernel's grant no longer covered
		}
		l.emitNet(n, c, d, t.proto, line, v, l.answeredMarks(n))
	default:
		l.refuseNet(n, d, t.proto, line)
	}
}

// unixConnectLine is the verdict of a relayed unix connect's line, for outcome o of a connect whose name was admitted
// as named and whose admit decided decided (unixAdmit). A connect made, or refused on what it reached, carries
// that decision. One whose lookup failed as the task's own would have connected nothing, and that errno is the answer:
// the name was admitted, so the line is the name's, like a relayed ECONNREFUSED (§7). A walk the loop cannot vouch for
// in its own view, or a relative name from another root, is refused path-unreliable, and a connect no thread could make
// with the task's credentials relay-credentials.
func unixConnectLine(o unixOutcome, named, decided verdictOf) verdictOf {
	switch o {
	case unixConnected, unixRefused:
		return decided
	case unixUnresolved:
		return named
	case unixOtherRoot, unixUnreliable:
		return refuse(rulePathUnreliable)
	}
	return refuse(ruleRelayCredentials)
}

// unixAdmit is a relayed connect's decision on the socket its name resolved to (R11, R11a): matched as decideResolved
// matches it, and through a write entry only when bound says the run bound that very socket (boundByRun), which a
// directory or a file that is no socket never is. An abstract name, which resolves to no path, keeps the name's
// decision, named.
func (c *compiled) unixAdmit(named verdictOf, resolved string, file unixFile, bound func(unixFile, verdictOf) verdictOf) verdictOf {
	if resolved == "" {
		return named
	}
	dec, implicit := c.decideResolved(resolved)
	if implicit {
		dec = bound(file, dec)
	}
	return dec
}

// grantedUnixVerdict is the verdict of a relayed unix connect's line once its result is known. An approved abstract
// name at a root tier is connected with the task's own bytes, which the run's kernel admits only on the one-connect
// grant askUnix made (GrantUnix, a second at most): connect_unix refuses one it no longer covers EPERM and the plane's
// socket_connect EACCES. Neither leaves a breadcrumb this loop can read for a unix name, and another LSM answers the
// same errnos, so such a result is observed, as kernelDecided calls an EPERM no breadcrumb names, never the person's
// allow of a connect that did not happen. Every other result is the connect's own (I3) and keeps the decision's verdict.
func (l *Loop) grantedUnixVerdict(d dest, dec verdictOf, res resp) record.Verdict {
	v := netVerdict(d, dec)
	if v == record.VerdictAllow && dec.human && len(d.abstract) > 0 && l.grantUnix != nil &&
		(res.errno == -int32(unix.EPERM) || res.errno == -int32(unix.EACCES)) {
		return record.VerdictObserved
	}
	return v
}

// decideResolved matches the socket a pathname resolved to (R11, SEMANTICS §5: "matched on the resolved
// socket"): a declared entry by the path it resolved to when the loop was built, and the implicit admit by
// the nearest filesystem entry above the socket's own path, each entry taken at its resolved path
// (agent.FSRule.Resolved). A socket that neither names is unmatched, whatever the path the target passed
// looked like. A net.ask unix: scope's place is refused unix-ask-scope before the write entry around it is asked:
// reached here, no person was asked about it (a datagram, or a name the agent repointed at it after the loop's walk;
// R11c). implicit says the admit is the write entry's, which holds only for a socket the run bound (R11a): the caller
// asks boundByRun.
func (c *compiled) decideResolved(resolved string) (dec verdictOf, implicit bool) {
	for _, u := range c.unix {
		if u.path != "" && u.resolved == resolved {
			return verdictOf{rule: u.name, allowed: true}, false
		}
	}
	if c.unixAskAt(resolved) != nil {
		return refuse(ruleUnixAskScope), false
	}
	if fr := nearestIn(c.fsResolved, resolved); fr != nil && fr.Write {
		return verdictOf{rule: fr.Name, allowed: true}, true
	}
	return refuse(ruleUnmatched), false
}

// resolveDeclared is a declared exec entry's path with every symlink followed: the whole path when it exists, else
// its resolved parent plus the declared last component (agent.FSRule.Resolved's rule for an entry that does not exist
// yet), else the path as declared. Unix entries and scopes are placed one name at a time (resolveUnixDeclared).
func resolveDeclared(k kernel, p string) string {
	if r, err := k.EvalSymlinks(p); err == nil {
		return r
	}
	if r, err := k.EvalSymlinks(path.Dir(p)); err == nil {
		return path.Join(r, path.Base(p))
	}
	return p
}

// resolveUnixDeclared is a unix path's place in this process's view (R11, R11c): agent.ResolveUnixPlace, compile's
// own resolution of NetRule.UnixResolved, its symlinks read with the kernel's PlaceLink — the path walked one name at
// a time from the root, each symlink followed whether or not its target exists yet, a ".." applied after the symlink
// before it, the names below the deepest existing one kept. A scope spelled through a symlink — a project under a
// symlinked home, /var/run — is so the canonical place the kernel's lookup lands at however many of its directories
// are missing, the place the loop's walk of a connect's name (unixScopeOf) and the relay's (decideResolved) are
// compared with. ok is false, and the place p, when it cannot be placed (ResolveUnixPlace): a relative path, a link
// loop, more names than ResolveUnixPlace takes, a directory the walk kept that an agent's thread made a symlink
// meanwhile. Each call is at most that many reads, each through directories with no symlink (agent.ReadPlaceLink), so
// placing a connect's name the agent made costs a bounded time on the notification path, however the agent races it.
func resolveUnixDeclared(k kernel, p string) (string, bool) {
	return agent.ResolveUnixPlace(p, k.PlaceLink)
}
