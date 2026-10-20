// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/internal/runtime/deputy"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A held open (ADR 0041 Stage B, D2-D5) is an open of a gate kind whose rules can score to allow or above (MayEscalate;
// openMayEscalate sums both fs kinds for a read-write open), completed race-free in the run's own kernel context and
// never answered CONTINUE: the open deputy, a process of the run, pins what the task's lookup reaches; this loop checks
// and scores the pinned object; the deputy opens it with the task's flags; and the descriptor, verified to be the
// pinned inode, is delivered with ADDFD|SEND. A sibling that rewrites the pathname after this loop copied it changes
// nothing: the kernel never reads it again.

// openDeputy is the deputy's client as this loop uses it (deputy.Client); tests fake it.
type openDeputy interface {
	Pin(q deputy.PinQuery, wait func() bool) (deputy.Pinned, error)
	PinOpenStart(q deputy.PinQuery, flags int) (*deputy.Pending, error)
	Open(pin int, leaf string, flags int, mode uint32, umask int, wait func() bool) (int, error)
	Outstanding() int64
}

// heldKernel delivers a held open's descriptor: ADDFD|SEND with the agent's O_CLOEXEC (sysKernel).
type heldKernel interface {
	DeliverHeld(id uint64, fd int, flags int) (int, error)
}

// DeliverHeld is heldKernel's: the deputy opened the file with the agent's own flags, O_NONBLOCK included, so the
// descriptor goes as it is.
func (k sysKernel) DeliverHeld(id uint64, fd int, flags int) (int, error) {
	return k.addFDSend(id, fd, flags)
}

// taskIdentityKernel reads what a person's alternate for a held open is reopened as (heldAsk, ADR 0057): the task's
// credentials and umask, as PrepareAskOpen reads them for a hold of this loop's own pin (sysKernel).
type taskIdentityKernel interface {
	TaskIdentity(tid int) (sys.TaskCreds, int, error)
}

// TaskIdentity is taskIdentityKernel's, from /proc/<tid>/status.
func (k sysKernel) TaskIdentity(tid int) (sys.TaskCreds, int, error) {
	creds, err := sys.ReadTaskCreds(tid)
	if err != nil {
		return sys.TaskCreds{}, 0, err
	}
	mask, err := taskUmask(tid)
	if err != nil {
		return sys.TaskCreds{}, 0, err
	}
	return creds, mask, nil
}

// Rule markers of a held open this loop refuses without the kernel's word: the open is outside what the deputy can
// complete as the kernel would (D4's held-unsupported), the deputy cannot answer (held-unavailable), or the
// outstanding held opens are at their ceiling (held-limit). Each is reason fs-gate, authority gate: the gate's
// completion could not be made, and it is never continued instead.
const (
	ruleHeldUnsupported = "held-unsupported"
	ruleHeldUnavailable = "held-unavailable"
	ruleHeldLimit       = "held-limit"
)

// procReads counts this loop's reads of a task's /proc files (status, stat): the cost the Stage B budget holds at zero
// per non-O_CREAT held open (ADR 0041 §Performance), which BenchmarkHeldOpen reads.
var procReads atomic.Int64

// gateFactsHeld is GateFields.GateFacts of a decision taken on the pinned object (D5, record minor 10): the score is
// the larger of the copied name's and the held object's, and the descriptor delivered is that object.
const gateFactsHeld = "held_object"

// heldPlan is one held open as it goes through D3.
type heldPlan struct {
	n     *notif
	r     *reader
	q     pathQuery
	flags int
	d     fsDecided
	// pin is the deputy's descriptor (-1 until pinned), leaf the missing final component of a create beneath it.
	pin  int
	leaf string
	st   unix.Stat_t
	// resolved is where the pinned object lies in this process's view, "" for a nameless one (a pipe, a socket, an
	// anonymous inode, an unlinked file): no name a predicate could match.
	resolved string
	// human is set once a person approved the open (the ask range): its lines carry authority human.
	human bool
	// opened is the deputy's open made with the pin (a read-only open of a regular file or a directory, deputy
	// opPinOpen), -1 when none was; openErr is that open's errno when it failed. It is delivered only once every check
	// of the pin has passed.
	opened  int
	openErr error
	// pending is a read-only open's pin request, sent before the copied name was checked (heldOpen).
	pending *deputy.Pending
	// repinned is set once D4's one re-pin was made (mayRepin).
	repinned bool
}

// heldOpen is D3 for an open whose gate kind escalates under gate.completion: held, or for a read-capable open of a
// run that holds its reads (ADR 0069), when a deputy serves this run, and reports whether it answered the
// notification: false leaves the open to the copied-fact path (D cells), which it is only for an open neither holds,
// a run with no deputy, or a refusal this loop already made on the copied name (d.enforce), which settleFS answers.
func (l *Loop) heldOpen(n *notif, r *reader, q pathQuery, flags int, d fsDecided) bool {
	c := l.table.Load()
	rt := c.pol.Rules
	if l.deputy == nil || rt == nil || d.enforce {
		return false
	}
	// The kinds the gate scores the open with decide whether the gate holds it: a read-write open by the read
	// predicates too (openMayEscalate, scoreOpen). Held reads hold every read-capable open.
	if !gateHolds(rt.Gate, flags) && !l.readHeld(c, flags) {
		return false
	}
	// An O_PATH open reads nothing, and ADDFD cannot deliver its descriptor (the kernel's fget ignores O_PATH files):
	// it stays on the copied name, a refused name refused and any other continued, a disclosed cell of its own
	// (gate.fs.read/o_path). Every access to contents through such a descriptor is another open, notified and held.
	if flags&unix.O_PATH != 0 {
		return false
	}
	h := &heldPlan{n: n, r: r, q: q, flags: flags, d: d, pin: -1, opened: -1}
	defer func() {
		if h.pin >= 0 {
			l.closeDup(h.pin)
		}
		if h.opened >= 0 {
			l.closeDup(h.opened)
		}
	}()
	// The copy itself (D4's last rows): a pathname the kernel could not read either is answered as the kernel
	// answers it, EFAULT for one that faulted, ENAMETOOLONG for one with no NUL within PATH_MAX and ENOENT for an empty
	// one (getname's answers), then EBADF for a relative one whose directory descriptor the task does not hold
	// (path_init's): each answer is the kernel's whatever the name, and none needs a fact the gate scores, which is
	// why it precedes the copied name's score (an empty name or a missing descriptor leaves the gate none, and was
	// refused unreadable). One this process could not read for its own reasons is no fact at all: the gate refuses it
	// unreadable. Before all of them, flags the kernel refuses before it reads the pathname are its EINVAL
	// (openFlagsInvalid).
	switch {
	case n.gone:
		return true
	case openFlagsInvalid(flags):
		l.heldAnswer(h, unix.EINVAL)
		return true
	case r.fault:
		l.heldAnswer(h, unix.EFAULT)
		return true
	case r.unreadPath == rulePathTruncated && q.path != "":
		l.heldAnswer(h, unix.ENAMETOOLONG)
		return true
	case q.path == "" && !q.empty && r.ok() && r.unreadPath == "":
		l.heldAnswer(h, unix.ENOENT)
		return true
	case r.noDirfd && q.path != "" && !strings.HasPrefix(q.path, "/"):
		l.heldAnswer(h, unix.EBADF)
		return true
	}
	// A read-only open's pin and open are asked for now, so the deputy walks while the copied name is checked below;
	// a refusal there drops the reply unseen (its open, of a regular file or a directory, had no effect but atime).
	// Only at tier landlock: at a root tier the fanotify listener writes the line of an open it refuses, and an
	// open made before this loop's checks would give a refused action two lines (R7a), so the open waits for them.
	if readOnlyOpen(flags) && q.path != "" && !c.rootTier() {
		p, err := l.deputy.PinOpenStart(heldPinQuery(n, l.tgidOfNotif(n), q, flags), flags)
		if err == nil {
			h.pending = p
			defer func() {
				if h.pending != nil {
					h.pending.Abandon()
				}
			}()
		}
	}
	// D3 step 1: the copied name. A refusal on it is final; the syscall never runs.
	end := fsEnd{p: q.joined, q: q}
	copied := c.gateFS(record.FSOpen, l.landed(n, end), "", flags, d, r.ok() && r.unreadPath == "" && !l.gateFactsIncomplete(n, record.FSOpen, end, fsEnd{}, flags))
	if copied.gate != nil && copied.gate.Verdict == gate.Refused {
		l.heldRefuse(h, copied.rule, record.ReasonFSGate, copied.gate)
		return true
	}
	h.d.gate = copied.gate
	if l.deputy.Outstanding() >= l.relayCeiling() {
		l.metrics.relayLimited.Add(1)
		l.heldRefuse(h, ruleHeldLimit, record.ReasonFSGate, h.d.gate)
		return true
	}
	// A re-pin (D4, below) starts again from the copied path's decision and the task's own flags.
	base, flags0 := h.d, h.flags
	for {
		// D3 step 2: the deputy's pin.
		ok, repin := l.pinHeld(h)
		if repin {
			h.repin(l, base, flags0)
			continue
		}
		if !ok {
			return true
		}
		// D4: what was pinned decides, never the copied name.
		if !l.heldClass(h) {
			return true
		}
		// D3 step 3: the floors on the pinned object.
		if !l.heldFloors(h, c) {
			return true
		}
		// D3 step 4: the gate on the pinned object, scored as the agent's own open of it is (scoreOpen: a read-write
		// open by the read predicates too); the larger of the two scores.
		// An open the gate does not score (one held only as a read, ADR 0069) has no gate decision.
		g := h.d.gate
		if openGated(rt.Gate, h.flags) && (h.resolved != "" || g == nil) {
			held := scoreOpen(rt.Gate, gate.Allow, h.resolved, h.flags, rt.Workdir)
			if g == nil || held.Verdict > g.Verdict || held.Score > g.Score {
				g = &held
			}
		}
		h.d.gate = g
		if g != nil {
			switch g.Verdict {
			case gate.Refused:
				l.heldRefuse(h, g.Rule, record.ReasonFSGate, g)
				return true
			case gate.Ask:
				l.heldAsk(h, g)
				return true
			}
		}
		// D3 steps 5 and 6: the deputy opens in the run; the descriptor must be the pinned inode.
		if !l.openHeld(h) {
			return true
		}
		// D4's one re-pin: the create's leaf appeared after the pin, so the open met what the task's own open would
		// meet now. It is pinned, checked and scored once more, and its next answer stands (mayRepin).
		h.repin(l, base, flags0)
	}
}

// repin readies h for D4's one re-pin: the pin and any open made with it are closed, and the plan starts again from
// the copied path's decision base and the task's own flags. The re-pin is made once (repinned), whichever reason
// asked for it, so a sibling that keeps changing what the name names cannot hold a worker.
func (h *heldPlan) repin(l *Loop, base fsDecided, flags int) {
	if h.pin >= 0 {
		l.closeDup(h.pin)
	}
	if h.opened >= 0 {
		l.closeDup(h.opened) // a read-only open made with the pin: no effect but atime, never delivered
	}
	h.pin, h.leaf, h.st, h.resolved, h.d, h.flags, h.repinned = -1, "", unix.Stat_t{}, "", base, flags, true
	h.opened, h.openErr = -1, nil
}

// tmpfileBit is __O_TMPFILE, O_TMPFILE without the O_DIRECTORY it carries.
const tmpfileBit = unix.O_TMPFILE &^ unix.O_DIRECTORY

// openFlagsInvalid reports whether the kernel refuses open flags with EINVAL before it reads the pathname
// (build_open_flags): O_CREAT with O_DIRECTORY (Linux 6.4 on), O_TMPFILE with O_CREAT or without write access. A held
// open whose walk fails would otherwise answer the walk's errno where the task's own open gets EINVAL (review finding
// F4's family). The kernel itself is asked, with an empty pathname, which it refuses ENOENT once the flags pass, so the
// answer is the running kernel's whatever its version; only flags that carry O_CREAT or __O_TMPFILE are asked about,
// the only ones open(2) and openat(2) can refuse so.
func openFlagsInvalid(flags int) bool {
	if flags&(unix.O_CREAT|tmpfileBit) == 0 {
		return false
	}
	fd, err := unix.Openat(unix.AT_FDCWD, "", flags|unix.O_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(fd)
	}
	return errors.Is(err, unix.EINVAL)
}

// heldCopiedRefusal is D3 step 1 for an open a person's scope holds under held completion (askOpen, askReadOpen): the
// gate's score of the copied name where this loop's walk of it landed, taken as heldOpen takes it. Its refusal is
// final, so the name the hold pins cannot pick a lower score than the one this loop decided on: the
// refusal is returned, for the caller to refuse with. nil when no deputy serves the run (the copied completion's
// holds score the pinned name, as before Stage B) or the copied name is not refused.
func (l *Loop) heldCopiedRefusal(n *notif, r *reader, q pathQuery, flags int) *gate.Decision {
	if l.deputy == nil {
		return nil
	}
	c := l.table.Load()
	end := fsEnd{p: q.joined, q: q}
	d := c.gateFS(record.FSOpen, l.landed(n, end), "", flags, fsDecided{}, r.ok() && r.unreadPath == "" && !l.gateFactsIncomplete(n, record.FSOpen, end, fsEnd{}, flags))
	if d.gate == nil || d.gate.Verdict != gate.Refused {
		return nil
	}
	return d.gate
}

// heldDirect reports whether an open goes to heldOpen without this loop's own walk of its name: a deputy serves the
// run, the gate holds the open or the run holds its reads and the open can read (ADR 0069), it is no O_PATH open, and
// the table has no fs.ask or fs.ask_read entry, whose holds decide on the walked verdict first (recordOpen).
func (l *Loop) heldDirect(flags int) bool {
	if l.deputy == nil || flags&unix.O_PATH != 0 {
		return false
	}
	c := l.table.Load()
	rt := c.pol.Rules
	if rt == nil || len(rt.FSAsk) != 0 || len(c.askRead) != 0 {
		return false
	}
	for i := range rt.FS {
		if rt.FS[i].Kind == agent.FSAsk {
			return false
		}
	}
	return gateHolds(rt.Gate, flags) || l.readHeld(c, flags)
}

// heldSpelling is a held open's verdict on its copied name as spelled, and R15c's refusal of a write whose spelling
// names a deny_write target, or which could not be read whole while there are targets (denyWrite's own rules on
// the spelling); heldFloors asks the same of where the pin lands. A spelling the walk names (walkNamed) never comes
// here (recordOpen): its spelling is the line's name only once walked.
func (l *Loop) heldSpelling(r *reader, p string, flags int) fsDecided {
	c := l.table.Load()
	rule, v, reason := c.fsVerdict(p, record.FSOpen, flags, false)
	d := fsDecided{rule: rule, verdict: v, reason: reason}
	rt := c.pol.Rules
	if isRead(record.FSOpen, flags) || len(rt.DenyWrite) == 0 {
		return d
	}
	if t, ok := c.denyWriteOpen(p, flags); ok {
		return fsDecided{rule: t.RuleName(), verdict: record.VerdictRefused, reason: reasonFor(record.FSOpen), enforce: true}
	}
	if r.unreadPath != "" {
		return fsDecided{rule: r.unreadPath, verdict: record.VerdictRefused, reason: reasonFor(record.FSOpen), enforce: true}
	}
	return d
}

// pinHeld asks the deputy to walk h's pathname as the task's lookup walks it and keeps the pin, and reports whether
// it did (ok) or asks for D4's one re-pin (repin); neither is an answer made. A walk's errno is the task's answer (D4:
// lookup failures are the walk's own errno, never CONTINUE and never a blanket EACCES); a deputy that cannot answer
// refuses held-unavailable.
func (l *Loop) pinHeld(h *heldPlan) (ok, repin bool) {
	n, flags := h.n, h.flags
	pq := heldPinQuery(n, l.tgidOfNotif(n), h.q, flags)
	if pq.Path == "" && !pq.Empty {
		l.heldAnswer(h, unix.ENOENT) // an empty pathname without AT_EMPTY_PATH (and none was read: args-unreadable)
		return false, false
	}
	// The ID_VALID after the pin (R2) says the tid the deputy walked from was still the task that trapped; the reader's
	// own bracket covers the one before it. A read-only open is pinned and opened in one exchange: its open has no effect but atime, and is delivered only
	// once the checks below pass (deputy opPinOpen). Any other open waits for them.
	var p deputy.Pinned
	var opened int
	var openErr, err error
	if h.pending != nil {
		p, opened, openErr, err = h.pending.Finish(l.heldWait(n))
		h.pending = nil
	} else {
		p, err = l.deputy.Pin(pq, l.heldWait(n))
		opened = -1
	}
	pin, leaf := p.FD, p.Leaf
	if opened >= 0 {
		h.opened = opened
	}
	h.openErr = openErr
	// The ID_VALID after the pin (R2): the deputy may have read /proc/<tid> (a relative name's cwd or dirfd, a magic
	// link), and only a live notification says that tid was still the task that trapped. A read-only open was made
	// already and has no effect; it is delivered only by ADDFD|SEND, which fails on a notification that is gone, so it
	// needs none. Every other open follows the checks, and is never made for a task that may not be this one.
	if !readOnlyOpen(flags) && !l.valid(n) {
		if pin >= 0 {
			l.closeDup(pin)
		}
		return false, false
	}
	if errors.Is(err, deputy.ErrAbandoned) || n.gone {
		// The task left while the deputy's lookup was late (the wait found its notification gone): nothing to answer,
		// no line, and no failure of the deputy's to count. A pin has no effect, and a read-only open made with it none
		// but atime (h.opened, closed by heldOpen); a late reply's descriptors are closed when it comes (deputy.Client's
		// drain).
		if pin >= 0 {
			l.closeDup(pin)
		}
		return false, false
	}
	if err != nil {
		var errno unix.Errno
		if errors.As(err, &errno) && errno != 0 {
			l.heldAnswer(h, errno)
			return false, false
		}
		l.heldUnavailable(h, err)
		return false, false
	}
	h.pin, h.leaf = pin, leaf
	if err := unix.Fstat(pin, &h.st); err != nil {
		l.heldUnavailable(h, err)
		return false, false
	}
	resolved, err := pinnedPath(pin, &h.st, leaf, p.ByDescriptor)
	// A regular file whose name was removed is nameless to every verdict, and has no name a read gate can read: an open
	// that reads it is refused unreadable when the read gate scores it, as the copied path refuses it
	// (gateFactsIncomplete).
	unreadable := errors.Is(err, errUnlinkedFile) && (!isWriteOpen(flags) || openReads(flags)) &&
		l.table.Load().pol.Rules.Gate.Has(gate.FSRead)
	switch {
	case (errors.Is(err, errNameRemoved) || errors.Is(err, errLinkedElsewhere)) && !h.repinned:
		// D4's one re-pin, for a name: the walk reached a file by a name that names another inode, or none, by the time
		// this loop reads the pin, as a rename over it does (an editor's save, the ledger's reason file; a rename
		// between this loop's fstat and its readlink is linked elsewhere). The task's own open, made now, opens what
		// the name names now: it is pinned, checked and scored once more, and the second answer stands.
		return false, true
	case unreadable, errors.Is(err, errLinkedElsewhere), errors.Is(err, errNameRemoved):
		// A linked object whose path this process cannot see, one reached by a name it no longer has, or, for a read
		// gate, a file whose name was removed: the gate needs a name it cannot read (D4). An open no gate scores, held
		// only as a read (ADR 0069), needs the name for its floor: it is refused held-unsupported, with no gate's word.
		if !openGated(l.table.Load().pol.Rules.Gate, flags) {
			l.heldRefuse(h, ruleHeldUnsupported, record.ReasonFSGate, h.d.gate)
			return false, false
		}
		l.heldRefuse(h, "gate.unreadable", record.ReasonFSGate, &gate.Decision{Verdict: gate.Refused, Score: gate.MaxScore, Rule: "gate.unreadable"})
		return false, false
	case errors.Is(err, errOtherView):
		resolved = "" // nameless: no name can match, and no entry names it (gate.md R1)
	case err != nil:
		l.heldUnavailable(h, err)
		return false, false
	}
	h.resolved = resolved
	return true, false
}

// heldPinQuery is the pin a held open of flags asks the deputy for.
func heldPinQuery(n *notif, tgid int, q pathQuery, flags int) deputy.PinQuery {
	// O_TMPFILE carries O_DIRECTORY: either open needs a directory, and a final symlink O_NOFOLLOW leaves is ENOTDIR.
	pq := deputy.PinQuery{TID: n.pid, TGID: tgid, DirFD: q.dirfd, Path: q.path, Empty: q.empty, Directory: flags&unix.O_DIRECTORY != 0}
	switch {
	case flags&(unix.O_CREAT|unix.O_EXCL) == unix.O_CREAT|unix.O_EXCL && flags&unix.O_TMPFILE != unix.O_TMPFILE:
		pq.Excl, pq.Nofollow = true, true
	case flags&unix.O_CREAT != 0 && flags&unix.O_TMPFILE != unix.O_TMPFILE:
		pq.Create = true
		pq.Nofollow = flags&unix.O_NOFOLLOW != 0
	default:
		pq.Nofollow = flags&unix.O_NOFOLLOW != 0
	}
	return pq
}

// errNameRemoved is a pin the deputy's walk reached by a name that, by the time this loop reads the pin, names nothing:
// its last link was removed after the walk (pinnedPath).
var errNameRemoved = errors.New("supervisor: the pinned object's name was removed after the pin")

// pinnedPath is where pin lies in this process's view, verified to be the same inode under that path
// (sameInodeHere), joined with leaf for a create. errOtherView for a nameless object, errLinkedElsewhere for a linked
// one this process cannot see by its path. An object with no link left is nameless only when the walk reached it
// through a descriptor (byFD: AT_EMPTY_PATH, a /proc/<pid>/fd magic link, a relative walk's start), as D4's row for a
// pipe, an anonymous inode or an unlinked file behind /proc/self/fd says; reached by a name, it had one when the walk
// took it, and a sibling removed it since. Taken as nameless, its floors and the gate's score on the pinned object were
// skipped and the copied name alone decided it: it is errNameRemoved, which refuses as unreadable.
func pinnedPath(pin int, st *unix.Stat_t, leaf string, byFD bool) (string, error) {
	link, err := readlinkRaw("/proc/self/fd/" + strconv.Itoa(pin))
	if err != nil {
		return "", err
	}
	if st.Nlink == 0 && !byFD {
		return "", errNameRemoved
	}
	if unlinkedFile(st) {
		return "", errUnlinkedFile // reached through a descriptor, a regular file whose name was removed
	}
	if st.Nlink == 0 || !strings.HasPrefix(link, "/") {
		return "", errOtherView
	}
	var here unix.Statx_t
	if unix.Statx(unix.AT_FDCWD, link, unix.AT_SYMLINK_NOFOLLOW|unix.AT_STATX_DONT_SYNC, unix.STATX_INO, &here) != nil ||
		uint64(here.Ino) != st.Ino || unix.Mkdev(here.Dev_major, here.Dev_minor) != uint64(st.Dev) {
		return "", errLinkedElsewhere
	}
	if leaf != "" {
		return cleanPath(link + "/" + leaf), nil
	}
	return link, nil
}

// Character-device classes the deputy opens as the kernel would for the task (D4): the memory class's null, zero,
// full, random and urandom, and the tty class, opened with O_NOCTTY. Every other device is refused held-unsupported:
// its open may act on the opener's own state (a /dev/net/tun open takes the opener's network namespace).
const (
	memMajor    = 1
	ttyMajor    = 4
	ttyAuxMajor = 5 // 5:0 /dev/tty, 5:1 /dev/console, 5:2 /dev/ptmx
	ptsFirst    = 136
	ptsLast     = 143
)

// stickyCreate is the kernel's may_create_in_sticky for an O_CREAT open that finds an existing file (fs.protected_regular
// for a regular file, fs.protected_fifos for a FIFO): in a sticky directory, a file owned by neither the directory's
// owner nor the opener is refused EACCES when the directory is world-writable and the sysctl is on, or group-writable
// and the sysctl is 2. dir is the directory's fstat, file the file's, fsuid the opener's, and level the sysctl's value
// for the file's type.
func stickyCreate(dir, file *unix.Stat_t, fsuid uint32, level int) error {
	if dir.Mode&unix.S_ISVTX == 0 || level == 0 || file.Uid == dir.Uid || file.Uid == fsuid {
		return nil
	}
	if dir.Mode&0o002 != 0 || dir.Mode&0o020 != 0 && level >= 2 {
		return unix.EACCES
	}
	return nil
}

// heldStickyCreate is stickyCreate for a held O_CREAT open (no O_EXCL) of an existing regular file or FIFO: the
// deputy reopens the pin through /proc/self/fd, whose directory is no sticky one, so the kernel's check of the file's
// own directory is made here, on the directory the pinned path names, as the task's own open makes it. It reads the
// task's fsuid and the sysctl only when that directory is sticky. A refusal is the kernel's EACCES (D4).
func (l *Loop) heldStickyCreate(h *heldPlan) bool {
	t := h.st.Mode & unix.S_IFMT
	if h.flags&unix.O_CREAT == 0 || h.flags&unix.O_EXCL != 0 || h.leaf != "" || h.resolved == "" || (t != unix.S_IFREG && t != unix.S_IFIFO) {
		return true
	}
	var dir unix.Stat_t
	if unix.Stat(filepath.Dir(h.resolved), &dir) != nil || dir.Mode&unix.S_ISVTX == 0 {
		return true // no sticky directory to check (or none this view can read: the kernel's open decides as before)
	}
	sysctl := "/proc/sys/fs/protected_regular"
	if t == unix.S_IFIFO {
		sysctl = "/proc/sys/fs/protected_fifos"
	}
	level := 1 // every distribution's default where the value cannot be read
	if b, err := os.ReadFile(sysctl); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			level = v
		}
	}
	procReads.Add(1)
	creds, err := sys.ReadTaskCreds(h.n.pid)
	if err != nil {
		l.heldUnavailable(h, err)
		return false
	}
	if err := stickyCreate(&dir, &h.st, creds.FSUID, level); err != nil {
		l.heldKernelErrno(h, unix.EACCES)
		return false
	}
	return true
}

// heldClass is D4 on the pinned object: what may be opened, what is refused, and the flags the open takes.
func (l *Loop) heldClass(h *heldPlan) bool {
	if !l.heldStickyCreate(h) {
		return false
	}
	switch h.st.Mode & unix.S_IFMT {
	case unix.S_IFBLK:
		l.heldRefuse(h, ruleHeldUnsupported, record.ReasonFSGate, h.d.gate)
		return false
	case unix.S_IFCHR:
		major, minor := unix.Major(uint64(h.st.Rdev)), unix.Minor(uint64(h.st.Rdev))
		switch {
		case major == memMajor && (minor == 3 || minor == 5 || minor == 7 || minor == 8 || minor == 9):
			return true
		case major == ttyMajor || (major == ttyAuxMajor && (minor == 0 || minor == 2)) || (major >= ptsFirst && major <= ptsLast):
			return l.heldTTY(h, major, minor)
		}
		l.heldRefuse(h, ruleHeldUnsupported, record.ReasonFSGate, h.d.gate)
		return false
	}
	// /proc/sys/net/ is looked up in the opener's network namespace: the deputy's is the run's, the agent's must be
	// the same.
	if strings.HasPrefix(h.resolved, "/proc/sys/net/") || h.resolved == "/proc/sys/net" {
		if !sameNetNS(h.n.pid) {
			l.heldRefuse(h, ruleHeldUnsupported, record.ReasonFSGate, h.d.gate)
			return false
		}
	}
	return true
}

// heldTTY is the tty class (D4): the open always takes O_NOCTTY, so the deputy never acquires a controlling
// terminal; it is refused where the task's own open would have acquired one (a session leader with none, whose call
// lacks O_NOCTTY), and /dev/tty, whose open names the opener's controlling terminal, unless the task's is the run's.
// One /proc/<tid>/stat read, for this class only.
func (l *Loop) heldTTY(h *heldPlan, major, minor uint32) bool {
	session, tty, err := sessionTTY(h.n.pid)
	if err != nil {
		l.heldUnavailable(h, err)
		return false
	}
	if h.flags&unix.O_NOCTTY == 0 && session == l.tgidOfNotif(h.n) && tty == 0 {
		l.heldRefuse(h, ruleHeldUnsupported, record.ReasonFSGate, h.d.gate)
		return false
	}
	if major == ttyAuxMajor && minor == 0 {
		_, own, err := sessionTTY(unix.Getpid())
		if err != nil || own != tty {
			l.heldRefuse(h, ruleHeldUnsupported, record.ReasonFSGate, h.d.gate)
			return false
		}
	}
	h.flags |= unix.O_NOCTTY
	return true
}

// sessionTTY reads a task's session id and controlling terminal (tty_nr, 0 for none), fields 6 and 7 of
// /proc/<pid>/stat, counted after the command's closing parenthesis, which a command name cannot fake.
func sessionTTY(pid int) (session, tty int, err error) {
	procReads.Add(1)
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, 0, err
	}
	end := strings.LastIndexByte(string(b), ')')
	if end < 0 {
		return 0, 0, errProcStat
	}
	f := strings.Fields(string(b[end+1:]))
	if len(f) < 5 {
		return 0, 0, errProcStat
	}
	if session, err = strconv.Atoi(f[3]); err != nil {
		return 0, 0, errProcStat
	}
	if tty, err = strconv.Atoi(f[4]); err != nil {
		return 0, 0, errProcStat
	}
	return session, tty, nil
}

// sameNetNS reports whether the task shares this process's network namespace, which is the deputy's: the stage that
// started it shared the launcher's, and the run's filter refuses a new one.
func sameNetNS(tid int) bool {
	var theirs, ours unix.Stat_t
	if unix.Stat("/proc/"+strconv.Itoa(tid)+"/ns/net", &theirs) != nil || unix.Stat("/proc/self/ns/net", &ours) != nil {
		return false
	}
	return theirs.Dev == ours.Dev && theirs.Ino == ours.Ino
}

// heldFloors is D3 step 3 on the pinned object: the floor the copied path applies to the same open, the contract's
// verdict for the tier (fsVerdictIn, decide.AdvisoryFS, must allow; anything else refuses) and for a write R15c's
// deny_write targets. The open is delivered only when the floor allows: a score never grants what the floor refuses
// (gate.md R1). Under gate.completion: held alone it is the copied path's floor and no stricter, so held completion
// changes how an open is completed, never which opens a tier allows, and the kernel's own decision on the deputy's
// open stands beneath it. A run that holds its reads (ADR 0069) adds the held-read floor for a read-capable open
// (heldReadFloors): a deny_read the Landlock ruleset leaves unenforced, nested in a write entry, is refused on the
// object the deputy reached, and so is a file a deny_read name rule covers that was made during the run. A person's
// approval takes the stricter checks a hold of this loop's pin takes (heldAskFloors). A nameless object has no entry
// to check, as Landlock's own check of it allows it (is_nouser_or_private).
func (l *Loop) heldFloors(h *heldPlan, c *compiled) bool {
	if h.resolved == "" {
		return true
	}
	rule, v, reason := c.fsVerdictIn(c.fsResolved, h.resolved, record.FSOpen, h.flags, false)
	if v != record.VerdictAllow {
		if reason == "" {
			reason = reasonFor(record.FSOpen)
		}
		l.heldRefuse(h, rule, reason, h.d.gate)
		return false
	}
	h.d.rule, h.d.verdict, h.d.reason = rule, record.VerdictAllow, ""
	if !isRead(record.FSOpen, h.flags) {
		if t, denied := c.denyWriteOpen(h.resolved, h.flags); denied {
			l.heldRefuse(h, t.RuleName(), record.ReasonWriteOutsideContract, h.d.gate)
			return false
		}
	}
	return l.heldReadFloors(h, c)
}

// heldAskFloors is what gateOpen checks before it asks a person about an open (D3 step 3 for the ask range): the
// nearest deny_read, enforced or not, and for a write the targets no approval reaches (AskDenyWriteTarget). An
// approval never grants an object the contract names as denied, whatever the tier enforces.
func (l *Loop) heldAskFloors(h *heldPlan, c *compiled, g *gate.Decision) bool {
	if nearest := decide.NearestIn(c.fsResolved, h.resolved); nearest != nil && nearest.DenyRead {
		l.heldRefuse(h, nearest.Name, record.ReasonReadDenied, g)
		return false
	}
	if !isRead(record.FSOpen, h.flags) {
		if t, denied := c.pol.Rules.AskDenyWriteTarget(h.resolved, false); denied {
			l.heldRefuse(h, t.RuleName(), record.ReasonWriteOutsideContract, g)
			return false
		}
	}
	return true
}

// openHeld is D3 steps 5 and 6: the deputy opens the pinned object with the task's flags, in the run; the opened
// descriptor must be the pinned inode (for a create, the new file beneath the pinned parent under the leaf); then it is
// delivered with ADDFD|SEND. It answers the notification, unless it reports repin: the create's leaf appeared after
// the pin (mayRepin), and the caller pins and decides it once more.
func (l *Loop) openHeld(h *heldPlan) (repin bool) {
	n := h.n
	fd, err := h.opened, h.openErr
	h.opened = -1 // owned below
	if fd < 0 && err == nil {
		fd, err = l.deputyOpen(h)
	}
	if fd < 0 {
		if mayRepin(h, err) {
			return true
		}
		if errors.Is(err, deputy.ErrAbandoned) {
			// The task left its open while the deputy waited on it (a FIFO with no writer, a stalled mount): the
			// deputy may still complete it, and its descriptor is closed when it comes (E35).
			l.metrics.orphaned.Add(1)
			l.emitHeldOutcome(h, false, false, true, nil)
			return false
		}
		var errno unix.Errno
		if errors.As(err, &errno) && errno != 0 {
			l.heldKernelErrno(h, errno)
			return false
		}
		l.heldUnavailable(h, err)
		return false
	}
	// This loop's copy is closed as soon as it has served, before any line: a line can wait on the ledger's queue (R23),
	// and a copy kept meanwhile is a second reference to the open file description the agent holds, so a FIFO it opened
	// would keep a reader or a writer after its close, and an flock it released by its close stay held. The deputy's
	// own copy is closed once its reply is sent.
	if !l.heldIdentity(h, fd) {
		return false
	}
	// No ID_VALID before the delivery: ADDFD|SEND on a notification that is gone fails ENOENT, handled below.
	k, ok := l.k.(heldKernel)
	if !ok {
		l.closeDup(fd)
		l.heldUnavailable(h, errors.New("no descriptor delivery"))
		return false
	}
	// ADDFD+SEND answers the notification and releases the thread in one ioctl, as respond's Send does, so the
	// thread's next notification is ordered after this one's line (R23a): sent is set before the ioctl, where admit
	// can see it. A delivery that fails is answered by respond below, which sets it as well.
	atomic.StoreUint32(&n.sent, 1)
	got, err := k.DeliverHeld(n.id, fd, h.flags)
	l.closeDup(fd)
	if err != nil {
		// A read-only open performed and not delivered changed nothing: no orphan, no line (E35 is about a side
		// effect). Any other open's effect happened, and its line says it was not delivered.
		effect := !readOnlyOpen(h.flags)
		if replyLost(err) {
			n.answered = true
			if effect {
				l.metrics.orphaned.Add(1)
			}
			l.emitHeldOutcome(h, effect, false, true, nil)
			return false
		}
		if !l.valid(n) {
			if effect {
				l.metrics.orphaned.Add(1)
				l.emitHeldOutcome(h, true, false, true, nil)
			}
			return false
		}
		// ADDFD's EMFILE is the task's own full table: its errno (D4). Anything else this process could not do.
		var errno unix.Errno
		if !errors.As(err, &errno) || errno != unix.EMFILE {
			errno = unix.EACCES
		}
		l.respond(n, respResult(-1, errno))
		ret := -int64(errno)
		l.emitHeldOutcome(h, true, false, n.gone, &ret)
		return false
	}
	n.answered = true
	if l.activity != nil {
		l.activity()
	}
	l.emitHeldOpen(h)
	_ = got
	return false
}

// mayRepin reports whether the deputy's open of a create met a leaf that appeared after the pin (D4): its
// openat(pin, leaf, O_CREAT|O_NOFOLLOW) failed EEXIST, or ELOOP on a symlink that the task's own open, made now, would
// follow. That is only when the task asked for neither O_EXCL nor, for ELOOP, O_NOFOLLOW (then the errno is the
// kernel's answer), no person approved the open (an approved absent leaf is created O_EXCL and never replaced by a
// file that appeared during the wait, ADR 0008: its errno stands), and no re-pin was made yet (the second answer
// stands, so a sibling that keeps swapping the leaf cannot hold a worker).
func mayRepin(h *heldPlan, err error) bool {
	if h.leaf == "" || h.human || h.repinned || h.flags&unix.O_EXCL != 0 {
		return false
	}
	var errno unix.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return errno == unix.EEXIST || errno == unix.ELOOP && h.flags&unix.O_NOFOLLOW == 0
}

// deputyOpen asks the deputy for the open, with the mode the syscall carries and, for a create, the task's umask read
// now (D5: never cached). A create whose leaf appeared meanwhile is pinned and scored once more (mayRepin).
func (l *Loop) deputyOpen(h *heldPlan) (int, error) {
	n := h.n
	mode := uint32(n.args[3])
	switch n.nr {
	case nrX86Open:
		mode = uint32(n.args[2])
	case nrX86Creat:
		mode = uint32(n.args[1])
	}
	umask := -1
	creates := (h.flags&unix.O_CREAT != 0 && h.leaf != "") || h.flags&unix.O_TMPFILE == unix.O_TMPFILE
	if creates {
		m, err := taskUmask(n.pid)
		if err != nil {
			return -1, err
		}
		umask = m
	}
	return l.deputy.Open(h.pin, h.leaf, h.flags, mode, umask, l.heldWait(n))
}

// readOnlyOpen reports whether open flags only read (deputy opPinOpen): no write access, create, truncate, temporary
// file or O_PATH.
func readOnlyOpen(flags int) bool {
	return flags&unix.O_ACCMODE == unix.O_RDONLY && flags&(unix.O_CREAT|unix.O_TRUNC|unix.O_PATH) == 0 &&
		flags&unix.O_TMPFILE != unix.O_TMPFILE
}

// heldIdentity is D3 step 6: the opened descriptor is the pinned inode, or for a create the new file beneath the
// pinned parent under the leaf. A mismatch is never delivered (heldMismatch), and fd is closed before its line.
func (l *Loop) heldIdentity(h *heldPlan, fd int) bool {
	var got unix.Stat_t
	if err := unix.Fstat(fd, &got); err != nil {
		l.closeDup(fd)
		l.heldMismatch(h, err)
		return false
	}
	want := h.st
	switch {
	case h.flags&unix.O_TMPFILE == unix.O_TMPFILE:
		// A new nameless file in the pinned directory: its device is the directory's.
		if got.Dev == want.Dev && got.Mode&unix.S_IFMT == unix.S_IFREG {
			return true
		}
	case h.leaf != "":
		var leaf unix.Stat_t
		if unix.Fstatat(h.pin, h.leaf, &leaf, unix.AT_SYMLINK_NOFOLLOW) == nil && leaf.Dev == got.Dev && leaf.Ino == got.Ino {
			return true
		}
	default:
		if got.Dev == want.Dev && got.Ino == want.Ino {
			return true
		}
	}
	l.closeDup(fd)
	l.heldMismatch(h, errors.New("the opened descriptor is not the pinned inode"))
	return false
}

// heldMismatch answers a held open whose descriptor failed the identity check: it is never delivered. A read-only
// open had no effect but atime, and is refused held-unavailable. Any other was made: a create made its file (a sibling
// may have renamed the new leaf before the check), a truncation happened, so its line is E35's, operation_completed
// true and fd_delivered false, with the errno the task gets as syscall_ret, and it counts orphaned (D5);
// a refusal line would say nothing happened.
func (l *Loop) heldMismatch(h *heldPlan, err error) {
	if readOnlyOpen(h.flags) {
		l.heldUnavailable(h, err)
		return
	}
	l.metrics.anomalies.Add(1)
	l.metrics.orphaned.Add(1)
	l.log.Warn("supervisor: held open made and not delivered, its descriptor is not what was scored", "nr", h.n.nr, "id", h.n.id, "err", err)
	l.respond(h.n, respResult(-1, refusalErrno))
	ret := -int64(refusalErrno)
	l.emitHeldOutcome(h, true, false, false, &ret)
}

// heldWait is the wait a deputy request makes while its reply is late (R21): the worker hands its place in the pool
// to a standby, and the notification is polled, so an open the task left is abandoned rather than waited on.
func (l *Loop) heldWait(n *notif) func() bool {
	return func() bool {
		l.backfill(n)
		live, err := l.idValid(n)
		if err != nil {
			return true // unknown, not abandoned: wait on
		}
		if !live {
			n.gone = true
		}
		return live
	}
}

// heldAnswer answers the task with errno, the answer its own syscall would have had (a lookup failure, a fault), and
// records the open under its advisory verdict with that result.
func (l *Loop) heldAnswer(h *heldPlan, errno unix.Errno) {
	l.respond(h.n, respMiss(errno))
	ret := -int64(errno)
	l.emitHeldOutcome(h, false, false, false, &ret)
}

// heldKernelErrno answers the task with the errno the deputy's open met in the kernel (D4: an errno that describes
// the task's state is that errno), and writes the open's one line with it as syscall_ret. The verdict follows the
// recorder's rule for a refusal the kernel returned (ADR 0016 (1), (3), decide.ChainFS): an EACCES, EPERM or EXDEV that
// the tier's model explains (decide.Evaluate at the run's tier, which at a root tier is the decision plane's or the
// listener's own reading of the contract) is that mechanism's refusal, written refused with the model's rule and
// reason; any other errno, an unexplained EACCES included (the file's own permission bits, a host LSM, Landlock after
// a rename this loop's names do not follow), keeps the verdict this loop's floor gave, and names no contract refusal
// the floor did not make. Where a decision plane decides the run, the model also reads the open object's identity: a
// plane keys some files at their own inodes (planeKeyedAt), so a hard link to one made before the run, whose path the
// model allows, is refused by that file's row, and the model's answer at the path the row is keyed at explains it
// (GAPS C38). The kernel recorder writes nothing for the deputy's open (supervisor R7a).
func (l *Loop) heldKernelErrno(h *heldPlan, errno unix.Errno) {
	l.respond(h.n, respMiss(errno))
	if h.resolved != "" {
		c := l.table.Load()
		kind := agent.ActionFSWrite
		if isRead(record.FSOpen, h.flags) {
			kind = agent.ActionFSRead
		}
		var model agent.EvalResult
		v, reason, _ := decide.ChainFS(-int32(errno), func() (record.Verdict, record.Reason) {
			model = decide.Evaluate(c.pol.Rules, agent.Action{Kind: kind, Path: h.resolved}, c.tier())
			if model.Verdict != agent.VerdictRefused && l.planeAttrs && h.leaf == "" {
				if p, ok := c.planeKeyedAt(&h.st); ok && p != h.resolved {
					model = decide.Evaluate(c.pol.Rules, agent.Action{Kind: kind, Path: p}, c.tier())
				}
			}
			if model.Verdict != agent.VerdictRefused && errno == unix.EACCES && l.snapshotExplains(kind, h.resolved) {
				// The deputy opens in the run's own domain: a name made after launch beside a deny_read ancestor is
				// refused it by the same ruleset as the task's own open (snapshotRead).
				model = agent.EvalResult{Verdict: agent.VerdictRefused, Rule: ruleDenyReadSnapshot, Reason: record.ReasonReadDenied}
			}
			if model.Verdict != agent.VerdictRefused {
				return record.VerdictAllow, ""
			}
			return record.VerdictRefused, model.Reason
		})
		if v == record.VerdictRefused {
			h.d.rule, h.d.verdict, h.d.reason = model.Rule, record.VerdictRefused, reason
		}
	}
	ret := -int64(errno)
	l.emitHeldOutcome(h, false, false, false, &ret)
}

// heldRefuse refuses the open with R10's errno under rule and reason: a refusal this loop makes itself. Its line
// names the pinned object, or before a pin the copied name as fs lines name it (lineName, walked before the answer).
func (l *Loop) heldRefuse(h *heldPlan, rule string, reason record.Reason, g *gate.Decision) {
	path := h.resolved
	if path == "" {
		path = l.lineName(h.n, fsEnd{p: h.q.joined, q: h.q})
	}
	l.respond(h.n, respErrno(refusalErrno))
	d := fsDecided{rule: rule, verdict: record.VerdictRefused, reason: reason, enforce: true, gate: g}
	l.emitHeldFS(h, path, d)
}

// heldUnavailable is D4's tego-side failure: the deputy gone or confused, this process out of descriptors or
// memory. It refuses held-unavailable and counts the anomaly; it never continues, and never hands the task this
// process's own errno.
func (l *Loop) heldUnavailable(h *heldPlan, err error) {
	l.metrics.anomalies.Add(1)
	l.log.Warn("supervisor: held open refused, the open deputy could not complete it", "nr", h.n.nr, "id", h.n.id, "err", err)
	l.heldRefuse(h, ruleHeldUnavailable, record.ReasonFSGate, h.d.gate)
}

// heldAsk is the ask range on the pinned object (D3 step 4): a person's answer, then the deputy's open, never the
// supervisor's own. A denial, a timeout or an unavailable broker refuses it. A live block of the pinned object that
// lands while the person decides withdraws the request, and one in force when the answer is back refuses the open
// whatever the answer, under the block's rule, before the deputy opens anything (liveHeld).
func (l *Loop) heldAsk(h *heldPlan, g *gate.Decision) {
	n := h.n
	if h.resolved == "" || h.st.Mode&unix.S_IFMT != unix.S_IFREG && h.leaf == "" {
		// The ask range completes regular files and creates only, as before Stage B (gate.md R4): an unsupported
		// completion is refused, never continued.
		l.heldRefuse(h, g.Rule, record.ReasonFSGate, &gate.Decision{Verdict: gate.Ask, Score: g.Score, Rule: g.Rule})
		return
	}
	if !l.heldAskFloors(h, l.table.Load(), g) {
		return
	}
	// The open syscall is what is held, whatever ask.hold says (ask-4), and the person sees the pinned object.
	req := ask.Request{Op: record.FSOpen, Target: h.resolved, Rule: g.Rule, Hold: ask.HoldOpen, PID: l.tgidOfNotif(n), TID: n.pid,
		Score: &g.Score, GateRule: g.Rule}
	// A person may answer with an alternate (ADR 0057) as they may on a hold of this loop's own pin: the file they
	// name is checked and reopened as the task's credentials and umask, read now, and delivered in the target's place
	// (completeAlternate), never by the deputy, whose domain grants nothing a person names outside the contract (the
	// fs.ask and fs.ask_read completions stay where they are for the same reason; ADR 0041 Step 8 note). Credentials
	// that cannot be read leave the request without the check, and the broker then takes no alternate.
	alt, alternates := l.k.(askAlternateKernel)
	id, identity := l.k.(taskIdentityKernel)
	var as *heldAskOpen
	if alternates && identity {
		if creds, mask, err := id.TaskIdentity(n.pid); err == nil {
			as = &heldAskOpen{fd: -1, resolved: h.resolved, creds: creds, umask: mask}
			// The check is a hold's own (alternateCheck): the protected paths, the live Set, then the gate scoring the
			// agent's own open of the person's file, so a held ask's alternate is put to the gate as a
			// hold's is.
			c := l.table.Load()
			rt, own, flags := c.pol.Rules, l.ownState, h.flags
			req.Alternates = ask.NewAlternateCheck(func(a *ask.AlternateFile) (string, error) {
				_, resolved, err := alt.OpenAlternate(as, a, flags, true, alternateCheck(rt, own, c.blocks, flags, nil))
				return resolved, err
			})
		}
	}
	// The live Set is loaded again at each look: by the watcher while the person decides, and once the answer is back.
	resolved, flags := h.resolved, h.flags
	live := func() (fsDecided, bool) { return l.table.Load().liveHeld(resolved, flags) }
	refuseLive := func() bool {
		ld, hit := live()
		if hit {
			l.heldRefuse(h, ld.rule, ld.reason, nil)
		}
		return hit
	}
	decision, err := l.askHeldUnless(n, req, func() bool { _, hit := live(); return hit })
	defer decision.CloseAlternate()
	if n.gone {
		return
	}
	if err == nil && decision.Alternate != "" && !decision.Approved && as != nil {
		l.completeAlternate(n, h.r, h.q, h.flags, as, req, decision, g, nil, alt, h)
		return
	}
	if err != nil || !decision.Approved {
		// A request withdrawn for a block (or cut short otherwise) names the block now in force; a person's denial
		// and a timeout keep their own reason.
		if err != nil && refuseLive() {
			return
		}
		l.respond(n, respErrno(refusalErrno))
		l.emitHeldFS(h, h.resolved, fsDecided{rule: g.Rule, verdict: record.VerdictRefused, reason: record.Reason(askReason(decision, err)), enforce: true, gate: g})
		return
	}
	if !l.valid(n) {
		return
	}
	if refuseLive() {
		return
	}
	// An approved absent leaf is created O_EXCL: a file appearing during the person's wait is never silently
	// substituted for the one approved (ADR 0008).
	if h.leaf != "" {
		h.flags |= unix.O_EXCL
	}
	h.human = true
	_ = l.openHeld(h) // an approved open is never re-pinned (mayRepin): openHeld answers it
}

// emitHeldOpen writes the line of a delivered held open: the ordinary fs action line (D5), on the pinned object's
// path, authority rule (human for an approved ask), with the gate's fields and gate_facts held_object. record: off
// keeps it out, as it keeps every allowed line out.
func (l *Loop) emitHeldOpen(h *heldPlan) {
	l.emitHeldFS(h, l.heldName(h), h.d)
}

// heldName is the name a held open's line written after the answer gives it: the pinned object, or with none (a
// nameless object, no pin) the name the decision's walk gave the open (memoName), never the lexical clean of a ".."
// spelling, which names a file the verdict was not taken on. An open whose spelling the walk
// names is walked by its decision before any hold (recordOpen sends none to heldDirect), so that memo is there.
// heldRefuse, which answers, names an unpinned open by lineName before its answer.
func (l *Loop) heldName(h *heldPlan) string {
	if h.resolved != "" {
		return h.resolved
	}
	return l.memoName(h.n, fsEnd{p: h.q.joined, q: h.q})
}

// emitHeldFS writes one held open's line with verdict d on path.
func (l *Loop) emitHeldFS(h *heldPlan, path string, d fsDecided) {
	c := l.table.Load()
	if d.verdict != record.VerdictRefused && (!c.recording() || l.heldQuiet(c, h)) {
		return
	}
	ev := action(l.event(h.n, record.KindFS, record.SourceSeccomp), d.rule, d.verdict, d.reason)
	if d.gate != nil && d.gate.Verdict != gate.Allow && d.verdict == record.VerdictRefused {
		ev.Authority = record.AuthorityGate
	}
	if h.human && d.verdict != record.VerdictRefused {
		ev.Authority = record.AuthorityHuman
	}
	l.emitFor(h.n, ev, struct {
		record.FSPayload
		GateFields
	}{record.FSPayload{Op: record.FSOpen, Path: path, Flags: h.flags}, heldGatePayload(d.gate)})
}

// emitHeldOutcome writes the line of a held open that was not delivered, or that failed with an errno: E35's fields
// say whether the open was performed, whether the descriptor was delivered, and whether what the task's syscall
// returned is known, as an approved open's line does. Under record: off only a refusal, or an open performed and
// not delivered, is written.
func (l *Loop) emitHeldOutcome(h *heldPlan, performed, delivered, unknown bool, ret *int64) {
	c := l.table.Load()
	if h.d.verdict != record.VerdictRefused && !performed && (!c.recording() || l.heldQuiet(c, h)) {
		return
	}
	path := l.heldName(h)
	rule, verdict, reason := h.d.rule, h.d.verdict, h.d.reason
	if verdict == "" {
		verdict = record.VerdictAllow
	}
	if unnamedFS(h.r, record.FSOpen, path, "") && verdict != record.VerdictRefused {
		rule, verdict, reason = noteOr(h.r, unreadMarker(h.r)), record.VerdictObserved, record.Reason("")
	}
	ev := action(l.event(h.n, record.KindFS, record.SourceSeccomp), rule, verdict, reason)
	if h.human && verdict != record.VerdictRefused {
		ev.Authority = record.AuthorityHuman
	}
	if !h.n.answered {
		// Nothing was answered (the task left): the line is still the run's, of a side effect that may have happened.
		h.n.answered = true
		defer func() { h.n.answered = false }()
	}
	l.emitFor(h.n, ev, struct {
		record.FSPayload
		GateFields
		OperationCompleted bool   `json:"operation_completed"`
		FDDelivered        bool   `json:"fd_delivered"`
		ResultUnknown      bool   `json:"result_unknown,omitempty"`
		SyscallRet         *int64 `json:"syscall_ret,omitempty"`
	}{record.FSPayload{Op: record.FSOpen, Path: path, Flags: h.flags}, heldGatePayload(h.d.gate), performed, delivered, unknown, ret})
}

// heldGatePayload is gatePayload for a decision taken on the pinned object (gate_facts held_object).
func heldGatePayload(g *gate.Decision) GateFields {
	f := gatePayload(g, false)
	if g != nil {
		f.GateFacts = gateFactsHeld
	}
	return f
}
