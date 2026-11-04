// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// heldAskOpen names an existing regular inode, or an absent leaf beneath a
// held parent. It contains no tracee-owned string or FD lookup after approval.
type heldAskOpen struct {
	fd                int
	missing, resolved string
	// name is the pin's own walk's name for a pathname with a ".." component (execWalk.named), "" otherwise: what a
	// refusal decided on the held object names the open (askLineName).
	name  string
	creds sys.TaskCreds
	umask int
}

// askLineName is the name a refusal of the open q gives it: lineName's, from the decision's walk, until the open is
// held, and once it is (h), the held object's walk's for a pathname with a ".." component. Every refusal made after
// the pin is decided on the held object (h.resolved: its rule, the deny_write and deny_read floors, its gate score, the
// person's answer), which the pin's walk reached, so a symlink the agent moved between the decision's walk and the pin
// cannot have the line name a file the refusal was not decided on. Either walk was made before the answer, and
// before any wait for a person.
func (l *Loop) askLineName(n *notif, q pathQuery, h *heldAskOpen) string {
	if h != nil && h.name != "" {
		return h.name
	}
	return l.lineName(n, fsEnd{p: q.joined, q: q})
}

type askOpenKernel interface {
	PrepareAskOpen(pathQuery, int) (*heldAskOpen, error)
	// CompleteAskOpen reopens h with the agent's flags and delivers it; check, when set, is put to the reopened
	// descriptor before ADDFD|SEND, and its error leaves the descriptor undelivered (askOpenDeliveryError).
	CompleteAskOpen(id uint64, h *heldAskOpen, flags int, mode uint32, check func(fd int) error) (int, error)
}

// askOpenDeliveryError means the approved open already succeeded, including
// its create/truncate side effects, but the descriptor was not delivered.
// Atomic ADDFD+SEND cannot make the preceding filesystem operation atomic.
type askOpenDeliveryError struct{ err error }

func (e *askOpenDeliveryError) Error() string { return e.err.Error() }
func (e *askOpenDeliveryError) Unwrap() error { return e.err }

func (k sysKernel) PrepareAskOpen(q pathQuery, flags int) (*heldAskOpen, error) {
	if flags&unix.O_TMPFILE == unix.O_TMPFILE || q.path == "" {
		return nil, unix.EOPNOTSUPP
	}
	creds, err := sys.ReadTaskCreds(q.tid)
	if err != nil {
		return nil, err
	}
	mask, err := taskUmask(q.tid)
	if err != nil {
		return nil, err
	}
	h := &heldAskOpen{fd: -1, creds: creds, umask: mask}
	err = runAskOpenAs(creds, mask, func() error {
		walk := q
		walk.create = flags&unix.O_CREAT != 0
		var e error
		if h.fd, h.missing, h.name, e = walkExec(walk, true); e != nil {
			return e
		}
		var st unix.Stat_t
		if e = unix.Fstat(h.fd, &st); e != nil {
			return e
		}
		kind := st.Mode & unix.S_IFMT
		if st.Nlink == 0 || (h.missing == "" && kind != unix.S_IFREG) || (h.missing != "" && kind != unix.S_IFDIR) {
			return unix.EOPNOTSUPP
		}
		link, e := readlinkRaw("/proc/self/fd/" + strconv.Itoa(h.fd))
		if e != nil {
			return e
		}
		if !strings.HasPrefix(link, "/") || !sameInodeHere(link, &st) {
			return errOtherView
		}
		if h.missing != "" {
			h.resolved = filepath.Join(link, h.missing)
		} else {
			h.resolved = link
		}
		return nil
	})
	if err != nil {
		if h.fd >= 0 {
			_ = unix.Close(h.fd)
		}
		return nil, err
	}
	return h, nil
}

func taskUmask(tid int) (int, error) {
	procReads.Add(1)
	data, err := os.ReadFile("/proc/" + strconv.Itoa(tid) + "/status")
	if err != nil {
		return 0, err
	}
	var mask int
	seen := false
	for _, line := range strings.Split(string(data), "\n") {
		if s, ok := strings.CutPrefix(line, "Umask:"); ok {
			if seen {
				return 0, unix.EINVAL
			}
			n, e := strconv.ParseUint(strings.TrimSpace(s), 8, 9)
			if e != nil {
				return 0, e
			}
			mask = int(n)
			seen = true
		}
	}
	if !seen {
		return 0, unix.EINVAL
	}
	return mask, nil
}

// The private fs_struct reproduces the target umask, including default-ACL
// semantics, without changing the launcher's process-wide umask.
func runAskOpenAs(creds sys.TaskCreds, mask int, fn func() error) error {
	type result struct {
		err      error
		panicked any
	}
	done := make(chan result, 1)
	var run func()
	run = func() {
		runtime.LockOSThread()
		if unix.Gettid() == unix.Getpid() {
			go run()
			runtime.UnlockOSThread()
			return
		}
		res := result{}
		defer func() { res.panicked = recover(); done <- res }()
		var innerErr error
		res.err = sys.RunAs(creds, func() {
			if e := unix.Unshare(unix.CLONE_FS); e != nil {
				innerErr = e
				return
			}
			unix.Umask(mask)
			innerErr = fn()
		})
		if res.err == nil {
			res.err = innerErr
		}
	}
	go run()
	res := <-done
	if res.panicked != nil {
		panic(res.panicked)
	}
	return res.err
}

// Linux's ADDFD+SEND returns the injected descriptor and completes the original
// syscall atomically. No approval is implemented with CONTINUE or SETFD.
func (k sysKernel) CompleteAskOpen(id uint64, h *heldAskOpen, flags int, mode uint32, check func(fd int) error) (int, error) {
	fd := -1
	err := runAskOpenAs(h.creds, h.umask, func() error {
		var e error
		if h.missing != "" {
			// A new object appearing during the human wait is never silently
			// substituted for the absent leaf that was approved.
			fd, e = unix.Openat(h.fd, h.missing, flags|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, mode)
		} else {
			if flags&(unix.O_CREAT|unix.O_EXCL) == unix.O_CREAT|unix.O_EXCL {
				return unix.EEXIST
			}
			var st unix.Stat_t
			if e = unix.Fstat(h.fd, &st); e != nil {
				return e
			}
			if st.Nlink == 0 {
				return unix.ENOENT
			}
			fd, e = unix.Open("/proc/self/fd/"+strconv.Itoa(h.fd), (flags&^unix.O_NOFOLLOW)|unix.O_CLOEXEC|unix.O_NONBLOCK, mode)
		}
		return e
	})
	if fd >= 0 {
		defer func() { _ = unix.Close(fd) }()
	}
	if err != nil {
		if fd >= 0 {
			return -1, &askOpenDeliveryError{err}
		}
		return -1, err
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return -1, &askOpenDeliveryError{err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return -1, &askOpenDeliveryError{unix.EOPNOTSUPP}
	}
	if err = setNonblock(fd, flags&unix.O_NONBLOCK != 0); err != nil {
		return -1, &askOpenDeliveryError{err}
	}
	if check != nil {
		if err = check(fd); err != nil {
			return -1, &askOpenDeliveryError{err}
		}
	}
	n, err := k.addFDSend(id, fd, flags)
	if err != nil {
		return -1, &askOpenDeliveryError{err}
	}
	return n, nil
}

// setNonblock leaves fd's O_NONBLOCK as the agent's open asked: this process opens with it set, so that a FIFO or a
// device cannot block it, and clears it when the agent did not ask for it.
func setNonblock(fd int, nonblock bool) error {
	if nonblock {
		return nil
	}
	current, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFL, current&^unix.O_NONBLOCK)
	return err
}

// addFDSend injects a duplicate of fd into the notifying task and completes notification id with it as the
// syscall's result, in one ioctl (SECCOMP_ADDFD_FLAG_SEND), with the agent's O_CLOEXEC. The ioctl runs with the
// thread's signals blocked (sys.SeccompNotifAddfdSend): a signal inside it made the kernel complete the agent's
// open with 0, a descriptor nobody delivered (custom-agent POC, item 5).
func (k sysKernel) addFDSend(id uint64, fd int, flags int) (agentFD int, err error) {
	err = k.ln.Borrow(func(ln int) error {
		var err error
		agentFD, err = sys.SeccompNotifAddfdSend(ln, id, fd, flags&unix.O_CLOEXEC != 0)
		return err
	})
	return agentFD, err
}

// heldIdentityRefused is the protected-identity floor's refusal of a reopened descriptor (its rule), put through
// CompleteAskOpen's check: the descriptor was opened and is not delivered.
type heldIdentityRefused string

func (r heldIdentityRefused) Error() string { return "held-read identity refused: " + string(r) }

// replyLost reports whether a delivery's error says the kernel holds the notification as answered with nothing
// delivered (sys.ErrNotifReplyLost): nothing may answer it again, and what the agent's syscall returned is not known.
func replyLost(err error) bool { return errors.Is(err, sys.ErrNotifReplyLost) }

func fsAskRule(rt *agent.RuleTable, p string) *agent.FSRule {
	var best *agent.FSRule
	for i := range rt.FSAsk {
		r := &rt.FSAsk[i]
		if agent.Covers(r.Governed(), p) && (best == nil || len(r.Governed()) > len(best.Governed())) {
			best = r
		}
	}
	return best
}

// askOpen is called only for write-opens after the unconditional protected-file
// checks. It rechecks policy against the held object's resolved location.
func (l *Loop) askOpen(n *notif, r *reader, q pathQuery, flags int, d fsDecided) bool {
	c := l.table.Load()
	rt := c.pol.Rules
	if len(rt.FSAsk) == 0 || !isWriteOpen(flags) {
		return false
	}
	// Root fallback mutation enforcement is an ordinary unmatched refusal,
	// which a safe descriptor-only ask may complete. Unconditional guards
	// are checked again against the pinned target below.
	if d.verdict == record.VerdictAllow {
		return false
	}
	var h *heldAskOpen // the held object, once the open is pinned below
	refuse := func(reason record.Reason, rule string) {
		lineAt := l.askLineName(n, q, h) // before the answer, which ends the notification
		l.respond(n, respErrno(refusalErrno))
		l.emitFS(n, r, record.FSOpen, lineAt, "", flags, fsDecided{rule: rule, verdict: record.VerdictRefused, reason: reason, enforce: true})
	}
	if r.failed || r.unreadPath != "" {
		refuse(record.ReasonAskUnreadable, rulePathUnreliable)
		return true
	}
	k, ok := l.k.(askOpenKernel)
	if !ok {
		// With no held object, the scope is matched on the open's name as its line gives it (lineName), never on the
		// lexical clean of a ".." spelling, a file the line does not name.
		if fsAskRule(rt, l.lineName(n, fsEnd{p: q.joined, q: q})) == nil {
			return false
		}
		refuse(record.ReasonAskUnavailable, "fs.ask")
		return true
	}
	if !l.valid(n) {
		return true
	}
	h, err := k.PrepareAskOpen(q, flags)
	if !l.valid(n) {
		if h != nil {
			l.closeDup(h.fd)
		}
		return true
	}
	if err != nil {
		if fsAskRule(rt, l.lineName(n, fsEnd{p: q.joined, q: q})) == nil {
			return false
		}
		h = nil
		refuse(record.ReasonAskUnreadable, "fs.ask")
		return true
	}
	defer l.closeDup(h.fd)
	rule := fsAskRule(rt, h.resolved)
	if rule == nil {
		return false
	}
	name := rule.RuleName()
	if name == "" {
		name = "fs.ask"
	}
	if !l.askScopeValid(rule, h.resolved) {
		refuse(record.ReasonAskUnavailable, name)
		return true
	}
	if _, denied := rt.DenyWriteTarget(h.resolved, false); denied {
		refuse(record.ReasonWriteOutsideContract, name)
		return true
	}
	if _, denied := rt.AskDenyWriteTarget(h.resolved, false); denied {
		refuse(record.ReasonWriteOutsideContract, name)
		return true
	}
	if nearest := decide.NearestIn(c.fsResolved, h.resolved); nearest != nil && nearest.DenyRead {
		refuse(record.ReasonReadDenied, nearest.Name)
		return true
	}
	_, v, _ := c.fsVerdictIn(c.fsResolved, h.resolved, record.FSOpen, flags, false)
	if v == record.VerdictAllow {
		return false
	}
	// Scored as the agent's own open of the held file: an O_RDWR write by the read predicates too (scoreOpen).
	g := scoreOpen(rt.Gate, gate.Ask, h.resolved, flags, rt.Workdir)
	if copied := l.heldCopiedRefusal(n, r, q, flags); copied != nil {
		g = *copied
	}
	if g.Verdict == gate.Refused {
		lineAt := l.askLineName(n, q, h) // before the answer, which ends the notification
		l.respond(n, respErrno(refusalErrno))
		l.emitFS(n, r, record.FSOpen, lineAt, "", flags, fsDecided{rule: g.Rule, verdict: record.VerdictRefused, reason: record.ReasonFSGate, enforce: true, gate: &g})
		return true
	}
	var gd *gate.Decision
	if openGated(rt.Gate, flags) {
		gd = &g
	}
	return l.completeHeldAskOpen(n, r, q, flags, h, name, gd, rule, record.FSOpen)
}

// heldNameRefused is ADR 0043's interface 2 (supervisor R15f): a held open's completion opens the file outside any
// plane, so at the tiers whose mechanisms decide name entries (cgroup and bpflsm, D7) a held file a name entry covers
// is refused read-denied, named per D8, whatever the access mode (D1 refuses a modification of a covered file, and
// O_RDWR reads it); a climb that cannot decide is refused path-unresolved. resolved is the held file's resolved path.
// It is asked before any person is, and again once the answer came, against the table then in force.
func (l *Loop) heldNameRefused(resolved string) (rule string, reason record.Reason, refused bool) {
	c := l.table.Load()
	if t := c.tier(); t != backend.TierCgroup && t != backend.TierBPFLSM {
		return "", "", false
	}
	return c.fsIx.NameRefused(resolved, record.ReasonReadDenied)
}

// completeHeldAskOpen asks a person about a held open of h (op is record.FSOpen, or ask.OpRead for an fs.ask_read
// hold) and completes it as they answer: an approval reopens h with the agent's flags and delivers it (ADDFD+SEND),
// a denial, a timeout or an unavailable broker refuses it, and an alternate delivers the file the person named in
// its place (completeAlternate). A kernel that opens alternates gives the request its check (Request.Alternates). A
// live block of h that lands while the person decides withdraws the request, and one in force when the answer is
// back refuses the open whatever the answer, under the block's rule (liveHeld).
func (l *Loop) completeHeldAskOpen(n *notif, r *reader, q pathQuery, flags int, h *heldAskOpen, name string, g *gate.Decision, rule *agent.FSRule, op string) bool {
	k := l.k.(askOpenKernel)
	refuse := func(reason record.Reason, name string) {
		lineAt := l.askLineName(n, q, h) // before the answer, which ends the notification
		l.respond(n, respErrno(refusalErrno))
		l.emitFS(n, r, record.FSOpen, lineAt, "", flags, fsDecided{rule: name, verdict: record.VerdictRefused, reason: reason, enforce: true, gate: g})
	}
	if labelRule := l.openLabel(n, os.Getpid(), flags); labelRule != "" {
		refuse(record.ReasonFSGate, labelRule)
		return true
	}
	if n.gone {
		return true
	}
	if rule, why, refused := l.heldNameRefused(h.resolved); refused {
		refuse(why, rule)
		return true
	}
	// A person is never asked about an object the run's held reads refuse by identity (ADR 0069 D3(b)): a hard link
	// of a launch-pinned target under an ask entry's name stays the target.
	if rule, refused := l.heldAskIdentityRefusal(h.fd, false); refused {
		refuse(record.ReasonReadDenied, rule)
		return true
	}
	// The open syscall is what is held, whatever ask.hold says: that places network asks only (ask-4).
	req := ask.Request{Op: op, Target: h.resolved, Rule: name, Hold: ask.HoldOpen, PID: l.tgidOf(n.pid), TID: n.pid}
	if g != nil {
		req.Score = &g.Score
		req.GateRule = g.Rule
	}
	alt, alternates := l.k.(askAlternateKernel)
	if alternates {
		// The check at answer time opens the alternate with the access mode alone: no truncation happens before the
		// answer is chosen. It reads only the held task's credentials, never h's descriptor, which the caller closes
		// once this returns while a late answer's check may still run.
		c := l.table.Load()
		rt, own := c.pol.Rules, l.ownState
		id, tid := n.id, n.pid
		req.Alternates = ask.NewAlternateCheck(func(a *ask.AlternateFile) (string, error) {
			if err := l.alternateProbeLabel(id, tid, flags); err != nil {
				return "", err
			}
			if err := l.heldAlternateCheck(c, a); err != nil {
				return "", err
			}
			_, resolved, err := alt.OpenAlternate(h, a, flags, true, alternateCheck(rt, own, c.blocks, flags, nil))
			return resolved, err
		})
	}
	// A live block landing while the person decides withdraws the request, and one in force once the answer is back
	// refuses the open under the block, never under the ask's rule, before anything is opened (liveHeld). An
	// alternate is put to the Set on its own file instead (alternateCheck), at the answer and again at delivery.
	live := func() (fsDecided, bool) { return l.table.Load().liveHeld(h.resolved, flags) }
	refuseLive := func() bool {
		ld, hit := live()
		if hit {
			lineAt := l.askLineName(n, q, h) // before the answer, which ends the notification
			l.respond(n, respErrno(refusalErrno))
			l.emitFS(n, r, record.FSOpen, lineAt, "", flags, ld)
		}
		return hit
	}
	decision, err := l.askHeldUnless(n, req, func() bool { _, hit := live(); return hit })
	// The decision owns the alternate's descriptor, if it carries one; nothing past this function holds it.
	defer decision.CloseAlternate()
	if n.gone {
		return true
	}
	if err == nil && decision.Alternate != "" && !decision.Approved && alternates {
		return l.completeAlternate(n, r, q, flags, h, req, decision, g, rule, alt, nil)
	}
	if err != nil || !decision.Approved {
		// A request withdrawn for a block (or cut short otherwise) names the block now in force; a person's denial
		// and a timeout keep their own reason.
		if err != nil && refuseLive() {
			return true
		}
		refuse(record.Reason(askReason(decision, err)), name)
		return true
	}
	if !l.valid(n) {
		return true
	}
	if rule != nil && !l.askScopeValid(rule, h.resolved) {
		refuse(record.ReasonAskUnavailable, name)
		return true
	}
	if rule, why, refused := l.heldNameRefused(h.resolved); refused {
		refuse(why, rule)
		return true
	}
	// Again once the answer is back, with the directory barriers: a replacement made before the pin, or while the
	// person decided, refuses the read as it does a deputy's (heldReadIdentityRefusal).
	if rule, refused := l.heldAskIdentityRefusal(h.fd, true); refused {
		refuse(record.ReasonReadDenied, rule)
		return true
	}
	if refuseLive() {
		return true
	}
	mode := uint32(n.args[3])
	if n.nr == nrX86Open {
		mode = uint32(n.args[2])
	}
	if n.nr == nrX86Creat {
		mode = uint32(n.args[1])
	}
	// ADDFD+SEND answers the notification and releases the thread in one ioctl, as respond's Send does, so the next
	// notification of the thread is ordered after this one's line the same way (R23a): sent is set before the ioctl,
	// where admit can see it. A completion that fails before the ioctl is answered by respond below.
	if labelRule := l.openLabel(n, os.Getpid(), flags); labelRule != "" {
		refuse(record.ReasonFSGate, labelRule)
		return true
	}
	if n.gone {
		return true
	}
	atomic.StoreUint32(&n.sent, 1)
	// The reopened descriptor is the one the agent would get: its identity and the names' history are checked on it,
	// after the reopen and before delivery, as a deputy's held read is (openHeld). A protected object put at the
	// pinned inode's place, or the pinned inode put at a protected name, during the completion is refused here.
	var check func(int) error
	if l.table.Load().heldReads != nil {
		check = func(fd int) error {
			if rule, refused := l.heldAskIdentityRefusal(fd, true); refused {
				return heldIdentityRefused(rule)
			}
			return nil
		}
	}
	fd, err := k.CompleteAskOpen(n.id, h, flags, mode, check)
	var identity heldIdentityRefused
	if err != nil && errors.As(err, &identity) {
		l.metrics.orphaned.Add(1)
		l.respond(n, respErrno(refusalErrno))
		ev := action(l.event(n, record.KindFS, record.SourceSupervisor), string(identity), record.VerdictRefused, record.ReasonReadDenied)
		ret := -int64(refusalErrno)
		var result *int64
		if !n.gone {
			result = &ret
		}
		l.awaitPrev(n)
		l.emit(ev, struct {
			record.FSPayload
			GateFields
			OperationCompleted bool   `json:"operation_completed"`
			FDDelivered        bool   `json:"fd_delivered"`
			ResultUnknown      bool   `json:"result_unknown,omitempty"`
			SyscallRet         *int64 `json:"syscall_ret,omitempty"`
		}{record.FSPayload{Op: record.FSOpen, Path: h.resolved, Flags: flags}, gatePayload(g, false), !readOnlyOpen(flags), false, n.gone, result})
		return true
	}
	if err == nil {
		n.answered = true
		if l.activity != nil {
			l.activity()
		}
	} else {
		var delivered *askOpenDeliveryError
		performed := errors.As(err, &delivered)
		if replyLost(err) {
			n.answered = true
			l.metrics.orphaned.Add(1)
			l.emitApprovedGateAskOpen(n, req, flags, performed, false, true, nil, g)
			return true
		}
		if !l.valid(n) {
			if performed {
				l.metrics.orphaned.Add(1)
				l.emitApprovedGateAskOpen(n, req, flags, true, false, true, nil, g)
			}
			return true
		}
		var errno unix.Errno
		if !errors.As(err, &errno) {
			errno = unix.EACCES
		}
		l.respond(n, respResult(-1, errno))
		result := -int64(errno)
		if n.gone {
			l.emitApprovedGateAskOpen(n, req, flags, performed, false, true, nil, g)
		} else {
			l.emitApprovedGateAskOpen(n, req, flags, performed, false, false, &result, g)
		}
		return true
	}
	result := int64(fd)
	l.emitApprovedGateAskOpen(n, req, flags, true, true, false, &result, g)
	return true
}

// completeAlternate delivers a person's alternate as the result of the held open (ask_alternate.go): the file is
// opened and checked again, now with the agent's flags, since it can change between the answer and now, and its
// descriptor is injected by ADDFD+SEND. A file that fails the checks now refuses the open, ask-unavailable, under
// the ask's rule: the target was not granted and nothing was delivered. One opened but not delivered (the
// notification went away) is recorded as an approved open's is, operation_completed without fd_delivered. The
// delivered line names the file delivered, with the target it stands for in alternate_for, and carries the gate's
// decision on the file delivered (alternateGate), never the target's: a gate that refuses that file refuses it here
// as at answer time, and the record's gate fields describe the path the line names. A
// refusal here is the target's line, with the target's gate decision. held is the open deputy's plan when the ask was
// a held open's (ADR 0041 Stage B, heldAsk), nil for a hold on this loop's own pin: its lines carry gate_facts
// held_object, and a refusal names the pinned object.
func (l *Loop) completeAlternate(n *notif, r *reader, q pathQuery, flags int, h *heldAskOpen, req ask.Request, d ask.Decision, g *gate.Decision, rule *agent.FSRule, alt askAlternateKernel, held *heldPlan) bool {
	refuse := func(reason record.Reason) {
		if held != nil {
			l.heldRefuse(held, req.Rule, reason, g)
			return
		}
		lineAt := l.askLineName(n, q, h) // before the answer, which ends the notification
		l.respond(n, respErrno(refusalErrno))
		l.emitFS(n, r, record.FSOpen, lineAt, "", flags, fsDecided{rule: req.Rule, verdict: record.VerdictRefused, reason: reason, enforce: true, gate: g})
	}
	if !l.valid(n) {
		return true
	}
	if labelRule := l.openLabel(n, os.Getpid(), flags); labelRule != "" {
		if held != nil {
			l.heldRefuse(held, labelRule, record.ReasonFSGate, g)
		} else {
			lineAt := l.askLineName(n, q, h)
			l.respond(n, respErrno(refusalErrno))
			l.emitFS(n, r, record.FSOpen, lineAt, "", flags, fsDecided{rule: labelRule, verdict: record.VerdictRefused, reason: record.ReasonFSGate, enforce: true, gate: g})
		}
		return true
	}
	if n.gone {
		return true
	}
	if rule != nil && !l.askScopeValid(rule, h.resolved) {
		refuse(record.ReasonAskUnavailable)
		return true
	}
	c := l.table.Load()
	// The delivered line carries the gate's decision on the file delivered, not the target's g:
	// the record says what the gate scored for the path it names. The live Set is loaded again here, at delivery.
	var ag *gate.Decision
	if err := l.heldAlternateCheck(c, d.File); err != nil {
		refuse(record.ReasonAskUnavailable)
		return true
	}
	fd, resolved, err := alt.OpenAlternate(h, d.File, flags, false, alternateCheck(c.pol.Rules, l.ownState, c.blocks, flags, &ag))
	if err != nil {
		refuse(record.ReasonAskUnavailable)
		return true
	}
	gf := gatePayload(ag, false)
	if held != nil {
		gf = heldGatePayload(ag)
	}
	if c.heldReads != nil {
		var st unix.Stat_t
		rule, refused := ruleHeldIdentityUnknown, true
		if err := unix.Fstat(fd, &st); err == nil {
			rule, refused = l.heldReadIdentityRefusal(c, unix.O_RDONLY, decide.HeldReadID{Dev: st.Dev, Ino: st.Ino}, true)
		}
		if refused {
			// The alternate may already have been truncated. Close before recording
			// the refusal and preserve that effect without claiming delivery.
			l.closeDup(fd)
			l.metrics.orphaned.Add(1)
			l.respond(n, respErrno(refusalErrno))
			ev := action(l.event(n, record.KindFS, record.SourceSupervisor), rule, record.VerdictRefused, record.ReasonReadDenied)
			ret := -int64(refusalErrno)
			var result *int64
			if !n.gone {
				result = &ret
			}
			l.awaitPrev(n)
			l.emit(ev, struct {
				record.FSPayload
				GateFields
				OperationCompleted bool   `json:"operation_completed"`
				FDDelivered        bool   `json:"fd_delivered"`
				ResultUnknown      bool   `json:"result_unknown,omitempty"`
				SyscallRet         *int64 `json:"syscall_ret,omitempty"`
			}{record.FSPayload{Op: record.FSOpen, Path: resolved, Flags: flags, AlternateFor: req.Target}, gf, true, false, n.gone, result})
			return true
		}
	}
	defer l.closeDup(fd)
	if !l.valid(n) {
		l.metrics.orphaned.Add(1)
		l.emitHumanOpen(n, req, resolved, req.Target, flags, true, false, true, nil, gf)
		return true
	}
	atomic.StoreUint32(&n.sent, 1) // ADDFD+SEND releases the thread: R23a, as in completeHeldAskOpen
	got, err := alt.DeliverFD(n.id, fd, flags)
	if err != nil {
		if replyLost(err) {
			n.answered = true
			l.metrics.orphaned.Add(1)
			l.emitHumanOpen(n, req, resolved, req.Target, flags, true, false, true, nil, gf)
			return true
		}
		if !l.valid(n) {
			l.metrics.orphaned.Add(1)
			l.emitHumanOpen(n, req, resolved, req.Target, flags, true, false, true, nil, gf)
			return true
		}
		var errno unix.Errno
		if !errors.As(err, &errno) {
			errno = unix.EACCES
		}
		l.respond(n, respResult(-1, errno))
		result := -int64(errno)
		if n.gone {
			l.emitHumanOpen(n, req, resolved, req.Target, flags, true, false, true, nil, gf)
		} else {
			l.emitHumanOpen(n, req, resolved, req.Target, flags, true, false, false, &result, gf)
		}
		return true
	}
	n.answered = true
	if l.activity != nil {
		l.activity()
	}
	result := int64(got)
	l.emitHumanOpen(n, req, resolved, req.Target, flags, true, true, false, &result, gf)
	return true
}

func (l *Loop) emitApprovedGateAskOpen(n *notif, req ask.Request, flags int, performed, delivered, unknown bool, syscallRet *int64, g *gate.Decision) {
	l.emitHumanOpen(n, req, req.Target, "", flags, performed, delivered, unknown, syscallRet, gatePayload(g, false))
}

// emitHumanOpen writes the line of an open a person's answer completed: an approved open's, on path the target, or
// an alternate's, on path the file delivered with alternateFor the target it stands for (POC 2026-10-06, additive
// within record v1). Its verdict is allow and its authority human; operation_completed, fd_delivered and the
// optional result_unknown and syscall_ret say what happened; g is the gate's decision on path. A delivered open is not written under record: off,
// whose ask and answer lines already say it; one that failed is.
func (l *Loop) emitHumanOpen(n *notif, req ask.Request, path, alternateFor string, flags int, performed, delivered, unknown bool, syscallRet *int64, gf GateFields) {
	if !l.table.Load().recording() && delivered {
		return
	}
	ev := action(l.event(n, record.KindFS, record.SourceSupervisor), req.Rule, record.VerdictAllow, "")
	ev.PID, ev.Authority = req.PID, record.AuthorityHuman
	l.awaitPrev(n)
	l.emit(ev, struct {
		record.FSPayload
		GateFields
		OperationCompleted bool   `json:"operation_completed"`
		FDDelivered        bool   `json:"fd_delivered"`
		ResultUnknown      bool   `json:"result_unknown,omitempty"`
		SyscallRet         *int64 `json:"syscall_ret,omitempty"`
	}{record.FSPayload{Op: record.FSOpen, Path: path, Flags: flags, AlternateFor: alternateFor}, gf, performed, delivered, unknown, syscallRet})
}
