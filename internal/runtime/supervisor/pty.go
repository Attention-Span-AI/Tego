// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// peerFromMaster never opens a slave pathname. Holding the duplicate prevents
// index reuse, and TIOCGPTPEER selects the master's own devpts instance.
// O_NOCTTY is relay-local: caller flags must never give this process a
// controlling terminal, including when policy subsequently refuses delivery.
func peerFromMaster(master, flags int, want int) (*sys.FD, error) {
	index, err := unix.IoctlGetInt(master, unix.TIOCGPTN)
	if err != nil || want >= 0 && index != want {
		return nil, unix.ENOTTY
	}
	if flags & ^(unix.O_ACCMODE|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK) != 0 {
		return nil, unix.EINVAL
	}
	return sys.OwnSyscall(unix.Syscall(unix.SYS_IOCTL, uintptr(master), unix.TIOCGPTPEER, uintptr(flags)|unix.O_CLOEXEC|unix.O_NOCTTY))
}

func (l *Loop) ptyPeer(n *notif) {
	if l.observing() {
		l.respond(n, respContinue())
		return
	}
	master, err := l.duplicate(n, int(int32(n.args[0])))
	if err != nil {
		l.ptyRefuse(n, "TIOCGPTPEER")
		return
	}
	defer l.closeDup(master)
	slave, err := peerFromMaster(master, int(n.args[2]), -1)
	if err != nil {
		l.respond(n, respResult(0, err))
		return
	}
	defer slave.Close() //nolint:errcheck // owned relay result
	l.deliverPty(n, slave, int(n.args[2]), "/dev/pts/"+ptyIndex(master))
}

func ptyIndex(master int) string {
	n, err := unix.IoctlGetInt(master, unix.TIOCGPTN)
	if err != nil {
		return "?"
	}
	return strconv.Itoa(n)
}

// deliverPty crosses the run's Landlock boundary with ADDFD. Ownership of a
// master removes only builtin.other_tty; it grants no contractual access to its
// slave. Decide the held slave, including reads of an O_RDWR open, before it
// can enter the task. Never reopen a slave pathname to make these checks.
func (l *Loop) deliverPty(n *notif, slave *sys.FD, flags int, p string) {
	h := &heldPlan{n: n, r: l.newReader(n), q: pathQuery{joined: p}, flags: flags, pin: -1, opened: -1}
	err := slave.Borrow(func(fd int) error {
		if err := unix.Fstat(fd, &h.st); err != nil {
			return err
		}
		var err error
		h.resolved, err = pinnedPath(fd, &h.st, "", true)
		return err
	})
	major := unix.Major(uint64(h.st.Rdev))
	if err != nil || h.st.Mode&unix.S_IFMT != unix.S_IFCHR || major < ptsFirst || major > ptsLast || !agent.OtherTTY(h.resolved) {
		l.ptyRefuse(n, p)
		return
	}
	c := l.table.Load()
	// Check both the spelling and the verified inode's location. A more permissive
	// spelling cannot replace a denial at the held object (ADR 0041 D3).
	for i, at := range []string{p, h.resolved} {
		rules := c.fsResolved
		if i == 0 {
			rules = c.fsBoth
		}
		rule, v, reason := c.fsVerdictIn(rules, at, record.FSOpen, flags, false)
		if decide.OpenReads(flags) {
			near := decide.NearestWhere(rules, at, func(r *decide.AdvisoryRule) bool { return r.Write || r.DenyRead })
			if near != nil && near.DenyRead {
				rule, v, reason = near.Name, record.VerdictRefused, record.ReasonReadDenied
				// Existing approval completion supports regular files, never devices.
				if near.AskRead {
					reason = record.ReasonAskUnavailable
				}
			}
		}
		if isWriteOpen(flags) {
			if t, denied := c.denyWriteOpen(at, flags); denied {
				l.heldRefuse(h, t.RuleName(), record.ReasonWriteOutsideContract, nil)
				return
			}
			if v != record.VerdictAllow {
				if ask := fsAskRule(c.pol.Rules, at); ask != nil {
					rule, reason = ask.RuleName(), record.ReasonAskUnavailable
				}
			}
		}
		if v != record.VerdictAllow {
			l.heldRefuse(h, rule, reason, nil)
			return
		}
		if d, hit := c.liveHeld(at, flags); hit {
			l.heldRefuse(h, d.rule, d.reason, nil)
			return
		}
		h.d = fsDecided{rule: rule, verdict: record.VerdictAllow}
		g := scoreOpen(c.pol.Rules.Gate, gate.Allow, at, flags, c.pol.Rules.Workdir)
		if g.Verdict != gate.Allow {
			// The gate's ask range cannot complete a character device either.
			l.heldRefuse(h, g.Rule, record.ReasonFSGate, &g)
			return
		}
	}
	k, ok := l.k.(interface {
		DeliverPty(uint64, *sys.FD, int) error
	})
	if !ok || !l.valid(n) {
		l.ptyRefuse(n, h.resolved)
		return
	}
	// Load the live set again immediately before the atomic delivery.
	if d, hit := l.table.Load().liveHeld(h.resolved, flags); hit {
		l.heldRefuse(h, d.rule, d.reason, nil)
		return
	}
	atomic.StoreUint32(&n.sent, 1)
	if err := k.DeliverPty(n.id, slave, flags); err != nil {
		if !replyLost(err) {
			l.ptyRefuse(n, h.resolved)
		}
		return
	}
	n.answered = true
	if l.activity != nil {
		l.activity()
	}
	l.emitHeldFS(h, h.resolved, h.d)
}

func (l *Loop) ptyRefuse(n *notif, p string) {
	l.respond(n, respErrno(refusalErrno))
	l.emitFS(n, l.newReader(n), record.FSOpen, p, "", unix.O_RDWR, fsDecided{rule: agent.BuiltinOtherTTY, verdict: record.VerdictRefused, reason: record.ReasonReadDenied, enforce: true})
}

// pidfd_getfd imports a descriptor without a Landlock open. No descriptor of a
// process outside the run may bypass the terminal layer. Until an import can
// be completed on a pinned source in the relay, all agent imports fail closed.
func handlePidfdGetfd(l *Loop, n *notif) {
	if l.observing() {
		l.respond(n, respContinue())
		return
	}
	l.ptyRefuse(n, fmt.Sprintf("pidfd_getfd:%d", n.args[1]))
}

func (l *Loop) ptyOpen(n *notif, r *reader, p, raw string, flags int) bool {
	if l.table.Load().pol.Rules.Builtins == nil || l.observing() || flags&unix.O_NOCTTY == 0 || !r.ok() || r.unreadPath != "" || !agent.OtherTTY(raw) || !strings.HasPrefix(raw, "/dev/pts/") {
		return false
	}
	index, err := strconv.Atoi(strings.TrimPrefix(raw, "/dev/pts/"))
	if err != nil || raw != "/dev/pts/"+strconv.Itoa(index) {
		return false
	}
	// Inspect the caller first; only another verified run member may contribute
	// a master. Recheck membership after taking its pidfd and duplicate.
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	candidates := []int{n.pid}
	for _, e := range procs {
		pid, err := strconv.Atoi(e.Name())
		if err == nil && pid != n.pid {
			if inside, err := l.inRun(pid); err == nil && inside {
				candidates = append(candidates, pid)
			}
		}
	}
	for _, pid := range candidates {
		if !l.valid(n) {
			return true
		}
		entries, err := os.ReadDir("/proc/" + strconv.Itoa(pid) + "/fdinfo")
		if err != nil {
			continue
		}
		for _, e := range entries {
			data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "fdinfo", e.Name()))
			if err != nil || !strings.Contains(string(data), "tty-index:\t"+strconv.Itoa(index)+"\n") {
				continue
			}
			num, err := strconv.Atoi(e.Name())
			if err != nil {
				continue
			}
			var master int
			pfd := -1
			if pid == n.pid {
				master, err = l.duplicate(n, num)
			} else {
				pfd, err = l.k.OpenPidFDProcess(pid)
				if err == nil {
					master, err = l.k.GetFD(pfd, num)
				}
			}
			if err != nil {
				l.closeDup(pfd)
				continue
			}
			if pid != n.pid {
				inside, err := l.inRun(pid)
				poll := []unix.PollFd{{Fd: int32(pfd), Events: unix.POLLIN}}
				_, pe := unix.Poll(poll, 0)
				l.closeDup(pfd)
				if err != nil || !inside || pe != nil || poll[0].Revents != 0 {
					l.closeDup(master)
					continue
				}
			}
			slave, err := peerFromMaster(master, flags, index)
			l.closeDup(master)
			if err != nil {
				continue
			}
			l.deliverPty(n, slave, flags, p)
			_ = slave.Close() // owned relay result
			return true
		}
	}
	// No held master: continue to the Landlock layer, including for the inherited
	// controlling terminal. Its result is not guessed by this copied-path check.
	return false
}

func (l *Loop) builtinTTYOpen(n *notif, r *reader, p string, q pathQuery, flags int) bool {
	c := l.table.Load()
	if c.pol.Rules.Builtins == nil || l.observing() {
		return false
	}
	at, err := l.fsTarget(n, q)
	if n.gone {
		return true
	}
	if err != nil || !agent.OtherTTY(at) {
		return false
	}
	var st unix.Stat_t
	if unix.Stat(at, &st) == nil && c.ownTTY != 0 && st.Rdev == c.ownTTY {
		return false
	}
	reason := record.ReasonReadDenied
	if isWriteOpen(flags) {
		reason = record.ReasonWriteOutsideContract
	}
	d := fsDecided{rule: agent.BuiltinOtherTTY, verdict: record.VerdictRefused, reason: reason, enforce: true, floor: true}
	l.respond(n, respErrno(refusalErrno))
	l.emitFS(n, r, record.FSOpen, at, "", flags, d)
	return true
}

// DeliverPty lends an owned peer only for the atomic ADDFD/SEND operation.
func (k sysKernel) DeliverPty(id uint64, slave *sys.FD, flags int) error {
	_, err := k.ln.SendSeccompDescriptor(id, slave, flags&unix.O_CLOEXEC != 0)
	return err
}
