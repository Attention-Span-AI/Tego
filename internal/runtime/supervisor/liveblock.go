// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"net/netip"
	"strings"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Live blocks (Options.LiveBlocks, internal/liveblock, MinorLiveBlock) refuse, on top of the contract, the actions a
// person named while the run runs. They are decided here because this loop is where tier landlock already decides:
// a running agent's Landlock domain can be made stricter only by the agent itself, so nothing outside it can add a
// rule to it. They only tighten. Each check turns a decision this loop would continue, relay, or hold for a person
// into a refusal this loop answers itself (EACCES, never CONTINUE), with the rule live.block[<kind>:<value>]; a
// refusal this loop already makes keeps its own rule and errno, so a block of something the contract refuses
// changes nothing. Where a block exists and the action cannot be named well enough to tell (an unreadable pathname,
// a walk that failed in this process), the action is refused under that marker, fail closed, as R15c refuses such
// a modification while a deny_write target exists.
//
// What this does not reach is what the run's filter does not notify (docs/OPERATIONS.md, "Live blocks"): a read
// open outside record: full and held reads, I/O on a descriptor already open, a mapping, a chmod outside record:
// full, and at the root tiers an action the kernel plane decides without a notification. And like every decision
// this loop makes on a copied pathname, an exec or fs block is decided on this loop's walk of the name: a peer that
// repoints a symlink between that walk and the kernel's own lookup can reach a blocked file (the race R15c names). A
// connect on an IP socket is not raced: it is relayed on the duplicate, under every contract while a net block exists
// (liveRelays), and a unix one that is relayed is matched again where the relay's walk lands. What stays continued is
// stated in docs/OPERATIONS.md ("Live blocks"): an addressed datagram (R13b), and under host_sockets: true a connect on
// a socket of another domain, which keeps the agent's own credentials and Landlock scope.

// blocks is the run's live blocks now; nil when there are none, or the loop was built without them.
func (c *compiled) blocks() *liveblock.Set {
	if c == nil || c.live == nil {
		return nil
	}
	return c.live()
}

// liveRelays reports whether a net block narrows a contract that continues its connects (host_sockets: true, which
// decides nothing): every other contract relays them already. Such a contract's reason to continue, that any address a
// sibling swaps in after the check is one it admits (handleConnect), does not hold once a block refuses some of them. It
// asks HasNet, so a block that has ended or not begun keeps the relay, as it keeps the notification (Set.HasNet).
func (c *compiled) liveRelays() bool { return c.netOpen && !c.hostSockets && c.blocks().HasNet() }

// decidesFastOpen reports whether the address a Fast-Open send connects to is decided: under a net: section, and under
// a live net block whatever the contract. There a send with no address cannot simply be continued either, since a
// sibling can write one in for the kernel's own read (sendUnaddressed), and a batch cannot be relayed at all.
func (c *compiled) decidesFastOpen() bool { return !c.netOpen || c.blocks().HasNet() }

// liveExec is an exec's decision under the live blocks: one this loop would continue is refused when a block names
// the image by any name this loop has for it (the line's name, the pathname as spelled, the image's own path) or by
// its identity, and, while a program is blocked, when the walk named no image at all (walked false): it may be the
// blocked one. unmatched is the marker decideExec refuses an unread pathname under. Every other decision stands.
//
// A block that matches by link (liveblock.MatchLink: the rules editor's "Also apply now" of an exec.allow entry
// removed) is asked of the contract's own grant instead (entryGrants, from p, R6's spelling, and the walk's image):
// it refuses what the contract grants under the entry at its value, as the run fixed that grant when it started, and
// leaves every other exec to the contract. Where the contract holds no such entry, it matches the whole file.
func (c *compiled) liveExec(d execDecision, p string, names []string, img execImage, walked bool, unmatched string) execDecision {
	s := c.blocks()
	if !s.HasExec() || !d.answer.cont {
		return d
	}
	refused := func(rule string) execDecision {
		return execDecision{rule: rule, verdict: record.VerdictRefused, reason: record.ReasonExecNotAllowed, answer: respErrno(refusalErrno)}
	}
	clean := make([]string, 0, len(names))
	for _, n := range names {
		clean = append(clean, strings.TrimSuffix(n, deletedSuffix))
	}
	grant := func(value string) (bool, bool) { return c.entryGrants(value, p, img, walked) }
	if e, ok := s.MatchExec(clean, liveblock.FileID{Dev: img.id.dev, Ino: img.id.ino}, walked && img.id != (fileID{}), grant); ok {
		return refused(e.Rule())
	}
	if !walked {
		if unmatched == ruleUnmatched {
			unmatched = rulePathUnreliable
		}
		return refused(unmatched)
	}
	return d
}

// liveNet is a destination's decision under the live blocks: one admitted (relayed or continued) is refused when a
// block names it, and so is one refused only for want of an entry while the contract has a net.ask scope, which would
// otherwise ask a person (askConnect, askDatagram and askUnix ask only an unmatched destination). An IP destination is
// matched by its address and port, and by the declared host the contract's entry admitted it under; a unix one by its
// cleaned absolute name or its abstract bytes. Every other refusal stands.
func (c *compiled) liveNet(d dest, dec verdictOf) verdictOf {
	s := c.blocks()
	if !s.HasNet() {
		return dec
	}
	askable := !dec.allowed && dec.rule == ruleUnmatched && (len(c.pol.Rules.NetAsk) > 0 || len(c.unixAsk) > 0)
	if !dec.allowed && !askable {
		return dec
	}
	var (
		e  liveblock.Entry
		ok bool
	)
	switch {
	case d.isInet():
		e, ok = s.MatchInet(d.ap, dec.host, thisHost)
	case d.isUnix():
		name := dec.sockPath
		if name == "" && strings.HasPrefix(d.unixPath, "/") {
			name = cleanPath(d.unixPath)
		}
		e, ok = s.MatchUnix(name, d.abstract)
	}
	if !ok {
		return dec
	}
	return verdictOf{rule: e.Rule(), host: dec.host, sockPath: dec.sockPath}
}

// liveInetAsked is the refusal the live blocks make now of an IP destination a person is being asked, or was asked,
// about (performAskConnect, askDatagram): a block naming its address and port, or host, the declared host the ask
// scope or the gate's admission matched it under, matched as liveNet matches an admitted destination. liveNet sees the
// Set of the moment the connect or datagram was decided only, and without a host for a destination nothing admits, and
// a block can land while the person decides: it outranks their answer, as it outranks one about a held open
// (liveHeld), so the request is put to the Set before anyone is asked, again at each tick of the hold and once the
// answer is back, before anything is connected or sent; a UDP socket's remembered approval, at each datagram. The Set is loaded
// at each call. The refusal is liveNet's: the block's rule, refused net-not-allowed.
func (c *compiled) liveInetAsked(ap netip.AddrPort, host string) (verdictOf, bool) {
	e, ok := c.blocks().MatchInet(ap, host, thisHost)
	if !ok {
		return verdictOf{}, false
	}
	return verdictOf{rule: e.Rule(), host: host}, true
}

// liveUnixAsked is liveInetAsked for a unix connect held for a net.ask unix: scope (askUnix): a block naming an abstract
// name by its bytes, or a pathname by any of names (the scope's own spelling and place, the name as the task spelled it,
// cleaned and joined), as liveNet and liveUnixLanded name a unix destination. An approval is matched again where the
// relay's walk lands (liveUnixLanded); this is what takes a pending request back, and names the block in the refusal of
// one withdrawn.
func (c *compiled) liveUnixAsked(abstract []byte, names ...string) (verdictOf, bool) {
	s := c.blocks()
	if !s.HasNet() {
		return verdictOf{}, false
	}
	if len(abstract) > 0 {
		if e, ok := s.MatchUnix("", abstract); ok {
			return verdictOf{rule: e.Rule()}, true
		}
		return verdictOf{}, false
	}
	for _, name := range names {
		if name == "" {
			continue
		}
		if e, ok := s.MatchUnix(name, nil); ok {
			return verdictOf{rule: e.Rule(), sockPath: name}, true
		}
	}
	return verdictOf{}, false
}

// liveUnixLanded is a relayed unix connect's admission under the live blocks, where the relay's walk landed
// (relayUnixAs): a socket a block names by that resolved path is refused, whatever name reached it.
func (c *compiled) liveUnixLanded(dec verdictOf, resolved string) verdictOf {
	if !dec.allowed || resolved == "" {
		return dec
	}
	if e, ok := c.blocks().MatchUnix(resolved, nil); ok {
		return verdictOf{rule: e.Rule(), host: dec.host, sockPath: resolved}
	}
	return dec
}

// liveFS is an fs action's decision under the live blocks: one this loop does not refuse itself (an advisory verdict,
// continued for Landlock, an ask, a held open) is refused, enforced here, when a block of the action's access class
// (liveAccess) has a path that is an end's or an ancestor of it, each end matched by its line's name and where the
// task's own lookup lands (matchEnds, as denyWrite matches). A path block matches every action; a read block only an
// open that reads, or a move; a write block every action but a pure read. A rename's ends are matched as folders above
// a block too (MatchWithin), as denyWrite matches them: renaming a block's ancestor would carry the blocked files to a
// name no block names. While a block of the action's class exists, an end whose walk failed in this process, or a
// pathname that could not be read whole, is refused too, under that marker. A refusal this loop already enforces
// stands.
func (l *Loop) liveFS(n *notif, r *reader, op string, flags int, d fsDecided, ends ...fsEnd) fsDecided {
	s := l.table.Load().blocks()
	acc := liveAccess(op, flags, d.mknod)
	if !s.HasAccess(acc) || d.enforce {
		return d
	}
	moves := op == record.FSRename
	var hit liveblock.Entry
	_, ok, unwalked := l.matchEnds(n, ends, func(_ int, p string) (agent.FSRule, bool) {
		e, ok := s.MatchPath(p, acc)
		if !ok && moves {
			e, ok = s.MatchWithin(p, acc)
		}
		if ok {
			hit = e
		}
		return agent.FSRule{}, ok
	})
	reason := reasonFor(op)
	// An open refused for reading: a read, or an O_RDWR open a read block refuses for the read it makes.
	if isRead(op, flags) || ok && op == record.FSOpen && !d.mknod && hit.Kind.Access()&liveblock.AccessWrite == 0 {
		reason = record.ReasonReadDenied
	}
	switch {
	case ok:
		return fsDecided{rule: hit.Rule(), verdict: record.VerdictRefused, reason: reason, enforce: true}
	case unwalked:
		return fsDecided{rule: rulePathUnreliable, verdict: record.VerdictRefused, reason: reason, enforce: true}
	case r.unreadPath != "":
		return fsDecided{rule: r.unreadPath, verdict: record.VerdictRefused, reason: reason, enforce: true}
	}
	return d
}

// liveHeld is the refusal the live blocks make now of a held open of resolved, the held object's path, with the
// agent's flags: a block of the open's access class (liveAccess) at resolved or above it, named and reasoned as liveFS
// names an open's refusal. The checks before a person is asked (liveFS on the copied name, heldReadFloors on the
// deputy's pin) see the Set of that moment only, and a block can land while the person decides: it outranks their
// answer, as it outranks one about a held mutation (liveMutation), so a held open is put to it again once the answer
// came, before anything is opened (a read asked for 250 ms before Never allow's read block landed was approved after
// it, and the agent read the file the dashboard called never readable). The Set is loaded at each
// call. resolved "" (no held object) matches nothing.
func (c *compiled) liveHeld(resolved string, flags int) (fsDecided, bool) {
	if resolved == "" {
		return fsDecided{}, false
	}
	e, ok := c.blocks().MatchPath(resolved, liveAccess(record.FSOpen, flags, false))
	if !ok {
		return fsDecided{}, false
	}
	reason := reasonFor(record.FSOpen)
	if isRead(record.FSOpen, flags) || e.Kind.Access()&liveblock.AccessWrite == 0 {
		reason = record.ReasonReadDenied
	}
	return fsDecided{rule: e.Rule(), verdict: record.VerdictRefused, reason: reason, enforce: true}, true
}

// liveAccess is the access classes of an fs action a live path block is matched for (liveblock.Access, r7
// LIVE-NARROW):
//   - an open is a read when its access mode reads (decide.OpenReads: O_RDONLY, O_RDWR, an O_PATH open, which is
//     decided as the read decide.IsRead takes it for) and a write when it is a write-open (decide.IsWriteOpen:
//     O_WRONLY, O_RDWR, O_CREAT, O_TRUNC); an O_RDWR open or an O_RDONLY|O_CREAT one is both;
//   - a rename and a hard link are both: they change names, and they would give a file under a read block a name
//     outside it, which a later read would reach unrefused (the move SEMANTICS §2 says cannot take a file out of a
//     rule);
//   - every other action is a write: an unlink, a mkdir, a symlink's own name, a truncate, a mode, owner or xattr
//     change, and a mknod (recorded as an open with O_CREAT|O_EXCL, decided as decide.OpMknod; mknod marks the
//     open-shaped line of one), which makes a name and reads nothing.
//
// An open whose flags give neither class cannot occur (an access mode of O_WRONLY is a write-open); it is taken as
// both, fail closed.
func liveAccess(op string, flags int, mknod bool) liveblock.Access {
	switch {
	case op == record.FSRename || op == record.FSLink:
		return liveblock.AccessRead | liveblock.AccessWrite
	case op == record.FSOpen && !mknod:
		var acc liveblock.Access
		if decide.OpenReads(flags) {
			acc |= liveblock.AccessRead
		}
		if decide.IsWriteOpen(flags) {
			acc |= liveblock.AccessWrite
		}
		if acc == 0 {
			acc = liveblock.AccessRead | liveblock.AccessWrite
		}
		return acc
	}
	return liveblock.AccessWrite
}
