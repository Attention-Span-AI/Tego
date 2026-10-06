// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// askReadOpen holds a read-open under an fs.ask_read entry for a person (POC 2026-10-06, SEMANTICS §6) and reports
// whether it answered the notification; false leaves it to settleFS, which continues it for the kernel to decide.
//
// The filter notifies every open of a table with such an entry (enforce-landlock's askRead arm), and the Landlock
// ruleset withholds the entry's reads exactly as a deny_read's, so whatever this loop continues the kernel refuses
// there. A read the model does not refuse read-denied cannot be one (decideFS walked it: it lies under no deny entry,
// or a write entry reopens it), and an O_PATH or O_DIRECTORY open reads no file's contents: each is continued as it
// would be without the entry. A candidate is pinned as an approved open's is (PrepareAskOpen: walked as the task,
// under its credentials, a regular file, named by the kernel's path for the pinned inode), and decided again on where
// it actually lies: the nearest entry deciding a read there must be an fs.ask_read entry, and anything else is
// continued, for the kernel to refuse or allow as it would have. A file in tego's own state is refused read-denied
// whatever entry is nearer (R6a), and one whose entry's pinned scope was replaced is refused ask-unavailable. A read
// gate can only escalate: its refusal refuses (fs-gate), and its score goes with the ask, which is then never
// remembered. The rest is held like an fs.ask write-open (completeHeldAskOpen) with op read, so the person, the
// ledger and a standing answer all see a read: an approval delivers a read-only descriptor of the pinned inode, an
// alternate a read-only descriptor of the person's file.
func (l *Loop) askReadOpen(n *notif, r *reader, q pathQuery, flags int, d fsDecided) bool {
	c := l.table.Load()
	if len(c.askRead) == 0 || !isRead(record.FSOpen, flags) || flags&(unix.O_PATH|unix.O_DIRECTORY) != 0 {
		return false
	}
	if d.verdict != record.VerdictRefused || d.reason != record.ReasonReadDenied {
		return false
	}
	k, ok := l.k.(askOpenKernel)
	if !ok {
		return false
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
		return false // no regular file the task reaches: the kernel answers the open, as it would have
	}
	defer l.closeDup(h.fd)
	rule := c.askReadRule(h.resolved)
	if rule == nil {
		return false
	}
	rt, name := c.pol.Rules, rule.RuleName()
	refuse := func(reason record.Reason, g *gate.Decision) {
		d := fsDecided{rule: name, verdict: record.VerdictRefused, reason: reason, enforce: true, gate: g}
		if g != nil {
			d.rule = g.Rule
		}
		lineAt := l.askLineName(n, q, h) // before the answer, which ends the notification
		l.respond(n, respErrno(refusalErrno))
		l.emitFS(n, r, record.FSOpen, lineAt, "", flags, d)
	}
	if ownStateOf(rt, h.resolved) != "" {
		refuse(record.ReasonReadDenied, nil)
		return true
	}
	if !l.askScopeValid(rule, h.resolved) {
		refuse(record.ReasonAskUnavailable, nil)
		return true
	}
	var gd *gate.Decision
	if rt.Gate.Has(gate.FSRead) {
		g := rt.Gate.Evaluate(gate.Ask, gate.Action{Kind: gate.FSRead, Complete: true, Path: h.resolved, Worktree: rt.Workdir})
		if copied := l.heldCopiedRefusal(n, r, q, flags); copied != nil {
			g = *copied
		}
		if g.Verdict == gate.Refused {
			refuse(record.ReasonFSGate, &g)
			return true
		}
		gd = &g
	}
	return l.completeHeldAskOpen(n, r, q, flags, h, name, gd, rule, ask.OpRead)
}

// askReadRule is the fs.ask_read entry that decides a read of p, the kernel's path for a pinned file: the nearest
// entry deciding a read there (a write or a deny_read entry, at its resolved path), when it is an fs.ask_read entry,
// and nil otherwise. A deny_read nested in the entry, or a write entry that reopens part of it, is nearer and wins.
func (c *compiled) askReadRule(p string) *agent.FSRule {
	near := decide.NearestWhere(c.fsResolved, p, func(r *decide.AdvisoryRule) bool { return r.Write || r.DenyRead })
	if near == nil || !near.AskRead {
		return nil
	}
	for i := range c.askRead {
		if r := &c.askRead[i]; decide.TrimDir(r.Governed()) == near.Path {
			return r
		}
	}
	return nil
}

// quietRead reports whether a read-open this loop neither held nor refuses gets no line: the filter notified it only
// because the table holds reads (askRead: an fs.ask_read entry, or held reads, ADR 0069 D2) or records a refused one
// (reason reads, ADR 0077), and the record mode keeps no read (summary or off) and no read gate scores one. It is
// answered as the filter would have let it pass, CONTINUE, so neither an fs.ask_read entry, held reads nor reason reads
// change what a summary run records of an allowed read nor the gap that says its reads are not recorded (SEMANTICS §7,
// ADR 0069 D4). In a held run that is an O_PATH open, which held reads leave as it was
// (readCapable), beneath a deny_read or not: it reads nothing, and no tier records one under summary. A
// read the model refuses is still recorded: the kernel refuses it, and its line is the refusal's.
func (l *Loop) quietRead(flags int, d fsDecided) bool {
	c := l.table.Load()
	return (len(c.askRead) > 0 || c.heldReads != nil || c.reasonReads) && c.record != agent.RecordFull && !c.pol.Rules.Gate.Has(gate.FSRead) &&
		isRead(record.FSOpen, flags) && d.verdict != record.VerdictRefused && !d.enforce
}

// ownStateOf is the entry of rt.OwnState at or above p, "" when none: tego's own state, which no held read
// completes on and no alternate reaches.
func ownStateOf(rt *agent.RuleTable, p string) string {
	for _, own := range rt.OwnState {
		if agent.Covers(own, p) {
			return own
		}
	}
	return ""
}
