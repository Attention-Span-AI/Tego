// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Held reads (ADR 0069) put every read-capable open of a run whose table holds its reads (agent.RuleTable.ReadsHeld)
// through ADR 0041 Stage B's held completion (heldOpen), with or without a gate: the open deputy pins what the task's
// lookup reaches, the floors below refuse on that object, and the deputy opens it in the run. The Landlock ruleset
// cannot withhold a read beneath a write grant, and an answer of CONTINUE on the copied pathname loses to a sibling
// that rewrites the pathname or swaps a link after the check; the deputy's descriptor is the object checked.

// readCapable reports whether an open with flags can read what it opens (ADR 0069 D2): O_RDONLY, O_RDWR, a
// directory, O_CREAT with read access; every open but O_WRONLY and O_PATH, which held reads leave as they were (an
// O_PATH descriptor reads nothing, and every read through one is another open, held).
func readCapable(flags int) bool {
	return flags&unix.O_PATH == 0 && flags&unix.O_ACCMODE != unix.O_WRONLY
}

// gateHolds reports whether the gate holds an open with flags: gate.completion: held, and a kind the gate scores the
// open with can escalate (openMayEscalate; ADR 0041 Step 8).
func gateHolds(p *gate.Policy, flags int) bool {
	return p.HeldCompletion() && openMayEscalate(p, flags)
}

// readHeld reports whether this loop holds an open with flags as a read (ADR 0069 D2): the table holds its reads at
// the run's tier, a deputy serves the run, and the open can read.
func (l *Loop) readHeld(c *compiled, flags int) bool {
	return c.heldReads != nil && l.deputy != nil && readCapable(flags)
}

// heldReadFloors is ADR 0069 D3 on the pinned object of a held read-capable open, after the floor the copied path
// applies (heldFloors): the object lies at or beneath a deny_read entry the nearest entry deciding a read there,
// whether the Landlock ruleset enforces it or not (a), or a deny_read name rule covers it, whenever it was made (c)
// (decide.HeldReadIndex); or it lies in tego's own state (d), as no held read completes there (askReadOpen's rule
// too). Each refuses read-denied naming the entry. Every held read-capable open, in a run that holds its reads or
// not, is also refused when a live read or path block, or an Adjustable run's read fence refusal, covers the object
// (ADR 0125 decision 2), under that block's or fence entry's rule. A nameless object has no name to check, as
// Landlock's own check of it allows it.
func (l *Loop) heldReadFloors(h *heldPlan, c *compiled) bool {
	if !readCapable(h.flags) || h.resolved == "" {
		return true
	}
	if c.heldReads != nil {
		dir := h.st.Mode&unix.S_IFMT == unix.S_IFDIR
		if rule, refused := c.heldReads.Refusal(c.fsResolved, h.resolved, dir); refused {
			l.heldRefuse(h, rule, record.ReasonReadDenied, h.d.gate)
			return false
		}
	}
	// The live blocks hold on the object the deputy opened too, not only on the copied name fs.go checks first: a name
	// swapped for a symlink between that check and the deputy's lookup lands here. It only tightens.
	if e, ok := c.blocks().MatchPath(h.resolved, liveblock.AccessRead); ok {
		l.heldRefuse(h, e.Rule(), record.ReasonReadDenied, h.d.gate)
		return false
	}
	if c.heldReads != nil {
		if own := l.heldOwnState(c, h.resolved); own != "" {
			l.heldRefuse(h, "fs."+string(agent.FSDenyRead)+"["+own+"]", record.ReasonReadDenied, h.d.gate)
			return false
		}
	}
	// A read an Adjustable run's read fence entry reaches got here only because the entry is lifted: its line names
	// the entry, live.fence[read:<value>], never the contract rule (or none) the floor matched, as decide.Evaluate
	// names it (ADR 0125 decision 9).
	if rt := c.ruleTable(); rt.Adjustable() {
		if e, ok := rt.Live.For(agent.Action{Kind: agent.ActionFSRead, Path: h.resolved}); ok {
			h.d.rule = e.Rule()
		}
	}
	return true
}

// heldOwnState is (d): the entry of tego's own state (RuleTable.OwnState, Options.OwnState) that p lies at or beneath,
// "" for none, and "" too where the run is given p to read: beneath the run's own runtime directory (its reason file,
// its CODEX_HOME), or beneath a write entry that lies inside that state, nearer than it (the run's own CODEX_HOME grant;
// a project inside a ledger root compile left readable, ledger-readable).
func (l *Loop) heldOwnState(c *compiled, p string) string {
	rt := c.pol.Rules
	own := ownStateOf(rt, p)
	if own == "" {
		for _, o := range l.ownState {
			if agent.Covers(o, p) {
				own = o
				break
			}
		}
	}
	if own == "" {
		return ""
	}
	if l.runtimeDir != "" && agent.Covers(l.runtimeDir, p) {
		return ""
	}
	if w := decide.NearestWhere(c.fsResolved, p, func(r *decide.AdvisoryRule) bool { return r.Write }); w != nil && agent.Covers(own, w.Path) {
		return ""
	}
	return own
}

// heldQuiet reports whether a held open allowed or answered with the kernel's errno gets no line: it was held only
// because the run holds its reads, the record mode keeps no read (summary or off), no read gate scores it, and it
// only reads. Held reads change how a read is completed, never what the record keeps (quietRead's rule for
// fs.ask_read); a refusal always has its line.
func (l *Loop) heldQuiet(c *compiled, h *heldPlan) bool {
	rt := c.pol.Rules
	return c.heldReads != nil && c.record != agent.RecordFull && !gateHolds(rt.Gate, h.flags) && !rt.Gate.Has(gate.FSRead) &&
		isRead(record.FSOpen, h.flags)
}
