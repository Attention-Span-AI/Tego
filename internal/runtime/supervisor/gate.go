// SPDX-License-Identifier: Apache-2.0
//go:build amd64 || arm64

package supervisor

import (
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"net/netip"
	"path/filepath"
	"slices"
)

// openReads reports whether a write open also reads the file it opens: its access mode is not O_WRONLY (O_RDWR, or
// O_RDONLY with O_CREAT or O_TRUNC; decide.OpenReads), so the descriptor hands the agent the file's bytes. The gate
// scores such an open with the read predicates as well as the write ones (gate.md R1: under `fs.read matches
// "*.pem"` an O_RDWR open of out/x.pem, beneath a write
// entry, read what the same O_RDONLY open was refused). A mknod is recorded with such flags but opens nothing; gateFS
// leaves it out, and gateOpen and the held-open paths never see one.
func openReads(flags int) bool { return isWriteOpen(flags) && decide.OpenReads(flags) }

// openGated reports whether the gate scores an open with flags: a read open by the read predicates, a write open by
// the write ones and, when it reads too (openReads), by the read ones as well.
func openGated(p *gate.Policy, flags int) bool {
	if !isWriteOpen(flags) {
		return p.Has(gate.FSRead)
	}
	return p.Has(gate.FSWrite) || openReads(flags) && p.Has(gate.FSRead)
}

// openMayEscalate reports whether the gate's rules can score an open with flags to allow or above, by the kinds
// openGated scores it with (gate.Policy.MayEscalate): such an open is held under gate.completion: held (ADR 0041 Step
// 8). A read-write open sums both kinds' scores (scoreOpen), so it escalates when either kind can or both together
// can (gate.Policy.MayEscalateReadWrite).
func openMayEscalate(p *gate.Policy, flags int) bool {
	if !isWriteOpen(flags) {
		return p.MayEscalate(gate.FSRead)
	}
	if openReads(flags) {
		return p.MayEscalateReadWrite()
	}
	return p.MayEscalate(gate.FSWrite)
}

// scoreOpen is the gate's decision at floor on an open of path, which the kernel names, with flags: the read
// predicates for a read open, the write ones for a write open and, when it reads too (openReads), the read and the
// write ones together, their scores summed as one action's are (ADR 0007, 2026-10-20). It is how the agent's own
// open of path is scored (gateFS), so a held target and an alternate are scored alike.
func scoreOpen(p *gate.Policy, floor gate.Verdict, path string, flags int, worktree string) gate.Decision {
	a := gate.Action{Kind: gate.FSWrite, Reads: openReads(flags), Complete: true, Path: path, Worktree: worktree}
	if !isWriteOpen(flags) {
		a.Kind = gate.FSRead
	}
	return p.Evaluate(floor, a)
}

func gatePayload(d *gate.Decision, unsupported bool) GateFields {
	if d == nil {
		return GateFields{}
	}
	outcome := "allow"
	if d.Verdict == gate.Ask {
		outcome = "ask"
	}
	if d.Verdict == gate.Refused {
		outcome = "refused"
	}
	return GateFields{Score: &d.Score, GateRule: d.Rule, GateOutcome: outcome, GateFacts: "copied_syscall", CompletionUnsupported: unsupported}
}
func (c *compiled) gateFS(op, p, p2 string, flags int, d fsDecided, complete bool) fsDecided {
	if d.gate != nil {
		return d
	}
	kind := gate.FSWrite
	if isRead(op, flags) {
		kind = gate.FSRead
	}
	policy := c.pol.Rules.Gate
	move := op == record.FSRename || op == record.FSLink
	// A write-open whose access mode is not O_WRONLY (O_RDWR; O_RDONLY with O_CREAT or O_TRUNC) reads the file
	// too, so the read predicates score it as well as the write ones (gate.md R1, amended 2026-10-16). A mknod is
	// recorded as an O_CREAT|O_EXCL open whose access mode reads O_RDONLY, but it opens and reads nothing.
	reads := op == record.FSOpen && !d.mknod && openReads(flags)
	// A refusal the floor made stands, and the gate adds nothing to it: unless it is one this loop does not enforce (an
	// advisory verdict on the spelling, continued for the kernel to decide) and the gate has no facts for the action.
	// The kernel may allow what the spelling's verdict refused (an unlinked file reopened read-write through
	// /proc/self/fd, whose spelling no write entry names and whose inode Landlock finds beneath one), so a gate without
	// facts refuses it unreadable rather than let it through unscored.
	floorRefused := d.verdict == record.VerdictRefused && (d.enforce || complete)
	if !(policy.Has(kind) || (move || reads) && policy.Has(gate.FSRead)) || floorRefused {
		return d
	}
	complete = complete && filepath.IsAbs(c.pol.Rules.Workdir)
	// A write-open that reads (above) is scored by the read predicates as well as the write ones, also when the gate
	// has no write predicate. The end of a move or hard link that leaves its name gives
	// the file a name an `fs.read matches` glob may not match, and a later read-open of it is scored under that name,
	// so the source, and the destination too under RENAME_EXCHANGE, is scored by the read predicates as well (ADR
	// 0041 Step 4); a destination that only receives a name reads nothing. A move or hard link is one call, one line
	// and one verdict, so it is one action over both its ends: every rule that matches an end it scores counts once and
	// the scores sum (gate.Action.Reads and Dest; ADR 0007, 2026-10-20).
	a := gate.Action{Kind: kind, Reads: reads || move, Complete: complete && filepath.IsAbs(p), Path: p, Worktree: c.pol.Rules.Workdir}
	if move {
		a.Dest, a.DestReads = p2, d.exchange
		a.PathNotDir, a.DestNotDir = d.srcNotDir, d.dstNotDir
		a.Complete = a.Complete && filepath.IsAbs(p2)
	}
	g := policy.Evaluate(gate.Allow, a)
	d.gate = &g
	if g.Verdict != gate.Allow {
		d.verdict = record.VerdictRefused
		d.reason = record.ReasonFSGate
		d.enforce = true
		d.rule = g.Rule
		d.unsupported = g.Verdict == gate.Ask
	}
	return d
}

func (l *Loop) gateNet(c *compiled, r *reader, d dest, proto string, dec verdictOf, floor gate.Verdict) (verdictOf, *gate.Decision) {
	p := c.pol.Rules.Gate
	if !p.Has(gate.Net) || floor == gate.Refused {
		return dec, nil
	}
	complete := r.ok() && d.ok
	a := gate.Action{Kind: gate.Net, Complete: complete, Declared: dec.rule != ruleUnmatched && dec.rule != "" && !agent.IsRuntimeRule(dec.rule), Host: dec.host}
	addHosts := func(hosts ...string) {
		for _, host := range hosts {
			if host == "" || slices.Contains(a.Hosts, host) {
				continue
			}
			if len(a.Hosts) == gate.MaxRules {
				a.Complete = false
				return
			}
			a.Hosts = append(a.Hosts, host)
		}
	}
	switch {
	case d.isInet():
		a.Host = d.ap.Addr().Unmap().String()
		a.Port = d.ap.Port()
		a.ThisHost = thisHost
		if resolver, ok := c.pol.Resolver.(interface {
			GateHosts(netip.AddrPort, string) ([]string, bool)
		}); ok {
			hosts, all := resolver.GateHosts(d.ap, proto)
			addHosts(hosts...)
			a.Complete = a.Complete && all
		} else {
			live, ok := c.pol.Resolver.(liveRules)
			switch {
			case ok:
				for _, nr := range live.Refreshed(c.pol.Rules.Net) {
					if nr.Host == "" || !agent.ProtocolMatches(nr.Proto, proto) {
						continue
					}
					if nr.Port == 0 {
						if d.ap.Port() != 0 && proto != protoRaw {
							continue
						}
					} else if nr.Port != int(d.ap.Port()) {
						continue
					}
					for _, ip := range nr.IPs {
						if ip.Unmap() == d.unzoned().ap.Addr().Unmap() {
							addHosts(nr.Host)
							break
						}
					}
				}
			case dec.host != "":
				addHosts(dec.host)
			}
		}
		if dec.host != "" {
			addHosts(dec.host)
		}
		if resolver, ok := l.askResolver.(interface {
			GateHosts(netip.AddrPort, string) ([]string, bool)
		}); ok {
			hosts, all := resolver.GateHosts(d.ap, proto)
			addHosts(hosts...)
			a.Complete = a.Complete && all
		}

	case d.isUnix():
		a.Host = ""
		a.Port = 0
	default:
		a.Complete = false
	}
	g := p.Evaluate(floor, a)
	dec.gate = &g
	if g.Verdict == gate.Refused {
		dec.allowed = false
		dec.continued = false
		dec.rule = g.Rule
		dec.kernelReason = record.ReasonNetGate
	}
	return dec, &g
}

func (l *Loop) gateExec(c *compiled, d execDecision, p, invocation string, argv []string, complete bool) execDecision {
	if !c.pol.Rules.Gate.Has(gate.Exec) || d.verdict == record.VerdictRefused {
		return d
	}
	g := c.pol.Rules.Gate.Evaluate(gate.Allow, gate.Action{Kind: gate.Exec, Complete: complete, Executable: p, Invocation: invocation, Args: argv})
	d.gate = &g
	if g.Verdict != gate.Allow {
		d.verdict = record.VerdictRefused
		d.answer = respErrno(refusalErrno)
		d.reason = record.ReasonExecGate
		d.rule = g.Rule
		d.unsupported = g.Verdict == gate.Ask
		d.search = false
	}
	return d
}

// gateOpen completes only an originally allowed read/write open which the gate
// raised to ask. Static refusals, protected paths and non-regular objects never
// acquire authority from the score. The held OFD and original credentials are
// reused by the same atomic ADDFD delivery path as a scoped fs.write ask.
func (l *Loop) gateOpen(n *notif, r *reader, q pathQuery, flags int, d fsDecided) (bool, fsDecided) {
	c := l.table.Load()
	// An open decideFS could not place (observed under path-unreliable: its walk failed) is gated too, as
	// settleFS gates it, so a walk that left no facts refuses as gate.unreadable (walkIncomplete, gate.md R1).
	unplaced := d.verdict == record.VerdictObserved && d.rule == rulePathUnreliable
	if !openGated(c.pol.Rules.Gate, flags) || (d.verdict != record.VerdictAllow && !unplaced) {
		return false, d
	}
	end := fsEnd{p: q.joined, q: q}
	target := l.landed(n, end)
	d = c.gateFS(record.FSOpen, target, "", flags, d, r.ok() && r.unreadPath == "" && !l.gateFactsIncomplete(n, record.FSOpen, end, fsEnd{}, flags))
	if d.gate == nil || d.gate.Verdict != gate.Ask {
		return false, d
	}
	var h *heldAskOpen // the held object, once the open is pinned below
	refuse := func(reason record.Reason) {
		d.verdict = record.VerdictRefused
		d.enforce = true
		d.reason = reason
		lineAt := l.askLineName(n, q, h) // before the answer, which ends the notification
		l.respond(n, respErrno(refusalErrno))
		l.emitFS(n, r, record.FSOpen, lineAt, "", flags, d)
	}
	k, ok := l.k.(askOpenKernel)
	if !ok {
		refuse(record.ReasonAskUnavailable)
		return true, d
	}
	if !l.valid(n) {
		return true, d
	}
	h, err := k.PrepareAskOpen(q, flags)
	if !l.valid(n) {
		if h != nil {
			l.closeDup(h.fd)
		}
		return true, d
	}
	if err != nil {
		h = nil
		refuse(record.ReasonAskUnreadable)
		return true, d
	}
	defer l.closeDup(h.fd)
	if nearest := decide.NearestIn(c.fsResolved, h.resolved); nearest != nil && nearest.DenyRead {
		refuse(record.ReasonReadDenied)
		return true, d
	}
	_, v, _ := c.fsVerdictIn(c.fsResolved, h.resolved, record.FSOpen, flags, false)
	if v != record.VerdictAllow {
		refuse(record.ReasonFSGate)
		return true, d
	}
	if !isRead(record.FSOpen, flags) {
		if _, denied := c.denyWriteOpen(h.resolved, flags); denied {
			refuse(record.ReasonWriteOutsideContract)
			return true, d
		}
		if _, denied := c.pol.Rules.AskDenyWriteTarget(h.resolved, false); denied {
			refuse(record.ReasonWriteOutsideContract)
			return true, d
		}
	}
	// Re-evaluate the resolved held inode; a symlink spelling cannot pick a
	// lower score and the original denial remains a floor.
	held := scoreOpen(c.pol.Rules.Gate, gate.Allow, h.resolved, flags, c.pol.Rules.Workdir)
	if held.Score > d.gate.Score {
		d.gate = &held
		d.rule = held.Rule
	}
	if held.Verdict == gate.Refused {
		d.gate = &held
		d.rule = held.Rule
		refuse(record.ReasonFSGate)
		return true, d
	}
	return l.completeHeldAskOpen(n, r, q, flags, h, d.rule, d.gate, nil, record.FSOpen), d
}
