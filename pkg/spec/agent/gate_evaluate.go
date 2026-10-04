// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
)

// EvaluateGateRow applies a configured gate after the caller's pure tier floor.
// Its facts are hypothetical table values; it performs no DNS, file or process
// lookups and grants no live operation. The kernel-only evaluator stays intact.
//
// An fs.read row is a read-only open and an fs.write row a write-only one (the conformance actor's O_WRONLY), each
// scored with its own kind's predicates. A run scores an open that reads and writes (O_RDWR, or O_RDONLY with O_CREAT
// or O_TRUNC) with both kinds as one action, their scores summed (gate.md R1, amended 2026-10-16 and 2026-10-20),
// which no row states: its score is at least each of the two rows' scores for its path. A rename's or hard link's
// source is scored by both kinds summed as the run's is, and its two ends are one action, every matching rule counted
// once.
func EvaluateGateRow(rt *RuleTable, a Action, floor EvalResult) EvalResult {
	if rt == nil || rt.Gate == nil || floor.Verdict == VerdictRefused {
		return floor
	}
	g := gate.Action{Complete: true, Path: a.Path, Worktree: rt.Workdir, Executable: a.Path, Invocation: a.Path, Args: a.Argv, Host: a.Host, Declared: floor.Rule != UnmatchedRule && floor.Rule != UnresolvedRule && !IsRuntimeRule(floor.Rule)}
	unsupported := false
	switch a.Kind {
	case ActionFSRead:
		g.Kind = gate.FSRead
		g.Complete = filepath.IsAbs(a.Path) && filepath.IsAbs(rt.Workdir)
	case ActionFSWrite:
		g.Kind = gate.FSWrite
		g.Complete = filepath.IsAbs(a.Path) && filepath.IsAbs(rt.Workdir)
	case ActionFSDelete, ActionFSRename, ActionFSMkdir, ActionFSLink, ActionFSAttr:
		// A non-open mutation, a hard link's two ends and an attribute change included (supervisor gateFS scores each
		// as a write); its ask has no approval path.
		g.Kind = gate.FSWrite
		unsupported = true
		g.Complete = filepath.IsAbs(a.Path) && filepath.IsAbs(rt.Workdir)
	case ActionExec:
		if g.Executable == "" && len(a.Argv) > 0 {
			g.Executable = a.Argv[0]
		}
		if g.Invocation == "" && len(a.Argv) > 0 {
			g.Invocation = a.Argv[0]
		}
		for _, r := range rt.Exec {
			if r.RuleName() == floor.Rule && r.Path != "" {
				g.Executable = r.Path
				if r.Resolved != "" {
					g.Executable = r.Resolved
				}
				break
			}
		}
		g.Kind = gate.Exec
		unsupported = true
		g.Complete = g.Executable != "" && floor.Rule != UnresolvedRule
	case ActionNetConnect, ActionNetSend:
		// An unconnected send is gated as the connect to its destination (supervisor sendDecisionCtl); a datagram's
		// ask cannot complete.
		g.Kind = gate.Net
		g.Complete = (a.Host != "" || a.Proto == ProtoUnix || strings.HasPrefix(a.Path, "unix:")) && a.Port >= 0 && a.Port <= 65535
		g.Port = uint16(a.Port)
		// The row's destination as decide's evalNet reads it: a path with no host is a unix socket and no
		// proto is TCP. Matched raw, a row with no proto skipped every tcp:// alias the run's gateNet adds
		// from the socket's real proto, and a unix row was not unsupported.
		proto := strings.ToLower(a.Proto)
		if a.Host == "" && a.Path != "" {
			proto = ProtoUnix
		}
		if proto == "" {
			proto = ProtoTCP
		}
		unsupported = proto != ProtoTCP
		if ip, e := netip.ParseAddr(a.Host); e == nil {
			for _, nr := range append(append([]NetRule(nil), rt.Net...), rt.NetAsk...) {
				if !ProtocolMatches(nr.Proto, proto) || nr.Port != a.Port || nr.Host == "" {
					continue
				}
				for _, addr := range nr.IPs {
					if addr.Unmap() == ip.Unmap() && !slices.Contains(g.Hosts, nr.Host) {
						if len(g.Hosts) == gate.MaxRules {
							g.Complete = false
							break
						}
						g.Hosts = append(g.Hosts, nr.Host)
					}
				}
			}
		}
	default:
		return floor
	}
	// A rename's or a hard link's source leaves its name, so the read predicates score it too, as the run's gateFS
	// does (ADR 0041 Step 4): the read and write predicates score it as one action, their scores summed (ADR 0007,
	// 2026-10-20), and with no write predicates at all the read ones alone decide the row. A row has no
	// RENAME_EXCHANGE, so its destination only receives a name and reads nothing. The two ends are one action, every
	// rule that matches an end it scores counted once and the scores summed, as a run's gateFS scores them. Only a
	// directory has paths beneath it for a read rule's path pattern to match: the row's
	// object is one when it exists as one or the row says `dir: true` (Action.Dir), as a run stats its source.
	move := a.Kind == ActionFSRename || a.Kind == ActionFSLink
	g.Reads = move
	if move {
		g.Dest = a.DestPath
		g.PathNotDir = !a.Dir
		g.Complete = g.Complete && filepath.IsAbs(a.DestPath)
	}
	if !rt.Gate.Has(g.Kind) && !(move && rt.Gate.Has(gate.FSRead)) {
		return floor
	}
	f := gate.Allow
	if floor.Verdict == VerdictAsk {
		f = gate.Ask
	}
	d := rt.Gate.Evaluate(f, g)
	floor.Score = &d.Score
	floor.GateRule = d.Rule
	floor.GateOutcome = "allow"
	if d.Verdict == gate.Ask {
		floor.GateOutcome = "ask"
	}
	if d.Verdict == gate.Refused {
		floor.GateOutcome = "refused"
	}
	if d.Verdict == gate.Refused || d.Verdict == gate.Ask && unsupported {
		floor.Verdict = VerdictRefused
		floor.Rule = d.Rule
		floor.CompletionUnsupported = d.Verdict == gate.Ask && unsupported
		switch g.Kind {
		case gate.FSRead, gate.FSWrite:
			floor.Reason = record.ReasonFSGate
		case gate.Exec:
			floor.Reason = record.ReasonExecGate
		case gate.Net:
			floor.Reason = record.ReasonNetGate
		}
	} else if d.Verdict == gate.Ask {
		floor.Verdict = VerdictAsk
		floor.Rule = d.Rule
	}
	return floor
}

func gatePredicateText(r gate.Rule) string { return r.Text() }
