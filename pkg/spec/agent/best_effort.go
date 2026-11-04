// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"slices"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The stable ids of ADR 0041 D1's (D) cells: a rule, an action and a tier at which the supervisor decides on
// copied syscall facts and answers CONTINUE when it does not refuse, so a sibling thread can change what the
// kernel then acts on. Such a cell is disclosed, never counted as enforced: compile warns once per id
// (unenforced) and run_start lists the run's ids in best_effort (D7). A cell leaves the list when its action
// is completed race-free (D1's Stage B).
const (
	// BestEffortAppArmorNamespace discloses the administrator's explicit opt-in,
	// whether or not a particular open needed the assumption. Never implicit.
	BestEffortAppArmorNamespace = "apparmor/assumed-root-namespace"

	// BestEffortBuiltinIPC discloses the continued-datagram boundary of ADR 0113.
	BestEffortBuiltinIPC = "builtin.host_ipc/datagram"
	// BestEffortGateFSReadOpen: an open an `fs.read matches` gate scores, continued when it allows.
	BestEffortGateFSReadOpen = "gate.fs.read/open"
	// BestEffortGateFSReadMove: the source of a rename or hard link, scored with the read predicates on its
	// copied name (ADR 0041 Step 4), as the directory it may be too (an end the decision's stat finds no directory is
	// matched by its name, RD4-3), and continued when it allows.
	BestEffortGateFSReadMove = "gate.fs.read/move"
	// BestEffortGateFSReadOPath: under `gate.completion: held`, an O_PATH open an `fs.read matches` gate scores,
	// continued when it allows: ADDFD cannot deliver an O_PATH descriptor, and one reads nothing (every access to
	// contents through it is another open, held).
	BestEffortGateFSReadOPath = "gate.fs.read/o_path"
	// BestEffortGateFSWriteOpen: a write-open an `fs.write outside worktree` gate scores, continued when it
	// allows.
	BestEffortGateFSWriteOpen = "gate.fs.write/open"
	// BestEffortGateFSWriteMutation: a non-open mutation (unlink, rename, link, symlink, mkdir, mknod,
	// truncate) and the attribute changes (the chmod, chown and xattr families, a POSIX ACL included) under a write
	// gate: the plane decides none of them by a gate predicate.
	BestEffortGateFSWriteMutation = "gate.fs.write/mutation"
	// BestEffortGateExec: an exec an `exec matches` gate scores, image and argv; the kernel re-reads argv.
	BestEffortGateExec = "gate.exec"
	// BestEffortGateNetUnixDatagram: an addressed unix datagram a `net to undeclared host` gate scores, never
	// relayed (it would leave with tego's credentials and cwd).
	BestEffortGateNetUnixDatagram = "gate.net/unix-datagram"
	// BestEffortGateNetUnixConnect: a unix connect a `net to undeclared host` gate scores under a contract
	// with no net: section, which has no relay as the agent to hold it to.
	BestEffortGateNetUnixConnect = "gate.net/unix-connect"
	// BestEffortDenyWrite: a write to a built-in deny_write target (agent-contract R20) at a tier no kernel
	// decision plane decides (tier landlock, tier cgroup on the fanotify listener), refused by the supervisor on
	// its copied pathname (supervisor R15c) and continued otherwise: fs.assurance's default (ADR 0041 D1 (a)).
	BestEffortDenyWrite = "deny_write/default"
	// BestEffortUserDenyWrite: a modification at or beneath an fs.deny_write entry (ADR 0071) at a tier no kernel
	// decision plane decides, refused by the supervisor on its copied pathname (supervisor R15c) as BestEffortDenyWrite's
	// targets are, and listed apart from them, since the entries are the contract's own. Blocked for ordinary commands;
	// not race-free at the no-root tier.
	BestEffortUserDenyWrite = "fs.deny_write"
	// BestEffortExecRules: an exec the command rules allow (exec.allow words, an unmatched deny or ask list), decided
	// on the supervisor's copy of argv and names and continued; the kernel copies them again (ADR 0048 (6)). Listed
	// at every tier, except in a run whose handle claims exec pins (ADR 0048 (7)): there the kernel holds each exec to
	// the decided facts.
	BestEffortExecRules = "exec.rules/argv"
	// BestEffortHostSocketsRoot: the unix-only state of a contract with no net: section (ADR 0070,
	// RuleTable.HostSocketsRefused) at tier cgroup or bpflsm. Kernel raw-name checks do not decide every unix
	// destination for it yet: the cgroup unix programs and the decision plane's unix hooks hold no row for such a
	// contract. A plane leaves connect, sendto and sendmsg notified (it narrows only the fs notifications, enforce-plane
	// R22, R27), so the state rests on what carries it at tier landlock: the supervisor's relay of every connect and of
	// the addressed datagrams it can reproduce (supervisor R7b), the abstract scope from Landlock ABI 6 and
	// RESOLVE_UNIX from ABI 9, and the datagram residual BestEffortHostSocketsDatagram names. Listed at the root tiers
	// in that cell's place on every unix connect and send; immutable name programs do not remove its alias residual (ADR 0113).
	BestEffortHostSocketsRoot = "host_sockets/root-tier"
	// BestEffortHostSocketsDatagram: the unix-only state at tier landlock (ADR 0070). The supervisor relays on its
	// duplicate every connect, every Fast-Open send, every send on a stream socket without a peer and every addressed
	// datagram it can reproduce exactly, and answers an addressed send on a connected unix stream socket with the
	// kernel's own EISCONN; on a connected IP stream socket, whose address the kernel ignores, it sends the payload to
	// the peer where it can reproduce the call. What it continues instead — an unaddressed sendmsg, a sendmmsg batch, an
	// addressed datagram with ancillary data, MSG_MORE or a payload past what it copies, an addressed send on a
	// connected seqpacket socket (whose receiver reads the sender's pid in SCM_CREDENTIALS, which no relay gives), and
	// one on a connected IP stream socket with ancillary data, MSG_ZEROCOPY or a payload past what it copies — the
	// kernel sends from the agent's own memory and descriptor table, so a sibling thread that writes a host socket's
	// name there and dup2s a unix datagram socket onto the descriptor reaches it where no Landlock right refuses it:
	// below ABI 9 for a pathname (RESOLVE_UNIX), below ABI 6 for an abstract name (the scope). The agent chooses the
	// shape of its own calls, so it can choose a continued one: the cell holds for every run of the tier, not only for
	// a rare program. Only a datagram receiver is reachable so (the journal, syslog): the kernel refuses a datagram to
	// a stream or seqpacket socket.
	BestEffortHostSocketsDatagram = "host_sockets/datagram"
)

// bestEffortWhy is the compile warning's text for each id.
var bestEffortWhy = map[string]string{
	BestEffortAppArmorNamespace: "fs.apparmor_assume_root_namespace accepts the risk of bypassing hidden ancestor restrictions when AppArmor namespace depth is unreadable; an administrator must establish root policy-namespace visibility outside the container",

	BestEffortBuiltinIPC: "a continued datagram re-reads the address and descriptor; the kernel name checks cover protected names where attached, but aliases and unsupported send shapes remain best effort without a native peer plane",
	BestEffortGateFSReadOpen: "an open the fs.read gate allows is continued, and the kernel reads its pathname again, " +
		"so a sibling thread can open another name than the one scored",
	BestEffortGateFSReadMove: "a rename or hard link source the fs.read gate allows is continued on its copied name",
	BestEffortGateFSReadOPath: "an O_PATH open the fs.read gate allows is continued on its copied name (no descriptor " +
		"delivery carries O_PATH); it reads nothing, and an open of contents through it is held",
	BestEffortGateFSWriteOpen: "a write-open the fs.write gate allows is continued, and the kernel reads its pathname " +
		"again, so a sibling thread can open another name than the one scored",
	BestEffortGateFSWriteMutation: "unlink, rename, link, symlink, mkdir, mknod, truncate, chmod, chown and xattr " +
		"changes under the fs.write gate are scored on copied names and continued; no kernel layer evaluates a gate " +
		"predicate",
	BestEffortGateExec: "an exec the exec gate allows is continued, and the kernel reads its image path and argv again",
	BestEffortGateNetUnixDatagram: "an addressed unix datagram the net gate allows is continued, never relayed, " +
		"so the kernel reads its address again",
	BestEffortGateNetUnixConnect: "with no net: section and host_sockets: true, a unix connect the net gate allows " +
		"is continued, so the kernel reads its address again",
	BestEffortHostSocketsDatagram: "with no net: section a send the supervisor does not relay (an unaddressed " +
		"sendmsg, a sendmmsg batch, one with ancillary data or MSG_MORE, or an addressed send on a connected " +
		"seqpacket socket) is continued, so below Landlock ABI 9 a sibling thread that rewrites its address " +
		"and swaps a unix datagram socket onto its descriptor can reach a host datagram socket such as the journal's; no " +
		"stream daemon (docker.sock, the session bus, an SSH or gpg agent) is reachable so",
	BestEffortHostSocketsRoot: "with no net: section the supervisor's relay and Landlock refuse outside sockets, as at tier landlock; " +
		"root tiers also carry immutable Unix name checks, but those programs do not establish a peer inode for every alias, " +
		"and a send the supervisor continues can re-read a changed destination: best effort at the root tiers for aliases and unsupported datagrams",
}

// BestEffortCells are the ids of the table's (D) cells, in a fixed order (ADR 0041 D1, D7). A gate kind
// counts only when its rules can raise a complete action out of the allow band, to allow or above
// (gate.Policy.MayEscalate): one that cannot makes no decision a CONTINUE could carry. A read-write open and a
// move's source are scored by both fs kinds summed (gate.Policy.MayEscalateReadWrite), so they count when the two
// kinds' rules escalate only together. The cells are the same at every tier, since no kernel
// layer evaluates a gate predicate. A net gate's IP connects and sends are relayed (D6) and are no cell; its
// unix cells need a `net to undeclared host` rule, the only predicate a unix destination can match.
func (rt *RuleTable) BestEffortCells() []string {
	return rt.bestEffortCells(rt.GateOpensHeld(), false)
}

// NeedsOpenDeputy reports whether the run's held opens need the open deputy: the contract chose `gate.completion:
// held` and a gate fs kind, or the two together on a read-write open, can score an open to allow or above (ADR 0041
// Stage B), or the run holds its reads at its tier (fs.reads, ADR 0069). The runtime starts the deputy for such a
// table, and the Landlock tier grants it its exec.
func (rt *RuleTable) NeedsOpenDeputy() bool {
	return rt.GateOpensHeld() || rt.ReadsHeld()
}

// GateOpensHeld reports whether the gate's escalating fs opens are held (gate.completion: held, ADR 0041 Stage B): what
// takes the gate's open cells out of the best-effort list. Held reads complete read opens the same way, but the
// cells stay listed unless the gate chose held completion, never counted as enforced on a reading of the run's
// other keys.
func (rt *RuleTable) GateOpensHeld() bool {
	return rt != nil && rt.Gate.HeldCompletion() && rt.Gate.MayEscalateReadWrite()
}

// bestEffortCells is BestEffortCells with held saying whether the open deputy completes the escalating fs opens:
// their open cells then leave the list, and an fs.read gate's O_PATH opens, which stay copied, enter it; and with
// execPinned saying whether the kernel holds the run's execs to the decided facts (ADR 0048 (6)): exec.rules/argv
// and gate.exec then leave it.
func (rt *RuleTable) bestEffortCells(held, execPinned bool) []string {
	if rt == nil {
		return nil
	}
	var out []string
	if rt.Contract != nil && rt.Contract.FS != nil && rt.Contract.FS.AppArmorAssumeRootNamespace {
		out = append(out, BestEffortAppArmorNamespace)
	}
	if rt.ExecCommands.HasRules() && !execPinned {
		out = append(out, BestEffortExecRules)
	}
	if rt.Gate == nil {
		return out
	}
	g := rt.Gate
	// together: only an action both fs kinds score, a read-write open (a write-open) or a move's source, escalates.
	together := g.MayEscalateReadWrite() && !g.MayEscalate(gate.FSRead) && !g.MayEscalate(gate.FSWrite)
	if g.MayEscalate(gate.FSRead) {
		if held {
			out = append(out, BestEffortGateFSReadOPath, BestEffortGateFSReadMove)
		} else {
			out = append(out, BestEffortGateFSReadOpen, BestEffortGateFSReadMove)
		}
	} else if together {
		out = append(out, BestEffortGateFSReadMove)
	}
	if g.MayEscalate(gate.FSWrite) || together {
		if held {
			out = append(out, BestEffortGateFSWriteMutation)
		} else {
			out = append(out, BestEffortGateFSWriteOpen, BestEffortGateFSWriteMutation)
		}
	}
	if g.MayEscalate(gate.Exec) && !execPinned {
		out = append(out, BestEffortGateExec)
	}
	if g.MayEscalateBy(gate.NetUndeclared) {
		out = append(out, BestEffortGateNetUnixDatagram)
		if rt.HostSocketsOpened() {
			// In the unix-only state (ADR 0070) the connect is relayed as the agent, on the copy the gate scored.
			out = append(out, BestEffortGateNetUnixConnect)
		}
	}
	return out
}

// BestEffortCellsAt is run_start's best_effort for a run at tier whose decision plane is planeMode (run_start's
// decision_plane: "lsm" or "fmod_ret" where a plane mode decides, "fanotify" or "" where none does): the gate
// cells (BestEffortCells), then BestEffortDenyWrite when the table has built-in deny_write targets and
// BestEffortUserDenyWrite when it has fs.deny_write entries (ADR 0071), its fs.assurance is best effort, and no plane decides the run: tier landlock, or tier cgroup on its listener (ADR
// 0041 D1 (a)). Under fs.assurance: kernel such a run never starts; an observe run enforces nothing.
func (rt *RuleTable) BestEffortCellsAt(tier backend.Tier, planeMode string) []string {
	return rt.BestEffortCellsRun(tier, planeMode, false, false)
}

// BestEffortCellsRun is BestEffortCellsAt for a run whose open deputy serves its held opens (deputy): only then do
// the escalating fs open cells leave the list. A run whose contract chose held completion but whose deputy did not
// start lists them, as a run without the key does (ADR 0041, the degrade). execPinned is the run's handle's exec pin
// claim: exec.rules/argv and gate.exec leave the list only with it (ADR 0048 (6)).
func (rt *RuleTable) BestEffortCellsRun(tier backend.Tier, planeMode string, deputy, execPinned bool) []string {
	out := rt.bestEffortCells(deputy && rt.GateOpensHeld(), execPinned)
	if rt != nil && rt.Builtins != nil && !rt.HostSocketsRefused() && tier != backend.TierObserve && !(tier != backend.TierLandlock && (planeMode == "lsm" || planeMode == "fmod_ret")) {
		out = append(out, BestEffortBuiltinIPC)
	}
	if rt.HostSocketsRefused() && (tier == backend.TierCgroup || tier == backend.TierBPFLSM) {
		out = append(out, BestEffortHostSocketsRoot)
	}
	if rt.HostSocketsRefused() && tier == backend.TierLandlock {
		out = append(out, BestEffortHostSocketsDatagram)
	}
	if rt == nil || !rt.hasDenyWriteResidual() || rt.FilesystemAssurance() == FSAssuranceKernel {
		return out
	}
	noPlane := planeMode != record.DecisionPlaneLSM && planeMode != record.DecisionPlaneFmodRet
	if tier == backend.TierLandlock || (tier == backend.TierCgroup && noPlane) {
		builtIn, user := rt.denyWriteKinds()
		if builtIn {
			out = append(out, BestEffortDenyWrite)
		}
		if user {
			out = append(out, BestEffortUserDenyWrite)
		}
	}
	return out
}

// denyWriteKinds reports whether the table's deny_write rules hold a built-in target (R20) and an fs.deny_write entry
// (ADR 0071): each is its own best-effort cell.
func (rt *RuleTable) denyWriteKinds() (builtIn, user bool) {
	for i := range rt.DenyWrite {
		if rt.DenyWrite[i].BuiltinRule != "" && !rt.DenyWrite[i].Unenforced {
			continue
		}
		if !rt.DenyWrite[i].IsDeclaredDenyWrite() {
			builtIn = true
		} else {
			user = true
		}
	}
	return builtIn, user
}

// BestEffortCellsFor is compile --test's column for one row (ADR 0041 D7: "compile --test columns show the same"): the
// ids of tier's (D) cells (BestEffortCellsAt, with no decision plane at tier cgroup, since compile probes no machine)
// that got, the row's answer at tier, rests on. A gate's copied-fact decision is disclosed whatever it answered: a
// sibling thread can race a benign spelling, continued, to the one the row names, so a refusal the cell makes is as
// best effort as an allow it continues. exec.rules/argv stays an allow's cell, as SEMANTICS and ADR 0048 class it: a
// refused exec never runs (R), and the race to a refused argv goes through an allow of another, which the cell
// already names wherever the table has command rules. A refusal the floor made before the gate or the supervisor's target check
// (Landlock, the plane, the root model) rests on no cell. An observe column enforces nothing and lists none.
//
//   - gate cells: the row's kind is the cell's action, and the floor did not refuse it (EvaluateGateRow scored it, or
//     left an answer the floor allowed): a read-open, a write-open, a non-open mutation (delete, mkdir, rename), a
//     rename's source under a read gate, an exec, a unix connect;
//   - exec.rules/argv: an exec row a command rule decided (CommandRule) and did not refuse, whose argv the supervisor
//     copies and continues; an exec it refuses never runs, so that refusal is exact (ADR 0048, SEMANTICS);
//   - deny_write/default: a modification the row's answer refused under a built-in deny_write target's rule;
//   - fs.deny_write: one it refused under an fs.deny_write entry's rule (ADR 0071).
func (rt *RuleTable) BestEffortCellsFor(a Action, got EvalResult, tier backend.Tier) []string {
	if rt == nil || tier == backend.TierObserve || tier == "" {
		return nil
	}
	// As compile's own warnings read the table (BestEffortCells): under gate.completion: held the open deputy is taken
	// to serve the run, so the gate's open cells are not the row's (ADR 0041 Stage B); a run whose deputy did not start
	// lists them in its own best_effort.
	cells := rt.BestEffortCellsRun(tier, "", true, false)
	if len(cells) == 0 {
		return nil
	}
	floorRefused := got.Verdict == VerdictRefused && got.Score == nil
	var applies []string
	if !floorRefused {
		switch a.Kind {
		case ActionFSRead:
			applies = []string{BestEffortGateFSReadOpen}
		case ActionFSWrite:
			applies = []string{BestEffortGateFSWriteOpen}
		case ActionFSDelete, ActionFSMkdir, ActionFSAttr:
			applies = []string{BestEffortGateFSWriteMutation}
		case ActionFSRename, ActionFSLink:
			applies = []string{BestEffortGateFSReadMove, BestEffortGateFSWriteMutation}
		case ActionExec:
			applies = []string{BestEffortGateExec}
		case ActionNetConnect:
			if a.Proto == ProtoUnix || (a.Host == "" && a.Path != "") {
				applies = []string{BestEffortGateNetUnixConnect}
			}
		case ActionNetSend:
			// An IP datagram a net gate admits is relayed (D6), no cell; a unix one is continued.
			if a.Proto == ProtoUnix || (a.Host == "" && a.Path != "") {
				applies = []string{BestEffortGateNetUnixDatagram}
			}
		case ActionMapExec, ActionNetBind, ActionNetHTTP, ActionNetSocket, ActionExecAnon:
		}
	}
	// An exec a command rule refused never runs, so the refusal is exact and rests on no cell; the cell is an allow's
	// (and an ask's, whose approval continues the copy).
	if a.Kind == ActionExec && got.CommandRule != "" && got.Verdict != VerdictRefused {
		applies = append(applies, BestEffortExecRules)
	}
	if got.Verdict == VerdictRefused && got.Score == nil && slices.Contains([]ActionKind{ActionFSWrite, ActionFSDelete, ActionFSRename, ActionFSMkdir, ActionFSLink, ActionFSAttr}, a.Kind) {
		if id := rt.denyWriteCell(got.Rule); id != "" {
			applies = append(applies, id)
		}
	}
	if (a.Kind == ActionNetConnect || a.Kind == ActionNetSend) && (a.Proto == ProtoUnix || (a.Host == "" && a.Path != "")) {
		// The root tiers' supervisor-only unix-only state: its refusal and its admit alike (ADR 0070).
		applies = append(applies, BestEffortHostSocketsRoot)
	}
	if a.Kind == ActionNetSend && got.Verdict != VerdictRefused {
		// Tier landlock's unix-only state: a datagram it admits may be one it continues (ADR 0070); a refusal is exact.
		applies = append(applies, BestEffortHostSocketsDatagram, BestEffortBuiltinIPC)
	}
	var out []string
	for _, id := range cells {
		if slices.Contains(applies, id) {
			out = append(out, id)
		}
	}
	return out
}

// denyWriteCell is the best-effort cell of the deny_write rule named rule: BestEffortDenyWrite for a built-in target,
// BestEffortUserDenyWrite for an fs.deny_write entry, "" when rule names none.
func (rt *RuleTable) denyWriteCell(rule string) string {
	for i := range rt.DenyWrite {
		if r := &rt.DenyWrite[i]; rule != "" && r.RuleName() == rule {
			if !r.IsDeclaredDenyWrite() {
				return BestEffortDenyWrite
			}
			return BestEffortUserDenyWrite
		}
	}
	return ""
}

// warnBestEffort is D7's compile disclosure: one unenforced warning per (D) cell, at the gate, and a warning for a
// `completion: held` with no fs gate rule that can score an open to allow or above, which holds nothing.
func (k *compiler) warnBestEffort() {
	if k.rt.Gate.HeldCompletion() && !k.rt.GateOpensHeld() {
		k.ds.warnf(k.pos("gate"), CodeRedundantRule, "gate.completion: held holds nothing: no fs.read or fs.write gate rule "+
			"can score an open to allow or above (ADR 0041 Stage B)").
			fix("remove gate.completion, or add the fs gate rules it is meant to hold")
	}
	for _, id := range k.rt.BestEffortCells() {
		if id == BestEffortExecRules || id == BestEffortAppArmorNamespace {
			continue // disclosed by execCommandWarnings or the fs namespace opt-in warning
		}
		k.ds.warnf(k.pos("gate"), CodeUnenforced, "best effort (%s): %s; the cell is recorded in run_start best_effort "+
			"and never counted as enforced (ADR 0041 D1)", id, bestEffortWhy[id]).
			fix("treat this gate cell as advisory against a hostile agent; a contract list (fs.write, deny_read, exec, net) decides in the kernel")
	}
}
