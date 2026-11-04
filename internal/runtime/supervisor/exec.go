// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// unattributedExec is what parent_exec_id carries when the parent cannot be identified: a re-parented
// orphan, or a parent that exited between the exec and this read (§4 handleExecve).
const unattributedExec = "unattributed"

// liveFenceRulePrefix begins every fence entry's rule, live.fence[<kind>:<value>] (liveblock.FenceRule).
const liveFenceRulePrefix = "live.fence["

// handleExecve decides and records one execve (R16, R16b). The argv is read under a byte budget with a
// truncation flag when the budget or the entry cap cut it short (R3, E10, E11).
func handleExecve(l *Loop, n *notif) {
	l.recordExec(n, atFDCWD, n.args[0], n.args[1], 0)
}

// handleExecveAt decides and records an execveat, including the AT_EMPTY_PATH form that names the binary
// by its descriptor alone.
func handleExecveAt(l *Loop, n *notif) {
	l.recordExec(n, int32(n.args[0]), n.args[1], n.args[2], int(int32(n.args[4])))
}

// recordExec reads an exec's pathname and argv, resolves the image it names as the task would, decides it
// and records one exec event (R16, R16b).
//
// This loop continues only an exec it matched to a grant; every other exec it refuses itself, with the
// errno it answers named by decideExec. Continuing a refused one and trusting Landlock's EXECUTE bit to
// refuse it too put `refused` in the ledger for execs that ran: an anonymous image (a memfd) is never
// seen by Landlock's file_open, a granted binary reached by another spelling than its entry's (its
// resolved path, a symlink to it, its own descriptor) is allowed by an inode rule the spelling did not
// match, and a directly-invoked ELF loader holds EXECUTE as some binary's PT_INTERP (SEMANTICS §4). A
// refusal this loop makes is true by construction; one it continues is decided by Landlock on the inode,
// which is what the match below is made on too.
func (l *Loop) recordExec(n *notif, dirfd int32, pathAddr, argvAddr uint64, flags int) {
	c := l.table.Load()
	r := l.newReader(n)
	q := pathQuery{tid: n.pid, dirfd: dirfd}.as(followLookup(flags&unix.AT_SYMLINK_NOFOLLOW != 0))
	if c.cmds != nil {
		// A run with command rules walks the exec's #! interpreters and a loader's program too: the task's root is opened
		// once for all of them (taskRoot), and closed here when the decision ends.
		q.root = &n.execRoot
		defer q.root.close()
	}
	// AT_EMPTY_PATH names the image by descriptor only when the pathname is empty: a non-empty pathname is
	// resolved as usual, whatever dirfd holds (fs/exec.c: getname_flags with LOOKUP_EMPTY). So the pathname
	// is read first; taking the descriptor on the flag alone let execveat(<fd of a granted binary>,
	// "/proc/self/fd/<memfd>", AT_EMPTY_PATH) be matched on one file while the kernel loaded another.
	//
	// R2 admits no exception: every read below is keyed by the tid, and only an ID_VALID after it says the
	// tid was still the task that trapped rather than a reused one (E3).
	if !l.valid(n) {
		return
	}
	var raw string
	unreadable, tooLong := false, false
	if pathAddr == 0 {
		unreadable = flags&unix.AT_EMPTY_PATH == 0 // a NULL pathname is EFAULT unless the descriptor names the image
	} else {
		var cut bool
		raw, cut = r.cstring(pathAddr, pathMax)
		unreadable = cut || (raw == "" && r.failed)
		// The kernel's getname answers ENAMETOOLONG once PATH_MAX bytes read with no NUL among them, and EFAULT
		// only when the read faults before that: a cut that read PATH_MAX bytes is the former.
		tooLong = cut && len(raw) >= pathMax-1
	}
	if !l.valid(n) {
		return
	}
	switch {
	case unreadable:
	case raw == "" && flags&unix.AT_EMPTY_PATH != 0:
		q.empty = true
	default:
		q.path = raw
		if raw != "" {
			q.joined = r.resolve(dirfd, raw)
		}
		if n.gone {
			return
		}
	}
	var (
		img  execImage
		ierr error = unix.EFAULT
	)
	if tooLong {
		ierr = unix.ENAMETOOLONG
	}
	// A run with command rules reads every image's #! line, through the walk's own descriptor (ADR 0048 (3)): any
	// ruled tool can be a script's interpreter, and the kernel runs it inside the same execve, with no notification of
	// its own.
	q.head = c.cmds != nil
	// A pinned run's pin names the image as the plane holds it (ADR 0048 (3) P2).
	q.kid = l.pinner != nil
	if !unreadable {
		if !l.valid(n) {
			return
		}
		img, ierr = l.k.ExecImage(q)
		if !l.valid(n) {
			return
		}
	}
	// A pathname that names nothing (R16b (0)): the walk, made as the task's own lookup makes it, met ENOENT or
	// ENOTDIR. The exec cannot happen, so the loop answers that errno itself and writes no line, at every record
	// level: nothing was named, decided or run, and a PATH search's misses (one execve per directory) otherwise read as
	// that many refusals or observations of one start. Answered rather than continued, a file created at the path after
	// the walk is a later syscall's, decided then. Every exec whose path names something keeps its decision below.
	if !unreadable && q.path != "" && execMissing(ierr) {
		l.missedExec(n, c, ierr)
		return
	}
	fileless := ierr == nil && img.fileless()
	// dropped is one fact of the exec (supervisor R16b), judged once on each image the walk reached for it: its own here, and
	// below what a run with command rules walks beyond it (execCommand.dropped). Every owner of the exec's line copies
	// this one value: this loop's line, the naming a kernel recorder's line takes, the fast handover's naming.
	dropped := ierr == nil && l.droppedImage(c, img)
	// The record names what was named: R6's spelling of a pathname, and the kernel's own spelling of an
	// image reached by descriptor or of an anonymous one. The latter keeps only the " (deleted)" marker
	// off and is never cleaned: a memfd's name is the agent's to choose and may hold "/" and "..", so a
	// cleaned "/memfd:/../usr/bin/python3" would put a disk path in the record that never ran.
	p := q.joined
	if q.empty || fileless {
		p = strings.TrimSuffix(img.link, deletedSuffix)
	} else if ierr == nil && img.here && img.linked && !strings.HasPrefix(p, "/") {
		// R6 could not name the pathname — its join to the cwd or dirfd passed PATH_MAX (""), or the cwd or
		// dirfd could not be read (the relative spelling) — while the walk from the task's own cwd or dirfd
		// reached a file: the line names that file, where the kernel's exec lands, not "" or a relative name.
		p = strings.TrimSuffix(img.link, deletedSuffix)
	}
	// name is what the line, and every owner of it, calls the image: p, except for a pathname with a ".." component,
	// which R6 cleans lexically while the kernel resolves it physically, so that "/grant/link/../x" spells /grant/x and
	// runs a file elsewhere. Such a pathname is named as fs lines name such an end (lineName): where its directory
	// landed, with its final component as spelled, never followed, so "/usr/lib/../bin/npx" names /usr/bin/npx and not
	// the npx-cli.js its link reaches (2s6-1, 2c6-1). The
	// name is the image walk's own (execImage.name), the walk the decision, the handover and the MCP match read, never a
	// second walk: a symlink the agent moved between two walks had the line name the declared server's file for the
	// agent's own image, and write an mcp line for a server that never started. A walk that could not name its
	// directory keeps the spelling.
	name := p
	if img.name != "" && !q.empty && !fileless {
		name = img.name
	}
	// Command rules disable the fast handover until the exec is decided, as an exec gate does (ADR 0048 (3)). So does
	// an anonymous image the run does not admit: the walk above has classified it, and decideExec refuses it exec-anon
	// as at tier 1 (SEMANTICS §4), where the plane's bprm_check refusal would name no entry.
	anonRefused := fileless && !c.execUnrestricted && !c.execAnonymous
	// So does a live block on a program (liveExec): the exec is decided here, never handed over undecided.
	// And so does an Adjustable run's exec fence entry, lifted or not: an exec a lift allows is named here after its
	// entry (fenceExecRule), never by the contract rule a plane would match (ADR 0125 decision 9).
	// And so does a running MCP relay: the handover returns before mcpRelayGate, so a plane that decides the run's execs
	// would otherwise run a relayed server the agent started around its shim (ADR 0126 §4 "The gate").
	if !anonRefused && !c.pol.Rules.Gate.Has(gate.Exec) && c.cmds == nil && !c.blocks().HasExec() && !c.fenceHasExec() && l.mcpRelayed == nil && l.kernelExecHandoff != nil && l.kernelExecHandoff() {
		l.handOverExec(n, r, c, name, raw, argvAddr, img, ierr == nil, !unreadable, fileless, dropped)
		return
	}
	unmatched := ruleUnmatched
	switch {
	case unreadable:
		unmatched = noteOr(r, ruleArgsUnreadable)
	case q.empty && ierr != nil:
		unmatched = rulePathUnreliable
	}
	// Decided on the name the line gives the image, never on the lexical clean of a ".." spelling, which names a file
	// the kernel does not run: an entry matched by spelling then covered a file the line does not name.
	d := c.decideExec(name, q.path, img, ierr, unmatched)
	// The kernel's exec open needs READ_FILE: an image beneath a name the deny_read enumeration did not grant at launch
	// is one the ruleset refuses, so it is refused here, never recorded allow (snapshotRead).
	if ierr == nil && d.verdict == record.VerdictAllow && !img.fileless() && l.snapshotRefuses != nil && l.snapshotRefuses(imageWhere(name, img, true)) {
		d = execDecision{rule: ruleDenyReadSnapshot, verdict: record.VerdictRefused, reason: record.ReasonReadDenied, answer: respErrno(refusalErrno)}
	}
	if c.cmds != nil && ierr != nil && d.answer.cont {
		d = unwalkedExec(d, ierr)
	}
	listener := false
	if ierr == nil {
		d, listener = c.listenerExec(d, img)
	}
	// The command rules (ADR 0048 (1), (3)): after the image floor, before the gate, on an exec whose walk reached an
	// image. What the exec loads beyond its own image (its #! chain, a directly-invoked loader's program) is walked
	// for every such exec that has a line, whatever the floor answers: it is a fact of the exec, which dropped judges,
	// and an observe run's would-be refusal runs it. The rules decide only an exec the floor allows: a lookup that
	// failed keeps its own errno and is never continued (unwalkedExec), and of a PATH-search candidate, a refused or
	// an observed exec only that walk is made (walkOnly), with no argv read past argv[0] for a guarded tool's
	// patterns (the whole staged read and match ran and were thrown away, and the line read argv again). Such an exec
	// with no line (quiet, below: no exec gate, record: off, not a refusal) is not walked, since
	// dropped is read only by a line; the rules leave its verdict as the floor gave it, so quiet is already known.
	var cmd execCommand
	stageGranted := false
	floorAllows := d.verdict == record.VerdictAllow
	lineless := !floorAllows && !c.pol.Rules.Gate.Has(gate.Exec) && !c.recording() && d.verdict != record.VerdictRefused
	// A pinned run walks every exec it may continue, line or not: the pin holds the kernel to the form that walk reads.
	if c.cmds != nil && ierr == nil && (!lineless || l.pinner != nil) {
		var ok bool
		if cmd, ok = l.decideCommand(c, n, r, q, raw, img, argvAddr, !floorAllows); !ok {
			return
		}
		dropped = dropped || cmd.dropped
		if !floorAllows {
			cmd = execCommand{}
		} else {
			var rule string
			cmd, rule = l.mcpStageGrant(c, n, r, cmd, img, argvAddr)
			if n.gone {
				return
			}
			if rule != "" {
				d.rule, stageGranted = rule, true
			}
		}
		if floorAllows && !stageGranted && cmd.refuses() {
			d, listener = commandDecision(cmd), false
			// An observe run enforces nothing: the would-be refusal runs (respond CONTINUEs, the line is stamped
			// observed), so run_end's exec_rules counts only what was actually refused, not what ran. The line still carries
			// the rule, so a learn or drift pass over the observe run reads it.
			if !c.pol.Observe {
				l.metrics.cmdRefused.Add(1)
				if cmd.res.Match == execmatch.MatchAmbiguous {
					l.metrics.cmdAmbiguous.Add(1)
				}
				if cmd.res.List == execmatch.ListAsk && !cmd.res.Unlisted {
					l.metrics.cmdAsked.Add(1)
				}
			}
		}
	}
	// A live block (liveExec) refuses an exec the floor, the command rules and the PATH search would continue; it comes
	// before the gate and the pin, so a blocked exec is neither scored nor pinned, and its line is this loop's.
	if live := c.liveExec(d, []string{name, raw, p, img.link}, img, ierr == nil && !unreadable, unmatched); live.rule != d.rule || live.verdict != d.verdict {
		d, listener = live, false
	}
	// A relayed MCP server starts only under the shim its relay admitted (ADR 0126 §4 "The gate").
	if relay, refused := l.mcpRelayGate(c, n, r, d, name, img, argvAddr); refused {
		d, listener = relay, false
	}
	if fr := c.fenceReadExec(d, []string{name, p, img.link}, img, ierr == nil && !unreadable, unmatched); fr.rule != d.rule || fr.verdict != d.verdict {
		d, listener = fr, false
	}
	// fenceNamed: an exec allowed only because its fence entry is lifted keeps this loop's line, named after the entry
	// (below, kernelOwned): the plane's recorder would name it by the plane's own rule, such as the #! interpreter's
	// exec[/bin/sh] or the folder's, which says the contract allowed what the live layer allowed (ADR 0125 decision 9;
	// seen at tier bpflsm in a root guest).
	if d.verdict == record.VerdictAllow && ierr == nil {
		d.rule = c.fenceExecRule(d.rule, name, img)
	}
	fenceNamed := d.verdict == record.VerdictAllow && strings.HasPrefix(d.rule, liveFenceRulePrefix)
	// record: off keeps the ledger to what was refused, and an exec nobody will record is not worth the
	// identity reads. Every verdict but a refusal is quiet when the run asked for refusals only: an allowed
	// exec, a PATH-search candidate (neither a refusal nor a decision, R28), and an observed one, such as an
	// unreadable pathname under a contract with no exec: section. An observe run's would-be refusal is still
	// VerdictRefused here (it is stamped observed when emitted), so it keeps its line.
	hasGate := c.pol.Rules.Gate.Has(gate.Exec)
	quiet := !hasGate && !c.recording() && d.verdict != record.VerdictRefused
	var (
		pid              = n.pid
		execID, parentID string
		argv             []string
		truncated        bool
	)
	if !quiet {
		// Ordinary recording copies up to 8192 pointers and 128 KiB. An enabled
		// gate instead scores a bounded copied vector while the notification is held;
		// neither vector claims the later kernel copy is immutable. Reads are bracketed (R2).
		switch {
		case hasGate:
			argv, truncated = r.argvLimited(argvAddr, gate.MaxText, gate.MaxArgs)
		case cmd.complete && cmd.argv != nil || cmd.staged && cmd.unreadable:
			// The command rules read the vector already, whole or to the bound (ADR 0048 (3)): the line carries that
			// copy, the one decided on.
			argv, truncated = cmd.argv, !cmd.complete
		default:
			argv, truncated = r.argv(argvAddr, c.argvMax)
		}
		if n.gone {
			return
		}
		// The identity reads happen while the target is still blocked, so /proc/<pid> is this exec's own
		// process; they are best-effort all the same.
		pid, execID, parentID = l.execIdentity(c, n)
		// R2's re-check for the identity: Tgid and ProcStat are keyed by the bare tid, after the last
		// ID_VALID of the path and argv reads, so only one after them says the tid was not reused (E3).
		if !l.valid(n) {
			return
		}
	}
	gatePath := p
	if ierr == nil && img.link != "" {
		gatePath = strings.TrimSuffix(img.link, deletedSuffix)
	}
	d = l.gateExec(c, d, gatePath, p, argv, !unreadable && !truncated && r.ok() && ierr == nil)
	if d.gate != nil && d.gate.Verdict != gate.Allow {
		listener = false
	}
	// In a pinned run every exec this loop continues carries its pin, written last before the answer (ADR 0048 (3)
	// P2); an exec whose pin cannot be written is refused, since the kernel would refuse or kill it.
	var (
		pinSeq     uint32
		pinRefused bool
	)
	if l.pinner != nil && d.answer.cont {
		var (
			seq uint32
			err error
		)
		if l.kernelExecHandoff == nil || !l.kernelExecHandoff() {
			// A pinned exec's line is the kernel's (ADR 0048 (8)): the recorder's exec record folded with the plane's
			// held or kill sample. With no recorder reading the run, a kill would have no line and this loop's allow
			// would stand for an exec the plane killed, so the exec is refused instead (fail closed).
			err = errPinNoKernelLine
		} else {
			seq, err = l.pinExec(c, n, r, dirfd, raw, img, cmd, argv, argvAddr)
		}
		if n.gone {
			return
		}
		if err != nil {
			l.log.Debug("exec pin", "tid", n.pid, "err", err)
			d, listener, pinRefused = pinRefusal(), false, true
			l.metrics.pinRefused.Add(1)
			if quiet {
				// A refusal always has its line, under record: off too.
				quiet = false
				pid, execID, parentID = l.execIdentity(c, n)
				if !l.valid(n) {
					return
				}
			}
		} else {
			pinSeq = seq
		}
	}
	// Capture one post-score ownership decision. The gate, the command rules and a running MCP relay each block fast
	// policy handover earlier; actual terminal readiness remains available for naming. Of a relayed run's exec that
	// keeps the handover's owner: the recorder writes the exec's line and a server's mcp line from this naming.
	terminalOwned := (hasGate || c.cmds != nil || l.mcpRelayed != nil) && d.verdict == record.VerdictAllow && d.answer.cont && l.kernelExecHandoff != nil && l.kernelExecHandoff()
	kernelOwned := !fenceNamed && d.verdict == record.VerdictAllow && d.answer.cont && (terminalOwned || l.kernelExecs != nil && l.kernelExecs())
	if listener {
		// Kept before the answer lets the kernel open the image, for the listener to find (ExecLine).
		l.execLines.put(n.pid, img.id)
	}
	if l.kernelExecHandoff != nil {
		// If a live recorder fails, the supervisor resumes ownership. Keep an
		// attempt marker so a later final ring drain cannot duplicate this line.
		if quiet {
			pid, _, _ = l.execIdentity(c, n)
		}
		_, ticks, err := l.k.ProcStat(pid)
		if !l.valid(n) {
			return
		}
		naming := ExecNaming{AttemptMonoNS: l.mono(), SupervisorOwned: true}
		// An exec the kernel's line records takes this loop's naming: one a gate or the command rules decided, and,
		// where the exec outcome links do not attach (no fast handover), one the plane decides (that line lost fileless
		// and dropped).
		if kernelOwned {
			cwd, _ := l.k.StatID(fmt.Sprintf("/proc/%d/cwd", n.pid))
			if !l.valid(n) {
				return
			}
			naming = ExecNaming{CwdDev: cwd.dev, CwdIno: cwd.ino, Path: name, RawPath: raw, Argv: argv, ExecID: execID, ParentExecID: parentID, ArgvTruncated: truncated, Fileless: fileless, Dropped: dropped, AttemptMonoNS: l.mono(), GateFields: gatePayload(d.gate, false)}
			if !truncated && ierr == nil {
				naming.MCPName = c.mcpServerOf(name, img, argv)
				naming.MCPPath = strings.TrimSuffix(img.link, deletedSuffix)
			}
			if cmd.decided || stageGranted {
				naming.CommandRule, naming.CommandList, naming.CommandMatch, naming.CommandVia, naming.ClosureOf = commandFields(cmd)
				naming.ArgvFacts, naming.ArgvRead = record.ArgvFactsCopied, cmd.res.K
			}
			if stageGranted {
				// Keep the kernel's actual exec outcome (including pin refusal/kill), with runtime provenance only
				// after it confirms the successful vector. A predicted seccomp allow must not hide a later kill.
				naming.RuntimeRule = d.rule
			}
			naming.PinSeq = pinSeq
		}
		l.execHanded.put(continuedExec{tid: n.pid, pid: pid, startNS: ticks * proc.NanosPerTick,
			named:  err == nil,
			naming: naming,
		})
	}
	// An observe run enforces nothing: respond turns a refusal into CONTINUE there (R30).
	l.respond(n, d.answer)
	if quiet {
		return
	}
	if kernelOwned {
		// The plane decides this exec in bprm_check, race-free on the image the kernel loads, and the kernel writes
		// its one line: the plane's refusal, or the exec record named by the plane's rule (R7a, TIER3-PLAN T9).
		// This loop's allow is a prediction the plane may overturn, so it writes none.
		if !terminalOwned {
			// A terminal handoff's naming carries the MCP server (MCPName), and the recorder writes its start line
			// after the exec's own (and, in a pinned run, only once the plane held the exec, ADR 0048 (8)).
			if server := c.mcpServerOf(name, img, argv); server != "" {
				l.emitMCP(n, pid, server, argv)
			}
		}
		return
	}
	ev := action(l.event(n, record.KindExec, record.SourceSeccomp), d.rule, d.verdict, d.reason)
	ev.PID = pid
	if d.gate != nil && d.gate.Verdict != gate.Allow {
		ev.Authority = record.AuthorityGate
	}
	payload := execPayload{
		ExecPayload: record.ExecPayload{
			Path: name, Argv: argv, ExecID: execID, ParentExecID: parentID,
		},
		ArgvTruncated: truncated,
		PathSearch:    d.search,
		Fileless:      fileless,
		Dropped:       dropped,
		GateFields:    gatePayload(d.gate, d.unsupported),
	}
	payload.PinUnavailable = pinRefused
	if cmd.decided || cmd.refuses() || stageGranted {
		// exec.ask is reserved: its refusal carries completion_unsupported as an unsupported gate ask does.
		payload.CompletionUnsupported = payload.CompletionUnsupported || d.unsupported
		ep := &payload.ExecPayload
		ep.CommandRule, ep.CommandList, ep.CommandMatch, ep.CommandVia, ep.ClosureOf = commandFields(cmd)
		ep.ArgvFacts, ep.ArgvRead = record.ArgvFactsCopied, len(cmd.argv)
	}
	l.emitFor(n, ev, payload)
	if d.verdict == record.VerdictAllow {
		if !hasGate {
			if server := c.mcpServerOf(name, img, argv); server != "" {
				l.emitMCP(n, pid, server, argv)
			}
		}
	}
}

// execMissing reports whether an exec's walk found nothing at its pathname: ENOENT (a component, or the final name,
// does not exist; a dangling symlink) or ENOTDIR (a component that is no directory), the kernel's own answer to such
// an exec. The task's lookup would fail there the same way, so nothing can run and nothing is decided (missedExec).
// A failure met at an automount point is not one (automountLookup): the task's own walk may mount what this walk did
// not.
func execMissing(err error) bool {
	var a automountLookup
	if errors.As(err, &a) {
		return false
	}
	return errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR)
}

// missedExec answers an exec whose pathname names nothing (execMissing) with the walk's errno and writes no line
// (R16b (0)): it counts in run_end.supervisor.exec_missing. Where a kernel recorder follows the run's execs it leaves
// the supervisor-owned marker every decided exec leaves, so the kernel's sample of the failed syscall is dropped, not
// written as an exec of its own. The answer is respMiss, no refusal, so an observe run answers the errno too (R30
// continues refusals only): continued, the kernel would look the path up again, and a file renamed into place between
// the walk and that lookup would run with no line, the marker having dropped the kernel's record of it.
func (l *Loop) missedExec(n *notif, c *compiled, err error) {
	l.metrics.execMissing.Add(1)
	if l.kernelExecHandoff != nil {
		pid, _, _ := l.execIdentity(c, n)
		_, ticks, perr := l.k.ProcStat(pid)
		if !l.valid(n) {
			return
		}
		l.execHanded.put(continuedExec{tid: n.pid, pid: pid, startNS: ticks * proc.NanosPerTick, named: perr == nil,
			naming: ExecNaming{AttemptMonoNS: l.mono(), SupervisorOwned: true}})
	}
	l.respond(n, respMiss(lookupErrno(err)))
}

// execIdentity resolves the process the exec belongs to and its exec id (<run>/<pid>/<start-boot-ns>,
// RUN-IDENTITY.md). The notification names the trapping thread, so the thread group is looked up first:
// after an execve from a non-leader thread the process keeps the group's pid, which is what the id must
// carry. Every step is best-effort; a failure costs an id component, never the event.
func (l *Loop) execIdentity(c *compiled, n *notif) (pid int, execID, parentID string) {
	pid = n.pid
	if tgid, err := l.k.Tgid(n.pid); err == nil && tgid > 0 {
		pid = tgid
	}
	parentID = unattributedExec
	ppid, start, err := l.k.ProcStat(pid)
	if err != nil {
		l.log.Debug("supervisor: exec identity", "pid", pid, "err", err)
		return pid, "", parentID
	}
	execID = execIDOf(c.pol.RunID, pid, start)
	if ppid <= 0 {
		return pid, execID, parentID
	}
	if _, pstart, perr := l.k.ProcStat(ppid); perr == nil {
		parentID = execIDOf(c.pol.RunID, ppid, pstart)
	}
	return pid, execID, parentID
}

// execIDOf builds <run>/<pid>/<start-boot-ns> from a starttime in USER_HZ ticks, the ~10 ms resolution
// /proc/<pid>/stat gives (E3). It goes through proc.ExecID, the constructor the tier-2 recorder uses for
// the kernel's exact start too, so both producers name one process with one id and a parent_exec_id
// written here matches an exec_id written there.
func execIDOf(run string, pid int, startTicks uint64) string {
	return string(proc.ExecID(identity.RunID(run), pid, startTicks*proc.NanosPerTick))
}

// execFile is a file exec entry at its symlink-resolved path, under its rule name.
type execFile struct{ path, name string }

// execDir is a directory exec entry at its resolved path, under its rule name, with the identity of the directory
// the Landlock builder bound its grant to when the loop first saw it (held, when it could be stat'ed).
type execDir struct {
	path, name string
	id         fileID
	held       bool
}

// resolveExecEntries fills the table's exec identities (execIDs, execDirs, and mcpIDs for a file entry that is a
// declared MCP server's command[0]): each entry's file, symlinks
// followed as the Landlock builder follows them when it opens the entry, and its resolved path. It runs
// once, in New, before the agent runs — when the Landlock builder bound EXECUTE to the same files — and the
// table is never rebuilt, so a symlink the agent later plants where an entry lies under its own write entry
// moves nothing. The identities are also the inodes the builder's grants are bound to (execHeld, a directory
// entry's id), which the no-gain rule and a directory entry's match ask by identity (execGrants, dirHeld).
func (l *Loop) resolveExecEntries(c *compiled) *compiled {
	c.statID = l.k.StatID
	c.execHeld = decide.HoldExecGrants(c.pol.Rules, func(p string) (decide.FileKey, error) {
		id, err := l.k.StatID(p)
		return decide.FileKey{Dev: id.dev, Ino: id.ino}, err
	})
	for i := range c.pol.Rules.Exec {
		e := &c.pol.Rules.Exec[i]
		if e.Path == "" {
			continue
		}
		if e.IsDir {
			d := execDir{path: trimDir(resolveDeclared(l.k, e.Path)), name: e.RuleName()}
			if id, err := l.k.StatID(d.path); err == nil {
				d.id, d.held = id, true
			}
			c.execDirs = append(c.execDirs, d)
			continue
		}
		if id, err := l.k.StatID(e.Path); err == nil {
			if c.execIDs == nil {
				c.execIDs = map[fileID][]execFile{}
			}
			resolved := resolveDeclared(l.k, e.Path)
			c.execIDs[id] = append(c.execIDs[id], execFile{path: resolved, name: e.RuleName()})
			if servers := c.mcp[cleanPath(e.Path)]; len(servers) > 0 && strings.Contains(e.Source, agent.ExecSourceMCP+":") {
				if c.mcpIDs == nil {
					c.mcpIDs = map[fileID][]mcpFile{}
				}
				c.mcpIDs[id] = append(c.mcpIDs[id], mcpFile{path: resolved, servers: servers})
			}
			if c.execPinned == nil {
				c.execPinned = map[string]bool{}
			}
			c.execPinned[e.Path] = true
		}
	}
	return c
}

// execDecision is one exec's verdict and the answer the loop gives the task.
type execDecision struct {
	rule    string
	verdict record.Verdict
	reason  record.Reason
	// search is the R28 case, which the event carries as path_search.
	search      bool
	answer      resp
	gate        *gate.Decision
	unsupported bool
}

// unwalkedExec is the answer, in a run with command rules, to an exec this loop would otherwise continue although its
// walk reached no image: a deny-list run allows an unmatched exec, a spelling can match a grant without a walk, and
// an exec with nothing to match is observed (decideExec). Continued, the kernel's own lookup could reach a file the
// walk did not (a symlink renamed into place between the two, a pathname mapped in after this read) and run it with
// no command rule deciding it (ADR 0048 (3)). So the loop answers the walk's own errno and nothing runs: a lookup the
// task would fail the same way keeps its errno (ELOOP, EFAULT for a pathname whose read faulted, ENAMETOOLONG for
// one with no NUL in PATH_MAX bytes), observed under the decision's rule; any other failure (EMFILE, ENOMEM, EXDEV)
// vouches for nothing and is refused path-unreliable, EACCES. A walk that met ENOENT or ENOTDIR never gets here: a
// pathname that names nothing is answered before any decision, with no line (missedExec, R16b (0)).
func unwalkedExec(d execDecision, err error) execDecision {
	if !execLookupFailure(err) {
		return execDecision{rule: rulePathUnreliable, verdict: record.VerdictRefused, reason: record.ReasonExecNotAllowed, answer: respErrno(refusalErrno)}
	}
	return execDecision{rule: d.rule, verdict: record.VerdictObserved, search: d.search, answer: respErrno(lookupErrno(err))}
}

// listenerExec is the verdict of an exec this loop continues at tier 2, where the fanotify listener decides the
// exec's open of its image as it decides every open (enforce-cgroup-observe R8): an image under a deny_read
// no longer write entry reopens is refused there, EPERM, whatever the exec entries and Landlock grant (an
// exec.allow directory inside a deny_read, a contract with no exec: section). The line then says refused,
// read-denied, under that deny_read (decide.ListenerOpenRefused, on where the image lies), and the loop
// still continues the exec: the refusal is the listener's, and so reports listener, and this line is the exec's
// one (the listener asks ExecLine and writes none). Tier bpflsm's plane refuses the same open, so its line is the
// same (TIER3-PLAN T11: it read allow there while the kernel refused). At tier 1 nothing refuses such an open.
func (c *compiled) listenerExec(d execDecision, img execImage) (_ execDecision, listener bool) {
	if d.verdict != record.VerdictAllow || !c.rootTier() || !img.here || img.fileless() {
		return d, false
	}
	if deny, ok := c.listenerOpenRefused(img.link); ok {
		d.rule, d.verdict, d.reason = deny.RuleName(), record.VerdictRefused, record.ReasonReadDenied
		return d, true
	}
	return d, false
}

// decideExec decides one exec from the spelling the task passed (p, R6's) and the image that spelling
// resolved to (img, or err when the walk failed). In order:
//
//   - An anonymous image is refused, rule exec-anon (R16b). No contract entry can name a
//     runtime-created memfd, and nothing below tier 3 governs one: Landlock's file_open allows an SB_NOUSER
//     file outright and tier 2's FAN_OPEN_EXEC_PERM sees no open. It comes first, before any spelling is
//     consulted, so no name — a PATH-search candidate's included — admits one. Under a contract with no
//     exec: section (SEMANTICS §1, deny nothing), or one that opted into exec.anonymous, it is allowed and
//     still recorded fileless. When exec is restricted the seccomp memfd arm has already refused the main
//     vector at creation, on every supported kernel, so this refusal is the record and the backstop for
//     anonymous images arriving by another route (SCM_RIGHTS, an inherited fd) — best effort, with the race
//     below.
//   - A granted exec is allowed and continued (execGranted). Landlock's EXECUTE bit decides the continued
//     syscall on the inode (R16). A walk that failed other than as the task's lookup would
//     (!execLookupFailure) matches no grant: its spelling was never verified, and an exec that falls through
//     to the last arm is refused under path-unreliable.
//   - A candidate of the run's own PATH search is observed (R28) and answered with its lookup's errno —
//     the refusal errno for a candidate that holds a file, or the errno of a walk that failed otherwise —
//     rather than continued, so a file planted at the candidate after this walk cannot be what the kernel
//     then loads. A directory that holds no such name, the common case, is a miss and never reaches this
//     function (missedExec, R16b (0)).
//   - With no exec: section, an exec under a deny_read tier 1 enforces is refused read-denied, as the
//     kernel refuses its exec open (execOpenRefused in decide.Evaluate), judged where the kernel spells the
//     image (imageWhere), so through a descriptor too. In a deny-list run, an image in the
//     run's own CODEX_HOME is refused codex-home-exec (inCodexHome, agent-contract.md R10a): a copy linked
//     there, judged where the kernel spells it (imageWhere), run by its path or through a descriptor. A copy
//     there opened, unlinked and run through its descriptor is fileless and takes the
//     fileless arm above, allowed in a deny-list run as a memfd copy is (R10a's stated residual; compile's
//     exec-rule-coverage says so). Anything else is allowed.
//   - Everything else is refused exec-not-allowed, answered by this loop (lookupErrno), never continued:
//     a refusal this loop continued was a claim Landlock had to make good, and for an anonymous image, a
//     granted binary's other spellings and a directly-invoked loader it did not.
//
// unmatched is the rule an unmatched exec is refused under: unmatched, or the marker for a pathname or
// descriptor that could not be read.
//
// raw is the pathname as the task passed it (empty for a descriptor): a spelling with a ".." component is
// never a PATH-search candidate. R6 cleans ".." lexically and the kernel resolves it physically, so
// /usr/local/bin/link/../python3, with link a symlink the agent made, cleans to a candidate while the kernel
// would load the python3 in the directory above link's target; a search's own spelling, PATH[j]/<basename>,
// has none.
func (c *compiled) decideExec(p, raw string, img execImage, err error, unmatched string) execDecision {
	refused := func(rule string, reason record.Reason) execDecision {
		return execDecision{rule: rule, verdict: record.VerdictRefused, reason: reason, answer: respErrno(lookupErrno(err))}
	}
	allowed := func(rule string) execDecision {
		return execDecision{rule: rule, verdict: record.VerdictAllow, answer: respContinue()}
	}
	resolved := err == nil
	if resolved && img.fileless() {
		// No exec: section deny-nothing (§1), or the run opted into anonymous exec (exec.anonymous):
		// the image is allowed and continued, still recorded fileless — the walk stays the record, never the
		// enforcement, for a run that asked for it. Otherwise it is refused: no contract entry can name a
		// runtime-created anonymous inode, and below tier 3 nothing else governs one. When exec is restricted
		// the memfd arm has already refused the main vector at creation (landlock.MemfdSealed, or MemfdRefused
		// on a kernel without MFD_NOEXEC_SEAL); this refusal is the backstop for an anonymous image that arrived another way (an fd
		// received over SCM_RIGHTS or inherited at launch, a file unlinked after opening) and the record either
		// way (GAPS C30).
		if c.execUnrestricted || c.execAnonymous {
			return allowed(ruleUnmatched)
		}
		return execDecision{
			rule: ruleExecAnon, verdict: record.VerdictRefused, reason: record.ReasonExecNotAllowed,
			answer: respErrno(refusalErrno),
		}
	}
	// A walk that failed other than as the task's own lookup would (EMFILE, ENFILE, ENOMEM or EIO in this
	// process, EXDEV) never verified the spelling: R6's is cleaned lexically, and an agent that pushed this
	// process toward fd exhaustion could otherwise have /grant/link/../x, or a symlink under a granted
	// directory, matched by a spelling that leads elsewhere. It admits no grant and is refused under
	// path-unreliable, as R15c refuses the same class of failure on the write side.
	unreliable := err != nil && !execLookupFailure(err)
	if !unreliable {
		if rule, ok := c.execGranted(p, img, resolved); ok {
			return allowed(rule)
		}
	} else if unmatched == ruleUnmatched {
		unmatched = rulePathUnreliable
	}
	// A path the run's own PATH search has to try before it reaches the granted binary is not the
	// agent reaching for a forbidden one. Nothing runs there and nothing is decided about the agent, so the
	// candidate is recorded against the entry it was searching for, with no verdict of its own.
	if r, ok := c.pathSearch[p]; ok && p != "" && !hasDotDot(raw) {
		return execDecision{rule: r, verdict: record.VerdictObserved, search: true, answer: respErrno(lookupErrno(err))}
	}
	if c.execUnrestricted {
		if p == "" && !resolved {
			// Nothing to match and deny nothing to apply it under: no verdict this loop could claim.
			return execDecision{rule: unmatched, verdict: record.VerdictObserved, answer: respContinue()}
		}
		where := imageWhere(p, img, resolved) // where the kernel's exec open lands, which is what both refusals decide on
		if d := c.nearestDenyRead(where); d != nil && !d.Unenforced {
			return refused(d.Name, record.ReasonReadDenied)
		}
		// The Landlock ruleset grants nothing at or beneath an absent built-in row's ungranted name, the exec open's
		// READ_FILE and EXECUTE included (ADR 0067 D3).
		if name, ok := decide.AbsentRead(c.ruleTable(), c.tier(), where); ok {
			return refused(name, record.ReasonReadDenied)
		}
		if c.inCodexHome(where) {
			return refused(ruleCodexHomeExec, record.ReasonExecNotAllowed)
		}
		if inSpellings(c.hookState, where) {
			return refused(ruleHookStateExec, record.ReasonExecNotAllowed)
		}
		return allowed(ruleUnmatched)
	}
	return refused(unmatched, record.ReasonExecNotAllowed)
}

// codexHomeSpellings lists the run's CODEX_HOME grant (agent.CodexHomeGrant) under its declared and resolved paths,
// each followed by itself with a trailing slash, so inCodexHome matches with no allocation on the exec path.
func codexHomeSpellings(rt *agent.RuleTable) []string {
	return runtimeGrantSpellings(rt, agent.CodexHomeGrant)
}

// runtimeGrantSpellings lists the run's runtime write grants of kind (agent.FSRule.Runtime) as codexHomeSpellings does.
func runtimeGrantSpellings(rt *agent.RuleTable, kind string) []string {
	var out []string
	for _, f := range rt.FS {
		if f.Runtime != kind {
			continue
		}
		for _, p := range []string{f.Path, f.Resolved} {
			if p == "" {
				continue
			}
			if p = cleanPath(p); p != "/" && !slices.Contains(out, p) {
				out = append(out, p, p+"/")
			}
		}
	}
	return out
}

// imageWhere is the place an unrestricted run's two exec refusals judge an image by, an enforced deny_read
// (nearestDenyRead) and the run's own CODEX_HOME (inCodexHome): the kernel's own spelling of it (readlink of the
// walk's descriptor) whenever the walk reached a named image, whether or not this process could walk that spelling
// back to the same inode (execImage.here), and the exec's spelling only when the walk reached nothing. A spelling not
// confirmed here may be a removed name another hard link outlives, so its " (deleted)" marker comes off; a confirmed
// one is a real name and is kept whole. Confirmation is what lets a path admit an image (execGranted); here a match
// can only refuse, and the agent shares this process's mount view, since the filter refuses namespace creation.
// Judged on the exec's own spelling instead, a linked file in a directory the agent had made unsearchable, run as
// /proc/self/fd/<n>, was no path in the home or under the deny_read: a copy in the home ran directly or as a
// loader's operand, and an exec the kernel refused under the deny_read was recorded allow. A
// fileless image has no place to lie: it is R10a's residual, never judged here.
func imageWhere(spelled string, img execImage, resolved bool) string {
	switch {
	case !resolved || img.fileless():
		return spelled
	case img.here:
		return img.link
	}
	return strings.TrimSuffix(img.link, deletedSuffix)
}

// inCodexHome reports whether p is the run's CODEX_HOME or lies beneath it (compiled.codexHome): the image of an exec
// a deny-list run refuses codex-home-exec (decideExec), and a directly-invoked loader's program (loadedProgram). p is
// where the kernel's open lands (imageWhere), so a symlink there to a program elsewhere (Codex's own tmp/arg0
// links to its binary) is that program, not a file in CODEX_HOME.
func (c *compiled) inCodexHome(p string) bool { return inSpellings(c.codexHome, p) }

// inSpellings reports whether p is one of the directories sp lists (runtimeGrantSpellings) or lies beneath it.
func inSpellings(sp []string, p string) bool {
	for i := 0; i+1 < len(sp); i += 2 {
		if p == sp[i] || strings.HasPrefix(p, sp[i+1]) {
			return true
		}
	}
	return false
}

// fenceHasExec reports whether the run is Adjustable with an exec or a read fence entry: every exec is then decided in
// this loop, never handed to a plane undecided, so a lifted exec is named after its entry and an image under an
// unlifted read entry is refused (fenceReadExec).
func (c *compiled) fenceHasExec() bool {
	rt := c.ruleTable()
	if !rt.Adjustable() {
		return false
	}
	for _, e := range rt.Live.Entries {
		if e.Kind == agent.LiveKindExec || e.Kind == agent.LiveKindRead {
			return true
		}
	}
	return false
}

// fenceReadExec is an Adjustable run's exec decision under its read refusals: an exec this loop would continue is
// refused when the image, by any name this loop has for it (the line's name, its path, where its descriptor lies), is
// at or beneath a path the live Set refuses reading: an unlifted read fence entry, or a live read or path block. The
// kernel's exec open reads the image, and the agent can read a running program's bytes through /proc/<child>/mem, so
// a run that may not read a file may not run it either. Locked keeps that question to fanotify's exec open at cgroup
// and bpflsm. Here the fence took the deny_read out of the kernel layers, so nothing else asks it.
// Compile keeps every exec.allow folder off a read entry, so the kernel layers grant no execute there; this
// is defence in depth, decided on names like a live exec block (best effort: a symlink swapped after the walk is the
// R15c race). An exec whose walk named no image is refused while a read refusal stands, as liveExec refuses one while
// a program is blocked. Every other decision stands.
func (c *compiled) fenceReadExec(d execDecision, names []string, img execImage, walked bool, unmatched string) execDecision {
	if !d.answer.cont || !c.ruleTable().Adjustable() {
		return d
	}
	s := c.blocks()
	if !s.HasAccess(liveblock.AccessRead) {
		return d
	}
	refused := func(rule string) execDecision {
		return execDecision{rule: rule, verdict: record.VerdictRefused, reason: record.ReasonReadDenied, answer: respErrno(refusalErrno)}
	}
	if img.fileless() {
		return d
	}
	if !walked {
		if unmatched == ruleUnmatched {
			unmatched = rulePathUnreliable
		}
		return refused(unmatched)
	}
	for _, n := range names {
		n = strings.TrimSuffix(n, deletedSuffix)
		if n == "" || !strings.HasPrefix(n, "/") {
			continue
		}
		if e, ok := s.MatchPath(path.Clean(n), liveblock.AccessRead); ok {
			return refused(e.Rule())
		}
	}
	return d
}

// fenceExecRule is rule, or, in an Adjustable run, the rule of the exec fence entry the exec reaches by the name its
// line gives it or by where its image lies here (agent.LiveTable.For: the entry's program, a helper image of it, or
// the bare name of the exec.deny entry it takes out). Such an exec got past the live layer only because the entry is
// lifted, so its line names live.fence[exec:<value>], never the contract's folder rule (or unmatched, with no exec:
// section) that matched it once the fence took the exec.deny entry out of the kernel layers (ADR 0125 decision 9),
// as heldReadFloors names a lifted read and decide.Evaluate names both.
func (c *compiled) fenceExecRule(rule, name string, img execImage) string {
	rt := c.ruleTable()
	if !rt.Adjustable() {
		return rule
	}
	names := []string{name}
	if img.here && !img.fileless() {
		names = append(names, strings.TrimSuffix(img.link, deletedSuffix))
	}
	for _, n := range names {
		if e, ok := rt.Live.For(agent.Action{Kind: agent.ActionExec, Path: n}); ok {
			return e.Rule()
		}
	}
	return rule
}

// execGranted matches an exec against the exec entries: first by the spelling the task passed — an entry
// naming it, or a directory entry above it, the match the record has always named — then by the file that
// spelling resolved to: the inode an entry named when the loop first saw it *and* reached at that entry's
// resolved path, or a file whose resolved path lies under a directory entry's. So a granted binary reached
// by another spelling that leads to the same place — its symlink-resolved path, a symlink the agent made
// to it, its own descriptor through fexecve when that descriptor was opened by such a spelling — is the
// grant it is and not a refusal. A hard link is not: it is another name of the inode, and the name is what
// the contract grants (SEMANTICS; tier 2 matches exec by path for the same reason). On Ubuntu 25.10
// /usr/bin/sleep, ls, dd, env, ln, mv and the rest are hard links of one uutils multi-call binary, and an
// inode match alone let exec.allow: [/usr/bin/sleep] run /usr/bin/ls. Landlock's EXECUTE is bound to the
// inode (enforce-landlock R3) and still allows every hard link of it; this refusal, answered by the loop
// and never continued, is tier 1's guard. The inode is kept alongside the path: a path alone would admit
// a file swapped in at the entry's resolved path after the loop was built.
//
// A resolved path is used only when it names the same inode in this process's view (execImage.here):
// another mount tree can spell a path that lies elsewhere here, and an image not here matches no entry by
// its file.
//
// A directory entry is matched by the spelling only when there is no such resolved path. The spelling is
// lexically cleaned (R6), and the kernel resolves ".." physically: /grant/link/../x, with link a symlink to
// /elsewhere/sub, cleans to /grant/x under exec.allow: [/grant/] and runs /elsewhere/x, which Landlock's
// EXECUTE, bound to /grant's inode, refuses. The ledger said allowed, and an exec the kernel refused could
// name a declared MCP server. The resolved path (img.link) is where the kernel's open landed, so it is what
// a directory entry is matched against when it exists (execDirs, below), under the entry's own name. A file
// entry is the same: exec.allow: [/grant/x] and the same /grant/link/../x cleaned to /grant/x, so a file entry
// with an identity (execPinned) is matched on the inode and resolved path the walk reached (execIDs) whenever
// there is one, and only an entry the loop could not stat when it was built keeps its spelling match.
func (c *compiled) execGranted(p string, img execImage, resolved bool) (string, bool) {
	physical := resolved && img.here
	if p != "" {
		for i := range c.pol.Rules.Exec {
			e := &c.pol.Rules.Exec[i]
			if e.Path == "" {
				continue
			}
			if physical && (e.IsDir || c.execPinned[e.Path]) {
				continue // matched below, on where the walk landed
			}
			if e.Path == p || (e.IsDir && strings.HasPrefix(p, strings.TrimSuffix(e.Path, "/")+"/")) {
				return e.RuleName(), true
			}
		}
	}
	if !resolved {
		return "", false
	}
	if !img.here {
		return "", false
	}
	for _, f := range c.execIDs[img.id] {
		if f.path == img.link {
			return f.name, true
		}
	}
	for _, d := range c.execDirs {
		if (d.path == "/" || (d.path != "" && strings.HasPrefix(img.link, d.path+"/"))) && c.dirHeld(d) {
			return d.name, true
		}
	}
	return "", false
}

// dirHeld reports whether a directory entry's resolved path still holds the inode the Landlock builder bound its
// EXECUTE to. The rule moves with the inode: after `mv out/bin out/old; mkdir out/bin` inside a write entry the kernel
// refuses an exec of out/bin/tool (EACCES), which the line recorded allow under the entry, so such
// an exec is granted by nothing here and refused by this loop, as any exec no entry grants. A directory that cannot be
// stat'ed now is not known to hold it, and grants nothing; an entry the loop could not stat when it was built keeps
// its path match.
func (c *compiled) dirHeld(d execDir) bool {
	if !d.held || c.statID == nil {
		return true
	}
	id, err := c.statID(d.path)
	return err == nil && id == d.id
}

// execGrants is the no-gain rule's exec grants by identity (decide.HeldExecGrants.Grants): a rename or a link compares
// what the ruleset grants where the inodes the Landlock builder held are now, so a line stays what the kernel answers
// after the agent moved or replaced an exec.allow directory inside a write entry.
func (l *Loop) execGrants(c *compiled) decide.ExecGrants {
	return c.execHeld.Grants(c.pol.Rules, func(p string) (decide.FileKey, error) {
		id, err := l.k.LstatID(p)
		return decide.FileKey{Dev: id.dev, Ino: id.ino}, err
	})
}

// droppedImage reports whether an exec's image was written during the run under one of its write entries
// (supervisor R16b): a linked file whose place lies under a write entry, at its resolved path, and whose inode changed
// after the loop was built, which is before the agent ran. The place is where the kernel spells the image
// (imageWhere), whether or not this process could walk that spelling back to the same inode: the flag only
// adds to what a line says, and the agent shares this process's mount view. Judged only on a confirmed
// spelling, an image the agent wrote in a directory it then made unsearchable, run through its descriptor,
// carried no flag, the evasion imageWhere closed for the refusals. A fileless image is
// flagged fileless instead. decideCommand also asks it of each #! interpreter and a loader's program it walks
// (execCommand.dropped).
func (l *Loop) droppedImage(c *compiled, img execImage) bool {
	if img.fileless() || l.started.IsZero() || img.changed.Before(l.started) {
		return false
	}
	near := nearestIn(c.fsResolved, imageWhere(img.link, img, true))
	return near != nil && near.Write
}

// lookupErrno is the errno a refused exec is answered with. When the walk failed with an errno the task's
// own exec lookup would meet at the same place, that errno: a PATH search keeps walking on ENOENT exactly
// as it did when the kernel answered it. Otherwise the refusal errno: the walk reached a file no entry
// grants, or could not vouch for what it reached, and fails closed.
func lookupErrno(err error) unix.Errno {
	var e unix.Errno
	if execLookupFailure(err) && errors.As(err, &e) {
		return e
	}
	return refusalErrno
}

// execLookupFailure reports whether an exec's walk failed with an errno the task's own exec lookup would
// meet at the same place. Any other failure (EMFILE, ENFILE, ENOMEM, EIO in this process, EXDEV) says
// nothing about where the spelling leads, and admits no grant by it (decideExec).
func execLookupFailure(err error) bool {
	var e unix.Errno
	if !errors.As(err, &e) {
		return false
	}
	switch e {
	case unix.ENOENT, unix.ENOTDIR, unix.ELOOP, unix.ENAMETOOLONG, unix.EACCES, unix.EBADF, unix.EFAULT:
		return true
	}
	return false
}

// walkNamed reports whether a line names a pathname by the walk that decides it rather than by R6's lexical clean
// (lineName, execWalk.named, R15b): one with a ".." component, which the clean resolves lexically where the kernel
// resolves it physically, or whose final component is ".", which the clean drops, so out/lk/. cleaned names the
// symlink out/lk while the kernel acts where out/lk leads. It
// allocates nothing: every fs line asks it.
func walkNamed(p string) bool {
	if hasDotDot(p) {
		return true
	}
	_, base := splitFinal(p)
	return base == "."
}

// hasDotDot reports whether a pathname has a ".." component. It allocates nothing.
func hasDotDot(p string) bool {
	for {
		i := strings.IndexByte(p, '/')
		if i < 0 {
			return p == ".."
		}
		if p[:i] == ".." {
			return true
		}
		p = p[i+1:]
	}
}

// nearestDenyRead is the nearest deny_read entry that is p or an ancestor of it, under either spelling
// (decide.NearestDenyRead over c.fsBoth, as fsVerdict matches).
func (c *compiled) nearestDenyRead(p string) *decide.AdvisoryRule {
	return decide.NearestDenyRead(c.fsBoth, p)
}

// pathSearchSet is the candidate table R28 decides on: every path the run's own PATH search has to try
// before it reaches a granted binary, mapped onto the rule name of the grant it is searching for. It is
// derived once per policy from the compiled table alone — no filesystem read, no state carried across
// notifications — so the same execve decides the same way whichever thread makes it, however many
// searches are interleaved, and whether or not any of them ever succeeds.
//
// Only an entry the contract declared as a bare basename produces candidates: that is the entry whose
// resolution glibc repeats at run time, because execvp walks PATH and calls execve once per directory
// (SEMANTICS §4, "a basename resolves to its PATH candidates"). An entry declared only by path or by
// directory is executed by that path and never searched for. The question is asked of ExecRule.ByName,
// not of Raw: entries that resolve to one file compile to one rule that keeps only the first spelling in
// Raw, so `command: [/usr/bin/python3]` beside `exec.allow: [python3]` has a path for Raw while the author
// still wrote the basename the run's own execvp searches for. Only the PATH elements *before* the granting
// directory are candidates: the search stops at the first execve that does not return, so a directory that
// follows the grant is never reached and an execve naming one is the agent's own doing, not the search's.
//
// The table is |PATH| x |basename entries| at most, computed once, in New.
func pathSearchSet(rt *agent.RuleTable) map[string]string {
	if rt == nil || rt.PATH == "" {
		return nil
	}
	// An empty PATH element is the current directory and a relative one is resolved against it (execvp).
	// This package has no cwd at policy time — /proc/<pid>/cwd is a per-notification read (R6) and each
	// thread has its own — so neither becomes a candidate: an execve naming one is refused like any other
	// unmatched path, which is the fail-closed direction.
	dirs := strings.Split(rt.PATH, ":")
	for i, d := range dirs {
		if d == "" || !strings.HasPrefix(d, "/") {
			dirs[i] = ""
			continue
		}
		dirs[i] = path.Clean(d)
	}
	var out map[string]string
	for i := range rt.Exec {
		e := &rt.Exec[i]
		if e.Path == "" || e.IsDir || !e.ByName {
			continue
		}
		base, grantDir := path.Base(e.Path), path.Dir(e.Path)
		stop := -1
		for j, d := range dirs {
			if d != "" && d == grantDir {
				stop = j
				break
			}
		}
		if stop < 0 {
			// The grant is not on the run's PATH at all, so no search of this basename can reach it and
			// every execve of it is the agent's own: no candidate.
			continue
		}
		for _, d := range dirs[:stop] {
			if d == "" {
				continue
			}
			cand := path.Join(d, base)
			if _, dup := out[cand]; dup {
				continue
			}
			if out == nil {
				out = map[string]string{}
			}
			out[cand] = e.RuleName()
		}
	}
	return out
}
