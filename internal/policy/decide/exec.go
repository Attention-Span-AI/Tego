// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"path/filepath"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// evalExec matches a binary against the compiled exec entries. The tiers
// differ on how a script's stage is decided (SEMANTICS §4): tier 3's exec hook
// passes any binfmt stage whose buffer starts with #! and decides on the
// interpreter by name; Landlock cannot match by name and needs
// EXECUTE|READ_FILE on the script file as well as on its interpreter, and tier
// 2 installs that same Landlock ruleset (execByInode). Tier 3 installs it too,
// so an unlisted script is refused there as well (ScriptFloor, SEMANTICS §4's
// 2026-09-29 note); a granted script's interpreter is then matched by name.
//
// An exec is also a read. The kernel opens the program, a #! script's
// interpreter and the PT_INTERP loader of the ELF the chain ends in, each
// O_RDONLY|__FMODE_EXEC (SEMANTICS §4), so every file_open rule that governs
// reading those files governs running them too; execOpenRefused asks that
// question of each one this package can name, once the exec rules have
// answered theirs.
//
// ix, when not nil, is rt's FSIndex: the reads are then asked of it (FSIndex.EvaluateExec), with the answers the
// scans give.
func evalExec(rt *agent.RuleTable, ix *FSIndex, a agent.Action, tier backend.Tier) agent.EvalResult {
	path := a.Path
	if path == "" && len(a.Argv) > 0 {
		path = a.Argv[0]
	}
	if path == "" {
		return invalidAction()
	}
	path = cleanPath(path)
	// The program and a #! script's interpreter, in the order the kernel opens them. The loader
	// comes last: binfmt_elf opens it for the ELF the chain ends in, the interpreter when there is
	// one, and only compile's record of a declared entry can name it (execLoader).
	opened := []string{path}
	if a.Script != "" {
		opened = append(opened, cleanPath(a.Script))
	}
	loader := execLoader(rt, opened[len(opened)-1], tier)
	// Observe mode enforces nothing.
	if tier == backend.TierObserve {
		return execNamed(rt, path, tier)
	}
	// A contract with no exec: section restricts nothing through its exec rules: SEMANTICS §1
	// gives "no exec:" and "exec: {}"/"exec.allow: []" opposite defaults, which is why
	// Contract.Exec is a pointer. The landlock builder reads exactly this bit (execUnrestricted,
	// internal/runtime/enforce/landlock) and adds EXECUTE to every read set, so reporting the
	// restrictive default here told an author an exec was impossible while the run performed it —
	// a false assurance from the one tool whose job is to answer that.
	//
	// "Restricts nothing" is about exec rules only. The open that loads the program still passes
	// every filesystem rule (execOpenRefused): the root tiers refuse it under a deny_read that
	// decides the read, and Landlock refuses it under an enforceable deny_read unless the binary is
	// declared and keeps an fd of its own; saying "allow" for an undeclared binary under ~/.ssh
	// certified a run the kernel refuses.
	if rt.ExecUnrestricted() {
		if res, refused := execOpenRefused(rt, ix, opened, loader, tier); refused {
			return res
		}
		return execNamed(rt, path, tier)
	}
	var res agent.EvalResult
	if a.Script != "" && !execByInode(tier) {
		// The script stage passes on its #! buffer, but tier 3 installs Landlock as well, whose EXECUTE rule is
		// asked of the script's own open first (ScriptFloor).
		if floor := ScriptFloor(rt, path, tier); floor.Verdict != agent.VerdictAllow {
			return floor
		}
		res = execVerdict(rt, opened[1], tier)
	} else {
		res = execVerdict(rt, path, tier)
		if res.Verdict == agent.VerdictAllow && a.Script != "" {
			// Landlock: the interpreter is opened with __FMODE_EXEC too, so it needs
			// its own EXECUTE|READ_FILE (SEMANTICS §4).
			res = execVerdict(rt, opened[1], tier)
		}
	}
	if res.Verdict != agent.VerdictAllow {
		return res
	}
	if refused, ok := execOpenRefused(rt, ix, opened, loader, tier); ok {
		return refused
	}
	return res
}

// execNamed is an allowed exec, attributed to the entry that names the binary when one does and
// to the unmatched bucket otherwise, so the ledger's rule field stays the declared entry.
func execNamed(rt *agent.RuleTable, path string, tier backend.Tier) agent.EvalResult {
	if i, ok := matchExec(rt, path, tier); ok {
		return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: rt.Exec[i].RuleName()}
	}
	return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: agent.UnmatchedRule}
}

// execOpenRefused reports the first file of an exec whose O_RDONLY|__FMODE_EXEC open a filesystem
// rule refuses, as the read that open is (SEMANTICS §4), and how the tier refuses it. opened is the
// program and a #! interpreter; loader is the PT_INTERP loader when execLoader knows it, else "".
//
// The root tiers' answer is SEMANTICS §2's nearest-ancestor walk, which runs at file_open whatever
// the open is for and stops only at fs entries, never at an exec.allow entry: a file under a
// deny_read that decides the read is read-denied declared or not, and a walk past MaxWalk steps is
// path-unresolved. Both answers are that specified walk's, not the product of either tier-2
// mechanism. Tier 2 decides the open in its fanotify listener, which sees the exec open as a
// FAN_OPEN_PERM as well as a FAN_OPEN_EXEC_PERM, refuses it under a deny_read that no write entry with a
// longer path covers, and bounds no depth (internal/runtime/enforce/cgroup/policy.go
// decideOpen); the tier-1 ruleset it inherits refuses only an undeclared binary under a deny_read
// that tier 1 enforces.
//
// The Landlock tier unions every rule on the path, and the exec open needs READ_FILE as well as
// EXECUTE (SEMANTICS §4). A declared entry holds an fd of its own with both (execGrants,
// enforce-landlock R5), which no deny_read above it withdraws, with one exception: a declared file
// that is itself an enforced deny_read target (and not inside another one) is a sealed deny node,
// and Prepare fails the run rather than grant it (enforce-landlock E32 (c)), which is reported as
// the read-denied it would be. An undeclared binary has only what the tier's other rules carry.
// With exec unrestricted, EXECUTE rides on the sibling read sets, the enumerated ancestors and the
// write masks, and an ancestor's reaches into the deny_read target beneath it; READ_FILE does not,
// because the target's entry carries Access 0, an ancestor carries no READ_FILE, and the levels
// inside the target are not enumerated (enforce-landlock R3; the shapes that reach inside by
// another name are E32's limitations, I11). That is evalFSLandlock's read arm. The exception is a
// write entry nested inside an enforceable target: its mask carries READ_FILE, and EXECUTE while
// exec is unrestricted, into its own subtree, and Landlock unions it; the read arm models that
// nested grant (nestedReadGrant), so a binary under such an entry passes here as it runs in the
// kernel (it was reported read-denied until R15 closed it). A declared entry's loader
// gets its own fd as well, except that Prepare refuses to grant a loader at or below any deny_read
// target, enforced or not, and fails the run naming it (enforce-landlock E29); that is reported as
// the read the grant would have re-opened, the target found at any depth, as Prepare finds it. Prepare refuses a
// loader under a write or ask entry too, which is no read refusal and is not modelled here; Compile
// warns about every such loader instead (compile_exec.go checkLoaders).
func execOpenRefused(rt *agent.RuleTable, ix *FSIndex, opened []string, loader string, tier backend.Tier) (agent.EvalResult, bool) {
	for _, p := range opened {
		file, ok := execFile(rt, p, tier)
		if !ok {
			continue
		}
		if tier == backend.TierLandlock {
			if _, declared := matchExec(rt, p, tier); declared {
				if i, sealed := sealedDenyTarget(rt, file); sealed {
					return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: rt.FS[i].RuleName(), Reason: record.ReasonReadDenied}, true
				}
				continue
			}
		}
		if res := execRead(rt, ix, file, tier); res.Verdict == agent.VerdictRefused {
			return res, true
		}
	}
	if loader == "" {
		return agent.EvalResult{}, false
	}
	if tier == backend.TierLandlock {
		// nearestFSOfKind, not evalFS: Prepare's governs() refuses a loader under any deny_read
		// target, including one tier 1 leaves unenforced, where the read arm would say allow.
		if i, ok := nearestFSOfKind(rt, loader, agent.FSDenyRead); ok {
			return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: rt.FS[i].RuleName(), Reason: record.ReasonReadDenied}, true
		}
		return agent.EvalResult{}, false
	}
	if res := execRead(rt, ix, loader, tier); res.Verdict == agent.VerdictRefused {
		return res, true
	}
	return agent.EvalResult{}, false
}

// execRead is the verdict of the read an exec's open of file is. In the root tiers, whose read is the
// nearest-wins walk (Evaluator.root), it is asked of ix when the caller holds one: tier 2's recorder asks about every
// exec, and a scan of a table the built-in .env scan filled with 50,000 entries cost 16-31 ms per exec, so a build
// that execs hundreds of processes a second put the drain goroutine behind. Anything else takes evalFS's scan.
func execRead(rt *agent.RuleTable, ix *FSIndex, file string, tier backend.Tier) agent.EvalResult {
	if ix != nil && !ix.scan && (tier == backend.TierCgroup || tier == backend.TierBPFLSM) && file == cleanPath(file) {
		c := ix.Canonical(file)
		return absentReadFloor(rt, agent.ActionFSRead, c, tier, ix.evalRootRead(c))
	}
	return evalFS(rt, agent.ActionFSRead, Canonical(rt, file), tier, objFile)
}

// execFile is the file an exec action opens. A path names itself. A bare command name (an `argv:
// [rg]` row) names no file of its own: it means the resolved candidate of the entry it matches, and
// nothing at all when no entry matches it, since this package makes no PATH lookup of its own (I6).
func execFile(rt *agent.RuleTable, p string, tier backend.Tier) (string, bool) {
	if p != filepath.Base(p) {
		return p, true
	}
	i, ok := matchExec(rt, p, tier)
	if !ok || rt.Exec[i].IsDir || rt.Exec[i].Path == "" {
		return "", false
	}
	return rt.Exec[i].Path, true
}

// execLoader is the PT_INTERP loader of the file p opens, when compile recorded one: p must be a
// declared file entry's own resolved path, or a bare name that means it (execFile). Anything else —
// an undeclared binary, one under a directory entry, a same-named file tier 3 matches by basename
// — is a different inode whose loader this package never read (I6), so it names none.
func execLoader(rt *agent.RuleTable, p string, tier backend.Tier) string {
	file, ok := execFile(rt, p, tier)
	if !ok {
		return ""
	}
	for i := range rt.Exec {
		if r := &rt.Exec[i]; !r.IsDir && r.Path == file && r.Interp != "" {
			return cleanPath(r.Interp)
		}
	}
	return ""
}

// sealedDenyTarget is the enforced deny_read entry whose target is file itself, when no other
// enforced target encloses it: the Landlock builder holds and seals exactly those (enforce-landlock
// R3, E29 (a) drops a target nested in another), so an exec grant landing on one fails Prepare
// (E32 (c)). A declared file inside a target is a different inode and keeps its grant (I11 (1)), and
// an unenforced target is never enumerated at all (R4), so neither is reported. Paths are compared
// both as declared and as resolved, since the builder holds each entry by following its symlinks.
func sealedDenyTarget(rt *agent.RuleTable, file string) (int, bool) {
	hit := -1
	for i := range rt.FS {
		r := rt.FS[i]
		if r.Kind != agent.FSDenyRead || denyUnenforced(rt, i) {
			continue
		}
		if cleanPath(r.Path) == file || r.Governed() == file {
			hit = i
		}
	}
	if hit < 0 {
		return -1, false
	}
	for i := range rt.FS {
		r := rt.FS[i]
		if i == hit || r.Kind != agent.FSDenyRead || denyUnenforced(rt, i) {
			continue
		}
		if t := r.Governed(); t != file && agent.Covers(t, file) {
			return -1, false
		}
	}
	return hit, true
}

// execByInode reports whether a tier decides exec by inode, the Landlock way, rather than by the
// exec hook's binfmt stages. Tier 1 is Landlock. Tier 2 installs the same Landlock ruleset and
// seccomp filter (internal/runtime/enforce/select.go construct, enforce-cgroup-observe R1), so every
// exec there also needs EXECUTE|READ_FILE on the resolved inode of the program and of a #! script's
// interpreter; its fanotify listener adds a FAN_OPEN_EXEC_PERM check that matches exact and
// directory paths only (cgroup policy.go decideExec) and fires on the script's own open as well. So
// neither a match by name nor an unlisted script can pass there. Only tier 3's exec hook decides
// per binfmt stage by dentry name (SEMANTICS §4, "Root tiers"), under the same Landlock floor for a
// #! script's own open (ScriptFloor).
func execByInode(tier backend.Tier) bool {
	return tier == backend.TierLandlock || tier == backend.TierCgroup
}

// ScriptFloor is the Landlock floor under a #! script at tier 3 (SEMANTICS §4's 2026-09-29 note, enforce-plane R9's
// composition, ADR 0019's one column): the plane passes the script's stage and decides on the interpreter, but the
// Landlock domain the child stage installs at every tier grants EXECUTE only to what an exec entry names by inode, a
// path or a directory above it, never by name, and the kernel asks it of the script's open before any binfmt stage
// runs. So an unlisted script is refused, unmatched, at bpflsm as at tiers 1 and 2. At any other tier, and for a
// granted script, it answers allow with no rule. Evaluate at bpflsm and the plane's column (PlaneEvaluator) both ask
// it, so the column is the plane intersected with Landlock and never the plane alone.
func ScriptFloor(rt *agent.RuleTable, script string, tier backend.Tier) agent.EvalResult {
	if tier != backend.TierBPFLSM {
		return agent.EvalResult{Verdict: agent.VerdictAllow}
	}
	if res := execVerdict(rt, script, backend.TierLandlock); res.Verdict != agent.VerdictAllow {
		return res
	}
	return agent.EvalResult{Verdict: agent.VerdictAllow}
}

// execVerdict is one exec lookup: the matching entry's verdict, or refused
// against the unmatched bucket.
func execVerdict(rt *agent.RuleTable, path string, tier backend.Tier) agent.EvalResult {
	i, ok := matchExec(rt, path, tier)
	if !ok {
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.UnmatchedRule, Reason: record.ReasonExecNotAllowed}
	}
	r := rt.Exec[i]
	if r.Verdict != agent.VerdictAllow {
		// ask compiles as refused in P0 (SEMANTICS §3.1, R2).
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: r.RuleName(), Reason: record.ReasonExecNotAllowed}
	}
	return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: r.RuleName()}
}

// matchExec finds the entry that grants path. Two arms hold in every tier because they are inode
// identity: the entry's path itself, and a directory entry above it, each under the entry's declared
// spelling and its symlink-resolved one (ExecRule.Resolved): tier 1's supervisor and tier 2's listener
// admit both, and a row naming what `readlink -f` shows (/usr/bin/dash for /bin/sh) was reported refused
// (R15). The third arm is name matching, which is neither universal nor
// unconditional (SEMANTICS §4).
//
// Compile stamps Basename on every rule — entries declared by absolute path, the implicit command
// rule and every mcp[].command[0] alike — so an unguarded basename arm made any binary sharing a
// final component match: a row for /tmp/work/python3 was reported allow against a deliberately
// pinned exec.allow: ["/opt/toolchain/bin/python3"].
func matchExec(rt *agent.RuleTable, path string, tier backend.Tier) (int, bool) {
	base := filepath.Base(path)
	// An action that is a bare command name (a `argv: [rg]` row, which LoadTestTable leaves
	// unresolved on purpose) names no file: the entry's own resolved candidate is the only thing
	// it can mean, in every tier.
	bareAction := path == base
	for i := range rt.Exec {
		r := &rt.Exec[i]
		switch {
		case r.Path != "" && r.Path == path:
		case r.IsDir && agent.Covers(r.Path, path):
		case r.Resolved != "" && r.Resolved != r.Path && (r.Resolved == path || (r.IsDir && agent.Covers(r.Resolved, path))):
		case r.Basename != "" && r.Basename == base && (bareAction || nameMatchable(r, tier)):
		default:
			continue
		}
		return i, true
	}
	return -1, false
}

// nameMatchable reports whether an entry may be matched by the final component of some other
// path. SEMANTICS §4 grants that to tier 3, whose exec hook "matches the final component of the
// file's dentry after symlink resolution", and to an entry the author wrote as a bare basename.
// The Landlock tier is explicitly the other way — "It cannot match by name": it holds one fd per
// resolved entry, so "a same-named binary elsewhere, such as a uv- or pyenv-managed Python, is a
// different inode and must be declared by path or directory". Tier 2 runs that same ruleset
// (execByInode). An entry the author wrote as a path names one inode in every tier; a hand-built
// rule, which carries no ByName, fails closed.
//
// The question is asked of ByName rather than of Raw because Raw is only the *first* spelling
// that resolved to this file: `command: ["/usr/bin/python3"]` beside `exec.allow: ["python3"]`
// compiles to one rule whose Raw is the path, and reading that string made the author's basename
// entry stop matching by name in tier 3 — `compile --test` then reported refused for an
// exec the kernel admits, the false assurance this guard exists to prevent.
func nameMatchable(r *agent.ExecRule, tier backend.Tier) bool {
	return !execByInode(tier) && r.ByName
}
