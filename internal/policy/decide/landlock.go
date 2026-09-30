// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// evalFSLandlock is tier 1's union rule: within a layer Landlock grants an
// access if any rule on the path grants it, so a mutation is allowed when any
// entry covering the path carries the right (the nearest such entry is
// reported), and a read is refused only under a deny_read entry the tier can
// actually enforce. A deny_read whose parent is inside a write entry is
// reported allow with the unenforced marker, because the supervisor's ADDFD
// creates files there outside the domain and no ruleset can deny beneath an
// allow (SEMANTICS §2, R15).
//
// A read under an enforced deny_read is still allowed through a write entry nested beneath the target
// that covers the path: the builder gives a write entry's mask the read set, and Landlock unions it with
// the target's access 0, so the kernel lets the read through and the root tiers' nearest-wins walk
// agrees (R15; it was answered refused, agent-contract §11's over-refusal). A declared exec
// entry strictly beneath the target reopens reads the same way at this tier alone: its grant holds an fd of
// its own with READ_FILE, on the file or on the whole directory (enforce-landlock R5, I11 (1)), which no
// deny_read above it withdraws (execReadGrant).
//
// A delete or rename is checked on the path's parent directory, which is where Landlock asks for
// REMOVE_FILE/REMOVE_DIR and REFER (and a link's MAKE_*): deleting or renaming a write entry itself
// needs those rights on the directory above it, which the entry does not grant (R15).
//
// No walk here is bounded: Landlock checks every rule from the path up to the root, however deep, and
// agent.MaxWalk is the root tiers' kernel walk alone (R15). A read 70 levels beneath a deny_read is refused
// as one level beneath it is.
func evalFSLandlock(rt *agent.RuleTable, kind agent.ActionKind, path string) agent.EvalResult {
	return (&Evaluator{rt: rt}).landlock(kind, path)
}

// nestedReadGrant is the nearest write entry that covers path and lies at or beneath the enforced
// deny_read target deny: its mask carries the read set into its own subtree, and Landlock's union lets
// the read through the target's access 0 (evalFSLandlock). bounded keeps the root tiers' agent.MaxWalk
// bound (fsDecider); the Landlock arm bounds no depth.
func nestedReadGrant(rt *agent.RuleTable, path string, deny int, bounded bool) (int, bool) {
	target := rt.FS[deny]
	best, bestSteps := -1, 0
	for i := range rt.FS {
		r := rt.FS[i]
		if r.Kind != agent.FSWrite || !(agent.Covers(target.Path, cleanPath(r.Path)) || agent.Covers(target.Governed(), cleanPath(r.Governed()))) {
			continue
		}
		n, covered := ruleSteps(r, path)
		if !covered || (bounded && n > agent.MaxWalk) {
			continue
		}
		if best < 0 || n < bestSteps {
			best, bestSteps = i, n
		}
	}
	return best, best >= 0
}

// execReadGrant is the declared exec entry whose Landlock grant reopens a read of path under the enforced
// deny_read target deny: the entry lies strictly beneath the target, where it keeps its own fd (enforce-landlock
// I11 (1)), and covers path — a file entry is the path itself, a directory entry its whole subtree. An exec
// grant carries READ_FILE as well as EXECUTE (R5), and Landlock unions it with the target's access 0. An entry at
// the target itself is a sealed deny node, which fails Prepare (E32 (c), sealedDenyTarget), and one above it
// leaves the target unenforced (compile_fs.go denyReadUnderExecDirs), so neither is a nested grant. Both
// spellings of each side are compared, as nestedReadGrant compares them (R15).
func execReadGrant(rt *agent.RuleTable, path string, deny int) (int, bool) {
	target := rt.FS[deny]
	for i := range rt.Exec {
		r := &rt.Exec[i]
		for _, e := range [2]string{r.Path, r.Resolved} {
			if e == "" {
				continue
			}
			if !strictlyBeneath(target.Path, e) && !strictlyBeneath(target.Governed(), e) {
				continue
			}
			if e == path || (r.IsDir && agent.Covers(e, path)) {
				return i, true
			}
		}
	}
	return -1, false
}

// strictlyBeneath reports whether p lies beneath the entry t and is not t itself.
func strictlyBeneath(t, p string) bool {
	n, ok := agent.CoverSteps(t, p)
	return ok && n > 0
}

// ExecReadGrant is the exec entry through which tier 1 reads path although the nearest deny_read covering it
// is enforced (execReadGrant), and whether one does. internal/runtime/supervisor's advisory read verdict asks
// it, so a read the kernel lets through is not recorded refused.
func ExecReadGrant(rt *agent.RuleTable, path string) (*agent.ExecRule, bool) {
	if rt == nil || path == "" {
		return nil, false
	}
	path = Canonical(rt, cleanPath(path))
	i, ok := nearestFSOfKind(rt, path, agent.FSDenyRead)
	if !ok || denyUnenforced(rt, i) {
		return nil, false
	}
	if _, ok := nestedReadGrant(rt, path, i, false); ok {
		return nil, false
	}
	if x, ok := execReadGrant(rt, path, i); ok {
		return &rt.Exec[x], true
	}
	return nil, false
}

// nearestGrant returns the nearest entry covering path that grants every bit
// of need — Landlock's union across the rules on a path (SEMANTICS §2), at any depth.
func nearestGrant(rt *agent.RuleTable, path string, need agent.AccessSet) (int, bool) {
	best, bestSteps := -1, 0
	for i := range rt.FS {
		if !rt.FS[i].Access.Has(need) {
			continue
		}
		n, covered := ruleSteps(rt.FS[i], path)
		if !covered {
			continue
		}
		if best < 0 || n < bestSteps {
			best, bestSteps = i, n
		}
	}
	return best, best >= 0
}

// accessAt is the union of the rights every entry covering path grants, plus
// the nearest covering entry's name — the two halves of the REFER comparison. bounded limits the name to
// the root tiers' agent.MaxWalk walk; Landlock's union names the nearest entry at any depth.
func accessAt(rt *agent.RuleTable, path string, bounded bool) (agent.AccessSet, string) {
	var union agent.AccessSet
	name := agent.UnmatchedRule
	if i, steps, ok := nearestFS(rt, path); ok && (!bounded || steps <= agent.MaxWalk) {
		name = rt.FS[i].RuleName()
	}
	for i := range rt.FS {
		if _, covered := ruleSteps(rt.FS[i], path); covered {
			union |= rt.FS[i].Access
		}
	}
	return union, name
}

// GrantName is the name of the entry a modification the Landlock ruleset allows is named by at tiers 1 and 2:
// the nearest entry that grants the right the operation needs (op a record.FS* constant), asked of the parent
// directory for an unlink or a rename, as Evaluate's Landlock column names an allowed modification
// (evalFSLandlock). A deny_read or a watch entry nearer than that grant names nothing the ruleset decided by.
// ok is false when no entry grants it. An unlink's and a rename's name is not followed (canonicalEnd).
func GrantName(rt *agent.RuleTable, op, path string) (string, bool) {
	if rt == nil || path == "" {
		return "", false
	}
	kind := grantKind(op)
	var at string
	if kind == agent.ActionFSDelete || kind == agent.ActionFSRename {
		at = filepath.Dir(canonicalEnd(rt, cleanPath(path)))
	} else {
		at = Canonical(rt, cleanPath(path))
	}
	if i, ok := nearestGrant(rt, at, fsAccess(kind)); ok {
		return rt.FS[i].RuleName(), true
	}
	return "", false
}

// grantKind is the action a recorded fs operation (a record.FS* constant) is a grant question for.
func grantKind(op string) agent.ActionKind {
	switch op {
	case record.FSUnlink:
		return agent.ActionFSDelete
	case record.FSRename:
		return agent.ActionFSRename
	case record.FSMkdir:
		return agent.ActionFSMkdir
	}
	return agent.ActionFSWrite
}

// ExecGrants is what the exec.allow grants of the run's Landlock ruleset give at the end p, through p itself and its
// ancestors: EXECUTE and READ_FILE (READ_DIR beneath a directory grant). The builder binds each grant to the inode it
// held at Prepare (enforce-landlock R5), and the rule moves with that inode: an exec.allow directory renamed within a
// write entry takes its EXECUTE to its new name and leaves none at the declared one. nil is the
// table's answer (ExecGrantAt), all a table alone can give; the supervisor answers by the identity of the
// inodes the builder held, which it took before the agent ran.
type ExecGrants func(p string) agent.AccessSet

// ExecGrantAt is what the exec.allow entries grant at the end p by the table, each entry at its target
// (landlockExecGrant).
func ExecGrantAt(rt *agent.RuleTable, p string) agent.AccessSet {
	if rt == nil {
		return 0
	}
	return landlockExecGrant(rt, p)
}

// RenameGainedBy is the rights a rename of the object at src to the name dst would gain under REFER's no-gain rule
// (SEMANTICS §2, evalRename), whatever the object is, as the run's Landlock ruleset decides it (security/landlock/fs.c,
// hook_path_rename, current_check_refer_path and no_more_access); ReferRefuses says whether they refuse the move. A
// rename within one directory reparents nothing, is never compared and gains nothing; across directories it gains each
// right the ruleset grants at dst's directory and not at src, src's own rule included (landlockRights: an exec.allow
// entry's EXECUTE included), with the exec grants' rights at a path from exec (nil: ExecGrantAt). A rule on the name dst
// replaces is never asked: an atomic replace of an exec.allow file entry inside a write entry is allowed. Both paths
// are landed ends (landedEnd): the ends' own names where the kernel's walk left them, their final
// components not followed (rename(2) moves a symlink itself, and a symlinked entry's rule is on its target).
// RENAME_EXCHANGE moves both objects, and is refused when either direction's gain refuses its object. A hard
// link is LinkGainsBy.
func RenameGainedBy(rt *agent.RuleTable, src, dst string, exec ExecGrants) agent.AccessSet {
	if rt == nil || src == "" || dst == "" {
		return 0
	}
	return referGained(landedEnd(src), landedEnd(dst), scanRights(rt, exec))
}

// landedEnd is an end p of a rename, a link or an unlink the run asks about, where the kernel's walk landed it: the
// supervisor's walk of the notified pathname, the recorder's d_path, a compile --test row its Lander (supervisor.Land)
// walked through the real tree. Every component but the last is already followed, so p is taken as it is and never rewritten by a
// declared spelling (canonicalEnd answers a question asked by name). A landed end carries a link's declared spelling
// only after the agent replaced that link with a real directory, which holds none of the rules Landlock put on the
// link's target: rewritten by an exec.allow directory's link or by an fs entry's (Canonical), a move
// or a link into that directory was judged at the target and recorded refused while the kernel allowed it (S4-1 and
// R4-C1), and an unlink there was blamed on Landlock.
func landedEnd(p string) string { return cleanPath(p) }

// scanRights is the ruleset's rights at an end by scan: the write entries' (landlockFSRights) and exec's, or the exec
// entries' by the table (ExecGrantAt) when exec is nil.
func scanRights(rt *agent.RuleTable, exec ExecGrants) func(string) agent.AccessSet {
	if exec == nil {
		return func(p string) agent.AccessSet { return landlockRights(rt, p) }
	}
	return func(p string) agent.AccessSet { return landlockFSRights(rt, p) | exec(p) }
}

// ReferRefuses reports whether REFER's no-gain rule refuses a move that gains the rights gained (RenameGainedBy): any
// right for a moved directory, for which every right counts, and only a file right (landlockFileRights) for any other
// object, as no_more_access compares them.
func ReferRefuses(gained agent.AccessSet, dir bool) bool {
	if dir {
		return gained != 0
	}
	return gained&landlockFileRights != 0
}

// LinkGainsBy is REFER's no-gain rule for a hard link of the regular file src to the new name dst, as the run's Landlock
// ruleset decides it (security/landlock/fs.c, hook_path_link and current_check_refer_path): only a link across
// directories is compared, and only the file rights (landlockFileRights) the ruleset grants at the new name's directory
// against those it grants at the file itself, its own entry's included. A link into an exec.allow directory the file's
// own place does not have EXECUTE in is refused (EXDEV), and the run's line says so (security F3, F4).
// linkat(2) without AT_SYMLINK_FOLLOW links a symlink itself, so neither end is followed: both are landed ends
// (landedEnd). The exec grants' rights at a path come from exec (nil: ExecGrantAt).
func LinkGainsBy(rt *agent.RuleTable, src, dst string, exec ExecGrants) bool {
	if rt == nil || src == "" || dst == "" {
		return false
	}
	return linkGains(landedEnd(src), landedEnd(dst), scanRights(rt, exec))
}

// LandlockLinkRefusal is how the run's Landlock ruleset answers a hard link of the regular file src to the new name dst
// (hook_path_link): MAKE_REG on the new name's directory, REFER on both directories when they differ, both granted by
// a write entry covering the directory (a file-level entry grants no directory right), and then LinkGainsBy. It is the
// floor the ruleset keeps under every tier, so tier 3's line, and compile --test's bpflsm column, refuse what it
// refuses even where the decision plane's path_link allows. refused is false when Landlock allows the link; rule is
// then the source directory's grant, and otherwise the entry the refusal is recorded under: the nearest entry of the
// directory that lacks the right (unmatched for none), or the source's grant for a right gained.
func LandlockLinkRefusal(rt *agent.RuleTable, src, dst string) (rule string, refused bool) {
	if rt == nil || src == "" || dst == "" {
		return agent.UnmatchedRule, false
	}
	return (&Evaluator{rt: rt}).landlockLink(landedEnd(src), landedEnd(dst))
}

// LandlockLinkRefusal is LandlockLinkRefusal(rt, src, dst) on the index.
func (ix *FSIndex) LandlockLinkRefusal(src, dst string) (rule string, refused bool) {
	return ix.LandlockLinkRefusalBy(src, dst, nil)
}

// LandlockLinkRefusalBy is LandlockLinkRefusal on the index with the exec grants' rights from exec (nil: their
// table's, ExecGrantAt): a producer that holds the inodes the builder granted asks by them (HeldExecGrants).
func (ix *FSIndex) LandlockLinkRefusalBy(src, dst string, exec ExecGrants) (rule string, refused bool) {
	if ix == nil || src == "" || dst == "" {
		return agent.UnmatchedRule, false
	}
	if ix.scan {
		return (&Evaluator{rt: ix.rt, exec: exec}).landlockLink(landedEnd(src), landedEnd(dst))
	}
	return (&Evaluator{rt: ix.rt, fs: ix, exec: exec}).landlockLink(landedEnd(src), landedEnd(dst))
}

// landlockLink is LandlockLinkRefusal on two canonical ends, asked of the scan or the index as e is. The source's
// directory is asked first, as the supervisor's line asks the source end first (recordLink); for a link within one
// directory both questions are MAKE_REG on it.
func (e *Evaluator) landlockLink(src, dst string) (string, bool) {
	grant := func(dir string) (string, bool) {
		if i, ok := e.grant(dir, fsAccess(agent.ActionFSLink)); ok {
			return e.name(i), true
		}
		return e.nearestName(dir, false), false
	}
	name, ok := grant(filepath.Dir(src))
	if !ok {
		return name, true
	}
	if d, ok := grant(filepath.Dir(dst)); !ok {
		return d, true
	}
	return name, linkGains(src, dst, e.landlockRights)
}

// landlockRename is how the run's Landlock ruleset answers a rename of the object at the canonical end src to the
// canonical end dst (hook_path_rename), asked of the scan or the index as e is: REFER, which every write entry
// carries with the MAKE_* and REMOVE_* rights (agent.AccessWriteSet), from a write entry covering each end's directory
// (a file-level entry grants no directory right), the source's first, as Evaluate's Landlock arm asks the ends; then
// REFER's no-gain rule (RenameGainedBy, ReferRefuses). It is the floor the ruleset keeps under the decision plane, whose path_rename
// decides on the objects and allowed a file-level write entry's own rename that this floor refuses with EACCES.
// refused is false when Landlock allows the rename; otherwise rule is the nearest entry of the directory
// that lacks the right (unmatched for none), or for a right gained the source's name (endName, bounded as the root
// tiers' walk names it when bounded).
func (e *Evaluator) landlockRename(src, dst string, dir, bounded bool) (string, bool) {
	for _, end := range [2]string{src, dst} {
		if r := e.landlock(agent.ActionFSRename, end); r.Verdict != agent.VerdictAllow {
			return r.Rule, true
		}
	}
	if ReferRefuses(referGained(src, dst, e.landlockRights), dir) {
		return e.endName(src, bounded), true
	}
	return "", false
}

// landlockDelete is how the run's Landlock ruleset answers an unlink or rmdir of the canonical end p: REMOVE_* on its
// directory, from a write entry covering it (Evaluate's Landlock arm). The floor under the plane, whose path_unlink and
// path_rmdir decide on the object.
func (e *Evaluator) landlockDelete(p string) (agent.EvalResult, bool) {
	r := e.landlock(agent.ActionFSDelete, p)
	return r, r.Verdict != agent.VerdictAllow
}

// LandlockDeleteRefusal is how the Landlock ruleset every enforcing tier keeps answers an unlink or rmdir of the name p
// (landedEnd): REMOVE_* on its directory, from a write entry covering it (landlockDelete). refused is false when it
// allows; rule is otherwise the directory's nearest entry, unmatched for none, as tier 1's line names it.
func LandlockDeleteRefusal(rt *agent.RuleTable, p string) (rule string, refused bool) {
	if rt == nil || p == "" {
		return agent.UnmatchedRule, false
	}
	r, refused := (&Evaluator{rt: rt}).landlockDelete(landedEnd(p))
	return r.Rule, refused
}

// LandlockDeleteRefusal is LandlockDeleteRefusal(rt, p) on the index.
func (ix *FSIndex) LandlockDeleteRefusal(p string) (rule string, refused bool) {
	if ix == nil || p == "" {
		return agent.UnmatchedRule, false
	}
	if ix.scan {
		return LandlockDeleteRefusal(ix.rt, p)
	}
	r, refused := (&Evaluator{rt: ix.rt, fs: ix}).landlockDelete(landedEnd(p))
	return r.Rule, refused
}

// LandlockRenameRefusal is landlockRename on two landed ends by scan (landedEnd), unbounded: how the Landlock ruleset
// every enforcing tier keeps answers a rename of the object at src, a directory when dir, to the name dst.
func LandlockRenameRefusal(rt *agent.RuleTable, src, dst string, dir bool) (rule string, refused bool) {
	if rt == nil || src == "" || dst == "" {
		return agent.UnmatchedRule, false
	}
	return (&Evaluator{rt: rt}).landlockRename(landedEnd(src), landedEnd(dst), dir, false)
}

// landlockRights is the ruleset's rights at a canonical end, on the index when e has one, with the exec grants' by
// e.exec when a producer supplied them.
func (e *Evaluator) landlockRights(p string) agent.AccessSet {
	if e.exec != nil {
		if e.fs != nil {
			return e.fs.landlockFSUnion(p) | e.exec(p)
		}
		return landlockFSRights(e.rt, p) | e.exec(p)
	}
	if e.fs != nil {
		return e.fs.landlockUnion(p)
	}
	return landlockRights(e.rt, p)
}

// endName is the name an end p of a rename is recorded under: its nearest entry (bounded by the root tiers' walk when
// bounded), save a symlinked entry matched by its own declared name, which names the symlink and no rule on it
// (symlinkName): the end is then named by its directory's nearest entry, as the run's line names it.
func (e *Evaluator) endName(p string, bounded bool) string {
	if e.fs != nil && !e.fs.scan && len(e.fs.links) == 0 {
		return e.nearestName(p, bounded) // no entry is declared through a link, so none is a symlinkName
	}
	if i, steps, ok := e.nearest(p); ok && steps == 0 && symlinkName(&e.rt.FS[i], p) {
		return e.nearestName(filepath.Dir(p), bounded)
	}
	return e.nearestName(p, bounded)
}

// linkGains is LinkGainsBy on two canonical ends, with the ruleset's rights at a path from rights: a hard link's object
// is a regular file.
func linkGains(src, dst string, rights func(string) agent.AccessSet) bool {
	return ReferRefuses(referGained(src, dst, rights), false)
}

// referGained is RenameGainedBy on two canonical ends, with the ruleset's rights at a path from rights:
// current_check_refer_path asks no REFER and compares nothing for a move within one directory (old_dentry->d_parent ==
// new_dir), and otherwise compares the rights at the new name's directory, its parent chain, with the moved object's
// own (its parent chain and its own rule), never with a rule on the name it replaces.
func referGained(src, dst string, rights func(string) agent.AccessSet) agent.AccessSet {
	dir := cleanDir(dst)
	if cleanDir(src) == dir {
		return 0 // no reparenting
	}
	return rights(dir) &^ rights(src)
}

// cleanDir is filepath.Dir of a clean path, without the Clean pass filepath.Dir makes over its result: every end the
// refer and unlink questions compare is clean (cleanPath, landedEnd, Canonical), and the indexed evaluator asks them
// on its query path (ADR 0028 S1's budget).
func cleanDir(p string) string {
	switch i := strings.LastIndexByte(p, '/'); {
	case i < 0:
		return "."
	case i == 0:
		return "/"
	default:
		return p[:i]
	}
}

// canonicalEnd is where the name p of a rename, a link or an unlink asked by name (Evaluate, the plane evaluator) lies:
// its directory canonicalized (Canonical), its final component as written. rename(2), linkat(2) without
// AT_SYMLINK_FOLLOW, unlink(2) and rmdir(2) never follow a final symlink, so an end that is a symlinked entry's declared
// name is the symlink, in the directory it lies in, and not the entry's target: canonicalized whole, the end was
// compared, and its directory's rights asked, at the target (F1 and F2). A path whose directory no link
// rewrites is returned as it is. Only an fs entry's declared link is followed (R15), never an exec.allow directory's:
// compile --test hands its rows over landed (RunResolved's Lander, supervisor.Land), and the run asks of landed ends
// (landedEnd).
func canonicalEnd(rt *agent.RuleTable, p string) string {
	return endOf(p, Canonical(rt, filepath.Dir(p)))
}

// canonicalEnd is canonicalEnd(rt, p) on the index: p must be clean. With no entry declared through a link,
// Canonical rewrites no directory, and p is its own end.
func (ix *FSIndex) canonicalEnd(p string) string {
	if !ix.scan && len(ix.links) == 0 {
		return p
	}
	return endOf(p, ix.Canonical(cleanDir(p)))
}

// endOf is p with its directory replaced by the canonical dir.
func endOf(p, dir string) string {
	if d := filepath.Dir(p); d == p || d == dir {
		return p
	}
	return filepath.Join(dir, filepath.Base(p))
}

// symlinkName reports whether the fs entry r covers the canonical end p only by its declared spelling, p being that
// spelling itself while the entry resolves elsewhere: the name is a symlink the run opened the entry through, the
// Landlock builder put the entry's rule on the target's inode, and tier 2's listener and tier 3's hooks decide the
// target. A rename, a link or an unlink of the name acts on the symlink, which no rule is on.
func symlinkName(r *agent.FSRule, p string) bool {
	if r.Resolved == "" || r.Path == "" {
		return false
	}
	res := filepath.Clean(r.Resolved)
	return res != filepath.Clean(r.Path) && filepath.Clean(r.Path) == p && !agent.Covers(res, p)
}

// landlockFileRights are the rights REFER's no-gain rule compares for a regular file: ACCESS_FILE in
// security/landlock/fs.c, the builder's fileRights (enforce-landlock R3). A directory right means nothing on a file.
const landlockFileRights = agent.AccessExecute | agent.AccessWriteFile | agent.AccessReadFile | agent.AccessTruncate |
	agent.AccessIoctlDev | agent.AccessResolveUnix

// landlockRights is the union of the rights the run's Landlock ruleset grants at the canonical end p, as
// internal/runtime/enforce/landlock builds it: every write entry covering p (landlockFSRights) and every exec entry
// covering it (landlockExecGrant). The read grants are left out (deny_read's enumerated levels, "/"'s read set when
// nothing is denied): each is READ_FILE and READ_DIR, with EXECUTE only while images are unrestricted, which every
// write entry grants as well, and the no-gain rule is asked only of ends a write entry covers.
func landlockRights(rt *agent.RuleTable, p string) agent.AccessSet {
	return landlockFSRights(rt, p) | landlockExecGrant(rt, p)
}

// landlockFSRights is what the write entries covering the canonical end p grant (landlockGrant), save a symlinked
// entry at its own declared name (symlinkName): that name is a symlink, and the entry's rule is on its target.
func landlockFSRights(rt *agent.RuleTable, p string) agent.AccessSet {
	var union agent.AccessSet
	for i := range rt.FS {
		if _, covered := ruleSteps(rt.FS[i], p); covered && !symlinkName(&rt.FS[i], p) {
			union |= landlockGrant(rt, &rt.FS[i])
		}
	}
	return union
}

// landlockGrant is what the ruleset grants through the fs entry r (the builder's fsEntries and writeMask): a write
// entry's rights with the read set, EXECUTE while images are unrestricted, and IOCTL_DEV only under /dev. An ask,
// watch, implicit or deny_read entry is held for identity and grants nothing.
func landlockGrant(rt *agent.RuleTable, r *agent.FSRule) agent.AccessSet {
	if r.Kind != agent.FSWrite {
		return 0
	}
	a := r.Access | agent.AccessReadFile | agent.AccessReadDir
	if rt.ExecUnrestricted() {
		a |= agent.AccessExecute
	}
	if r.Path != "/dev" && !strings.HasPrefix(r.Path, "/dev/") {
		a &^= agent.AccessIoctlDev
	}
	return a
}

// landlockExecGrant is what the exec entries covering the end p grant by the table (the builder's execGrants,
// enforce-landlock R5): EXECUTE and READ_FILE, and READ_DIR for a directory entry, which covers its whole subtree; a
// file entry covers itself. An entry is compared where the builder's grant is, at its Resolved (the kernel's walk of
// the declared name), never at a declared spelling that resolves elsewhere: that name is a symlink, or, in a landed
// end, a directory the agent put in the link's place, and neither holds the grant (ADR 0019's 2026-10-17 design
// note). Compared there as well, the spelling granted EXECUTE beneath a replaced link, and at the
// link itself only its own name was spared.
func landlockExecGrant(rt *agent.RuleTable, p string) agent.AccessSet {
	var a agent.AccessSet
	for i := range rt.Exec {
		r := &rt.Exec[i]
		e := r.Resolved
		if e == "" {
			e = r.Path
		}
		if e == "" {
			continue
		}
		switch e = cleanPath(e); {
		case r.IsDir && agent.Covers(e, p):
			a |= agent.AccessExecute | agent.AccessReadFile | agent.AccessReadDir
		case !r.IsDir && e == p:
			a |= agent.AccessExecute | agent.AccessReadFile
		}
	}
	return a
}

// denyUnenforced reports whether the Landlock tier must give up on a deny_read
// entry: it is compiled only when no enumerated level lies at or below a write
// or ask entry, the nearest enumerated level being the entry's own parent
// (SEMANTICS §2). Compile stamps the same answer on FSRule.Unenforced; this
// recomputes it so a hand-built table behaves identically.
func denyUnenforced(rt *agent.RuleTable, i int) bool {
	r := rt.FS[i]
	if r.Unenforced {
		return true
	}
	// Containment is asked of the resolved subtrees, the same question Compile's own
	// unenforced check and the backend's I5 cross-check ask (E8,
	// internal/runtime/enforce/landlock/enumerate.go unenforcedUnder): the run opens every
	// entry O_PATH without O_NOFOLLOW, so a rule governs the inode the link points at. Asking
	// it of the declared names reported a deny_read entry that symlinks *out* of a write entry
	// as unenforceable while Compile and the backend both enforce it — `compile --test`
	// contradicting the table it was handed.
	//
	// The target itself is compared, not its parent: an ancestor of the target lies below a
	// write entry iff the target does, and comparing the target also catches E26's degenerate
	// case where the write entry and the deny_read target are the same path.
	target := r.Governed()
	for j := range rt.FS {
		o := rt.FS[j]
		if o.Kind != agent.FSWrite && o.Kind != agent.FSAsk {
			continue
		}
		if agent.Covers(o.Governed(), target) {
			return true
		}
	}
	return false
}

// fsAccess is the Landlock right a filesystem action needs. Reads are decided
// by deny_read enumeration rather than by a right (SEMANTICS §2), and a
// rename needs REFER plus the comparison evalRename makes.
func fsAccess(kind agent.ActionKind) agent.AccessSet {
	switch kind {
	case agent.ActionFSWrite:
		return agent.AccessWriteFile
	case agent.ActionFSDelete:
		return agent.AccessRemoveFile
	case agent.ActionFSMkdir:
		return agent.AccessMakeDir
	case agent.ActionFSRename:
		return agent.AccessRefer
	case agent.ActionFSLink:
		// A hard link makes a regular file's name (MAKE_REG on the new name's directory) and, across directories,
		// needs REFER on both directories (Evaluator.landlock asks a link of the end's directory); the supervisor's
		// line asks the write entry that covers each directory (AdvisoryFS), the grant every write entry carries both
		// rights in.
		return agent.AccessMakeReg
	}
	return agent.AccessReadFile
}
