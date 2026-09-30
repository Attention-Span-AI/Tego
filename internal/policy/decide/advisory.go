// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// This file is the model the seccomp supervisor (internal/runtime/supervisor) records an fs syscall's advisory
// verdict by at tiers 1 and 2 (docs/p0/supervisor.md R15, R17, R15b): the mechanism's own answer, which
// Landlock and tier 2's listener make good on the continued syscall (ADR 0016 step 1). It keeps the
// supervisor's own nearest-wins tables, ordered longest path first, which answer without allocating.

// WriteFlagMask is O_WRONLY|O_RDWR|O_CREAT|O_TRUNC: the open flags the supervisor's filter notifies on (R15,
// and enforce-landlock R12, which applies the same mask in BPF). The event records the flags it saw, not the
// flags the filter tested, and under record: full the filter notifies every open and only this mask tells a
// write-open from a read-open.
const WriteFlagMask = 0x243

// IsWriteOpen reports whether open flags make an open a write: a WriteFlagMask bit. That covers R15's "or
// O_TMPFILE" too, since the kernel refuses an O_TMPFILE open without O_WRONLY or O_RDWR (EINVAL). O_TMPFILE's
// own bits must not be tested: it is __O_TMPFILE|O_DIRECTORY, so a test of any of them read every opendir as a
// write, and its value differs by architecture (on arm64 the x86 value's 0x10000 is O_DIRECT).
//
// An O_PATH open is never a write, whatever else it carries: open and openat drop every flag but O_CLOEXEC,
// O_DIRECTORY and O_NOFOLLOW when O_PATH is set (build_open_how), no file_open hook runs for it, and it can
// neither truncate nor create. openat2 refuses the combination (EINVAL). Each later use of the descriptor is
// checked on its own (a linkat through it, a reopen through /proc/self/fd).
func IsWriteOpen(flags int) bool {
	return flags&OPath == 0 && flags&WriteFlagMask != 0
}

// OPath is O_PATH, the same value on x86-64 and arm64 (the generic 010000000).
const OPath = 0x200000

// OpenReads reports whether an open reads the file it opens: its access mode is not O_WRONLY (O_RDONLY, O_RDWR, or
// mode 3, which the kernel checks for read permission too), whatever write bit it also carries. An O_RDWR open, or an
// O_RDONLY one with O_CREAT or O_TRUNC, is a write-open (IsWriteOpen) and a read at once, so a read gate scores it as
// well as a write gate (gate.md R1, amended 2026-10-16). An O_PATH open reads nothing but is decided as the read
// IsRead takes it to be. O_ACCMODE (3) and O_WRONLY (1) are the same on x86-64 and arm64.
func OpenReads(flags int) bool {
	return flags&OPath != 0 || flags&3 != 1
}

// IsRead reports whether an operation only reads: an open (record.FSOpen) whose flags carry no write bit.
// Every other operation the supervisor records modifies something.
func IsRead(op string, flags int) bool {
	return op == record.FSOpen && !IsWriteOpen(flags)
}

// IsAttrOp reports whether an fs operation changes a file's attributes rather than its content or names: a mode
// change (record.FSChmod), an extended attribute set or removed (record.FSXattr, a POSIX ACL included) or an owner
// change (record.FSChown). No Landlock ABI governs one and no hook of tier 2's kernel recorder sees one.
func IsAttrOp(op string) bool {
	return op == record.FSChmod || op == record.FSXattr || op == record.FSChown
}

// OpMknod is the operation a mknod is decided as (AdvisoryFS). record v1 has no mknod op, so its line says
// open O_CREAT|O_EXCL (record.FSOpen), but a mknod is no open: tier 2's fanotify listener never sees it, and
// the Landlock ruleset decides it as the create it is. It never appears in a record.
const OpMknod = "mknod"

// AdvisoryRule is one filesystem entry reduced to what an advisory verdict needs, ordered longest path first
// so the first match is the nearest ancestor (SEMANTICS §2).
type AdvisoryRule struct {
	Path string
	Name string
	// Write is a declared write entry: it allows reads and modifications alike.
	Write bool
	// DenyRead is a declared deny_read entry: it refuses reads of what lies under it.
	DenyRead bool
	// Unenforced marks a deny_read entry tier 1 leaves out of its ruleset because a write, ask or
	// exec.allow directory entry encloses it (agent.FSRule.Unenforced, enforce-landlock R4). The exec verdict
	// reads it: the kernel refuses the exec open of an undeclared binary under an enforced deny_read and runs
	// one under an unenforced one.
	Unenforced bool
	// UnenforcedName is Name with agent.UnenforcedSuffix, the label of a read tier 1 allows under this entry
	// when Unenforced; built once here so the query path allocates nothing.
	UnenforcedName string
	// AskRead marks a deny_read entry compiled from fs.ask_read (agent.FSRule.AskRead): it decides every verdict
	// as the deny_read it is, and tells tier 1's supervisor that a read-open it decides may be held for a person.
	AskRead bool
}

// AdvisoryList is one of the advisory tables: the entries longest path first, and the same entries keyed by
// path, so that the nearest entry enclosing a path is a lookup per component of the path and not a walk of every
// entry. The .env scan can put 50,000 deny_read entries into a table (agent.envScanMaxEntries, files the agent
// plants in an earlier run), and the supervisor asks the list once per notified fs syscall, each of which holds
// the agent's thread until answered: scanned, a tier-1 read-open cost milliseconds and a rename tens of them
// (TestAdvisoryCostDoesNotGrowWithEntries holds the cost flat). Read only once built.
type AdvisoryList struct {
	// Rules is the list, longest path first; among equal paths, in table order.
	Rules []AdvisoryRule
	// at is the positions in Rules of the entries at each path, ascending.
	at map[string][]int
	// watch is the table's watch entries under each spelling, which the advisory tables leave out and a name
	// still honours (nameAt); it is the contract's own few, not the scan's.
	watch []advisoryWatch
	// ix answers the questions that need the whole table (the tier-2 listener's, REFER's, the exec grant's)
	// by index; nil when the list was built from entries alone, and they are then asked by scan.
	ix          *FSIndex
	hasDenyRead bool
}

type advisoryWatch struct{ path, name string }

// AdvisoryTables is a table's fs entries as the supervisor matches them, each list longest path first.
type AdvisoryTables struct {
	// Declared is every entry at its declared path.
	Declared *AdvisoryList
	// Resolved is every entry at its symlink-resolved path (agent.FSRule.Resolved): the table a relayed unix
	// connect's resolved socket, or where a walk found a spelling lands, is matched against.
	Resolved *AdvisoryList
	// Both is every entry under both spellings, resolved and declared: what the advisory verdicts on the
	// paths a target passed compare with (R15b). A relative path is joined to the task's /proc/<pid>/cwd,
	// which the kernel spells canonically, while a program may spell an absolute one through the symlink the
	// contract was written through; matched against the declared paths alone, a write Landlock allowed under
	// a project reached through a symlink was recorded refused, and a read it refused allow.
	Both *AdvisoryList
	// FS is the table's index (NewFSIndex), set by NewAdvisoryTablesFor: the supervisor asks REFER's rule, the
	// listener's open decision and the exec grant of it, whatever the number of entries.
	FS *FSIndex
}

// NewAdvisoryTablesFor derives the advisory tables from a table, with the table's index, so that every
// question the supervisor asks costs the depth of the path and not the number of entries.
func NewAdvisoryTablesFor(rt *agent.RuleTable) AdvisoryTables {
	if rt == nil {
		return AdvisoryTables{}
	}
	t := NewAdvisoryTables(rt.FS)
	t.FS = NewFSIndex(rt)
	for _, l := range []*AdvisoryList{t.Declared, t.Resolved, t.Both} {
		l.ix = t.FS
	}
	return t
}

// NewAdvisoryTables derives the advisory tables from a table's fs entries.
func NewAdvisoryTables(fs []agent.FSRule) AdvisoryTables {
	var declaredL, resolvedL, bothL []AdvisoryRule
	var watch []advisoryWatch
	for _, r := range fs {
		if r.Kind == agent.FSWatch {
			for _, sp := range [2]string{r.Path, r.Resolved} {
				if sp = TrimDir(sp); sp != "" {
					watch = append(watch, advisoryWatch{sp, r.RuleName()})
				}
			}
		}
		if r.Path == "" || r.Kind == agent.FSWatch {
			// A watch entry carries no rights of its own (agent.FSRule: "Access: 0 for deny_read, watch
			// and implicit entries"); it selects what is recorded individually rather than aggregated
			// (SEMANTICS §7). Letting it into the nearest-wins table would shadow an ancestor write
			// grant and invent refusals for writes Landlock actually allows.
			continue
		}
		fr := AdvisoryRule{
			Path: TrimDir(r.Path),
			// agent.FSRule.RuleName is the one spelling of a `rule` field
			// (spec/record/v1/README.md: "the declared entry or unmatched").
			// A position in the compiled list is not an entry anyone declared
			// and never matched what `tego drift` compares against.
			Name:       r.RuleName(),
			Write:      r.Kind == agent.FSWrite,
			DenyRead:   r.Kind == agent.FSDenyRead,
			Unenforced: r.Kind == agent.FSDenyRead && r.Unenforced,
			AskRead:    r.Kind == agent.FSDenyRead && r.AskRead,
		}
		if fr.Unenforced {
			fr.UnenforcedName = fr.Name + agent.UnenforcedSuffix
		}
		declaredL = append(declaredL, fr)
		declared := fr
		if r.Resolved != "" {
			fr.Path = TrimDir(r.Resolved)
		}
		resolvedL = append(resolvedL, fr)
		// Resolved first, so that of two spellings of one length the canonical one is the entry matched.
		bothL = append(bothL, fr)
		if declared.Path != fr.Path {
			bothL = append(bothL, declared)
		}
	}
	return AdvisoryTables{
		Declared: newAdvisoryList(declaredL, watch),
		Resolved: newAdvisoryList(resolvedL, watch),
		Both:     newAdvisoryList(bothL, watch),
	}
}

// newAdvisoryList orders rules longest path first: the first entry that is an ancestor of the target is the
// nearest one. The order among equal paths is the given one, which the position lists keep.
func newAdvisoryList(rules []AdvisoryRule, watch []advisoryWatch) *AdvisoryList {
	sort.SliceStable(rules, func(i, j int) bool { return len(rules[i].Path) > len(rules[j].Path) })
	l := &AdvisoryList{Rules: rules, at: make(map[string][]int, len(rules)), watch: watch}
	for i := range rules {
		l.hasDenyRead = l.hasDenyRead || rules[i].DenyRead
		if p := rules[i].Path; p != "" {
			l.at[p] = append(l.at[p], i)
		}
	}
	return l
}

// HasDenyRead reports whether an unresolved lookup could cross a negative
// filesystem entry while Landlock's enclosing write grant still admits it.
func (l *AdvisoryList) HasDenyRead() bool { return l != nil && l.hasDenyRead }

// TrimDir drops a declared entry's trailing slash so that matching can compare "<entry>/" prefixes. The
// root keeps its slash: it is the one entry that is its own separator.
func TrimDir(p string) string {
	if p == "/" {
		return p
	}
	return strings.TrimSuffix(p, "/")
}

// NearestIn is the nearest ancestor of p among the entries of l, which is p itself or the enclosing entry with
// the longest path (SEMANTICS §2), the first of those in table order; nil when none encloses p.
func NearestIn(l *AdvisoryList, p string) *AdvisoryRule { return NearestWhere(l, p, nil) }

// NearestWhere is NearestIn over the entries keep accepts (all of them when keep is nil). An entry encloses p
// when its path is p, or p continues it with a "/", or it is the root; each of those is a key of the list, so
// the walk asks the list once per "/" of p, deepest first, which is the order of a scan of the list longest
// path first, whatever the spelling of the paths.
func NearestWhere(l *AdvisoryList, p string, keep func(*AdvisoryRule) bool) *AdvisoryRule {
	if l == nil || p == "" {
		return nil
	}
	at := func(key string) *AdvisoryRule {
		for _, i := range l.at[key] {
			if r := &l.Rules[i]; keep == nil || keep(r) {
				return r
			}
		}
		return nil
	}
	if r := at(p); r != nil {
		return r
	}
	for i := len(p) - 1; i > 0; i-- {
		if p[i] == '/' {
			if r := at(p[:i]); r != nil {
				return r
			}
		}
	}
	if p[0] == '/' {
		return at("/")
	}
	return nil
}

// nearestReadIn is NearestIn over the entries that decide a read: write and deny_read.
func nearestReadIn(l *AdvisoryList, p string) *AdvisoryRule {
	return NearestWhere(l, p, func(r *AdvisoryRule) bool { return r.Write || r.DenyRead })
}

// NearestDenyRead is the nearest deny_read entry of l that is p or an ancestor of it, whatever other entry
// lies between: Landlock unions every rule on a path, so what a deny_read withholds is decided by the
// deny_read alone (Evaluate's Landlock read arm, nearestFSOfKind).
func NearestDenyRead(l *AdvisoryList, p string) *AdvisoryRule {
	return NearestWhere(l, p, func(r *AdvisoryRule) bool { return r.DenyRead })
}

// AdvisoryFS is the advisory verdict of one fs syscall on path p in rt's tier: nearest entry wins (SEMANTICS
// §2) over rules, one of the AdvisoryTables of rt. A write entry allows anything; every other outcome depends
// on whether the operation modifies. A walk that ends without a hit is unmatched, which allows a read and
// refuses everything else — the same asymmetry the root tiers apply (R15, R17, SEMANTICS §2 "reads allowed,
// everything else refused").
//
// At tier cgroup a file a name entry covers (ADR 0043 D1, D7) is refused as a deny_read entry at its own path would
// refuse it, once the walk allowed the question: a read-open and a write-open read-denied, as the fanotify listener
// refuses them, any other modification with the operation's reason, which the listener fallback's supervisor
// enforces (fallbackMutation), named per D8; a climb that cannot decide refuses path-unresolved. dir says the object
// is a directory, which no name entry decides: a mkdir, an rmdir, a rename of a directory, a directory listing. An
// end the operation does not follow (an unlink's, a rename's, a link's, a creation's) is matched in the directory it
// lies in (canonicalEnd), an open's and a truncate's where the declared links lead (Canonical), as Evaluate asks them.
//
// A read-open only reaches the supervisor under record: full; under summary and off the filter never
// notifies one (enforce-landlock R16).
func AdvisoryFS(rt *agent.RuleTable, rules *AdvisoryList, p, op string, flags int, dir bool) (string, record.Verdict, record.Reason) {
	var tier backend.Tier
	if rt != nil {
		tier = rt.Tier
	}
	near := NearestIn(rules, p)
	rule := agent.UnmatchedRule
	if near != nil {
		rule = near.Name
	}
	// Tier 2's fanotify listener decides every open without seeing its access mode, so a write-open under a
	// deny_read nested in a write entry is refused read-denied unless a longer write entry reopens the path,
	// whatever Landlock grants: the verdict is the listener's, as compile --test answers it (R15).
	if op == record.FSOpen && !IsRead(op, flags) && tier == backend.TierCgroup {
		if d, ok := rules.listenerOpenRefused(rt, p); ok {
			return d.RuleName(), record.VerdictRefused, record.ReasonReadDenied
		}
		// So is a write-open of a file a name entry covers (Evaluate's listenerNameRefused); a climb that cannot decide
		// is left to the root walk's name check below.
		if rule, why, refused := rules.nameRefused(rt, p, op, dir, record.ReasonReadDenied); refused && why == record.ReasonReadDenied {
			return rule, record.VerdictRefused, why
		}
	}
	if tier == backend.TierCgroup && !IsRead(op, flags) && !IsAttrOp(op) {
		name, steps, named := nameAtSteps(rt, rules, near, p)
		var d fsDecision
		hit := near != nil && advisorySteps(near.Path, p) <= agent.MaxWalk
		if hit {
			d = fsDecision{name: near.Name, kind: agent.FSImplicit}
			if near.Write {
				d.kind = agent.FSWrite
			} else if near.DenyRead {
				d.kind = agent.FSDenyRead
			}
		}
		if r := rootAnswer(p, name, steps, named, d, hit, false, OpReason(op)); r.Verdict != agent.VerdictAllow {
			return r.Rule, record.VerdictRefused, r.Reason
		}
		if rule, why, refused := rules.nameRefused(rt, p, op, dir, OpReason(op)); refused {
			return rule, record.VerdictRefused, why
		}
	}
	// Landlock checks an unlink's REMOVE_* and a rename's REFER on the parent directory, so deleting or
	// renaming a write entry itself (write: [./out], then rm -rf out) is decided by what grants the
	// directory above it, which that entry does not (Evaluate's evalFSLandlock; R15). A hard link is decided there
	// at both ends too (MAKE_REG on the new name's directory, REFER on both when they differ), never on the file:
	// a file-level write entry grants no directory right, so linking it elsewhere is refused (EXDEV).
	// Tier 3's hooks decide on the path itself.
	if (op == record.FSUnlink || op == record.FSRename || op == record.FSLink) && tier != backend.TierBPFLSM {
		at := filepath.Dir(p)
		if w := NearestWhere(rules, at, func(r *AdvisoryRule) bool { return r.Write }); w != nil {
			return w.Name, record.VerdictAllow, ""
		}
		return nameAt(rt, rules, NearestIn(rules, at), at), record.VerdictRefused, OpReason(op)
	}
	read := IsRead(op, flags)
	if near != nil && near.Write && !read {
		return rule, record.VerdictAllow, ""
	}
	if read {
		// Only a write or a deny_read entry decides a read: an implicit entry (the ledger root, the contract)
		// is a write guard that grants no read, and nearer than a deny_read above it (the ledger root beneath
		// ~/.tego, agent-contract R6a) it made a read Landlock refused read as allowed. A deny_read the
		// Landlock ruleset leaves unenforced refuses nothing at tier 1 (ADR 0016); tier 2's fanotify listener
		// refuses it.
		//
		// An O_PATH open reads nothing and the kernel runs no file_open hook for it (do_dentry_open returns before
		// security_file_open and the fanotify permission event), so no tier's mechanism refuses one: not the
		// Landlock ruleset, a deny_read it enforces included, not tier 2's fanotify listener, not the decision
		// plane, whose only open hook is file_open, and not held reads (ADR 0069 D2), which leave it as it was. At
		// every tier it is allowed by the entry with the O_PATH marker, never "refused" for an open the kernel let
		// through, nor "unenforced" in a run that holds its reads. Every read through its
		// descriptor is another open, decided on its own.
		d := nearestReadIn(rules, p)
		if d != nil && d.DenyRead && op == record.FSOpen && flags&OPath != 0 {
			return d.Name + agent.OPathSuffix, record.VerdictAllow, ""
		}
		if d != nil && d.DenyRead && !(d.Unenforced && tier == backend.TierLandlock) {
			// A declared exec entry strictly inside the target keeps its own fd with READ_FILE at tier 1
			// (enforce-landlock R5, I11 (1)), so the kernel lets a read of it, or beneath a directory entry,
			// through (ExecReadGrant; R15).
			if tier == backend.TierLandlock {
				if x, ok := rules.execReadGrant(rt, p); ok {
					return x.RuleName(), record.VerdictAllow, ""
				}
			}
			return d.Name, record.VerdictRefused, record.ReasonReadDenied
		}
		// A deny_read the Landlock ruleset cannot enforce is named with the marker compile --test gives it
		// (evalFSLandlock), so the line and compile's answer carry one label.
		if d != nil && d.DenyRead && d.Unenforced && tier == backend.TierLandlock {
			return d.UnenforcedName, record.VerdictAllow, ""
		}
		// A read at or beneath the name the Landlock ruleset leaves ungranted for an absent built-in row is refused by
		// that ruleset, which every enforcing tier installs (AbsentRead, ADR 0067 D3): recorded allow, it was a read
		// that never happened.
		if name, ok := AbsentRead(rt, tier, p); ok {
			return name, record.VerdictRefused, record.ReasonReadDenied
		}
		// Tier 2's listener refuses a read-open of a file a name entry covers (ListenerOpenName).
		if tier == backend.TierCgroup {
			if rule, why, refused := rules.nameRefused(rt, p, op, dir, record.ReasonReadDenied); refused {
				return rule, record.VerdictRefused, why
			}
		}
		return nameAt(rt, rules, near, p), record.VerdictAllow, ""
	}
	// A modification is decided by the Landlock ruleset at tiers 1 and 2 (tier 2 inherits it for writes),
	// which unions the rights of every rule on the path: any enclosing write entry grants it, a deny_read or
	// an implicit entry nested in it included. Nearest-wins, tier 3's rule, recorded refused a write that
	// happened (ADR 0016 step 1, R15); a deny_write target is refused by the supervisor's own check on top.
	if w := NearestWhere(rules, p, func(r *AdvisoryRule) bool { return r.Write }); w != nil {
		return w.Name, record.VerdictAllow, ""
	}
	return nameAt(rt, rules, near, p), record.VerdictRefused, OpReason(op)
}

// listenerOpenRefused is ListenerOpenRefused(rt, p), by the list's index when it has one.
func (l *AdvisoryList) listenerOpenRefused(rt *agent.RuleTable, p string) (agent.FSRule, bool) {
	if l != nil && l.ix != nil {
		return l.ix.ListenerOpenRefused(p)
	}
	return ListenerOpenRefused(rt, p)
}

// nameRefused is the name entries' answer (FSIndex.NameRefused) for op's object at p, by the list's index when it has
// one: never for a directory; an end op does not follow is asked in the directory it lies in (canonicalEnd), an
// open's and a truncate's where the declared links lead (Canonical).
func (l *AdvisoryList) nameRefused(rt *agent.RuleTable, p, op string, dir bool, reason record.Reason) (string, record.Reason, bool) {
	if dir {
		return "", "", false
	}
	follows := op == record.FSOpen || op == record.FSTruncate
	if l != nil && l.ix != nil {
		if !l.ix.HasNames() {
			return "", "", false
		}
		end := l.ix.canonicalEnd(p)
		if follows {
			end = l.ix.Canonical(p)
		}
		return l.ix.NameRefused(end, reason)
	}
	n := newNameIndex(rt)
	if n == nil {
		return "", "", false
	}
	end := canonicalEnd(rt, cleanPath(p))
	if follows {
		end = Canonical(rt, cleanPath(p))
	}
	return nameRefused(n, end, reason, func(q string) int { return denyAtScan(rt, q) })
}

// execReadGrant is ExecReadGrant(rt, p), by the list's index when it has one.
func (l *AdvisoryList) execReadGrant(rt *agent.RuleTable, p string) (*agent.ExecRule, bool) {
	if l != nil && l.ix != nil {
		return l.ix.ExecReadGrant(p)
	}
	return ExecReadGrant(rt, p)
}

// nameAt is the name of an action at p that no entry's kind decides by name — an allowed read, a refused
// modification: the nearest entry of any kind, watch entries included, as Evaluate names it (nearestFS,
// SEMANTICS §7). near is the nearest entry of the advisory tables, which hold no watch entry (a watch entry
// grants nothing and must not shadow a grant); a watch entry of rt, under its declared or its resolved path,
// that lies nearer names the action instead. Nothing is allocated unless a watch entry names it.
func nameAt(rt *agent.RuleTable, l *AdvisoryList, near *AdvisoryRule, p string) string {
	name, _, _ := nameAtSteps(rt, l, near, p)
	return name
}

func nameAtSteps(rt *agent.RuleTable, l *AdvisoryList, near *AdvisoryRule, p string) (string, int, bool) {
	name, best := agent.UnmatchedRule, -1
	path := ""
	if near != nil {
		name, best = near.Name, len(near.Path)
		path = near.Path
	}
	if rt == nil || l == nil {
		return name, advisorySteps(path, p), path != ""
	}
	for _, w := range l.watch {
		if len(w.path) <= best {
			continue
		}
		if p == w.path || strings.HasPrefix(p, w.path+"/") || (w.path == "/" && strings.HasPrefix(p, "/")) {
			name, best = w.name, len(w.path)
			path = w.path
		}
	}
	return name, advisorySteps(path, p), path != ""
}

// advisorySteps measures the same component distance as CoverSteps, without
// cleaning or allocating: the caller's resolved/declared view is already clean.
func advisorySteps(at, p string) int {
	if at == "" {
		return 0
	}
	if at == p {
		return 0
	}
	rest := p[len(at):]
	if at != "/" {
		rest = rest[1:]
	}
	return strings.Count(rest, "/") + 1
}
