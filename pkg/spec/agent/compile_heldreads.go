// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// This file is fs.reads as compile output (ADR 0069): which deny_read targets lie at or beneath a write entry, where
// the Landlock ruleset cannot withhold a read, and so whether a run holds its read opens, the open deputy completing
// each one and the supervisor refusing it on the object it reached (RuleTable.ReadsHeldAt). Held reads also carry the
// name rules a file made during the run is refused by, which no ruleset row exists for.

// ReadsMode is fs.reads (ADR 0069 D1).
type ReadsMode string

const (
	// ReadsAuto, the default, holds read opens at tier landlock exactly when a deny_read target lies at or beneath a
	// write entry (RuleTable.Reads.Nested); the root tiers' kernel refuses such a read itself.
	ReadsAuto ReadsMode = "auto"
	// ReadsHeld holds read opens at every enforcing tier, so a file a deny_read name rule covers that is made during
	// the run is refused too.
	ReadsHeld ReadsMode = "held"
	// ReadsDirect never holds them: a nested target stays unenforced at tier landlock, warned and recorded. Only the
	// top-level contract's value counts (a loosening value of a stricter key, ADR 0065).
	ReadsDirect ReadsMode = "direct"
)

// readsOrder is fs.reads' merge order, strictest first (merge.go): held, then auto, then direct, which is loosening.
var readsOrder = []string{string(ReadsHeld), string(ReadsAuto), string(ReadsDirect)}

// HeldReadCost describes the work added per read open. The pre-identity figures
// predate the directory barriers; current cost grows with the watched tree.
const HeldReadCost = "extra work per read open grows with the protected tree; current overhead is unmeasured"

// Why a run's reads are held or direct (RuleTable.ReadsWhy): run_start fs_reads.why's values, which the record
// defines (record.FSReadsWhy*).
const (
	ReadsWhyContract    = record.FSReadsWhyContract
	ReadsWhyNested      = record.FSReadsWhyNested
	ReadsWhyDirect      = record.FSReadsWhyDirect
	ReadsWhyNoneNested  = record.FSReadsWhyNoneNested
	ReadsWhyKernel      = record.FSReadsWhyKernel
	ReadsWhyRecordsOnly = record.FSReadsWhyRecordsOnly
)

// HeldReads is RuleTable.Reads.
type HeldReads struct {
	// Mode is the effective fs.reads: never "" after Compile.
	Mode ReadsMode
	// Nested are the deny_read targets at or beneath a write entry, in table order: a declared entry, a file a
	// declared glob expanded to, a built-in entry or a .env file the scan found. The Landlock ruleset leaves each
	// unenforced (FSRule.Unenforced); held reads refuse it.
	Nested []NestedRead
	// Patterns are the deny_read name rules a held read is refused by wherever the file came from: the
	// RuleTable.DenyReadPatterns the table's deny_read entries stand for (the built-in home paths only while the
	// built-in list is on).
	Patterns []DenyReadPattern
	// Names are the built-in .env list's name entries over the .env scan's roots (ADR 0043 Terms, F3: never beneath
	// a dependency directory), and Exempt D3's exemptions of them: what refuses a .env file made during the run.
	// Empty while the built-in list is off.
	Names  []NameDenyRule
	Exempt []NameExemptRule
}

// NestedRead is one deny_read target inside a write entry (HeldReads.Nested).
type NestedRead struct {
	// Rule is the deny_read's rule name (FSRule.RuleName).
	Rule string
	// Path and Resolved are the target's, Write and WriteResolved the write entry's that covers it, as declared and
	// where it lands.
	Path, Resolved, Write, WriteResolved string
	// BuiltIn marks a target of the built-in list or the .env scan.
	BuiltIn bool
	// Pos is where the target was declared; zero for a built-in one.
	Pos Pos
}

// ReadsHeldAt reports whether a run of the table at tier holds its read opens (ADR 0069 D1): fs.reads: held at every
// enforcing tier, auto at tier landlock while a deny_read target lies inside a write entry, direct never, and no run
// that enforces nothing.
func (rt *RuleTable) ReadsHeldAt(t backend.Tier) bool {
	return rt.ReadsWhy(t) == ReadsWhyContract || rt.ReadsWhy(t) == ReadsWhyNested
}

// ReadsHeld is ReadsHeldAt the table's own tier: a run's table is placed at its tier (AtTier) before Prepare.
func (rt *RuleTable) ReadsHeld() bool { return rt != nil && rt.ReadsHeldAt(rt.Tier) }

// ReadsWhy is why a run of the table at tier holds its reads or reads direct, one of the ReadsWhy values.
func (rt *RuleTable) ReadsWhy(t backend.Tier) string {
	if rt == nil {
		return ReadsWhyRecordsOnly
	}
	switch t {
	case backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM:
	case backend.TierObserve, backend.TierAuto:
		return ReadsWhyRecordsOnly // observe enforces nothing; auto is no run's tier (AtTier places it)
	default:
		return ReadsWhyRecordsOnly
	}
	switch rt.Reads.Mode {
	case ReadsHeld:
		return ReadsWhyContract
	case ReadsDirect:
		return ReadsWhyDirect
	case ReadsAuto:
	}
	if t != backend.TierLandlock {
		return ReadsWhyKernel
	}
	if len(rt.Reads.Nested) == 0 {
		return ReadsWhyNoneNested
	}
	return ReadsWhyNested
}

// NestedRule is the nested target a deny_read rule name stands for, if one does.
func (h *HeldReads) NestedRule(rule string) (NestedRead, bool) {
	for _, n := range h.Nested {
		if n.Rule == rule {
			return n, true
		}
	}
	return NestedRead{}, false
}

func validateFSReads(ds *diags, c *Contract, at func(string) Pos) {
	if c.FS == nil {
		return
	}
	switch c.FS.Reads {
	case "", ReadsAuto, ReadsHeld, ReadsDirect:
	default:
		ds.errorf(at("fs.reads"), CodeSchema, "fs.reads %q: want auto, held or direct", c.FS.Reads)
	}
	// Held reads reuse gate.completion: held's completion, and need what it needs (ADR 0069 D2), refused as gate and
	// ask are. A ring's IORING_OP_OPENAT never passes the seccomp filter, so where a root tier's plane admits io_uring
	// the held floor would never see that open, and the name rules a file made during the run is refused by would not
	// hold. setuid: true leaves no_new_privs unset at a root tier, so a task may change its credentials, while the
	// deputy completes every read with the credentials it was exec'd with (ADR 0041 RGD2-5): the open would be
	// answered as someone else. auto holds reads only at tier landlock, where io_uring stays ENOSYS and no_new_privs is
	// mandatory.
	if c.FS.Reads == ReadsHeld && c.IOUring {
		ds.errorf(at("fs.reads"), CodeSchema, "fs.reads: held requires io_uring disabled: a ring's opens never reach the open deputy").
			fix("drop io_uring: true, or remove fs.reads: held")
	}
	if c.FS.Reads == ReadsHeld && c.Setuid {
		ds.errorf(at("fs.reads"), CodeSchema, "fs.reads: held requires setuid disabled: the open deputy completes reads with the run's starting credentials, not a setuid program's").
			fix("drop setuid: true, or remove fs.reads: held")
	}
}

// heldReads settles RuleTable.Reads once the fs entries and the fs.ask_read entries are final (an fs.ask_read entry
// may replace a built-in deny_read) and before the exec grants mark their own unenforced entries
// (denyReadUnderExecDirs), so Nested holds the targets a write entry covers and nothing else. It says which reads are
// held and why, with the cost, or, for fs.reads: direct, each nested target's unenforced warning.
func (k *compiler) heldReads() {
	h := &k.rt.Reads
	h.Mode = ReadsAuto
	if k.c.FS != nil && k.c.FS.Reads != "" {
		h.Mode = k.c.FS.Reads
	}
	for i := range k.rt.FS {
		r := &k.rt.FS[i]
		if r.Kind != FSDenyRead || !r.Unenforced || r.AskRead {
			continue
		}
		w, ok := k.nestedWrite[r.Path]
		if !ok {
			continue
		}
		h.Nested = append(h.Nested, NestedRead{Rule: r.RuleName(), Path: r.Path, Resolved: r.Resolved, Write: w.declared,
			WriteResolved: w.resolved, BuiltIn: r.BuiltIn, Pos: r.Pos})
	}
	builtIn := k.c.FS == nil || k.c.FS.DenyRead == nil || len(k.c.FS.DenyRead) > 0
	h.Patterns = k.heldPatterns(builtIn)
	if builtIn {
		b := &fsBuilder{k: k, rules: k.rt.FS}
		if scopes := b.envNameScopes(envScanRoots(k.rt.ContractPath, k.o.cwd)); len(scopes) > 0 {
			h.Names = BuiltInEnvEntries(scopes)
			h.Exempt = b.nameExempts(h.Names)
		}
	}
	k.heldReadsDiagnostics()
	k.heldGlobNotes()
}

// heldPatterns is HeldReads.Patterns: RuleTable.DenyReadPatterns, less the built-in home paths' while the built-in
// list is off (`deny_read: []`), which compile records for a person's alternates whatever the contract says
// (builtInDenyReadPatterns) but which no ruleset row denies then.
func (k *compiler) heldPatterns(builtIn bool) []DenyReadPattern {
	if builtIn {
		return slices.Clone(k.rt.DenyReadPatterns)
	}
	off := map[string]bool{}
	if home := k.o.home; home != "" {
		for _, rel := range builtInDenyRead {
			off["fs."+string(FSDenyRead)+"["+filepath.Join(home, rel)+"]"] = true
		}
	}
	var out []DenyReadPattern
	for _, p := range k.rt.DenyReadPatterns {
		if !off[p.Rule] {
			out = append(out, p)
		}
	}
	return out
}

// heldReadsDiagnostics is what compile says of fs.reads: under fs.reads: direct, or auto where no run can land at
// tier landlock, each nested target's unenforced warning as before ADR 0069; where reads are held at tier landlock,
// which targets are held, the cost, and the launch identity and replacement checks (ADR 0069 D3(b));
// under fs.reads: held, the cost at every tier.
func (k *compiler) heldReadsDiagnostics() {
	h := &k.rt.Reads
	landlock := k.mayLand(backend.TierLandlock)
	held := h.Mode == ReadsHeld || h.Mode == ReadsAuto && len(h.Nested) > 0
	if !landlock || !held {
		if !landlock {
			return
		}
		for _, n := range h.Nested {
			k.ds.warnf(n.Pos, CodeUnenforced, "deny_read %s%s is unenforced in the landlock tier: parent %s%s is writable",
				n.Path, resolvedNote(n.Path, n.Resolved), n.Write, resolvedNote(n.Write, n.WriteResolved)).
				fix("pin a root tier, move the secret outside the write entry, or remove fs.reads: direct").only(backend.TierLandlock)
		}
		return
	}
	for _, n := range h.Nested {
		k.ds.warnf(n.Pos, CodeHeldReads, "deny_read %s%s lies inside write entry %s%s: at tier landlock the run's reads are held (fs.reads: %s), "+
			"so the open deputy completes every read open, %s; launch-pinned targets stay refused after rename or hard link; "+
			"a file put at a protected name later is pinned in turn; a change that cannot be followed refuses held reads until restart",
			n.Path, resolvedNote(n.Path, n.Resolved), n.Write, resolvedNote(n.Write, n.WriteResolved), h.Mode, HeldReadCost).
			fix("move the secret outside the write entry to read directly, or pin a root tier").only(backend.TierLandlock)
	}
	if h.Mode == ReadsHeld {
		k.ds.warnf(k.pos("fs.reads"), CodeHeldReads, "fs.reads: held: the open deputy completes every read open of the run at every tier, %s, "+
			"and a file a deny_read name rule covers is refused whenever it was made", HeldReadCost).
			fix("remove fs.reads: held to hold reads only where a deny_read target lies inside a write entry")
	}
}

// globLaterTail ends compile_fs's warning at a whole deny_read glob (CodeGlobNoMatch): what it says of a matching file
// made after compile.
const globLaterTail = "; files created later are not covered"

// heldGlobNotes rewords that warning where the table's runs hold their reads at a tier it can land at: a held read
// refuses a matching file made during the run there (D3 (c), the glob as written, HeldReads.Patterns), so compile
// says so, and keeps "not covered" for the tiers that read direct (the print must not contradict its own reads line).
func (k *compiler) heldGlobNotes() {
	if k.c.FS == nil {
		return
	}
	var held, direct []string
	for _, t := range k.rt.Reach {
		if k.rt.ReadsHeldAt(t) {
			held = append(held, string(t))
		} else {
			direct = append(direct, string(t))
		}
	}
	if len(held) == 0 {
		return
	}
	note := "; a matching file made during the run is refused at " + tierPhrase(held) +
		", where the run holds its reads (fs.reads: " + string(k.rt.Reads.Mode) + ")"
	if len(direct) > 0 {
		note += ", and not covered at " + tierPhrase(direct)
	}
	// A glob whose name entry the caps kept already says its later files are covered at the root tiers
	// (laterCovered, ADR 0043); held reads add tier landlock where they hold there.
	landlock := slices.Contains(held, string(backend.TierLandlock))
	for i := range k.c.FS.DenyRead {
		pos := k.pos("fs.deny_read." + strconv.Itoa(i))
		for j := range k.ds.list {
			d := &k.ds.list[j]
			if d.Code != CodeGlobNoMatch || d.File != pos.File || d.Line != pos.Line || d.Col != pos.Col ||
				!strings.HasPrefix(d.Message, "fs.deny_read ") {
				continue
			}
			switch {
			case strings.HasSuffix(d.Message, globLaterTail):
				d.Message = strings.TrimSuffix(d.Message, globLaterTail) + note
			case landlock && strings.HasSuffix(d.Message, laterCovered):
				d.Message = strings.TrimSuffix(d.Message, laterCovered) + laterCoveredRoot +
					", and at tier landlock, where the run holds its reads (fs.reads: " + string(k.rt.Reads.Mode) + ")"
			}
		}
	}
}

// tierPhrase names tiers in prose: "tier landlock", "tiers cgroup, bpflsm".
func tierPhrase(ts []string) string {
	if len(ts) == 1 {
		return "tier " + ts[0]
	}
	return "tiers " + strings.Join(ts, ", ")
}

// heldReadsLine is compile's print of fs.reads (PrintRuleTable): which reads are held, why and at what cost, or why
// they are direct.
func heldReadsLine(rt *RuleTable) string {
	h := &rt.Reads
	targets := func() string {
		names := make([]string, 0, len(h.Nested))
		for i, n := range h.Nested {
			if i == 3 {
				names = append(names, "and "+strconv.Itoa(len(h.Nested)-3)+" more")
				break
			}
			names = append(names, n.Path+" in "+n.Write)
		}
		return strings.Join(names, ", ")
	}
	// What holding costs beyond the time (ADR 0041 D2, enforce-landlock R10): the deputy is a process of the run's
	// domain, so no process of the run makes a domain of its own, and where the domain handles EXECUTE the deputy's
	// start takes the runtime exec grant on tego's own binary.
	held := "; the open deputy, a process of the run, completes each read open and the floor refuses one on the object it " +
		"reached; the run's processes make no Landlock domain of their own (landlock_* answer ENOSYS)"
	if !rt.ExecUnrestricted() {
		held += "; runtime exec grant: tego's own binary, for the deputy"
	}
	switch {
	case h.Mode == ReadsHeld:
		return "held at every tier (fs.reads: held); " + HeldReadCost + held +
			"; launch-pinned targets moved or hard-linked to another name stay refused; a file put at a protected name later is pinned in turn; a change that cannot be followed refuses held reads until restart"
	case h.Mode == ReadsDirect && len(h.Nested) > 0:
		return "direct (fs.reads: direct): " + strconv.Itoa(len(h.Nested)) + " deny_read target(s) inside write entries unenforced at tier landlock: " + targets()
	case h.Mode == ReadsDirect:
		return "direct (fs.reads: direct)"
	case len(h.Nested) > 0 && rt.mayLandAt(backend.TierLandlock):
		return "held at tier landlock (fs.reads: auto: " + targets() + "); " + HeldReadCost + held +
			"; launch-pinned targets moved or hard-linked to another name stay refused; a file put at a protected name later is pinned in turn; a change that cannot be followed refuses held reads until restart"
	case len(h.Nested) > 0:
		return "direct (fs.reads: auto: the kernel refuses a deny_read inside a write entry at this table's tiers)"
	}
	return "" // auto with nothing nested: the default, and nothing to hold
}

// mayLandAt reports whether a run of the table can be given tier t (RuleTable.Reach).
func (rt *RuleTable) mayLandAt(t backend.Tier) bool { return slices.Contains(rt.Reach, t) }

// heldAtLandlock reports whether a run of the table can land at tier landlock and holds its reads there.
func (rt *RuleTable) heldAtLandlock() bool {
	return rt.mayLandAt(backend.TierLandlock) && rt.ReadsHeldAt(backend.TierLandlock)
}
