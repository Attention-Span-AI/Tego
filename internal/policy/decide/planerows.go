// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// This file is the plane's row compiler (ADR 0028 S4, docs/p0/TIER3-PLAN.md T5, enforce-plane R5, R11, R17): it
// turns a compiled RuleTable into the rows bpf/decide.bpf.c walks, as an abstract list keyed by canonical path.
// The fill (TIER3-PLAN T4) opens each path O_PATH and keys its row by the inode the kernel resolves; nothing here
// knows an inode. The rows come from the root model (rootrows.go), so the plane and compile --test's bpflsm column
// cannot disagree (TestPlaneRowsMatchEvaluate).
//
// The kernel's walk stops at the first row of the run's gen it meets (tego_walk_step): it does not go on past a
// row whose entry does not decide the question, as RootIndex.Walk does. So every row here is complete: each carries
// the answer the root model gives at its own path for every question, inherited from the entries above it where
// its own entries do not decide (a watch entry, an implicit entry for a read, a row that is not an entry at all).
// A path whose nearest row is p takes p's answer, because no entry lies between them: an entry's path is a row.

// Plane capacities, mirrored from bpf/include/events.h (TEGO_PLANE_ROWS_MAX, TEGO_PLANE_EXEC_ROWS_MAX) and held
// to it by internal/bpf TestPlaneCapsMatchRowCompiler. A slot's maps hold no more, and the compiler never
// truncates: a table over either cap is ErrPlaneCap (enforce-plane §6 E13).
const (
	PlaneRowsMax       = 4096
	PlaneExecRowsMax   = 1024
	PlaneListenRowsMax = 256
)

// PlaneKind is a row's tego_plane_row.kind: what the walk answers when it stops at this row, as bits.
type PlaneKind uint8

// The kind bits. A row with no bit set refuses a modification and allows a read.
const (
	// PlaneReadDeny: a read (file_open without a write mode, and the open of an exec) of this inode or of anything
	// whose nearest row this is, is refused.
	PlaneReadDeny PlaneKind = 1 << 0
	// PlaneModifyAllow: a modification (write-open, create, delete, rename, mkdir, link) here is allowed.
	PlaneModifyAllow PlaneKind = 1 << 1
	// PlaneRenameRefused: renaming this inode itself (the walk's depth 0) is refused, because it is a deny_write
	// target or a directory above one up to the outermost write entry enclosing it (enforce-plane R11). It says
	// nothing of the paths beneath this row, which PlaneModifyAllow decides.
	PlaneRenameRefused PlaneKind = 1 << 2
	// PlaneExecDir: an exec.allow directory covers this inode (PlaneRow.Exec names the lowest such entry).
	PlaneExecDir PlaneKind = 1 << 3
	// PlaneProtected: a deny_write target lies at or above this inode, so the attribute hooks (chmod, chown, xattr,
	// ACL) refuse here and beneath (enforce-plane R12). Landlock governs none of those calls, and the plane decides
	// them for the targets' protection only: no other row refuses one.
	PlaneProtected PlaneKind = 1 << 4
	// PlaneMountOnly marks a kernel row keyed at a mounted root below a deny_write target (PlaneRows.Mounts), which
	// only the attribute hooks' walk inside a superblock reads; the walk that crosses mounts passes it. No row of
	// PlaneRows.FS carries it.
	PlaneMountOnly PlaneKind = 1 << 5
	// PlaneScopeOnly marks a row keyed at a name entry's scope directory that no entry, target or exec grant keys
	// (ADR 0043 D4): only the name check's climb reads it (its scope bits); the walk passes it, so the row changes no
	// answer and no walk bound. A scope directory that is another row's path carries its bits on that row instead.
	PlaneScopeOnly PlaneKind = 1 << 6
	// PlaneBuiltinIPC is an immutable IPC/Tego target checked against the native Unix peer.
	PlaneBuiltinIPC PlaneKind = 1 << 7
)

// Strictness orders kinds for REFER (enforce-plane R10): 2 for a row that refuses reads, 1 for one that allows
// reads and refuses modifications, 0 for one that allows both. The root model never pairs a refused read with an
// allowed modification: the entry deciding a modification is the nearest non-watch entry, and a deny_read at
// least as near would decide it refused.
func (k PlaneKind) Strictness() uint8 {
	switch {
	case k&PlaneReadDeny != 0:
		return 2
	case k&PlaneModifyAllow == 0:
		return 1
	}
	return 0
}

// PlaneReferRefused is REFER's comparison (path_rename, path_link): a move is refused when the source's nearest
// row is stricter than the destination's. A walk that met no row answers as kind 0 (reads allowed, modifications
// refused). In the root model both ends must allow the modification first, so both are strictness 0 and the
// comparison never refuses on its own; it is the kernel's guard against a move the table did not foresee.
func PlaneReferRefused(src, dst PlaneKind) bool { return src.Strictness() > dst.Strictness() }

// PlaneSection says which list of the RuleTable a PlaneRule indexes.
type PlaneSection uint8

// Sections a row's rule can come from.
const (
	// PlaneNoRule: no entry decides (an unmatched read is allowed, an unmatched modification refused).
	PlaneNoRule PlaneSection = iota
	// PlaneFSRule indexes RuleTable.FS.
	PlaneFSRule
	// PlaneDenyWriteRule indexes RuleTable.DenyWrite.
	PlaneDenyWriteRule
	// PlaneNameRule indexes RuleTable.NameDeny (ADR 0043), Scope the position in its scopes of the one that decided.
	PlaneNameRule
)

// PlaneRule is the entry that decides one question at a row.
type PlaneRule struct {
	Section PlaneSection
	Index   int
	// Scope is a name entry's scope that decided (PlaneNameRule), a position in its Scopes, which the built-in's
	// rule name carries (ADR 0043 D8); 0 for the other sections.
	Scope int
}

// planeNone is the zero decision.
var planeNone = PlaneRule{Section: PlaneNoRule, Index: -1}

// Name is the rule a ledger line carries for this decision, or "" for none.
func (r PlaneRule) Name(rt *agent.RuleTable) string {
	switch r.Section {
	case PlaneFSRule:
		return rt.FS[r.Index].RuleName()
	case PlaneDenyWriteRule:
		return rt.DenyWrite[r.Index].RuleName()
	case PlaneNameRule:
		return rt.NameDeny[r.Index].RuleName(r.Scope)
	case PlaneNoRule:
	}
	return ""
}

// PlaneRow is one fs row: the canonical path the fill keys by its inode, and the complete answer there.
//
// The kernel row's rule_idx is the row's position in PlaneRows.FS, not an entry's: a row answers two questions
// (and a rename of itself), whose deciding entries can differ (a deny_read and an implicit entry at one path; a
// write entry nested under a deny_read at the same path), and one u16 cannot name both. The ledger resolves the
// position by the hook's question (PlaneRows.RuleAt).
type PlaneRow struct {
	Path         string
	Kind         PlaneKind
	BuiltinFlags uint16 // bit 0: ledger root or descendant; control socket names only
	// Read and Modify are the entries deciding each question here; PlaneNoRule when none does.
	Read, Modify PlaneRule
	// Rename is the deny_write target a rename of this inode itself carries (PlaneRenameRefused), else none.
	Rename PlaneRule
	// Exec is the lowest exec.allow directory entry covering the row (PlaneExecDir), -1 for none.
	Exec int
	// Named is the nearest fs entry of any kind within the walk's bound (SEMANTICS §7's attribution), -1 for none.
	Named int
	// Scopes is the scope bits of a row at a name entry's scope directory (PlaneRows.Scopes; ADR 0043 D4), which the
	// kernel row's spare byte carries; 0 elsewhere.
	Scopes uint8
}

// PlaneExecRow is one exec row: the executable the fill keys by its inode, and the directory and final name the
// kernel compares with the dentry (ADR 0025 (1) as T2 amended it). Path is the entry's resolved spelling, the one
// bprm->file's dentry carries.
type PlaneExecRow struct {
	Path, Parent, Name string
	// Rule is the entry's position in RuleTable.Exec.
	Rule int
}

// PlaneExecName is an exec entry the author wrote as a bare command name (SEMANTICS §4, ExecRule.ByName): it matches
// by the final component wherever the file lies, so it keys no inode: its exec row is keyed by
// internal/bpf.PlaneNameKey(Name), and bprm_check compares the name's bytes (docs/p0/enforce-plane.md §2.7).
type PlaneExecName struct {
	Name string
	Rule int
}

// PlaneListenRow grants one Unix listener name. A pathname is keyed by its
// held parent inode and basename; an abstract name is an exact byte sequence.
type PlaneListenRow struct {
	Path, Parent, Name string
	Abstract           bool
	Rule               int
}

// NeutralRule is ADR 0025 (3)'s pin: a Landlock rule on a keyed inode whose rights the run's domain already grants
// there, so the domain holds the inode for as long as any member lives and grants nothing new
// (TestNeutralRulesKeepTheUnion). Access holds read rights only (READ_FILE, READ_DIR), never a write right; the
// builder masks it by ABI and file-ness as it masks every rule, and adds none when nothing is left (a file under an
// enforced deny_read whose ancestors grant only READ_DIR, where Landlock refuses every open itself).
type NeutralRule struct {
	Path   string
	Access agent.AccessSet
}

// PlaneRows is a table compiled for the plane.
type PlaneRows struct {
	// FS is the fs rows, sorted by path; a row's position is its kernel rule_idx.
	FS []PlaneRow
	// Exec is the exec rows, one per executable, in RuleTable.Exec order.
	Exec []PlaneExecRow
	// Names is the bare-name exec entries.
	Names []PlaneExecName
	// Listen contains only Unix listeners. IP bind policy is compiled separately.
	Listen    []PlaneListenRow
	Protected []PlaneListenRow // immutable parent/name targets, Rule carries 0x8000 plus an FS row
	// ListenPolicy distinguishes an omitted listener section from an empty list.
	ListenPolicy     bool
	BuiltinTerminals bool // every enforcing run has the independent Landlock tty layer
	// Keyed is every path whose inode the plane keys, opened following a final symlink: the fs rows but NoFollow's,
	// the executables and their directories, sorted.
	Keyed []string
	// NoFollow is the fs rows keyed at the path's own inode, a final symlink not followed, sorted: the declared
	// spelling of a deny_write target whose resolved path differs (a .git/hooks that is a symlink), and each
	// directory above it up to the outermost write entry enclosing it, where no row of Keyed is keyed already
	// (enforce-plane R11). Unlinking, renaming or replacing the link itself walks from the link's own dentry, which
	// the resolved target's row does not reach. They carry no neutral rule: Landlock holds them for identity alone.
	NoFollow []string
	// Neutral is one pin per keyed inode that the domain grants a read right at, in Keyed order.
	Neutral []NeutralRule
	// Mounts is the mounted roots Prepare keys for the attribute hooks (WithMounts), none from CompilePlane.
	Mounts []PlaneMountRow

	// ExecPolicy is a table whose contract has an exec: section (or no contract, which decides exec as Prepare
	// does): its slot's header then says exec is decided, and the slot carries the bare-name rows beside the exec
	// rows (§2.7).
	ExecPolicy bool
	// NetPolicy is a table whose contract has a net: section (or no contract, which fails closed as
	// agent.RuleTable.NetUnrestricted does): its slot's header then says socket_create decides (R14), which takes
	// no entry in the fs rows map.
	NetPolicy bool

	// The name entries (ADR 0043), all empty for a table without them. Scopes is the scope directories in bit order (bit i is Scopes[i]); NameRows the
	// slot's name rows; Leads the prefilter's literal starts and PrefixLens the distinct prefix lengths the slot header
	// carries. Compacted is how many covered per-file rows D6 dropped.
	Scopes     []string
	NameRows   []PlaneNameRow
	Leads      []string
	PrefixLens []uint8
	Compacted  int

	fsByPath   map[string]int
	execByPath map[string]int
	nameRule   map[string]int
	// nameByKey is NameRows by key; nameScopes each entry's scope paths; compacted each dropped path's deciding
	// entry in RuleTable.FS, which names its refusal (D8).
	nameByKey   map[uint64]int
	nameEntries int
	nameScopes  [][]string
	compacted   map[string]int
}

// ExecMapEntries is what the slot's exec-rows map holds for the run: an exec row per executable, and, with an exec:
// section, a row per bare-name entry, all in one inner map of PlaneExecRowsMax entries. Whether exec is decided is the
// slot header's (enforce-plane R6), which takes no entry here.
func (s *PlaneRows) ExecMapEntries() int {
	if !s.ExecPolicy {
		return len(s.Exec)
	}
	return len(s.Exec) + len(s.Names)
}

// FSMapEntries is what the slot's fs rows map holds for the run: an fs row per keyed inode and a row per mounted
// root (WithMounts), all in one inner map of PlaneRowsMax entries. Whether net is decided is the slot header's
// (enforce-plane R6), which takes no entry here.
func (s *PlaneRows) FSMapEntries() int {
	return len(s.FS) + len(s.Mounts)
}

// ErrPlaneCap is a table the plane cannot hold: more fs map entries (PlaneRows.FSMapEntries) or exec map entries
// (PlaneRows.ExecMapEntries) than a slot's maps, or more keyed paths than the launcher can hold a descriptor each
// for (FDCap, PlaneRows.FitFDs). At tier bpflsm pinned it is a compile error and refuses Prepare, never a truncated
// row set (enforce-plane §6 E13): a row left out is a rule the kernel does not apply, and a quieter run is the silent
// fallback I7 forbids. An auto run is given tier cgroup instead (§2.4 condition 7).
type ErrPlaneCap struct {
	FSRows, ExecRows int
	// Held and FDCap are set when the descriptor budget is the cap the table passes: the keyed paths the Landlock
	// plan holds a descriptor each for, and how many the launcher can hold (landlock.FDBudget.Cap).
	Held, FDCap int
	// Compacted is how many covered per-file rows ADR 0043 D6 dropped before the cap was still passed.
	Compacted int
}

func (e *ErrPlaneCap) Error() string {
	note := ""
	if e.Compacted > 0 {
		note = fmt.Sprintf(", after dropping %d per-file rows name entries cover", e.Compacted)
	}
	if e.FDCap != 0 || e.Held != 0 {
		return fmt.Sprintf("the decision plane keys %d paths, each held at a descriptor for the run, and this launcher's "+
			"descriptor cap is %d (soft RLIMIT_NOFILE less what it holds and keeps for the run; at most %d inodes a run)%s",
			e.Held, e.FDCap, PlaneRowsMax, note)
	}
	return fmt.Sprintf("the decision plane keys %d inodes for fs rules (with the mounted roots; at most %d a run) and %d exec rows (executables and bare names; at most %d)%s",
		e.FSRows, PlaneRowsMax, e.ExecRows, PlaneExecRowsMax, note)
}

// Held is how many descriptors the Landlock plan holds for the plane's keys at least: one per keyed path, per path
// keyed without following and per mounted root (two paths on one inode share one, so it can be fewer; a deny_read
// target's enumerated siblings and the other entries are more).
func (s *PlaneRows) Held() int {
	n := len(s.Keyed) + len(s.NoFollow) + len(s.Mounts) + len(s.Protected)
	for _, r := range s.Listen {
		if !r.Abstract {
			n++ // a dedicated parent descriptor per declaration, even with a shared parent
		}
	}
	return n
}

// CompactedAt reports whether ADR 0043 D6 dropped the per-file row at path, a RuleTable FS entry's Path: the
// plane decides that file by its name entry alone. A nil s compacted nothing.
func (s *PlaneRows) CompactedAt(path string) bool {
	if s == nil {
		return false
	}
	_, ok := s.compacted[path]
	return ok
}

// FitFDs refuses rows whose keyed paths pass fdCap, the launcher's descriptor budget (landlock.FDBudget.Cap), with
// ErrPlaneCap naming both: the plan would meet EMFILE at Prepare (enforce-plane §2.4 condition 7). A negative fdCap is
// a budget that could not be read, which refuses nothing here; Prepare's own budget still holds the plan.
func (s *PlaneRows) FitFDs(fdCap int) error {
	if fdCap < 0 || s.Held() <= fdCap {
		return nil
	}
	return &ErrPlaneCap{FSRows: len(s.FS) + len(s.Mounts), ExecRows: s.ExecMapEntries(), Held: s.Held(), FDCap: fdCap, Compacted: s.Compacted}
}

// ErrPlaneExecVerdict is an exec entry whose verdict is not allow: an exec row carries no verdict (the kernel's
// row is the one name the file may run under), and P0's compile produces no other (an ask entry is P1).
type ErrPlaneExecVerdict struct{ Rule int }

func (e *ErrPlaneExecVerdict) Error() string {
	return fmt.Sprintf("exec entry %d is not an allow entry, which the decision plane cannot express", e.Rule)
}

// PlaneDiagnostic is compile's report of a table the plane cannot hold (ErrPlaneCap, ErrPlaneExecVerdict), when the
// table can land at tier bpflsm (RuleTable.Tier or Reach, ADR 0019): an error when bpflsm is the only tier it can run
// at (pinned), since Prepare would refuse it (enforce-plane §6 E13), and a warning naming bpflsm otherwise, where an
// auto run is given tier cgroup instead (§2.4 condition 7). fdCap is the launcher's descriptor budget
// (landlock.FDBudget.Cap), negative when unknown. ok is false when the table fits or cannot reach bpflsm.
func PlaneDiagnostic(rt *agent.RuleTable, file string, fdCap int) (d agent.Diagnostic, ok bool) {
	if rt == nil || (rt.Tier != backend.TierBPFLSM && !slices.Contains(rt.Reach, backend.TierBPFLSM)) {
		return d, false
	}
	rows, err := CompilePlane(rt)
	if err == nil {
		err = rows.FitFDs(fdCap)
	}
	if err == nil {
		return d, false
	}
	d = agent.Diagnostic{File: file, Line: 1, Code: agent.CodeUnenforced, Severity: agent.SeverityWarning, Tier: backend.TierBPFLSM,
		Message: "tier bpflsm cannot enforce this contract: " + err.Error(),
		Fix:     "narrow the fs, deny_read and exec.allow entries, or pin tier: cgroup"}
	if pinnedBPFLSM(rt) {
		d.Severity = agent.SeverityError
	} else {
		d.Message += "; an auto run is given tier cgroup"
	}
	return d, true
}

// pinnedBPFLSM reports a table that can run at tier bpflsm alone: its contract or the machine config pinned it
// (Reach is the pinned tier alone), or a hand-built table compiled to it with no Reach.
func pinnedBPFLSM(rt *agent.RuleTable) bool {
	if len(rt.Reach) == 0 {
		return rt.Tier == backend.TierBPFLSM
	}
	return len(rt.Reach) == 1 && rt.Reach[0] == backend.TierBPFLSM
}

// CompilePlane is the row compiler: the root model of rt as the plane's rows, exec rows, keyed inodes and neutral
// Landlock rules. It is pure and runs once per compile or Prepare; the query paths (Find, Decide, ExecMatch) are
// the ones that allocate nothing. It indexes the table's entries by path once (rowindex.go), so each row costs a
// walk up its own ancestors and the whole compile is near-linear in the table; the scan per row it replaced took
// seconds at the caps.
func CompilePlane(rt *agent.RuleTable) (*PlaneRows, error) {
	if rt == nil {
		return nil, fmt.Errorf("decide: no rule table")
	}
	s := &PlaneRows{fsByPath: make(map[string]int, len(rt.FS)), execByPath: make(map[string]int, len(rt.Exec)), nameRule: map[string]int{}}
	s.ListenPolicy = rt.Listen != nil
	s.BuiltinTerminals = rt.Builtins != nil
	for i, r := range rt.Listen {
		if r.Proto != agent.ProtoUnix {
			continue
		}
		e := PlaneListenRow{Path: r.UnixPath, Abstract: r.Abstract, Rule: i}
		if r.Abstract {
			e.Name = r.UnixPath
		} else {
			e.Parent, e.Name = filepath.Dir(r.UnixPath), filepath.Base(r.UnixPath)
		}
		s.Listen = append(s.Listen, e)
	}
	if len(s.Listen) > PlaneListenRowsMax {
		return nil, fmt.Errorf("decide: Unix listener rows %d exceed %d", len(s.Listen), PlaneListenRowsMax)
	}
	paths := make(map[string]bool, len(rt.FS)+len(rt.Exec))
	for i := range rt.FS {
		if rt.FS[i].Path != "" {
			paths[rt.FS[i].Canonical()] = true
		}
	}
	if rt.Builtins != nil {
		for _, p := range []string{rt.Builtins.Ledger, rt.Builtins.LedgerResolved} {
			if p != "" {
				paths[p] = true
			}
		}
		for _, n := range rt.Builtins.PeerNames {
			paths[n.Parent] = true
			s.Protected = append(s.Protected, PlaneListenRow{Path: n.Path, Parent: n.Parent, Name: n.Name, Rule: 0x2000})
		}
		for _, n := range rt.Builtins.Names {
			paths[n.Parent] = true
			if n.Target != filepath.Join(n.Parent, n.Name) {
				paths[filepath.Dir(n.Target)] = true
			}
		}
		own := rt.Builtins.OwnRuntimeResolved
		if own == "" {
			own = rt.Builtins.OwnRuntime
		}
		if own != "" {
			parent := filepath.Dir(own)
			paths[parent] = true
			s.Protected = append(s.Protected, PlaneListenRow{Path: "builtin-own:" + own, Parent: parent, Name: filepath.Base(own), Rule: 0x4000})
		}
	}
	// A deny_write target and every directory above it up to the outermost write entry that encloses it
	// (enforce-plane R11): renaming any of them carries the target out of its place. Above that entry no write
	// entry covers the path, so every modification there is refused already.
	px := newPlaneIndex(rt)
	for j := range rt.DenyWrite {
		t := denyWritePath(rt.DenyWrite[j])
		if rt.DenyWrite[j].BuiltinRule != "" {
			paths[t] = true
		}
		top, ok := px.outermostWrite(t)
		if !ok {
			continue // compile keeps only targets beneath a write entry; nothing to key otherwise
		}
		for cur := t; ; cur = filepath.Dir(cur) {
			paths[cur] = true
			if cur == top || cur == "/" {
				break
			}
		}
	}
	// A file beneath an fs.deny_write directory entry with another hard link (RuleTable.DenyWriteLinked) is
	// keyed at its own inode: a write through the other name walks from that name's directory, which reaches only the
	// write entry, while the row here answers what the entry above the file does (denyWriteIdx).
	for _, p := range rt.DenyWriteLinked {
		if p = filepath.Clean(p); filepath.IsAbs(p) {
			paths[p] = true
		}
	}
	for i := range rt.Exec {
		r := &rt.Exec[i]
		if r.Verdict != agent.VerdictAllow {
			return nil, &ErrPlaneExecVerdict{Rule: i}
		}
		p := execPath(r)
		switch {
		case p == "":
		case r.IsDir:
			paths[p] = true
		default:
			if _, dup := s.execByPath[p]; !dup {
				s.execByPath[p] = len(s.Exec)
				s.Exec = append(s.Exec, PlaneExecRow{Path: p, Parent: filepath.Dir(p), Name: filepath.Base(p), Rule: i})
			}
		}
		if r.ByName && r.Basename != "" {
			if _, dup := s.nameRule[r.Basename]; !dup {
				s.nameRule[r.Basename] = i
				s.Names = append(s.Names, PlaneExecName{Name: r.Basename, Rule: i})
			}
		}
	}
	noFollow := linkRows(rt, px, paths, s.Exec)
	for p := range noFollow {
		paths[p] = true
	}
	s.ExecPolicy = !rt.ExecUnrestricted()
	s.NetPolicy = !rt.NetUnrestricted()
	rx := newRowIndex(rt)
	x := NewRootIndex(rx.rows())
	// ADR 0043: the name entries' scope rows, and D6's compaction of the per-file rows they cover (NewNameIndex is
	// nil for a table without name entries, whose rows are then exactly the rows without them).
	var pn *planeNames
	if nx := NewNameIndex(rt); nx != nil {
		var err error
		if len(rt.NameDeny) > agent.NameEntriesMax {
			return nil, &ErrPlaneNameCap{Why: fmt.Sprintf("%d name entries, at most %d", len(rt.NameDeny), agent.NameEntriesMax)}
		}
		if pn, err = compileNames(rt); err != nil {
			return nil, err
		}
		keep := planeKeep(rt, paths, noFollow, s)
		for _, sc := range pn.scopes {
			if !paths[sc] {
				paths[sc] = true
				pn.scopeOnly[sc] = true
			}
			keep[sc] = true
		}
		dropped := compactRows(rt, nx, &x, paths, keep, keyedCount(paths, s))
		for p := range dropped {
			delete(paths, p)
		}
		s.compacted, s.Compacted = dropped, len(dropped)
	}
	if fsEntries := len(paths); fsEntries > PlaneRowsMax || s.ExecMapEntries() > PlaneExecRowsMax {
		return nil, &ErrPlaneCap{FSRows: fsEntries, ExecRows: s.ExecMapEntries(), Compacted: s.Compacted}
	}
	sorted := make([]string, 0, len(paths))
	for p := range paths {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)
	s.FS = make([]PlaneRow, 0, len(sorted))
	for _, p := range sorted {
		s.fsByPath[p] = len(s.FS)
		if pn != nil && pn.scopeOnly[p] {
			s.FS = append(s.FS, PlaneRow{Path: p, Kind: PlaneScopeOnly, Read: planeNone, Modify: planeNone, Rename: planeNone, Exec: -1, Named: -1})
			continue
		}
		s.FS = append(s.FS, compileRow(px, &x, p))
	}
	if pn != nil {
		s.setNames(rt, pn)
	}
	keyed := make(map[string]bool, len(paths)+2*len(s.Exec))
	for p := range paths {
		if noFollow[p] {
			s.NoFollow = append(s.NoFollow, p)
		} else {
			keyed[p] = true
		}
	}
	sort.Strings(s.NoFollow)
	for _, e := range s.Exec {
		keyed[e.Path], keyed[e.Parent] = true, true
	}
	for _, e := range s.Listen {
		if !e.Abstract {
			keyed[e.Parent] = true
		}
	}
	s.Keyed = make([]string, 0, len(keyed))
	for p := range keyed {
		s.Keyed = append(s.Keyed, p)
	}
	sort.Strings(s.Keyed)
	g := newLandlockGrants(rt, rx)
	for _, p := range s.Keyed {
		if a := g.at(p) & (agent.AccessReadFile | agent.AccessReadDir); a != 0 {
			s.Neutral = append(s.Neutral, NeutralRule{Path: p, Access: a})
		}
	}
	if rt.Builtins != nil {
		for _, n := range rt.Builtins.Names {
			found := false
			for i, r := range s.FS {
				if r.Path == n.Target {
					s.Protected = append(s.Protected, PlaneListenRow{Path: n.Path, Parent: n.Parent, Name: n.Name, Rule: 0x8000 | i})
					// Configured aliases keep their own names. Also guard the
					// resolved target's name if an outside server replaces it;
					// its old inode alone cannot protect that replacement.
					if n.Target != filepath.Join(n.Parent, n.Name) {
						s.Protected = append(s.Protected, PlaneListenRow{Path: "builtin-target:" + n.Path,
							Parent: filepath.Dir(n.Target), Name: filepath.Base(n.Target), Rule: 0x8000 | i})
					}
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("decide: immutable target %s has no plane row", n.Target)
			}
		}
	}
	if len(s.Protected)+len(s.Listen) > PlaneListenRowsMax {
		return nil, fmt.Errorf("decide: immutable and Unix listener names %d exceed %d", len(s.Protected)+len(s.Listen), PlaneListenRowsMax)
	}
	return s, nil
}

// planeKeep is every row path compaction may not drop (ADR 0043 D6): the paths a row keys for anything but an fs
// entry of its own (a deny_write chain, a link's spelling, an exec.allow directory) and the exec and listener keys.
func planeKeep(rt *agent.RuleTable, paths, noFollow map[string]bool, s *PlaneRows) map[string]bool {
	entry := make(map[string]bool, len(rt.FS))
	for i := range rt.FS {
		if rt.FS[i].Path != "" {
			entry[rt.FS[i].Canonical()] = true
		}
	}
	keep := map[string]bool{}
	if rt.Builtins != nil {
		for _, p := range []string{rt.Builtins.Ledger, rt.Builtins.LedgerResolved} {
			if p != "" {
				keep[p] = true
			}
		}
	}
	for _, n := range s.Protected {
		keep[n.Parent] = true
	}
	for _, r := range rt.DenyWrite {
		if r.BuiltinRule != "" {
			keep[denyWritePath(r)] = true
		}
	}
	if rt.Builtins != nil {
		for _, n := range rt.Builtins.Names {
			keep[n.Parent] = true
		}
		own := rt.Builtins.OwnRuntimeResolved
		if own == "" {
			own = rt.Builtins.OwnRuntime
		}
		if own != "" {
			keep[filepath.Dir(own)] = true
		}
	}
	for p := range paths {
		if !entry[p] || noFollow[p] {
			keep[p] = true
		}
	}
	for _, e := range s.Exec {
		keep[e.Path], keep[e.Parent] = true, true
	}
	for _, e := range s.Listen {
		if !e.Abstract {
			keep[e.Parent] = true
		}
	}
	return keep
}

// keyedCount is how many paths the plane keys before compaction (D6 (a)): the fs rows, links' spellings included,
// with the exec keys and the listeners' parents; mounted roots, which Prepare adds, are not counted.
func keyedCount(paths map[string]bool, s *PlaneRows) int {
	n := len(paths)
	extra := map[string]bool{}
	for _, e := range s.Exec {
		for _, p := range [2]string{e.Path, e.Parent} {
			if !paths[p] {
				extra[p] = true
			}
		}
	}
	for _, e := range s.Listen {
		if !e.Abstract && !paths[e.Parent] {
			extra[e.Parent] = true
		}
	}
	return n + len(extra)
}

// linkRows are the rows CompilePlane keys at a path's own inode (PlaneRows.NoFollow): for each deny_write target
// declared at a spelling other than its resolved path, that spelling and each directory above it up to the
// outermost write entry enclosing it, less the paths rows (the resolved chains, the fs entries, the exec
// directories) or exec rows key already, which keep their following open. The model refuses a modification or a
// rename at either spelling (denyWriteIdx asks both); keyed only at the resolved inode, the plane would let the
// agent unlink the link and put a directory of its own in its place.
func linkRows(rt *agent.RuleTable, px *planeIndex, paths map[string]bool, exec []PlaneExecRow) map[string]bool {
	var out map[string]bool
	for j := range rt.DenyWrite {
		r := &rt.DenyWrite[j]
		if r.Path == "" {
			continue
		}
		t := filepath.Clean(r.Path)
		if t == denyWritePath(*r) {
			continue
		}
		top, ok := px.outermostWrite(t)
		if !ok {
			continue // no write entry covers the spelling: every modification there is refused already
		}
		for cur := t; ; cur = filepath.Dir(cur) {
			if !paths[cur] {
				if out == nil {
					out = map[string]bool{}
				}
				out[cur] = true
			}
			if cur == top || cur == "/" {
				break
			}
		}
	}
	for _, e := range exec {
		for _, p := range [2]string{e.Path, e.Parent} {
			if out[p] {
				// An executable and its directory are held following; the row there is keyed the same way.
				delete(out, p)
				paths[p] = true
			}
		}
	}
	return out
}

// compileRow is the complete answer at p: the root model's walk from p for each question, the deny_write
// targets above and at p for a modification, and those above, at and beneath p for a rename of p itself (the
// two questions Evaluate's evalDenyWrite asks, with and without ancestors).
func compileRow(px *planeIndex, x *RootIndex, p string) PlaneRow {
	row := PlaneRow{Path: p, Read: planeNone, Modify: planeNone, Rename: planeNone, Exec: -1}
	rv, mv := x.Walk(p, true), x.Walk(p, false)
	row.Named = rv.Named
	if b := px.rt.Builtins; b != nil {
		for _, root := range []string{b.Ledger, b.LedgerResolved} {
			if root != "" && agent.Covers(root, p) {
				row.BuiltinFlags |= 1
			}
		}
	}
	switch {
	case rv.Unresolved:
		row.Kind |= PlaneReadDeny // an exhausted walk refuses both questions (SEMANTICS §2)
	case !rv.Allow:
		row.Kind |= PlaneReadDeny
		row.Read = PlaneRule{Section: PlaneFSRule, Index: rv.Rule}
	case rv.Rule >= 0:
		row.Read = PlaneRule{Section: PlaneFSRule, Index: rv.Rule}
	}
	if j, ok := px.denyWriteIdx(p, false); ok {
		row.Modify = PlaneRule{Section: PlaneDenyWriteRule, Index: j}
		row.Kind |= PlaneProtected
		if px.rt.DenyWrite[j].BuiltinRule != "" {
			row.Kind |= PlaneBuiltinIPC
		}
	} else if !mv.Unresolved {
		if mv.Allow {
			row.Kind |= PlaneModifyAllow
		}
		if mv.Rule >= 0 {
			row.Modify = PlaneRule{Section: PlaneFSRule, Index: mv.Rule}
		}
	}
	if j, ok := px.denyWriteIdx(p, true); ok {
		row.Kind |= PlaneRenameRefused
		row.Rename = PlaneRule{Section: PlaneDenyWriteRule, Index: j}
	}
	if i := px.execDirAt(p); i >= 0 {
		row.Kind |= PlaneExecDir
		row.Exec = i
	}
	return row
}

// denyWritePath is where a deny_write target's inode lies: its resolved path.
func denyWritePath(r agent.FSRule) string { return filepath.Clean(r.Governed()) }

// execPath is where an exec entry's inode lies: the resolved spelling, which bprm->file's dentry carries.
func execPath(r *agent.ExecRule) string {
	if r.Resolved != "" {
		return filepath.Clean(r.Resolved)
	}
	if r.Path != "" {
		return filepath.Clean(r.Path)
	}
	return ""
}

// PlaneQuestion is what a hook asks the walk.
type PlaneQuestion uint8

// The questions.
const (
	// PlaneRead: file_open without a write mode.
	PlaneRead PlaneQuestion = iota
	// PlaneModify: a write-open, create, delete, mkdir or link at the path.
	PlaneModify
	// PlaneRename: path_rename of the path itself (either end).
	PlaneRename
	// PlaneProtect: an attribute change at the path (path_chmod, path_chown, the xattr and ACL hooks), refused only
	// beneath a deny_write target (enforce-plane R12).
	PlaneProtect
)

// PlaneVerdict is the plane's answer for one question on one path.
type PlaneVerdict struct {
	Allow bool
	// Row is the row the walk stopped at (the kernel's rule_idx), -1 when it met none.
	Row int
	// Rule is the deciding entry, PlaneNoRule for an unmatched answer or an exhausted walk.
	Rule PlaneRule
	// Named is the row's nearest entry, -1 for none.
	Named int
	// Unresolved is an exhausted walk, refused path-unresolved.
	Unresolved bool
}

// Find is the kernel's walk over the rows (tego_plane_walk): from path, a clean absolute canonical path, through
// each parent to "/", the first row met, and its depth. It meets none (row -1) when it reaches "/" first, and is
// unresolved when agent.MaxWalk steps pass without a row or the root. A step is a path component: the kernel's walk
// crosses a mount without one (enforce-plane R7), so no mount table is needed here.
func (s *PlaneRows) Find(path string) (row, depth int, unresolved bool) {
	cur := path
	for step := 0; step <= agent.MaxWalk; step++ {
		if i, ok := s.fsByPath[cur]; ok && s.FS[i].Kind&PlaneScopeOnly == 0 {
			return i, step, false
		}
		if cur == "/" {
			return -1, step, false
		}
		cur = filepath.Dir(cur)
	}
	return -1, 0, true
}

// Decide is the plane's answer to q on path: Find, then the row's kind.
func (s *PlaneRows) Decide(path string, q PlaneQuestion) PlaneVerdict {
	i, depth, unresolved := s.Find(path)
	v := PlaneVerdict{Row: i, Rule: planeNone, Named: -1, Unresolved: unresolved}
	if unresolved {
		return v
	}
	if i < 0 {
		v.Allow = q == PlaneRead || q == PlaneProtect
		return v
	}
	r := &s.FS[i]
	v.Named = r.Named
	switch {
	case q == PlaneRead:
		v.Allow, v.Rule = r.Kind&PlaneReadDeny == 0, r.Read
	case q == PlaneProtect:
		v.Allow = r.Kind&PlaneProtected == 0
		if !v.Allow {
			v.Rule = r.Modify
		}
	case q == PlaneRename && depth == 0 && r.Kind&PlaneRenameRefused != 0:
		v.Rule = r.Rename
	default:
		v.Allow, v.Rule = r.Kind&PlaneModifyAllow != 0, r.Modify
	}
	return v
}

// KindAt is the kind of path's nearest row, 0 when the walk meets none: what REFER compares.
func (s *PlaneRows) KindAt(path string) PlaneKind {
	if i, _, unresolved := s.Find(path); i >= 0 && !unresolved {
		return s.FS[i].Kind
	}
	return 0
}

// RuleAt resolves a kernel rule_idx for a question: the rule the ledger line names.
func (s *PlaneRows) RuleAt(row int, q PlaneQuestion, depth int) PlaneRule {
	if row < 0 || row >= len(s.FS) {
		return planeNone
	}
	r := &s.FS[row]
	switch {
	case q == PlaneRead:
		return r.Read
	case q == PlaneRename && depth == 0 && r.Kind&PlaneRenameRefused != 0:
		return r.Rename
	}
	return r.Modify
}

// RowName is the rule a plane refusal's ledger line names from the kernel's rule_idx for q (TIER3-PLAN T9): the
// entry RuleAt names, else the row's nearest entry of any kind, else unmatched. It is PlaneRefusal's naming, read
// from the row the kernel stopped at rather than from a path. depth 0 is a rename of the row's own inode.
func (s *PlaneRows) RowName(rt *agent.RuleTable, row int, q PlaneQuestion, depth int) string {
	if r, ok := s.nameRuleAt(row); ok {
		// A name entry decided (ADR 0043 D8): its own rule. A file whose RuleTable entry compaction dropped is named
		// by that entry, which the recorder finds by the record's path (observe planeFS, FSIndex.DenyReadAt).
		return r.Name(rt)
	}
	if row < 0 || row >= len(s.FS) {
		return agent.UnmatchedRule
	}
	if r := s.RuleAt(row, q, depth); r.Section != PlaneNoRule {
		return r.Name(rt)
	}
	return s.NamedAt(rt, row)
}

// NamedAt is the row's nearest entry of any kind (PlaneRow.Named), unmatched when none: what a REFER refusal is
// named by, as PlaneEvaluator names it.
func (s *PlaneRows) NamedAt(rt *agent.RuleTable, row int) string {
	if r, ok := s.nameRuleAt(row); ok {
		return r.Name(rt) // a covered source's REFER refusal, or D5's, names the name entry (ADR 0043 D8)
	}
	if row < 0 || row >= len(s.FS) || s.FS[row].Named < 0 {
		return agent.UnmatchedRule
	}
	return rt.FS[s.FS[row].Named].RuleName()
}

// PlaneRuleFSRow is the bit bprm_check sets on the rule of an exec an exec.allow directory matched: the rest is the
// fs row's position, not an exec entry's (TEGO_PLANE_RULE_FS_ROW; internal/bpf.PlaneRuleFSRow).
const PlaneRuleFSRow uint32 = 1 << 16

// ExecRuleAt resolves bprm_check's rule to an exec entry's position in RuleTable.Exec, -1 for none: an entry's own
// position, or, with PlaneRuleFSRow set, the fs row's exec.allow entry (PlaneRow.Exec). The kernel records the
// row's position there because the row, not an entry, is what it holds (docs/p0/enforce-plane.md §2.7's condition
// 2, resolved at T9).
func (s *PlaneRows) ExecRuleAt(rt *agent.RuleTable, idx uint32) int {
	if idx&PlaneRuleFSRow != 0 {
		row := int(idx &^ PlaneRuleFSRow)
		if row >= len(s.FS) || s.FS[row].Kind&PlaneExecDir == 0 {
			return -1
		}
		return s.FS[row].Exec
	}
	if int(idx) >= len(rt.Exec) {
		return -1
	}
	return int(idx)
}

// ExecMatch is the plane's exec answer for the file at path, a clean absolute canonical path: the lowest exec entry
// matching by its exec row (this file under this name in this directory), by an exec.allow directory above it (the
// nearest fs row's PlaneExecDir), or by a bare name. It is the test oracle RootExecMatch's answer on such a path (rootoracle_test.go).
func (s *PlaneRows) ExecMatch(path string) (rule int, ok bool) {
	rule = -1
	if i, hit := s.execByPath[path]; hit {
		rule = s.Exec[i].Rule
	}
	if i, _, unresolved := s.Find(path); i >= 0 && !unresolved && s.FS[i].Kind&PlaneExecDir != 0 {
		if e := s.FS[i].Exec; rule < 0 || e < rule {
			rule = e
		}
	}
	if e, hit := s.nameRule[filepath.Base(path)]; hit && (rule < 0 || e < rule) {
		rule = e
	}
	return rule, rule >= 0
}

// PlaneMountRow is a mounted root at or below a deny_write target, keyed at Prepare from the launcher's mountinfo
// (enforce-plane R12, ADR 0024 (5)): the attribute hooks get a dentry and no mount, so their walk stays inside the
// superblock, and a filesystem mounted below a target (a tmpfs at .git/x) would otherwise walk to its own root and
// meet no row. The kernel row at the mounted root carries Row's kind with PlaneMountOnly and Row as its rule_idx: the
// answer the path model gives there, since Row is the nearest row above the mountpoint and no entry lies between.
// The walk that crosses mounts passes it and meets Row itself, so no other hook's answer changes, and a mounted root
// that is also reachable elsewhere (a bind mount's source) can only have its attribute changes refused there.
type PlaneMountRow struct {
	Path string
	Row  int
}

// WithMounts is s with a mount row for each of points, the mountpoints of the launcher's mount namespace (clean,
// absolute, as mountinfo prints them resolved), that lies strictly below a deny_write target and is no fs row's path
// already; the others are left out. Each mount row's path joins Keyed, with its neutral rule, so the run's domain
// pins the mounted root as it pins every keyed inode (R17). s is not changed; FS and the rule positions are s's, so
// the recorder, which compiles the table without mounts, names every decision alike. A table whose rows and mount
// rows exceed a slot's map is ErrPlaneCap.
func (s *PlaneRows) WithMounts(rt *agent.RuleTable, points []string) (*PlaneRows, error) {
	if s == nil || rt == nil || len(rt.DenyWrite) == 0 || len(points) == 0 {
		return s, nil
	}
	var mounts []PlaneMountRow
	seen := map[string]bool{}
	for _, p := range points {
		if p == "" || p[0] != '/' {
			continue
		}
		p = filepath.Clean(p)
		if seen[p] {
			continue
		}
		seen[p] = true
		if _, isRow := s.fsByPath[p]; isRow {
			continue // the row keys the mounted root itself: the fill opens its path through the mount
		}
		below := false
		for j := range rt.DenyWrite {
			if t := denyWritePath(rt.DenyWrite[j]); t != p && agent.Covers(t, p) {
				below = true
				break
			}
		}
		if !below {
			continue
		}
		row, _, unresolved := s.Find(p)
		if row < 0 || unresolved {
			continue // no row above: no target covers p after all (a target the compiler kept no row for)
		}
		mounts = append(mounts, PlaneMountRow{Path: p, Row: row})
	}
	if len(mounts) == 0 {
		return s, nil
	}
	if n := s.FSMapEntries() + len(mounts); n > PlaneRowsMax {
		return nil, &ErrPlaneCap{FSRows: n, ExecRows: s.ExecMapEntries()}
	}
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].Path < mounts[j].Path })
	out := *s
	out.Mounts = mounts
	keyed := make(map[string]bool, len(s.Keyed)+len(mounts))
	for _, p := range s.Keyed {
		keyed[p] = true
	}
	g := newLandlockGrants(rt, newRowIndex(rt))
	out.Keyed = slices.Clone(s.Keyed)
	out.Neutral = slices.Clone(s.Neutral)
	out.Listen = slices.Clone(s.Listen)
	for _, m := range mounts {
		if keyed[m.Path] {
			continue
		}
		out.Keyed = append(out.Keyed, m.Path)
		if a := g.at(m.Path) & (agent.AccessReadFile | agent.AccessReadDir); a != 0 {
			out.Neutral = append(out.Neutral, NeutralRule{Path: m.Path, Access: a})
		}
	}
	sort.Strings(out.Keyed)
	sort.Slice(out.Neutral, func(i, j int) bool { return out.Neutral[i].Path < out.Neutral[j].Path })
	return &out, nil
}

// RootRows is the fs rows as the root model's rows, for RootIndex.Walk. Only an fs entry decides a RootCell, so
// a row decided by a deny_write target has no RootRow form; ok is false for such a table.
func (s *PlaneRows) RootRows() (rows []RootRow, ok bool) {
	rows = make([]RootRow, 0, len(s.FS))
	for _, r := range s.FS {
		if r.Modify.Section == PlaneDenyWriteRule {
			return nil, false
		}
		if r.Kind&PlaneScopeOnly != 0 {
			continue // the walk passes a scope-only row
		}
		named := r.Named
		read := RootCell{Rule: -1, Allow: r.Kind&PlaneReadDeny == 0}
		if r.Read.Section == PlaneFSRule {
			read.Rule = r.Read.Index
		}
		mod := RootCell{Rule: -1, Allow: r.Kind&PlaneModifyAllow != 0}
		if r.Modify.Section == PlaneFSRule {
			mod.Rule = r.Modify.Index
		}
		rows = append(rows, RootRow{Path: r.Path, Named: named, Read: read, Modify: mod})
	}
	return rows, true
}

// landlockGrants is the pure half of what the run's Landlock domain grants at a path (enforce-landlock R3, R5), the
// rights a neutral rule may carry: the rules the builder certainly adds on the path's ancestors or on it. Write
// entries grant the read set with their write rights; exec entries READ_FILE (and READ_DIR on a directory); with no
// enforced deny_read "/" gets the read set; otherwise every enumerated level READ_DIR and every sibling beside the
// path to a target the read set. Loader grants and the ABI mask are left out: a subset of the domain's grant is all
// a neutral rule needs.
type landlockGrants struct {
	enumerated bool
	onPath     map[string]map[string]bool
	// under is what the write entries and the exec.allow directories grant beneath each (cleaned) path, execFiles
	// what the exec file entries grant at theirs: a keyed path asks the ones on its chain of parents.
	under     map[string]agent.AccessSet
	execFiles map[string]bool
}

func newLandlockGrants(rt *agent.RuleTable, rx *rowIndex) landlockGrants {
	var targets []string
	for i := range rt.FS {
		if rt.FS[i].Kind != agent.FSDenyRead || rx.denyUnenforced(i) {
			continue
		}
		if t := filepath.Clean(rt.FS[i].Governed()); t != "/" {
			targets = append(targets, t)
		}
	}
	const read = agent.AccessReadFile | agent.AccessReadDir
	g := landlockGrants{enumerated: len(targets) > 0, under: map[string]agent.AccessSet{}, execFiles: map[string]bool{}}
	if g.enumerated {
		_, g.onPath = AncestorSet(Outermost(targets))
	}
	for i := range rt.FS {
		if r := &rt.FS[i]; r.Kind == agent.FSWrite {
			g.under[filepath.Clean(r.Governed())] |= read | r.Access
		}
	}
	for i := range rt.Exec {
		switch r := &rt.Exec[i]; {
		case execPath(r) == "":
		case r.IsDir:
			g.under[execPath(r)] |= read | agent.AccessExecute
		default:
			g.execFiles[execPath(r)] = true
		}
	}
	return g
}

// at is the grant at p, a clean absolute path.
func (g *landlockGrants) at(p string) agent.AccessSet {
	const read = agent.AccessReadFile | agent.AccessReadDir
	var a agent.AccessSet
	if !g.enumerated {
		a |= read
	} else {
		if _, level := g.onPath[p]; level {
			a |= agent.AccessReadDir
		}
		for cur := p; ; {
			dir, ok := parent(cur)
			if !ok {
				break
			}
			if names, level := g.onPath[dir]; level {
				a |= agent.AccessReadDir
				if !names[cur[strings.LastIndexByte(cur, '/')+1:]] {
					a |= read // cur is a sibling the enumeration grants
				}
			}
			cur = dir
		}
	}
	// under(e, p) on a clean p is e on p's chain of parents, or e == "/", which covers a relative p too.
	for cur, ok := p, true; ok; cur, ok = parent(cur) {
		a |= g.under[cur]
	}
	if p != "/" && (p == "" || p[0] != '/') {
		a |= g.under["/"]
	}
	if g.execFiles[p] {
		a |= agent.AccessReadFile | agent.AccessExecute
	}
	return a
}
