// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// This file is ADR 0043's name entries in the plane's row compiler: the scope rows and their bits (D4), the name
// rows and their arms the kernel's name check reads (D2, D3, D9), the kernel's name check and D5's climb as models
// over those rows (DecideObject, ScopeMoveRefused), and compaction (D6). The plane answers from its rows alone, as
// the kernel will, and TestPlaneRowsMatchEvaluate holds it to the root model (Evaluate, NameIndex). A table without
// name entries gets exactly the rows it had before them.

// PlaneCompactAt is D6's threshold: the plane drops covered per-file rows only from a table that keys more paths
// than this. It is the product value (agent.NameCompactAt) and a pure constant of the table, so the recorder's
// CompilePlane drops what Prepare's did (F8); a test lowers it to compact small tables.
var PlaneCompactAt = agent.NameCompactAt

// PlaneRuleName is the tag of a kernel rule_idx a name entry decided (ADR 0043 D8): 0x8000 | scope bit << 6 | the
// entry's position in RuleTable.NameDeny. fs rows stay below PlaneRowsMax, 0xffff stays none, and PlaneRuleFSRow and
// the listener's bit lie above 16 bits.
const PlaneRuleName uint16 = 0x8000

// PlaneNameAll is an exemption arm's Rule when it cancels every entry's arms for its name (D3).
const PlaneNameAll uint16 = 0xffff

// PlaneNameTag is the kernel rule_idx of a refusal by entry (its NameDeny position, below 64) whose scope bit
// (below 8) decided.
func PlaneNameTag(entry, scopeBit int) uint16 {
	return PlaneRuleName | uint16(scopeBit&7)<<6 | uint16(entry&63)
}

// PlaneNameUntag is PlaneNameTag's inverse; ok is false for an index without the tag.
func PlaneNameUntag(idx uint16) (entry, scopeBit int, ok bool) {
	if idx == 0xffff || idx&PlaneRuleName == 0 {
		return -1, -1, false
	}
	return int(idx & 63), int(idx>>6) & 7, true
}

// PlaneNameArm is one arm of a name row: what the row's name means beneath the scopes whose bits it carries.
type PlaneNameArm struct {
	// Scopes is the scope bits (PlaneRows.Scopes) the arm applies beneath.
	Scopes uint8
	// Depth is 0 for an arm met at any level of the climb, 1 for one met only at the object's own directory (D3's
	// exemption of one file's name in its parent).
	Depth uint8
	// Exempt cancels arms instead of refusing: Rule's entry (a built-in exception), or every entry (PlaneNameAll,
	// D3's exemption).
	Exempt bool
	// Rule is the entry's position in RuleTable.NameDeny, or PlaneNameAll.
	Rule uint16
	// RawFrom is a built-in exception arm's prefix length: the name's bytes from there compare exactly with the
	// row's (the scan's spelling, ADR 0043 implementation note), the bytes before it folded.
	RawFrom uint8
}

// PlaneNameRow is one row of the slot's name map (ADR 0043 D9): keyed by agent.NameKey of its folded literal and
// form, holding the literal for the compare that confirms a key hit, and its arms.
type PlaneNameRow struct {
	Key    uint64
	Name   string
	Prefix bool
	Arms   []PlaneNameArm
}

// ErrPlaneNameCap is a table whose name entries do not fit the slot's name map (rows, arms a row, scopes, prefix
// lengths, leads) or whose name keys collide. Compile leaves out an entry that would not fit
// (agent.FitNameEntries), so only a table built by hand meets it.
type ErrPlaneNameCap struct{ Why string }

func (e *ErrPlaneNameCap) Error() string {
	return "the decision plane cannot hold this table's name entries: " + e.Why
}

// planeNames is CompilePlane's name state: the scopes in bit order, the name rows, and the paths of the scope rows
// no other row keys (PlaneScopeOnly).
type planeNames struct {
	scopes    []string
	bits      map[string]uint8
	rows      []PlaneNameRow
	scopeOnly map[string]bool
}

// compileNames builds the scope bits and the name rows of rt's name entries (ADR 0043 D3, D4, D9): a deny arm per
// entry on its literal's row, scoped to its scopes' bits; an exempt arm per built-in exception on the exception's
// exact row, cancelling that entry alone; an exempt arm per D3 exemption on its name's exact row, at depth 1 under
// its parent's bit, cancelling every entry. The scopes are sorted, so the bits are a function of the table.
func compileNames(rt *agent.RuleTable) (*planeNames, error) {
	pn := &planeNames{bits: map[string]uint8{}, scopeOnly: map[string]bool{}}
	set := map[string]bool{}
	for _, e := range rt.NameDeny {
		for _, s := range e.Scopes {
			set[s.Canonical] = true
		}
	}
	for _, x := range rt.NameExempt {
		set[x.Parent] = true
	}
	for s := range set {
		pn.scopes = append(pn.scopes, s)
	}
	sort.Strings(pn.scopes)
	if len(pn.scopes) > agent.NameScopesMax {
		return nil, &ErrPlaneNameCap{Why: fmt.Sprintf("%d scope directories, at most %d", len(pn.scopes), agent.NameScopesMax)}
	}
	for i, s := range pn.scopes {
		pn.bits[s] = 1 << i
	}
	byName := map[nameKey]int{}
	row := func(name string, prefix bool) (*PlaneNameRow, error) {
		k := nameKey{name, prefix}
		if i, ok := byName[k]; ok {
			return &pn.rows[i], nil
		}
		key, ok := agent.NameKey(name, prefix)
		if !ok {
			return nil, &ErrPlaneNameCap{Why: fmt.Sprintf("the name %q cannot be keyed", name)}
		}
		byName[k] = len(pn.rows)
		pn.rows = append(pn.rows, PlaneNameRow{Key: key, Name: name, Prefix: prefix})
		return &pn.rows[len(pn.rows)-1], nil
	}
	for i, e := range rt.NameDeny {
		var mask uint8
		for _, s := range e.Scopes {
			mask |= pn.bits[s.Canonical]
		}
		r, err := row(e.Literal, e.Prefix)
		if err != nil {
			return nil, err
		}
		r.Arms = append(r.Arms, PlaneNameArm{Scopes: mask, Rule: uint16(i)})
		for _, x := range e.Except {
			r, err := row(agent.FoldName(x), false)
			if err != nil {
				return nil, err
			}
			r.Arms = append(r.Arms, PlaneNameArm{Scopes: mask, Exempt: true, Rule: uint16(i), RawFrom: uint8(len(e.Literal))})
		}
	}
	for _, x := range rt.NameExempt {
		r, err := row(x.Name, false)
		if err != nil {
			return nil, err
		}
		r.Arms = append(r.Arms, PlaneNameArm{Scopes: pn.bits[x.Parent], Depth: 1, Exempt: true, Rule: PlaneNameAll})
	}
	slices.SortStableFunc(pn.rows, func(a, b PlaneNameRow) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		switch {
		case a.Prefix == b.Prefix:
			return 0
		case !a.Prefix:
			return -1
		}
		return 1
	})
	keys := map[uint64]bool{}
	prefixes := map[int]bool{}
	for _, r := range pn.rows {
		if keys[r.Key] {
			return nil, &ErrPlaneNameCap{Why: fmt.Sprintf("the name key of %q collides with another row's", r.Name)}
		}
		keys[r.Key] = true
		if len(r.Arms) > agent.NameArmsMax {
			return nil, &ErrPlaneNameCap{Why: fmt.Sprintf("the row of %q has %d arms, at most %d", r.Name, len(r.Arms), agent.NameArmsMax)}
		}
		if r.Prefix {
			prefixes[len(r.Name)] = true
		}
	}
	switch {
	case len(pn.rows) > agent.NameRowsMax:
		return nil, &ErrPlaneNameCap{Why: fmt.Sprintf("%d name rows, at most %d", len(pn.rows), agent.NameRowsMax)}
	case len(prefixes) > agent.NamePrefixesMax:
		return nil, &ErrPlaneNameCap{Why: fmt.Sprintf("%d prefix lengths, at most %d", len(prefixes), agent.NamePrefixesMax)}
	case len(agent.MinimalNameLeads(rt.NameDeny)) > agent.NameLeadsMax:
		return nil, &ErrPlaneNameCap{Why: fmt.Sprintf("more than %d name leads", agent.NameLeadsMax)}
	}
	return pn, nil
}

// nameKey is a name row's identity while the rows are built: its folded name and form.
type nameKey struct {
	name   string
	prefix bool
}

// setNames records pn in s: the scope bits, the name rows indexed by key, the leads and the prefix lengths.
func (s *PlaneRows) setNames(rt *agent.RuleTable, pn *planeNames) {
	s.Scopes = pn.scopes
	s.NameRows = pn.rows
	s.nameByKey = make(map[uint64]int, len(pn.rows))
	lens := map[uint8]bool{}
	for i, r := range pn.rows {
		s.nameByKey[r.Key] = i
		if r.Prefix {
			lens[uint8(len(r.Name))] = true
		}
	}
	for l := range lens {
		s.PrefixLens = append(s.PrefixLens, l)
	}
	slices.Sort(s.PrefixLens)
	s.Leads = agent.MinimalNameLeads(rt.NameDeny)
	s.nameEntries = len(rt.NameDeny)
	s.nameScopes = make([][]string, len(rt.NameDeny))
	for i, e := range rt.NameDeny {
		for _, sc := range e.Scopes {
			s.nameScopes[i] = append(s.nameScopes[i], sc.Canonical)
		}
	}
	for i := range s.FS {
		s.FS[i].Scopes = pn.bits[s.FS[i].Path]
	}
}

// nameArmRef is one arm a name's lookups found, with the row it is on.
type nameArmRef struct {
	arm PlaneNameArm
	row *PlaneNameRow
}

// maxNameArms bounds the arms one name can meet: its exact row and one row per prefix length, eight arms each.
const maxNameArms = (1 + agent.NamePrefixesMax) * agent.NameArmsMax

// nameCheck is the kernel's name check of the object at path, a clean absolute canonical path, over the rows (ADR
// 0043 D2 to D4): the leads prefilter; the exact key and one prefix key per prefix length, each hit confirmed by
// the folded compare; the arms applied (an exception arm cancels its entry where the name's tail is the scan's
// spelling, a D3 arm cancels every entry where the object's directory carries its bit); then the climb from the
// object's directory, at most agent.MaxWalk levels, which meets each entry's scope bits on the rows of the
// directories it passes and stops at a dependency directory's name. The first entry, in NameDeny order, that is
// covered refuses with the scope that covered it; one undecided at the bound refuses path-unresolved. It allocates
// nothing.
func (s *PlaneRows) nameCheck(path string) (rule PlaneRule, unresolved, hit bool) {
	if s.nameEntries == 0 || path == "/" || path == "" {
		return planeNone, false, false
	}
	i := strings.LastIndexByte(path, '/')
	if i < 0 {
		return planeNone, false, false
	}
	name, dir := path[i+1:], path[:i]
	if dir == "" {
		dir = "/"
	}
	lead := false
	for _, l := range s.Leads {
		if len(name) >= len(l) && agent.FoldEqual(name[:len(l)], l) {
			lead = true
			break
		}
	}
	if !lead || len(name) > 255 {
		return planeNone, false, false
	}
	var arms [maxNameArms]nameArmRef
	n := 0
	look := func(sub string, prefix bool) {
		key, ok := agent.NameKey(sub, prefix)
		if !ok {
			return
		}
		ri, hit := s.nameByKey[key]
		if !hit {
			return
		}
		r := &s.NameRows[ri]
		if r.Prefix != prefix || !agent.FoldEqual(sub, r.Name) {
			return // a key collision matches nothing
		}
		for _, a := range r.Arms {
			if n < len(arms) {
				arms[n] = nameArmRef{a, r}
				n++
			}
		}
	}
	look(name, false)
	for _, l := range s.PrefixLens {
		if int(l) <= len(name) {
			look(name[:l], true)
		}
	}
	// The arms: which entries the name matches, less those an exception or an exemption cancels.
	var live, cancelled uint64
	dirBits := s.scopeBits(dir)
	for _, a := range arms[:n] {
		switch {
		case !a.arm.Exempt:
			live |= 1 << (a.arm.Rule & 63)
		case a.arm.Rule == PlaneNameAll:
			if a.arm.Depth == 1 && dirBits&a.arm.Scopes != 0 {
				return planeNone, false, false
			}
		case len(name) >= int(a.arm.RawFrom) && name[a.arm.RawFrom:] == a.row.Name[a.arm.RawFrom:]:
			cancelled |= 1 << (a.arm.Rule & 63)
		}
	}
	live &^= cancelled
	if live == 0 {
		return planeNone, false, false
	}
	// The climb: each live entry's state, decided at the first of its scopes met or at a dependency directory.
	var covered, decided uint64
	var scopeAt [64]string
	cur := dir
	for level := 1; level <= agent.MaxWalk && live&^decided != 0; level++ {
		bits := s.scopeBits(cur)
		for e := 0; e < s.nameEntries && e < 64; e++ {
			if live&(1<<e) == 0 || decided&(1<<e) != 0 {
				continue
			}
			if bits&s.entryMask(e) != 0 {
				covered |= 1 << e
				decided |= 1 << e
				scopeAt[e] = cur
			}
		}
		if cur == "/" || agent.IsEnvSkipDir(cur[strings.LastIndexByte(cur, '/')+1:]) {
			decided |= live
			break
		}
		next, ok := parent(cur)
		if !ok {
			decided |= live
			break
		}
		cur = next
	}
	for e := 0; e < s.nameEntries && e < 64; e++ {
		switch {
		case live&(1<<e) == 0:
		case covered&(1<<e) != 0:
			return PlaneRule{Section: PlaneNameRule, Index: e, Scope: s.scopeIndex(e, scopeAt[e])}, false, true
		case decided&(1<<e) == 0:
			return planeNone, true, true
		}
	}
	return planeNone, false, false
}

// scopeBits is the scope bits of the row at p, 0 when p keys no row.
func (s *PlaneRows) scopeBits(p string) uint8 {
	if i, ok := s.fsByPath[p]; ok {
		return s.FS[i].Scopes
	}
	return 0
}

// NameEntryMasks is each name entry's deny arms' scope bits, by its position in RuleTable.NameDeny: what the kernel's
// config row carries (bpf.PlaneNameConfig.EntryMask), from which it also builds each scope bit's entries.
func (s *PlaneRows) NameEntryMasks() []uint8 {
	out := make([]uint8, s.nameEntries)
	for e := range out {
		out[e] = s.entryMask(e)
	}
	return out
}

// nameRuleAt is the name entry a kernel rule_idx carrying PlaneRuleName names (ADR 0043 D8): the entry at its
// position, with the scope its bit is; ok is false for an index without the tag, or one naming no entry or scope of
// these rows.
func (s *PlaneRows) nameRuleAt(row int) (PlaneRule, bool) {
	if row < 0 || row > 0xffff {
		return planeNone, false
	}
	e, bit, ok := PlaneNameUntag(uint16(row))
	if !ok || e >= s.nameEntries || bit >= len(s.Scopes) {
		return planeNone, false
	}
	return PlaneRule{Section: PlaneNameRule, Index: e, Scope: s.scopeIndex(e, s.Scopes[bit])}, true
}

// entryMask is entry e's deny arms' scope bits.
func (s *PlaneRows) entryMask(e int) uint8 {
	var m uint8
	for _, sc := range s.nameScopes[e] {
		if i, ok := s.fsByPath[sc]; ok {
			m |= s.FS[i].Scopes
		}
	}
	return m
}

// scopeIndex is the position in entry e's scopes of the scope at path p, which names the refusal (D8).
func (s *PlaneRows) scopeIndex(e int, p string) int {
	for j, sc := range s.nameScopes[e] {
		if sc == p {
			return j
		}
	}
	return -1
}

// DecideObject is the plane's answer for the object at path, a file unless dir: the walk (Decide), then, for a file
// whose read, modification or rename the walk allows, the name check (ADR 0043 D1). A covered file is refused as its
// own deny_read entry would refuse it, named by the RuleTable's entry at its path when its row was compacted (D8)
// and by the name entry otherwise; a name check that cannot decide is path-unresolved.
func (s *PlaneRows) DecideObject(path string, q PlaneQuestion, dir bool) PlaneVerdict {
	v := s.Decide(path, q)
	if !v.Allow || v.Unresolved || q == PlaneProtect || s.nameEntries == 0 {
		return v
	}
	if dir {
		// A directory at a compacted file's path is a question the kernel cannot be asked while the file is there
		// (compile saw a regular file, and the name entry refuses its removal); the model answers it as the dropped
		// row did, refused by the file's entry, so the column stays the root model's (D6: verdict-neutral).
		if i, ok := s.compacted[path]; ok {
			v.Allow, v.Rule = false, PlaneRule{Section: PlaneFSRule, Index: i}
		}
		return v
	}
	rule, unresolved, hit := s.nameCheck(path)
	if !hit {
		return v
	}
	v.Allow = false
	if unresolved {
		v.Unresolved, v.Rule = true, planeNone
		return v
	}
	if i, ok := s.compacted[path]; ok {
		rule = PlaneRule{Section: PlaneFSRule, Index: i}
	}
	v.Rule = rule
	return v
}

// ScopeMoveRefused is D5 over the rows: a rename of the directory at src to dst, clean absolute canonical paths,
// refused when some entry's scopes cover the old place (the climb from src as level 1, src's own name included) and
// not the new one, unless src carries one of that entry's scope bits itself (its scope row moves with it). A climb
// that cannot decide on either side is unresolved.
func (s *PlaneRows) ScopeMoveRefused(src, dst string) (rule PlaneRule, unresolved, refused bool) {
	if s.nameEntries == 0 || src == dst {
		return planeNone, false, false
	}
	for e := 0; e < s.nameEntries && e < 64; e++ {
		mask := s.entryMask(e)
		if mask == 0 || s.scopeBits(src)&mask != 0 {
			continue
		}
		at, before, beforeUnresolved := s.climbPlace(src, mask)
		if !before && !beforeUnresolved {
			continue
		}
		if _, after, afterUnresolved := s.climbPlace(dst, mask); after && !afterUnresolved {
			continue
		} else if beforeUnresolved || afterUnresolved {
			return planeNone, true, true
		}
		return PlaneRule{Section: PlaneNameRule, Index: e, Scope: s.scopeIndex(e, at)}, false, true
	}
	return planeNone, false, false
}

// climbPlace is the climb from dir as level 1 for a scope mask: the scope met, whether one was met before a
// dependency directory or "/", and whether the bound passed first.
func (s *PlaneRows) climbPlace(dir string, mask uint8) (at string, covered, unresolved bool) {
	cur := dir
	for level := 1; ; level++ {
		if level > agent.MaxWalk {
			return "", false, true
		}
		if s.scopeBits(cur)&mask != 0 {
			return cur, true, false
		}
		if cur == "/" || agent.IsEnvSkipDir(cur[strings.LastIndexByte(cur, '/')+1:]) {
			return "", false, false
		}
		next, ok := parent(cur)
		if !ok {
			return "", false, false
		}
		cur = next
	}
}

// compactRows is D6: the fs rows the plane may drop because a name entry decides their file alike, by every way the
// run can reach it, dropped only as many as bring the keyed paths down to PlaneCompactAt, in reverse path order. A
// row qualifies when every entry at its path is a deny_read entry of the built-in .env list or of a declared glob
// with a name entry; a name entry not exposed by a bind covers the path (the root model's NameIndex); compile saw a
// regular file with one link, reached through no symlink and not a mount point; its filesystem spells a file one way
// (xfs or btrfs, or ext4, f2fs or tmpfs with a directory compile read as case-exact); no other row keys the path
// (a deny_write chain, an exec or listener key, a scope); and, without the row, the walk from the path allows both a
// read and a modification within the bound, so the name check alone decides, with the entry's verdict and rule. It
// returns each dropped path's deciding entry (the lowest at the path, which the row named).
func compactRows(rt *agent.RuleTable, nx *NameIndex, x *RootIndex, paths map[string]bool, keep map[string]bool, keyed int) map[string]int {
	if nx == nil || keyed <= PlaneCompactAt {
		return nil
	}
	at := map[string][]int{}
	for i := range rt.FS {
		if p := rt.FS[i].Canonical(); paths[p] && !keep[p] {
			at[p] = append(at[p], i)
		}
	}
	declared := map[string]bool{}
	builtIn := false
	for _, e := range rt.NameDeny {
		if e.BuiltIn {
			builtIn = true
		} else {
			declared[e.Raw] = true
		}
	}
	var cands []string
	for p, idx := range at {
		if compactable(rt, nx, x, p, idx, declared, builtIn) {
			cands = append(cands, p)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(cands)))
	out := map[string]int{}
	for _, p := range cands {
		if keyed <= PlaneCompactAt {
			break
		}
		out[p] = at[p][0]
		keyed--
	}
	return out
}

// compactable is compactRows' test of one path p and the entries at it.
func compactable(rt *agent.RuleTable, nx *NameIndex, x *RootIndex, p string, idx []int, declared map[string]bool, builtIn bool) bool {
	for _, i := range idx {
		r := &rt.FS[i]
		switch {
		case r.Kind != agent.FSDenyRead:
			return false
		case !(r.BuiltIn && builtIn) && !(r.Raw != "" && declared[r.Raw]):
			return false
		case !r.Regular || r.Nlink != 1 || r.FileMountPoint || r.IsMountPoint || r.Path != p:
			return false
		}
		switch r.Filesystem {
		case "xfs", "btrfs":
		case "ext4", "f2fs", "tmpfs":
			if !r.DirCaseExact {
				return false
			}
		default:
			return false
		}
	}
	m, ok := nx.Match(p, false)
	if !ok || m.Unresolved {
		return false
	}
	name := p[strings.LastIndexByte(p, '/')+1:]
	for j := range rt.NameDeny {
		e := &rt.NameDeny[j]
		if !e.BindExposed || !e.Matches(name) {
			continue
		}
		if _, _, covered, unresolved := agent.NameClimb(e.Scopes, p); covered || unresolved {
			return false
		}
	}
	rv, mv := x.walkBeneath(p, true), x.walkBeneath(p, false)
	return rv.Allow && mv.Allow && !rv.Unresolved && !mv.Unresolved
}
