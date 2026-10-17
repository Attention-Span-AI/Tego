// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"encoding/binary"
	"path/filepath"
	"slices"
	"strings"
)

// This file is ADR 0043's name entries as compile output (RuleTable.NameDeny, NameExempt): what a name entry is,
// how a final name matches it, where its scopes cover a file, how the plane keys it, and which entries a run's
// caps can hold. It is pure: the compiler (compile_namedeny.go) gathers the facts, and the decision core
// (internal/policy/decide) asks these predicates of a canonical path.

// The caps on a run's name entries (ADR 0043 Terms), which the plane's slot holds and decide.CompilePlane checks:
// name rows (exact, prefix, exception and exemption-only rows), arms per row, scope directories (exemption parents
// included), distinct prefix lengths and prefilter leads; and entries, which the kernel's rule_idx tag names in six
// bits (ADR 0043 D8).
const (
	NameRowsMax     = 64
	NameArmsMax     = 8
	NameScopesMax   = 8
	NamePrefixesMax = 4
	NameLeadsMax    = 8
	NameEntriesMax  = 64
)

// NameCompactAt is ADR 0043 D6's threshold: a table whose plane keys more paths than this may have its covered
// per-file rows dropped. Compile gathers the facts compaction needs (the casefold flag of a covered file's
// directory) only past it; decide.PlaneCompactAt starts at this value.
const NameCompactAt = 1024

// The literal floors (ADR 0043 Terms): a declared glob's final component is a name entry only when its literal is
// at least this long, so `k*` or `a` keep the compile-time expansion.
const (
	nameExactFloor  = 2
	namePrefixFloor = 3
)

// EnvSkipDirs are the dependency directories (ADR 0043 Terms): the directories the built-in .env scan never
// enters, compared case-exactly as the scan compares them. A name entry covers nothing beneath one unless the
// scope itself lies at or below it.
var EnvSkipDirs = []string{".git", "node_modules", "vendor", "target", ".venv", "venv"}

// IsEnvSkipDir reports whether a directory's final name is a dependency directory's, byte for byte.
func IsEnvSkipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", "target", ".venv", "venv":
		return true
	}
	return false
}

// builtInEnvExact and builtInEnvPrefix are the built-in .env list as name entries (SEMANTICS §1, agent-contract
// R6; ADR 0043 Terms): `.env` itself, and every `.env.<x>` but the example files, which the scan skips too
// (isEnvFile asks the same two).
const (
	builtInEnvExact  = ".env"
	builtInEnvPrefix = ".env."
)

// builtInEnvExcept are the names the built-in prefix entry does not cover, as the scan spells them: each starts
// with the prefix literal, and only its bytes after the literal compare exactly (NameDenyRule.Matches).
var builtInEnvExcept = []string{".env.example", ".env.sample", ".env.template", ".env.dist"}

// BuiltInEnvEntries is the built-in .env list's two name entries over scopes, in allocation order: `.env` exact,
// then `.env.` as a prefix but its example files. The compiler makes them; doctor's known answers fill them as a
// run's slot holds them.
func BuiltInEnvEntries(scopes []NameScope) []NameDenyRule {
	return []NameDenyRule{
		{Literal: builtInEnvExact, Scopes: scopes, BuiltIn: true},
		{Literal: builtInEnvPrefix, Prefix: true, Except: slices.Clone(builtInEnvExcept), Scopes: slices.Clone(scopes), BuiltIn: true},
	}
}

// NameScope is one directory a name entry covers files beneath: Canonical is its resolved path, the spelling the
// kernel's walk and every canonical path meet; Spelling is the path compile named it by (a scan root, a glob's
// literal base), which a built-in entry's rule name carries.
type NameScope struct {
	Canonical string
	Spelling  string
}

// NameDenyRule is one name entry (ADR 0043): a deny_read compiled to a final name, exact or a literal prefix,
// ASCII-folded, that covers a matching file beneath any of its scopes, files created after compile included.
type NameDenyRule struct {
	// Literal is the name or the prefix, ASCII-folded (FoldName).
	Literal string
	// Prefix makes Literal a prefix: a name matches when it starts with Literal (Literal itself included).
	Prefix bool
	// Scopes are the directories the entry covers beneath, nearest-first order not implied.
	Scopes []NameScope
	// Except are folded exact names the entry does not cover: the built-in prefix entry's example files.
	Except []string
	// Raw is the declared glob; "" for the built-in.
	Raw string
	// Pos is where the glob was declared; zero for the built-in.
	Pos Pos
	// BuiltIn marks the built-in .env list's two entries.
	BuiltIn bool
	// BindExposed says compile's mount table shows a directory beneath one of the scopes mounted outside it, where
	// a file is reached without passing the scope (ADR 0043 D6 (f)): no row it covers is ever compacted.
	BindExposed bool
}

// NameExemptRule is ADR 0043 D3's exemption: a write entry declared in the top-level contract file at an existing
// file whose folded name a name entry matches. It cancels every entry's arms for that name in that directory.
type NameExemptRule struct {
	// Parent is the write entry's resolved parent directory, canonical.
	Parent string
	// Name is the write entry's resolved final name, folded.
	Name string
	// Write is the write entry's position in RuleTable.FS.
	Write int
}

// FoldName is name with the ASCII letters A-Z lowered and every other byte kept (ADR 0043 D2): no Unicode folding.
func FoldName(name string) string {
	for i := 0; i < len(name); i++ {
		if c := name[i]; c >= 'A' && c <= 'Z' {
			b := []byte(name)
			for j := i; j < len(b); j++ {
				b[j] = FoldByte(b[j])
			}
			return string(b)
		}
	}
	return name
}

// FoldByte is one byte of FoldName.
func FoldByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// Matches reports whether a final name, as the dentry spells it, matches the entry (ADR 0043 D2 as built): the
// literal part compared ASCII-folded, the whole name for an exact literal and its start for a prefix; a prefix
// entry's exception compared as the scan spells it, the bytes after the literal exactly (Implementation notes, C2),
// so `.env.EXAMPLE`, which the scan denies, stays covered while `.ENV.example` is an exception as `.env.example`
// is. It allocates nothing.
func (r *NameDenyRule) Matches(name string) bool {
	n := len(r.Literal)
	if !r.Prefix {
		return len(name) == n && FoldEqual(name, r.Literal)
	}
	if len(name) < n || !FoldEqual(name[:n], r.Literal) {
		return false
	}
	for _, x := range r.Except {
		if len(x) == len(name) && len(x) >= n && name[n:] == x[n:] {
			return false
		}
	}
	return true
}

// MatchesFolded reports whether some spelling of a folded name could match the entry, its exceptions aside: what
// an exemption, which names a folded name (D3), cancels.
func (r *NameDenyRule) MatchesFolded(folded string) bool {
	if !r.Prefix {
		return folded == r.Literal
	}
	return strings.HasPrefix(folded, r.Literal)
}

// FoldEqual reports whether name, ASCII-folded, equals folded, without allocating.
func FoldEqual(name, folded string) bool {
	if len(name) != len(folded) {
		return false
	}
	for i := 0; i < len(name); i++ {
		if FoldByte(name[i]) != folded[i] {
			return false
		}
	}
	return true
}

// Form is the entry's literal as a pattern: the literal, with a `*` after a prefix.
func (r *NameDenyRule) Form() string {
	if r.Prefix {
		return r.Literal + "*"
	}
	return r.Literal
}

// RuleName is the rule a refusal by this entry carries when no RuleTable entry lies at the file's own path (ADR
// 0043 D8): a declared glob's own name, "fs.deny_read[<raw glob>]", and for the built-in a label naming the scope
// that decided, "fs.deny_read[<scope spelling>/**/<form>]". `**` is not contract syntax, so a label never equals
// a declared entry's name (ADR 0030).
func (r *NameDenyRule) RuleName(scope int) string {
	if !r.BuiltIn {
		return "fs.deny_read[" + r.Raw + "]"
	}
	sp := "/"
	if scope >= 0 && scope < len(r.Scopes) {
		sp = r.Scopes[scope].Spelling
	}
	return "fs.deny_read[" + strings.TrimSuffix(sp, "/") + "/**/" + r.Form() + "]"
}

// NameKey is the key a name row is written under in the plane's name map (ADR 0043 D9): FNV-1a over the length and
// the folded literal as eight-byte words in the host's byte order, zero-padded (the exec rows' internal/bpf
// PlaneNameKey over folded bytes), with bit 63 cleared, bit 62 set for a prefix key and clear for an exact one, and
// 0 (the config row's key) replaced by 1. A prefix row's key is the key of its literal's bytes, which the kernel
// computes over a name's first len(literal) bytes. ok is false for a literal the kernel cannot carry (empty, or
// longer than 255 bytes). bpf/decide_names.h's name check is its kernel twin, over the dentry's words as the kernel
// loads them; TestNameKeyVectors pins both byte orders (NameKeyIn), since the plane is built bpfel and bpfeb. It
// allocates nothing (the decision core's name check asks it per question).
func NameKey(literal string, prefix bool) (key uint64, ok bool) {
	return NameKeyIn(literal, prefix, hostBigEndian)
}

// hostBigEndian is this host's byte order.
var hostBigEndian = binary.NativeEndian.Uint16([]byte{0, 1}) == 1

// NameKeyIn is NameKey with the words read big-endian or little-endian: the host's order is NameKey's, and the
// other is the key a host of that byte order writes and its kernel looks up.
func NameKeyIn(literal string, prefix, bigEndian bool) (key uint64, ok bool) {
	if literal == "" || len(literal) > 255 {
		return 0, false
	}
	h := uint64(0xcbf29ce484222325) ^ uint64(len(literal))
	for i := 0; i < len(literal); i += 8 {
		var w uint64
		for j := 0; j < 8 && i+j < len(literal); j++ {
			shift := 8 * j
			if bigEndian {
				shift = 8 * (7 - j)
			}
			w |= uint64(FoldByte(literal[i+j])) << shift
		}
		h = (h ^ w) * 0x100000001b3
	}
	h &^= 1 << 63
	if prefix {
		h |= 1 << 62
	} else {
		h &^= 1 << 62
	}
	if h == 0 {
		h = 1
	}
	return h, true
}

// NameClimb is ADR 0043 D4's scope test of the file at path, a clean absolute canonical path, for one entry's scopes
// (canonical paths): the climb from the file's directory towards "/", at most MaxWalk levels counted from the file,
// meets one of scopes before it meets a dependency directory (a scope that is itself one, or lies beneath one,
// covers its own base). covered names the scope it met (its position in scopes) and how many levels above the file
// it lies; unresolved is a climb that passed the bound before it decided, which refuses (fail closed). The object
// itself is never its own scope: a name entry decides files, and a scope is a directory.
func NameClimb(scopes []NameScope, path string) (scope, level int, covered, unresolved bool) {
	if len(scopes) == 0 {
		return -1, 0, false, false
	}
	dir, ok := parentDir(path)
	if !ok {
		return -1, 0, false, false
	}
	return NameClimbDir(scopes, dir)
}

// NameClimbDir is NameClimb for a file directly in dir, the climb starting at dir as level 1: the coverage of a
// place, which a directory rename moves (D5) with the directory's own name at level 1.
func NameClimbDir(scopes []NameScope, dir string) (scope, level int, covered, unresolved bool) {
	if len(scopes) == 0 || dir == "" {
		return -1, 0, false, false
	}
	cur := dir
	for level = 1; ; level++ {
		if level > MaxWalk {
			return -1, level, false, true
		}
		for i := range scopes {
			if scopes[i].Canonical == cur {
				return i, level, true, false
			}
		}
		if cur == "/" || IsEnvSkipDir(cur[strings.LastIndexByte(cur, '/')+1:]) {
			return -1, level, false, false
		}
		next, ok := parentDir(cur)
		if !ok {
			return -1, level, false, false
		}
		cur = next
	}
}

// parentDir is the directory holding p, a clean absolute path, and false at "/".
func parentDir(p string) (string, bool) {
	if p == "/" || p == "" {
		return "", false
	}
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return "/", true
	}
	return p[:i], true
}

// NameLeftOut is a candidate name entry FitNameEntries could not give the plane room for, and why: a cap it would
// pass, or a key it shares with a row already allotted.
type NameLeftOut struct {
	Entry NameDenyRule
	Why   string
}

// NameEntriesWhole reports whether every name-eligible deny_read entry of the table, the built-in pair included, has
// its name entry: none was left out by a cap or a collision (RuleTable.NameLeftOut). ADR 0043 D7's capability
// fs.deny_read.created_later needs it beside the plane's name check: a left-out entry's later files are not refused.
func (rt *RuleTable) NameEntriesWhole() bool { return len(rt.NameLeftOut) == 0 }

// nameRowKey is one name row: a literal and its form. Two entries with one literal and form share a row, an arm
// each.
type nameRowKey struct {
	literal string
	prefix  bool
}

// nameKeyOf is NameKey; a test forces a collision through it, which no pair of real literals is known to make.
var nameKeyOf = NameKey

// nameAlloc is what FitNameEntries has given out so far.
type nameAlloc struct {
	arms       map[nameRowKey]int
	keys       map[uint64]nameRowKey
	scopes     map[string]bool
	prefixLens map[int]bool
	leads      map[string]bool
	exempt     map[[2]string]bool
}

func (a *nameAlloc) clone() *nameAlloc {
	return &nameAlloc{arms: cloneMap(a.arms), keys: cloneMap(a.keys), scopes: cloneMap(a.scopes),
		prefixLens: cloneMap(a.prefixLens), leads: cloneMap(a.leads), exempt: cloneMap(a.exempt)}
}

func cloneMap[K comparable, V any](m map[K]V) map[K]V {
	out := make(map[K]V, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// arm adds one arm to the row of literal in its form, and says what it costs when it does not fit: a key that
// collides with another row's, or a row past NameArmsMax arms or the slot past NameRowsMax rows.
func (a *nameAlloc) arm(literal string, prefix bool) string {
	k := nameRowKey{literal, prefix}
	if _, have := a.arms[k]; !have {
		key, ok := nameKeyOf(literal, prefix)
		if !ok {
			return "a name longer than 255 bytes"
		}
		if other, taken := a.keys[key]; taken && other != k {
			return "its name key collides with the row of " + other.literal
		}
		a.keys[key] = k
		if len(a.arms) >= NameRowsMax {
			return "the plane's 64 name rows a run"
		}
	}
	a.arms[k]++
	if a.arms[k] > NameArmsMax {
		return "the plane's 8 arms a name row"
	}
	return ""
}

// fits says why the allocation passes a cap that is not per row, "" when it passes none.
func (a *nameAlloc) fits() string {
	switch {
	case len(a.scopes) > NameScopesMax:
		return "the plane's 8 scope directories a run"
	case len(a.prefixLens) > NamePrefixesMax:
		return "the plane's 4 prefix lengths a run"
	case len(minimalLeads(a.leads)) > NameLeadsMax:
		return "the plane's 8 name leads a run"
	}
	return ""
}

// NameLead is a literal's prefilter word (ADR 0043 D2): its first eight bytes, folded.
func NameLead(literal string) string {
	if len(literal) > 8 {
		return literal[:8]
	}
	return literal
}

// minimalLeads is leads without one another lead is a prefix of: a name that passes the shorter passes the longer's
// test too, so the slot header keeps the shorter alone (`.env` covers `.env.`'s lead).
func minimalLeads(leads map[string]bool) []string {
	var out []string
	for l := range leads {
		covered := false
		for o := range leads {
			if o != l && strings.HasPrefix(l, o) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, l)
		}
	}
	slices.Sort(out)
	return out
}

// MinimalNameLeads is the prefilter leads of entries (the slot header's leads, ADR 0043 D2), sorted.
func MinimalNameLeads(entries []NameDenyRule) []string {
	leads := map[string]bool{}
	for i := range entries {
		leads[NameLead(entries[i].Literal)] = true
	}
	return minimalLeads(leads)
}

// exemptionApplies reports whether an exemption cancels entry's arms: the entry matches a spelling of its folded
// name, and a file of that name in its parent lies beneath one of the entry's scopes.
func exemptionApplies(e *NameDenyRule, x NameExemptRule) bool {
	if !e.MatchesFolded(x.Name) {
		return false
	}
	_, _, covered, _ := NameClimb(e.Scopes, joinName(x.Parent, x.Name))
	return covered
}

func joinName(dir, name string) string {
	if dir == "/" {
		return "/" + name
	}
	return dir + "/" + name
}

// FitNameEntries is ADR 0043's allocation (Terms): candidates in allocation order (the built-in exact entry, the
// built-in prefix entry, then declared entries in declared order), each given the rows, arms, scopes, leads and
// prefix lengths it needs together with those of every exemption that applies to it, or left out whole when they
// do not fit or its name key collides with a row already allotted. An exemption is allotted only with a kept
// entry it applies to. kept is in allocation order; the caller orders NameDeny.
func FitNameEntries(candidates []NameDenyRule, exempts []NameExemptRule) (kept []NameDenyRule, keptExempt []NameExemptRule, left []NameLeftOut) {
	a := &nameAlloc{arms: map[nameRowKey]int{}, keys: map[uint64]nameRowKey{}, scopes: map[string]bool{},
		prefixLens: map[int]bool{}, leads: map[string]bool{}, exempt: map[[2]string]bool{}}
	for _, e := range candidates {
		if len(kept) == NameEntriesMax {
			left = append(left, NameLeftOut{Entry: e, Why: "the plane's 64 name entries a run"})
			continue
		}
		t := a.clone()
		why := t.arm(e.Literal, e.Prefix)
		for _, x := range e.Except {
			if why == "" {
				why = t.arm(x, false)
			}
		}
		var added []NameExemptRule
		for _, x := range exempts {
			if why != "" {
				break
			}
			k := [2]string{x.Parent, x.Name}
			if t.exempt[k] || !exemptionApplies(&e, x) {
				continue
			}
			t.exempt[k] = true
			why = t.arm(x.Name, false)
			t.scopes[x.Parent] = true
			added = append(added, x)
		}
		for _, s := range e.Scopes {
			t.scopes[s.Canonical] = true
		}
		if e.Prefix {
			t.prefixLens[len(e.Literal)] = true
		}
		t.leads[NameLead(e.Literal)] = true
		if why == "" {
			why = t.fits()
		}
		if why != "" {
			left = append(left, NameLeftOut{Entry: e, Why: why})
			continue
		}
		a = t
		kept = append(kept, e)
		keptExempt = append(keptExempt, added...)
	}
	return kept, keptExempt, left
}

// NameEntryOf classifies a deny_read glob's final component (ADR 0043 Terms): a literal free of `*?[\` of at least
// two bytes is an exact entry, and such a literal of at least three bytes followed by one `*` a prefix entry; any
// other component (a suffix, a class, a bare `*`, a literal under the floor) is none, and keeps the compile-time
// expansion alone. literal is folded.
func NameEntryOf(component string) (literal string, prefix, ok bool) {
	lit, star := strings.CutSuffix(component, "*")
	if strings.ContainsAny(lit, `*?[\`) {
		return "", false, false
	}
	switch {
	case star && len(lit) >= namePrefixFloor:
		return FoldName(lit), true, true
	case !star && len(lit) >= nameExactFloor:
		return FoldName(lit), false, true
	}
	return "", false, false
}

// globBase is the glob's literal base (ADR 0043 Terms): the longest leading run of components of the absolute
// pattern p that holds no glob character, short of the final component.
func globBase(p string) string {
	dir := filepath.Dir(p)
	base := "/"
	for c := range strings.SplitSeq(strings.TrimPrefix(dir, "/"), "/") {
		if c == "" {
			continue
		}
		if strings.ContainsAny(c, `*?[\`) {
			break
		}
		base = filepath.Join(base, c)
	}
	return base
}
