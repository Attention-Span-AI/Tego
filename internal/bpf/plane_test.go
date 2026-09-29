// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"encoding/binary"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// planeDeclared is how many of each hook's arguments bpf/decide.bpf.c declares: its 6.1 prototype or a prefix of
// it (ARCHITECTURE §11.1 rule 1; path_rename's flags came later and are not read).
var planeDeclared = map[string]int{
	"file_open": 1, "bprm_check": 1, "path_rename": 4, "path_link": 3, "path_unlink": 2, "path_rmdir": 2,
	"socket_connect": 3, "socket_sendmsg": 2,
	"path_mknod": 3, "path_mkdir": 2, "path_symlink": 2, "path_truncate": 1, "file_truncate": 1, "path_chmod": 1,
	"path_chown": 1, "inode_setxattr": 2, "inode_removexattr": 2, "inode_set_acl": 2, "inode_remove_acl": 2,
	"socket_create": 4, "mmap_file": 4, "file_mprotect": 3,
	"socket_bind": 3, "ptrace_access_check": 2, "ptrace_traceme": 1, "bpf": 3, "key_permission": 3,
	"socket_listen": 2,
}

// planeDeclaredFmodRet is the arguments a hook's fmod_ret program reads where its security_ function takes fewer
// than its LSM hook: security_mmap_file(file, prot, flags) against bpf_lsm_mmap_file(file, reqprot, prot, flags). The
// body's fourth parameter is then the return slot, which it never reads in that mode (decide_stepc.h).
var planeDeclaredFmodRet = map[string]int{"mmap_file": 3}

// TestPlaneAttachTargetsResolve asserts each plane hook's two attach targets, bpf_lsm_<hook> for LSM mode and the
// security_ function for fmod_ret mode, are in the running kernel's BTF with at least the arguments the C
// declares. Unprivileged: the kernel's BTF is world-readable.
func TestPlaneAttachTargetsResolve(t *testing.T) {
	t.Parallel()
	spec := kernelBTF(t)
	for _, h := range PlaneHooks {
		declared, ok := planeDeclared[h.Name]
		if !ok {
			t.Fatalf("%s: no declared argument count in planeDeclared", h.Name)
		}
		for _, target := range []string{"bpf_lsm_" + h.LSM, h.Security} {
			declared := declared
			if n, ok := planeDeclaredFmodRet[h.Name]; ok && target == h.Security {
				declared = n
			}
			t.Run(target, func(t *testing.T) {
				params, err := paramsOf(spec, target)
				if err != nil && h.Optional {
					t.Skipf("%s is optional (enforce-plane R3) and this kernel has no %s: %v", h.Name, target, err)
				}
				if err != nil {
					t.Fatalf("%s: %v", h.Name, err)
				}
				if declared > len(params) {
					t.Fatalf("%s declares %d arguments, %s has %d (ARCHITECTURE §11.1 rule 1)", h.Name, declared,
						target, len(params))
				}
			})
		}
	}
}

// TestPlaneNamesAreDisjoint keeps the plane's programs and maps apart from tier 2's, which share a pin directory
// and a program listing with them.
func TestPlaneNamesAreDisjoint(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, n := range slices.Concat(CgroupPrograms, TrackPrograms, TracePrograms, SSLPrograms) {
		seen[n] = true
	}
	for _, m := range PlaneModes {
		progs := PlanePrograms(m)
		if len(progs) != len(PlaneHooks) {
			t.Fatalf("%s: %d programs for %d hooks", m, len(progs), len(PlaneHooks))
		}
		for _, p := range progs {
			if seen[p] {
				t.Errorf("program %s is named twice", p)
			}
			seen[p] = true
		}
	}
	maps := map[string]bool{}
	for _, m := range slices.Concat(SharedMaps, NetMaps, CaptureMaps) {
		maps[m] = true
	}
	for _, m := range PlaneMaps {
		if maps[m] {
			t.Errorf("map %s is named twice", m)
		}
	}
	if slices.Contains(Objects(), ObjectPlaneRdonly) || slices.Contains(Objects(), ObjectPlaneProbe) {
		t.Error("Objects lists a plane build; every loop over the tier-2 objects would load it")
	}
}

// TestPlaneCapsMatchRowCompiler (enforce-plane R5, E13) holds the row compiler's caps (internal/policy/decide) to the slot
// maps' sizes, and its row positions and kind bits to the row's rule_idx and kind fields: the compiler refuses a
// table over the caps rather than truncate it, which is sound only if the caps are these maps' sizes.
func TestPlaneCapsMatchRowCompiler(t *testing.T) {
	t.Parallel()
	if decide.PlaneRowsMax != PlaneRowsMax || decide.PlaneExecRowsMax != PlaneExecRowsMax || decide.PlaneListenRowsMax != PlaneListenRowsMax {
		t.Errorf("row compiler caps %d/%d, maps %d/%d", decide.PlaneRowsMax, decide.PlaneExecRowsMax, PlaneRowsMax, PlaneExecRowsMax)
	}
	if PlaneWalkMax != agent.MaxWalk {
		t.Errorf("the kernel walk's bound %d is not the root model's %d", PlaneWalkMax, agent.MaxWalk)
	}
	if PlaneRuleFSRow != decide.PlaneRuleFSRow || uint64(PlaneRowsMax-1)&uint64(PlaneRuleFSRow) != 0 {
		t.Errorf("bprm_check's fs-row bit %#x is %#x in the row compiler, or a row position reaches it",
			PlaneRuleFSRow, decide.PlaneRuleFSRow)
	}
	var row PlaneRow
	if uint64(PlaneRowsMax-1) > uint64(^row.RuleIdx) {
		t.Errorf("a row position up to %d does not fit rule_idx", PlaneRowsMax-1)
	}
	all := decide.PlaneReadDeny | decide.PlaneModifyAllow | decide.PlaneRenameRefused | decide.PlaneExecDir |
		decide.PlaneProtected | decide.PlaneMountOnly
	row.Kind = uint8(all)
	if decide.PlaneKind(row.Kind) != all {
		t.Errorf("kind bits %08b do not fit the row's kind", all)
	}
	for _, k := range []struct {
		c decide.PlaneKind
		b uint8
	}{{decide.PlaneReadDeny, PlaneRowReadDeny}, {decide.PlaneModifyAllow, PlaneRowModifyAllow},
		{decide.PlaneRenameRefused, PlaneRowRenameRefused}, {decide.PlaneExecDir, PlaneRowExecDir},
		{decide.PlaneProtected, PlaneRowProtected}, {decide.PlaneMountOnly, PlaneRowMountOnly}} {
		if uint8(k.c) != k.b {
			t.Errorf("row compiler kind bit %08b is %08b in the kernel's enum tego_plane_row_kind", k.c, k.b)
		}
	}
	if uint8(decide.PlaneScopeOnly) != PlaneRowScopeOnly || PlaneRowScopeOnly&uint8(all) != 0 {
		t.Errorf("the scope-only kind bit %08b is %08b in the row compiler, or overlaps another", PlaneRowScopeOnly, decide.PlaneScopeOnly)
	}
	// ADR 0043 D9's name caps, the row compiler's and compile's, and D8's tag.
	for _, c := range []struct {
		name        string
		kernel, go_ int
	}{
		{"name rows", PlaneNameRowsMax, agent.NameRowsMax}, {"arms a row", PlaneNameArms, agent.NameArmsMax},
		{"scopes", PlaneScopesMax, agent.NameScopesMax}, {"prefix lengths", PlaneNamePrefixes, agent.NamePrefixesMax},
		{"leads", PlaneNameLeads, agent.NameLeadsMax}, {"entries", PlaneNameEntries, agent.NameEntriesMax},
		{"name map keys", PlaneNameKeys, agent.NameRowsMax + 1}, {"dependency names", PlaneNameDeps, len(agent.EnvSkipDirs)},
	} {
		if c.name == "dependency names" {
			if c.go_ > c.kernel {
				t.Errorf("%d dependency directories do not fit the config row's %d", c.go_, c.kernel)
			}
			continue
		}
		if c.kernel != c.go_ {
			t.Errorf("the kernel's %s cap is %d, compile's %d", c.name, c.kernel, c.go_)
		}
	}
	for _, d := range agent.EnvSkipDirs {
		if len(d) > PlaneNameDepLen {
			t.Errorf("dependency directory %q is longer than the config row's %d bytes", d, PlaneNameDepLen)
		}
	}
	if PlaneRuleName != decide.PlaneRuleName || PlaneNameArmAll != decide.PlaneNameAll {
		t.Errorf("the name tag %#x / all-arm %#x are %#x / %#x in the row compiler", PlaneRuleName, PlaneNameArmAll,
			decide.PlaneRuleName, decide.PlaneNameAll)
	}
	// The tag is disjoint from every fs row position and from the u32 bits bprm_check and the listener set; the
	// largest tag is not TEGO_PLANE_RULE_NONE.
	maxTag := decide.PlaneNameTag(PlaneNameEntries-1, PlaneScopesMax-1)
	if uint32(PlaneRowsMax-1)&uint32(PlaneRuleName) != 0 || uint32(maxTag)&(PlaneRuleFSRow|PlaneRuleListen) != 0 ||
		maxTag == PlaneRuleNone {
		t.Errorf("the name tag %#x meets a row position, bprm_check's fs-row bit or the listener's, or is none", maxTag)
	}
	if PlaneSlotNameDecides&(PlaneSlotExecDecides|PlaneSlotExecAnon|PlaneSlotUnixDecides|PlaneSlotNetDecides|
		PlaneSlotNetICMP|PlaneSlotListenDecides|PlaneSlotKeyringAllowed) != 0 {
		t.Errorf("PlaneSlotNameDecides %#x overlaps another slot flag", PlaneSlotNameDecides)
	}
}

// TestPlaneSlotSetLeads is the header's prefilter as the hooks read it (bpf/decide_names.h tego_name_candidate):
// each lead its folded literal's bytes in the host's order, zero past its length, its length, the shortest length,
// and the prefix lengths; a set the header cannot carry leaves the header unchanged.
func TestPlaneSlotSetLeads(t *testing.T) {
	t.Parallel()
	s := PlaneSlot{Gen: 7, Flags: PlaneSlotExecDecides}
	if !s.SetLeads([]string{".env", "secret.j"}, []uint8{5, 9}) {
		t.Fatal("SetLeads refused two leads and two prefix lengths")
	}
	var w [8]byte
	copy(w[:], ".env")
	if s.NLeads != 2 || s.LeadLen[0] != 4 || s.LeadLen[1] != 8 || s.MinLen != 4 || s.Lead[0] != binary.NativeEndian.Uint64(w[:]) {
		t.Errorf("leads %+v", s)
	}
	if s.NPrefixes != 2 || s.PrefixLen != [PlaneNamePrefixes]uint8{5, 9, 0, 0} {
		t.Errorf("prefix lengths %d %v", s.NPrefixes, s.PrefixLen)
	}
	if s.Gen != 7 || s.Flags != PlaneSlotExecDecides {
		t.Errorf("SetLeads changed the header's gen or flags: %+v", s)
	}
	before := s
	for _, bad := range []struct {
		leads []string
		lens  []uint8
	}{
		{[]string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}, nil},
		{[]string{"toolonglead"}, nil},
		{[]string{""}, nil},
		{nil, []uint8{1, 2, 3, 4, 5}},
		{nil, []uint8{0}},
	} {
		if s.SetLeads(bad.leads, bad.lens) || s != before {
			t.Errorf("SetLeads(%q, %v) was taken or changed the header", bad.leads, bad.lens)
		}
	}
}

// TestPlaneNameRowsEncode is the name row and config row as decide_names.h reads them: the literal zero-padded with
// its form and its arms summed up (deny entries, a built-in exception's entries and literal length, D3's scope bits),
// a row the summary cannot say refused; the config row's entry masks, each scope bit's entries, the dependency names
// as zero-padded words, and the coverage D5's climb stops at.
func TestPlaneNameRowsEncode(t *testing.T) {
	t.Parallel()
	arms := []PlaneNameArm{{Scopes: 1, Rule: 0}, {Scopes: 2, Depth: 1, Flags: PlaneNameArmExempt, Rule: PlaneNameArmAll},
		{Scopes: 1, Rule: 5}}
	r, ok := NewPlaneNameRow(".env.", true, 9, arms)
	if !ok || r.Flags != PlaneNameRowPrefix || r.NameLen != 5 || r.Gen != 9 || string(r.Name[:6]) != ".env.\x00" ||
		r.Deny != 1<<0|1<<5 || r.Exempt != 2 || r.Except != 0 {
		t.Errorf("name row %+v", r)
	}
	// The built-in's exceptions on .env.example's exact row cancel the prefix entry (1) from byte 5 on.
	x, ok := NewPlaneNameRow(".env.example", false, 9, []PlaneNameArm{{Scopes: 1, Flags: PlaneNameArmExempt, Rule: 1, RawFrom: 5}})
	if !ok || x.Except != 1<<1 || x.ExceptFrom != 5 || x.Deny != 0 || x.Exempt != 0 {
		t.Errorf("exception row %+v", x)
	}
	for _, bad := range []struct {
		why  string
		arms []PlaneNameArm
	}{
		{"nine arms", make([]PlaneNameArm, PlaneNameArms+1)},
		{"an entry past 63", []PlaneNameArm{{Rule: PlaneNameEntries}}},
		{"an exception of entry 64", []PlaneNameArm{{Flags: PlaneNameArmExempt, Rule: PlaneNameEntries, RawFrom: 5}}},
		{"exceptions of two literal lengths", []PlaneNameArm{{Flags: PlaneNameArmExempt, Rule: 1, RawFrom: 5},
			{Flags: PlaneNameArmExempt, Rule: 2, RawFrom: 6}}},
		{"an exemption of every entry at depth 0", []PlaneNameArm{{Scopes: 1, Flags: PlaneNameArmExempt, Rule: PlaneNameArmAll}}},
	} {
		if _, ok := NewPlaneNameRow(".env", false, 1, bad.arms); ok {
			t.Errorf("a row with %s was taken", bad.why)
		}
	}
	if _, ok := NewPlaneNameRow("", false, 1, nil); ok {
		t.Error("an empty literal was given a row")
	}
	c, ok := NewPlaneNameConfig(9, []uint8{0b01, 0b10, 0b11}, agent.EnvSkipDirs)
	if !ok || c.Flags != PlaneNameRowConfig || c.NEntries != 3 || c.NDeps != uint8(len(agent.EnvSkipDirs)) || c.Scopes != 3 {
		t.Fatalf("config %+v", c)
	}
	// The climb reads a directory's name only when its length is a dependency name's.
	var lens uint32
	for _, d := range agent.EnvSkipDirs {
		lens |= 1 << len(d)
	}
	if c.DepLens != lens || c.DepLens&(1<<len("node_modules")) == 0 {
		t.Errorf("dependency lengths %b, want %b", c.DepLens, lens)
	}
	// Scopes is the union of the entries' deny arms, not every bit the rows carry: a D3 exemption's parent bit covers
	// no entry, so D5's place climb need not meet it.
	if d, _ := NewPlaneNameConfig(9, []uint8{0b001, 0b100}, nil); d.Scopes != 0b101 {
		t.Errorf("scopes %03b, want the entries' union 101", d.Scopes)
	}
	if c.Entries != 0b111 || c.BitEntries[0] != 0b101 || c.BitEntries[1] != 0b110 || c.BitEntries[2] != 0 {
		t.Errorf("entries %b, bit entries %b", c.Entries, c.BitEntries)
	}
	var nm [PlaneNameDepLen]byte
	copy(nm[:], "node_modules")
	if c.Dep[1][0] != binary.NativeEndian.Uint64(nm[:8]) || c.Dep[1][1] != binary.NativeEndian.Uint64(nm[8:]) {
		t.Errorf("dependency name words %x, want node_modules", c.Dep[1])
	}
	// D5's climb stops once it met every bit of Scopes: the entries of the bits met, ORed, then hold Entries.
	for m := 0; m < 4; m++ {
		var cov uint64
		for b := 0; b < 2; b++ {
			if m&(1<<b) != 0 {
				cov |= c.BitEntries[b]
			}
		}
		if uint8(m)&c.Scopes == c.Scopes && cov&c.Entries != c.Entries {
			t.Errorf("scope bits %02b meet every bit of %02b but cover %b of %b", m, c.Scopes, cov, c.Entries)
		}
	}
	if _, ok := NewPlaneNameConfig(1, nil, []string{"a-dependency-name-too-long"}); ok {
		t.Error("a dependency name past 16 bytes was taken")
	}
}

// refNameKey is PlaneNameKey spelled bytewise: each eight-byte word assembled in the host's order, zero-padded.
func refNameKey(name string) uint64 {
	little := binary.NativeEndian.Uint16([]byte{1, 0}) == 1
	h := uint64(0xcbf29ce484222325) ^ uint64(len(name))
	for i := 0; i < len(name); i += 8 {
		var w uint64
		for j := 0; j < 8 && i+j < len(name); j++ {
			shift := 8 * j
			if !little {
				shift = 8 * (7 - j)
			}
			w |= uint64(name[i+j]) << shift
		}
		h = (h ^ w) * 0x100000001b3
	}
	return h>>1 | 1
}

// TestPlaneNameKey pins the exec name key decide.bpf.c's tego_name_read computes (the root test
// TestPlaneStepAHooksDecide checks the kernel agrees): never 0 (reserved), never with the top bit a kernel
// address carries, equal to the bytewise reference, and different for names that differ only past a word or in
// length. A name the kernel cannot carry has no key.
func TestPlaneNameKey(t *testing.T) {
	t.Parallel()
	names := []string{"t", "python3", "python3.", "python3.12", "a-name-of-exactly-16", strings.Repeat("x", 255),
		strings.Repeat("x", 254), "\x00", "\x00\x00"}
	seen := map[uint64]string{}
	for _, n := range names {
		k, ok := PlaneNameKey(n)
		if !ok {
			t.Fatalf("%q: no key", n)
		}
		if k == 0 || k>>63 != 0 || k&1 != 1 {
			t.Errorf("%q: key %#x is 0, a kernel-half address or even", n, k)
		}
		if ref := refNameKey(n); k != ref {
			t.Errorf("%q: key %#x, bytewise reference %#x", n, k, ref)
		}
		if other, dup := seen[k]; dup {
			t.Errorf("%q and %q share key %#x", n, other, k)
		}
		seen[k] = n
	}
	for _, bad := range []string{"", strings.Repeat("x", 256)} {
		if _, ok := PlaneNameKey(bad); ok {
			t.Errorf("a key for a %d-byte name", len(bad))
		}
		if _, _, ok := PlaneExecName(bad); ok {
			t.Errorf("PlaneExecName took a %d-byte name", len(bad))
		}
	}
	name, n, ok := PlaneExecName("python3")
	if !ok || n != 7 || string(name[:7]) != "python3" || name[7] != 0 {
		t.Errorf("PlaneExecName(python3) = %q, %d, %v", name[:8], n, ok)
	}
}

// TestPlaneRecordedMask is the record fallback's mask (enforce-plane §7, R23; TIER3-PLAN T9b): each hook a recorder
// fexit wraps is a hook of the plane, its program one of trace_proc's, and its bit PlaneHookNumber of the hook; a
// build with none attached, or no recorder at all, samples every refusal (0), and a program that is no fexit of a
// plane hook sets nothing.
func TestPlaneRecordedMask(t *testing.T) {
	t.Parallel()
	var all uint32
	for hook, prog := range PlaneFexitPrograms {
		n := PlaneHookNumber(hook)
		if n == 0 || n >= 32 {
			t.Fatalf("hook %s has number %d", hook, n)
		}
		if !slices.Contains(TracePrograms, prog) {
			t.Errorf("%s: %s is not one of trace_proc's programs", hook, prog)
		}
		one := PlaneRecordedMask(func(p string) bool { return p == prog })
		if one != 1<<n {
			t.Errorf("%s alone: mask %#x, want %#x", prog, one, uint32(1)<<n)
		}
		all |= one
	}
	if len(PlaneFexitPrograms) != 10 {
		t.Errorf("%d hooks with a recorder fexit, want the ten of steps A and B", len(PlaneFexitPrograms))
	}
	if got := PlaneRecordedMask(func(string) bool { return true }); got != all {
		t.Errorf("every program attached: %#x, want %#x", got, all)
	}
	if PlaneRecordedMask(nil) != 0 || PlaneRecordedMask(func(string) bool { return false }) != 0 {
		t.Error("a build with no recorder fexit attached does not sample every refusal")
	}
	if PlaneRecordedMask(func(p string) bool { return p == ProgSchedExec || p == ProgSocketConnect }) != 0 {
		t.Error("a program that wraps no plane hook set a bit")
	}
	if PlaneHookNumber("bprm_check") != 2 || PlaneHookNumber("nope") != 0 {
		t.Error("PlaneHookNumber is not enum tego_plane_hook")
	}
}
