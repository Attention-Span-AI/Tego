// SPDX-License-Identifier: Apache-2.0

package bpftests

import (
	"math/rand/v2"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// ADR 0043's name entries in the decision plane (NAME-BPF; bpf/decide_names.h): the shape of the kernel half, which
// the guest's TestPlaneNameEntriesDecide holds to behaviour.

var namesPath = filepath.Join(sourceDir, "decide_names.h")

// nameCallers are the hooks that ask the name entries, and how: directly (file_open, path_rename, path_link), or
// through tego_modify_hook with its names argument set (ADR 0043 D1: the hooks that change a file's content or name).
// path_mkdir and path_rmdir call tego_modify_hook with names clear: a name entry never decides a directory.
var (
	// nameGlobals are decide_names.h's global functions, each verified once per program.
	nameGlobals    = []string{"tego_plane_name_check", "tego_plane_climb", "tego_plane_name", "tego_plane_move"}
	nameDirect     = []string{"file_open", "path_link", "path_rename"}
	nameModifyHook = map[string]string{
		"path_unlink": "1", "path_mknod": "1", "path_symlink": "1", "path_truncate": "1", "file_truncate": "1",
		"path_mkdir": "0", "path_rmdir": "0",
	}
)

// TestPlaneClimbIsOutsideTheWalk is ADR 0043 D4's placement: the climb reads directory names (the dependency test),
// so it is its own global function outside the walk's markers, and the walk between them still names no climb and
// reads no name (TestPlaneWalkHasNoStringOps covers the rest).
func TestPlaneClimbIsOutsideTheWalk(t *testing.T) {
	t.Parallel()
	path, _ := planeSource(t)
	raw := readRaw(t, path)
	start := strings.Index(raw, "---- The walk (TEGO_PLANE_WALK")
	end := strings.Index(raw, "---- end of the walk (TEGO_PLANE_WALK_END)")
	if start < 0 || end < start {
		t.Fatal("decide.bpf.c has no walk markers")
	}
	walk := stripComments(raw[start:end])
	for _, banned := range []string{"climb", "tego_plane_name", "tego_dep_dir", "scope"} {
		if strings.Contains(walk, banned) {
			t.Errorf("the walk names %q: the name check's climb lives in decide_names.h, outside the walk", banned)
		}
	}
	names := read(t, namesPath)
	for _, global := range nameGlobals {
		if !regexp.MustCompile(`(?m)^__attribute__\(\(noinline\)\) int ` + global + `\(`).MatchString(names) {
			t.Errorf("%s is not a global noinline function in decide_names.h", global)
		}
	}
	// The climb steps through bpf_loop(TEGO_PLANE_WALK_ITERS, tego_climb_step, ...) at one site, tego_plane_climb's,
	// which sets the state up through tego_climb_setup: a global function verified once per program however many
	// climbs call it. The climb keeps the order it met the scopes in (tego_climb_state.seq), so a refusal's nearest
	// scope takes no climb of its own: tego_plane_name climbs once, and tego_plane_move twice (D5's old place and new
	// place), through tego_plane_climb.
	if strings.Count(names, "bpf_loop(TEGO_PLANE_WALK_ITERS, tego_climb_step,") != 1 ||
		!strings.Contains(functionBody(t, namesPath, "tego_plane_climb"), "bpf_loop(TEGO_PLANE_WALK_ITERS, tego_climb_step, s, 0);") ||
		!strings.Contains(functionBody(t, namesPath, "tego_plane_climb"), "tego_climb_setup(") {
		t.Error("the climb does not step through bpf_loop(TEGO_PLANE_WALK_ITERS, tego_climb_step, s, 0) in tego_plane_climb alone, set up by tego_climb_setup")
	}
	for fn, n := range map[string]int{"tego_plane_name": 1, "tego_plane_move": 2} {
		if c := strings.Count(functionBody(t, namesPath, fn), "tego_plane_climb("); c != n {
			t.Errorf("%s calls tego_plane_climb %d times, want %d", fn, c, n)
		}
	}
	// D5's new place starts at the new name, whose row is not looked up (the inode there after the move is the
	// source's) but whose name takes the dependency test: the climb starts there as at a mountpoint just crossed to.
	if !strings.Contains(functionBody(t, namesPath, "tego_plane_move"), "TEGO_CLIMB_PARAMS(1, TEGO_CLIMB_PLACE) | TEGO_CLIMB_NEW_NAME") ||
		!strings.Contains(functionBody(t, namesPath, "tego_climb_setup"), "s->crossed = cfg->zero ^ ((params >> 16) & 1);") {
		t.Error("D5's new place is not climbed from the new name with its row skipped (TEGO_CLIMB_NEW_NAME)")
	}
	// The name check and the climb are siblings, called one after the other by tego_plane_name: neither calls the
	// other, so a chain holds one frame of theirs (ADR 0043 D9's verifier note: the 512-byte stack).
	if strings.Contains(functionBody(t, namesPath, "tego_plane_name_check"), "tego_plane_climb(") ||
		strings.Contains(functionBody(t, namesPath, "tego_plane_climb"), "tego_plane_name_check(") {
		t.Error("the name check and the climb call each other: their frames would stack in a hook's chain")
	}
	// It is bounded as the walk is: BOUND past TEGO_PLANE_WALK_MAX levels, UNRESOLVED at a dentry with no parent.
	step := functionBody(t, namesPath, "tego_climb_step")
	if !regexp.MustCompile(`if \(s->level > TEGO_PLANE_WALK_MAX\) \{\s*TEGO_CLIMB_END\(s, TEGO_WALK_BOUND\);\s*return 1;`).MatchString(step) {
		t.Error("tego_climb_step does not end BOUND past TEGO_PLANE_WALK_MAX levels")
	}
	if !regexp.MustCompile(`if \(!p \|\| p == d\) \{\s*TEGO_CLIMB_END\(s, TEGO_WALK_UNRESOLVED\);\s*return 1;`).MatchString(step) {
		t.Error("tego_climb_step does not end UNRESOLVED at a dentry with no parent short of a mount root")
	}
	if !strings.Contains(step, "TEGO_CLIMB_END(s, TEGO_WALK_MISMATCH);") {
		t.Error("tego_climb_step does not refuse a row whose identity is gone (ADR 0025 (4))")
	}
	// The walk passes a scope-only row, so the climb's rows decide nothing (decide.PlaneRows.Find).
	if !strings.Contains(functionBody(t, path, "tego_walk_step"), "!(r->kind & TEGO_ROW_SCOPE_ONLY)") {
		t.Error("tego_walk_step does not pass a scope-only row (TEGO_ROW_SCOPE_ONLY)")
	}
}

// TestNameCheckIsGatedByTheHeaderFlag is ADR 0043 D9's cost and fail-closed rule: no hook asks the name entries
// unless the slot header carries TEGO_SLOT_NAME_DECIDES. Every call of a hook helper sits behind tego_names_on(hdr)
// in its condition, which tests the flag; tego_plane_name reads the header again and refuses NOROWS, counted, when
// it is gone, of another gen or without the flag (a cleared slot), before its prefilter reads a name.
func TestNameCheckIsGatedByTheHeaderFlag(t *testing.T) {
	t.Parallel()
	if on := functionBody(t, namesPath, "tego_names_on"); !strings.Contains(on, "return (hdr->flags & TEGO_SLOT_NAME_DECIDES) != 0;") {
		t.Errorf("tego_names_on does not test the header's TEGO_SLOT_NAME_DECIDES:\n%s", on)
	}
	name := functionBody(t, namesPath, "tego_plane_name")
	gate := strings.Index(name, `if (!hdr || hdr->gen != (__u32)run || !(hdr->flags & TEGO_SLOT_NAME_DECIDES))
        return tego_name_failed(run_idx, TEGO_WALK_NOROWS);`)
	if gate < 0 || gate > strings.Index(name, "tego_name_candidate(") || gate > strings.Index(name, "tego_plane_name_check(") {
		t.Error("tego_plane_name does not refuse NOROWS without a header of the run's gen carrying the flag, before it reads a name")
	}
	_, src := planeSource(t)
	for _, call := range []string{"tego_name_check_path(", "tego_name_move_path("} {
		for i := 0; ; {
			j := strings.Index(src[i:], call)
			if j < 0 {
				break
			}
			at := i + j
			i = at + 1
			// The definition itself is not a call.
			if line := src[strings.LastIndex(src[:at], "\n")+1 : at]; strings.Contains(line, "static") || strings.Contains(line, "int ") && !strings.Contains(line, "=") {
				continue
			}
			// The guard sits in the same condition, before the call: the text since the condition's start.
			cond := src[strings.LastIndex(src[:at], "if (")+1 : at]
			if !strings.Contains(cond, "tego_names_on(hdr)") {
				t.Errorf("a call of %s is not behind tego_names_on(hdr) in its condition: %q", call, cond)
			}
		}
	}
}

// TestNameCheckCallersAreTheListedHooks is ADR 0043 D1's hook list: file_open, path_link and path_rename ask the name
// entries directly; path_unlink, path_mknod, path_symlink, path_truncate and file_truncate through tego_modify_hook
// with names set, path_mkdir and path_rmdir with it clear; no other hook asks (bprm_check, step C, the attribute and
// socket hooks never do), and only decide_names.h's hook helpers call the global functions.
func TestNameCheckCallersAreTheListedHooks(t *testing.T) {
	t.Parallel()
	for name, body := range planeBodies(t) {
		direct := strings.Contains(body, "tego_name_check_path(") || strings.Contains(body, "tego_name_move_path(") ||
			strings.Contains(body, "tego_names_on(")
		if direct != slices.Contains(nameDirect, name) {
			t.Errorf("%s: asks the name entries directly %v, want %v", name, direct, slices.Contains(nameDirect, name))
		}
		want, modify := nameModifyHook[name]
		calls := regexp.MustCompile(`tego_modify_hook\([^,]+,[^,]+,\s*run,\s*hdr,\s*([01]),`).FindAllStringSubmatch(body, -1)
		switch {
		case !modify && strings.Contains(body, "tego_modify_hook("):
			t.Errorf("%s calls tego_modify_hook, which no list here expects", name)
		case modify && (len(calls) != 1 || calls[0][1] != want):
			t.Errorf("%s: tego_modify_hook's names argument %v, want one call with %s", name, calls, want)
		}
	}
	if !strings.Contains(functionBody(t, filepath.Join(sourceDir, "decide.bpf.c"), "tego_modify_hook"),
		"names && !tego_is_dir(dentry->d_inode) && tego_names_on(hdr)") {
		t.Error("tego_modify_hook asks names without its names argument, the object's kind and the header's flag")
	}
	// The global functions are reached only through the hook helpers of decide_names.h.
	_, src := planeSource(t)
	for _, global := range nameGlobals {
		n := strings.Count(src, global+"(")
		names := strings.Count(read(t, namesPath), global+"(")
		if n != names {
			t.Errorf("%s is called outside decide_names.h (%d uses, %d there)", global, n, names)
		}
	}
	// D5 is asked of each direction only where that direction moves a directory: an exchange of a file with a
	// directory leaves the file's names to D1, as decide.PlaneEvaluator.rename asks D5 of a directory alone.
	move := functionBody(t, namesPath, "tego_name_move_path")
	if !regexp.MustCompile(`if \(odir\)\s*res = tego_plane_move\(src, sm, dst, dm, runw\);`).MatchString(move) ||
		!regexp.MustCompile(`if \(res == TEGO_NAME_NONE && ndir\)\s*res = tego_plane_move\(dst, dm, src, sm, runw\);`).MatchString(move) {
		t.Errorf("tego_name_move_path asks D5 of a direction that moves no directory:\n%s", move)
	}
	rename := planeBodies(t)["path_rename"]
	for _, want := range []string{"odir = tego_is_dir(old_dentry->d_inode);", "ndir = positive && tego_is_dir(new_dentry->d_inode);",
		"tego_name_move_path(sc, old_dentry, old_dir, odir, new_dentry, new_dir, ndir, run, &nrule)"} {
		if !strings.Contains(rename, want) {
			t.Errorf("path_rename lacks %q: D5's directions are the objects' kinds", want)
		}
	}
	// The objects' kinds are read back through the task's scratch value before the walks, so the verifier walks
	// path_rename's chain once and not once per combination of them (ADR 0043's note: 94 to 104 ms against 32 to 39 on
	// 6.17), and path_link's kind likewise.
	kinds := regexp.MustCompile(`kinds = tego_plane_unknown\(sc, \(__u64\)positive \| \(__u64\)odir << 1 \| \(__u64\)ndir << 2 \|\s*` +
		`\(__u64\)files << 3 \| \(__u64\)dirs << 4\);`)
	if !kinds.MatchString(rename) || strings.Index(rename, "tego_plane_unknown(sc,") > strings.Index(rename, "tego_nearest(") {
		t.Error("path_rename does not read its objects' kinds back through tego_plane_unknown before its walks")
	}
	if !strings.Contains(planeBodies(t)["path_link"], "file = tego_plane_unknown(sc, !tego_is_dir(old_dentry->d_inode)) & 1;") {
		t.Error("path_link does not read its object's kind back through tego_plane_unknown")
	}
	// A hook's chain: tego_name_check_path calls tego_plane_name, which calls the name check and then the climb;
	// tego_name_move_path calls tego_plane_move, which calls the climb. No hook calls a climb or the check itself.
	for helper, global := range map[string]string{"tego_name_check_path": "tego_plane_name(", "tego_name_move_path": "tego_plane_move("} {
		if !strings.Contains(functionBody(t, namesPath, helper), global) {
			t.Errorf("%s does not call %s", helper, global)
		}
	}
}

// TestNameCheckRunsOnlyWhereTheWalkAllows is ADR 0043 D1's "a name entry decides only what the walk allows": in
// every direct caller and in tego_modify_hook, the name check is an else-if arm after the walk's own refusals, so a
// refusal the walk makes keeps its reason and its rule.
func TestNameCheckRunsOnlyWhereTheWalkAllows(t *testing.T) {
	t.Parallel()
	bodies := planeBodies(t)
	bodies["tego_modify_hook"] = functionBody(t, filepath.Join(sourceDir, "decide.bpf.c"), "tego_modify_hook")
	before := map[string][]string{
		"file_open":        {"tego_walk_failed(tego_nearest(", "TEGO_ROW_READ_DENY", "TEGO_ROW_MODIFY_ALLOW"},
		"path_link":        {"tego_walk_failed(tego_nearest(", "!(dkind & TEGO_ROW_MODIFY_ALLOW)"},
		"path_rename":      {"tego_walk_failed(tego_nearest(", "tego_rename_end(skind, sdepth)"},
		"tego_modify_hook": {"tego_walk_failed(tego_nearest(", "!(kind & TEGO_ROW_MODIFY_ALLOW)"},
	}
	for name, walk := range before {
		body := bodies[name]
		at := strings.Index(body, "tego_names_on(hdr)")
		if at < 0 {
			t.Errorf("%s asks no name", name)
			continue
		}
		for _, w := range walk {
			if i := strings.Index(body, w); i < 0 || i > at {
				t.Errorf("%s asks the name before the walk's %q", name, w)
			}
		}
		if !regexp.MustCompile(`else if \([^;]*$`).MatchString(body[:at]) {
			t.Errorf("%s asks the name outside an else-if arm of the walk's verdict", name)
		}
	}
	// path_rename: each end's name after that end's walk refusal, then REFER, then D5 last.
	ren := bodies["path_rename"]
	order := []string{"tego_rename_end(skind, sdepth)", "tego_name_check_path(sc, old_dentry", "tego_rename_end(dkind, ddepth)",
		"tego_name_check_path(sc, new_dentry", "tego_strictness(skind) > tego_strictness(dkind)", "tego_name_move_path("}
	last := -1
	for _, o := range order {
		i := strings.Index(ren, o)
		if i < last {
			t.Errorf("path_rename asks %q out of decide.PlaneEvaluator.rename's order", o)
		}
		last = i
	}
}

// TestNameLookupsFailClosed is ADR 0043 D9's fail-closed rule: a candidate whose slot has no name map, no config row
// or one of another gen is refused NOROWS and counted, never read as no match; the climb refuses a missing rows,
// name or config map; and every failure the name check or D5 returns is counted at the slot.
func TestNameLookupsFailClosed(t *testing.T) {
	t.Parallel()
	cfg := functionBody(t, namesPath, "tego_name_cfg")
	for _, want := range []string{"if (!names)\n        return 0;", "cfg->gen != gen", "!(cfg->flags & TEGO_NAME_ROW_CONFIG)"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("tego_name_cfg lacks %q", want)
		}
	}
	for fn, want := range map[string]string{
		"tego_plane_name_check": `if (!names || !cfg)
        return tego_name_failed(run_idx, TEGO_WALK_NOROWS);`,
		"tego_plane_climb": `if (!rows || !cfg)
        return TEGO_WALK_NOROWS;`,
		"tego_plane_move": `if (!cfg)
        return tego_name_failed(run_idx, TEGO_WALK_NOROWS);`,
	} {
		if !strings.Contains(functionBody(t, namesPath, fn), want) {
			t.Errorf("%s does not refuse NOROWS without the slot's maps or the run's config row:\n%s", fn, want)
		}
	}
	if !regexp.MustCompile(`if \(!cfg \|\| !s->rows\) \{\s*TEGO_CLIMB_END\(s, TEGO_WALK_NOROWS\);\s*return 1;`).MatchString(
		functionBody(t, namesPath, "tego_climb_step")) {
		t.Error("tego_climb_step does not end NOROWS without the slot's rows map or config row")
	}
	failed := functionBody(t, namesPath, "tego_name_failed")
	for res, counter := range map[string]string{"UNRESOLVED": "unresolved", "BOUND": "bound", "MISMATCH": "mismatch", "NOROWS": "norows"} {
		if !regexp.MustCompile(`case TEGO_WALK_` + res + `:\s*TEGO_PLANE_COUNT\(run_idx, ` + counter + `\);`).MatchString(failed) {
			t.Errorf("tego_name_failed does not count TEGO_WALK_%s in %s", res, counter)
		}
	}
	// Every failure that refuses is counted once: the name check's where it returns them; a climb's by its caller,
	// which alone knows whether it decides (tego_plane_name for a name, tego_plane_move for D5).
	check := functionBody(t, namesPath, "tego_plane_name_check")
	if bare := regexp.MustCompile(`return TEGO_WALK_[A-Z]+;`).FindString(check); bare != "" {
		t.Errorf("tego_plane_name_check has %q: a failure leaves it uncounted", bare)
	}
	name := functionBody(t, namesPath, "tego_plane_name")
	firstClimb := strings.Index(name, "tego_plane_climb(")
	for _, r := range regexp.MustCompile(`return ([^;]*);`).FindAllStringSubmatchIndex(name, -1) {
		switch v := name[r[2]:r[3]]; {
		case v == "res" && r[0] < firstClimb:
			// the name check's own answer, counted there
		case v == "TEGO_NAME_NONE", strings.HasPrefix(v, "TEGO_NAME_DENY |"), strings.HasPrefix(v, "tego_name_failed(run_idx, "):
		default:
			t.Errorf("tego_plane_name returns %q: a climb's failure must be counted (tego_name_failed)", v)
		}
	}
	move := functionBody(t, namesPath, "tego_plane_move")
	for _, r := range regexp.MustCompile(`return ([^;]*);`).FindAllStringSubmatch(move, -1) {
		if v := r[1]; v != "TEGO_NAME_NONE" && !strings.HasPrefix(v, "TEGO_NAME_DENY |") && !strings.HasPrefix(v, "tego_name_failed(run_idx, ") {
			t.Errorf("tego_plane_move returns %q: D5's failures must be counted (tego_name_failed)", v)
		}
	}
	// The climb's own state: what its callback changes is a word written whole, every value XORed with the config
	// row's zero, so the verifier knows nothing of it and its passes over the callback converge on every kernel
	// (tego_climb_state's note); a value written otherwise, a constant above all, makes each value a pass of its own.
	step := functionBody(t, namesPath, "tego_climb_step")
	for _, m := range regexp.MustCompile(`s->(result|crossed|met|own|level|seq) = ([^;]*);`).FindAllStringSubmatch(step, -1) {
		if !strings.Contains(m[2], "TEGO_CLIMB_ZERO(s)") {
			t.Errorf("tego_climb_step stores s->%s = %s without the config row's zero", m[1], m[2])
		}
	}
	if !strings.Contains(read(t, namesPath), "#define TEGO_CLIMB_END(s, code) ((s)->result = TEGO_CLIMB_ZERO(s) ^ (code))") {
		t.Error("TEGO_CLIMB_END stores the climb's end without the config row's zero")
	}
	setup := functionBody(t, namesPath, "tego_climb_setup")
	for _, f := range []string{"level", "crossed", "met", "own", "seq", "result"} {
		if !regexp.MustCompile(`s->` + f + ` = cfg->zero\b`).MatchString(setup) {
			t.Errorf("tego_climb_setup seeds s->%s from another value than the config row's zero", f)
		}
	}
	state := regexp.MustCompile(`(?s)struct tego_climb_state \{(.*?)\};`).FindStringSubmatch(read(t, namesPath))
	if state == nil {
		t.Fatal("decide_names.h has no struct tego_climb_state")
	}
	for _, f := range []string{"level", "crossed", "met", "own", "seq", "result"} {
		if !regexp.MustCompile(`__u64 [a-z, ]*\b` + f + `\b`).MatchString(state[1]) {
			t.Errorf("tego_climb_state.%s is not a whole word", f)
		}
	}
	// A hook refuses every failure with tego_walk_failed's reason.
	for name, body := range planeBodies(t) {
		if !slices.Contains(nameDirect, name) {
			continue
		}
		if !strings.Contains(body, "tego_walk_failed(res)") {
			t.Errorf("%s does not refuse a failed name check with tego_walk_failed's reason", name)
		}
	}
}

// TestNameRowsAreEachALookupsOwn holds the name check's five row pointers to values of their own lookups: a key that
// finds no row reads the config row looked up afresh (key 0, which an unused prefix length looks up at once), never
// the caller's cfg pointer, and a second miss refuses NOROWS (D9). A verifier that keeps a map value's id past its
// NULL test (Fedora's 7.2) told the paths apart by which rows aliased cfg, and verified the compare pass once for each
// combination: 65,000 verified instructions in every program that asks names, against 8,700 on 6.17.
func TestNameRowsAreEachALookupsOwn(t *testing.T) {
	t.Parallel()
	row := functionBody(t, namesPath, "tego_name_row")
	if strings.Contains(row, "cfg") {
		t.Errorf("tego_name_row hands out the caller's config row pointer:\n%s", row)
	}
	if !regexp.MustCompile(`r = bpf_map_lookup_elem\(names, &k\);\s*if \(!r\) \{\s*k = 0;\s*r = bpf_map_lookup_elem\(names, &k\);\s*if \(!r\)\s*return 0;\s*\}`).
		MatchString(row) {
		t.Errorf("tego_name_row does not look the config row up afresh on a miss, and NULL when it is gone:\n%s", row)
	}
	check := functionBody(t, namesPath, "tego_plane_name_check")
	if strings.Contains(check, "tego_name_row(names, cfg") || regexp.MustCompile(`s->r[0-4] = tego_name_row\(`).MatchString(check) {
		t.Error("tego_plane_name_check stores a row pointer it has not tested for the config row's absence")
	}
	if n := strings.Count(check, "TEGO_NAME_ROW_AT("); n != 5 {
		t.Errorf("tego_plane_name_check takes %d rows through TEGO_NAME_ROW_AT, want 5 (the exact key and four prefix keys)", n)
	}
	at := regexp.MustCompile(`(?s)#define TEGO_NAME_ROW_AT\(.*?while \(0\)`).FindString(read(t, namesPath))
	if !strings.Contains(at, "if (!r_)") || !strings.Contains(at, "return tego_name_failed(run_idx, TEGO_WALK_NOROWS);") {
		t.Errorf("TEGO_NAME_ROW_AT does not refuse NOROWS when the config row is gone:\n%s", at)
	}
	for j := 1; j <= 4; j++ {
		want := "tego_name_key_of(s->k" + strconv.Itoa(j) + ", 1) & TEGO_ALL(tego_nz(TEGO_PLEN(s, " + strconv.Itoa(j) + ")))"
		if !strings.Contains(check, want) {
			t.Errorf("prefix key %d is not 0 (the config row's key) for an unused prefix length: want %q", j, want)
		}
	}
}

// TestDependencyNameTestReadsOnlyDependencyLengths is ADR 0043 D4's dependency test in the climb (tego_dep_dir): a
// directory's name is read only when its whole length is a dependency name's, tested against the config row's
// TEGO_PLANE_NAME_DEP_LEN before the bit set, never a length taken modulo the set's width: a 48-byte name that
// starts with a 16-byte dependency name then read as that name, and the climb stopped short of the scope (the
// guest's TestPlaneNameEntriesDecide holds the behaviour).
func TestDependencyNameTestReadsOnlyDependencyLengths(t *testing.T) {
	t.Parallel()
	body := functionBody(t, namesPath, "tego_dep_dir")
	guard := strings.Index(body, "len > TEGO_PLANE_NAME_DEP_LEN ||")
	name := strings.Index(body, "TEGO_N_NAME(d,")
	if guard < 0 || name < 0 || guard > name {
		t.Error("tego_dep_dir reads a directory's name before it tests the name's length against TEGO_PLANE_NAME_DEP_LEN")
	}
	if regexp.MustCompile(`len\s*(&|%)`).MatchString(body) {
		t.Error("tego_dep_dir takes the name's length modulo something: a long name can pass for a dependency name")
	}
}

// TestNamePassMasksPastLen is ADR 0043 D2's masking: an inline d_iname keeps stale slab bytes past the name's end, so
// every word of a name the name entries read is masked to the name's length before it is folded, hashed or compared.
// A name's words are read through TEGO_N_RDF (the build's reader with the probe-read build's fault kept,
// TestNameReadsFailClosedOnTheProbeReadBuild); a d_name field (its hash_len, its bytes' address) is read at a CO-RE
// offset, through TEGO_N_HASHLEN and TEGO_N_NAME, and is no name word.
func TestNamePassMasksPastLen(t *testing.T) {
	t.Parallel()
	src := read(t, namesPath)
	reads := regexp.MustCompile(`TEGO_N_RDF\(`).FindAllStringIndex(src, -1)
	if len(reads) == 0 {
		t.Fatal("decide_names.h reads no name word")
	}
	for _, r := range reads {
		if planeMacroLine(src, r[0]) {
			continue // the macros themselves, and the d_name field reads they define
		}
		if window := src[max(0, r[0]-len("tego_name_mask(")):r[0]]; window != "tego_name_mask(" {
			end := strings.Index(src[r[0]:], ";")
			t.Errorf("a name word %s is not masked to the name's length (tego_name_mask)", src[r[0]:r[0]+max(0, end)])
		}
	}
}

// TestNameReadsFailClosedOnTheProbeReadBuild is ADR 0043 D2's failure paths: the rdonly build's loads have no fault
// signal, and on the probe-read build (AL2023's 6.1) a failed bpf_probe_read_kernel of a name's hash_len, of its
// bytes' address or of a word of its bytes refuses path-unresolved, counted, never reads as a name that matches
// nothing: in the prefilter, in the name check's reads and its two passes, and in the climb's dependency test, where
// a dependency directory read as none would make D5's new place covered. Every read of a name goes through the
// fault-keeping reader; the pointer reads (d_parent, d_inode, the mount's fields) fail as the walk's do, into an
// unresolved climb.
func TestNameReadsFailClosedOnTheProbeReadBuild(t *testing.T) {
	t.Parallel()
	src := read(t, namesPath)
	for _, want := range []string{
		"#if TEGO_PLANE_RDONLY\n#define TEGO_N_FAULTS 0\n#define TEGO_N_RDF(addr, flt) TEGO_RD_WORD(addr)\n#else\n#define TEGO_N_FAULTS 1",
		"*flt |= (__u64)bpf_probe_read_kernel(&v, sizeof(v), (void *)addr);",
		"#define TEGO_N_RDF(addr, flt) tego_n_rdf((addr), &(flt))",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("decide_names.h's name reader lacks %q", want)
		}
	}
	// No name word or d_name field is read past the fault-keeping reader: TEGO_RD_WORD appears only in the macros.
	for _, r := range regexp.MustCompile(`TEGO_RD_WORD\(`).FindAllStringIndex(src, -1) {
		if !planeMacroLine(src, r[0]) {
			line := src[strings.LastIndex(src[:r[0]], "\n")+1:]
			t.Errorf("decide_names.h reads past TEGO_N_RDF: %q", strings.TrimSpace(line[:strings.Index(line, "\n")]))
		}
	}
	refuse := "if (s->fault)\n        return tego_name_failed(run_idx, TEGO_WALK_UNRESOLVED);"
	check := functionBody(t, namesPath, "tego_plane_name_check")
	if n := strings.Count(check, refuse); n != 3 {
		t.Errorf("tego_plane_name_check refuses a fault %d times, want 3 (its reads of d_name, the keys' pass, the compare pass)", n)
	}
	if f, l := strings.Index(check, refuse), strings.Index(check, "if (!len || len > TEGO_NAME_MAX - 1)"); f < 0 || l < f {
		t.Error("tego_plane_name_check reads a failed d_name's length as no name before it refuses the fault")
	}
	for _, loop := range []string{"tego_name_keys_step", "tego_name_rows_cmp_step"} {
		after := regexp.MustCompile(`bpf_loop\(TEGO_NAME_WORDS, ` + loop + `, s, 0\);\s*#if TEGO_N_FAULTS\s*` +
			`if \(s->fault\)\s*return tego_name_failed\(run_idx, TEGO_WALK_UNRESOLVED\);`)
		if !after.MatchString(check) {
			t.Errorf("tego_plane_name_check does not refuse a fault right after its bpf_loop over %s", loop)
		}
	}
	name := functionBody(t, namesPath, "tego_plane_name")
	cand, flt, none := strings.Index(name, "cand = tego_name_candidate(hdr, d, &flt);"),
		strings.Index(name, "if (flt)"), strings.Index(name, "if (!cand)")
	if cand < 0 || flt < cand || none < flt ||
		!strings.Contains(name[flt:none], "return tego_name_failed(run_idx, TEGO_WALK_UNRESOLVED);") {
		t.Error("tego_plane_name does not refuse a prefilter whose name could not be read before it reads it as no candidate")
	}
	if !strings.Contains(functionBody(t, namesPath, "tego_name_candidate"), "TEGO_N_RDF(TEGO_N_NAME(d, *flt), *flt)") {
		t.Error("the prefilter does not read the name's first word through the fault-keeping reader")
	}
	if !strings.Contains(functionBody(t, namesPath, "tego_climb_step"), "tego_dep_dir(d, cfg, &s->fault)") {
		t.Error("the climb's dependency test does not keep its faults in the climb's state")
	}
	climb := functionBody(t, namesPath, "tego_plane_climb")
	loop := strings.Index(climb, "bpf_loop(TEGO_PLANE_WALK_ITERS, tego_climb_step, s, 0);")
	if fault := strings.Index(climb, "if (s->fault)\n        return TEGO_WALK_UNRESOLVED;"); loop < 0 || fault < loop {
		t.Error("tego_plane_climb does not end a climb whose dependency test faulted UNRESOLVED")
	}
	// The fault words are seeded from the config row's zero, as every word the climb's callback changes is.
	if !strings.Contains(functionBody(t, namesPath, "tego_climb_setup"), "#if TEGO_N_FAULTS\n    s->fault = cfg->zero;\n#endif") {
		t.Error("tego_climb_setup does not seed the climb's fault word from the config row's zero")
	}
}

// TestExecNamePassIsUnchanged is ADR 0043 F10: the exec rows' name passes compare bytes exactly (enforce-plane R9),
// so the name entries' folding never reaches them: plane_name.h's exec functions call no fold, and the folded pass is
// the name entries' own.
func TestExecNamePassIsUnchanged(t *testing.T) {
	t.Parallel()
	path := filepath.Join(sourceDir, "include", "plane_name.h")
	for _, fn := range []string{"tego_name_word", "tego_name_hash_step", "tego_name_cmp_step", "tego_name_key", "tego_name_eq"} {
		body := functionBody(t, path, fn)
		for _, banned := range []string{"tego_fold_word", "tego_upper_bits", "TEGO_WORD_BYTE"} {
			if strings.Contains(body, banned) {
				t.Errorf("the exec pass %s calls %s: exec rows compare names byte for byte", fn, banned)
			}
		}
	}
	if !strings.Contains(functionBody(t, path, "tego_name_cmp_step"), "const struct tego_plane_exec_row *r = p->r;") {
		t.Error("the exec compare no longer reads an exec row")
	}
}

// TestNameKeyConstantsMatchGo pins the kernel's name key to agent.NameKey's: FNV-1a's basis and prime, the length
// mixed into the basis, bit 63 cleared, bit 62 the form, and 0 (the config row's key) replaced by 1.
func TestNameKeyConstantsMatchGo(t *testing.T) {
	t.Parallel()
	src := read(t, namesPath)
	for _, want := range []string{"#define TEGO_FNV_BASIS 0xcbf29ce484222325ULL", "#define TEGO_FNV_PRIME 0x100000001b3ULL",
		"s->k0 = TEGO_FNV_BASIS ^ len;", "s->k1 = TEGO_FNV_BASIS ^ TEGO_PLEN(s, 1);"} {
		if !strings.Contains(src, want) {
			t.Errorf("decide_names.h lacks %q", want)
		}
	}
	key := functionBody(t, namesPath, "tego_name_key_of")
	for _, want := range []string{"h = (h & ~(3ULL << 62)) | prefix << 62;", "return h | (tego_nz(h) ^ 1);"} {
		if !strings.Contains(key, want) {
			t.Errorf("tego_name_key_of lacks %q (agent.NameKey's last step)", want)
		}
	}
	if got, ok := agent.NameKey(".env", false); !ok || got&(1<<63) != 0 || got&(1<<62) != 0 {
		t.Errorf("agent.NameKey(.env) = %#x: an exact key keeps bits 63 and 62 clear", got)
	}
}

// TestFoldWordMatchesFoldByte runs plane_name.h's SWAR fold, with the constants read from the source, over every
// byte value at every position of a word among random neighbours, against agent.FoldByte: a capital A-Z is lowered,
// every other byte (bit 7 set included) is kept, and no byte's result depends on another's.
func TestFoldWordMatchesFoldByte(t *testing.T) {
	t.Parallel()
	body := functionBody(t, filepath.Join(sourceDir, "include", "plane_name.h"), "tego_upper_bits")
	consts := regexp.MustCompile(`0x([0-9a-f]{16})ULL`).FindAllStringSubmatch(body, -1)
	if len(consts) != 4 {
		t.Fatalf("tego_upper_bits has %d 64-bit constants, want 4 (heptets, >= 'A', > 'Z', the high bits)", len(consts))
	}
	var c [4]uint64
	for i, m := range consts {
		v, err := strconv.ParseUint(m[1], 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		c[i] = v
	}
	fold := func(w uint64) uint64 {
		hept := w & c[0]
		up := ((hept + c[1]) ^ (hept + c[2])) &^ w & c[3]
		return w | up>>2
	}
	r := rand.New(rand.NewPCG(1, 2))
	for pos := 0; pos < 8; pos++ {
		for b := 0; b < 256; b++ {
			for trial := 0; trial < 4; trial++ {
				w := r.Uint64()
				w = w&^(0xff<<(8*pos)) | uint64(b)<<(8*pos)
				got := fold(w)
				for k := 0; k < 8; k++ {
					in, out := byte(w>>(8*k)), byte(got>>(8*k))
					if out != agent.FoldByte(in) {
						t.Fatalf("fold(%#016x) byte %d: %#02x -> %#02x, want %#02x", w, k, in, out, agent.FoldByte(in))
					}
				}
			}
		}
	}
}

// TestNameKeysPassMatchesNameKeyInBothOrders transcribes decide_names.h's keys pass into Go, for a kernel of each
// byte order (the plane is built bpfel and bpfeb): each word loaded from the name's memory in that order, stale bytes
// past the name's end included, masked to the name's length (tego_name_mask, its shift built from c * 8 - 1),
// folded (tego_upper_bits), its last capital found (tego_marks_end), and folded into the exact key and each prefix
// key that reaches it (TEGO_PREFIX_STEP), then finished (tego_name_key_of). The keys must be agent.NameKeyIn's of
// the folded name and of its folded prefixes in that order, the key userspace writes on a host of that order; the
// last capital's end must be one past the last 'A' to 'Z'. The guest's TestPlaneNameEntriesDecide holds the
// compiled little-endian pass to the same keys; no big-endian kernel boots here, so this is that order's check.
func TestNameKeysPassMatchesNameKeyInBothOrders(t *testing.T) {
	t.Parallel()
	src := read(t, namesPath)
	for _, want := range []string{
		"__u64 c = n - ((n - 8) & TEGO_ALL(tego_lt(8, n))), sh = c * 8 - 1;",
		"return w & ~((~0ULL << sh) << 1);", "return w & ~((~0ULL >> sh) >> 1);",
		"x |= x >> 8;", "x |= x << 8;", "return (x * 0x0101010101010101ULL) >> 56;",
		"h = (h & ~(3ULL << 62)) | prefix << 62;",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("decide_names.h no longer has %q: transcribe the change here", want)
		}
	}
	lt := func(a, b uint64) uint64 { return (a - b) >> 63 }
	for _, big := range []bool{false, true} {
		load := func(mem []byte, at int) uint64 {
			var w uint64
			for j := 0; j < 8; j++ {
				shift := 8 * j
				if big {
					shift = 8 * (7 - j)
				}
				w |= uint64(mem[at+j]) << shift
			}
			return w
		}
		mask := func(w, n uint64) uint64 { // n >= 1
			c := n - ((n - 8) & -lt(8, n))
			sh := c*8 - 1
			if big {
				return w &^ ((^uint64(0) >> sh) >> 1)
			}
			return w &^ ((^uint64(0) << sh) << 1)
		}
		upper := func(w uint64) uint64 {
			hept := w & 0x7f7f7f7f7f7f7f7f
			return ((hept + 0x3f3f3f3f3f3f3f3f) ^ (hept + 0x2525252525252525)) &^ w & 0x8080808080808080
		}
		marksEnd := func(up uint64) uint64 {
			x := up >> 7
			if big {
				x |= x << 8
				x |= x << 16
				x |= x << 32
			} else {
				x |= x >> 8
				x |= x >> 16
				x |= x >> 32
			}
			return (x * 0x0101010101010101) >> 56
		}
		keyOf := func(h, prefix uint64) uint64 {
			h = h&^(3<<62) | prefix<<62
			if h == 0 {
				h = 1
			}
			return h
		}
		r := rand.New(rand.NewPCG(7, uint64(len(src))))
		const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-~#\x80\xc3\xa9"
		for trial := 0; trial < 3000; trial++ {
			n := 1 + r.IntN(255)
			if trial < 40 {
				n = 1 + trial%12
			}
			name := make([]byte, n)
			for i := range name {
				name[i] = letters[r.IntN(len(letters))]
			}
			mem := make([]byte, (n+7)/8*8)
			copy(mem, name)
			for i := n; i < len(mem); i++ {
				mem[i] = byte(r.Uint32()) | 1 // d_iname's stale bytes past the NUL
			}
			plens := []uint64{uint64(1 + r.IntN(n)), uint64(1 + r.IntN(n)), uint64(1 + r.IntN(n)), uint64(1 + r.IntN(n))}
			k := [5]uint64{0xcbf29ce484222325 ^ uint64(n)}
			for j, p := range plens {
				k[j+1] = 0xcbf29ce484222325 ^ p
			}
			var upperEnd uint64
			for at := uint64(0); at < uint64(len(mem)); at += 8 {
				w := mask(load(mem, int(at)), uint64(n)-at)
				up := upper(w)
				f := w | up>>2
				if end := marksEnd(up); end != 0 {
					upperEnd = at + end
				}
				k[0] = (k[0] ^ f) * 0x100000001b3
				for j, p := range plens {
					if lt(at, p) == 1 {
						k[j+1] = (k[j+1] ^ mask(f, p-at)) * 0x100000001b3
					}
				}
			}
			folded := agent.FoldName(string(name))
			if want, _ := agent.NameKeyIn(folded, false, big); keyOf(k[0], 0) != want {
				t.Fatalf("big-endian %v: the exact key of %q is %#x, agent.NameKeyIn's %#x", big, name, keyOf(k[0], 0), want)
			}
			for j, p := range plens {
				if want, _ := agent.NameKeyIn(folded[:p], true, big); keyOf(k[j+1], 1) != want {
					t.Fatalf("big-endian %v: the %d-byte prefix key of %q is %#x, agent.NameKeyIn's %#x", big, p, name,
						keyOf(k[j+1], 1), want)
				}
			}
			var wantEnd uint64
			for i, b := range name {
				if b >= 'A' && b <= 'Z' {
					wantEnd = uint64(i + 1)
				}
			}
			if upperEnd != wantEnd {
				t.Fatalf("big-endian %v: %q's last capital ends at %d, want %d", big, name, upperEnd, wantEnd)
			}
		}
	}
}

// planeMacroLine reports whether offset at of src lies in a #define, its continuation lines included.
func planeMacroLine(src string, at int) bool {
	start := strings.LastIndex(src[:at], "\n") + 1
	for {
		if strings.HasPrefix(strings.TrimSpace(src[start:at]), "#define") {
			return true
		}
		if start == 0 {
			return false
		}
		prev := strings.LastIndex(src[:start-1], "\n") + 1
		if !strings.HasSuffix(strings.TrimRight(src[prev:start-1], " \t"), "\\") {
			return false
		}
		start, at = prev, start-1
	}
}
