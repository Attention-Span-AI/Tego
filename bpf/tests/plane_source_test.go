// SPDX-License-Identifier: Apache-2.0

package bpftests

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
)

// The decision plane, bpf/decide.bpf.c (ADRs 0024, 0025; docs/p0/TIER3-PLAN.md §3). Its programs are emitted by the
// TEGO_PLANE_HOOK macro, which programs() cannot see (no literal SEC line), so these tests read the invocations.

var (
	planeHookRe = regexp.MustCompile(`(?m)^TEGO_PLANE_HOOK\(\s*([a-z_]+)\s*,\s*([a-z_]+)\s*,\s*([a-z_]+)\s*,`)
	returnRe    = regexp.MustCompile(`return\s+([^;]*);`)
)

// planeSource returns decide.bpf.c's path and the plane's whole source: decide.bpf.c and the step files it
// includes (decide_stepb.h, decide_stepc.h), comments stripped, in include order.
func planeSource(t *testing.T) (path, src string) {
	t.Helper()
	path = filepath.Join(sourceDir, "decide.bpf.c")
	src = read(t, path)
	for _, m := range regexp.MustCompile(`(?m)^#include "(decide_[a-z0-9_]+\.h)"`).FindAllStringSubmatch(src, -1) {
		src += "\n" + read(t, filepath.Join(sourceDir, m[1]))
	}
	return path, src
}

// stepBPath is the file step B's bodies and helpers are in.
var stepBPath = filepath.Join(sourceDir, "decide_stepb.h")

// socketAllowPath is ADR 0018 (1)'s allowlist, shared by the plane's socket_create and cgroup/sock_create.
var socketAllowPath = filepath.Join(sourceDir, "include", "socket_allow.h")

// planeFexitHooks are the plane hooks a recorder fexit in trace_proc.bpf.c wraps (ADR 0024 (11)): the fexit takes
// the plane's decision, so the plane writes no sample of its own there, except through tego_plane_fallback where the
// build's fexit is not attached (T9b). On every other hook the plane's own sample is the refused action's one line
// (enforce-plane R23).
var planeFexitHooks = map[string]string{
	"file_open": "tego_file_open", "path_unlink": "tego_path_unlink", "path_rmdir": "tego_path_rmdir",
	"path_rename": "tego_path_rename", "path_link": "tego_path_link", "path_mknod": "tego_path_mknod",
	"path_mkdir": "tego_path_mkdir", "path_symlink": "tego_path_symlink", "path_truncate": "tego_path_truncate",
	"file_truncate": "tego_file_truncate",
}

// balanced returns src from its first '{' to the matching '}'.
func balanced(t *testing.T, src, what string) string {
	t.Helper()
	open := strings.Index(src, "{")
	if open < 0 {
		t.Fatalf("%s has no body", what)
	}
	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[open : i+1]
			}
		}
	}
	t.Fatalf("%s is unbalanced", what)
	return ""
}

// macroDefinition returns the text of one #define, continuation lines joined.
func macroDefinition(t *testing.T, src, name string) string {
	t.Helper()
	i := strings.Index(src, "#define "+name+"(")
	if i < 0 {
		t.Fatalf("no #define %s", name)
	}
	var out strings.Builder
	for _, line := range strings.Split(src[i:], "\n") {
		out.WriteString(strings.TrimSuffix(strings.TrimRight(line, " \t"), "\\"))
		out.WriteByte('\n')
		if !strings.HasSuffix(strings.TrimRight(line, " \t"), "\\") {
			break
		}
	}
	return out.String()
}

// TestPlaneHooksHaveBothSections is ADR 0024 (1): every plane hook exists in both modes from one body. The macro
// emits exactly one SEC("lsm/...") and one SEC("fmod_ret/...") around the body, every hook in
// internal/bpf.PlaneHooks is invoked through it with the same hook and security_ function, and no source declares
// an lsm or fmod_ret program any other way, which would be a hook in one mode only.
func TestPlaneHooksHaveBothSections(t *testing.T) {
	t.Parallel()
	_, src := planeSource(t)
	def := macroDefinition(t, src, "TEGO_PLANE_HOOK")
	if strings.Count(def, `SEC("lsm/" #lsm_hook)`) != 1 || strings.Count(def, `SEC("fmod_ret/" #security_fn)`) != 1 ||
		strings.Count(def, "SEC(") != 2 {
		t.Fatalf("TEGO_PLANE_HOOK does not emit exactly one lsm and one fmod_ret section:\n%s", def)
	}
	if strings.Count(def, "tego_decide_##name(TEGO_PLANE_LSM,") != 1 ||
		strings.Count(def, "tego_decide_##name(TEGO_PLANE_FMOD_RET,") != 1 {
		t.Errorf("the two programs do not both call the one body, once each with their own mode")
	}
	var got, want []ebpfbindings.PlaneHook
	for _, m := range planeHookRe.FindAllStringSubmatch(src, -1) {
		got = append(got, ebpfbindings.PlaneHook{Name: m[1], LSM: m[2], Security: m[3]})
	}
	for _, h := range ebpfbindings.PlaneHooks {
		want = append(want, ebpfbindings.PlaneHook{Name: h.Name, LSM: h.LSM, Security: h.Security})
	}
	slices.SortFunc(got, func(a, b ebpfbindings.PlaneHook) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(want, func(a, b ebpfbindings.PlaneHook) int { return strings.Compare(a.Name, b.Name) })
	if !slices.Equal(got, want) {
		t.Fatalf("decide.bpf.c's hooks are %v, internal/bpf.PlaneHooks says %v", got, want)
	}
	for _, h := range got {
		if !strings.HasPrefix(h.Security, "security_") {
			t.Errorf("%s: fmod_ret target %q is not a security_ function", h.Name, h.Security)
		}
	}
	for _, path := range sources(t) {
		for _, p := range programs(t, path) {
			if strings.HasPrefix(p.section, "lsm") || strings.HasPrefix(p.section, "fmod_ret") {
				t.Errorf("%s: %s declares SEC(%q) outside TEGO_PLANE_HOOK, so it has no program in the other mode",
					p.file, p.name, p.section)
			}
		}
	}
}

// TestPlanePrivateExitsTestTheWrappersInode is enforce-plane R4: each fmod_ret program returns 0 where its
// security_* wrapper does, on IS_PRIVATE of the same inode the wrapper tests, so fmod_ret mode neither decides an
// action the chain skips nor skips one the chain decides.
func TestPlanePrivateExitsTestTheWrappersInode(t *testing.T) {
	t.Parallel()
	bodies := planeBodies(t)
	// Each wrapper's IS_PRIVATE operand (security/security.c): the directory for the entry ops, the old name for
	// rename and link, the path's object for the path ops, the dentry for the inode ops.
	privateOperand := map[string]string{
		"path_rename": "old_dentry", "path_link": "old_dentry",
		"path_unlink": "dir->dentry", "path_rmdir": "dir->dentry", "path_mknod": "dir->dentry",
		"path_mkdir": "dir->dentry", "path_symlink": "dir->dentry",
		"path_truncate": "path->dentry", "path_chmod": "path->dentry", "path_chown": "path->dentry",
		"inode_setxattr": "dentry", "inode_removexattr": "dentry", "inode_set_acl": "dentry", "inode_remove_acl": "dentry",
	}
	exitRe := regexp.MustCompile(`mode == TEGO_PLANE_FMOD_RET && \(?tego_is_private\(([^)]*)\)`)
	for h, want := range privateOperand {
		m := exitRe.FindStringSubmatch(bodies[h])
		if m == nil {
			t.Errorf("%s: fmod_ret mode does not reproduce security_%s's IS_PRIVATE exit", h, h)
			continue
		}
		if m[1] != want {
			t.Errorf("%s: fmod_ret mode tests IS_PRIVATE on %s, security_%s on %s", h, m[1], h, want)
		}
	}
}

// TestPlaneReturnsOnlyZeroOrEACCES is ADR 0024 (7) and enforce-plane.md R2 (and its I2 in §8): a plane program returns 0 or -EACCES and nothing else. Both
// programs of the macro return tego_plane_verdict of the body, which maps anything but 0 to -EACCES (an LSM
// program returning a global function's int unchanged is refused, T0), and each body returns only 0 or -EACCES
// itself, so the mapping is a guard, not a translation of other errnos.
func TestPlaneReturnsOnlyZeroOrEACCES(t *testing.T) {
	t.Parallel()
	path, src := planeSource(t)
	verdict := functionBody(t, path, "tego_plane_verdict")
	if rets := returnRe.FindAllStringSubmatch(verdict, -1); len(rets) != 1 ||
		strings.TrimSpace(rets[0][1]) != "decision == 0 ? 0 : -EACCES" {
		t.Errorf("tego_plane_verdict is %s; it must return decision == 0 ? 0 : -EACCES and nothing else", verdict)
	}
	def := macroDefinition(t, src, "TEGO_PLANE_HOOK")
	rets := returnRe.FindAllStringSubmatch(def, -1)
	if len(rets) != 2 {
		t.Fatalf("TEGO_PLANE_HOOK has %d returns, want the two programs' own", len(rets))
	}
	for _, m := range rets {
		if !strings.HasPrefix(strings.TrimSpace(m[1]), "tego_plane_verdict(tego_decide_##name(") {
			t.Errorf("a plane program returns %q, not tego_plane_verdict of its body", m[1])
		}
	}
	idx := planeHookRe.FindAllStringIndex(src, -1)
	if len(idx) == 0 {
		t.Fatal("no TEGO_PLANE_HOOK invocations")
	}
	for _, loc := range idx {
		// The body follows the invocation's closing parenthesis; balanced finds its braces.
		name := planeHookRe.FindStringSubmatch(src[loc[0]:])[1]
		body := balanced(t, src[loc[0]:], name)
		assertPlaneReturnContract(t, name, body, src, map[string]bool{})
	}
}

// assertPlaneReturnContract follows only the plane's explicit refusal helpers,
// checking their returns too. A new helper cannot silently become a third errno.
func assertPlaneReturnContract(t *testing.T, name, body, src string, seen map[string]bool) {
	t.Helper()
	if seen[name] {
		return
	}
	seen[name] = true
	for _, m := range returnRe.FindAllStringSubmatch(body, -1) {
		e := strings.TrimSpace(m[1])
		if e == "0" || e == "-EACCES" || regexp.MustCompile(`^[a-z_]+\s*\?\s*-EACCES\s*:\s*0$`).MatchString(e) {
			continue
		}
		found := false
		for _, helper := range []string{"tego_control_refuse", "tego_ptrace_peer", "tego_listen_refuse", "tego_mknod_bind"} {
			if strings.HasPrefix(e, helper+"(") {
				assertPlaneReturnContract(t, helper, helperBody(t, src, helper), src, seen)
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s returns %q; a plane body returns 0 or -EACCES only", name, e)
		}
	}
}

// planeRunModeGuard accepts a separate immediate null/mode pair or one short-
// circuit guard. Its end is the first point where policy maps may be read.
func planeRunModeGuard(body string) []int {
	if loc := regexp.MustCompile(`if \(!run \|\| run->plane != TEGO_PLANE_RUN_MODE\(mode\)[^\n]*\)\s*return 0;`).FindStringIndex(body); loc != nil {
		return loc
	}
	return regexp.MustCompile(`if \(!run\)\s*return 0;\s*if \(run->plane != TEGO_PLANE_RUN_MODE\(mode\)\)\s*return 0;`).FindStringIndex(body)
}

// TestPlaneWalkHasNoStringOps is TIER3-PLAN §3: the walk matches by inode keys, never by path strings, so it reads
// no name, copies no string and calls no bpf_d_path (unavailable to path_* hooks below 6.8). It also stays form d
// of ADR 0024's T0 note: a global (non-static, noinline) function stepping through bpf_loop, with no loop of its own.
func TestPlaneWalkHasNoStringOps(t *testing.T) {
	t.Parallel()
	path, _ := planeSource(t)
	raw := readRaw(t, path)
	start := strings.Index(raw, "---- The walk (TEGO_PLANE_WALK")
	end := strings.Index(raw, "---- end of the walk (TEGO_PLANE_WALK_END)")
	if start < 0 || end < start {
		t.Fatal("decide.bpf.c has no walk markers; the walk must sit between them")
	}
	// Both markers sit inside comments: start at the first one's opening, end before the second's.
	start = strings.LastIndex(raw[:start], "/*")
	end = strings.LastIndex(raw[:end], "/*")
	walk := stripComments(raw[start:end])
	for _, banned := range []string{
		"bpf_d_path", "_str(", "bpf_strncmp", "bpf_strtol", "bpf_strtoul", "strcmp", "strncmp", "strlen",
		"memcmp", "__builtin_mem", "d_name", "d_iname", "char ", "bpf_snprintf",
	} {
		if strings.Contains(walk, banned) {
			t.Errorf("the walk uses %q; it keys on inode pointers only, never on a name", banned)
		}
	}
	if regexp.MustCompile(`\bfor\s*\(|#pragma|goto\s`).MatchString(walk) {
		t.Error("the walk has a loop of its own; it steps through bpf_loop only")
	}
	for _, loop := range whileRe.FindAllString(walk, -1) {
		if !whileZeroRe.MatchString(loop) {
			t.Errorf("the walk has its own loop (%q); it steps through bpf_loop only", loop)
		}
	}
	if !regexp.MustCompile(`(?m)^__attribute__\(\(noinline\)\) int tego_plane_walk\(`).MatchString(walk) {
		t.Error("tego_plane_walk is not a global noinline function (form d)")
	}
	// The object and TEGO_PLANE_WALK_MAX levels above it, with an iteration to spare for a mount crossing above
	// each: decide.PlaneRows.Find looks at steps 0..MaxWalk, and a crossing is no step.
	if strings.Count(walk, "bpf_loop(TEGO_PLANE_WALK_ITERS, tego_walk_step,") != 1 {
		t.Error("the walk does not step through one bpf_loop(TEGO_PLANE_WALK_ITERS, tego_walk_step, ...)")
	}
	events := read(t, filepath.Join(sourceDir, "include", "events.h"))
	if !strings.Contains(events, "#define TEGO_PLANE_WALK_ITERS (2 * (TEGO_PLANE_WALK_MAX + 1))") {
		t.Error("TEGO_PLANE_WALK_ITERS is not a lookup and a mount crossing at each of the WALK_MAX + 1 levels")
	}
}

// TestPlaneWalkFailsClosed is enforce-plane R7's refusals, which no kernel cell reaches for a disconnected dentry:
// a walk that ends neither at a row nor at the root is refused path-unresolved and counted. It pins every link of
// that chain, any one of which, changed, turns a deep or disconnected path into an unmatched allow: the result
// enum's order (ROOT and HIT below UNRESOLVED, every refusal at or above it), the walk's BOUND until a step ends it,
// the step's UNRESOLVED at a dentry with no parent and BOUND past TEGO_PLANE_WALK_MAX levels, the walk's count of
// each, and tego_walk_failed's threshold.
func TestPlaneWalkFailsClosed(t *testing.T) {
	t.Parallel()
	path, _ := planeSource(t)
	events := read(t, filepath.Join(sourceDir, "include", "events.h"))
	enum := regexp.MustCompile(`enum tego_plane_walk_result \{([^}]*)\}`).FindStringSubmatch(events)
	if enum == nil {
		t.Fatal("events.h has no enum tego_plane_walk_result")
	}
	want := map[string]string{"ROOT": "0", "HIT": "1", "UNRESOLVED": "2", "BOUND": "3", "MISMATCH": "4", "NOROWS": "5"}
	got := map[string]string{}
	for _, m := range regexp.MustCompile(`TEGO_WALK_([A-Z]+)\s*=\s*(\d+)`).FindAllStringSubmatch(enum[1], -1) {
		got[m[1]] = m[2]
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("TEGO_WALK_%s = %q, want %s: tego_walk_failed refuses every result from UNRESOLVED up", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("enum tego_plane_walk_result has %v, want exactly %v", got, want)
	}

	walk := functionBody(t, path, "tego_plane_walk")
	init := strings.Index(walk, "s.result = TEGO_WALK_BOUND;")
	loop := strings.Index(walk, "bpf_loop(")
	if init < 0 || loop < init {
		t.Error("tego_plane_walk does not start its result at TEGO_WALK_BOUND before the loop")
	}
	for res, counter := range map[string]string{"UNRESOLVED": "unresolved", "BOUND": "bound", "MISMATCH": "mismatch"} {
		c := regexp.MustCompile(`case TEGO_WALK_` + res + `:\s*TEGO_PLANE_COUNT\(run_idx, ` + counter + `\);\s*break;`)
		if !c.MatchString(walk) {
			t.Errorf("tego_plane_walk does not count TEGO_WALK_%s in %s", res, counter)
		}
	}
	if !strings.Contains(walk, "return s.result;") {
		t.Error("tego_plane_walk does not return the step's result")
	}
	// A verifier before 6.8 ("verify callbacks as if they are called unknown number of times"; AL2023's 6.1) verifies
	// a bpf_loop callback once, from its first call's state: a counter that starts at a constant 0 there makes the
	// step's BOUND branch dead, hard-wired away, and a walk 65 levels deep meets a row the kernel must not reach.
	// So the counters start from the caller's zeroed hit, memory a global function's verifier knows nothing of.
	for _, want := range []string{"s.steps = hit->depth;", "s.crossed = (__u8)hit->depth;"} {
		if !strings.Contains(walk, want) {
			t.Errorf("tego_plane_walk lacks %q: its step counters start from a constant the 6.1 verifier folds", want)
		}
	}

	step := functionBody(t, path, "tego_walk_step")
	if !regexp.MustCompile(`if \(!p \|\| p == d\) \{\s*s->result = TEGO_WALK_UNRESOLVED;\s*return 1;`).MatchString(step) {
		t.Error("tego_walk_step does not end UNRESOLVED at a dentry with no parent short of a mount root")
	}
	if !regexp.MustCompile(`if \(s->steps > TEGO_PLANE_WALK_MAX\) \{\s*s->result = TEGO_WALK_BOUND;\s*return 1;`).MatchString(step) {
		t.Error("tego_walk_step does not end BOUND past TEGO_PLANE_WALK_MAX levels")
	}

	failed := functionBody(t, path, "tego_walk_failed")
	if !regexp.MustCompile(`if \(res < TEGO_WALK_UNRESOLVED\)\s*return 0;`).MatchString(failed) ||
		!strings.Contains(failed, "TEGO_R_PATH_UNRESOLVED") {
		t.Error("tego_walk_failed does not refuse every result from TEGO_WALK_UNRESOLVED up")
	}
}

// planeBodies returns each TEGO_PLANE_HOOK body by hook name, comments stripped.
func planeBodies(t *testing.T) map[string]string {
	t.Helper()
	_, src := planeSource(t)
	out := map[string]string{}
	for _, loc := range planeHookRe.FindAllStringIndex(src, -1) {
		name := planeHookRe.FindStringSubmatch(src[loc[0]:])[1]
		out[name] = balanced(t, src[loc[0]:], name)
	}
	return out
}

// planeRunLookup is the run-set lookup a hook's body starts with: the caller's cgroup (step B's socket_create too:
// the caller creates the socket), or for step D's unix hooks
// the socket's (enforce-plane R14), since the supervisor relays every unix connect of the agent from its own cgroup
// on a duplicate of the agent's socket, as cgroup/connect_unix keys the run by the attachment the socket's cgroup
// reaches (enforce-cgroup-observe §5 R1).
func planeRunLookup(hook string) string {
	if hook == "socket_listen" {
		return "tego_listen_sock_run(sock)"
	}
	if hook == "socket_bind" {
		return "tego_current_run(&tego_run_set)"
	}
	if planeUnixHook(hook) {
		return "tego_unix_sock_run(&tego_run_set, sock)"
	}
	return "tego_current_run(&tego_run_set)"
}

// TestPlaneHooksLookTheRunUpFirst is enforce-plane R1 (I1): every body's first act is the run-set lookup, and a
// miss returns 0 before policy rows or record buffers are touched. Socket identity
// can supply the run for supervisor relays; original bind/listen prefer the task.
func TestPlaneHooksLookTheRunUpFirst(t *testing.T) {
	t.Parallel()
	for name, body := range planeBodies(t) {
		want := planeRunLookup(name)
		lookup := strings.Index(body, want)
		guard := planeRunModeGuard(body)
		if lookup < 0 || guard == nil || guard[0] < lookup {
			t.Errorf("%s: no run-set lookup followed by null/own-mode refusal", name)
			continue
		}
		between := body[lookup+len(want) : guard[0]]
		if name == "socket_bind" {
			if !strings.Contains(between, "if (!run)\n        run = tego_unix_sock_run(&tego_run_set, sock);") {
				t.Error("socket_bind lost original-task priority or outside-relay socket fallback")
			}
			between = strings.ReplaceAll(between, "tego_unix_sock_run(&tego_run_set, sock)", "socket_identity")
			between = strings.ReplaceAll(between, "if (!run)", "")
		}
		if name == "socket_listen" {
			// This fresh hook pointer load has its own null proof later. It
			// reads socket identity, not policy, before the own-mode guard.
			between = strings.ReplaceAll(between, "struct sock *sk = sock->sk;", "")
		}
		if call := regexp.MustCompile(`\b[a-z_][a-z0-9_]*\s*\(|->`).FindString(between); call != "" {
			t.Errorf("%s: %q between the run-set lookup and its miss", name, call)
		}
		// Step C's bodies return 0 before the lookup for no file or no PROT_EXEC (ADR 0027), which
		// TestPlaneMapHooksReturnBeforeTheRunLookup holds.
		if _, early := planeMapHooks[name]; early {
			continue
		}
		if name != "socket_bind" && strings.Contains(body[:lookup], "(") && regexp.MustCompile(`\b[a-z_][a-z0-9_]*\s*\(`).MatchString(body[:lookup]) {
			t.Errorf("%s: a call before the run-set lookup", name)
		}
	}
}

// TestPlaneEveryHookRecordsItsDecision is ADR 0024 (11): recorder-owned decisions
// leave task scratch under the matching hook. Bind uses a terminal syscall
// marker; control hooks emit their own typed refusal with the correct hook.
func TestPlaneEveryHookRecordsItsDecision(t *testing.T) {
	t.Parallel()
	path, _ := planeSource(t)
	hookConst := map[string]string{}
	for _, h := range ebpfbindings.PlaneHooks {
		hookConst[h.Name] = "TEGO_HOOK_" + strings.ToUpper(h.Name)
	}
	// Step B's helpers record under the hook their caller names.
	for helper, file := range map[string]string{"tego_modify_hook": path, "tego_protect_hook": stepBPath} {
		if !strings.Contains(functionBody(t, file, helper), "tego_plane_record(sc, hook,") {
			t.Errorf("%s does not record its decision under its caller's hook", helper)
		}
	}
	record := functionBody(t, path, "tego_plane_record")
	for _, field := range []string{"sc->rule_idx = rule;", "sc->hook = hook;", "sc->reason = reason;", "sc->obj = obj;",
		"sc->verdict = reason ? TEGO_V_REFUSED : TEGO_V_ALLOW;"} {
		if !strings.Contains(record, field) {
			t.Errorf("tego_plane_record does not set %q", field)
		}
	}
	for name, body := range planeBodies(t) {
		c, ok := hookConst[name]
		if !ok {
			t.Errorf("%s: no enum tego_plane_hook value", name)
			continue
		}
		if name == "socket_bind" {
			for _, want := range []string{"sc->bind.op = TEGO_EV_BIND_RESULT;", "sc->listen_run_idx = run->run_idx;", "sc->listen_gen = run->gen;", "sc->bind.reason = reason;", "sc->bind.rule_idx = TEGO_PLANE_RULE_LISTEN | rule;"} {
				if !strings.Contains(body, want) {
					t.Errorf("bind terminal scratch lacks %q", want)
				}
			}
			continue
		}
		if slices.Contains([]string{"ptrace_access_check", "ptrace_traceme", "bpf", "key_permission"}, name) {
			if !strings.Contains(body, c) || !strings.Contains(body, "tego_control_refuse(run, "+c) {
				t.Errorf("%s has no correctly attributed control refusal", name)
			}
			continue
		}
		if !strings.Contains(body, c) {
			t.Errorf("%s never records under %s", name, c)
		}
		if !regexp.MustCompile(`tego_plane_record\((sc|scratch),\s*`+c).MatchString(body) &&
			!regexp.MustCompile(`tego_(modify|protect)_hook\([^;]*`+c).MatchString(body) &&
			!strings.Contains(body, "tego_map_decide(") {
			t.Errorf("%s does not record its decision through tego_plane_record", name)
		}
	}
}

// TestPlaneFileOpenNeverAppliesExecRows is enforce-plane R8: file_open decides reads and modifications only, so
// PT_INTERP's open of the loader needs no exec row; and it skips a stacking filesystem's backing open.
func TestPlaneFileOpenNeverAppliesExecRows(t *testing.T) {
	t.Parallel()
	body := planeBodies(t)["file_open"]
	for _, banned := range []string{"tego_plane_exec_rows", "TEGO_Q_EXEC", "exec_rule"} {
		if strings.Contains(body, banned) {
			t.Errorf("file_open uses %q; exec is decided at bprm_check only", banned)
		}
	}
	backing := strings.Index(body, "if (tego_internal_mount(file->f_path.mnt))\n        return 0;")
	walk := strings.Index(body, "tego_nearest(")
	if backing < 0 || walk < backing {
		t.Error("file_open does not return 0 for an open on a private clone (a backing open included) before it walks")
	}
	for _, q := range []string{"TEGO_FMODE_READ", "TEGO_FMODE_WRITE", "TEGO_FMODE_CREATED", "TEGO_O_TRUNC"} {
		if !strings.Contains(body, q) {
			t.Errorf("file_open does not read %s", q)
		}
	}
}

// TestPlaneExecComparesTheWholeName is enforce-plane R9: bprm_check matches the final name by its length and every
// byte, through the build's reader, never with a string helper or by a hash alone; and a #! stage passes. The name
// pass lives in include/plane_name.h, which decide.bpf.c and the fill both include (enforce-plane §6 E15).
func TestPlaneExecComparesTheWholeName(t *testing.T) {
	t.Parallel()
	path := filepath.Join(sourceDir, "include", "plane_name.h")
	body := planeBodies(t)["bprm_check"]
	eq := functionBody(t, path, "tego_name_eq")
	cmp := functionBody(t, path, "tego_name_cmp_step")
	rd := functionBody(t, path, "tego_name_word")
	for _, src := range []string{body, eq, cmp, rd, functionBody(t, path, "tego_name_key")} {
		for _, banned := range []string{"_str(", "bpf_strncmp", "strcmp", "d_path", "d_name.hash"} {
			if strings.Contains(src, banned) {
				t.Errorf("the exec name compare uses %q", banned)
			}
		}
	}
	if !strings.Contains(eq, "r->name_len != p->len") || !strings.Contains(eq, "bpf_loop(TEGO_NAME_WORDS, tego_name_cmp_step,") {
		t.Errorf("tego_name_eq does not compare the length and then the words:\n%s", eq)
	}
	if !strings.Contains(cmp, "__builtin_memcpy(&row_word, &r->name[off]") || !strings.Contains(cmp, "tego_name_word(p, i) != row_word") {
		t.Errorf("tego_name_cmp_step does not compare every word with the row's:\n%s", cmp)
	}
	if !strings.Contains(rd, "TEGO_RD_WORD(p->addr + i * 8)") || !strings.Contains(rd, "tego_word_mask(") {
		t.Errorf("tego_name_word does not read masked words through the build's reader:\n%s", rd)
	}
	script := strings.Index(body, "bprm->buf[0] == '#' && bprm->buf[1] == '!'")
	file := strings.Index(body, "file = bprm->file;")
	if script < 0 || file < script {
		t.Error("bprm_check does not pass a #! stage before deciding the file")
	}
	fileArm := functionBody(t, filepath.Join(sourceDir, "decide.bpf.c"), "tego_exec_file_row")
	for _, arm := range []string{"tego_name_eq(&nm, r)", "tego_exec_file_row(", "kind & TEGO_ROW_EXEC_DIR"} {
		if !strings.Contains(body, arm) {
			t.Errorf("bprm_check lacks %q", arm)
		}
	}
	for _, arm := range []string{"tego_name_eq(nm, r)", "r->parent == (__u64)pinode"} {
		if !strings.Contains(fileArm, arm) {
			t.Errorf("tego_exec_file_row (bprm_check's file arm) lacks %q", arm)
		}
	}
}

// TestPlaneExecRowsAreKeyedByTheLink is enforce-plane R9, R16 and §6 E15 (ADR 0025's 2026-09-30 note): an exec row is
// keyed by the link, not the inode alone, and the key is one function for the fill that writes it and bprm_check
// that looks it up; bprm_check trusts no key alone (it compares the row's inode, directory and name), and the fill
// computes the name key from the dentry it keys, after comparing its bytes with the entry's.
func TestPlaneExecRowsAreKeyedByTheLink(t *testing.T) {
	t.Parallel()
	hdr := filepath.Join(sourceDir, "include", "plane_name.h")
	key := functionBody(t, hdr, "tego_exec_link_key")
	for _, want := range []string{"inode", "parent", "name_key", "(1ULL << 63)"} {
		if !strings.Contains(key, want) {
			t.Errorf("tego_exec_link_key does not use %q:\n%s", want, key)
		}
	}
	// The file arm is one function, tego_exec_file_row, for bprm_check and step C's mappings, so they cannot drift
	// from the key the fill writes.
	path, _ := planeSource(t)
	arm := functionBody(t, path, "tego_exec_file_row")
	for _, want := range []string{"sc->launder_dentry = (__u64)inode;", "sc->launder_mnt = (__u64)pinode;",
		"tego_exec_link_key(*(volatile __u64 *)&sc->launder_dentry, *(volatile __u64 *)&sc->launder_mnt,", "r->inode != (__u64)inode",
		"r->i_ino != inode->i_ino", "TEGO_PLANE_COUNT(run->run_idx, mismatch)", "r->parent == (__u64)pinode", "tego_name_eq(nm, r)"} {
		if !strings.Contains(arm, want) {
			t.Errorf("tego_exec_file_row lacks %q", want)
		}
	}
	body := planeBodies(t)["bprm_check"]
	mapRow := functionBody(t, filepath.Join(sourceDir, "decide_stepc.h"), "tego_map_exec_row")
	for name, src := range map[string]string{"bprm_check": body, "tego_map_exec_row": mapRow} {
		if !strings.Contains(src, "tego_exec_file_row(sc, exec_rows, run, dentry, inode, &nm, key, ") {
			t.Errorf("%s does not take its file arm from tego_exec_file_row", name)
		}
		if strings.Contains(src, "ikey = (__u64)inode;") || strings.Contains(src, "exec_rows, &ikey") {
			t.Errorf("%s looks an exec row up by a key of its own", name)
		}
	}
	fill := stripComments(read(t, filepath.Join(sourceDir, "decide_fill.bpf.c")))
	for _, want := range []string{`#include "plane_name.h"`, "name_key = tego_name_key(dentry, &nm);",
		"if (!tego_name_eq(&nm, row))", "key = tego_exec_link_key(key, *(volatile __u64 *)&cfg->launder, name_key);",
		"row->inode = (__u64)inode;"} {
		if !strings.Contains(fill, want) {
			t.Errorf("the fill lacks %q", want)
		}
	}
	for _, src := range []string{"decide.bpf.c", "decide_fill.bpf.c"} {
		if !strings.Contains(read(t, filepath.Join(sourceDir, src)), `#include "plane_name.h"`) {
			t.Errorf("%s does not include plane_name.h", src)
		}
	}
}

// TestPlaneRenamesAndLinksKeepTheirRows is enforce-plane R10 and R11 as the row compiler states them
// (decide.PlaneRows.Decide): unlink and rmdir are modifications at the object; each end of a rename is a rename of
// itself, which a deny_write target or an ancestor refuses at depth 0 (reason deny-write-ancestor); rename and link
// refuse REFER when the source's nearest row is stricter than the destination's; and the fmod_ret programs of the
// path hooks return 0 for an IS_PRIVATE inode as the security_ wrappers do (R4).
func TestPlaneRenamesAndLinksKeepTheirRows(t *testing.T) {
	t.Parallel()
	path, _ := planeSource(t)
	bodies := planeBodies(t)
	modify := functionBody(t, path, "tego_modify_hook")
	if !strings.Contains(modify, "!(kind & TEGO_ROW_MODIFY_ALLOW)") || !strings.Contains(modify, "reason = refuse_as;") {
		t.Errorf("tego_modify_hook does not decide a modification at the object:\n%s", modify)
	}
	for _, hook := range []string{"path_unlink", "path_rmdir"} {
		if !strings.Contains(bodies[hook], "TEGO_R_DELETE_OUTSIDE_CONTRACT)") {
			t.Errorf("%s does not refuse a removal as TEGO_R_DELETE_OUTSIDE_CONTRACT", hook)
		}
	}
	end := functionBody(t, path, "tego_rename_end")
	if !strings.Contains(end, "depth == 0 && (kind & TEGO_ROW_RENAME_REFUSED)") || !strings.Contains(end, "TEGO_R_DENY_WRITE_ANCESTOR") {
		t.Errorf("tego_rename_end does not refuse a deny_write target or ancestor at depth 0:\n%s", end)
	}
	if strings.Count(bodies["path_rename"], "tego_rename_end(") != 2 {
		t.Error("path_rename does not decide both ends as renames of themselves")
	}
	strict := functionBody(t, path, "tego_strictness")
	if !strings.Contains(strict, "TEGO_ROW_READ_DENY") || !strings.Contains(strict, "TEGO_ROW_MODIFY_ALLOW") {
		t.Errorf("tego_strictness is not decide.PlaneKind.Strictness:\n%s", strict)
	}
	for _, h := range []string{"path_rename", "path_link"} {
		if !strings.Contains(bodies[h], "tego_strictness(skind) > tego_strictness(dkind)") || !strings.Contains(bodies[h], "TEGO_R_REFER") {
			t.Errorf("%s never refuses REFER (R10)", h)
		}
	}
}

// TestPlaneTestsADentrysInodeAtRunTime is the plane's guard against a verifier that takes a trusted dentry's d_inode
// for a pointer that is never NULL: the verifier's BTF_TYPE_SAFE_TRUSTED(struct dentry) ("no negative dentry-s in
// places where bpf can see it"), which RHEL 9's 5.14, 6.8 and 6.12 carry and later kernels make trusted-or-NULL. An
// lsm program's NULL test of a d_inode loaded straight from a hook's dentry is then a branch the verifier never
// takes, and it hard-wires the branch, so on those kernels path_rename read a rename's negative destination as
// positive in lsm mode and refused a file moved into a stricter directory (REFER's reverse arm; the guest's
// TestPlaneStepAHooksDecide cell "rename into a stricter directory", refused on 5.14, 6.8 and 6.12 with NAME-BPF's
// first objects). Whether a dentry is positive is therefore asked through tego_positive, which tests the pointer
// read back through the task's scratch value, a scalar the verifier knows nothing of, and no code tests a d_inode
// against NULL as a value. A test that only guards a read of the inode's fields (inode && inode->i_mode ...) is safe
// either way: a hard-wired guard reads the field through the exception-handled load, which reads 0 at NULL.
func TestPlaneTestsADentrysInodeAtRunTime(t *testing.T) {
	t.Parallel()
	path, src := planeSource(t)
	for _, banned := range []*regexp.Regexp{
		regexp.MustCompile(`->d_inode\s*(!=|==)\s*(0|NULL)\b`),
		regexp.MustCompile(`(0|NULL)\s*(!=|==)\s*[A-Za-z_][A-Za-z0-9_]*(->[A-Za-z_][A-Za-z0-9_]*)*->d_inode\b`),
		regexp.MustCompile(`!\s*\(?\s*[A-Za-z_][A-Za-z0-9_]*(->[A-Za-z_][A-Za-z0-9_]*)*->d_inode\b`),
		regexp.MustCompile(`\bd_is_(positive|negative)\b`),
	} {
		if m := banned.FindString(src); m != "" {
			t.Errorf("the plane tests a d_inode against NULL as a value (%q); ask tego_positive", m)
		}
	}
	positive := functionBody(t, path, "tego_positive")
	if !strings.Contains(positive, "return tego_plane_unknown(sc, (__u64)dentry->d_inode) != 0;") {
		t.Errorf("tego_positive does not test the inode laundered through the task's scratch value:\n%s", positive)
	}
	rename := planeBodies(t)["path_rename"]
	decl := regexp.MustCompile(`\bint positive\b[^;]*;`).FindStringIndex(rename)
	ask := strings.Index(rename, "positive = tego_positive(sc, new_dentry);")
	if decl == nil || ask < 0 || ask < strings.Index(rename, "sc = tego_plane_scratch_get();") ||
		decl[1]+strings.Index(rename[decl[1]:], "positive") < ask {
		t.Error("path_rename does not take its destination's positivity from tego_positive before any use of it")
	}
}

// TestPlaneDecidesMatchesTheBodies holds internal/bpf.PlaneHook.Decides to decide.bpf.c: a hook decides exactly
// when its body or an explicitly checked refusal helper returns -EACCES.
// TestPlaneReturnsOnlyZeroOrEACCES checks those helpers too. Doctor's mode
// probe reads Decides to require the hook's probe syscall to be refused in the scratch cgroup (docs/p0/
// enforce-plane.md R21), so a body that starts refusing without the flag, or the flag without the body, fails
// here rather than leaving the probe checking load and scope only.
func TestPlaneDecidesMatchesTheBodies(t *testing.T) {
	t.Parallel()
	_, src := planeSource(t)
	decides := map[string]bool{}
	for _, loc := range planeHookRe.FindAllStringIndex(src, -1) {
		name := planeHookRe.FindStringSubmatch(src[loc[0]:])[1]
		body := balanced(t, src[loc[0]:], name)
		for _, helper := range []string{"tego_control_refuse", "tego_ptrace_peer", "tego_listen_refuse", "tego_mknod_bind"} {
			if strings.Contains(body, helper+"(") {
				body += helperBody(t, src, helper)
			}
		}
		for _, m := range returnRe.FindAllStringSubmatch(body, -1) {
			if strings.Contains(strings.TrimSpace(m[1]), "-EACCES") {
				decides[name] = true
			}
		}
	}
	for _, h := range ebpfbindings.PlaneHooks {
		if h.Decides != decides[h.Name] {
			t.Errorf("%s: internal/bpf.PlaneHooks says Decides=%v, decide.bpf.c's body refuses=%v", h.Name, h.Decides,
				decides[h.Name])
		}
	}
}

// TestPlaneExecRefusalsWriteTheirSample is enforce-plane R23 for bprm_check, the one step A hook no recorder fexit
// wraps: every refusal it makes writes the plane's own sample, the refused exec's one ledger line, and no hook a
// recorder fexit wraps writes one of its own (that fexit reads the decision instead, TestRecorderTakesThePlaneDecision;
// where it is not attached, tego_plane_fallback writes it, TestPlaneFallbackOnEveryFexitHookRefusal).
func TestPlaneExecRefusalsWriteTheirSample(t *testing.T) {
	t.Parallel()
	bodies := planeBodies(t)
	exec := bodies["bprm_check"]
	refusals := strings.Count(exec, "return -EACCES;")
	if samples := strings.Count(exec, "tego_exec_sample(run, bprm, "); refusals == 0 || samples != refusals {
		t.Errorf("bprm_check refuses %d times and writes its sample %d times", refusals, samples)
	}
	for name, body := range bodies {
		if _, fexit := planeFexitHooks[name]; fexit && (strings.Contains(body, "_sample(") || strings.Contains(body, "bpf_ringbuf") ||
			strings.Contains(body, "tego_protect_hook(")) {
			t.Errorf("%s writes a ring sample, beside the recorder fexit's line of the same action", name)
		}
	}
	path, _ := planeSource(t)
	execSample := functionBody(t, path, "tego_exec_sample")
	for _, want := range []string{"a.kind = TEGO_EV_PLANE_EXEC;", "a.named = 1;", "a.name = (__u64)bprm->filename;",
		"tego_plane_own_sample(run, &a);"} {
		if !strings.Contains(execSample, want) {
			t.Errorf("bprm_check's sample lacks %q: it names the spelling the task passed through the one writer", want)
		}
	}
	sample := functionBody(t, path, "tego_plane_own_sample")
	for _, want := range []string{"TEGO_RD_WORD(", "tego_word_mask(", "tego_lost_inc(&tego_lost", "TEGO_V_REFUSED",
		"e->rule_idx = a->rule;", ": 0;"} {
		if !strings.Contains(sample+functionBody(t, path, "tego_path_step"), want) {
			t.Errorf("the plane's exec sample lacks %q: it reads the name through the build's reader, clears what "+
				"follows its NUL, counts a loss and carries the whole rule", want)
		}
	}
	if strings.Contains(sample, "_str(") || strings.Contains(sample, "bpf_d_path") {
		t.Error("the plane's exec sample reads the name with a probe-read string helper or bpf_d_path, which " +
			"lockdown=confidentiality or fmod_ret mode refuses")
	}
}

// TestRecorderTakesThePlaneDecision is ADR 0024 (11) and TIER3-PLAN T9 in trace_proc.bpf.c: each fexit on a hook
// the plane decides at takes the task's decision for its own call (the hook and the object it names) before any
// early return, and stamps a plane refusal on the record it writes; sched_process_exec names an exec the plane
// allowed by the plane's rule.
func TestRecorderTakesThePlaneDecision(t *testing.T) {
	t.Parallel()
	path := filepath.Join(sourceDir, "trace_proc.bpf.c")
	src := read(t, path)
	prog := func(name string) string {
		t.Helper()
		i := strings.Index(src, "BPF_PROG("+name+",")
		if i < 0 {
			t.Fatalf("no program %s", name)
		}
		return balanced(t, src[i:], name)
	}
	for _, tc := range []struct{ prog, take string }{
		{"tego_file_open", "tego_plane_take(TEGO_HOOK_FILE_OPEN, (__u64)file)"},
		{"tego_path_unlink", "tego_plane_take(TEGO_HOOK_PATH_UNLINK, (__u64)dentry)"},
		{"tego_path_rmdir", "tego_plane_take(TEGO_HOOK_PATH_RMDIR, (__u64)dentry)"},
		{"tego_path_rename", "tego_plane_take(TEGO_HOOK_PATH_RENAME, (__u64)old_dentry)"},
		{"tego_path_link", "tego_plane_take(TEGO_HOOK_PATH_LINK, (__u64)new_dentry)"},
		{"tego_path_mkdir", "tego_plane_take(TEGO_HOOK_PATH_MKDIR, (__u64)dentry)"},
		{"tego_path_mknod", "tego_plane_take(TEGO_HOOK_PATH_MKNOD, (__u64)dentry)"},
		{"tego_path_symlink", "tego_plane_take(TEGO_HOOK_PATH_SYMLINK, (__u64)dentry)"},
		{"tego_path_truncate", "tego_plane_take(TEGO_HOOK_PATH_TRUNCATE, (__u64)TEGO_READ(path, dentry))"},
		{"tego_file_truncate", "tego_plane_take(TEGO_HOOK_FILE_TRUNCATE, (__u64)file)"},
	} {
		body := prog(tc.prog)
		take, miss := strings.Index(body, tc.take), strings.Index(body, "if (!run)\n        return 0;")
		if take < 0 || miss < 0 || take < miss || strings.Count(body[:take], "return") != 1 {
			t.Errorf("%s does not take the plane's decision right after the run lookup:\n%s", tc.prog, body)
		}
		stamp := body
		if strings.Contains(tc.prog, "truncate") {
			stamp = functionBody(t, path, "tego_truncate") // both truncate programs end in it
		}
		if !strings.Contains(stamp, "tego_plane_stamp(&e->hdr, said, ret);") {
			t.Errorf("%s never stamps the plane's refusal on its record", tc.prog)
		}
	}
	for _, h := range ebpfbindings.PlaneHooks {
		if p, ok := planeFexitHooks[h.Name]; ok && !strings.Contains(src, "BPF_PROG("+p+",") {
			t.Errorf("planeFexitHooks names %s for %s, which trace_proc.bpf.c does not declare", p, h.Name)
		}
	}
	if held := prog("tego_path_mknod"); !strings.Contains(held, "tego_plane_stamp(&e->hdr, said, ret);\n            held->dentry") {
		t.Error("tego_path_mknod does not stamp the plane's refusal on the create it holds for the open")
	}
	if tr := functionBody(t, path, "tego_truncate"); !strings.Contains(tr, "tego_plane_stamp(&held->fs.hdr, said, ret);") {
		t.Error("tego_truncate does not stamp the plane's refusal on the O_TRUNC open it ends")
	}
	exec := prog("tego_sched_exec")
	if !strings.Contains(exec, "tego_plane_take_exec((__u64)TEGO_READ(bprm, file))") ||
		!strings.Contains(exec, "tego_plane_exec_named(e, said);") {
		t.Error("sched_process_exec does not name an exec the plane allowed by the plane's rule")
	}
	take := functionBody(t, path, "tego_plane_take")
	for _, want := range []string{"sc->hook != hook || sc->obj != obj", "sc->hook = TEGO_HOOK_NONE;"} {
		if !strings.Contains(take, want) {
			t.Errorf("tego_plane_take lacks %q: it takes only its own call's decision, and consumes it", want)
		}
	}
	takeExec := functionBody(t, path, "tego_plane_take_exec")
	for _, want := range []string{"sc->exec_obj != obj", "sc->exec_obj = 0;"} {
		if !strings.Contains(takeExec, want) {
			t.Errorf("tego_plane_take_exec lacks %q: it takes only this exec's bprm_check decision, and consumes it", want)
		}
	}
	record := functionBody(t, filepath.Join(sourceDir, "decide.bpf.c"), "tego_plane_record")
	if !strings.Contains(record, "if (hook == TEGO_HOOK_BPRM_CHECK) {") || !strings.Contains(record, "sc->exec_obj = obj;") {
		t.Error("tego_plane_record does not keep bprm_check's decision apart for sched_process_exec")
	}
	if stamp := functionBody(t, path, "tego_plane_stamp"); !strings.Contains(stamp, "ret != -EACCES") {
		t.Error("tego_plane_stamp stamps a plane refusal the chain did not return")
	}
}

// TestPlaneKeepsNoPerCPUScratch is ADR 0024's T2 note applied to every map the plane's programs use: they run with
// migration disabled but can be preempted, so a per-CPU buffer filled in one step and read back in a later one can
// be overwritten in between by the next plane program on that CPU. The refusal sample's path buffer was one: a
// preempted sample could carry another task's (maybe another run's) refused exec path on this run's line. Scratch
// that lives across steps is the task's own storage.
func TestPlaneKeepsNoPerCPUScratch(t *testing.T) {
	t.Parallel()
	_, src := planeSource(t)
	maps := read(t, filepath.Join(sourceDir, "include", "maps.h"))
	defs := regexp.MustCompile(`struct\s*\{([^}]*)\}\s*(\w+)\s+SEC\("\.maps"\)`).FindAllStringSubmatch(maps, -1)
	if len(defs) == 0 {
		t.Fatal("maps.h has no map definitions this test can read")
	}
	used := 0
	for _, d := range defs {
		if !regexp.MustCompile(`&` + d[2] + `\b`).MatchString(src) {
			continue
		}
		used++
		if strings.Contains(d[1], "PERCPU") {
			t.Errorf("decide.bpf.c uses %s, a per-CPU map, which a preempted plane program shares with the next "+
				"one on its CPU", d[2])
		}
	}
	if used == 0 {
		t.Fatal("decide.bpf.c uses no map maps.h defines; the test reads the wrong files")
	}
}

// TestPlaneWalkStepCountsNothing: the walk's step is on the allow path of every open, exec and rename beneath a
// ruled directory, and a slot keeps its previous run's rows, which the step walks past. An atomic counter bumped
// there is one cache line shared by every CPU of the run, so the step counts nothing; only refusals are counted,
// by tego_plane_walk and the hooks.
func TestPlaneWalkStepCountsNothing(t *testing.T) {
	t.Parallel()
	path, _ := planeSource(t)
	body := functionBody(t, path, "tego_walk_step")
	for _, banned := range []string{"TEGO_PLANE_COUNT", "__sync_", "__atomic_", "tego_lost_inc"} {
		if strings.Contains(body, banned) {
			t.Errorf("tego_walk_step uses %s on the walk's allow path", banned)
		}
	}
}

// TestPlaneStepBCreatesAreModifications is enforce-plane R13: path_mknod (may_o_create's hook, before an O_CREAT
// open makes its inode), path_mkdir, path_symlink, path_truncate and file_truncate each decide a modification at
// their object with the walk that crosses mounts, as unlink does (decide.PlaneRows.Decide, PlaneModify), mkdir with
// its own reason; file_truncate skips what file_open skips.
func TestPlaneStepBCreatesAreModifications(t *testing.T) {
	t.Parallel()
	bodies := planeBodies(t)
	modify := functionBody(t, filepath.Join(sourceDir, "decide.bpf.c"), "tego_modify_hook")
	if !strings.Contains(modify, "tego_nearest(sc, dentry, mnt, run,") || !strings.Contains(modify, "!(kind & TEGO_ROW_MODIFY_ALLOW)") {
		t.Errorf("tego_modify_hook does not decide a modification by the crossing walk:\n%s", modify)
	}
	for hook, reason := range map[string]string{
		"path_mknod": "TEGO_R_WRITE_OUTSIDE_CONTRACT", "path_mkdir": "TEGO_R_MKDIR_OUTSIDE_CONTRACT",
		"path_symlink": "TEGO_R_WRITE_OUTSIDE_CONTRACT",
	} {
		// hdr and the names argument are ADR 0043's (TestNameCheckCallersAreTheListedHooks holds which hooks set it).
		call := regexp.MustCompile(`tego_modify_hook\(dentry, dir->mnt, run, hdr, [01], TEGO_HOOK_` + strings.ToUpper(hook) +
			`, \(__u64\)dentry,\s*` + reason + `\)`)
		if !call.MatchString(bodies[hook]) {
			t.Errorf("%s does not decide its new name as a modification refused %s", hook, reason)
		}
	}
	for _, hook := range []string{"path_truncate", "file_truncate"} {
		if !strings.Contains(bodies[hook], "tego_modify_hook(") {
			t.Errorf("%s does not decide the truncate as a modification", hook)
		}
	}
	ft := bodies["file_truncate"]
	for _, skip := range []string{"tego_no_path(file->f_path.dentry, file->f_path.mnt)",
		"tego_internal_mount(file->f_path.mnt)"} {
		if i, w := strings.Index(ft, skip), strings.Index(ft, "tego_modify_hook("); i < 0 || w < i {
			t.Errorf("file_truncate does not skip %s before it decides, as file_open does", skip)
		}
	}
}

// TestPlaneAttributeHooksProtectOnly is enforce-plane R12: chmod, chown, the xattr hooks and the ACL hooks walk
// inside the object's superblock (no vfsmount: the inode hooks get none) and refuse only where the nearest row
// carries TEGO_ROW_PROTECTED, a deny_write target at or above it; they never ask the modification question the
// write entries answer, since Landlock governs none of these calls. A walk that fails refuses (R7).
func TestPlaneAttributeHooksProtectOnly(t *testing.T) {
	t.Parallel()
	bodies := planeBodies(t)
	protect := functionBody(t, stepBPath, "tego_protect_hook")
	if !strings.Contains(protect, "tego_plane_walk(*(volatile __u64 *)&sc->launder_dentry, 0, run->run_idx, run->gen,") {
		t.Errorf("tego_protect_hook does not walk inside the superblock (vfsmount 0):\n%s", protect)
	}
	if !strings.Contains(protect, "h.kind & TEGO_ROW_PROTECTED") || strings.Contains(protect, "TEGO_ROW_MODIFY_ALLOW") {
		t.Errorf("tego_protect_hook does not refuse on TEGO_ROW_PROTECTED alone:\n%s", protect)
	}
	if !strings.Contains(protect, "tego_walk_failed(") {
		t.Error("tego_protect_hook does not refuse a walk that failed closed")
	}
	for _, h := range []string{"path_chmod", "path_chown", "inode_setxattr", "inode_removexattr", "inode_set_acl", "inode_remove_acl"} {
		body := bodies[h]
		if !strings.Contains(body, "tego_protect_hook(") || strings.Contains(body, "tego_nearest(") {
			t.Errorf("%s is not decided by tego_protect_hook alone", h)
		}
		if !strings.Contains(body, "tego_no_path") {
			t.Errorf("%s decides an object no path names", h)
		}
	}
	walk := functionBody(t, filepath.Join(sourceDir, "decide.bpf.c"), "tego_plane_walk")
	if !strings.Contains(walk, "s.mroot = TEGO_D_SBROOT(dentry);") {
		t.Error("tego_plane_walk without a vfsmount does not stop at the dentry's superblock root")
	}
	step := functionBody(t, filepath.Join(sourceDir, "decide.bpf.c"), "tego_walk_step")
	if !strings.Contains(step, "!(s->m && (r->kind & TEGO_ROW_MOUNT_ONLY))") {
		t.Error("the walk that crosses mounts does not pass a mounted root's row (TEGO_ROW_MOUNT_ONLY)")
	}
	if !regexp.MustCompile(`if \(!m\) \{\s*s->result = TEGO_WALK_ROOT;`).MatchString(step) {
		t.Error("the walk inside a superblock does not end as ROOT at the superblock's root")
	}
}

// TestPlaneStepBRefusalsWriteTheirSample is enforce-plane R23 for step B's hooks no recorder fexit wraps: every
// refusal of an attribute hook or socket_create writes the plane's own sample, the action's one ledger line, and the
// sample reads names through the build's reader only.
func TestPlaneStepBRefusalsWriteTheirSample(t *testing.T) {
	t.Parallel()
	bodies := planeBodies(t)
	path, _ := planeSource(t)
	protect := functionBody(t, stepBPath, "tego_protect_hook")
	if !regexp.MustCompile(`if \(!reason\)\s*return 0;\s*tego_attr_sample\(dentry, run, hook, rule, reason\);\s*return reason;`).MatchString(protect) {
		t.Errorf("tego_protect_hook does not write its sample on every refusal:\n%s", protect)
	}
	if sample := functionBody(t, stepBPath, "tego_attr_sample"); !strings.Contains(sample, "tego_plane_own_sample(run, &a);") {
		t.Errorf("tego_attr_sample writes no sample:\n%s", sample)
	}
	if unslotted := functionBody(t, stepBPath, "tego_protect_unslotted"); !strings.Contains(unslotted, "tego_attr_sample(dentry, run, hook,") {
		t.Errorf("an attribute hook's refusal on a slot with no header writes no sample:\n%s", unslotted)
	}
	sock := bodies["socket_create"]
	refusals := strings.Count(sock, "return -EACCES;")
	if samples := strings.Count(sock, "tego_plane_own_sample(run, &a);"); refusals == 0 || samples != refusals {
		t.Errorf("socket_create refuses %d times and writes its sample %d times", refusals, samples)
	}
	_, src := planeSource(t)
	control := helperBody(t, src, "tego_control_refuse")
	for _, want := range []string{"a.kind = TEGO_EV_PLANE_CONTROL;", "a.hook = hook;", "a.reason = reason;", "tego_plane_own_sample(run, &a);", "return -EACCES;"} {
		if !strings.Contains(control, want) {
			t.Errorf("control refusal lacks its typed one-line owner: %q", want)
		}
	}
	for _, want := range []string{"tego_unix_listen_marker(sock,run,reason,rule)", "tego_listen_refuse(run,sock,reason)"} {
		if !strings.Contains(bodies["socket_listen"], want) {
			t.Errorf("listen lost terminal Unix / sampled IP ownership: %q", want)
		}
	}
	sample := functionBody(t, path, "tego_plane_own_sample")
	for _, want := range []string{"tego_path_step", "tego_lost_inc(&tego_lost", "TEGO_V_REFUSED", "e->family = a->family;",
		"e->dir_ino = a->dir_ino;", "e->flags = a->flags | (a->name_len << 16);", ": 0;"} {
		if !strings.Contains(sample, want) {
			t.Errorf("the plane's step B sample lacks %q", want)
		}
	}
	if strings.Contains(sample, "_str(") || strings.Contains(sample, "bpf_d_path") {
		t.Error("the plane's step B sample reads a name with a probe-read string helper or bpf_d_path")
	}
	for name := range bodies {
		terminalOrControl := slices.Contains([]string{"socket_bind", "socket_listen", "ptrace_access_check", "ptrace_traceme", "bpf", "key_permission"}, name)
		if _, fexit := planeFexitHooks[name]; !fexit && !terminalOrControl && name != "bprm_check" && !planeUnixHook(name) && !strings.Contains(bodies[name], "_sample(") &&
			!strings.Contains(bodies[name], "tego_protect_hook(") && !strings.Contains(bodies[name], "tego_map_decide(") {
			t.Errorf("%s has no recorder fexit and writes no sample of its own", name)
		}
	}
}

// TestPlaneSocketCreateIsTheAllowlist is ADR 0018 (5) and enforce-plane R14: socket_create passes a kernel socket
// before anything else, decides only under a net: section (the slot header's TEGO_SLOT_NET_DECIDES), fails closed
// on a slot with no header of the run's gen, and admits exactly the seccomp filter's allowlist (enforce/landlock
// socketAllowTest).
func TestPlaneSocketCreateIsTheAllowlist(t *testing.T) {
	t.Parallel()
	body := planeBodies(t)["socket_create"]
	kern, lookup := strings.Index(body, "if (kern)\n        return 0;"), strings.Index(body, "tego_plane_slot_of(run)")
	if kern < 0 || lookup < kern {
		t.Error("socket_create does not pass a kernel socket before it reads the slot header")
	}
	if !strings.Contains(body, "if (!(hdr->flags & TEGO_SLOT_NET_DECIDES))\n        return 0;") ||
		!strings.Contains(body, "(hdr->flags & TEGO_SLOT_NET_ICMP) != 0") || strings.Contains(body, "TEGO_NET_POLICY_KEY") {
		t.Error("socket_create does not decide by the slot header's net flags")
	}
	if !regexp.MustCompile(`if \(!hdr\) \{[^}]*return -EACCES;`).MatchString(body) {
		t.Error("socket_create does not fail closed on a slot with no header of the run's gen")
	}
	if !strings.Contains(read(t, stepBPath), `#include "socket_allow.h"`) {
		t.Error(`decide_stepb.h does not take the allowlist from include/socket_allow.h, the one cgroup/sock_create calls`)
	}
	allowed := functionBody(t, socketAllowPath, "tego_socket_allowed")
	for _, want := range []string{"family == TEGO_AF_UNIX", "family == TEGO_AF_NETLINK", "protocol == TEGO_NETLINK_ROUTE",
		"family != TEGO_AF_INET && family != TEGO_AF_INET6",
		"protocol == 0 || protocol == TEGO_IPPROTO_TCP", "protocol == 0 || protocol == TEGO_IPPROTO_UDP",
		"icmp && (protocol == TEGO_IPPROTO_ICMP || protocol == TEGO_IPPROTO_ICMPV6)", "type & TEGO_SOCK_TYPE_MASK"} {
		if !strings.Contains(allowed, want) {
			t.Errorf("tego_socket_allowed lacks %q (ADR 0018 (1))", want)
		}
	}
	if !regexp.MustCompile(`(?m)^#define TEGO_NETLINK_ROUTE 0$`).MatchString(read(t, socketAllowPath)) {
		t.Error("TEGO_NETLINK_ROUTE is not 0")
	}
	for c, v := range map[string]string{"TEGO_AF_UNIX": "1", "TEGO_AF_INET": "2", "TEGO_AF_INET6": "10", "TEGO_AF_NETLINK": "16",
		"TEGO_SOCK_STREAM": "1", "TEGO_SOCK_DGRAM": "2", "TEGO_IPPROTO_ICMP": "1", "TEGO_IPPROTO_TCP": "6",
		"TEGO_IPPROTO_UDP": "17", "TEGO_IPPROTO_ICMPV6": "58"} {
		if !regexp.MustCompile(`(?m)^#define ` + c + ` ` + v + `$`).MatchString(read(t, filepath.Join(sourceDir, "include", "common.h"))) {
			t.Errorf("%s is not %s", c, v)
		}
	}
}

// TestPlaneFileOpenSkipsPrivateClones settles enforce-plane §2.7's condition 1 (E4): overlayfs' copy-up opens the new
// upper file with a plain dentry_open on its private clone of the upper mount, in the agent's task, after the
// agent's own open of the merged file was decided. file_open and file_truncate return 0 for a file on a mount whose
// mnt_ns is MNT_NS_INTERNAL, which no name the agent opens resolves through.
func TestPlaneFileOpenSkipsPrivateClones(t *testing.T) {
	t.Parallel()
	path, _ := planeSource(t)
	internal := functionBody(t, path, "tego_internal_mount")
	if !strings.Contains(internal, "mnt_ns") || !strings.Contains(internal, "TEGO_MNT_NS_INTERNAL") {
		t.Errorf("tego_internal_mount does not compare mnt_ns with MNT_NS_INTERNAL:\n%s", internal)
	}
	if !strings.Contains(read(t, path), "#define TEGO_MNT_NS_INTERNAL ((__u64)-22)") {
		t.Error("TEGO_MNT_NS_INTERNAL is not ERR_PTR(-EINVAL)")
	}
	body := planeBodies(t)["file_open"]
	if i, w := strings.Index(body, "tego_internal_mount(file->f_path.mnt)"), strings.Index(body, "tego_nearest("); i < 0 || w < i {
		t.Error("file_open does not skip a private clone's file before it walks")
	}
}

// planeUnixHook reports step D's unix hooks, whose decision's one ledger line is the supervisor's (enforce-plane R14,
// enforce-cgroup-observe §5 R7): they write no sample of their own, as cgroup_net's unix programs write none.
func planeUnixHook(name string) bool {
	for _, h := range ebpfbindings.PlaneHooks {
		if h.Name == name {
			return h.Unix
		}
	}
	return false
}

// TestPlaneFallbackOnEveryFexitHookRefusal is enforce-plane §7 and R23's record fallback (TIER3-PLAN T9b): on each of
// the ten hooks a recorder fexit wraps, every refusal path, the scratch value that could not be had included, calls
// tego_plane_fallback, which writes the plane's own TEGO_EV_PLANE_FS sample exactly when the build's mask
// (tego_plane_recorded, pinned by name, written by the backend) says that hook's fexit is not attached. So a
// refused action has the fexit's line or the plane's, never none and never both. The mask is read on the refusal
// path only, never before a decision.
func TestPlaneFallbackOnEveryFexitHookRefusal(t *testing.T) {
	t.Parallel()
	path, src := planeSource(t)
	bodies := planeBodies(t)
	if len(planeFexitHooks) != len(ebpfbindings.PlaneFexitPrograms) {
		t.Errorf("the source tests know %d fexit hooks, internal/bpf %d", len(planeFexitHooks), len(ebpfbindings.PlaneFexitPrograms))
	}
	for hook, prog := range planeFexitHooks {
		if ebpfbindings.PlaneFexitPrograms[hook] != prog {
			t.Errorf("%s: the recorder's fexit is %s here and %q in internal/bpf", hook, prog, ebpfbindings.PlaneFexitPrograms[hook])
		}
	}
	// The helpers some hooks decide through: each refuses on its !sc path and on its recorded refusal.
	helpers := map[string]string{
		"tego_modify_hook": functionBody(t, path, "tego_modify_hook"),
	}
	for name, body := range helpers {
		refusals := strings.Count(body, "TEGO_PLANE_COUNT(run->run_idx, unresolved);") + strings.Count(body, "tego_plane_record(")
		if n := strings.Count(body, "tego_plane_fallback(run, hook, dentry, "); refusals != 2 || n != refusals {
			t.Errorf("%s refuses %d ways and falls back %d times:\n%s", name, refusals, n, body)
		}
	}
	for hook := range planeFexitHooks {
		body, ok := bodies[hook]
		if !ok {
			t.Fatalf("no body for %s", hook)
		}
		refusals := strings.Count(body, "return -EACCES;")
		// A slot with no header of the run's gen refuses before any decision, through tego_plane_unslotted_fs,
		// which falls back itself.
		unslotted := strings.Count(body, "tego_plane_unslotted_fs(run, ")
		helper := ""
		for name := range helpers {
			if strings.Contains(body, name+"(") {
				helper = name
			}
		}
		switch {
		case hook == "path_mknod":
			// The socket node's bind ownership lives in its own subprogram (its frame kept off path_mknod's, which the
			// name entries' check stacks on), entered from the floor's socket arm. The floor is the task's record of
			// this very decision, which tego_modify_hook wrote (hook path_mknod, object dentry); without that record
			// the bind arm refuses, as the floor did (no scratch value).
			bind := helperBody(t, src, "tego_mknod_bind")
			if !strings.Contains(body, "if ((node_mode & 0170000) == 0140000)\n        return tego_mknod_bind(run, dentry);") {
				t.Error("path_mknod does not hand its socket node to tego_mknod_bind")
			}
			for _, want := range []string{"__u8 floor = tego_modify_hook(", "if ((node_mode & 0170000) == 0140000)", "return floor ? -EACCES : 0;"} {
				if !strings.Contains(body, want) {
					t.Errorf("path_mknod lost its filesystem floor: %q", want)
				}
			}
			for _, want := range []string{
				"if (!sc || sc->hook != TEGO_HOOK_PATH_MKNOD || sc->obj != (__u64)dentry)\n        return -EACCES;\n    floor = sc->reason;",
				"sc->bind.op == TEGO_EV_BIND_RESULT", "sc->listen_run_idx == run->run_idx", "sc->listen_gen == run->gen", "if (floor)",
				"tego_listen_path_reason(run, dentry, &rule)", "return floor ? -EACCES : 0;",
			} {
				if !strings.Contains(bind, want) {
					t.Errorf("tego_mknod_bind lost filesystem floor or exact bind ownership: %q", want)
				}
			}
		case helper != "":
			if refusals != 1+unslotted || unslotted != 1 || strings.Contains(body, "tego_plane_scratch_get(") {
				t.Errorf("%s decides through %s and should refuse only by its answer", hook, helper)
			}
		case refusals == 0 || unslotted != 1 || strings.Count(body, "tego_plane_fallback(run, ")+unslotted != refusals:
			t.Errorf("%s refuses %d times and falls back %d times", hook, refusals, strings.Count(body, "tego_plane_fallback(run, ")+unslotted)
		}
	}
	for name, body := range bodies {
		if _, fexit := planeFexitHooks[name]; !fexit && strings.Contains(body, "tego_plane_fallback(") {
			t.Errorf("%s has no recorder fexit and still takes the fallback, beside its own sample", name)
		}
	}
	if u := functionBody(t, path, "tego_plane_unslotted_fs"); !strings.Contains(u, "tego_plane_fallback(run, hook, dentry, TEGO_PLANE_RULE_NONE, TEGO_R_PATH_UNRESOLVED, flags);") {
		t.Errorf("tego_plane_unslotted_fs does not fall back:\n%s", u)
	}
	// The fallback tests the mask inline and builds its sample in tego_plane_fallback_sample, a global function (its
	// arguments kept off the fs hooks' frames, on which the name entries' check stacks, and the sample verified once
	// in a program however many of its paths fall back), handed the dentry's name address, directory inode number and
	// device as scalars with the rule, reason, hook and flags packed beside them.
	fallback := functionBody(t, path, "tego_plane_fallback")
	wraps, call := strings.Index(fallback, "if (tego_recorder_wraps(hook))\n        return;"),
		strings.Index(fallback, "tego_plane_fallback_sample(run,\n"+
			"                                TEGO_RD_WORD((__u64)dentry + bpf_core_field_offset(struct dentry, d_name) +\n"+
			"                                              bpf_core_field_offset(struct qstr, name)),\n"+
			"                                dentry->d_parent->d_inode->i_ino,\n"+
			"                                (__u64)rule | (__u64)reason << 32 | (__u64)hook << 40,\n"+
			"                                (__u64)flags | (__u64)dentry->d_sb->s_dev << 32);")
	sample := functionBody(t, path, "tego_plane_fallback_sample")
	if wraps < 0 || call < wraps || !strings.Contains(sample, "tego_plane_own_sample(run, &a);") ||
		!strings.Contains(sample, "a.kind = TEGO_EV_PLANE_FS;") || !strings.Contains(sample, "a.rule = (__u32)rule_reason_hook;") ||
		!strings.Contains(sample, "a.reason = (__u8)(rule_reason_hook >> 32);") ||
		!strings.Contains(sample, "a.hook = (__u16)(rule_reason_hook >> 40);") || !strings.Contains(sample, "a.flags = (__u32)flags_dev;") ||
		!strings.Contains(sample, "a.dev = flags_dev >> 32;") || !strings.Contains(sample, "a.dir_ino = dir_ino;") ||
		!strings.Contains(sample, "a.name = name;") || !strings.Contains(sample, "a.named = 1;") {
		t.Errorf("tego_plane_fallback does not write its sample exactly where the fexit is not attached:\n%s\n%s", fallback, sample)
	}
	if !regexp.MustCompile(`(?m)^__attribute__\(\(noinline\)\) int tego_plane_fallback_sample\(`).MatchString(read(t, path)) {
		t.Error("tego_plane_fallback_sample is not a global function: a static one is verified once per call site")
	}
	if w := functionBody(t, path, "tego_recorder_wraps"); !strings.Contains(w, "bpf_map_lookup_elem(&tego_plane_recorded, &key)") ||
		!strings.Contains(w, "mask && hook < 32 && (*mask & (1U << hook))") {
		t.Errorf("tego_recorder_wraps does not read the build's mask, failing toward a sample:\n%s", w)
	}
	maps := read(t, filepath.Join(sourceDir, "include", "maps.h"))
	i := strings.Index(maps, "} tego_plane_recorded SEC")
	if i < 0 || !strings.Contains(maps[strings.LastIndex(maps[:i], "struct {"):i], "LIBBPF_PIN_BY_NAME") {
		t.Error("tego_plane_recorded is not a map pinned by name, which every launcher of the build writes and adopts")
	}
}
