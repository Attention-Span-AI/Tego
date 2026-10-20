// SPDX-License-Identifier: Apache-2.0

package bpftests

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// execPinPath is ADR 0048 P2's pin code (bprm_check's steps, the sched_process_exec check, the MAC loops).
var execPinPath = filepath.Join(sourceDir, "decide_execpin.h")

// pinDef returns the body of the function name defined (not called) in src.
func pinDef(t *testing.T, src, name string) string {
	t.Helper()
	loc := regexp.MustCompile(`(?m)^(static|__attribute__\(\(noinline\)\)) [^;{]*\b` + name + `\(`).FindStringIndex(src)
	if loc == nil {
		t.Fatalf("no definition of %s", name)
	}
	return balanced(t, src[loc[0]:], name)
}

// TestExecPinOnlyNarrows is ADR 0048 (3) P2's first source rule: a pin only refuses. bprm_check's pin step comes
// before the EXEC_DECIDES return and the #! pass, and every answer of it other than 0 is -EACCES with its sample; no
// path returns 0 because of a pin, so what the step passes the steps below still decide. The pin program returns
// nothing but 0, and its kill is the only thing it does on a mismatch.
func TestExecPinOnlyNarrows(t *testing.T) {
	t.Parallel()
	body := squash(planeBodies(t)["bprm_check"])
	step := "if (hdr->flags & TEGO_SLOT_EXEC_PIN) { reason = tego_pin_bprm(run, hdr, bprm); if (reason) { " +
		"tego_exec_sample(run, bprm, TEGO_PLANE_RULE_NONE, reason); return -EACCES; } }"
	at := strings.Index(body, step)
	if at < 0 {
		t.Fatalf("bprm_check's pin step is not the refuse-only block %q:\n%s", step, body)
	}
	for _, later := range []string{"TEGO_SLOT_EXEC_DECIDES", "bprm->buf[0] == '#'", "tego_plane_scratch_get()"} {
		if i := strings.Index(body, later); i < 0 || i < at {
			t.Errorf("bprm_check reaches %q before the pin step (or not at all)", later)
		}
	}
	pin := read(t, execPinPath)
	for _, fn := range []string{"tego_pin_first", "tego_pin_later", "tego_pin_bprm"} {
		for _, m := range regexp.MustCompile(`return\s+([^;]*);`).FindAllStringSubmatch(pinDef(t, pin, fn), -1) {
			expr := strings.TrimSpace(m[1])
			if expr != "0" && expr != "reason" && !strings.HasPrefix(expr, "TEGO_R_") &&
				!strings.HasPrefix(expr, "tego_pin_") {
				t.Errorf("%s returns %q: a pin step answers 0 or a refusal's reason", fn, expr)
			}
		}
	}
	check := pinDef(t, pin, "tego_exec_pin_check")
	if !strings.HasPrefix(regexp.MustCompile(`(?m)^static [^\n]*tego_exec_pin_check`).FindString(pin), "static __always_inline void") {
		t.Errorf("tego_exec_pin_check answers a value; the pin program decides nothing a hook returns")
	}
	if strings.Count(check, "tego_pin_kill(") != 1 {
		t.Errorf("the pin check kills from more or fewer than one place:\n%s", check)
	}
	area := squash(pinDef(t, pin, "tego_pin_area"))
	for _, m := range regexp.MustCompile(`return\s+([^;]*);`).FindAllStringSubmatch(area, -1) {
		expr := strings.TrimSpace(m[1])
		if expr == "0" {
			t.Errorf("tego_pin_area holds an area without comparing its MAC")
		}
	}
	for _, held := range []string{"want = st->pin.mac_cov;", "want = st->pin.mac_tail;",
		"return mac == want ? 0 : TEGO_R_ARGV_CHANGED;"} {
		if !strings.Contains(area, held) {
			t.Errorf("tego_pin_area lacks %q", held)
		}
	}
}

// TestExecPinHeldOnlyAfterTheMatch is ADR 0048 (8)'s proof sample: the pin check reports a held exec from one place,
// after the kill's early return and after it marked the task's outcome held, so no path that kills also says held; and
// the held sample sends no signal. The ledger's fold says kernel_pinned only on it, never on a missing kill.
func TestExecPinHeldOnlyAfterTheMatch(t *testing.T) {
	t.Parallel()
	pin := read(t, execPinPath)
	check := squash(pinDef(t, pin, "tego_exec_pin_check"))
	if strings.Count(check, "tego_pin_held(") != 1 {
		t.Fatalf("the pin check reports held from more or fewer than one place:\n%s", check)
	}
	held := strings.Index(check, "tego_pin_held(")
	kill := strings.Index(check, "tego_pin_kill(")
	ret := strings.Index(check[kill:], "return;")
	mark := strings.Index(check, "st->outcome = TEGO_PIN_OUT_HELD;")
	if kill < 0 || ret < 0 || held < kill+ret || mark < 0 || held < mark {
		t.Errorf("the held sample is not after the kill's return and the held mark:\n%s", check)
	}
	if body := pinDef(t, pin, "tego_pin_held"); strings.Contains(body, "bpf_send_signal") ||
		!strings.Contains(body, "TEGO_EV_PLANE_EXEC_HELD") || !strings.Contains(body, "tego_lost_inc(") {
		t.Errorf("tego_pin_held signals, writes another kind, or loses a sample uncounted:\n%s", body)
	}
}

// TestExecPinLoopsAreBounded: each MAC loop's callback stops at a constant bound on its index whatever its state
// says, the area MAC refuses a length past TEGO_PIN_MAX_LEN before it loops, and the spelling MAC refuses one past
// TEGO_PIN_PATH_MAX.
func TestExecPinLoopsAreBounded(t *testing.T) {
	t.Parallel()
	pin := read(t, execPinPath)
	for fn, bound := range map[string]string{
		"tego_umac_step":  "if (i >= TEGO_PIN_MAX_LEN / TEGO_PIN_STEP)",
		"tego_kmac_step":  "if (i >= TEGO_PIN_KWORDS ||",
		"tego_uword_step": "if (i >= TEGO_PIN_STEP / 8)",
	} {
		body := squash(pinDef(t, pin, fn))
		if at := strings.Index(body, bound); at < 0 || strings.Index(body, "if (") != at {
			t.Errorf("%s does not stop at %q before anything else it tests", fn, bound)
		}
	}
	area := squash(pinDef(t, pin, "tego_pin_area"))
	if strings.Count(area, "if (len > TEGO_PIN_MAX_LEN) return TEGO_R_ARGV_UNREADABLE;") != 2 {
		t.Errorf("tego_pin_area does not refuse a covered or tail length past TEGO_PIN_MAX_LEN before each MAC")
	}
	first := squash(pinDef(t, pin, "tego_pin_first"))
	if !strings.Contains(first, "if (pin->len_path > TEGO_PIN_PATH_MAX) return TEGO_R_PIN_MISMATCH;") {
		t.Errorf("tego_pin_first MACs a spelling longer than getname allows")
	}
	if n := strings.Count(pin, "bpf_loop("); n != 3 {
		t.Errorf("%d bpf_loop calls; the pin code has the area MAC's two (its chunks, then the last chunk's words) and the kernel bytes' MAC's", n)
	}
}

// TestExecPinKeepsNoPinOnTheStack: a pin (about 160 bytes) or a task's pin state never lives on the 512-byte BPF
// stack; both are map values, read through pointers. The area MAC reads into the task's own storage, never a per-CPU
// buffer (TestPlaneKeepsNoPerCPUScratch holds every map the plane uses to that).
func TestExecPinKeepsNoPinOnTheStack(t *testing.T) {
	t.Parallel()
	_, src := planeSource(t)
	if m := regexp.MustCompile(`struct\s+tego_(exec_pin|exec_armed|pin_keyval)\s+\w+\s*(\[|;|=)`).FindString(stripComments(src)); m != "" {
		t.Errorf("a pin, pin state or key on the stack: %q", m)
	}
	step := squash(pinDef(t, read(t, execPinPath), "tego_umac_step"))
	if !strings.Contains(step, "bpf_task_storage_get(&tego_plane_exec_armed, bpf_get_current_task_btf(), 0, 0)") ||
		!strings.Contains(step, "bpf_probe_read_user(st->buf, TEGO_PIN_STEP,") {
		t.Errorf("the area MAC's chunk is not read into the task's own storage:\n%s", step)
	}
	maps := read(t, filepath.Join(sourceDir, "include", "maps.h"))
	def := regexp.MustCompile(`struct\s*\{([^}]*)\}\s*tego_plane_exec_armed\s+SEC`).FindStringSubmatch(maps)
	if def == nil || !strings.Contains(def[1], "BPF_MAP_TYPE_TASK_STORAGE") {
		t.Errorf("tego_plane_exec_armed is not task storage")
	}
}

// TestExecPinStorageNullRefuses: the task-storage helper may answer NULL (its busy lock below 6.2, or no memory).
// bprm_check's first stage then refuses pin-unverifiable, a later stage pin-missing, and the area MAC's chunk loop
// stops with an error that the check turns into argv-unreadable: no NULL ever reads as a held pin.
func TestExecPinStorageNullRefuses(t *testing.T) {
	t.Parallel()
	pin := read(t, execPinPath)
	first := squash(pinDef(t, pin, "tego_pin_first"))
	if !regexp.MustCompile(`if \(!st\) return TEGO_R_PIN_UNVERIFIABLE;`).MatchString(first) {
		t.Errorf("tego_pin_first does not refuse on a NULL from the storage helper")
	}
	later := squash(pinDef(t, pin, "tego_pin_later"))
	if !strings.Contains(later, "if (!st || !st->armed) return TEGO_R_PIN_MISSING;") {
		t.Errorf("tego_pin_later does not refuse without an armed state")
	}
	step := squash(pinDef(t, pin, "tego_umac_step"))
	if !strings.Contains(step, "if (!st) { c->err = -TEGO_PIN_ENOMEM; return 1; }") {
		t.Errorf("the chunk loop goes on without its buffer")
	}
	area := squash(pinDef(t, pin, "tego_pin_area"))
	if strings.Count(area, "if (err) return TEGO_R_ARGV_UNREADABLE;") != 1 || strings.Count(area, "tego_umac(") != 1 {
		t.Errorf("tego_pin_area does not refuse an unread area after its one MAC")
	}
	check := squash(pinDef(t, pin, "tego_exec_pin_check"))
	if !strings.Contains(check, "if (!st || !st->armed) { reason = TEGO_R_PIN_MISSING;") {
		t.Errorf("the pin check does not kill a task that holds no armed pin")
	}
}

// TestExecPinUnknownTailHoldsTheVector is REXEC-PINSc1-1: an unknown-form exec that binfmt interpreted is held by its
// area's tail, and a tail check alone let a racing thread put arguments in front of the decided argv[1:]. The first
// stage keeps the vector's length the kernel copied (bprm->argc, before any binfmt stage changes it), the area check
// holds it to the pin's argc before the tail's MAC (internal/execpin's TestUnknownTailHoldsOnlyTheDecidedVector models
// the rest), and the first later stage refuses a binfmt_misc P stage, which keeps argv[0] in front of the tail, unless
// the decided argv[0] is the filename the tail starts with.
func TestExecPinUnknownTailHoldsTheVector(t *testing.T) {
	t.Parallel()
	pin := read(t, execPinPath)
	if first := squash(pinDef(t, pin, "tego_pin_first")); !strings.Contains(first, "st->argc0 = bprm->argc;") {
		t.Errorf("tego_pin_first does not keep the vector's length the kernel copied")
	}
	area := squash(pinDef(t, pin, "tego_pin_area"))
	branch := regexp.MustCompile(`if \(st->pin\.form == TEGO_PIN_FORM_UNKNOWN && interpreted\) \{(.*?)\} else if`).FindStringSubmatch(area)
	if branch == nil || !strings.Contains(branch[1], "if (st->argc0 != st->pin.argc) return TEGO_R_ARGV_CHANGED;") {
		t.Errorf("tego_pin_area's unknown-and-interpreted branch does not hold the vector's length:\n%s", area)
	}
	later := squash(pinDef(t, pin, "tego_pin_later"))
	if !strings.Contains(later, "if (s == 0 && (bprm->interp_flags & TEGO_BINPRM_PRESERVE_ARGV0) && "+
		"!(st->pin.flags & TEGO_PIN_ARGV0_FILENAME)) return TEGO_R_PIN_MISMATCH;") {
		t.Errorf("tego_pin_later admits a binfmt_misc P stage whose argv[0] the tail does not hold:\n%s", later)
	}
}

// TestExecPinGuardReadsTheLeader is REXEC-PINSc1-3: the argv-guarded mark is stored on the task that exec'd, which
// de_thread makes its thread group's leader, and a thread the new program starts later shares the leader's memory
// with no mark of its own. The guard the ptrace hooks read answers for the target or, when the target is another
// thread, for its group leader.
func TestExecPinGuardReadsTheLeader(t *testing.T) {
	t.Parallel()
	guarded := squash(pinDef(t, read(t, execPinPath), "tego_pin_guarded"))
	for _, want := range []string{"st = tego_pin_state(run, t); if (st && st->guarded) return 1;",
		"leader = t->group_leader; if (!leader || leader == t) return 0; st = tego_pin_state(run, leader); return st && st->guarded;"} {
		if !strings.Contains(guarded, want) {
			t.Errorf("tego_pin_guarded lacks %q:\n%s", want, guarded)
		}
	}
}

// TestExecPinKillNamesTheRecordsSeq is REXEC-PINSc2-1: the ledger's fold pairs an exec's record with the plane's
// sample by seq alone, so every sample of the pin check names the seq the recorder's exec record reads as its
// pin_seq, the task's cur_seq. The check reads it before its first branch, so a kill of a slot cleared since
// bprm_check, or of an exec no pin was armed for, names it as a kill of a pin that did not hold does; a kill naming 0
// there would pair with any earlier exec's waiting record. cur_seq is written only by bprm_check's first stage, so the
// two programs of one sched_process_exec read one value in either order. The held sample names the pin it checked.
func TestExecPinKillNamesTheRecordsSeq(t *testing.T) {
	t.Parallel()
	pin := read(t, execPinPath)
	check := squash(pinDef(t, pin, "tego_exec_pin_check"))
	look := strings.Index(check, "st = tego_pin_state(run, bpf_get_current_task_btf()); if (st) seq = st->cur_seq;")
	cleared := strings.Index(check, "if (!hdr) {")
	if look < 0 || cleared < look || strings.Count(check, "seq = st->") != 1 || strings.Count(check, "tego_pin_kill(run, (__u32)old_pid, (__u64)seq |") != 1 {
		t.Errorf("the pin check's kill does not name the task's cur_seq on every path, the cleared slot's included:\n%s", check)
	}
	if !strings.Contains(check, "tego_pin_held(run, (__u32)old_pid, st->pin.seq);") {
		t.Errorf("the held sample does not name the pin the check read:\n%s", check)
	}
	if rec := squash(pinDef(t, read(t, filepath.Join(sourceDir, "trace_proc.bpf.c")), "tego_exec_pin_seq")); !strings.Contains(rec,
		"if (!st || st->run_idx != run->run_idx || st->gen != run->gen) return 0; return st->cur_seq;") {
		t.Errorf("the exec record's pin_seq is not the task's cur_seq of the run, as tego_pin_state reads it:\n%s", rec)
	}
	first := squash(pinDef(t, pin, "tego_pin_first"))
	if strings.Count(squash(pin), "cur_seq = ") != strings.Count(first, "cur_seq = ") || strings.Count(first, "cur_seq = ") != 2 {
		t.Errorf("cur_seq is written outside bprm_check's first stage, or that stage does not reset and set it")
	}
	for _, glob := range []string{"*.bpf.c", "*.h", filepath.Join("include", "*.h")} {
		paths, err := filepath.Glob(filepath.Join(sourceDir, glob))
		if err != nil || len(paths) == 0 {
			t.Fatalf("no %s under %s: %v", glob, sourceDir, err)
		}
		for _, src := range paths {
			if src != execPinPath && strings.Contains(read(t, src), "cur_seq =") {
				t.Errorf("%s writes cur_seq", src)
			}
		}
	}
}
