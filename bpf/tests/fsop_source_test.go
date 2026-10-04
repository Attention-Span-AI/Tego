// SPDX-License-Identifier: Apache-2.0

package bpftests

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fsopDirRe matches one tego_fsop_dir call and captures the buffer it fills (e->dir, e->dir2).
var fsopDirRe = regexp.MustCompile(`tego_fsop_dir\(\s*run\s*,\s*(e->[a-z0-9_]+)\s*,`)

// Exec intent is a kernel-private f_flags bit. FMODE_EXEC in file->f_mode would miss Landlock's refused image
// opens, because file allocation sets f_mode from access bits alone. The successful exec's old_pid likewise
// must come from the tracepoint argument before de_thread changed it, rather than the current task id.
func TestRecorderPreservesExecOpenIntentAndOriginalTID(t *testing.T) {
	t.Parallel()
	path := filepath.Join(sourceDir, "trace_proc.bpf.c")
	fill := squash(functionBody(t, path, "tego_fs_fill"))
	if !strings.Contains(fill, "e->exec_open = (e->flags & TEGO_FMODE_EXEC) ? 1 : 0;") {
		t.Error("image-open intent must come from the kernel's f_flags, including early LSM refusals")
	}
	if !regexp.MustCompile(`(?m)^#define\s+TEGO_FMODE_EXEC\s+0x00000020\b`).MatchString(read(t, path)) {
		t.Error("image-open marker must use the kernel-private __FMODE_EXEC bit")
	}
	for _, p := range programs(t, path) {
		if p.name == "tego_sched_exec" {
			if !strings.Contains(squash(p.body), "e->old_tid = old_pid;") {
				t.Error("successful exec must preserve the tracepoint's original executing thread id")
			}
			return
		}
	}
	t.Fatal("trace_proc.bpf.c: no program tego_sched_exec")
}

func TestExecResultsAreRunScopedNegativeAndShared(t *testing.T) {
	t.Parallel()
	path := filepath.Join(sourceDir, "trace_proc.bpf.c")
	body := squash(functionBody(t, path, "tego_exec_result_emit"))
	lookup, miss, ret, skip, reserve := strings.Index(body, "tego_run_lookup(&tego_run_set, cgroup_id)"),
		strings.Index(body, "if (!run) return 0;"), strings.Index(body, "ret = ctx->ret;"),
		strings.Index(body, "if (ret >= 0) return 0;"), strings.Index(body, "bpf_ringbuf_reserve(")
	if lookup < 0 || miss < lookup || ret < miss || skip < ret || reserve < skip {
		t.Error("exec result must consult the run scope first and reserve only for a negative syscall return")
	}
	if strings.Contains(body, "tego_recording(") {
		t.Error("failed exec attempts must retain their result under record: off")
	}
	for _, want := range []string{"TEGO_EV_EXEC_RESULT", "e->start_ns = tego_task_start();", "e->ret = ret;"} {
		if !strings.Contains(body, want) {
			t.Errorf("exec result does not preserve its identity and signed result: missing %s", want)
		}
	}
	seen := 0
	for _, p := range programs(t, path) {
		if p.name != "tego_exec_result" && p.name != "tego_execat_result" {
			continue
		}
		seen++
		if squash(p.body) != "{ return tego_exec_result_emit(ctx); }" {
			t.Errorf("%s must share the same result writer", p.name)
		}
	}
	if seen != 2 {
		t.Fatalf("%d failed-exec result producers, want execve and execveat", seen)
	}
}

func TestExecResultsExcludeInternalRestartsBeforeReservation(t *testing.T) {
	t.Parallel()
	path := filepath.Join(sourceDir, "trace_proc.bpf.c")
	body := squash(functionBody(t, path, "tego_exec_result_emit"))
	skip, ring, reserve := strings.Index(body, "if (tego_exec_restart(ret)) return 0;"),
		strings.Index(body, "ring = tego_ring_of("), strings.Index(body, "bpf_ringbuf_reserve(")
	if skip < 0 || ring < skip || reserve < ring {
		t.Fatal("internal exec restarts must be ignored before ring accounting or emission")
	}
	restart := squash(functionBody(t, path, "tego_exec_restart"))
	for name, value := range map[string]string{
		"ERESTARTSYS": "512", "ERESTARTNOINTR": "513", "ERESTARTNOHAND": "514", "ERESTART_RESTARTBLOCK": "516",
	} {
		if !regexp.MustCompile(`(?m)^#define\s+TEGO_`+name+`\s+`+value+`\b`).MatchString(read(t, path)) ||
			!strings.Contains(restart, "ret == -TEGO_"+name) {
			t.Errorf("exec restart guard does not exclude Linux %s (-%s)", name, value)
		}
	}
}

func TestExecInterpreterMarkerUsesTheKernelBinfmtState(t *testing.T) {
	t.Parallel()
	for _, p := range programs(t, filepath.Join(sourceDir, "trace_proc.bpf.c")) {
		if p.name != "tego_sched_exec" {
			continue
		}
		body := squash(p.body)
		for _, want := range []string{"filename = TEGO_READ(bprm, filename);", "e->interpreted = TEGO_READ(bprm, interp) != filename;"} {
			if !strings.Contains(body, want) {
				t.Errorf("interpreter argv rewriting must be marked from binfmt state: missing %s", want)
			}
		}
		return
	}
	t.Fatal("trace_proc.bpf.c: no successful exec producer")
}

// TestFsopProgramsWalkEachDirOnce pins that a filesystem-op program walks each side's parent directory once on any
// one path: a second tego_fsop_dir into the same buffer is allowed only after a return, on another branch. The held
// create in tego_path_mknod walked its directory twice back to back (a merge leftover): the whole two-pass dentry
// walk ran again on every O_CREAT open, and a directory path of exactly TEGO_PATH_MAX bytes left dir[0] set, so the
// second walk read it as not-zeroed and recorded DIR_NONE.
func TestFsopProgramsWalkEachDirOnce(t *testing.T) {
	t.Parallel()
	seen := 0
	for _, p := range programs(t, filepath.Join(sourceDir, "trace_proc.bpf.c")) {
		calls := fsopDirRe.FindAllStringSubmatchIndex(p.body, -1)
		if len(calls) == 0 {
			continue
		}
		seen++
		last := map[string]int{}
		for _, c := range calls {
			buf := p.body[c[2]:c[3]]
			if prev, ok := last[buf]; ok && !regexp.MustCompile(`\breturn\b`).MatchString(p.body[prev:c[0]]) {
				t.Errorf("%s walks %s twice on one path: a second tego_fsop_dir with no return between", p.name, buf)
			}
			last[buf] = c[1]
		}
	}
	if seen == 0 {
		t.Fatal("trace_proc.bpf.c: no program calls tego_fsop_dir")
	}
}

// TestSymlinkTargetOfNameMaxMinusOneIsWhole pins that a 255-byte symlink target is recorded whole: its read returns
// TEGO_NAME_MAX (the NUL fills the buffer's last byte) exactly as a longer, cut one does, so the program asks
// whether the 256th source byte is the NUL, as the exec path does for its filename, in both builds.
func TestSymlinkTargetOfNameMaxMinusOneIsWhole(t *testing.T) {
	t.Parallel()
	path := filepath.Join(sourceDir, "trace_proc.bpf.c")
	body := ""
	for _, p := range programs(t, path) {
		if p.name == "tego_path_symlink" {
			body = p.body
		}
	}
	if body == "" {
		t.Fatal("trace_proc.bpf.c: no program tego_path_symlink")
	}
	for _, rdonly := range []bool{false, true} {
		flat := strings.Join(strings.Fields(readerBuild(t, body, rdonly)), " ")
		if !regexp.MustCompile(`n == TEGO_NAME_MAX\)`).MatchString(flat) {
			t.Errorf("rdonly=%v: tego_path_symlink does not treat a read of TEGO_NAME_MAX apart", rdonly)
		}
		probe := `bpf_probe_read_kernel\(&c, 1, old_name \+ TEGO_NAME_MAX - 1\) == 0 && c == 0\) e->name2_ok = 1;`
		if rdonly {
			probe = `tego_kbyte\(\(__u64\)old_name \+ TEGO_NAME_MAX - 1\) == 0\) e->name2_ok = 1;`
		}
		if !regexp.MustCompile(probe).MatchString(flat) {
			t.Errorf("rdonly=%v: tego_path_symlink marks a 255-byte target cut: it must probe the 256th byte (%s)",
				rdonly, probe)
		}
	}
}
