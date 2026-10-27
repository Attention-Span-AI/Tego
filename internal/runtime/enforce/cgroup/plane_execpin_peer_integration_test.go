// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"strings"
	"testing"
)

// execPinPeerAgent runs one attempt per argument, each "kind:path:w1,w2" (an image and its vector), and prints each
// attempt's spec, pid and result code:
//
//   - exec: a child execs the image; the code is its exit status (the errno of a refused execve, -9 for SIGKILL);
//   - traced: a child asks to be traced (PTRACE_TRACEME) and execs the image, the agent resuming it at its exec stop;
//     the code is its exit status;
//   - guard: a child execs the image (a sleeper), and once it runs the agent writes one byte at its argument area with
//     process_vm_writev and then tries PTRACE_ATTACH; the code is the first's errno * 100 + the second's;
//   - guardthread: as guard, at a thread of the image that is not its leader (a Go sleeper starts its runtime's
//     threads at once), which shares the leader's memory, argument area included.
const execPinPeerAgent = `import ctypes, os, sys, time
libc = ctypes.CDLL(None, use_errno=True)
class iovec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]
libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
libc.process_vm_writev.argtypes = [ctypes.c_int, ctypes.POINTER(iovec), ctypes.c_ulong, ctypes.POINTER(iovec),
                                   ctypes.c_ulong, ctypes.c_ulong]
def wait_exit(pid):
    while True:
        _, st = os.waitpid(pid, 0)
        if os.WIFSTOPPED(st):
            libc.ptrace(7, pid, None, None)  # PTRACE_CONT
            continue
        return os.waitstatus_to_exitcode(st)
def arg_start(pid):
    stat = open("/proc/%d/stat" % pid).read()
    return int(stat[stat.rindex(")") + 2:].split()[45])
for spec in sys.argv[1:]:
    kind, path, words = spec.split(":")
    argv = words.split(",")
    pid = os.fork()
    if pid == 0:
        if kind == "traced" and libc.ptrace(0, 0, None, None) != 0:  # PTRACE_TRACEME
            os._exit(98)
        try:
            os.execve(path, argv, {})
        except OSError as e:
            os._exit(e.errno)
    if kind not in ("guard", "guardthread"):
        print("RESULT", spec, pid, wait_exit(pid), flush=True)
        continue
    for _ in range(200):
        try:
            if os.readlink("/proc/%d/exe" % pid).endswith(path[1:]):
                break
        except OSError:
            pass
        time.sleep(0.01)
    time.sleep(0.05)
    target = pid
    if kind == "guardthread":
        for _ in range(200):
            tids = sorted(int(x) for x in os.listdir("/proc/%d/task" % pid) if int(x) != pid)
            if tids:
                target = tids[0]
                break
            time.sleep(0.01)
        else:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
            print("RESULT", spec, pid, 97, flush=True)
            continue
    one = ctypes.create_string_buffer(b"x")
    local, remote = iovec(ctypes.addressof(one), 1), iovec(arg_start(pid), 1)
    w = 0 if libc.process_vm_writev(target, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0) == 1 else ctypes.get_errno()
    a = 0
    if libc.ptrace(16, target, None, None) != 0:  # PTRACE_ATTACH
        a = ctypes.get_errno()
    else:
        os.waitpid(target, 0x40000000)  # __WALL: a thread that is not the leader is a clone child
        libc.ptrace(17, target, None, None)  # PTRACE_DETACH
    os.kill(pid, 9)
    os.waitpid(pid, 0)
    print("RESULT", spec, pid, w * 100 + a, flush=True)
`

// execPinPeerContract is a deny-list run of execPinPeerAgent: every image runs, and every exec is pinned because the
// run has command rules. tool is a tool no row knows (a deny entry reads it anywhere); git is git's row, which reads
// a dashed argv[0] (git-status) as its subcommand, so that exec is decided on argv[0] alone (k = 1).
func execPinPeerContract(args ...string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = `"` + a + `"`
	}
	return `version: 0
name: exec-pin-peer
command: ["python3", "./agent.py", ` + strings.Join(q, ", ") + `]
fs:
  write: ["./out/"]
exec:
  deny: ["tool push", "git push"]
net:
  allow: []
env:
  pass: ["PATH", "HOME"]
record: full
`
}

// runExecPinPeer runs execPinPeerAgent at cell with images bin/tool, bin/git and bin/other, each execracer, which
// run as `<any> <seconds>` sleeps (a copy of /bin/sleep may be a multi-call binary that dispatches on argv[0]), and the
// extra files.
func runExecPinPeer(t *testing.T, bin string, uid, gid int, cell string, extra map[string]string, args ...string) (string, []map[string]any) {
	t.Helper()
	return runExecPinPeerEnv(t, bin, uid, gid, cell, extra, nil, args...)
}

// runExecPinPeerEnv is runExecPinPeer with env added to tego's environment.
func runExecPinPeerEnv(t *testing.T, bin string, uid, gid int, cell string, extra map[string]string, env []string,
	args ...string) (string, []map[string]any) {
	t.Helper()
	sleep := buildExecRacer(t)
	files := map[string]string{"agent.py": execPinPeerAgent, "bin/tool": sleep, "bin/git": sleep, "bin/other": sleep}
	for k, v := range extra {
		files[k] = v
	}
	return runExecPinAgentEnv(t, bin, uid, gid, cell, execPinPeerContract(args...), nil, files, env)
}

// TestPlaneRunExecPinTraced is ADR 0048 P2's K6 traced cell ((3) bprm_check step 4): a guarded exec of a task that
// already has a tracer (PTRACE_TRACEME) is refused at bprm_check, exec-traced (EACCES), since the tracer would get
// the exec stop and could rewrite argv in the new image before the program reads it; so is a k = 1 dashed-form exec
// (git-status), decided on argv[0] alone. The control, a traced exec of an image no rule guards, runs.
func TestPlaneRunExecPinTraced(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	guarded, dashed, control := "traced:./bin/tool:tool,0", "traced:./bin/git:git-status,0", "traced:./bin/other:other,0"
	for _, cell := range execPinCells(modes) {
		t.Run(cell, func(t *testing.T) {
			out, events := runExecPinPeer(t, bin, uid, gid, cell, nil, guarded, dashed, control)
			wantExits(t, out, map[string]int{guarded: 13, dashed: 13, control: 0})
			_, pids := execPinResults(t, out)
			for _, spec := range []string{guarded, dashed} {
				lines := execLinesOf(events, pids[spec])
				if len(lines) != 1 || lines[0]["verdict"] != "refused" || lines[0]["rule"] != "exec.pin" ||
					lines[0]["plane_reason"] != "exec-traced" || lines[0]["signal"] != nil {
					t.Errorf("%s: exec lines %v, want one exec.pin refusal, exec-traced", spec, lines)
				}
			}
			wantOnePinnedRun(t, control, execLinesOf(events, pids[control]))
			if rules := execRulesOf(t, events); rules == nil || rules["pin_refused"] != float64(2) || rules["killed"] != nil {
				t.Errorf("run_end exec_rules %v, want pin_refused 2 and no kill", rules)
			}
		})
	}
}

// TestPlaneRunExecPinGuardedPtrace is ADR 0048 P2's K6 guarded ptrace cell ((3) "After the check"): once a guarded
// exec matched its pin the task is argv-guarded, so a peer of the same run can neither write into it with
// process_vm_writev nor attach to it with PTRACE_ATTACH (the plane's ptrace_access_check refuses, process-scope;
// the first call reports EPERM, the second EACCES), for a k = 1 dashed-form exec as well, nor into a thread the
// guarded program started after its exec, whose memory is the leader's (the mark is the exec'ing task's, and the
// hooks read the target's thread group leader too). The control, a process no rule guards, takes both.
func TestPlaneRunExecPinGuardedPtrace(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	guarded, dashed, control := "guard:./bin/tool:tool,30", "guard:./bin/git:git-status,30", "guard:./bin/other:other,30"
	thread := "guardthread:./bin/tool:tool,31"
	// process_vm_writev reports the hook's refusal as EPERM (mm_access's EACCES mapped, as doctor's cell found);
	// PTRACE_ATTACH returns the hook's EACCES as it is.
	const refused = 1*100 + 13
	for _, cell := range execPinCells(modes) {
		t.Run(cell, func(t *testing.T) {
			out, events := runExecPinPeer(t, bin, uid, gid, cell, nil, guarded, dashed, control, thread)
			wantExits(t, out, map[string]int{guarded: refused, dashed: refused, control: 0, thread: refused})
			_, pids := execPinResults(t, out)
			for _, spec := range []string{guarded, dashed, control, thread} {
				wantOnePinnedRun(t, spec, execLinesOf(events, pids[spec]))
			}
			scope := 0
			for _, e := range events {
				if e["kind"] == "refused" && e["rule"] == "process-scope" {
					scope++
				}
			}
			if scope < 6 {
				t.Errorf("%d process-scope refusals, want one per refused call (6)", scope)
			}
			wantNoKill(t, events)
		})
	}
}

// TestPlaneRunExecPinInterpreted is ADR 0048 P2's K6 interpreted cell: a script run through `#!/usr/bin/env python3`
// (the guest has no node; env then execs python3, a second exec with its own pin) and a two-stage script (its #!
// names another script, whose #! names /bin/sh: two binfmt_script stages in one exec) each run pinned, every exec
// line saying kernel_pinned.
func TestPlaneRunExecPinInterpreted(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	env, two := "exec:./out/envpy:envpy", "exec:./out/two:two"
	scripts := map[string]string{
		"out/envpy": "#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n",
		"out/two":   "#!./out/stage\nexit 0\n",
		"out/stage": "#!/bin/sh\nexit 0\n",
	}
	for _, cell := range execPinCells(modes) {
		t.Run(cell, func(t *testing.T) {
			out, events := runExecPinPeer(t, bin, uid, gid, cell, scripts, env, two)
			wantExits(t, out, map[string]int{env: 0, two: 0})
			_, pids := execPinResults(t, out)
			if lines := execLinesOf(events, pids[env]); len(lines) != 2 {
				t.Errorf("%s: exec lines %v, want two (env, then python3)", env, lines)
			} else {
				for _, l := range lines {
					wantOnePinnedRun(t, env, []map[string]any{l})
				}
			}
			wantOnePinnedRun(t, two, execLinesOf(events, pids[two]))
			wantNoKill(t, events)
		})
	}
}

// TestPlaneRunExecPinUnpinned is ADR 0048 P2's K6 unpinned cell: in a pinned run, an exec the supervisor continued
// without writing its pin (a test hook, TEGO_TEST_EXEC_PIN_SKIP, skips the write for the image named other, as a
// lost write would) is refused at bprm_check, pin-missing (EACCES), never run; the run's other execs run pinned.
func TestPlaneRunExecPinUnpinned(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	skipped, pinned := "exec:./bin/other:other,0", "exec:./bin/tool:tool,0"
	for _, cell := range execPinCells(modes) {
		t.Run(cell, func(t *testing.T) {
			out, events := runExecPinPeerEnv(t, bin, uid, gid, cell, nil, []string{"TEGO_TEST_EXEC_PIN_SKIP=other"},
				skipped, pinned)
			wantExits(t, out, map[string]int{skipped: 13, pinned: 0})
			_, pids := execPinResults(t, out)
			lines := execLinesOf(events, pids[skipped])
			if len(lines) != 1 || lines[0]["verdict"] != "refused" || lines[0]["rule"] != "exec.pin" ||
				lines[0]["plane_reason"] != "pin-missing" || lines[0]["signal"] != nil {
				t.Errorf("the unpinned exec: lines %v, want one exec.pin refusal, pin-missing", lines)
			}
			wantOnePinnedRun(t, pinned, execLinesOf(events, pids[pinned]))
			if rules := execRulesOf(t, events); rules == nil || rules["pin_refused"] != float64(1) || rules["killed"] != nil {
				t.Errorf("run_end exec_rules %v, want pin_refused 1 and no kill", rules)
			}
		})
	}
}

// wantOnePinnedRun checks that lines is one exec line that ran and says kernel_pinned (allow, or observed in a
// deny-list section).
func wantOnePinnedRun(t *testing.T, what string, lines []map[string]any) {
	t.Helper()
	if len(lines) != 1 || lines[0]["verdict"] == "refused" || lines[0]["argv_facts"] != "kernel_pinned" {
		t.Errorf("%s: exec lines %.800v, want one run that says kernel_pinned", what, lines)
	}
}
