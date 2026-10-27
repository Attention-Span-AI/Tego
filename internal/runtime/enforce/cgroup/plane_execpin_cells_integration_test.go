// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/execpin"
)

// execPinShapesAgent forks once per argument and, in the child, execs ./bin/<name> with the vector the argument
// describes, printing each attempt's spec, pid and exit status (the errno of a refused execve, or -9 for SIGKILL):
//
//   - big:N:w1,w2: the words, then filler elements of up to 32 KiB until the vector's bytes, each element's NUL
//     counted, are exactly N;
//   - many:N:w1,w2: the words, then N paths of 20 bytes;
//   - thread:w1,w2: the words, exec'd from a thread that is not the process's leader.
//
// The image is ./bin/<w1>.
const execPinShapesAgent = `import os, sys, threading
def vector(spec):
    kind, _, rest = spec.partition(":")
    if kind == "thread":
        return kind, rest.split(",")
    n, _, words = rest.partition(":")
    argv = words.split(",")
    if kind == "many":
        return kind, argv + ["p%019d" % i for i in range(int(n))]
    left = int(n) - sum(len(a) + 1 for a in argv)
    while left > 0:
        take = min(left, 32768)
        argv.append("x" * (take - 1))
        left -= take
    return kind, argv
def run(argv):
    try:
        os.execve("./bin/" + argv[0], argv, {})
    except OSError as e:
        os._exit(e.errno)
for spec in sys.argv[1:]:
    kind, argv = vector(spec)
    pid = os.fork()
    if pid == 0:
        if kind == "thread":
            t = threading.Thread(target=run, args=(argv,))
            t.start()
            t.join()
            os._exit(99)
        run(argv)
    _, st = os.waitpid(pid, 0)
    print("RESULT", spec, pid, os.waitstatus_to_exitcode(st), flush=True)
`

// execLinesOfSpec returns the ledger's exec lines of the agent's attempt spec, found by its pid (a long vector's line
// may carry no argv to match on).
func execLinesOfSpec(t *testing.T, out string, events []map[string]any, spec string) []map[string]any {
	t.Helper()
	_, pids := execPinResults(t, out)
	return execLinesOf(events, pids[spec])
}

// logExecLines logs each exec line's path, verdict, rule, argv_facts and first two argv elements, for a failure.
func logExecLines(t *testing.T, events []map[string]any) {
	t.Helper()
	for _, e := range events {
		if e["kind"] != "exec" {
			continue
		}
		argv := strSlice(e["argv"])
		t.Logf("exec %v pid %v: %v %v %v, %d elements %.80q", e["path"], e["pid"], e["verdict"], e["rule"],
			e["argv_facts"], len(argv), argv[:min(len(argv), 2)])
	}
}

// logRaceShape logs a race cell's exec lines by shape (verdict, rule, plane_reason, argv_facts, argv_from, the
// image's name, syscall_ret, signal) and its gap lines by why, to say where a count went.
func logRaceShape(t *testing.T, events []map[string]any) {
	t.Helper()
	shapes := map[string]int{}
	for _, e := range events {
		if e["kind"] == "exec" {
			shapes[fmt.Sprintf("%v %v %v %v %v %s %v %v", e["verdict"], e["rule"], e["plane_reason"], e["argv_facts"],
				e["argv_from"], filepath.Base(fmt.Sprint(e["path"])), e["syscall_ret"], e["signal"])]++
		}
	}
	t.Logf("exec lines by shape: %v; gaps: %v", shapes, gapCounts(events))
}

// gapCounts sums the run's gap lines by why.
func gapCounts(events []map[string]any) map[string]int {
	gaps := map[string]int{}
	for _, e := range events {
		if e["kind"] == "gap" {
			c, _ := e["count"].(float64)
			gaps[fmt.Sprint(e["why"])] += max(int(c), 1)
		}
	}
	return gaps
}

// recordLossGaps are the gaps of records the run lost on their way to the ledger: past one, a race cell's exact
// counts cannot hold, so the cell says the loss rather than a count.
var recordLossGaps = []string{"ringbuf-full", "channel-full", "exec-fragment-overflow"}

// wantExits checks the agent's exit status for each spec.
func wantExits(t *testing.T, out string, want map[string]int) {
	t.Helper()
	codes, _ := execPinResults(t, out)
	for spec, code := range want {
		if got, ok := codes[spec]; !ok || got != code {
			t.Fatalf("%.40s exited %d (seen %v), want %d:\n%.2000s", spec, got, ok, code, out)
		}
	}
}

// wantOnePinnedAllow checks that lines is one allow line that says kernel_pinned.
func wantOnePinnedAllow(t *testing.T, what string, lines []map[string]any) {
	t.Helper()
	if len(lines) != 1 || lines[0]["verdict"] != "allow" || lines[0]["argv_facts"] != "kernel_pinned" {
		t.Errorf("%s: exec lines %.800v, want one allow that says kernel_pinned", what, lines)
	}
}

// wantNoKill checks run_end's exec_rules for no kill and no pin refusal.
func wantNoKill(t *testing.T, events []map[string]any) {
	t.Helper()
	if rules := execRulesOf(t, events); rules == nil || rules["killed"] != nil || rules["pin_refused"] != nil {
		t.Errorf("run_end exec_rules %v, want no kill and no pin refusal", rules)
	}
}

// TestPlaneRunExecPinLargeArgv is ADR 0048 P2's K6 large argv cell: under a tail-dependent rule (deny `tool log
// --force` on a tool no row knows, whose option may then sit anywhere in the vector) a vector of exactly 128 KiB, each
// element's NUL counted (execpin.MaxArea, the supervisor's read budget, R7), whose elements are each longer than the
// recorder's per-string bound, is read whole, decided, pinned whole and runs; one byte more is past the bound, so the
// decision cannot be made on the whole vector and the supervisor refuses it args-unreadable (EACCES), never the plane.
func TestPlaneRunExecPinLargeArgv(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	if execpin.MaxArea != 128*1024 {
		t.Fatalf("execpin.MaxArea %d: the cell is written for 128 KiB", execpin.MaxArea)
	}
	whole, over := fmt.Sprintf("big:%d:tool,log", execpin.MaxArea), fmt.Sprintf("big:%d:tool,log", execpin.MaxArea+1)
	for _, cell := range execPinCells(modes) {
		t.Run(cell, func(t *testing.T) {
			out, events := runExecPinAgent(t, bin, uid, gid, cell, execPinContract("  deny: [\"tool log --force\"]\n"),
				[]string{whole, over}, map[string]string{"agent.py": execPinShapesAgent})
			wantExits(t, out, map[string]int{whole: 0, over: 13})
			wantOnePinnedAllow(t, "the 128 KiB vector", execLinesOfSpec(t, out, events, whole))
			refused := execLinesOfSpec(t, out, events, over)
			if len(refused) != 1 || refused[0]["rule"] != "args-unreadable" || refused[0]["signal"] != nil ||
				refused[0]["mechanism"] == "plane" {
				t.Errorf("the vector one byte over: %d refused lines, want one supervisor args-unreadable refusal: %.800v",
					len(refused), refused)
			}
			wantNoKill(t, events)
			if t.Failed() {
				logExecLines(t, events)
			}
		})
	}
}

// TestPlaneRunExecPinPrefix is ADR 0048 P2's K6 prefix cell: under `allow: [git add]` (here the path entry
// `./bin/git add`), `git add` with 10,000 paths of 20 bytes, about 210 KB, past the 128 KiB budget, is decided on its
// prefix and runs pinned (R7: an exec decided on its prefix is not refused for its length); and a word past the
// prefix the supervisor read (its first stage reads 32 elements, so the pin covers those) rewritten while the kernel
// copies the vector (execracer -tail flips the 43rd) never changes the verdict: every attempt runs, none is refused or
// killed.
func TestPlaneRunExecPinPrefix(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	racer := buildExecRacer(t)
	tool, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	const attempts = 500
	contract := func(command string) string {
		return `version: 0
name: exec-pin-prefix
command: ` + command + `
fs:
  write: ["./out/"]
exec:
  allow: ["python3", "./bin/execracer", "./bin/git add"]
net:
  allow: []
env:
  pass: ["PATH", "HOME"]
record: full
`
	}
	many := "many:10000:git,add"
	for _, cell := range execPinCells(modes) {
		t.Run(cell, func(t *testing.T) {
			out, events := runExecPinAgent(t, bin, uid, gid, cell, contract(`["python3", "./agent.py", "`+many+`"]`), nil,
				map[string]string{"agent.py": execPinShapesAgent, "bin/git": string(tool), "bin/execracer": racer})
			wantExits(t, out, map[string]int{many: 0})
			wantOnePinnedAllow(t, "git add with 10,000 paths", execLinesOfSpec(t, out, events, many))
			wantNoKill(t, events)

			rep, events := runPinRace(t, bin, uid, gid, cell,
				contract(fmt.Sprintf(`["./bin/execracer", "-tail", "./bin/git", "%d", "./out/report"]`, attempts)),
				map[string]string{"bin/execracer": racer, "bin/git": string(tool)})
			if rep.ran != attempts {
				t.Errorf("tail race: %+v, want every attempt to run", rep)
			}
			var lines int
			for _, e := range events {
				if e["kind"] != "exec" || !strings.HasSuffix(fmt.Sprint(e["path"]), "/bin/git") {
					continue
				}
				lines++
				// The decision read the prefix stage's 32 elements and no more, so the pin covers those; the word
				// the racer flips is the 43rd.
				if e["verdict"] != "allow" || e["argv_facts"] != "kernel_pinned" || e["argv_read"] != float64(32) {
					t.Fatalf("tail race: a git add line %v, want an allow that read 32 elements and says kernel_pinned", e)
				}
			}
			if lines != attempts {
				t.Errorf("tail race: %d git add lines, want %d", lines, attempts)
			}
			wantNoKill(t, events)
		})
	}
}

// TestPlaneRunExecPinNonLeader is ADR 0048 P2's K6 non-leader cell: an exec from a thread that is not its process's
// leader runs pinned. The pin is keyed by the exec's own thread; the kernel's de_thread hands the leader's pid to it
// before sched_process_exec, which K0 measured on every row, 5.14 and 6.1 included.
func TestPlaneRunExecPinNonLeader(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	for _, cell := range execPinCells(modes) {
		t.Run(cell, func(t *testing.T) {
			thread := "thread:tool,status"
			out, events := runExecPinAgent(t, bin, uid, gid, cell, execPinContract("  deny: [\"tool push\"]\n"),
				[]string{thread}, map[string]string{"agent.py": execPinShapesAgent})
			wantExits(t, out, map[string]int{thread: 0})
			wantOnePinnedAllow(t, "the non-leader exec", execLinesOfSpec(t, out, events, thread))
			wantNoKill(t, events)
		})
	}
}

// TestPlaneRunExecPinScriptRewrite is ADR 0048 P2's K6 script rewrite cell: a thread rewrites the option on the
// script's #! line in place ("-e", then "-x") while the agent execs it. The script pin covers binfmt_script's whole
// vector, the line's option included, so an exec whose kernel vector holds the other option is killed at
// sched_process_exec (argv-changed, SIGKILL) before the interpreter's first instruction.
func TestPlaneRunExecPinScriptRewrite(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	racer := buildExecRacer(t)
	for _, cell := range execPinCells(modes) {
		t.Run(cell, func(t *testing.T) {
			// Byte 11 of the script is the option's letter.
			rep, events := runPinRace(t, bin, uid, gid, cell, execPinRaceContract("-flip", "./out/git", "11", "e", "x"),
				map[string]string{"bin/execracer": racer, "out/git": "#!/bin/sh -e\nexit 0\n"})
			checkPinRace(t, cell, rep, events, "", "argv-changed")
		})
	}
}

// TestPlaneRunExecPinSymlinkSwap is ADR 0048 P2's K6 symlink swap cell: a thread points ./out/l at one image, then at
// another, while the agent execs ./out/l. The supervisor's walk decides on the file the link named then, and the pin
// holds that file's identity; when the kernel's walk opens the other, bprm_check refuses it pin-mismatch (EACCES).
// Every attempt runs pinned or is that refusal, each one line, and on a machine with more than one CPU the race is
// won at least once.
func TestPlaneRunExecPinSymlinkSwap(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	racer := buildExecRacer(t)
	tool, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	for _, cell := range execPinCells(modes) {
		t.Run(cell, func(t *testing.T) {
			rep, events := runPinRace(t, bin, uid, gid, cell, execPinRaceContract("-swap", "./out/l", "./out/l",
				"../bin/a/git", "../bin/b/git"), map[string]string{"bin/execracer": racer, "bin/a/git": string(tool),
				"bin/b/git": string(tool)})
			checkPinRace(t, cell, rep, events, "pin-mismatch", "")
		})
	}
}

// TestPlaneRunExecPinInterpreterSwap is ADR 0048 P2's K6 interpreter swap cell: a script's #! line names ./out/l, a
// same-named interpreter a thread replaces (the link points at one copy of /bin/sh, then at another) in a directory
// the agent can write. The pin holds the interpreter the supervisor read; when binfmt_script opens the other, the
// later stage's bprm_check refuses it pin-mismatch (EACCES).
func TestPlaneRunExecPinInterpreterSwap(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	racer := buildExecRacer(t)
	sh, err := os.ReadFile("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, cell := range execPinCells(modes) {
		t.Run(cell, func(t *testing.T) {
			rep, events := runPinRace(t, bin, uid, gid, cell, execPinRaceContract("-swap", "./out/git", "./out/l",
				"../bin/a/sh", "../bin/b/sh"), map[string]string{"bin/execracer": racer, "bin/a/sh": string(sh),
				"bin/b/sh": string(sh), "out/git": "#!./out/l\nexit 0\n"})
			checkPinRace(t, cell, rep, events, "pin-mismatch", "")
		})
	}
}

// TestPlaneRunExecPinKillFailed is ADR 0048 P2's K6 kill-failed cell: the script rewrite race, run by a binary whose
// test hook (TEGO_TEST_EXEC_PIN_KILL_ERR, tegotesthooks) says every plane kill's bpf_send_signal failed EPERM. Each
// kill's line is refused with kill_failed -1 and detected_bypass, the run has an exec-pin-kill-failed gap a kill and
// run_end counts them, and the launcher's pidfd backstop answered each one (the run's own log). The kernel did send
// the kills (no send failure can be made on a real one: K0 found none in 10,000 a row), so the backstop finds a
// process already dying; that it kills a live one is TestKillPinnedExecKillsTheSampledProcess.
func TestPlaneRunExecPinKillFailed(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	racer := buildExecRacer(t)
	for _, cell := range execPinCells(modes) {
		t.Run(cell, func(t *testing.T) {
			rep, events, p := runPinRaceEnv(t, bin, uid, gid, cell, execPinRaceContract("-flip", "./out/git", "11", "e", "x"),
				map[string]string{"bin/execracer": racer, "out/git": "#!/bin/sh -e\nexit 0\n"},
				[]string{"TEGO_TEST_EXEC_PIN_KILL_ERR=1"})
			checkPinRaceKill(t, cell, rep, events, "", "argv-changed", -1)
			log := ownLogLines(p, "pidfd kill")
			if n := strings.Count(log, "\n") + 1; log == "" || n != rep.other {
				t.Errorf("%d pidfd backstop lines for %d kills:\n%s", n, rep.other, log)
			}
		})
	}
}

// execPinRaceAttempts2 is the attempts of each K6 race cell but the 5000-attempt race to push.
const execPinRaceAttempts2 = 1000

// execPinRaceContract runs execracer's race mode (-flip) with its four arguments under `deny: [git push]` (so every exec is
// pinned), each attempt ["git", "status"].
func execPinRaceContract(mode string, args ...string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = fmt.Sprintf("%q", a)
	}
	return fmt.Sprintf(`version: 0
name: exec-pin-cell
command: ["./bin/execracer", %q, %s, "%d", "./out/report", "status"]
fs:
  write: ["./out/"]
exec:
  deny: [git push]
net:
  allow: []
env:
  pass: ["PATH", "HOME"]
record: full
`, mode, strings.Join(q, ", "), execPinRaceAttempts2)
}

// racerReport is execracer's tally.
type racerReport struct{ attempts, eacces, ran, other, busy int }

// buildExecRacer builds test/workloads/execracer and returns its image.
func buildExecRacer(t *testing.T) string {
	t.Helper()
	racer := filepath.Join(t.TempDir(), "execracer")
	if out, err := exec.Command("go", "build", "-o", racer, "github.com/attention-span-ai/tego/test/workloads/execracer").CombinedOutput(); err != nil {
		t.Fatalf("build the racer: %v\n%s", err, out)
	}
	b, err := os.ReadFile(racer)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// runPinRace runs an execracer contract at cell and returns its report and the run's ledger lines.
func runPinRace(t *testing.T, bin string, uid, gid int, cell, contract string, files map[string]string) (racerReport, []map[string]any) {
	t.Helper()
	rep, events, _ := runPinRaceEnv(t, bin, uid, gid, cell, contract, files, nil)
	return rep, events
}

// runPinRaceEnv is runPinRace with env added to tego's environment; it also returns the project, whose run's own log
// the caller can read.
func runPinRaceEnv(t *testing.T, bin string, uid, gid int, cell, contract string, files map[string]string,
	env []string) (racerReport, []map[string]any, *planeProject) {
	t.Helper()
	tier, mode, _ := strings.Cut(cell, "@")
	all := map[string]string{"agent.yaml": contract}
	for k, v := range files {
		all[k] = v
	}
	p := newPlaneProject(t, uid, gid, all, []string{"out"}, nil)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("the run's own log on pins:\n%s", ownLogLines(p, "pin"))
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var out bytes.Buffer
	cmd := p.runAt(ctx, bin, tier, "agent.yaml", mode, &out)
	cmd.Env = append(cmd.Env, env...)
	if err := cmd.Run(); err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	requirePinsOn(t, p)
	b, err := os.ReadFile(filepath.Join(p.project, "out", "report"))
	if err != nil {
		t.Fatalf("the racer's report: %v\n%s", err, out.String())
	}
	var r racerReport
	s := strings.TrimSpace(string(b))
	if !strings.Contains(s, "busy=") {
		s += " busy=0"
	}
	if _, err := fmt.Sscanf(s, "attempts=%d eacces=%d ran=%d other=%d busy=%d", &r.attempts, &r.eacces, &r.ran, &r.other,
		&r.busy); err != nil {
		t.Fatalf("report %q: %v", b, err)
	}
	return r, runEvents(t, p.ledger), p
}

// checkPinRace checks a K6 race cell against its report: every attempt that ran is one line that says kernel_pinned;
// every attempt refused EACCES is one bprm_check refusal with refusedReason (exec.pin, no signal); every attempt that
// ended otherwise is one kill with killedReason (exec.pin, SIGKILL); run_end counts both; and on a machine with more
// than one CPU the plane acted at least once. Attempts the racer's own write made fail ETXTBSY reach no exec line.
func checkPinRace(t *testing.T, cell string, rep racerReport, events []map[string]any, refusedReason, killedReason string) {
	t.Helper()
	checkPinRaceKill(t, cell, rep, events, refusedReason, killedReason, 0)
}

// checkPinRaceKill is checkPinRace where every kill's send is said to have failed with killErr (0: none did): each
// kill line then carries kill_failed killErr and detected_bypass, the run has one exec-pin-kill-failed gap a kill,
// and run_end's kill_failed equals the kills.
func checkPinRaceKill(t *testing.T, cell string, rep racerReport, events []map[string]any, refusedReason,
	killedReason string, killErr int) {
	t.Helper()
	var ran, refused, killed, busy, odd int
	for _, e := range events {
		if e["kind"] != "exec" || strings.HasSuffix(fmt.Sprint(e["path"]), "/bin/execracer") {
			continue
		}
		switch {
		case e["syscall_ret"] == float64(-26):
			busy++ // ETXTBSY: the racer's write held the file

		case e["verdict"] == "refused" && e["rule"] == "exec.pin" && e["signal"] == nil && refusedReason != "":
			refused++
			if e["plane_reason"] != refusedReason {
				t.Errorf("a pin refusal: %v, want plane_reason %s", e, refusedReason)
			}
		case e["verdict"] == "refused" && e["rule"] == "exec.pin" && e["signal"] == "SIGKILL" && killedReason != "":
			killed++
			if killErr == 0 && (e["plane_reason"] != killedReason || e["kill_failed"] != nil) ||
				killErr != 0 && (e["plane_reason"] != killedReason || e["kill_failed"] != float64(killErr) ||
					e["detected_bypass"] != true) {
				t.Errorf("a kill: %v, want plane_reason %s and kill_failed %d", e, killedReason, killErr)
			}
		case e["verdict"] != "refused" && e["argv_facts"] == "kernel_pinned":
			ran++
		default:
			if odd++; odd <= 3 {
				t.Errorf("an exec line that is neither a pinned run, the plane's refusal nor its kill: %v", e)
			}
		}
	}
	rules := execRulesOf(t, events)
	gaps := gapCounts(events)
	for _, why := range recordLossGaps {
		if gaps[why] != 0 {
			t.Errorf("the run lost records (%s: %d): the race overran the record, so its counts below cannot be exact", why,
				gaps[why])
		}
	}
	if refused != rep.eacces || killed != rep.other || ran != rep.ran || busy != rep.busy {
		t.Errorf("%+v: the ledger has %d refusals, %d kills, %d pinned runs and %d ETXTBSY", rep, refused, killed, ran, busy)
		logRaceShape(t, events)
	}
	wantFailed := any(nil)
	if killErr != 0 && killed != 0 {
		wantFailed = float64(killed)
	}
	if rules == nil || refused != 0 && rules["pin_refused"] != float64(refused) || killed != 0 && rules["killed"] != float64(killed) ||
		rules["kill_failed"] != wantFailed {
		t.Errorf("run_end exec_rules %v, want pin_refused %d, killed %d and kill_failed %v", rules, refused, killed, wantFailed)
	}
	if killErr != 0 && gaps["exec-pin-kill-failed"] != killed {
		t.Errorf("%d exec-pin-kill-failed gaps, want one a kill (%d)", gaps["exec-pin-kill-failed"], killed)
	}
	t.Logf("%s: %+v (ledger: refused %d, killed %d, ran %d)", cell, rep, refused, killed, ran)
	if refused+killed == 0 && runtime.NumCPU() > 1 {
		t.Errorf("the plane neither refused nor killed in %d attempts: the race was not run", rep.attempts)
	}
}
