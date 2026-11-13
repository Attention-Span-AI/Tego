// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// execPinAgent forks and execs ./bin/tool once per argv its arguments name (each a comma-separated vector), and prints
// each attempt's argv, pid and exit status (the errno of a refused execve, or -9 for SIGKILL).
const execPinAgent = `import os, sys
for spec in sys.argv[1:]:
    argv = spec.split(",")
    pid = os.fork()
    if pid == 0:
        try:
            os.execve("./bin/tool", argv, {})
        except OSError as e:
            os._exit(e.errno)
    _, st = os.waitpid(pid, 0)
    print("RESULT", spec, pid, os.waitstatus_to_exitcode(st), flush=True)
`

// execPinCells is each plane cell a pinned run is checked in: the cgroup tier at both plane modes, and tier 3 at lsm.
func execPinCells(modes []string) []string {
	var cells []string
	for _, mode := range modes {
		cells = append(cells, "cgroup@"+mode)
		if mode == "lsm" {
			cells = append(cells, "bpflsm@"+mode)
		}
	}
	return cells
}

// execPinResults reads the agent's RESULT lines: each attempt's exit status and pid, by its argv spec.
func execPinResults(t *testing.T, out string) (codes map[string]int, pids map[string]int) {
	t.Helper()
	codes, pids = map[string]int{}, map[string]int{}
	for _, line := range strings.Split(out, "\n") {
		var spec string
		var pid, code int
		if n, _ := fmt.Sscanf(line, "RESULT %s %d %d", &spec, &pid, &code); n == 3 {
			codes[spec], pids[spec] = code, pid
		}
	}
	return codes, pids
}

// execLinesOf returns the ledger's exec lines of pid.
func execLinesOf(events []map[string]any, pid int) []map[string]any {
	var lines []map[string]any
	for _, e := range events {
		if e["kind"] == "exec" && e["pid"] == float64(pid) {
			lines = append(lines, e)
		}
	}
	return lines
}

// execRulesOf returns run_end's supervisor.exec_rules, or nil when the run has none.
func execRulesOf(t *testing.T, events []map[string]any) map[string]any {
	t.Helper()
	for _, e := range events {
		if e["kind"] != "run_end" {
			continue
		}
		sup, _ := e["supervisor"].(map[string]any)
		rules, _ := sup["exec_rules"].(map[string]any)
		return rules
	}
	t.Fatal("the run has no run_end line")
	return nil
}

// execPinContract is a run of execPinAgent with the given exec list entries beside the agent's own grants.
func execPinContract(extra string) string {
	return `version: 0
name: exec-pins
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
exec:
  allow: ["python3", "./bin/tool"]
` + extra + `net:
  allow: []
env:
  pass: ["PATH", "HOME"]
record: full
`
}

// runExecPinAgent runs execPinAgent at one plane cell ("tier@mode") with contract, the agent's arguments appended to
// its command, and returns its output and its ledger's lines.
func runExecPinAgent(t *testing.T, bin string, uid, gid int, cell, contract string, args []string,
	files map[string]string) (string, []map[string]any) {
	t.Helper()
	return runExecPinAgentEnv(t, bin, uid, gid, cell, contract, args, files, nil)
}

// runExecPinAgentEnv is runExecPinAgent with env added to tego's environment.
func runExecPinAgentEnv(t *testing.T, bin string, uid, gid int, cell, contract string, args []string,
	files map[string]string, env []string) (string, []map[string]any) {
	t.Helper()
	tier, mode, _ := strings.Cut(cell, "@")
	tool, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	all := map[string]string{"agent.py": execPinAgent, "agent.yaml": contract, "bin/tool": string(tool)}
	for k, v := range files {
		all[k] = v
	}
	if len(args) > 0 {
		quoted := make([]string, len(args))
		for i, a := range args {
			quoted[i] = fmt.Sprintf("%q", a)
		}
		all["agent.yaml"] = strings.Replace(contract, `"./agent.py"]`, `"./agent.py", `+strings.Join(quoted, ", ")+`]`, 1)
	}
	p := newPlaneProject(t, uid, gid, all, []string{"out"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	var out bytes.Buffer
	cmd := p.runAt(ctx, bin, tier, "agent.yaml", mode, &out)
	cmd.Env = append(cmd.Env, env...)
	if err := cmd.Run(); err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("the run's own log on pins:\n%s", ownLogLines(p, "pin"))
		}
	})
	requirePinsOn(t, p)
	return out.String(), runEvents(t, p.ledger)
}

// requirePinsOn skips a cell whose run Prepare could not pin because this kernel's recorder has no exec outcomes (the
// sys_exit_execve and sys_exit_execveat programs did not attach): there a kill would have no line, so the run goes
// unpinned and claims nothing, the fallback ADR 0048's K0 rule gives a row that cannot hold pins. Any other reason
// pins are off fails the test.
func requirePinsOn(t *testing.T, p *planeProject) {
	t.Helper()
	off := ownLogLines(p, "exec pins off")
	switch {
	case off == "":
	case strings.Contains(off, "the kernel recorder has no exec outcomes"):
		t.Skipf("this kernel's recorder has no exec outcomes, so the run is not pinned (the disclosed fallback): %s", off)
	default:
		t.Fatalf("the run was not pinned: %s", off)
	}
}

// ownLogLines is every line of the run's own log (under the project's test home) that holds word.
func ownLogLines(p *planeProject, word string) string {
	var lines []string
	_ = filepath.WalkDir(filepath.Join(p.base, "home"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, l := range strings.Split(string(b), "\n") {
			if strings.Contains(l, word) {
				lines = append(lines, l)
			}
		}
		return nil
	})
	return strings.Join(lines, "\n")
}

// TestPlaneRunExecPinned is ADR 0048 (3) P2 through a real run: a run with command rules at a plane cell has its
// slot pinned, every exec the supervisor continues runs under its pin and its one line says argv_facts
// kernel_pinned, an exec a deny entry names is the supervisor's refusal (EACCES) and never reaches the plane's pin,
// and run_end counts no kill and no pin refusal.
func TestPlaneRunExecPinned(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	for _, cell := range execPinCells(modes) {
		t.Run(cell, func(t *testing.T) {
			out, events := runExecPinAgent(t, bin, uid, gid, cell, execPinContract("  deny: [\"tool push\"]\n"),
				[]string{"tool,status", "tool,push", "tool,log,-1"}, nil)
			codes, pids := execPinResults(t, out)
			want := map[string]int{"tool,status": 0, "tool,push": 13, "tool,log,-1": 0}
			for spec, code := range want {
				if got, ok := codes[spec]; !ok || got != code {
					t.Fatalf("%s exited %d (seen %v), want %d:\n%s", spec, got, ok, code, out)
				}
			}
			for _, spec := range []string{"tool,status", "tool,log,-1"} {
				lines := execLinesOf(events, pids[spec])
				if len(lines) != 1 || lines[0]["verdict"] != "allow" || lines[0]["argv_facts"] != "kernel_pinned" ||
					lines[0]["source"] != "kernel" {
					t.Errorf("%s: exec lines %v, want one kernel allow line that says kernel_pinned", spec, lines)
				}
			}
			lines := execLinesOf(events, pids["tool,push"])
			if len(lines) != 1 || lines[0]["verdict"] != "refused" || lines[0]["rule"] != "exec.deny[tool push]" ||
				lines[0]["signal"] != nil {
				t.Errorf("tool push: exec lines %v, want one refusal by exec.deny[tool push]", lines)
			}
			rules := execRulesOf(t, events)
			if rules == nil || rules["refused"] != float64(1) || rules["killed"] != nil || rules["pin_refused"] != nil ||
				rules["kill_failed"] != nil {
				t.Errorf("run_end exec_rules %v, want one refusal and no kill or pin refusal", rules)
			}
			for _, e := range events {
				if e["kind"] == "exec" && e["argv_facts"] == "unproven" {
					t.Errorf("an unproven exec line: %v", e)
				}
			}
			if execPinCheckSkippable(t, bin) {
				requireNoExecPinClaim(t, events)
			} else {
				requireExecPinClaim(t, events)
			}
		})
	}
}

// execPinCheckSkippable reports whether doctor withholds the exec pin claim on this kernel (ADR 0148): the check
// after an exec is a tracepoint program a kernel that preempts kernel code can skip, so a product build makes no claim
// there and a test build's waiver keeps it. Doctor's own report says which, in its exec pin cell's words.
func execPinCheckSkippable(t *testing.T, bin string) bool {
	t.Helper()
	out, err := isolatedTego(t, bin, "doctor", "--json").Output()
	if err != nil && len(out) == 0 {
		t.Fatalf("tego doctor --json: %v", err)
	}
	return strings.Contains(string(out), "tracepoint program this kernel can skip")
}

// requireExecPinClaim checks the claim of ADR 0048 (6) and (9) on a pinned run's run_start: the plane's mode passed
// doctor's exec pin cell in the run's own probe, so the capabilities say exec.command_argv and best_effort leaves out
// exec.rules/argv.
func requireExecPinClaim(t *testing.T, events []map[string]any) {
	t.Helper()
	for _, e := range events {
		if e["kind"] != "run_start" {
			continue
		}
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if s := string(b); !strings.Contains(s, `"exec.command_argv":true`) || strings.Contains(s, `"exec.rules/argv"`) {
			t.Errorf("a pinned run's run_start claims no exec pins: %.1500s", s)
		}
		return
	}
	t.Error("no run_start line")
}

// requireNoExecPinClaim is the run_start of a pinned run where doctor withheld the claim (ADR 0148): the pins still
// applied (each exec's line says kernel_pinned), but the capabilities do not say exec.command_argv and best_effort
// keeps exec.rules/argv.
func requireNoExecPinClaim(t *testing.T, events []map[string]any) {
	t.Helper()
	for _, e := range events {
		if e["kind"] != "run_start" {
			continue
		}
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if s := string(b); strings.Contains(s, `"exec.command_argv":true`) || !strings.Contains(s, `"exec.rules/argv"`) {
			t.Errorf("a pinned run claims exec pins on a kernel whose exec pin check can be skipped: %.1500s", s)
		}
		return
	}
	t.Error("no run_start line")
}

// TestPlaneRunExecPinOff is ADR 0048 P2's control: a run with no command rules and no exec gate is not pinned, so
// its execs carry no argv_facts and no pin is written, held or killed, and run_end has no exec_rules.
func TestPlaneRunExecPinOff(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	for _, cell := range execPinCells(modes) {
		t.Run(cell, func(t *testing.T) {
			out, events := runExecPinAgent(t, bin, uid, gid, cell, execPinContract(""),
				[]string{"tool,status", "tool,push"}, nil)
			codes, pids := execPinResults(t, out)
			if codes["tool,status"] != 0 || codes["tool,push"] != 0 || len(codes) != 2 {
				t.Fatalf("results %v, want both execs to run:\n%s", codes, out)
			}
			for _, spec := range []string{"tool,status", "tool,push"} {
				lines := execLinesOf(events, pids[spec])
				if len(lines) != 1 || lines[0]["verdict"] != "allow" || lines[0]["argv_facts"] != nil {
					t.Errorf("%s: exec lines %v, want one allow line with no argv_facts", spec, lines)
				}
			}
			if rules := execRulesOf(t, events); rules != nil {
				t.Errorf("run_end exec_rules %v in a run with no command rules", rules)
			}
		})
	}
}

// execPinRaceAttempts is how many attempts TestPlaneRunExecPinRace makes in each plane cell (ADR 0048 K6).
const execPinRaceAttempts = 5000

// TestPlaneRunExecPinRace is ADR 0048 K6's race at the plane: C6's TOCTOU fixture (execracer) in a run that denies
// git push. Each attempt's child flips a buffer between diff and push on one thread while its main thread execs a git
// fixture (a #! script that records its argv[1]) with it. The supervisor decides on its own copy of argv and writes the
// pin of that copy; the kernel copies argv again after the CONTINUE. At tier 1 a copy that read diff and a kernel copy
// that read push ran push (the disclosed race, R5); in a pinned run the plane holds the exec to the decided copy, so an
// exec whose kernel copy differs is killed at sched_process_exec, before the script's first instruction. Asserted per
// cell: push never ran; every refused attempt is the supervisor's (exec.deny[git push], EACCES) or the plane's kill
// (exec.pin, argv-changed, SIGKILL), and each kill's line carries the kernel's vector and the decided one, which differ;
// every git exec that ran is one line (observed, unmatched: deny-list mode) whose vector is not push and which says
// kernel_pinned; run_end counts the kills. The race must be run: a cell with
// no kill fails on a machine with more than one CPU, where C6 measured the race won about 400 times in 3000.
func TestPlaneRunExecPinRace(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	racerELF := buildExecRacer(t)
	contract := fmt.Sprintf(`version: 0
name: exec-pin-race
command: ["./bin/execracer", "./out/git", "%d", "./out/report"]
fs:
  write: ["./out/"]
exec:
  deny: [git push]
net:
  allow: []
env:
  pass: ["PATH", "HOME"]
record: full
`, execPinRaceAttempts)
	for _, cell := range execPinCells(modes) {
		t.Run(cell, func(t *testing.T) {
			tier, mode, _ := strings.Cut(cell, "@")
			p := newPlaneProject(t, uid, gid, map[string]string{"agent.yaml": contract, "bin/execracer": racerELF,
				"out/git": "#!/bin/sh\necho \"$1\" >> out/ran\n"}, []string{"out"}, nil)
			t.Cleanup(func() {
				if t.Failed() {
					t.Logf("the run's own log on pins:\n%s", ownLogLines(p, "pin"))
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()
			var out bytes.Buffer
			started := time.Now()
			skipsBefore := skipSnapshot(t)
			if err := p.runAt(ctx, bin, tier, "agent.yaml", mode, &out).Run(); err != nil {
				t.Fatalf("run: %v\n%s", err, out.String())
			}
			took := time.Since(started)
			logSkipDelta(t, cell, skipsBefore, skipSnapshot(t))
			requirePinsOn(t, p)
			rep, err := os.ReadFile(filepath.Join(p.project, "out", "report"))
			if err != nil {
				t.Fatalf("the racer's report: %v\n%s", err, out.String())
			}
			var n, eacces, ranN, other int
			if _, err := fmt.Sscanf(strings.TrimSpace(string(rep)), "attempts=%d eacces=%d ran=%d other=%d", &n, &eacces, &ranN, &other); err != nil {
				t.Fatalf("report %q: %v", rep, err)
			}
			ranBytes, _ := os.ReadFile(filepath.Join(p.project, "out", "ran"))
			if pushes := strings.Count(string(ranBytes), "push\n"); pushes != 0 {
				t.Errorf("git push ran %d times in a pinned run", pushes)
			}
			var refused, killed, allowed int
			var rules map[string]any
			eachRunEvent(t, p.ledger, func(e map[string]any) {
				if e["kind"] == "run_end" {
					sup, _ := e["supervisor"].(map[string]any)
					rules, _ = sup["exec_rules"].(map[string]any)
				}
				if e["kind"] != "exec" || !strings.HasSuffix(fmt.Sprint(e["path"]), "/out/git") {
					return
				}
				decided, argv := strSlice(e["argv_decided"]), strSlice(e["argv"])
				switch {
				case e["verdict"] == "refused" && e["rule"] == "exec.deny[git push]":
					refused++
					if e["argv_facts"] != "copied_syscall" || e["signal"] != nil {
						t.Errorf("a supervisor refusal: %v", e)
					}
				case e["verdict"] == "refused" && e["rule"] == "exec.pin":
					killed++
					// The kernel's vector is binfmt_script's (/bin/sh, the script, the word); the decided one is the
					// supervisor's copy of the attempt's (git, the word), which a deny entry did not refuse.
					if e["signal"] != "SIGKILL" || e["plane_reason"] != "argv-changed" || len(argv) == 0 ||
						len(decided) != 2 || decided[1] == "push" || argv[len(argv)-1] == decided[1] || e["kill_failed"] != nil {
						t.Errorf("a kill's line: %v", e)
					}
				case e["verdict"] == "observed" && e["rule"] == "unmatched":
					// Deny-list mode: an exec no command rule matched runs, observed (ADR 0048 (8)).
					allowed++
					if len(argv) == 0 || argv[len(argv)-1] == "push" || e["argv_facts"] != "kernel_pinned" {
						t.Errorf("an allowed git line: %v", e)
					}
				default:
					t.Errorf("a git line that is neither the supervisor's refusal, the plane's kill nor an allow: %v", e)
				}
			})
			if refused != eacces {
				t.Errorf("%d supervisor refusals, %d attempts answered EACCES", refused, eacces)
			}
			if killed != other {
				t.Errorf("%d kill lines, %d attempts ended otherwise than by EACCES or a run", killed, other)
			}
			if allowed != ranN {
				t.Errorf("%d allowed git lines, %d attempts ran", allowed, ranN)
			}
			if rules == nil || killed != 0 && rules["killed"] != float64(killed) || rules["kill_failed"] != nil {
				t.Errorf("run_end exec_rules %v, want killed %d and no failed kill", rules, killed)
			}
			t.Logf("%s: %d attempts in %v: refused %d, killed %d, ran %d (allowed lines %d)", cell, n,
				took.Round(time.Second), eacces, killed, ranN, allowed)
			if killed == 0 && runtime.NumCPU() > 1 {
				t.Errorf("no attempt was killed in %d: the race was not run", n)
			}
		})
	}
}

// strSlice is a JSON array of strings, or nil.
func strSlice(v any) []string {
	a, _ := v.([]any)
	var out []string
	for _, x := range a {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}
