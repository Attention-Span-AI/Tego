// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// execPinGateInsertAttempts is how many execs the gate-only insertion race makes per cell.
const execPinGateInsertAttempts = 2000

// TestPlaneRunExecPinGateInsert is ADR 0048 P2's K6 gate-only insertion cell. In a run with an exec
// gate and no command rules, every exec is pinned in the unknown form and a #! script's exec is held by its area's
// tail. The racer execs a script as [./out/deploy.sh, staging] while a thread puts --prod in front of staging and takes
// it out again; the gate refuses a vector that puts --prod first (the racer's own command line holds the word too,
// later). A tail check alone ran a vector the gate scored without --prod with --prod inserted (the last bytes were
// still "staging\0"); held to the vector's length the first stage counted as well, such an exec is killed at
// sched_process_exec, argv-changed, before the script's first instruction.
// Asserted per cell: --prod never ran; every refused attempt is the gate's (EACCES) or the plane's kill (exec.pin,
// argv-changed, SIGKILL) whose decided vector holds no --prod, or an execve the racer made fail EFAULT; every script
// exec that ran is one line that says kernel_pinned and whose vector holds no --prod; run_end counts the kills; and
// the race was run.
func TestPlaneRunExecPinGateInsert(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	racerELF := buildExecRacer(t)
	contract := fmt.Sprintf(`version: 0
name: exec-pin-gate-insert
command: ["./bin/execracer", "-insert", "./out/deploy.sh", "%d", "./out/report", "staging", "--prod"]
fs:
  write: ["./out/"]
gate:
  rules:
    - 'exec matches "deploy.sh --prod*"': 95
net:
  allow: []
env:
  pass: ["PATH", "HOME"]
record: full
`, execPinGateInsertAttempts)
	files := map[string]string{"bin/execracer": racerELF, "out/deploy.sh": "#!/bin/sh\necho \"$@\" >> out/ran\n"}
	for _, cell := range execPinCells(modes) {
		t.Run(cell, func(t *testing.T) {
			rep, events, p := runPinRaceEnv(t, bin, uid, gid, cell, contract, files, nil)
			ranBytes, err := os.ReadFile(filepath.Join(p.project, "out", "ran"))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			if n := strings.Count(string(ranBytes), "--prod"); n != 0 {
				t.Errorf("a vector holding --prod ran %d times in a pinned run", n)
			}
			for _, why := range recordLossGaps {
				if g := gapCounts(events)[why]; g != 0 {
					t.Errorf("the run lost records (%s: %d): the race overran the record, so its counts cannot be exact", why, g)
				}
			}
			var gated, killed, faulted, ran int
			for _, e := range events {
				if e["kind"] != "exec" || !strings.HasSuffix(fmt.Sprint(e["path"]), "/out/deploy.sh") {
					continue
				}
				decided, argv := strSlice(e["argv_decided"]), strSlice(e["argv"])
				switch {
				case e["syscall_ret"] == float64(-14):
					// EFAULT: the kernel counted a vector whose last slot the racer cleared before the copy read it, so
					// the exec failed before its bprm_check and ran nothing.
					faulted++
				case e["verdict"] == "refused" && strings.HasPrefix(fmt.Sprint(e["rule"]), "gate.rules["):
					gated++
				case e["verdict"] == "refused" && e["rule"] == "exec.pin":
					killed++
					if e["signal"] != "SIGKILL" || e["plane_reason"] != "argv-changed" || e["kill_failed"] != nil ||
						len(decided) == 0 || strings.Contains(strings.Join(decided, " "), "--prod") {
						t.Errorf("a kill's line: %v", e)
					}
				case e["verdict"] != "refused" && e["argv_facts"] == "kernel_pinned":
					ran++
					if strings.Contains(strings.Join(argv, " "), "--prod") {
						t.Errorf("a pinned run with --prod: %v", e)
					}
				default:
					t.Errorf("a script line that is neither the gate's refusal, the plane's kill nor a pinned run: %v", e)
				}
			}
			if gated != rep.eacces || killed+faulted != rep.other || ran != rep.ran {
				t.Errorf("%+v: the ledger has %d gate refusals, %d kills, %d EFAULTs and %d pinned runs", rep, gated, killed,
					faulted, ran)
				logRaceShape(t, events)
			}
			if rules := execRulesOf(t, events); rules == nil || killed != 0 && rules["killed"] != float64(killed) ||
				rules["kill_failed"] != nil {
				t.Errorf("run_end exec_rules %v, want killed %d and no failed kill", rules, killed)
			}
			t.Logf("%s: %+v (ledger: gated %d, killed %d, EFAULT %d, ran %d)", cell, rep, gated, killed, faulted, ran)
			if killed == 0 && runtime.NumCPU() > 1 {
				t.Errorf("no attempt was killed in %d: the race was not run", rep.attempts)
			}
		})
	}
}

// execPinMiscAgent execs each argument's file with the argv[0] the argument names (path=argv0), printing each
// attempt's spec, pid and exit status (the errno of a refused execve).
const execPinMiscAgent = `import os, sys
for spec in sys.argv[1:]:
    path, _, argv0 = spec.partition("=")
    pid = os.fork()
    if pid == 0:
        try:
            os.execve(path, [argv0, "staging"], {})
        except OSError as e:
            os._exit(e.errno)
    _, st = os.waitpid(pid, 0)
    print("RESULT", spec, pid, os.waitstatus_to_exitcode(st), flush=True)
`

// binfmtMisc is where binfmt_misc's control files are.
const binfmtMisc = "/proc/sys/fs/binfmt_misc"

// registerBinfmtMisc registers binfmt_misc entry name for files ending .ext, run by /bin/sh with flags, and removes
// it when the test ends. It mounts binfmt_misc where nothing has, and skips where the kernel has none.
func registerBinfmtMisc(t *testing.T, name, ext, flags string) {
	t.Helper()
	if _, err := os.Stat(binfmtMisc + "/register"); err != nil {
		if err := mountBinfmtMisc(); err != nil {
			t.Skipf("binfmt_misc is not available on this kernel (a module the guest does not load): %v", err)
		}
	}
	entry := fmt.Sprintf(":%s:E::%s::/bin/sh:%s", name, ext, flags)
	if err := os.WriteFile(binfmtMisc+"/register", []byte(entry), 0); err != nil {
		t.Fatalf("register %q: %v", entry, err)
	}
	t.Cleanup(func() {
		if err := os.WriteFile(binfmtMisc+"/"+name, []byte("-1"), 0); err != nil {
			t.Errorf("unregister %s: %v", name, err)
		}
	})
}

// mountBinfmtMisc mounts binfmt_misc at its usual place; the kernel answers ENODEV where it has no binfmt_misc.
func mountBinfmtMisc() error {
	return unix.Mount("binfmt_misc", binfmtMisc, "binfmt_misc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "")
}

// TestPlaneRunExecPinGateMiscP is ADR 0048 P2's K6 binfmt_misc cell. An interpreted unknown-form
// exec's tail is the filename, then argv[1:]: what binfmt_script and binfmt_misc put there. A binfmt_misc entry with
// the P flag keeps argv[0] in front of that tail instead, where the tail does not hold it unless argv[0] is the
// filename. In a gate-only run, under an entry with P: an exec whose argv[0] is its filename runs pinned, and one whose
// argv[0] is another word is refused at the interpreter's bprm_check, pin-mismatch (EACCES); under an entry without P,
// argv[0] is dropped and the second shape runs pinned too.
func TestPlaneRunExecPinGateMiscP(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	registerBinfmtMisc(t, "tegopinp", "tegop", "P")
	registerBinfmtMisc(t, "tegopinn", "tegon", "")
	contract := `version: 0
name: exec-pin-gate-misc
command: ["python3", "./agent.py", "./out/x.tegop=./out/x.tegop", "./out/x.tegop=other", "./out/x.tegon=other"]
fs:
  write: ["./out/"]
gate:
  rules:
    - 'exec matches "deploy.sh --prod*"': 95
net:
  allow: []
env:
  pass: ["PATH", "HOME"]
record: full
`
	same, other, noP := "./out/x.tegop=./out/x.tegop", "./out/x.tegop=other", "./out/x.tegon=other"
	for _, cell := range execPinCells(modes) {
		t.Run(cell, func(t *testing.T) {
			tier, mode, _ := strings.Cut(cell, "@")
			p := newPlaneProject(t, uid, gid, map[string]string{"agent.yaml": contract, "agent.py": execPinMiscAgent,
				"out/x.tegop": "exit 0\n", "out/x.tegon": "exit 0\n"}, []string{"out"}, nil)
			for _, f := range []string{"out/x.tegop", "out/x.tegon"} {
				if err := os.Chmod(filepath.Join(p.project, f), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			var out bytes.Buffer
			if err := p.runAt(ctx, bin, tier, "agent.yaml", mode, &out).Run(); err != nil {
				t.Fatalf("run: %v\n%s", err, out.String())
			}
			requirePinsOn(t, p)
			events := runEvents(t, p.ledger)
			wantExits(t, out.String(), map[string]int{same: 0, other: 13, noP: 0})
			_, pids := execPinResults(t, out.String())
			wantOnePinnedRun(t, same, execLinesOf(events, pids[same]))
			wantOnePinnedRun(t, noP, execLinesOf(events, pids[noP]))
			lines := execLinesOf(events, pids[other])
			if len(lines) != 1 || lines[0]["verdict"] != "refused" || lines[0]["rule"] != "exec.pin" ||
				lines[0]["plane_reason"] != "pin-mismatch" || lines[0]["signal"] != nil {
				t.Errorf("the P-flag exec whose argv[0] is not its filename: lines %v, want one exec.pin refusal, pin-mismatch", lines)
			}
		})
	}
}
