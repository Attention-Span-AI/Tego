// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// execRulesDenyContract is a deny-list: images unrestricted, `git push` and `rm -r` never run (ADR 0048 (1)).
const execRulesDenyContract = `version: 0
name: plane-cmd-deny
command: ["/bin/sh", "./agent.sh"]
fs:
  write: ["./out/", "/dev/null"]
exec:
  deny: [git push, rm -r]
env:
  pass: ["PATH", "HOME"]
record: summary
`

// execRulesDenyAgent tries the refused forms and the allowed neighbours, each reported as "RESULT <name> <status>".
const execRulesDenyAgent = `rm -r out/tree >/dev/null 2>&1; echo "RESULT rm-r $?"
rm -fr out/tree2 >/dev/null 2>&1; echo "RESULT rm-fr $?"
rm out/tree3 --rec --forc >/dev/null 2>&1; echo "RESULT rm-long $?"
: > out/f; rm out/f; echo "RESULT rm $?"
if command -v git >/dev/null 2>&1; then
	git -C . push >/dev/null 2>&1; echo "RESULT git-push $?"
	git --version >/dev/null 2>&1; echo "RESULT git-version $?"
fi
`

// execRulesAllowContract restricts images and constrains rm to -f (ADR 0048 (1)): rm -f runs, rm -r is unlisted.
const execRulesAllowContract = `version: 0
name: plane-cmd-allow
command: ["/bin/sh", "./agent.sh"]
fs:
  write: ["./out/", "/dev/null"]
exec:
  allow: ["/bin/sh", "rm -f"]
env:
  pass: ["PATH", "HOME"]
record: summary
`

const execRulesAllowAgent = `: > out/x; rm -f out/x; echo "RESULT rm-f $?"
rm -r out/tree >/dev/null 2>&1; echo "RESULT rm-r $?"
`

// TestPlaneExecCommandRulesEndToEnd is ADR 0048 C6 at the root tiers: the supervisor decides command rules at every
// tier (P1), so in each plane mode this machine passes, and on the fanotify listener, `tego run --tier cgroup`
// refuses a denied command and a constrained tool's unlisted invocation at execve (the shell reports 126), with the
// rule and the command-rule fields on the supervisor's line, while every neighbour runs. Command rules keep the exec
// out of the fast handover, so the plane's exec decision and the supervisor's both hold.
func TestPlaneExecCommandRulesEndToEnd(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	for _, mode := range append(modes, PlaneFanotify) {
		for _, tc := range []struct {
			name, contract, agent string
			want                  map[string]string
			rule                  string
		}{
			{"deny", execRulesDenyContract, execRulesDenyAgent,
				map[string]string{"rm-r": "126", "rm-fr": "126", "rm-long": "126", "rm": "0"}, "exec.deny[rm -r]"},
			{"allow", execRulesAllowContract, execRulesAllowAgent,
				map[string]string{"rm-f": "0", "rm-r": "126"}, "exec.args[rm]"},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				p := newPlaneProject(t, uid, gid, map[string]string{"agent.sh": tc.agent, "agent.yaml": tc.contract},
					[]string{"out", "out/tree/sub", "out/tree2/sub", "out/tree3/sub"}, nil)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				var out bytes.Buffer
				err := p.runAt(ctx, bin, "cgroup", "agent.yaml", mode, &out).Run()
				t.Logf("tego run (%s): %v\n%s", mode, err, out.String())
				if err != nil {
					t.Fatalf("the run did not complete: %v", err)
				}
				res := agentResults(t, out.String())
				for name, w := range tc.want {
					if res[name] != w {
						t.Errorf("%s: %q, want %q", name, res[name], w)
					}
				}
				if git, ok := res["git-push"]; ok && (git != "126" || res["git-version"] != "0") {
					t.Errorf("git push %q (want 126), git --version %q (want 0)", git, res["git-version"])
				}
				events := runEvents(t, p.ledger)
				if findEvent(events, func(e map[string]any) bool {
					return e["kind"] == "exec" && e["verdict"] == "refused" && e["rule"] == tc.rule &&
						e["reason"] == "exec-not-allowed" && e["command_list"] != nil && e["argv_facts"] == "copied_syscall"
				}) == nil {
					t.Errorf("no refused exec line with rule %s and its command-rule fields", tc.rule)
				}
			})
		}
	}
}

// execMissAgent starts programs by name through env, which searches PATH with execvp (one execve per directory),
// on a PATH that begins with two directories that do not exist.
const execMissAgent = `PATH=/nonexistent-tego-a:/nonexistent-tego-b:$PATH; export PATH
env true; echo "RESULT true $?"
env true; echo "RESULT true2 $?"
env tego-no-such-command-anywhere >/dev/null 2>&1; echo "RESULT nosuch $?"
`

// TestPlaneExecMissWritesNoLine is supervisor R16b (0) at the root tiers, in each plane mode this machine passes and
// on the fanotify listener: an exec whose pathname names nothing is answered ENOENT by the supervisor, which writes no
// line and leaves its supervisor-owned marker, so the kernel recorder writes none either (no observed line with
// syscall_ret for the failed execve), under a restricted contract, a deny-list one with command rules, and one with
// no exec: section, whose execs the fast handover gave to the kernel before. run_end counts the misses in
// exec_missing.
func TestPlaneExecMissWritesNoLine(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	contracts := map[string]string{
		"restricted": `version: 0
name: plane-miss-allow
command: ["/bin/sh", "./agent.sh"]
fs:
  write: ["./out/", "/dev/null"]
exec:
  allow: ["/bin/sh", env, "true"]
env:
  pass: ["PATH", "HOME"]
record: summary
`,
		"deny-list": execRulesDenyContract,
		"no exec section": `version: 0
name: plane-miss-open
command: ["/bin/sh", "./agent.sh"]
fs:
  write: ["./out/", "/dev/null"]
env:
  pass: ["PATH", "HOME"]
record: summary
`,
	}
	for _, mode := range append(modes, PlaneFanotify) {
		for name, contract := range contracts {
			t.Run(mode+"/"+name, func(t *testing.T) {
				p := newPlaneProject(t, uid, gid, map[string]string{"agent.sh": execMissAgent, "agent.yaml": contract}, []string{"out"}, nil)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				var out bytes.Buffer
				err := p.runAt(ctx, bin, "cgroup", "agent.yaml", mode, &out).Run()
				t.Logf("tego run (%s): %v\n%s", mode, err, out.String())
				if err != nil {
					t.Fatalf("the run did not complete: %v", err)
				}
				res := agentResults(t, out.String())
				if res["true"] != "0" || res["true2"] != "0" || res["nosuch"] != "127" {
					t.Errorf("env true %q, %q (want 0), a missing command %q (want 127)", res["true"], res["true2"], res["nosuch"])
				}
				var missing float64
				starts := map[string]int{}
				for _, e := range runEvents(t, p.ledger) {
					if path, _ := e["path"].(string); e["kind"] == "exec" && strings.HasPrefix(path, "/nonexistent-tego-") {
						t.Errorf("an exec line for a miss: %v", e)
					}
					// Without the supervisor-owned marker the kernel recorder writes the failed execve as a line of its
					// own, which no naming joins: path "<truncated>" and syscall_ret -2. Every exec in this agent that
					// names a file succeeds, so no exec line carries syscall_ret, and every line names a file.
					if path, _ := e["path"].(string); e["kind"] == "exec" {
						if _, ok := e["syscall_ret"]; ok {
							t.Errorf("an exec line for a failed execve (the kernel recorder's sample of a miss): %v", e)
						}
						if _, err := os.Stat(path); err != nil {
							t.Errorf("an exec line whose path names nothing: %v", e)
						}
						// By argv[0], else by the image's name: a line may name the spelling (/usr/bin/true) or the file
						// it resolves to (gnutrue on Ubuntu 25.10).
						name := filepath.Base(path)
						if argv, _ := e["argv"].([]any); len(argv) > 0 {
							if a0, _ := argv[0].(string); a0 != "" {
								name = filepath.Base(a0)
							}
						}
						if name == "gnutrue" {
							name = "true"
						}
						starts[name]++
					}
					if target, _ := e["target"].(string); e["kind"] == "refused" && strings.HasPrefix(target, "/nonexistent-tego-") {
						t.Errorf("a refused line for a miss: %v", e)
					}
					if e["kind"] == "run_end" {
						if sup, ok := e["supervisor"].(map[string]any); ok {
							missing, _ = sup["exec_missing"].(float64)
						}
					}
				}
				// Two missing directories for each of the three env searches, at least.
				if missing < 6 {
					t.Errorf("run_end.supervisor.exec_missing = %v, want at least 6", missing)
				}
				// One line per start and none besides: three env starts and two true starts.
				if starts["env"] != 3 || starts["true"] != 2 {
					t.Errorf("exec lines by image %v, want env 3 and true 2", starts)
				}
			})
		}
	}
}

// missRaceAgent swaps out/x and out/x.tmp by rename in a loop in one process while another forks N children, each of
// which execs out/x: a child that exits other than 127 is an exec the kernel ran. It writes the pids that ran to
// out/ran.txt.
const missRaceAgent = `import os, sys, signal
d = sys.argv[1]
N = int(sys.argv[2])
x = os.path.join(d, "x"); t = os.path.join(d, "x.tmp")
with open(t, "w") as f:
    f.write("#!/bin/sh\nexit 0\n")
os.chmod(t, 0o755)
flipper = os.fork()
if flipper == 0:
    while True:
        try: os.rename(t, x)
        except OSError: pass
        try: os.rename(x, t)
        except OSError: pass
ran = []
devnull = os.open("/dev/null", os.O_WRONLY)
for i in range(N):
    pid = os.fork()
    if pid == 0:
        os.dup2(devnull, 2)
        try:
            os.execv(x, [x])
        except OSError:
            os._exit(127)
    _, st = os.waitpid(pid, 0)
    if os.WIFEXITED(st) and os.WEXITSTATUS(st) != 127:
        ran.append(pid)
os.kill(flipper, signal.SIGKILL)
os.waitpid(flipper, 0)
with open(os.path.join(d, "ran.txt"), "w") as f:
    f.write("\n".join(str(p) for p in ran) + "\n")
print("RESULT ran", len(ran))
`

// TestPlaneExecMissObserveRace at tier cgroup, in each plane mode this machine passes and on the
// fanotify listener: in a `tego run --observe` run a miss (R16b (0)) is answered with its errno, never continued.
// Continued, the kernel's second lookup ran a file renamed into place after the supervisor's walk, the miss's
// supervisor-owned marker dropped the kernel recorder's record of it, and 22 to 32 execs of about 100 that ran had no
// line of any kind. Every exec that ran must have its exec line, whichever writer wrote it.
func TestPlaneExecMissObserveRace(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not available")
	}
	contract := `version: 0
name: plane-miss-race
command: ["/usr/bin/python3", "./race.py", "./out", "300"]
fs:
  write: ["./out/", "/dev/null"]
env:
  pass: ["PATH", "HOME"]
record: summary
`
	for _, mode := range append(modes, PlaneFanotify) {
		t.Run(mode, func(t *testing.T) {
			p := newPlaneProject(t, uid, gid, map[string]string{"race.py": missRaceAgent, "agent.yaml": contract}, []string{"out"}, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			var out bytes.Buffer
			cmd := exec.CommandContext(ctx, bin, "run", "--tier", "cgroup", "--observe", "agent.yaml")
			cmd.Dir = p.project
			cmd.Env = append(os.Environ(), "TEGO_CONFIG="+p.cfg, "TEGO_TEST_PLANE="+mode,
				"TEGO_TEST_CHAIN_ANCHOR="+filepath.Join(p.base, "chain.log"), "TEGO_TEST_OWN_LOG_HOME="+filepath.Join(p.base, "home"),
				"PYTHONDONTWRITEBYTECODE=1")
			cmd.Stdout, cmd.Stderr = &out, &out
			cmd.WaitDelay = 15 * time.Second
			err := cmd.Run()
			t.Logf("tego run --observe (%s): %v\n%s", mode, err, out.String())
			if err != nil {
				t.Fatalf("the run did not complete: %v", err)
			}
			b, err := os.ReadFile(filepath.Join(p.project, "out", "ran.txt"))
			if err != nil {
				t.Fatal(err)
			}
			lined := map[int]bool{}
			for _, e := range runEvents(t, p.ledger) {
				if path, _ := e["path"].(string); e["kind"] == "exec" && strings.HasSuffix(path, "/out/x") {
					if pid, ok := e["pid"].(float64); ok {
						lined[int(pid)] = true
					}
				}
			}
			ran, unlined := strings.Fields(string(b)), 0
			for _, s := range ran {
				if n, _ := strconv.Atoi(s); !lined[n] {
					unlined++
				}
			}
			t.Logf("%s: %d execs of out/x ran, %d with an exec line", mode, len(ran), len(ran)-unlined)
			if unlined != 0 {
				t.Errorf("%d of %d execs that ran have no exec line: an observe run continued a miss the kernel then won", unlined, len(ran))
			}
		})
	}
}

// TestPlaneExecSearchOracle at tier cgroup, in each plane mode this machine passes and on the
// fanotify listener: the supervisor walks an exec's pathname as root, and a miss answered from that walk (ENOENT)
// told an agent dropped to the sudo caller whether a name exists in a root-owned 0700 directory it cannot search
// (126 for a present file, 127 for an absent one; `ls` of the directory fails). The walk now holds the task's search
// permission to every directory, so both are EACCES (126), the kernel's own answer, under a contract with no exec:
// section and under one whose images are restricted.
func TestPlaneExecSearchOracle(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	dir, err := os.MkdirTemp("", "tego-oracle-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "present"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	agent := dir + "/present; echo \"RESULT present $?\"\n" + dir + "/absent; echo \"RESULT absent $?\"\n" +
		"ls " + dir + " >/dev/null 2>&1; echo \"RESULT ls $?\"\n"
	contracts := map[string]string{
		"no exec section": `version: 0
name: plane-oracle
command: ["/bin/sh", "./agent.sh"]
fs:
  write: ["./out/", "/dev/null"]
env:
  pass: ["PATH", "HOME"]
record: summary
`,
		"restricted": `version: 0
name: plane-oracle-restricted
command: ["/bin/sh", "./agent.sh"]
fs:
  write: ["./out/", "/dev/null"]
exec:
  allow: ["/bin/sh", "/usr/bin/ls"]
env:
  pass: ["PATH", "HOME"]
record: summary
`,
	}
	for _, mode := range append(modes, PlaneFanotify) {
		for name, c := range contracts {
			t.Run(mode+"/"+name, func(t *testing.T) {
				p := newPlaneProject(t, uid, gid, map[string]string{"agent.sh": agent, "agent.yaml": c}, []string{"out"}, nil)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				var out bytes.Buffer
				err := p.runAt(ctx, bin, "cgroup", "agent.yaml", mode, &out).Run()
				t.Logf("tego run (%s): %v\n%s", mode, err, out.String())
				res := agentResults(t, out.String())
				if res["ls"] == "0" {
					t.Fatalf("the agent can list %s: the case proves nothing", dir)
				}
				if res["present"] != "126" || res["absent"] != "126" {
					t.Errorf("present %q, absent %q in a 0700 root directory the agent cannot search: want 126 (EACCES) for both", res["present"], res["absent"])
				}
				for _, e := range runEvents(t, p.ledger) {
					if e["kind"] == "run_end" {
						if sup, ok := e["supervisor"].(map[string]any); ok && sup["exec_missing"] != nil {
							t.Errorf("run_end.supervisor.exec_missing %v: an exec the task cannot look up is no miss", sup["exec_missing"])
						}
					}
				}
			})
		}
	}
}

// TestPlaneExecMagicLinkOracle at tier cgroup: the supervisor's walk, as root, followed a procfs
// magic link (/proc/<pid>/cwd, /proc/1/root) the agent may not follow (the kernel asks ptrace_may_access, and the agent,
// another user, may not read a root process), and answered a miss behind it ENOENT with no line: 126 for a present
// name and 127 for an absent one, where the kernel answers EACCES for both. The cwd sits in a 0755 directory under a
// 0700 one, so only the link reaches it. A walk through another process's magic link that fails is now EACCES, in
// every plane mode and on the fanotify listener, under a contract with no exec: section and under a restricted one.
func TestPlaneExecMagicLinkOracle(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	dir, err := os.MkdirTemp("", "tego-magic-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "present"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sl := exec.Command("sleep", "600")
	sl.Dir = sub
	if err := sl.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sl.Process.Kill(); _ = sl.Wait() })
	cwd := "/proc/" + strconv.Itoa(sl.Process.Pid) + "/cwd"
	agent := "ls " + cwd + "/ >/dev/null 2>&1; echo \"RESULT ls $?\"\n" +
		cwd + "/present; echo \"RESULT present $?\"\n" +
		cwd + "/absent; echo \"RESULT absent $?\"\n" +
		cwd + "/absent/x; echo \"RESULT absentx $?\"\n" +
		"ls /proc/1/root/ >/dev/null 2>&1; echo \"RESULT root_ls $?\"\n" +
		"/proc/1/root/bin/sh -c 'exit 0'; echo \"RESULT root_present $?\"\n" +
		"/proc/1/root/tego-no-such-name; echo \"RESULT root_absent $?\"\n"
	contracts := map[string]string{
		"no exec section": `version: 0
name: plane-magic
command: ["/bin/sh", "./agent.sh"]
fs:
  write: ["./out/", "/dev/null"]
env:
  pass: ["PATH", "HOME"]
record: summary
`,
		"restricted": `version: 0
name: plane-magic-restricted
command: ["/bin/sh", "./agent.sh"]
fs:
  write: ["./out/", "/dev/null"]
exec:
  allow: ["/bin/sh", "/usr/bin/ls"]
env:
  pass: ["PATH", "HOME"]
record: summary
`,
	}
	for _, mode := range append(modes, PlaneFanotify) {
		for name, c := range contracts {
			t.Run(mode+"/"+name, func(t *testing.T) {
				p := newPlaneProject(t, uid, gid, map[string]string{"agent.sh": agent, "agent.yaml": c}, []string{"out"}, nil)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				var out bytes.Buffer
				err := p.runAt(ctx, bin, "cgroup", "agent.yaml", mode, &out).Run()
				t.Logf("tego run (%s): %v\n%s", mode, err, out.String())
				res := agentResults(t, out.String())
				if res["ls"] == "0" || res["root_ls"] == "0" {
					t.Fatalf("the agent can list %s or /proc/1/root: the case proves nothing", cwd)
				}
				for _, k := range []string{"present", "absent", "absentx", "root_present", "root_absent"} {
					if res[k] != "126" {
						t.Errorf("%s: exit %q behind a magic link the agent may not follow: want 126 (EACCES), as for every name there", k, res[k])
					}
				}
				for _, e := range runEvents(t, p.ledger) {
					if e["kind"] == "run_end" {
						if sup, ok := e["supervisor"].(map[string]any); ok && sup["exec_missing"] != nil {
							t.Errorf("run_end.supervisor.exec_missing %v: an exec behind a link the task may not follow is no miss", sup["exec_missing"])
						}
					}
				}
			})
		}
	}
}
