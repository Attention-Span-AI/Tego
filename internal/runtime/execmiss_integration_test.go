// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// missPATH is the PATH the miss tests' script searches: two directories that do not exist, a file standing where a
// directory should (ENOTDIR), then the host's usual directories.
func missPATH(out string) string {
	return "/nonexistent-tego-a:/nonexistent-tego-b:" + filepath.Join(out, "afile") + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
}

// TestIntegrationExecMissWritesNoLine is supervisor R16b (0) on the real kernel at tier landlock: a program started
// by name is one execve per PATH directory, and every directory that holds no such name is a miss the supervisor
// answers with ENOENT (ENOTDIR for a file on PATH) and writes no line for, at every record level, while the start and
// every refusal of a file that exists keep their lines. Three `git status` starts, a `git push` refused unlisted and a
// command that exists nowhere: the ledger holds exec lines only for files that exist, run_end counts the misses in
// exec_missing, and drift reads git as three allowed starts and no observation. Before, each miss was a refused line
// (the custom-agent POC: seven tries of git push made 133 refused exec events).
func TestIntegrationExecMissWritesNoLine(t *testing.T) {
	git := needGit(t)
	for _, mode := range []string{"summary", "full", "off"} {
		t.Run(mode, func(t *testing.T) {
			contract := strings.Replace(execRulesContract("xmiss", "/bin/sh", `  allow: ["/bin/sh", "/usr/bin/sh", "/usr/bin/env", "git status"]`),
				"record: summary", "record: "+mode, 1)
			f := newFixture(t, contract)
			if err := os.WriteFile(filepath.Join(f.out, "afile"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			script := "PATH=" + missPATH(f.out) + `; export PATH
for i in 1 2 3; do env git status >>out/log 2>&1; echo "status$i $?" >> out/st; done
env git push >>out/log 2>&1; echo "push $?" >> out/st
env tego-no-such-command-anywhere >>out/log 2>&1; echo "nosuch $?" >> out/st`
			runScript(t, f, script)
			st := statuses(t, f)
			for _, c := range []string{"status1", "status2", "status3"} {
				if st[c] == 126 || st[c] == 127 {
					t.Errorf("%s: exit %d, git status did not start\n%s", c, st[c], logOf(f))
				}
			}
			if st["push"] != 126 || st["nosuch"] != 127 {
				t.Errorf("git push exit %d (want 126, refused unlisted), a missing command exit %d (want 127)", st["push"], st["nosuch"])
			}
			dirs := runDirs(t, f.root)
			if len(dirs) != 1 {
				t.Fatalf("want one run, have %v", dirs)
			}
			var end *record.RunEndPayload
			pushRefused, statusAllowed, allowed := 0, 0, 0
			for _, e := range events(t, dirs[0]) {
				switch e.Kind {
				case record.KindExec:
					var p record.ExecPayload
					if err := e.DecodePayload(&p); err != nil {
						t.Fatal(err)
					}
					if _, err := os.Stat(p.Path); err != nil {
						t.Errorf("an exec line for %s, which names nothing (%s %s): a miss writes no line", p.Path, e.Verdict, e.Rule)
					}
					switch {
					case e.Verdict == record.VerdictRefused && e.Rule == "exec.args[git]":
						pushRefused++
					case e.Verdict == record.VerdictAllow:
						allowed++
						if p.CommandRule == "git status" {
							statusAllowed++
						}
					}
				case record.KindRefused:
					var p record.RefusedPayload
					if err := e.DecodePayload(&p); err == nil && strings.Contains(p.Target, "nonexistent-tego") {
						t.Errorf("a refused line for a miss: %+v", p)
					}
				case record.KindRunEnd:
					end = &record.RunEndPayload{}
					if err := e.DecodePayload(end); err != nil {
						t.Fatal(err)
					}
				}
			}
			// A git found on PATH lies past three misses (two missing directories and the file), and the missing
			// command misses in every directory of PATH; git push is refused on each directory that holds git.
			gitDir := filepath.Dir(git)
			before := 3
			for _, d := range strings.Split(missPATH(f.out), ":")[3:] {
				if d == gitDir {
					break
				}
				if _, err := os.Stat(filepath.Join(d, "git")); err != nil {
					before++
				}
			}
			want := int64(4*before + len(strings.Split(missPATH(f.out), ":")))
			if end == nil || end.Supervisor.ExecMissing < want {
				t.Errorf("run_end.supervisor.exec_missing %+v, want at least %d", end, want)
			}
			if pushRefused == 0 {
				t.Errorf("git push left no refused line: an existing file's refusal must keep its line")
			}
			if mode == "off" {
				return // only refusals are kept: the starts have no line
			}
			if statusAllowed != 3 {
				t.Errorf("%d allowed git status lines, want the three starts", statusAllowed)
			}
			// drift as a user runs it (the engine never imports the read side): tego drift <run> --json.
			cmd := exec.Command(tegoBinary(t), "drift", filepath.Base(dirs[0]), "--json")
			cmd.Env = isolatedEnv(t, f)
			out, err := cmd.Output()
			var rep struct {
				Rules []struct {
					Section  string `json:"section"`
					Rule     string `json:"rule"`
					Allow    int    `json:"allow"`
					Refused  int    `json:"refused"`
					Observed int    `json:"observed"`
				} `json:"rules"`
			}
			if jerr := json.Unmarshal(out, &rep); jerr != nil {
				t.Fatalf("tego drift --json: %v, %v\n%s", err, jerr, out)
			}
			driftAllowed, driftRefused := 0, 0
			for _, c := range rep.Rules {
				if c.Section != "exec" {
					continue
				}
				if c.Observed != 0 {
					t.Errorf("drift: %s observed %d, want none (a miss is no observation)", c.Rule, c.Observed)
				}
				driftAllowed += c.Allow
				driftRefused += c.Refused
			}
			if driftAllowed != allowed || driftRefused != pushRefused {
				t.Errorf("drift: exec allowed %d refused %d, want the %d starts and %d refusals the ledger holds", driftAllowed, driftRefused, allowed, pushRefused)
			}
		})
	}
}

// missRaceAgent swaps out/x and out/x.tmp by rename in a loop in one process while another forks N children, each of
// which execs out/x: a child that exits other than 127 is an exec the kernel ran. It writes the pids that ran to
// out/ran.txt. Between the supervisor's walk and any later lookup of the same path the file can come or go.
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
`

// TestIntegrationExecMissObserveRace at tier landlock: in a `tego run --observe` run a miss
// (R16b (0)) is answered with its errno, never continued. Continued, the kernel looked the path up a second time, a
// file renamed into place after the supervisor's walk ran, and the run held no line for it: 44 of 129 execs that ran
// had no line of any kind. Every exec that ran must have its exec line.
func TestIntegrationExecMissObserveRace(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not available")
	}
	f := newFixture(t, `version: 0
name: xmiss-race
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/", "/dev/null"]
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 256
record: summary
`)
	script := filepath.Join(f.dir, "race.py")
	if err := os.WriteFile(script, []byte(missRaceAgent), 0o644); err != nil {
		t.Fatal(err)
	}
	run := exec.Command(tegoBinary(t), "run", "--observe", filepath.Join(f.dir, "agent.yaml"), "--", python, script, f.out, "300")
	run.Dir = f.dir
	run.Env = isolatedEnv(t, f)
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("tego run --observe: %v\n%s", err, out)
	}
	b, err := os.ReadFile(filepath.Join(f.out, "ran.txt"))
	if err != nil {
		t.Fatal(err)
	}
	ran := strings.Fields(string(b))
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("want one run, have %v", dirs)
	}
	lined := map[string]bool{}
	for _, e := range events(t, dirs[0]) {
		if e.Kind != record.KindExec {
			continue
		}
		var p record.ExecPayload
		if err := e.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(p.Path, "/out/x") {
			lined[strconv.Itoa(e.PID)] = true
		}
	}
	unlined := 0
	for _, pid := range ran {
		if !lined[pid] {
			unlined++
		}
	}
	t.Logf("%d execs of out/x ran, %d with an exec line", len(ran), len(ran)-unlined)
	if unlined != 0 {
		t.Errorf("%d of %d execs that ran have no exec line: an observe run continued a miss the kernel then won", unlined, len(ran))
	}
}

// TestIntegrationExecMagicLinkOracle at tier landlock: the supervisor's walk followed a procfs magic
// link of a process outside the run (/proc/<pid>/cwd) with its own rights, which the agent lacks there (Landlock scopes
// ptrace to the agent's domain; as root under sudo the process is also another user's), and answered a miss behind it
// ENOENT with no line: /proc/<pid>/cwd/present exited 126 and /proc/<pid>/cwd/absent 127, though the agent cannot list
// that directory. The kernel answers the agent EACCES for both, and so does the supervisor now: a walk through another
// process's magic link that fails is EACCES, decided and recorded as an attempt, under a contract with no exec:
// section and under a restricted one.
func TestIntegrationExecMagicLinkOracle(t *testing.T) {
	ls, err := exec.LookPath("ls")
	if err != nil {
		t.Skip("no ls")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "present"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sl := exec.Command("sleep", "600")
	sl.Dir = dir
	if err := sl.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sl.Process.Kill(); _ = sl.Wait() })
	cwd := "/proc/" + strconv.Itoa(sl.Process.Pid) + "/cwd"
	script := "ls " + cwd + "/ >/dev/null 2>&1; echo \"ls $?\" >> out/st\n" +
		cwd + "/present >/dev/null 2>&1; echo \"present $?\" >> out/st\n" +
		cwd + "/absent >/dev/null 2>&1; echo \"absent $?\" >> out/st\n" +
		cwd + "/absent/x >/dev/null 2>&1; echo \"absentx $?\" >> out/st\n"
	for name, contract := range map[string]string{
		"no exec section": `version: 0
name: xmagic
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/", "/dev/null"]
env:
  pass: ["PATH", "HOME"]
record: summary
`,
		"restricted": execRulesContract("xmagic-restricted", "/bin/sh", `  allow: ["/bin/sh", "/usr/bin/sh", "`+ls+`"]`),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, contract)
			runScript(t, f, script)
			st := statuses(t, f)
			if st["ls"] == 0 {
				t.Skipf("the agent can list %s here: the case proves nothing", cwd)
			}
			for _, c := range []string{"present", "absent", "absentx"} {
				if st[c] != 126 {
					t.Errorf("%s/%s: exit %d, want 126 (EACCES, the kernel's answer behind a link the agent may not follow)", cwd, c, st[c])
				}
			}
			dirs := runDirs(t, f.root)
			if len(dirs) != 1 {
				t.Fatalf("want one run, have %v", dirs)
			}
			lines := map[string]int{}
			for _, e := range events(t, dirs[0]) {
				if e.Kind != record.KindExec {
					continue
				}
				var p record.ExecPayload
				if err := e.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				if strings.HasPrefix(p.Path, cwd+"/") {
					lines[strings.TrimPrefix(p.Path, cwd+"/")]++
				}
			}
			// Each failed attempt behind the link has its line, as an attempt at a name the agent cannot see is
			// recorded anywhere else: a miss there is no different in the record either.
			if lines["absent"] != 1 || lines["absent/x"] != 1 {
				t.Errorf("exec lines by name behind the link %v: want one for absent and one for absent/x", lines)
			}
		})
	}
}

// TestIntegrationExecProcDirOracle at tier landlock, on procfs: /proc/<pid>/fdinfo is 0555, and
// its permission operation asks ptrace_may_access, which Landlock refuses the agent for a process outside its domain
// (`ls /proc/<pid>/fdinfo` fails). The supervisor, outside that domain, looked the name up itself: a descriptor the
// process holds open was decided (126) and one it does not hold was a miss (127, no line), so the agent learned which
// descriptors a process of its user outside the run has open. Another process's procfs directory is now an unsure
// step at every tier, so both are EACCES (126), the kernel's own answer, decided and recorded as attempts, under a
// contract with no exec: section and under a restricted one.
func TestIntegrationExecProcDirOracle(t *testing.T) {
	ls, err := exec.LookPath("ls")
	if err != nil {
		t.Skip("no ls")
	}
	sl := exec.Command("sleep", "600")
	if err := sl.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sl.Process.Kill(); _ = sl.Wait() })
	fdinfo := "/proc/" + strconv.Itoa(sl.Process.Pid) + "/fdinfo"
	script := "ls " + fdinfo + "/ >/dev/null 2>&1; echo \"ls $?\" >> out/st\n" +
		fdinfo + "/0 >/dev/null 2>&1; echo \"present $?\" >> out/st\n" +
		fdinfo + "/tego-no-such-fd >/dev/null 2>&1; echo \"absent $?\" >> out/st\n" +
		fdinfo + "/0/x >/dev/null 2>&1; echo \"presentx $?\" >> out/st\n"
	for name, contract := range map[string]string{
		"no exec section": `version: 0
name: xprocdir
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/", "/dev/null"]
env:
  pass: ["PATH", "HOME"]
record: summary
`,
		"restricted": execRulesContract("xprocdir-restricted", "/bin/sh", `  allow: ["/bin/sh", "/usr/bin/sh", "`+ls+`"]`),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, contract)
			runScript(t, f, script)
			st := statuses(t, f)
			if st["ls"] == 0 {
				t.Skipf("the agent can list %s here: the case proves nothing", fdinfo)
			}
			for _, c := range []string{"present", "absent", "presentx"} {
				if st[c] != 126 {
					t.Errorf("%s/%s: exit %d, want 126 (EACCES, the kernel's answer in a directory the agent may not look into)", fdinfo, c, st[c])
				}
			}
			dirs := runDirs(t, f.root)
			if len(dirs) != 1 {
				t.Fatalf("want one run, have %v", dirs)
			}
			lines := map[string]int{}
			for _, e := range events(t, dirs[0]) {
				if e.Kind != record.KindExec {
					continue
				}
				var p record.ExecPayload
				if err := e.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				if strings.HasPrefix(p.Path, fdinfo+"/") {
					lines[strings.TrimPrefix(p.Path, fdinfo+"/")]++
				}
			}
			if lines["tego-no-such-fd"] != 1 || lines["0/x"] != 1 {
				t.Errorf("exec lines by name in %s %v: want one for tego-no-such-fd and one for 0/x", fdinfo, lines)
			}
		})
	}
}
