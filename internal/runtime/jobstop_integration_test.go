// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// jobShell starts bash as the session leader of p, the way a terminal starts a login shell, with job control on
// (set -m), running script with args. Its jobs, `tego run` among them, are process groups of that session, so a
// stopped tego is reported to it exactly as to an interactive shell. The session ends at cleanup.
func jobShell(t *testing.T, p *pty, env []string, script string, args ...string) *exec.Cmd {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skipf("no bash: %v", err)
	}
	cmd := exec.Command(bash, append([]string{"--norc", "--noprofile", "-c", "set -m\n" + script, "bash"}, args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = p.slave, p.slave, p.slave
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start bash: %v", err)
	}
	t.Cleanup(func() {
		_ = unix.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
	})
	return cmd
}

// waitOutput waits up to d for re to match what the terminal was sent and returns the first submatch.
func (p *pty) waitOutput(t *testing.T, re *regexp.Regexp, d time.Duration) string {
	t.Helper()
	for end := time.Now().Add(d); ; time.Sleep(10 * time.Millisecond) {
		if m := re.FindSubmatch(p.written()); m != nil {
			return string(m[1])
		}
		if time.Now().After(end) {
			t.Fatalf("the terminal never showed %v; it got %q", re, p.written())
		}
	}
}

// waitRunning waits up to 10 s for pid's /proc state to leave T (stopped).
func waitRunning(t *testing.T, pid int) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); procState(t, pid) == "T"; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("pid %d is still stopped", pid)
		}
	}
}

// waitLflag waits up to 5 s for the terminal to be canonical (ICANON set) or not, and returns the lflag it ended on.
func (p *pty) waitLflag(t *testing.T, canonical bool) uint32 {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		tio := p.termios(t)
		if (tio.Lflag&unix.ICANON != 0) == canonical || time.Now().After(end) {
			return tio.Lflag
		}
	}
}

// An interactive agent that stops itself (Claude Code's Ctrl-Z: kill(own pid, SIGTSTP)) stops only itself; tego, the
// shell's job, kept running, so the shell never got the terminal back (G2). Now tego follows its agent: it puts back
// the terminal modes it saved before the agent ran and stops with the same signal, and the shell reports the job
// stopped (148 = 128+SIGTSTP). Continued, tego resumes the agent: in the foreground (fg) with the agent's own modes
// back on the terminal; continued in the background (kill -CONT to tego alone, so nothing else resumes the agent),
// without touching the terminal. Either way the agent finishes and tego exits with its status.
//
// Pins runtime-launch.md R9b: a launcher sharing a terminal with its agent follows the agent's own stop.
func TestIntegrationAStoppedAgentStopsTegoAndResumes(t *testing.T) {
	sleep, err := filepath.EvalSymlinks("/bin/sleep")
	if err != nil {
		t.Skipf("no sleep: %v", err)
	}
	for _, mode := range []string{"fg", "bg"} {
		t.Run(mode, func(t *testing.T) {
			bin := tegoBinary(t)
			f := newFixture(t, contractFor("ijobstop", []string{"/bin/sh"},
				[]string{"/bin/sh", "/usr/bin/sh", "/bin/sleep", "/usr/bin/sleep", sleep}))
			env := isolatedEnv(t, f)
			p := openPTY(t)
			cooked := p.termios(t)
			agent := `echo $$ > out/pid
while [ ! -e out/go ]; do sleep 0.05; done
kill -TSTP $$
echo resumed > out/resumed
while [ ! -e out/done ]; do sleep 0.05; done
exit 7`
			resume := `fg; echo "exit=$?"`
			if mode == "bg" {
				// bash's wait answers 148 for a job it has not yet seen continued (its CLD_CONTINUED is asynchronous):
				// asked again until it has.
				resume = `kill -CONT "$pid"; wait "$pid"; rc=$?
while [ "$rc" = 148 ]; do sleep 0.05; wait "$pid"; rc=$?; done
echo "exit=$rc"`
			}
			script := `cd "$2" || exit 99
"$1" run agent.yaml -- /bin/sh -c "$3"
echo "stopped=$? pid=$(jobs -p)"
pid=$(jobs -p)
while [ ! -e out/cont ]; do sleep 0.05; done
` + resume
			jobShell(t, p, env, script, bin, f.dir, agent)

			pidFile := filepath.Join(f.out, "pid")
			waitForFile(t, pidFile, 20*time.Second)
			agentPID := atoiFile(t, pidFile)
			// The agent turns the terminal raw, as a TUI does, and then stops itself.
			raw := cooked
			raw.Lflag &^= unix.ICANON | unix.ECHO
			setTermios(t, p, &raw)
			touch(t, filepath.Join(f.out, "go"))

			got := p.waitOutput(t, regexp.MustCompile(`stopped=(\d+ pid=\d+)`), 20*time.Second)
			status, pidText, _ := strings.Cut(got, " pid=")
			if status != "148" {
				t.Fatalf("the shell saw the job end %s, want 148 (stopped by SIGTSTP)", status)
			}
			tego, _ := strconv.Atoi(pidText)
			t.Cleanup(func() { _ = unix.Kill(-tego, syscall.SIGKILL) }) // the job's group, which the session's end may not reach
			if s := procState(t, tego); s != "T" {
				t.Fatalf("tego is in state %s, want T (stopped)", s)
			}
			if s := procState(t, agentPID); s != "T" {
				t.Fatalf("the agent is in state %s, want T (stopped)", s)
			}
			if tio := p.termios(t); tio.Lflag&unix.ICANON == 0 || tio.Lflag&unix.ECHO == 0 {
				t.Fatalf("the stopped job left the terminal raw (lflag %#x); the shell must get its modes back", tio.Lflag)
			}

			touch(t, filepath.Join(f.out, "cont"))
			waitForFile(t, filepath.Join(f.out, "resumed"), 20*time.Second)
			waitRunning(t, tego)
			// In the foreground the shell's SIGCONT reaches the agent too, which may run before tego puts its modes
			// back, so the raw modes are waited for. In the background only tego resumes the agent, and it does so
			// without touching the terminal, so the modes are already final.
			if lflag := p.waitLflag(t, mode == "bg"); (lflag&unix.ICANON == 0) != (mode == "fg") {
				t.Fatalf("after %s the terminal's lflag is %#x; want the agent's raw modes back only in the foreground", mode, lflag)
			}
			touch(t, filepath.Join(f.out, "done"))
			if code := p.waitOutput(t, regexp.MustCompile(`exit=(\d+)`), 20*time.Second); code != "7" {
				t.Fatalf("tego exited %s, want the agent's 7", code)
			}
		})
	}
}

// nohup's promise: a run started with SIGHUP ignored keeps it ignored, so the hangup a terminal sends its
// foreground group reaches neither tego nor the agent, which inherits the ignored disposition as it would without
// tego. tego used to subscribe to SIGHUP regardless, so the hangup started stop_grace and ended the run (129).
//
// Also pins runtime-launch.md R9b: a SIGHUP the launcher inherited as ignored stays ignored.
func TestIntegrationAnIgnoredSIGHUPKeepsTheRun(t *testing.T) {
	sleep, err := filepath.EvalSymlinks("/bin/sleep")
	if err != nil {
		t.Skipf("no sleep: %v", err)
	}
	bin := tegoBinary(t)
	f := newFixture(t, contractFor("inohup", []string{"/bin/sh"},
		[]string{"/bin/sh", "/usr/bin/sh", "/bin/sleep", "/usr/bin/sleep", sleep}))
	env := isolatedEnv(t, f)
	agent := `while read -r k v; do [ "$k" = SigIgn: ] && echo "$v" > out/sigign; done < /proc/self/status
while [ ! -e out/done ]; do sleep 0.05; done
echo finished > out/finished`
	// trap '' HUP is what nohup does before it execs its command.
	cmd := exec.Command("/bin/sh", "-c", `trap '' HUP; exec "$0" run agent.yaml -- /bin/sh -c "$1"`, bin, agent)
	cmd.Dir, cmd.Env = f.dir, env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // a job of its own, as the hangup's target
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Kill(-cmd.Process.Pid, syscall.SIGKILL) })
	waitForFile(t, filepath.Join(f.out, "sigign"), 20*time.Second)
	if err := unix.Kill(-cmd.Process.Pid, syscall.SIGHUP); err != nil { // the hangup, to tego and the agent at once
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // the hangup's effect, if any, is immediate: give it the time to show
	touch(t, filepath.Join(f.out, "done"))
	err = cmd.Wait()
	if code := exitCodeOf(t, err); code != 0 {
		t.Fatalf("tego exited %d after SIGHUP, want 0 (the agent finished)\n%s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(f.out, "finished")); err != nil {
		t.Fatal("the agent did not finish")
	}
	mask, err := strconv.ParseUint(strings.TrimSpace(readFileString(filepath.Join(f.out, "sigign"))), 16, 64)
	if err != nil {
		t.Fatal(err)
	}
	if mask&(1<<(uint(syscall.SIGHUP)-1)) == 0 {
		t.Fatalf("the agent's SigIgn %#x lacks SIGHUP: nohup's ignored disposition did not reach it", mask)
	}
}

func atoiFile(t *testing.T, path string) int {
	t.Helper()
	n, err := strconv.Atoi(strings.TrimSpace(readFileString(path)))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return n
}

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

func setTermios(t *testing.T, p *pty, tio *unix.Termios) {
	t.Helper()
	if err := sys.FileDo(p.slave, func(fd int) error { return unix.IoctlSetTermios(fd, unix.TCSETS, tio) }); err != nil {
		t.Fatalf("TCSETS: %v", err)
	}
}
