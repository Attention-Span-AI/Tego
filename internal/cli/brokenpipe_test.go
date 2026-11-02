// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// brokenPipeHelperEnv makes this test binary, re-run by the tests below, stand in for a command that writes to a
// stderr whose reader has left: "held" as a supervising command, "help" as one printing its usage, "ordinary" as a
// command that supervises nothing.
const brokenPipeHelperEnv = "TEGO_TEST_BROKEN_PIPE"

// brokenPipeAgentExit is the exit the stand-in returns: an agent's own, which a closed stderr must not replace.
const brokenPipeAgentExit = 7

// brokenPipeHelper runs a command through mainWith, the way Main does, on the real os.Stderr: only a write to fd 1 or
// 2 takes the runtime's SIGPIPE path, which a buffer or a stubbed writer never reaches.
func brokenPipeHelper(mode string) {
	cmd := Command{Name: "agent", Passthrough: true, Supervises: mode != "ordinary", Run: func(_ context.Context, _ *flag.FlagSet, _, stderr io.Writer) int {
		fmt.Fprintln(stderr, "tego's own line, for a reader that left")
		return brokenPipeAgentExit
	}, Usage: "[flags]"}
	argv := []string{"tego", "agent"}
	if mode == "help" {
		argv = append(argv, "-h")
	}
	os.Exit(mainWith(context.Background(), argv, os.Stdout, os.Stderr, []Command{cmd}))
}

// runBrokenPipeHelper starts the stand-in with a stderr nothing reads and returns how it ended.
func runBrokenPipeHelper(t *testing.T, mode string) error {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), brokenPipeHelperEnv+"="+mode)
	cmd.Stderr = w
	return cmd.Run()
}

// TestBrokenPipeLeavesARunsExit: `tego run agent.yaml 2>&1 | head -1` lost the launcher to SIGPIPE on the summary
// after head left, so the agent's exit became 141, whatever tego's own comment on a stderr it cannot write said; and a
// line during the run ended the supervisor under a live agent. An ordinary command keeps the Unix default, so
// `tego events <run> | head` ends quietly, and so does a supervising command's help, which runs nothing.
func TestBrokenPipeLeavesARunsExit(t *testing.T) {
	var exit *exec.ExitError
	if err := runBrokenPipeHelper(t, "held"); !errors.As(err, &exit) || exit.ExitCode() != brokenPipeAgentExit {
		t.Errorf("a supervising command writing to a closed pipe: %v, want the agent's exit %d", err, brokenPipeAgentExit)
	}
	for _, mode := range []string{"ordinary", "help"} {
		if err := runBrokenPipeHelper(t, mode); !errors.As(err, &exit) {
			t.Errorf("%s writing to a closed pipe: %v, want it ended by SIGPIPE", mode, err)
		} else if st, ok := exit.Sys().(syscall.WaitStatus); !ok || !st.Signaled() || st.Signal() != syscall.SIGPIPE {
			t.Errorf("%s writing to a closed pipe: %v, want it ended by SIGPIPE", mode, err)
		}
	}
}

// TestSupervisingCommandsHoldBrokenPipe: run, watch and adopt are the commands a run depends on staying alive; a
// command added beside them has to say which it is.
func TestSupervisingCommandsHoldBrokenPipe(t *testing.T) {
	for _, c := range []Command{cmdRun(), cmdWatch(), cmdAdopt()} {
		if !c.Supervises {
			t.Errorf("tego %s does not hold a broken pipe", c.Name)
		}
	}
}

// TestHeldBrokenPipeReachesNoChild: the agent's own SIGPIPE stays its default. signal.Ignore would have held the
// launcher too, and would have reached the agent across execve, where a `yes | head` under tego then spins on EPIPE.
func TestHeldBrokenPipeReachesNoChild(t *testing.T) {
	holdBrokenPipe()
	out, err := exec.Command("/bin/sh", "-c", "grep ^SigIgn: /proc/self/status").Output()
	if err != nil {
		t.Fatal(err)
	}
	_, hex, ok := strings.Cut(strings.TrimSpace(string(out)), "\t")
	if !ok {
		t.Fatalf("SigIgn line: %q", out)
	}
	mask, err := strconv.ParseUint(hex, 16, 64)
	if err != nil {
		t.Fatal(err)
	}
	if mask&(1<<(syscall.SIGPIPE-1)) != 0 {
		t.Errorf("a child inherits SIGPIPE ignored: SigIgn %s", hex)
	}
}
