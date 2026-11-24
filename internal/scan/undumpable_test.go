// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/scan/catalog"
)

// undumpableScanHelperEnv makes this test binary, re-executed, a process that made itself undumpable, as a secret-holding
// launcher does (ADR 0126, "Amendment 2026-11-21"): it says so and waits for its stdin to close.
const undumpableScanHelperEnv = "TEGO_SCAN_UNDUMPABLE_HELPER"

func TestUndumpableScanHelper(t *testing.T) {
	if os.Getenv(undumpableScanHelperEnv) == "" {
		t.Skip("helper process for TestScanSaysAnUndumpableProcessIsUnreadable")
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	fmt.Println("undumpable")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// TestScanSaysAnUndumpableProcessIsUnreadable: a process of the scanner's own user that made itself undumpable has its
// program file hidden, so the scan cannot say what it is. A running launcher is such a process. The scan reports it
// (unreadable-program, permission, its pid in unreadable_program_pids) and never leaves it out or guesses that it is
// not an agent: the snapshot is partial and `tego scan --check` exits unreadable unless the person allows it. It is
// the reader's own words, not a new loss.
func TestScanSaysAnUndumpableProcessIsUnreadable(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestUndumpableScanHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), undumpableScanHelperEnv+"=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdin.Close(); _ = cmd.Wait() })
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "undumpable\n" {
		t.Fatalf("the helper said %q, %v", line, err)
	}
	fs, err := openProc("/proc")
	if err != nil {
		t.Fatal(err)
	}
	defer fs.close()
	p, err := fs.open(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	got := readProcess(context.Background(), p, cmd.Process.Pid, uint32(os.Getuid()), catalog.Rows(), "/proc/helper")
	if !got.unreadable || got.exited || got.critical {
		t.Fatalf("an undumpable process of this user: unreadable %v exited %v critical %v; want unreadable, still there, not a failed read", got.unreadable, got.exited, got.critical)
	}
	if len(got.sources) != 1 || got.sources[0].State != "unreadable-program" || got.sources[0].Reason != "permission" || got.sources[0].NotRead != 1 {
		t.Fatalf("sources %+v, want one unreadable-program source for permission", got.sources)
	}
}
