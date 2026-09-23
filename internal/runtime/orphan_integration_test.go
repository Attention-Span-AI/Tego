// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationADaemonOutlivingItsLauncherGetsENOSYS: a descendant that
// double-forked away from the agent survives the launcher's SIGKILL — PDEATHSIG reaches only the agent's
// own process, and the flag is cleared across fork — and from then on every syscall the seccomp filter
// notifies fails with ENOSYS, because the only listener died with the launcher (seccomp_unotify(2): with
// the listener closed, a notifying syscall returns ENOSYS). Nothing answers it, so nothing can allow it:
// the run fails closed. The sweep then ends the orphan and kills the survivor.
//
// The descendant waits on a FIFO the test opens only after the launcher is dead and its lock free, so
// its write-open is certain to come after the launcher's death and before the sweep. It reports through
// the stdout and stderr it inherited, which are plain files here: a write(2) on a descriptor it already
// holds is not a notified syscall. The write it attempts is into the contract's own fs.write directory,
// which Landlock admits, so the only thing that can refuse it is the dead listener.
func TestIntegrationADaemonOutlivingItsLauncherGetsENOSYS(t *testing.T) {
	bin := tegoBinary(t)
	f := newFixture(t, contractFor("idaemon", []string{"/bin/sh"}, []string{"/bin/sh", "/bin/sleep"}))
	cfg := writeMachineConfig(t, f)

	fifo := filepath.Join(f.dir, "release")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	late := filepath.Join(f.out, "after-launcher.txt")
	script := filepath.Join(f.dir, "daemonize.sh")
	// ( ... & ) is the double fork: the subshell starts the descendant in the background and exits at
	// once, so the descendant is nobody's child the launcher's PDEATHSIG applies to. The agent itself
	// then waits in sleep, which PDEATHSIG does end. The descendant's last wait loops: its second open of
	// the FIFO can land while release still holds the write end, and read then meets end of file, which
	// would end the descendant before the sweep it is waiting for (CI run #27, under -race).
	body := `#!/bin/sh
( /bin/sh -c '
	echo "descendant ready pid=$$"
	read line < "$0"
	if echo late > "$1"; then echo "descendant wrote"; else echo "descendant refused"; fi
	while ! read line < "$0"; do :; done
' "$1" "$2" & )
exec /bin/sleep 120
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, script, fifo)

	outFile := filepath.Join(t.TempDir(), "stdout")
	errFile := filepath.Join(t.TempDir(), "stderr")
	stdout, err := os.Create(outFile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdout.Close() }()
	stderr, err := os.Create(errFile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stderr.Close() }()

	cmd := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"), "--", "/bin/sh", script, fifo, late)
	cmd.Dir = f.dir
	cmd.Env = append(os.Environ(), "TEGO_CONFIG="+cfg)
	// Files, not buffers: exec.Cmd would put a pipe and a copying goroutine behind a buffer, and Wait
	// would then block until the descendant, which holds the pipe too, exited.
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start launcher: %v", err)
	}
	dir := waitForStartedRun(t, f.root, 20*time.Second)
	// Whatever happens below, the launcher is killed and the sweep ends what it left: a test that fails
	// half way must not leave a descendant running in the invoking user's cgroup tree.
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = Sweep(context.Background(), f.root, KeepForever)
	})
	pid := waitForDescendant(t, outFile, errFile)

	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("kill launcher: %v", err)
	}
	_ = cmd.Wait()
	waitLockFree(t, dir)
	if !alive(pid) {
		t.Fatalf("the descendant %d did not survive its launcher; the test proves nothing", pid)
	}

	// Release the descendant: open blocks until its read-open is waiting, which it already is.
	release(t, fifo)
	report := waitForLine(t, outFile, errFile, "descendant wrote", "descendant refused")
	if strings.Contains(report, "descendant wrote") {
		t.Fatalf("a write-open after the launcher died was allowed:\n%s", readFileString(outFile))
	}
	if _, err := os.Stat(late); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the file the orphaned descendant tried to create exists (%v)", err)
	}
	// The shell reports the failed redirection with strerror(3), "Function not implemented" for ENOSYS;
	// Go spells the same errno in lower case.
	if msg := readFileString(errFile); !strings.Contains(strings.ToLower(msg), syscall.ENOSYS.Error()) {
		t.Fatalf("the refused write-open did not fail with ENOSYS (%q); stderr:\n%s", syscall.ENOSYS.Error(), msg)
	}
	if !alive(pid) {
		t.Fatal("the descendant must still be alive when the sweep runs")
	}

	res, err := Sweep(context.Background(), f.root, KeepForever)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if res.Orphaned != 1 {
		t.Fatalf("swept %d/%d run(s), want 1 (errs %v)", res.Orphaned, res.Scanned, res.Errs)
	}
	if got := lastReason(t, dir); got != record.RunEndOrphaned {
		t.Fatalf("run ended with %q, want orphaned", got)
	}
	// The sweep killed what the dead launcher left in the run's cgroup and removed the cgroup, which
	// cannot be removed while the descendant is in it.
	assertCgroupRemoved(t, f, filepath.Base(dir), "idaemon")
}

// readyLine is what the descendant prints once it is waiting on the FIFO.
var readyLine = regexp.MustCompile(`descendant ready pid=(\d+)`)

// waitForDescendant waits for the descendant's ready line and returns its pid.
func waitForDescendant(t *testing.T, outFile, errFile string) int {
	t.Helper()
	line := waitForLine(t, outFile, errFile, "descendant ready")
	m := readyLine.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("no pid in %q", line)
	}
	pid, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatal(err)
	}
	return pid
}

// waitForLine returns the first line of outFile containing any of want, failing with both files after 20s.
func waitForLine(t *testing.T, outFile, errFile string, want ...string) string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, l := range strings.Split(readFileString(outFile), "\n") {
			for _, w := range want {
				if strings.Contains(l, w) {
					return l
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no line with any of %q within 20s\nstdout:\n%s\nstderr:\n%s", want, readFileString(outFile), readFileString(errFile))
	return ""
}

// waitLockFree waits until the dead launcher's run lock is released, which is when the kernel has closed
// every descriptor it held, the seccomp listener among them.
func waitLockFree(t *testing.T, dir string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if held, _, err := ProbeLock(dir); err == nil && !held {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the killed launcher's lock on %s was never released", dir)
}

// release writes one line into the FIFO, which lets the descendant's pending read return.
func release(t *testing.T, fifo string) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		w, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			done <- err
			return
		}
		_, err = fmt.Fprintln(w, "go")
		if cerr := w.Close(); err == nil {
			err = cerr
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("release the descendant: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the descendant never opened its FIFO: it is not waiting where the test expects")
	}
}

// alive reports whether pid exists and is not a zombie.
func alive(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	// The state is the field after the parenthesised comm, which may itself hold spaces.
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	return i >= 0 && i+2 < len(s) && s[i+2] != 'Z' && s[i+2] != 'X'
}

// readFileString reads a file for a report, "" when it cannot.
func readFileString(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}
