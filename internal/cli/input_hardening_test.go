// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// signalHelperEnv makes this test binary, re-run by TestASecondSignalEndsTheCommand, stand in for a
// command stuck where no context reaches (see signalHelper).
const signalHelperEnv = "TEGO_TEST_SIGNAL_HELPER"

// signalHelper takes Main's signal context, says so, and once it is cancelled blocks as a command
// stuck in a read would: only the second signal's default action can end it.
func signalHelper() {
	ctx, stop := notifyContext()
	defer stop()
	fmt.Println("ready")
	<-ctx.Done()
	fmt.Println("cancelled")
	time.Sleep(time.Minute)
	os.Exit(3)
}

// TestASecondSignalEndsTheCommand: the first SIGTERM cancels the command's context, and the second
// ends a command that did not stop on it. Main held the handler for its whole life, so a compile
// blocked on a FIFO ignored every SIGINT and SIGTERM and only SIGKILL ended it.
// SIGTERM, not SIGINT: a process a non-interactive shell starts in the background begins with SIGINT
// ignored, releasing the handler restores that, and CI starts the suites that way.
func TestASecondSignalEndsTheCommand(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), signalHelperEnv+"=1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	lines := bufio.NewScanner(out)
	expect := func(want string) {
		t.Helper()
		got := make(chan string, 1)
		go func() {
			if lines.Scan() {
				got <- lines.Text()
			}
			close(got)
		}()
		select {
		case line := <-got:
			if line != want {
				t.Fatalf("helper said %q, want %q", line, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("helper never said %q", want)
		}
	}
	expect("ready")
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	expect("cancelled")
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("helper exited %v, want death by SIGTERM", err)
		}
		if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGTERM {
			t.Fatalf("helper ended %v, want death by SIGTERM", err)
		}
	case <-time.After(10 * time.Second):
		st, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", cmd.Process.Pid))
		t.Fatalf("a second SIGTERM did not end the command:\n%s", st)
	}
}

// within fails the test when f has not returned in d: every input below once blocked forever.
func within(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v", what, d)
	}
}

func mkfifo(t *testing.T, path string) string {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestInputFIFOsDoNotHang: a contract, a profile, a test table or a run's contract copy planted as a
// FIFO with no writer made compile, run and drift wait forever in open(2).
func TestInputFIFOsDoNotHang(t *testing.T) {
	dir := t.TempDir()
	fifo := mkfifo(t, filepath.Join(dir, "agent.yaml"))
	within(t, 5*time.Second, "compile of a FIFO contract", func() {
		if code, _, errs := run(t, "compile", fifo); code == identity.ExitOK {
			t.Errorf("compile of an empty FIFO exited 0: %q", errs)
		}
	})

	profiles := filepath.Join(dir, "profiles")
	if err := os.Mkdir(profiles, 0o700); err != nil {
		t.Fatal(err)
	}
	mkfifo(t, filepath.Join(profiles, "base.yaml"))
	within(t, 5*time.Second, "a FIFO profile", func() {
		if _, _, err := (dirProfiles{Root: profiles}).Resolve("base"); err != nil {
			t.Logf("resolve: %v", err) // an empty profile is the loader's to refuse
		}
	})

	contract := filepath.Join(dir, "ok.yaml")
	if err := os.WriteFile(contract, []byte("version: 0\nname: fifo\ncommand: [\"/bin/true\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	table := mkfifo(t, filepath.Join(dir, "table.yaml"))
	within(t, 5*time.Second, "compile --test of a FIFO table", func() {
		if code, _, errs := run(t, "compile", "--test", table, contract); code == identity.ExitOK {
			t.Errorf("an empty FIFO test table passed: %q", errs)
		}
	})

	copyFIFO := mkfifo(t, filepath.Join(dir, "contract.yaml"))
	within(t, 5*time.Second, "a FIFO contract copy", func() {
		if _, err := readCopy(copyFIFO); !errors.Is(err, agent.ErrNotAFile) {
			t.Errorf("readCopy of a FIFO = %v, want ErrNotAFile", err)
		}
	})
}

// TestAContractFromAPipeStillCompiles: O_NONBLOCK must not cost `tego compile <(generate)`, whose
// path is a pipe with a writer.
func TestAContractFromAPipeStillCompiles(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	go func() {
		time.Sleep(50 * time.Millisecond) // the read must wait for the bytes, not see end of file
		_, _ = w.WriteString("version: 0\nname: piped\ncommand: [\"/bin/true\"]\n")
		_ = w.Close()
	}()
	path := fmt.Sprintf("/proc/self/fd/%d", r.Fd())
	code, out, errs := run(t, "compile", path)
	if code != identity.ExitOK || !strings.Contains(out, "command  /bin/true") {
		t.Fatalf("compile of a pipe: exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestInitWritesNothingThroughALink: agent.yaml and .gitignore that are symbolic links lead wherever
// their author chose; init wrote through both, --force overwriting the link's target and the
// .gitignore line landing in the file the link named.
func TestInitWritesNothingThroughALink(t *testing.T) {
	outside := t.TempDir()
	target := filepath.Join(outside, "bashrc")
	const original = "export KEEP=1\n"
	if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := os.Symlink(target, filepath.Join(dir, "agent.yaml")); err != nil {
		t.Fatal(err)
	}
	code, _, errs := run(t, "init", dir)
	if code != identity.ExitFinding || !strings.Contains(errs, "symbolic link") {
		t.Fatalf("init over a linked agent.yaml: exit %d stderr %q", code, errs)
	}
	if _, err := os.Lstat(filepath.Join(dir, ".tego")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused init left .tego/ behind (%v)", err)
	}
	code, _, errs = run(t, "init", "--force", dir)
	if code != identity.ExitOK {
		t.Fatalf("init --force: exit %d stderr %q", code, errs)
	}
	if got, _ := os.ReadFile(target); string(got) != original {
		t.Fatalf("--force wrote through the link: the target now holds %q", got)
	}
	if st, err := os.Lstat(filepath.Join(dir, "agent.yaml")); err != nil || !st.Mode().IsRegular() {
		t.Fatalf("--force left agent.yaml %v (%v), want a regular file in place of the link", st, err)
	}

	dir2 := t.TempDir()
	if err := os.Symlink(target, filepath.Join(dir2, ".gitignore")); err != nil {
		t.Fatal(err)
	}
	code, _, errs = run(t, "init", dir2)
	if code == identity.ExitOK || !strings.Contains(errs, ".gitignore") {
		t.Fatalf("init over a linked .gitignore: exit %d stderr %q", code, errs)
	}
	if got, _ := os.ReadFile(target); string(got) != original {
		t.Fatalf("init appended through the .gitignore link: %q", got)
	}
	// .gitignore is planned before anything is written, as agent.yaml is: a refusal there left .tego/ and
	// agent.yaml behind, unannounced.
	for _, name := range []string{".tego", "agent.yaml"} {
		if _, err := os.Lstat(filepath.Join(dir2, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("init refused over a linked .gitignore left %s behind (%v)", name, err)
		}
	}
}

// TestInitRefusesAFIFOContract: an agent.yaml planted as a FIFO is refused at once, not waited on.
func TestInitRefusesAFIFOContract(t *testing.T) {
	dir := t.TempDir()
	mkfifo(t, filepath.Join(dir, "agent.yaml"))
	within(t, 5*time.Second, "init over a FIFO", func() {
		if code, _, errs := run(t, "init", dir); code != identity.ExitFinding {
			t.Errorf("exit %d stderr %q", code, errs)
		}
	})
}

// TestStarterNamesDevNullAndItsNetwork: the starter contract let Python's subprocess.DEVNULL fail
// (a write-open of /dev/null outside every write entry) and, with no net: section, left the host's
// unix sockets reachable, the D-Bus session bus and with it `systemd-run --user` among them
// (agent-contract R19).
func TestStarterNamesDevNullAndItsNetwork(t *testing.T) {
	dir := t.TempDir()
	if code, _, errs := run(t, "init", "--name", "starter", dir); code != identity.ExitOK {
		t.Fatalf("init: exit %d stderr %q", code, errs)
	}
	c, _, err := agent.Load(filepath.Join(dir, "agent.yaml"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.FS == nil || !slices.Contains(c.FS.Write, "/dev/null") {
		t.Errorf("the starter's fs.write does not grant /dev/null: %+v", c.FS)
	}
	if c.Net == nil {
		t.Error("the starter has no net: section, so it refuses no connect")
	}
}
