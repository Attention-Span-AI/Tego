// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/realtego"
)

// TestGuardTegoSeesTheGovernanceLedger: an appended governance segment, a new segment and a new blob are each
// reported (ADR 0100 (5): the governance ledger at <tego home>/gov).
func TestGuardTegoSeesTheGovernanceLedger(t *testing.T) {
	d := filepath.Join(t.TempDir(), ".tego")
	gov := filepath.Join(d, "gov")
	if err := os.MkdirAll(filepath.Join(gov, "blobs"), 0o700); err != nil {
		t.Fatal(err)
	}
	seg := filepath.Join(gov, "gov-2026-10.jsonl")
	if err := os.WriteFile(seg, []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	check := guardTego([]string{d}, nil)
	if err := check(); err != nil {
		t.Fatalf("untouched: %v", err)
	}
	f, err := os.OpenFile(seg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("b\n")
	_ = f.Close()
	next := filepath.Join(gov, "gov-2026-11.jsonl")
	blob := filepath.Join(gov, "blobs", strings.Repeat("ab", 32))
	for _, p := range []string{next, blob} {
		if err := os.WriteFile(p, []byte("c"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	err = check()
	for _, want := range []string{seg + " (written)", next + " (made)", blob + " (made)"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("the guard's report %v does not say %s", err, want)
		}
	}
}

// TestGuardTegoSeesWhatAChangedHomeHolds: a new run directory, an appended chain.log, a made ~/.tego and a
// removed entry are each reported, and an untouched directory is not.
func TestGuardTegoSeesWhatAChangedHomeHolds(t *testing.T) {
	d := filepath.Join(t.TempDir(), ".tego")
	check := guardTego([]string{d}, nil)
	if err := check(); err != nil {
		t.Fatalf("an absent, untouched ~/.tego: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(d, "runs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil || !strings.Contains(err.Error(), d+" (made)") {
		t.Fatalf("a made ~/.tego: %v", err)
	}

	anchor := filepath.Join(d, "chain.log")
	if err := os.WriteFile(anchor, []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	check = guardTego([]string{d}, nil)
	if err := check(); err != nil {
		t.Fatalf("untouched: %v", err)
	}
	f, err := os.OpenFile(anchor, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("b\n")
	_ = f.Close()
	if err := os.Mkdir(filepath.Join(d, "runs", "r-1"), 0o700); err != nil {
		t.Fatal(err)
	}
	err = check()
	if err == nil || !strings.Contains(err.Error(), anchor+" (written)") || !strings.Contains(err.Error(), filepath.Join(d, "runs", "r-1")+" (made)") {
		t.Fatalf("an appended anchor and a new run: %v", err)
	}

	check = guardTego([]string{d}, nil)
	if err := os.Remove(anchor); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil || !strings.Contains(err.Error(), anchor+" (removed)") {
		t.Fatalf("a removed anchor: %v", err)
	}
}

// TestGuardTegoSeesAWrittenShellHistory: a shell history file beside ~/.tego that a test made, appended to or
// removed is reported (a shell on a pseudo-terminal, or bash -i, saves what was typed there when it exits), and
// one that nothing touched is not, whether or not it exists.
func TestGuardTegoSeesAWrittenShellHistory(t *testing.T) {
	home := t.TempDir()
	hist := filepath.Join(home, ".bash_history")
	dirs, files := []string{filepath.Join(home, ".tego")}, []string{hist}
	check := guardTego(dirs, files)
	if err := check(); err != nil {
		t.Fatalf("an absent, untouched history: %v", err)
	}
	if err := os.WriteFile(hist, []byte("ls\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil || !strings.Contains(err.Error(), hist+" (made)") {
		t.Fatalf("a made history: %v", err)
	}
	check = guardTego(dirs, files)
	if err := check(); err != nil {
		t.Fatalf("untouched: %v", err)
	}
	f, err := os.OpenFile(hist, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("tego run agent.yaml\n")
	_ = f.Close()
	if err := check(); err == nil || !strings.Contains(err.Error(), hist+" (written)") {
		t.Fatalf("an appended history: %v", err)
	}
	check = guardTego(dirs, files)
	if err := os.Remove(hist); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil || !strings.Contains(err.Error(), hist+" (removed)") {
		t.Fatalf("a removed history: %v", err)
	}
}

// TestRealShellHistoriesAreBesideTheRealTego: the history files the guard watches are the ~/.bash_history of
// each home whose ~/.tego it watches, found through passwd as those are, never through $HOME.
func TestRealShellHistoriesAreBesideTheRealTego(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var want []string
	for _, d := range RealTegoDirs() {
		want = append(want, filepath.Join(filepath.Dir(d), ".bash_history"))
	}
	if got := RealShellHistories(); !slices.Equal(got, want) {
		t.Fatalf("RealShellHistories() = %v, want %v", got, want)
	}
}

// TestUnderRealTego: a path is under a real ~/.tego only by whole components.
func TestUnderRealTego(t *testing.T) {
	dirs := RealTegoDirs()
	if len(dirs) == 0 { // no passwd home for this uid: nothing is under one
		if UnderRealTego("/root/.tego") {
			t.Error("a path is under a real ~/.tego with none to be under")
		}
		return
	}
	d := dirs[0]
	for path, want := range map[string]bool{d: true, d + "/runs": true, d + "/runs/../chain.log": true, d + "-other/runs": false, "/tmp/x/.tego/runs": false} {
		if got := UnderRealTego(path); got != want {
			t.Errorf("UnderRealTego(%q) = %v, want %v", path, got, want)
		}
	}
}

// TestGuardTegoSeesAWriteInsideARun: a file of an existing run directory that a test appended to, chmodded,
// made or removed is reported (a sweep or a gc reaching the real ledger root edits a run's events.jsonl in place),
// and the same tree untouched is not.
func TestGuardTegoSeesAWriteInsideARun(t *testing.T) {
	d := filepath.Join(t.TempDir(), ".tego")
	run := filepath.Join(d, "runs", "r-old")
	if err := os.MkdirAll(run, 0o700); err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(run, "events.jsonl")
	if err := os.WriteFile(events, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	check := guardTego([]string{d}, nil)
	if err := check(); err != nil {
		t.Fatalf("untouched: %v", err)
	}
	f, err := os.OpenFile(events, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("{}\n")
	_ = f.Close()
	if err := check(); err == nil || !strings.Contains(err.Error(), events+" (written)") {
		t.Fatalf("an event appended to an existing run: %v", err)
	}

	check = guardTego([]string{d}, nil)
	if err := os.Chmod(events, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil || !strings.Contains(err.Error(), events+" (written)") {
		t.Fatalf("an existing run's file chmodded: %v", err)
	}

	check = guardTego([]string{d}, nil)
	lock := filepath.Join(run, "lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(events); err != nil {
		t.Fatal(err)
	}
	err = check()
	if err == nil || !strings.Contains(err.Error(), lock+" (made)") || !strings.Contains(err.Error(), events+" (removed)") {
		t.Fatalf("a file made and one removed in an existing run: %v", err)
	}
}

// TestGuardRealTegoWatchesWhatItsPathsName: GuardRealTego checks the directories and files guardPaths names,
// the shell history among them, and reports a history written after it was called.
func TestGuardRealTegoWatchesWhatItsPathsName(t *testing.T) {
	home := t.TempDir()
	hist := filepath.Join(home, ".bash_history")
	if err := os.WriteFile(hist, []byte("ls\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := guardPaths
	t.Cleanup(func() { guardPaths = saved })
	guardPaths = func() ([]string, []string) { return []string{filepath.Join(home, ".tego")}, []string{hist} }
	check := GuardRealTego()
	if err := check(); err != nil {
		t.Fatalf("untouched: %v", err)
	}
	if err := os.WriteFile(hist, []byte("ls\ntego run agent.yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil || !strings.Contains(err.Error(), hist+" (written)") {
		t.Fatalf("GuardRealTego missed a written history: %v", err)
	}
}

// TestRealGuardPathsAreTheRealHomes: what GuardRealTego watches outside this package's own tests is every
// RealTegoDirs directory and every RealShellHistories file.
func TestRealGuardPathsAreTheRealHomes(t *testing.T) {
	dirs, files := guardPaths()
	if !slices.Equal(dirs, RealTegoDirs()) {
		t.Errorf("directories %v, want RealTegoDirs %v", dirs, RealTegoDirs())
	}
	if !slices.Equal(files, RealShellHistories()) {
		t.Errorf("files %v, want RealShellHistories %v", files, RealShellHistories())
	}
}

// TestGuardTegoSeesAWriteThroughASymlinkedHistory: a ~/.bash_history that is a symbolic link (a dotfiles manager's
// stow or chezmoi link) is watched by its target too, so a line appended through the link is reported; a link
// pointed elsewhere is reported as well, and the link untouched is not.
func TestGuardTegoSeesAWriteThroughASymlinkedHistory(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(t.TempDir(), "history")
	if err := os.WriteFile(target, []byte("ls\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hist := filepath.Join(home, ".bash_history")
	if err := os.Symlink(target, hist); err != nil {
		t.Fatal(err)
	}
	dirs, files := []string{filepath.Join(home, ".tego")}, []string{hist}
	check := guardTego(dirs, files)
	if err := check(); err != nil {
		t.Fatalf("untouched: %v", err)
	}
	f, err := os.OpenFile(hist, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("tego run agent.yaml\n")
	_ = f.Close()
	if err := check(); err == nil || !strings.Contains(err.Error(), hist+" (written)") {
		t.Fatalf("a history appended through its link: %v", err)
	}

	other := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(other, []byte("ls\ntego run agent.yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	check = guardTego(dirs, files)
	if err := os.Remove(hist); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, hist); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil || !strings.Contains(err.Error(), hist) {
		t.Fatalf("a history link pointed elsewhere: %v", err)
	}
}

// TestGuardedRunFailsTheBinaryOnAChangedHome: the code guardedRun, under GuardedMain and GuardedLeakCheckMain,
// returns is the tests' own when nothing the guard watches changed, and non-zero, with the guard's FAIL line on
// stderr, when the tests wrote it, whatever the tests returned (TestGuardedMainsFailTheBinary holds the helpers).
func TestGuardedRunFailsTheBinaryOnAChangedHome(t *testing.T) {
	home := t.TempDir()
	hist := filepath.Join(home, ".bash_history")
	saved := guardPaths
	t.Cleanup(func() { guardPaths = saved })
	guardPaths = func() ([]string, []string) { return []string{filepath.Join(home, ".tego")}, []string{hist} }
	for _, code := range []int{0, 3} {
		var stderr bytes.Buffer
		if got := guardedRun(func() int { return code }, &stderr); got != code || stderr.Len() != 0 {
			t.Errorf("tests that return %d and touch nothing: code %d, stderr %q", code, got, stderr.String())
		}
	}
	for i, code := range []int{0, 3} {
		var stderr bytes.Buffer
		got := guardedRun(func() int {
			if err := os.WriteFile(hist, []byte(strings.Repeat("x\n", i+1)), 0o600); err != nil {
				t.Fatal(err)
			}
			return code
		}, &stderr)
		if got == 0 || !strings.Contains(stderr.String(), "FAIL: ") || !strings.Contains(stderr.String(), hist) {
			t.Errorf("tests that return %d and write the history: code %d, stderr %q", code, got, stderr.String())
		}
	}
}

// guardChildEnv is "clean:<dir>" or "write:<dir>" in this test binary as TestGuardedMainsFailTheBinary re-executes
// it: the guard of the binary's own TestMain then also watches <dir>/.tego and <dir>/.bash_history, beside the real
// homes and never instead of them, and TestGuardChild makes that history in write mode. <dir> is the child's only
// when guardChildDir accepts it: a directory inside the temporary directory, holding the marker the parent wrote,
// that is no real home. The child only makes the history (O_EXCL), never opens one that exists. So the variable set
// by mistake fails this package, weakens no guard and changes no file (identity-config.md R27 (b3):
// a write:<home> used to truncate that home's history before the guard reported it).
const guardChildEnv = "TEGO_TESTUTIL_GUARD_CHILD"

// guardChildMarker is the file TestGuardedMainsFailTheBinary writes in each directory it hands the child.
const guardChildMarker = "guard-child.marker"

// guardChildRealHomes names the real homes guardChildDir refuses: RealTegoDirs and RealShellHistories. Only
// TestGuardChildDirIsNeverARealHome replaces it, to show that refusal holds for a directory no other check refuses.
var guardChildRealHomes = func() (dirs, files []string) { return RealTegoDirs(), RealShellHistories() }

// guardChildDir refuses a directory the child must not watch or write: one that is not absolute, not inside the
// temporary directory, a real home (its .tego under RealTegoDirs, its .bash_history among RealShellHistories,
// symbolic links resolved), or without the parent's marker.
func guardChildDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%s=%q: not an absolute directory", guardChildEnv, dir)
	}
	tmp, err := filepath.Abs(os.TempDir())
	if err != nil {
		return err
	}
	// Inside the temporary directory, and not that directory itself (or a parent of it).
	if !realtego.Under(dir, []string{tmp}) || realtego.Under(tmp, []string{dir}) {
		return fmt.Errorf("%s=%q: not inside the temporary directory %s", guardChildEnv, dir, tmp)
	}
	realDirs, realFiles := guardChildRealHomes()
	if realtego.Under(filepath.Join(dir, ".tego"), realDirs) || realtego.Under(filepath.Join(dir, shellHistory), realFiles) {
		return fmt.Errorf("%s=%q: a real home", guardChildEnv, dir)
	}
	if st, err := os.Lstat(filepath.Join(dir, guardChildMarker)); err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("%s=%q: no %s the parent test wrote", guardChildEnv, dir, guardChildMarker)
	}
	return nil
}

func init() {
	_, dir, ok := strings.Cut(os.Getenv(guardChildEnv), ":")
	if !ok || guardChildDir(dir) != nil {
		return
	}
	homes := guardPaths
	guardPaths = func() ([]string, []string) {
		dirs, files := homes()
		return append(dirs, filepath.Join(dir, ".tego")), append(files, filepath.Join(dir, shellHistory))
	}
}

// TestGuardChild is the re-executed binary's test: in a write mode it makes the history of the directory
// guardChildEnv names, as a test that reached the developer's own ~/.bash_history would, and then ends as the mode
// says: returns (write), panics (write-panic), waits for the -test.timeout alarm (write-timeout) or for a signal
// (write-hold), or kills its own process (write-kill); in clean mode, or without the variable, it writes nothing. A
// variable naming a directory guardChildDir refuses, a history that already exists, or an unknown mode fails it with
// nothing written.
func TestGuardChild(t *testing.T) {
	v := os.Getenv(guardChildEnv)
	if v == "" {
		return
	}
	mode, dir, _ := strings.Cut(v, ":")
	if err := guardChildDir(dir); err != nil {
		t.Fatal(err)
	}
	switch mode {
	case "clean":
		return
	case "write", "write-panic", "write-timeout", "write-hold", "write-kill":
	default:
		t.Fatalf("%s=%q: unknown mode %q", guardChildEnv, v, mode)
	}
	f, err := os.OpenFile(filepath.Join(dir, shellHistory), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("tego run agent.yaml\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatal(err)
	}
	switch mode {
	case "write-panic":
		panic("TestGuardChild panics after it wrote the history")
	case "write-timeout", "write-hold":
		time.Sleep(time.Hour)
	case "write-kill":
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		time.Sleep(time.Hour)
	}
}

// goTestArgs are the arguments go test starts every test binary with that GuardedMain reads: with them it runs the
// tests in a re-executed child and checks after the child ended, however it ended.
var goTestArgs = []string{"-test.paniconexit0"}

// TestGuardedMainsFailTheBinary: this package's TestMain exits with GuardedLeakCheckMain's code, which runs
// GuardedMain, so a re-executed binary whose one test writes a watched history exits non-zero with the guard's FAIL
// line naming it, and one whose test writes nothing exits 0, whether the guard runs in the binary's own process (a
// helper's re-exec, a binary run by hand) or, as go test starts it, around a child that runs the tests. It fails if
// either exported helper stops running the guard (returns m.Run() or LeakCheckMain(m)), which guardedRun's own test
// cannot see. As go test starts the binary, a test that wrote the history and then panicked, ran into -test.timeout,
// was killed or was signalled through the binary is reported too (the check ran only when m.Run returned, so each of
// those exited 2 or by the signal with no word of the history it wrote).
func TestGuardedMainsFailTheBinary(t *testing.T) {
	command := func(mode, dir string, args ...string) (*exec.Cmd, *bytes.Buffer) {
		cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestGuardChild$", "-test.count=1"}, args...)...)
		cmd.Env = append(os.Environ(), guardChildEnv+"="+mode+":"+dir)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		return cmd, &out
	}
	codeOf := func(err error, out *bytes.Buffer) (int, string) {
		t.Helper()
		var exit *exec.ExitError
		switch {
		case err == nil:
			return 0, out.String()
		case errors.As(err, &exit):
			return exit.ExitCode(), out.String()
		}
		t.Fatalf("running the child: %v", err)
		return 0, ""
	}
	run := func(mode, dir string, args ...string) (int, string) {
		t.Helper()
		cmd, out := command(mode, dir, args...)
		return codeOf(cmd.Run(), out)
	}
	// marked is a directory of this test's own, holding the marker that tells the child this parent made it.
	marked := func() string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, guardChildMarker), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	reported := func(code int, out, hist string) bool {
		return code != 0 && strings.Contains(out, "FAIL: these tests touched") && strings.Contains(out, hist+" (made)")
	}
	for _, how := range []struct {
		name string
		args []string
	}{{"in its own process", nil}, {"as go test starts it", goTestArgs}} {
		if code, out := run("clean", marked(), how.args...); code != 0 {
			t.Fatalf("%s, a child that wrote nothing exited %d:\n%s", how.name, code, out)
		}
		dir := marked()
		hist := filepath.Join(dir, ".bash_history")
		if code, out := run("write", dir, how.args...); !reported(code, out, hist) {
			t.Fatalf("%s, a child that wrote %s exited %d, want non-zero with the guard's FAIL line naming it:\n%s",
				how.name, hist, code, out)
		}
	}
	for _, end := range []struct {
		mode string
		args []string
		want string // what else the output must hold
	}{
		{"write-panic", goTestArgs, "panic: TestGuardChild panics after it wrote the history"},
		{"write-timeout", append([]string{"-test.timeout=2s"}, goTestArgs...), "panic: test timed out after 2s"},
		{"write-kill", goTestArgs, "ended by signal killed"},
	} {
		dir := marked()
		hist := filepath.Join(dir, ".bash_history")
		if code, out := run(end.mode, dir, end.args...); !reported(code, out, hist) || !strings.Contains(out, end.want) {
			t.Errorf("a child in %s mode exited %d, want non-zero with %q and the guard's FAIL line naming %s:\n%s",
				end.mode, code, end.want, hist, out)
		}
	}
	// A signal to the binary go test started (go test's SIGQUIT when a test outlives its -timeout) reaches the tests,
	// and the guard checks once they ended.
	dir := marked()
	hist := filepath.Join(dir, ".bash_history")
	cmd, out := command("write-hold", dir, goTestArgs...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Lstat(hist); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("the held child never wrote %s:\n%s", hist, out)
		}
	}
	_ = cmd.Process.Signal(syscall.SIGQUIT)
	if code, out := codeOf(cmd.Wait(), out); !reported(code, out, hist) || !strings.Contains(out, "SIGQUIT: quit") {
		t.Errorf("a held child sent SIGQUIT through the binary exited %d, want non-zero with its goroutine dump and the "+
			"guard's FAIL line naming %s:\n%s", code, hist, out)
	}

	// The guard's own marker set by mistake (a bogus pid, or a pid that is not the binary's parent) weakens nothing:
	// the binary takes its own snapshot and reports the history.
	for _, v := range []string{"1", "0", "x", strconv.Itoa(os.Getpid() + 1)} {
		dir := marked()
		hist := filepath.Join(dir, ".bash_history")
		cmd, out := command("write", dir, goTestArgs...)
		cmd.Env = append(cmd.Env, guardParentEnv+"="+v)
		if code, out := codeOf(cmd.Run(), out); !reported(code, out, hist) {
			t.Errorf("%s=%s set by mistake: a child that wrote %s exited %d, want non-zero with the guard's FAIL line:\n%s",
				guardParentEnv, v, hist, code, out)
		}
	}

	// The variable set by mistake, at a directory holding a history, fails the
	// package and leaves the history as it was: the child only makes a history, never opens one that exists.
	dir = marked()
	hist = filepath.Join(dir, ".bash_history")
	const kept = "one\ntwo\nthree\n"
	if err := os.WriteFile(hist, []byte(kept), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := run("write", dir); code == 0 {
		t.Errorf("a child aimed at an existing history exited 0, want non-zero:\n%s", out)
	}
	if b, err := os.ReadFile(hist); err != nil || string(b) != kept {
		t.Errorf("a child aimed at an existing history left it %q (%v), want %q", b, err, kept)
	}

	// A directory this test did not mark (the developer's home, say) is not the child's to write: it fails and makes
	// nothing there.
	dir = t.TempDir()
	if code, out := run("write", dir); code == 0 || !strings.Contains(out, guardChildMarker) {
		t.Errorf("a child aimed at an unmarked directory exited %d, want non-zero naming the marker:\n%s", code, out)
	}
	if _, err := os.Lstat(filepath.Join(dir, ".bash_history")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a child aimed at an unmarked directory made a history there: %v", err)
	}
}

// TestGuardChildDirIsNeverARealHome: the directory guardChildEnv names is the child's only when it lies inside the
// temporary directory, is not a real home (its .tego under RealTegoDirs or its history among RealShellHistories) and
// holds the parent's marker; anything else is refused before the child opens a file.
func TestGuardChildDirIsNeverARealHome(t *testing.T) {
	ok := t.TempDir()
	if err := os.WriteFile(filepath.Join(ok, guardChildMarker), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := guardChildDir(ok); err != nil {
		t.Fatalf("a marked directory of the test's own was refused: %v", err)
	}
	for _, d := range RealTegoDirs() {
		if err := guardChildDir(filepath.Dir(d)); err == nil {
			t.Errorf("the real home %s was accepted", filepath.Dir(d))
		}
	}
	for _, bad := range []string{"relative/dir", "/", "/etc", filepath.Dir(os.TempDir())} {
		if err := guardChildDir(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if err := guardChildDir(t.TempDir()); err == nil || !strings.Contains(err.Error(), guardChildMarker) {
		t.Errorf("an unmarked directory: %v, want a refusal naming the marker", err)
	}

	// Each refusal holds on its own, for a directory that every other check accepts.
	// A marked directory, no real home, that is outside the temporary directory (TMPDIR is its sibling).
	base := t.TempDir()
	tmp, outside := filepath.Join(base, "tmp"), filepath.Join(base, "outside")
	for _, d := range []string{tmp, outside} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, guardChildMarker), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmp)
	if err := guardChildDir(outside); err == nil || !strings.Contains(err.Error(), "not inside the temporary directory "+tmp) {
		t.Errorf("a marked directory outside the temporary directory: %v, want a refusal naming %s", err, tmp)
	}
	// A marked directory inside the temporary directory whose .tego, or whose history, is a real one.
	home := filepath.Join(tmp, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, guardChildMarker), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := guardChildDir(home); err != nil {
		t.Fatalf("a marked directory inside the temporary directory, no real home: %v", err)
	}
	saved := guardChildRealHomes
	t.Cleanup(func() { guardChildRealHomes = saved })
	for name, homes := range map[string]func() ([]string, []string){
		"its .tego": func() ([]string, []string) { return []string{filepath.Join(home, ".tego")}, nil },
		"its history": func() ([]string, []string) {
			return []string{filepath.Join(base, ".tego")}, []string{filepath.Join(home, shellHistory)}
		},
	} {
		guardChildRealHomes = homes
		if err := guardChildDir(home); err == nil || !strings.Contains(err.Error(), "a real home") {
			t.Errorf("a marked directory inside the temporary directory, %s real: %v, want a refusal as a real home", name, err)
		}
	}
}

// TestStartedByGoTestReadsGoTestsArguments: the guard runs the tests in a child exactly when the binary holds
// -test.paniconexit0, which go test gives every test binary it starts and a test's re-exec of its own binary as a
// helper does not, and is no fuzzing worker (whose coordinator's guard already watches it).
func TestStartedByGoTestReadsGoTestsArguments(t *testing.T) {
	for _, c := range []struct {
		args []string
		want bool
	}{
		{[]string{"-test.testlogfile=/x/testlog.txt", "-test.paniconexit0", "-test.timeout=10m0s", "-test.count=1"}, true},
		{[]string{"--test.paniconexit0"}, true},
		{[]string{"-test.paniconexit0=true"}, true},
		{[]string{"-test.paniconexit0=false"}, false},
		{[]string{"-test.paniconexit0=x"}, false},
		{nil, false},
		{[]string{"-test.run=^TestHelper$", "-test.timeout=30s"}, false},
		{[]string{"-test.paniconexit0", "-test.fuzzworker"}, false},
		{[]string{"-test.paniconexit0", "-test.fuzzworker=false"}, true},
		{[]string{"--", "-test.paniconexit0"}, false},
		{[]string{"test.paniconexit0"}, false},
		{[]string{"-test.paniconexit0x"}, false},
	} {
		if got := startedByGoTest(c.args); got != c.want {
			t.Errorf("startedByGoTest(%q) = %v, want %v", c.args, got, c.want)
		}
	}
}
