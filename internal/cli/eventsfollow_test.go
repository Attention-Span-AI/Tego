// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// fixtureLines is the frozen v1 fixture ledger's lines, each with its "\n".
func fixtureLines(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureRun(t), ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(data), "\n")
	if lines[len(lines)-1] != "" {
		t.Fatal("the fixture ledger does not end in a newline")
	}
	return lines[:len(lines)-1]
}

// TestEventsFollowOfAnEndedRunIsEvents: over a run that has ended, --follow prints exactly what events prints,
// table and --json alike, and exits 0.
func TestEventsFollowOfAnEndedRunIsEvents(t *testing.T) {
	dir := fixtureRun(t)
	for _, extra := range [][]string{nil, {"--json"}, {"--kind", "exec"}} {
		args := append([]string{"events", dir}, extra...)
		code, want, errs := run(t, args...)
		if code != identity.ExitOK {
			t.Fatalf("%v: exit %d (%s)", args, code, errs)
		}
		code, got, errs := run(t, append(args, "--follow")...)
		if code != identity.ExitOK {
			t.Fatalf("%v --follow: exit %d (%s)", args, code, errs)
		}
		if got != want {
			t.Fatalf("%v --follow printed\n%s\nevents prints\n%s", args, got, want)
		}
	}
}

// TestEventsFollowPrintsEachLineAndExitsAtRunEnd: following a live run prints the lines it holds, then each
// line its writer appends, byte for byte under --json, and exits 0 once run_end is written and the lock is
// released.
func TestEventsFollowPrintsEachLineAndExitsAtRunEnd(t *testing.T) {
	lines := fixtureLines(t)
	dir := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(dir, ledger.LockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := sys.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(dir, ledger.EventsFile)
	appendLines := func(ls []string) {
		f, err := os.OpenFile(events, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		if _, err := f.WriteString(strings.Join(ls, "")); err != nil {
			t.Fatal(err)
		}
	}
	held := 3
	appendLines(lines[:len(lines)-held])
	var out, errb lockedBuffer
	done := make(chan int, 1)
	go func() { done <- Main([]string{"tego", "events", dir, "--follow", "--json"}, &out, &errb) }()
	waitOut := func(want string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for out.String() != want {
			if time.Now().After(deadline) {
				t.Fatalf("stdout\n%s\nwant\n%s\n(stderr %q)", out.String(), want, errb.String())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitOut(strings.Join(lines[:len(lines)-held], ""))
	appendLines(lines[len(lines)-held : len(lines)-1])
	waitOut(strings.Join(lines[:len(lines)-1], ""))
	appendLines(lines[len(lines)-1:]) // run_end
	select {
	case code := <-done:
		t.Fatalf("exited %d before the lock was released (stderr %q)", code, errb.String())
	case <-time.After(300 * time.Millisecond):
	}
	_ = lock.Close()
	select {
	case code := <-done:
		if code != identity.ExitOK {
			t.Fatalf("exit %d at run_end (stderr %q)", code, errb.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("--follow did not exit at run_end")
	}
	if out.String() != strings.Join(lines, "") {
		t.Fatal("--follow --json is not the stored ledger byte for byte")
	}
}

// TestEventsFollowOfALostRun: a run with no run_end and nobody holding its lock will write no more: --follow
// prints what it holds and exits 125 [run-lost], never 0 as if it had ended.
func TestEventsFollowOfALostRun(t *testing.T) {
	lines := fixtureLines(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), []byte(strings.Join(lines[:len(lines)-1], "")), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "events", dir, "--follow", "--json")
	// limits-check-doctor-cli.md §7: the run directory named once, and every command that ends an orphan.
	want := "tego events: ledger: no writer holds the run's lock and its ledger ends without run_end: " + dir +
		"; the next tego run, tego stop or tego gc ends it as orphaned [run-lost]\n"
	if code != identity.ExitError || errs != want {
		t.Fatalf("exit %d, stderr %q; want 125 and %q", code, errs, want)
	}
	if out != strings.Join(lines[:len(lines)-1], "") {
		t.Fatal("the lines of the lost run were not all printed")
	}
}

// TestEventsFollowRefusesItsConflicts: --follow reads forward and waits, so it takes neither --last nor
// --verify.
func TestEventsFollowRefusesItsConflicts(t *testing.T) {
	dir := fixtureRun(t)
	for _, args := range [][]string{
		{"events", dir, "--follow", "--last"},
		{"events", dir, "--verify", "--follow"},
	} {
		code, _, errs := run(t, args...)
		if code != identity.ExitUsage || !strings.Contains(errs, "[usage]") {
			t.Errorf("%v: exit %d, stderr %q; want 2 [usage]", args, code, errs)
		}
	}
}

// TestEventsFollowNamesABreakInTheChain: a line whose prev names no line is 125 [ledger-corrupt] naming the
// file, after the rows before it.
func TestEventsFollowNamesABreakInTheChain(t *testing.T) {
	lines := fixtureLines(t)
	dir := t.TempDir()
	// The third line dropped: the fourth's prev names a line that is not there.
	broken := append(append([]string{}, lines[:2]...), lines[3:]...)
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), []byte(strings.Join(broken, "")), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "events", dir, "--follow", "--json")
	if code != identity.ExitError || !strings.Contains(errs, "[ledger-corrupt]") ||
		!strings.Contains(errs, filepath.Join(dir, ledger.EventsFile)) {
		t.Fatalf("exit %d, stderr %q; want 125 [ledger-corrupt] naming the file", code, errs)
	}
	if out != strings.Join(lines[:2], "") {
		t.Fatalf("printed %q, want the two lines before the break", out)
	}
}
