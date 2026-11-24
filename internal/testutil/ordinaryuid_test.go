// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestPtraceAttachSucceedsLeavesNoStop: an attach that works leaves the tracee running (state S, not t), where a bare
// attach and a detach from another thread left it in a stop its parent's Wait reported in place of its exit.
func TestPtraceAttachSucceedsLeavesNoStop(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skipf("sleep: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	if !PtraceAttachSucceeds(cmd.Process.Pid) {
		t.Skip("this kernel's Yama scope refuses an attach to a child")
	}
	state := func() string {
		b, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/stat")
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		return strings.Fields(s[strings.LastIndexByte(s, ')')+1:])[0]
	}
	deadline := time.Now().Add(5 * time.Second)
	for state() == "t" || state() == "T" {
		if time.Now().After(deadline) {
			t.Fatalf("the tracee is still stopped (state %s) after the attach returned", state())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// rerunSubjectEnv makes TestRerunSubject run its subtest; without it the test does nothing, so a plain run of the package
// passes it at once.
const rerunSubjectEnv = "TEGO_TESTUTIL_RERUN_SUBJECT"

// rerunSubjectName is a subtest name that is full of regular-expression syntax, as TestRulesUndoExitTable's "a file that
// cannot be written is exit 125 [io], and nothing is written" is.
const rerunSubjectName = "a name with [io], and (parens) . * + ?"

// TestRerunSubject is the subject of TestRerunPatternSelectsASubtestWhoseNameHoldsRegexpSyntax, started as a process of its own.
func TestRerunSubject(t *testing.T) {
	if os.Getenv(rerunSubjectEnv) == "" {
		return
	}
	t.Run(rerunSubjectName, func(t *testing.T) {})
}

// TestRerunPatternSelectsASubtestWhoseNameHoldsRegexpSyntax: the pattern RerunAsOrdinaryUser hands the child's -test.run
// selects exactly the test or subtest named, whatever characters its name holds. Unquoted, "[io]" is a character class,
// the pattern matches no name, and the child "passes" with no test run (RerunAsOrdinaryUser then fails the test for the
// missing PASS line).
func TestRerunPatternSelectsASubtestWhoseNameHoldsRegexpSyntax(t *testing.T) {
	full := "TestRerunSubject/" + strings.ReplaceAll(rerunSubjectName, " ", "_")
	run := func(pattern string) string {
		cmd := exec.Command(os.Args[0], "-test.run="+pattern, "-test.count=1", "-test.v")
		cmd.Env = append(os.Environ(), rerunSubjectEnv+"=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("-test.run=%s: %v\n%s", pattern, err, out)
		}
		return string(out)
	}
	if out := run(rerunPattern(full)); !strings.Contains(out, "--- PASS: "+full+" ") {
		t.Errorf("the pattern %q did not run the subtest:\n%s", rerunPattern(full), out)
	}
	if out := run(rerunPattern("TestRerunSubject")); !strings.Contains(out, "--- PASS: "+full+" ") {
		t.Errorf("the parent's pattern did not run its subtest:\n%s", out)
	}
	if out := run("^" + full + "$"); strings.Contains(out, "--- PASS: "+full+" ") {
		t.Errorf("the unquoted pattern ran the subtest; this test no longer shows why the pattern is quoted:\n%s", out)
	}
}
