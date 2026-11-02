// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// stdioChildEnv makes this test binary, re-executed by TestGuardedStdioLeakCheckMainFailsOnAClosedStdin, close its
// own descriptor 0 ("close") or leave it ("clean").
const stdioChildEnv = "TEGO_TESTUTIL_STDIO_CHILD"

// TestStdioChild is the re-executed binary's test. With stdioChildEnv "close" it closes descriptor 0, as a hand-built
// runner whose notify descriptor was left at its zero value did on shutdown (ADR 0023 C10 note), and opens a file,
// which then becomes descriptor 0.
func TestStdioChild(t *testing.T) {
	switch os.Getenv(stdioChildEnv) {
	case "":
		t.Skip("run as TestGuardedStdioLeakCheckMainFailsOnAClosedStdin's child")
	case "close":
		if err := os.Stdin.Close(); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(os.Args[0])
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
	}
}

// TestGuardedStdioLeakCheckMainFailsOnAClosedStdin runs this package's own test binary, whose TestMain exits with
// GuardedStdioLeakCheckMain's code, twice: clean, where the binary passes, and with a test that closes descriptor 0,
// where the binary must fail and say a standard descriptor was closed or replaced, although the test itself passed.
func TestGuardedStdioLeakCheckMainFailsOnAClosedStdin(t *testing.T) {
	run := func(mode string) (int, string) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestStdioChild$", "-test.count=1")
		cmd.Env = append(os.Environ(), stdioChildEnv+"="+mode)
		devnull, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = devnull.Close() }()
		var out bytes.Buffer
		cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, &out, &out
		err = cmd.Run()
		var exit *exec.ExitError
		switch {
		case err == nil:
			return 0, out.String()
		case errors.As(err, &exit):
			return exit.ExitCode(), out.String()
		}
		t.Fatalf("child: %v", err)
		return 0, ""
	}
	if code, out := run("clean"); code != 0 {
		t.Fatalf("a clean child exited %d:\n%s", code, out)
	}
	code, out := run("close")
	if code == 0 || !strings.Contains(out, "a test closed or replaced a standard descriptor") {
		t.Fatalf("a child that closed its stdin exited %d without the stdio check's FAIL line:\n%s", code, out)
	}
	if strings.Contains(out, "--- FAIL") {
		t.Fatalf("the child's own test should have passed, so the failure is the check's:\n%s", out)
	}
}
