// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"runtime/pprof"
	"strings"
	"testing"
)

// TestMain fails the binary on a leaked goroutine (LeakCheckMain), on a standard descriptor a test closed or
// replaced (GuardedStdioLeakCheckMain, TestGuardedStdioLeakCheckMainFailsOnAClosedStdin) and, as every package whose
// tests can start the tego binary does (tools/isocheck GO-4: TestTegoEnvIsolatesWhateverTheDeveloperExported
// builds that environment), when the invoking user's real ~/.tego or ~/.bash_history changed while the tests ran.
func TestMain(m *testing.M) {
	os.Exit(GuardedStdioLeakCheckMain(m))
}

// leakChildEnv makes this test binary, re-executed by TestLeakCheckMainFailsOnALeak, leak one goroutine.
const leakChildEnv = "TEGO_TESTUTIL_LEAK_CHILD"

// TestLeakChild is the re-executed binary's test. With leakChildEnv set it leaks a goroutine that waits
// on a channel only that goroutine can reach, which is the shape of a drain whose stop channel was
// dropped; without it the child is a clean run.
func TestLeakChild(t *testing.T) {
	switch os.Getenv(leakChildEnv) {
	case "":
		t.Skip("run as TestLeakCheckMainFailsOnALeak's child")
	case "leak":
		leakForever()
	}
}

// leakForever starts the goroutine TestLeakCheckMainFailsOnALeak expects the gate to name.
func leakForever() {
	stop := make(chan struct{})
	go func() { <-stop }()
}

// TestLeakCheckMainFailsOnALeak runs this package's own test binary twice: once clean, where the gate
// must pass, and once with a deliberately leaked goroutine, where it must fail the binary and name the
// goroutine's function. It is the gate's only proof that it can fail at all, since every package that
// wires it passes.
func TestLeakCheckMainFailsOnALeak(t *testing.T) {
	run := func(mode string) (int, string) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestLeakChild$", "-test.count=1")
		cmd.Env = append(os.Environ(), leakChildEnv+"="+mode)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
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
	if code, out := run("clean"); code != 0 {
		t.Fatalf("a clean run exited %d:\n%s", code, out)
	}
	code, out := run("leak")
	if code != 1 {
		t.Fatalf("a run that leaked a goroutine exited %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, "goroutine(s) leaked") || !strings.Contains(out, "leakForever") {
		t.Fatalf("the gate failed without naming the leaked goroutine:\n%s", out)
	}
}

// TestNoProfileFailsTheGate: a toolchain without the goroutineleak profile fails the check instead of
// passing it. The gate used to return 0 there, so a package it gated passed whether or not it leaked, on
// every build of the go 1.26.0 go.mod that did not pick Go 1.27 (ADR 0029 step 1).
func TestNoProfileFailsTheGate(t *testing.T) {
	prev := lookupProfile
	lookupProfile = func(string) *pprof.Profile { return nil }
	t.Cleanup(func() { lookupProfile = prev })
	var out bytes.Buffer
	if n, err := checkLeaks(&out); !errors.Is(err, errNoLeakProfile) || n != 0 {
		t.Fatalf("checkLeaks without the profile = %d, %v; want errNoLeakProfile", n, err)
	}
}
