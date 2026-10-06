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

// noFDLeakChildEnv makes this test binary, re-executed by TestNoFDLeakFailsOnALeak, run TestNoFDLeakChild.
const noFDLeakChildEnv = "TEGO_TESTUTIL_NOFDLEAK_CHILD"

// TestNoFDLeakChild is the re-executed binary's test. In mode "leak" it opens a descriptor under NoFDLeak and
// never closes it; in mode "clean" it opens and closes one.
func TestNoFDLeakChild(t *testing.T) {
	mode := os.Getenv(noFDLeakChildEnv)
	if mode == "" {
		t.Skip("run as TestNoFDLeakFailsOnALeak's child")
	}
	NoFDLeak(t)
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "clean" {
		_ = f.Close()
		return
	}
	leaked = append(leaked, f) // kept reachable, so no finalizer closes it before the check
}

var leaked []*os.File

// TestNoFDLeakFailsOnALeak is NoFDLeak's negative control: a test that leaks one descriptor fails and the
// failure names it; the same test closing it passes. Every package that wires NoFDLeak passes, so this is the
// only proof it can fail at all.
func TestNoFDLeakFailsOnALeak(t *testing.T) {
	run := func(mode string) (int, string) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestNoFDLeakChild$", "-test.count=1")
		cmd.Env = append(os.Environ(), noFDLeakChildEnv+"="+mode)
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
		t.Fatalf("a run that leaked a descriptor exited %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, "leaked descriptors") || !strings.Contains(out, os.DevNull) {
		t.Fatalf("the check failed without naming the leaked descriptor:\n%s", out)
	}
}

// TestNoFDLeakRefusesParallel: NoFDLeak in a parallel test panics (through t.Setenv) rather than measure a
// table other tests are changing.
func TestNoFDLeakRefusesParallel(t *testing.T) {
	t.Run("parallel", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if recover() == nil {
				t.Error("NoFDLeak in a parallel test did not panic")
			}
		}()
		NoFDLeak(t)
	})
}

// TestFDGrowth: growth names the new numbers; a number reopened on another file is not growth.
func TestFDGrowth(t *testing.T) {
	before := map[int]string{3: "/a", 4: "/b"}
	if g := fdGrowth(before, map[int]string{3: "/a", 4: "/c"}); g != "" {
		t.Errorf("a reopened number counted as growth: %s", g)
	}
	g := fdGrowth(before, map[int]string{3: "/a", 4: "/b", 7: "/x"})
	if !strings.Contains(g, "7 -> /x") {
		t.Errorf("growth = %q, want it to name 7 -> /x", g)
	}
}

// TestNoFDLeakFailsWithoutATable: an unreadable table fails the test rather than pass it unchecked.
func TestNoFDLeakFailsWithoutATable(t *testing.T) {
	prev := fdDir
	fdDir = t.TempDir() + "/missing"
	defer func() { fdDir = prev }()
	if _, err := openFDs(); err == nil {
		t.Fatal("openFDs of a missing directory succeeded")
	}
}
