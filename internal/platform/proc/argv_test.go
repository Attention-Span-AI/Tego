// SPDX-License-Identifier: Apache-2.0

package proc

import (
	"os"
	"os/exec"
	"slices"
	"testing"
)

// Read the kernel's argv bytes in a separate process so the final two empty
// arguments are actual exec arguments rather than a fabricated proc fixture.
func TestArgvKeepsRealEmptyTrailingArguments(t *testing.T) {
	const helper = "TEGO_PROC_EMPTY_ARGV_HELPER"
	if os.Getenv(helper) == "1" {
		got, err := New().Argv(os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, os.Args) {
			t.Fatalf("kernel argv %q, want exec arguments %q", got, os.Args)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestArgvKeepsRealEmptyTrailingArguments$", "-test.timeout=10s", "--", "tail", "", "")
	cmd.Env = append(os.Environ(), helper+"=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("argv helper: %v\n%s", err, out)
	}
}
