// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestHelpersForTheDefaultStateDirVerifyIt is ADR 0034 item 2 for the detached helpers: a launcher with no
// StateDir hands its linger timer and ring trimmer the default spelled out as hoststate.Path, and they opened that
// path with OpenAt, which skips the owner and mode check. A helper started for the default directory must open it
// verified, as the launcher did.
func TestHelpersForTheDefaultStateDirVerifyIt(t *testing.T) {
	var argv []string
	savedStart := startHelperProcess
	startHelperProcess = func(_ string, args ...string) error { argv = args; return nil }
	t.Cleanup(func() { startHelperProcess = savedStart })
	verified := 0
	savedOpen := openHostState
	openHostState = func() (*hoststate.Dir, error) {
		verified++
		return nil, errors.New("verified open refused in the test")
	}
	t.Cleanup(func() { openHostState = savedOpen })

	if err := startTimerProcess("/proc/self/exe", "h1", time.Minute, "", ""); err != nil {
		t.Fatal(err)
	}
	if len(argv) != 5 || argv[0] != LingerCommand {
		t.Fatalf("timer argv %q", argv)
	}
	if code := LingerMain(argv[1:]); code != identity.ExitError {
		t.Fatalf("LingerMain with the verified open refused: exit %d, want %d", code, identity.ExitError)
	}
	if verified != 1 {
		t.Fatalf("the timer for the default state directory opened it verified %d times, want 1", verified)
	}
	if code := RingTrimMain([]string{"h1", t.TempDir(), hoststate.Path + "/"}); code != identity.ExitError {
		t.Fatalf("RingTrimMain with the verified open refused: exit %d", code)
	}
	if verified != 2 {
		t.Fatalf("the ring trimmer for the default state directory did not open it verified (%d opens)", verified)
	}
	// A directory the caller chose (tests, Options.StateDir) is still its own to choose.
	if _, _, err := TrimRings(SweepOptions{BPFFS: t.TempDir(), StateDir: t.TempDir()}, "h1"); err != nil {
		t.Fatalf("TrimRings in a chosen directory: %v", err)
	}
	if verified != 2 {
		t.Fatal("a chosen state directory was opened as the host one")
	}
}
