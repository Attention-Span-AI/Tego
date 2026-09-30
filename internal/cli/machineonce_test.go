// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// countSources counts the machine config loads an invocation makes (machineSources is one per load).
func countSources(t *testing.T) *int {
	t.Helper()
	n := new(int)
	orig := machineSources
	t.Cleanup(func() { machineSources = orig })
	machineSources = func(uid int, secure bool) (s config.Sources, home string, d []config.Diagnostic) {
		*n++
		return orig(uid, secure)
	}
	return n
}

// TestRunIDCommandsLoadTheMachineOnce: a bare run id makes the ledger root, the prices, the anchor and
// drift's tables read one config.Load, not one each.
func TestRunIDCommandsLoadTheMachineOnce(t *testing.T) {
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())
	for _, args := range [][]string{{"measure", id}, {"learn", id}, {"drift", id}, {"events", id, "--verify"}, {"events", id}} {
		n := countSources(t)
		run(t, args...)
		if *n != 1 {
			t.Errorf("tego %s loaded the machine config %d times, want 1", strings.Join(args, " "), *n)
		}
	}
}

// TestRunNotFoundKeepsTheConfigDiagnostics: a group-writable layer that sets ledger_root is skipped, the
// built-in root is used and a valid run id reads as "no such run"; the skip is the only explanation.
func TestRunNotFoundKeepsTheConfigDiagnostics(t *testing.T) {
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())
	cfg := os.Getenv("TEGO_CONFIG")
	if err := os.Chmod(cfg, 0o666); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"events", "drift", "measure", "learn"} {
		code, _, errs := run(t, cmd, id)
		if code != identity.ExitUsage || !strings.Contains(errs, "no such run") && !strings.Contains(errs, "no run") {
			t.Fatalf("%s: exit %d, stderr:\n%s", cmd, code, errs)
		}
		if !strings.Contains(errs, "The layer was skipped.") {
			t.Errorf("%s: stderr does not say why the layer was skipped:\n%s", cmd, errs)
		}
	}
}
