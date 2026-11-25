// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestDoctorExitsMatchIdentity: the two "not offered" statuses spelled here are doctor's.
func TestDoctorExitsMatchIdentity(t *testing.T) {
	if doctorExitRequire != identity.ExitRequire || doctorExitFinding != identity.ExitFinding {
		t.Fatalf("doctor's not-offered exits %d and %d, identity says %d and %d", doctorExitRequire, doctorExitFinding,
			identity.ExitRequire, identity.ExitFinding)
	}
}

// recordingTB is a testing.TB whose Skipf and Fatalf record the call and return, so RequireTier's answer can be read.
type recordingTB struct {
	testing.TB
	skipped, failed bool
}

func (r *recordingTB) Helper()               {}
func (r *recordingTB) Skipf(string, ...any)  { r.skipped = true }
func (r *recordingTB) Fatalf(string, ...any) { r.failed = true }

// TestRequireTierSkipsOnlyWhenTheMachineSaysSo: a fake doctor exiting each status. 0 runs the test, 211 and 1 (no
// tier, or none at all) skip it, and every other end fails it: 125 (a refused machine config),
// a usage error, a signal, and a binary that is not there.
func TestRequireTierSkipsOnlyWhenTheMachineSaysSo(t *testing.T) {
	dir := t.TempDir()
	n := 0
	fake := func(body string) string {
		n++
		p := filepath.Join(dir, fmt.Sprintf("doctor-%d", n))
		if err := os.WriteFile(p, []byte("#!/bin/sh\necho doctor said something\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, c := range []struct {
		name            string
		bin             string
		skipped, failed bool
	}{
		{"offered", fake("exit 0"), false, false},
		{"below the tier", fake("exit 211"), true, false},
		{"no tier at all", fake("exit 1"), true, false},
		{"refused config", fake("exit 125"), false, true},
		{"usage", fake("exit 2"), false, true},
		{"killed", fake("kill -9 $$"), false, true},
		{"missing binary", filepath.Join(dir, "absent"), false, true},
	} {
		for _, withOutputFile := range []bool{false, true} {
			cmd := exec.Command(c.bin, "doctor", "--require", "cgroup")
			// The fake doctors read nothing of the invoking user's home; the command still gets the isolated environment
			// every run of a doctor gets, with a config of the test's own that does not exist.
			cmd.Env = TegoEnv(t, t.TempDir(), "TEGO_CONFIG="+filepath.Join(dir, "no-such-config.yaml"))
			if withOutputFile { // a case helper's command, as internal/runtime's crossOwner.command makes it
				f, err := os.Create(filepath.Join(t.TempDir(), "out"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = f.Close() })
				cmd.Stdout, cmd.Stderr = f, f
			}
			r := &recordingTB{TB: t}
			RequireTier(r, cmd, "cgroup")
			if r.skipped != c.skipped || r.failed != c.failed {
				t.Errorf("%s (output file set %t): skipped %t failed %t, want skipped %t failed %t", c.name, withOutputFile, r.skipped, r.failed, c.skipped, c.failed)
			}
		}
	}
}
