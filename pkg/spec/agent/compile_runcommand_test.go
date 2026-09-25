// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"path/filepath"
	"testing"
)

// TestRunCommandIsGrantedForItsRun: the command `tego run` is given on
// its command line is the launching user's choice, and is granted as the run's own command for that run, as
// the contract's command is. A name found nowhere adds nothing and no diagnostic (its execve fails, exit 127),
// a name the contract's command already covers adds no second rule, and the contract hash does not move.
func TestRunCommandIsGrantedForItsRun(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [python]\nexec: {}\n")
	base, _ := f.compile(c)
	for _, tc := range []struct {
		name  string
		cmd   string
		grant string
		rules int
	}{
		{"a name on the run's PATH", "static-tool", filepath.Join(f.bin, "static-tool"), len(base.Exec) + 1},
		{"a path", filepath.Join(f.bin, "static-tool"), filepath.Join(f.bin, "static-tool"), len(base.Exec) + 1},
		{"the contract's own command", "python", filepath.Join(f.bin, "python"), len(base.Exec)},
		{"a name found nowhere", "no-such-tool", "", len(base.Exec)},
	} {
		rt, ds := f.compile(c, WithRunCommand(tc.cmd))
		if HasErrors(ds) {
			t.Errorf("%s: errors %s", tc.name, render(ds))
		}
		if len(rt.Exec) != tc.rules {
			t.Errorf("%s: %d exec rules, want %d: %+v", tc.name, len(rt.Exec), tc.rules, rt.Exec)
		}
		if rt.Hash != base.Hash {
			t.Errorf("%s: the run command moved the contract hash", tc.name)
		}
		// RunCommandGrant names a rule only when the run command added one.
		if added := tc.rules > len(base.Exec); (rt.RunCommandGrant != "") != added || (added && rt.RunCommandGrant != tc.grant) {
			t.Errorf("%s: RunCommandGrant = %q, want %q", tc.name, rt.RunCommandGrant, map[bool]string{true: tc.grant}[added])
		}
		if tc.grant == "" {
			continue
		}
		var found bool
		for _, r := range rt.Exec {
			if r.Path == tc.grant && r.Source == ExecSourceCommand {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: %s is not granted as the run's command: %+v", tc.name, tc.grant, rt.Exec)
		}
	}
	for _, r := range base.Exec {
		if r.Basename == "static-tool" {
			t.Errorf("without a run command static-tool is granted: %+v", r)
		}
	}
}
