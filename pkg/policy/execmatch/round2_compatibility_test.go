// SPDX-License-Identifier: Apache-2.0
package execmatch_test

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

// These preserve the released readings while the newer private clauses are
// recommended for amendment.
func TestRawKnownOptionCompatibility(t *testing.T) {
	for _, list := range []execmatch.List{execmatch.ListDeny, execmatch.ListAsk} {
		p, err := execmatch.Parse("git --forc push", list, rows.Builtin())
		if err != nil {
			t.Fatal(err)
		}
		ix := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{p}, execmatch.IndexOptions{})
		f := execmatch.Facts{Requested: "git", Image: "git", Argv0: "git", Argv: []string{"git", "push", "--force"}, ArgvComplete: true}
		if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeNone {
			t.Errorf("%s changed literal raw option reading: %+v", list, r)
		}
	}
}

func TestIdentityAliasKeepsLiteralRuntimeGrant(t *testing.T) {
	id := execmatch.ID{Dev: 2, Ino: 414}
	for _, stage := range []bool{false, true} {
		grantArgv := []string{"x", "install"}
		f := execmatch.Facts{Requested: "x", Image: "x", Argv0: "x", Argv: []string{"x", "list"}, ArgvComplete: true, HasID: true, ID: id}
		if stage {
			grantArgv = []string{"script", "install", "script"}
			f = execmatch.Facts{Requested: "script", Image: "script", Argv0: "script", Argv: []string{"script"}, Path: "script", ArgvComplete: true, Form: execmatch.FormScript, Interp: []execmatch.Stage{{Path: "/tmp/x", Image: "x", HasID: true, ID: id, Arg: "install"}}}
		}
		p := execmatch.ExactPattern("harness-hook", "pip3", grantArgv)
		ix := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{p}, execmatch.IndexOptions{Identities: map[execmatch.ID]string{id: "pip3"}})
		if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused || !r.Unlisted {
			t.Errorf("stage %v literal identity lost constraint: %+v", stage, r)
		}
	}
}
