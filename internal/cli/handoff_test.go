// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/internal/handoff"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestRulesHandoffResolvesSessionAfterFlags(t *testing.T) {
	root := gcRoot(t)
	const id = identity.RunID("r-519c2703-0dmw7w54wuixg-naw97n")
	endedRunNamed(t, root, id, "helper")
	oldOpen, oldExec := openControl, execControl
	t.Cleanup(func() { openControl, execControl = oldOpen, oldExec })
	openControl = func() (*handoff.Binary, error) { return &handoff.Binary{}, nil }
	var got []string
	execControl = func(_ *handoff.Binary, args, env []string) error {
		got = slices.Clone(args)
		return &handoff.Error{Code: handoff.CodeUnpinned, What: "test", Fix: "none"}
	}
	for _, args := range [][]string{
		{"helper-w97n", "--json"}, {"--json", "helper-w97n"}, {"--", "helper-w97n"},
		{"--json=false", "helper-w97n"}, {"--json", "--", "helper-w97n"},
		{"--last"}, {"--nonesuch", "helper-w97n"}, {"--json", "unresolved-abcd"},
	} {
		want := append([]string{"rules"}, args...)
		for i, s := range want {
			if s == "helper-w97n" && args[0] != "--nonesuch" {
				want[i] = string(id)
			}
		}
		_, _, _ = run(t, append([]string{"rules"}, args...)...)
		if !slices.Equal(got, want) {
			t.Errorf("rules %v: handed %v, want %v", args, got, want)
		}
	}
}
