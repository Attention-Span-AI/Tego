// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"slices"
	"strings"
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

// TestRulesHistoryAndUndoHandOff: `tego rules history` and `tego rules undo` are tego-control's: the engine hands each
// over with its verb, its one flag, and every other word after "--", in the order typed, so a word that starts with a dash
// is never read as a flag there. A first word that is a session's name is not read as a run id here, since the arguments
// are an agent or a file and a change id; the handoff happens once, and the engine reads nothing of its own standard input
// first (handOff replaces the process in place, internal/handoff Exec; TestHandoffPassesTheTerminalAndInput).
func TestRulesHistoryAndUndoHandOff(t *testing.T) {
	root := gcRoot(t)
	const id = identity.RunID("r-519c2703-0dmw7w54wuixg-naw97n")
	endedRunNamed(t, root, id, "helper")
	oldOpen, oldExec := openControl, execControl
	t.Cleanup(func() { openControl, execControl = oldOpen, oldExec })
	opened := 0
	openControl = func() (*handoff.Binary, error) { opened++; return &handoff.Binary{}, nil }
	var got []string
	execControl = func(_ *handoff.Binary, args, env []string) error {
		got = slices.Clone(args)
		return &handoff.Error{Code: handoff.CodeUnpinned, What: "test", Fix: "none"}
	}
	for _, c := range []struct{ args, want []string }{
		{[]string{"history", "helper-w97n"}, []string{"rules", "history", "--", "helper-w97n"}},
		{[]string{"history", "agent.yaml", "--json"}, []string{"rules", "history", "--json", "--", "agent.yaml"}},
		{[]string{"history", "--json", "/work/agent.yaml"}, []string{"rules", "history", "--json", "--", "/work/agent.yaml"}},
		{[]string{"undo", "helper-w97n"}, []string{"rules", "undo", "--", "helper-w97n"}},
		{[]string{"undo", "agent", "rc-123", "--yes"}, []string{"rules", "undo", "--yes", "--", "agent", "rc-123"}},
		{[]string{"undo", "--yes", "agent"}, []string{"rules", "undo", "--yes", "--", "agent"}},
		{[]string{"undo", "--", "-odd-name"}, []string{"rules", "undo", "--", "-odd-name"}},
	} {
		got, opened = nil, 0
		_, _, _ = run(t, append([]string{"rules"}, c.args...)...)
		if !slices.Equal(got, c.want) || opened != 1 {
			t.Errorf("rules %v: handed %v after %d opens, want %v after one", c.args, got, opened, c.want)
		}
	}
	// A flag the verb does not have is usage, and nothing is handed on.
	got, opened = nil, 0
	if code, _, errs := run(t, "rules", "undo", "--nonesuch", "agent"); code != identity.ExitUsage || opened != 0 || errs == "" {
		t.Errorf("an unknown flag: exit %d after %d opens: %q", code, opened, errs)
	}
	// The verbs are listed on the noun's page.
	_, out, _ := run(t, "rules")
	for _, want := range []string{"tego rules history <agent | file> [--json]", "tego rules undo <agent | file> [<id>] [--yes]"} {
		if !strings.Contains(out, want) {
			t.Errorf("tego rules lists no %q:\n%s", want, out)
		}
	}
}
