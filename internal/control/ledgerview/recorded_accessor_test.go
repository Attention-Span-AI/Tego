// SPDX-License-Identifier: Apache-2.0

package ledgerview

import "testing"

// TestRecordedCommandAccessor: the two readings of a line's program and where each comes from. Program is the file
// that ran (the recorded path); Argv0 is the program as the command names it (the first recorded argument, which may
// be a bare name). A line with one of the fields gives both readings from it, and a record too old to carry either
// keeps the reading it had, the first word of its text.
func TestRecordedCommandAccessor(t *testing.T) {
	for _, c := range []struct {
		name           string
		e              Event
		program, argv0 string
	}{
		{"a path and arguments", Event{Target: "/opt/my tools/curl --help", path: "/opt/my tools/curl", argv: []string{"/opt/my tools/curl", "--help"}}, "/opt/my tools/curl", "/opt/my tools/curl"},
		{"a bare name", Event{Target: "git status", path: "/usr/bin/git", argv: []string{"git", "status"}}, "/usr/bin/git", "git"},
		{"arguments and no path", Event{Target: "/opt/my tools/tar -x", argv: []string{"/opt/my tools/tar", "-x"}}, "/opt/my tools/tar", "/opt/my tools/tar"},
		{"a path and no arguments (a mirror)", Event{Target: "/opt/my tools/wget", path: "/opt/my tools/wget"}, "/opt/my tools/wget", "/opt/my tools/wget"},
		{"neither field (an old record)", Event{Target: "/usr/bin/curl --help"}, "/usr/bin/curl", "/usr/bin/curl"},
		{"nothing", Event{}, "", ""},
	} {
		if got := c.e.Program(); got != c.program {
			t.Errorf("%s: Program = %q, want %q", c.name, got, c.program)
		}
		if got := c.e.Argv0(); got != c.argv0 {
			t.Errorf("%s: Argv0 = %q, want %q", c.name, got, c.argv0)
		}
	}
	spaced := &Run{Command: "/opt/my tools/codex --no-daemon", command: []string{"/opt/my tools/codex", "--no-daemon"}}
	if spaced.program() != "codex" || spaced.CommandAgent() != "codex" {
		t.Errorf("recorded arguments: program %q, agent %q, want codex twice", spaced.program(), spaced.CommandAgent())
	}
	old := &Run{Command: "/usr/bin/claude --print"}
	if old.program() != "claude" || old.CommandAgent() != "claude" {
		t.Errorf("command text alone: program %q, agent %q, want claude twice", old.program(), old.CommandAgent())
	}
}
