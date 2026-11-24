// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"strings"
	"testing"
)

// Installed systemd.service(5), systemd 257.9, COMMAND LINES table 2:
// @, -, :, +, !, !!, their permitted combinations, and the special forms
// immediately following the table. Shell prefix | is documented in v260.
func TestExecStartDocumentedForms(t *testing.T) {
	for _, tc := range []struct {
		name, raw  string
		args       int
		unresolved bool
	}{
		{"argv0", "@codex custom arg", 1, false},
		{"ignore-failure", "-codex arg", 1, false},
		{"literal-environment", ":codex $USER", 1, false},
		{"full-privileges", "+codex arg", 1, false},
		{"credentials", "!codex arg", 1, false},
		{"ambient-fallback", "!!codex arg", 1, false},
		{"combined", "+:-@codex custom $TEST", 1, false},
		{"combined-reordered", "@-:!!codex custom $TEST", 1, false},
		{"quoted-path-spaces", `"/opt/program files/codex" arg`, 1, false},
		{"absolute", "/usr/bin/codex arg", 1, false},
		{"unquoted-midword", `/usr/bin/co"dex" arg`, 1, false},
		{"literal-dollar", "codex $$USER", 1, false},
		{"environment-word", "codex $USER", 0, true},
		{"environment-part", "codex prefix${USER}", 0, true},
		{"executable-environment", "$COMMAND arg", 0, true},
		{"executable-specifier", "%h/codex arg", 0, true},
		{"argument-specifier", "codex %h", 1, false},
		{"escaped-semicolon", `codex / >/dev/null & \; ls`, 5, false},
		{"shell-explicit", "sh -c codex", 0, true},
		{"shell-prefix", "|codex", 0, true},
		{"shell-standalone", "| codex", 0, true},
		{"shell-argv0", "@|codex login", 0, true},
		{"shell-after-prefixes", "+:-@|codex login", 0, true},
		{"shell-ambient-fallback", "!!|codex", 0, true},
		{"shell-escaped", `"\x7ccodex"`, 0, true},
		{"shell-before-prefixes", "|@-:!codex login", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseExecStart([]byte(tc.raw))
			if tc.unresolved {
				if err != errUnresolved || got != (unitExec{}) {
					t.Fatalf("want unresolved without evidence, got %+v (%v)", got, err)
				}
			} else if err != nil || got.Program != "codex-native" || got.Arguments != tc.args {
				t.Fatalf("documented form: %+v (%v), want codex with %d args", got, err, tc.args)
			}
		})
	}
}

func TestUnitCombinedBudgetAfterFinalCommand(t *testing.T) {
	for _, suffix := range []string{"# padding\n", "; padding\n", "\n", "[Unit]\n", "Description=padding\n"} {
		t.Run(strings.TrimSpace(suffix), func(t *testing.T) {
			// Two physical lines and one ExecStart word leave 4093 physical lines.
			prefix := "[Service]\nExecStart=codex\n"
			good := prefix + strings.Repeat(suffix, unitTokenLimit-3)
			doc, err := parseUnit(t.Context(), strings.NewReader(good))
			if err != nil || len(doc.Exec) != 1 {
				t.Fatalf("exact combined cap refused: %+v (%v)", doc, err)
			}
			doc, err = parseUnit(t.Context(), strings.NewReader(good+suffix))
			if err != errLimit || len(doc.Exec) != 0 {
				t.Fatalf("post-command line bypassed combined cap: %+v (%v)", doc, err)
			}
		})
	}
}

func TestUnitDocumentedResetAndMultipleCommands(t *testing.T) {
	doc, err := parseUnit(t.Context(), strings.NewReader("[Service]\nType=oneshot\nExecStart=claude\nExecStart=\nExecStart=codex one\nExecStart=codex two three\n"))
	if err != nil || !doc.Reset || len(doc.Exec) != 2 || doc.Exec[0].Program != "codex-native" || doc.Exec[0].Arguments != 1 || doc.Exec[1].Arguments != 2 {
		t.Fatalf("documented reset/multiple commands: %+v (%v)", doc, err)
	}
}
