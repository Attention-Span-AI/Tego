// SPDX-License-Identifier: Apache-2.0

package sig

import (
	"reflect"
	"testing"
)

func TestEvidenceKeepsGuardSelection(t *testing.T) {
	rules := append(Default(), Rule{Name: "path", Path: "/opt/custom"}, Rule{Name: "file", File: FileID{1, 2}})
	cases := []struct {
		name  string
		facts Facts
		want  Fact
	}{
		{"exe", Facts{Exe: "/bin/claude"}, FactExeName},
		{"argv0", Facts{Exe: "/bin/other", Argv: []string{"/bin/codex", "secret"}}, FactArgv0Name},
		{"comm", Facts{Exe: "/bin/other", Comm: "opencode"}, FactCommName},
		{"native precedes argv0", Facts{Exe: "/bin/claude", Argv: []string{"codex"}, Comm: "gemini"}, FactExeName},
		{"wrapper", Facts{Exe: "/bin/node", Argv: []string{"node", "--key=secret", "/lib/@openai/codex/bin/codex.js"}}, FactArgvPattern},
		{"path", Facts{Exe: "/opt/custom"}, FactPath},
		{"file", Facts{File: FileID{1, 2}}, FactFileID},
		{"unknown", Facts{Exe: "/bin/python3", Argv: []string{"python3", "secret.py"}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old, matched := rules.Match(tc.facts)
			var selected Rule
			var fact Fact
			var ok bool
			for _, r := range rules {
				f, hit := r.Evidence(tc.facts)
				if hit != r.Match(tc.facts) {
					t.Fatal("per-rule selection changed")
				}
				if hit && !ok {
					selected, fact, ok = r, f, true
				}
			}
			if ok != matched || !reflect.DeepEqual(selected, old) || fact != tc.want {
				t.Fatalf("selection or fact: %v %s %v", selected, fact, ok)
			}
		})
	}
}
