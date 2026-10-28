// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"strings"
	"testing"
)

// TestRedactEnvText: env.set values are hidden line for line, plain, quoted, block and flow, and nothing else moves.
func TestRedactEnvText(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"plain and block": {"name: x\nenv:\n  set:\n    A: one # c\n    B: |\n      two\n      three\n  pass: [PATH]\n",
			"name: x\nenv:\n  set:\n    A: (value hidden)\n    B: (value hidden)\n\n\n  pass: [PATH]\n"},
		"quoted": {"env:\n  set:\n    A: \"o:ne\"\n", "env:\n  set:\n    A: (value hidden)\n"},
		"flow":   {"env:\n  set: {A: one, B: two}\nname: x\n", "env:\n  set: {(value hidden)}\nname: x\n"},
		"none":   {"name: x\nset: 1\n", "name: x\nset: 1\n"},
		"flow over lines": {"env:\n  set: {\n    A: s1,\n    B: s2\n  }\nname: x\n",
			"env:\n  set: {(value hidden)}\n\n\n\nname: x\n"},
		"alias to a mapping": {"base: &a\n  A: s1\n  B: s2\nenv:\n  set: *a\n",
			"base: &a\n  A: (value hidden)\n  B: (value hidden)\nenv:\n  set: (value hidden)\n"},
		"not yaml":         {"set: [\n", Unreadable + "\n"},
		"not yaml, no set": {"a: [\n", "a: [\n"},
	} {
		if got := RedactEnvText(tc.in); got != tc.want {
			t.Errorf("%s:\n%q\nwant\n%q", name, got, tc.want)
		}
	}
}

// TestRedactEnvTextAnchors: a value reached through an anchor, an alias or a merge key never survives, and the line
// count stays.
func TestRedactEnvTextAnchors(t *testing.T) {
	for name, in := range map[string]string{
		"flow anchor":      "x: &a {A: s1,\n  B: s1}\nenv:\n  set: *a\n",
		"scalar anchor":    "s: &s s1\nenv:\n  set:\n    A: *s\n",
		"anchored value":   "env:\n  set:\n    A: &s s1\nother: *s\n",
		"env alias":        "e: &e\n  set:\n    A: s1\nenv: *e\n",
		"merge":            "b: &b\n  set:\n    A: s1\nenv:\n  <<: *b\n",
		"merge in set":     "b: &b\n  A: s1\nenv:\n  set:\n    <<: *b\n    B: s1\n",
		"block over lines": "env:\n  set:\n    A: >-\n      s1\n      s1\n",
	} {
		got := RedactEnvText(in)
		if strings.Contains(got, "s1") {
			t.Errorf("%s: a value survived:\n%s", name, got)
		}
		if strings.Count(got, "\n") != strings.Count(in, "\n") {
			t.Errorf("%s: line count changed:\n%q", name, got)
		}
	}
}
