// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
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
		"two documents":    {"name: x\n---\nenv:\n  set:\n    A: s1\n", Unreadable + "\n\n\n\n\n"},
		"one document in markers": {"---\nenv:\n  set:\n    A: s1\n...\n",
			"---\nenv:\n  set:\n    A: (value hidden)\n...\n"},
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

// TestRedactEnvTextSpellings: however a key spells set (setSpellings, each env.set to the compiler), no value shows,
// whether the text parses or not; nor in UTF-16, which puts a zero byte beside each letter.
func TestRedactEnvTextSpellings(t *testing.T) {
	leaks := func(got string) bool { return strings.Contains(got, "s1") || strings.Contains(got, utf16LE("s1")) }
	for name, in := range setSpellings {
		for _, text := range []string{in, in + "bad: [\n"} {
			if got := RedactEnvText(text); leaks(got) || strings.Count(got, "\n") != strings.Count(text, "\n") {
				t.Errorf("%s: a value survived, or the line count changed:\n%q", name, got)
			}
		}
	}
	if got := RedactEnvText(utf16LE("env:\n  set:\n    A: s1\n")); leaks(got) {
		t.Errorf("UTF-16: a value survived:\n%q", got)
	}
}

// TestRedactEnvTextLineBreaks: YAML also ends a line at a CR alone, NEL, LS or PS, and reads UTF-16, so its line
// numbers there do not name the text's "\n" lines; a contract with env.set in such a form, which the compiler reads,
// is hidden whole. CR LF lines are still hidden line for line.
func TestRedactEnvTextLineBreaks(t *testing.T) {
	const text = "version: 0\nname: x\ncommand: [\"true\"]\nenv:\n  set:\n    A: s1\n    B: >-\n      s0\n      s1\n"
	leaks := func(got string) bool { return strings.Contains(got, "s1") || strings.Contains(got, utf16LE("s1")) }
	for name, in := range map[string]string{
		"CR alone": strings.ReplaceAll(text, "\n", "\r"),
		"NEL":      strings.ReplaceAll(text, "\n", "\u0085"),
		"LS":       strings.ReplaceAll(text, "\n", "\u2028"),
		"PS":       strings.ReplaceAll(text, "\n", "\u2029"),
		"UTF-16":   "\xff\xfe" + utf16LE(text),
	} {
		c, _, err := agent.LoadBytes("/proj/agent.yaml", []byte(in), &agent.ProfileChain{})
		if err != nil || c.Env.Set["A"] != "s1" {
			t.Fatalf("%s: the compiler does not read it as env.set: %v", name, err)
		}
		if got := RedactEnvText(in); leaks(got) || !strings.HasPrefix(got, Unreadable) {
			t.Errorf("%s: a value survived:\n%q", name, got)
		}
	}
	crlf := strings.ReplaceAll(text, "\n", "\r\n")
	if got := RedactEnvText(crlf); leaks(got) || !strings.Contains(got, "\n    A: "+Hidden+"\n    B: "+Hidden+"\n") {
		t.Errorf("CR LF: not hidden line for line:\n%q", got)
	}
}

// TestRedactEnvTextDocuments: a text of more than one YAML document, which the compiler refuses, is hidden whole:
// reading only its first document would show a later one's env.set values.
func TestRedactEnvTextDocuments(t *testing.T) {
	for name, in := range map[string]string{
		"in the second":         "name: x\n---\nenv:\n  set:\n    A: s1\n",
		"in both":               "env:\n  set:\n    A: s1\n---\nenv:\n  set:\n    B: s1\n",
		"after an end marker":   "name: x\n...\n---\nenv:\n  set:\n    A: s1\n",
		"a second that is torn": "name: x\n---\nenv:\n  set:\n    A: s1\n  bad: [\n",
	} {
		got := RedactEnvText(in)
		if strings.Contains(got, "s1") || !strings.HasPrefix(got, Unreadable+"\n") || strings.Count(got, "\n") != strings.Count(in, "\n") {
			t.Errorf("%s:\n%q", name, got)
		}
	}
}
