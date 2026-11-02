// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestSetsEnv: env.set is decided on a parse; a text that is not one YAML document is held back only when it could
// spell a "set" key, so assets/, settings.json or reset in a broken text still reach their diagnostics.
func TestSetsEnv(t *testing.T) {
	for name, tc := range map[string]struct {
		in             string
		sets, readable bool
	}{
		"env.set":               {"env:\n  set:\n    A: x\n", true, true},
		"no env.set":            {"fs:\n  write: [./assets/]\nreset: 1\n", false, true},
		"broken, assets/":       {"fs:\n  write: [./assets/\n", false, false},
		"broken, settings.json": {"fs:\n  deny_read: [./settings.json]\n  bad: [\n", false, false},
		"broken, reset":         {"fs:\n  write: [./reset/, ./offset_set/, ./settle\n", false, false},
		"broken, set key":       {"env:\n  set:\n    A: [\n", true, false},
		"broken, flow set":      {"env: {set: {A: x}\n", true, false},
		"broken, UTF-16":        {utf16LE("env:\n  set:\n    A: x\n"), true, false},
		// A contract is one document: a second is not read past, and holds the editor back when it may hold a value.
		"two documents":           {"name: x\n---\nenv:\n  set:\n    A: x\n", true, false},
		"two documents, no set":   {"name: x\n---\nname: y\n", false, false},
		"a broken second":         {"name: x\n---\nenv: {set: [\n", true, false},
		"one document in markers": {"---\nenv:\n  set:\n    A: x\n...\n", true, true},
	} {
		if sets, readable := SetsEnv(tc.in); sets != tc.sets || readable != tc.readable {
			t.Errorf("%s: SetsEnv = %v, %v; want %v, %v", name, sets, readable, tc.sets, tc.readable)
		}
	}
}

// setSpellings are env.set written without the plain `set:` key of a block mapping. The compiler reads each as
// env.set {A: s1} (TestSetsEnvSpellings checks it).
var setSpellings = map[string]string{
	"tagged key":          "env:\n  !!str set:\n    A: s1\n",
	"explicit key":        "env:\n  ? set # the key\n  : {A: s1}\n",
	"tagged explicit key": "env:\n  ? !!str set # the key\n  : {A: s1}\n",
	"hex escape":          "env:\n  \"s\\x65t\":\n    A: s1\n",
	"unicode escape":      "env:\n  \"\\u0073et\":\n    A: s1\n",
	"long escape":         "env:\n  \"se\\U00000074\":\n    A: s1\n",
	"escaped line break":  "env:\n  ? \"se\\\n    t\"\n  : {A: s1}\n",
}

// TestSetsEnvSpellings: however a key spells set, a text that parses has env.set and one that does not parse is held
// back, so the editor never opens on a broken text's value.
func TestSetsEnvSpellings(t *testing.T) {
	for name, in := range setSpellings {
		c, _, err := agent.LoadBytes("/proj/agent.yaml", []byte("version: 0\nname: x\ncommand: [\"true\"]\n"+in), &agent.ProfileChain{})
		if err != nil || c.Env.Set["A"] != "s1" {
			t.Fatalf("%s: the compiler does not read it as env.set: %v", name, err)
		}
		if sets, readable := SetsEnv(in); !sets || !readable {
			t.Errorf("%s: SetsEnv = %v, %v; want true, true", name, sets, readable)
		}
		if sets, readable := SetsEnv(in + "bad: [\n"); !sets || readable {
			t.Errorf("%s, broken: SetsEnv = %v, %v; want true, false (held back)", name, sets, readable)
		}
	}
}

// utf16LE is the ASCII text s as UTF-16LE with no byte-order mark: a zero byte beside every letter.
func utf16LE(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteByte(s[i])
		b.WriteByte(0)
	}
	return b.String()
}

// demoEnv is env.set as the demo kit's contract writes it, with a comment and a quoted value.
const demoEnv = "name: codex\nenv:\n  pass: [PATH]\n  set:\n    CODEX_HOME: /home/u/.codex-demo # its own home\n" +
	"    HISTFILE: \"/dev/null\"\n    TMPDIR: /tmp/demo-tmp\nexec:\n  allow: [codex]\n"

// TestEditableEnvRoundTrip: the editor opens on the text with every env.set value hidden, and a free edit of another
// line comes back with each value's own source text, so the file changes only where the person changed it.
func TestEditableEnvRoundTrip(t *testing.T) {
	shown, err := EditableEnv(demoEnv)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{".codex-demo", "/dev/null", "demo-tmp"} {
		if strings.Contains(shown, secret) {
			t.Fatalf("the editor's text carries %q:\n%s", secret, shown)
		}
	}
	edited := strings.Replace(shown, "allow: [codex]", "allow: [codex, git]", 1)
	got, restored, err := RestoreEnv(edited, demoEnv)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Replace(demoEnv, "allow: [codex]", "allow: [codex, git]", 1); got != want {
		t.Errorf("RestoreEnv:\n%s\nwant\n%s", got, want)
	}
	slices.Sort(restored)
	if !slices.Equal(restored, []string{"/dev/null", "/home/u/.codex-demo", "/tmp/demo-tmp"}) {
		t.Errorf("restored = %v", restored)
	}
}

// TestRestoreEnv: removing a variable is allowed; adding one, or giving one a value, is ErrEnvEdit; a placeholder in
// a flow mapping or before a comment is put back double-quoted; a text that does not parse passes through.
func TestRestoreEnv(t *testing.T) {
	shown, err := EditableEnv(demoEnv)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("remove a variable", func(t *testing.T) {
		got, _, err := RestoreEnv(strings.Replace(shown, "    TMPDIR: "+Hidden+"\n", "", 1), demoEnv)
		if err != nil || strings.Contains(got, "TMPDIR") || !strings.Contains(got, "CODEX_HOME: /home/u/.codex-demo") {
			t.Errorf("RestoreEnv = %v\n%s", err, got)
		}
	})
	for name, posted := range map[string]string{
		"a new value":    strings.Replace(shown, "TMPDIR: "+Hidden, "TMPDIR: /tmp/other", 1),
		"a new variable": strings.Replace(shown, "    TMPDIR:", "    TOKEN: "+Hidden+"\n    TMPDIR:", 1),
		"emptied":        strings.Replace(shown, "TMPDIR: "+Hidden, "TMPDIR:", 1),
		"an alias":       "x: &x /tmp/other\n" + strings.Replace(shown, "TMPDIR: "+Hidden, "TMPDIR: *x", 1),
		"a merge":        strings.Replace(shown, "    TMPDIR: "+Hidden+"\n", "    <<: {TMPDIR: /tmp/other}\n", 1),
		"env by alias":   "e: &e\n  set:\n    CODEX_HOME: " + Hidden + "\nenv: *e\n",
	} {
		if _, _, err := RestoreEnv(posted, demoEnv); !errors.Is(err, ErrEnvEdit) {
			t.Errorf("%s: %v, want ErrEnvEdit", name, err)
		}
	}
	t.Run("flow and comment", func(t *testing.T) {
		posted := "name: codex\nenv:\n  set: {CODEX_HOME: " + Hidden + ", HISTFILE: '" + Hidden + "'}\n"
		got, _, err := RestoreEnv(posted, demoEnv)
		if err != nil || !strings.Contains(got, `{CODEX_HOME: "/home/u/.codex-demo", HISTFILE: "/dev/null"}`) {
			t.Errorf("RestoreEnv = %v\n%s", err, got)
		}
		got, _, err = RestoreEnv(strings.Replace(shown, "TMPDIR: "+Hidden, "TMPDIR: "+Hidden+" # mine", 1), demoEnv)
		if err != nil || !strings.Contains(got, `TMPDIR: "/tmp/demo-tmp" # mine`) {
			t.Errorf("RestoreEnv = %v\n%s", err, got)
		}
	})
	t.Run("does not parse", func(t *testing.T) {
		// Two documents pass through too: the compile then names the second, and no value is put back into either.
		for _, in := range []string{shown + "bad: [\n", shown + "---\nname: other\n"} {
			if got, restored, err := RestoreEnv(in, demoEnv); err != nil || got != in || restored != nil {
				t.Errorf("RestoreEnv = %q %v %v", got, restored, err)
			}
		}
	})
}

// TestEditableEnvRefuses: an env.set whose values could not be put back exactly gets no editor.
func TestEditableEnvRefuses(t *testing.T) {
	for name, in := range map[string]string{
		"flow":           "env:\n  set: {A: s1}\n",
		"alias value":    "s: &s s1\nenv:\n  set:\n    A: *s\n",
		"anchored value": "env:\n  set:\n    A: &s s1\nother: *s\n",
		"env alias":      "e: &e\n  set:\n    A: s1\nenv: *e\n",
		"merge in set":   "b: &b\n  A: s1\nenv:\n  set:\n    <<: *b\n",
		"nested":         "env:\n  set:\n    A: [s1]\n",
		"not yaml":       "env:\n  set: [\n",
		"two documents":  "env:\n  set:\n    A: s1\n---\nenv:\n  set:\n    B: s2\n",
	} {
		if _, err := EditableEnv(in); err == nil {
			t.Errorf("%s: EditableEnv offered an editor", name)
		}
	}
	// A multi-line value is shown on one line and put back double-quoted.
	in := "env:\n  set:\n    B: |\n      two\n      three\nname: x\n"
	shown, err := EditableEnv(in)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := RestoreEnv(strings.Replace(shown, "name: x", "name: y", 1), in)
	if err != nil || !strings.Contains(got, `B: "two\nthree\n"`) || strings.Count(got, "\n") != strings.Count(in, "\n") {
		t.Errorf("RestoreEnv = %v\n%q", err, got)
	}
}
