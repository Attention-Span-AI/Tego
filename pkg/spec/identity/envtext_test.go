// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEnvEntryName: a message names an entry's variable and nothing of its value; an entry whose name cannot be
// told from its value has no name to print (rule (a) of envtext.go).
func TestEnvEntryName(t *testing.T) {
	for entry, want := range map[string]string{
		"TOKEN=sk-live-0123": "TOKEN", "TOKEN": "TOKEN", "_x9=": "_x9", "A=b=c": "A",
		"sk-live-0123": "", "=sk-live-0123": "", "1BAD=v": "", "NO-DASH": "", "": "", "A B=v": "", "\x00=v": "",
	} {
		name, ok := EnvEntryName(entry)
		if name != want || ok != (want != "") {
			t.Errorf("EnvEntryName(%q) = %q, %v; want %q", entry, name, ok, want)
		}
	}
}

// TestEnvPlace: a location variable's value is printed only when it is an absolute clean path (rules (b) and (c)).
func TestEnvPlace(t *testing.T) {
	for value, want := range map[string]bool{
		"/run/user/1000": true, "/": true, "/home/u/.config/tego/machine.yaml": true, "/opt/my tools": true,
		"": false, "machine.yaml": false, "./x": false, "/a/../b": false, "/a//b": false, "/a/": false,
		"/a\nb": false, "/a\x1b[31m": false, "sk-live-0123": false,
	} {
		if got := EnvPlace(value); got != want {
			t.Errorf("EnvPlace(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestEnvInspect(t *testing.T) {
	for want, names := range map[string][]string{
		"":                                    nil,
		"print it with: echo $TEGO_CONFIG":    {"TEGO_CONFIG"},
		"print them with: echo $A; echo $B_2": {"A", "B_2"},
	} {
		if got := EnvInspect(names...); got != want {
			t.Errorf("EnvInspect(%q) = %q, want %q", names, got, want)
		}
	}
}

// TestEnvRuleStatementsNameItsLimits: the rule's two statements, this package's comment and the operations guide, both
// say where a reader would otherwise see a contradiction or a promise the code does not keep: an inherited PATH is
// listed where a program was not found and only named in the rule table, and a bare secret shaped like a variable
// name is shown as the name.
func TestEnvRuleStatementsNameItsLimits(t *testing.T) {
	flat := func(b []byte) string {
		s := strings.NewReplacer("//", " ", "`", "", "\t", " ", "\n", " ").Replace(string(b))
		return strings.Join(strings.Fields(s), " ")
	}
	code, err := os.ReadFile("envtext.go")
	if err != nil {
		t.Fatal(err)
	}
	guide, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "development", "operations.md"))
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"envtext.go": flat(code), "docs/development/operations.md": flat(guide)} {
		for _, want := range []string{
			"An inherited PATH is both a pass-through entry and a list of places: the rule table names it only as inherited",
			"lists its directories",
			"an env.set PATH is never printed",
			"shaped like a variable name",
			"cannot be told from a name",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("%s does not say %q", name, want)
			}
		}
	}
}
