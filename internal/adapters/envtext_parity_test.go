// SPDX-License-Identifier: Apache-2.0

package adapters

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/adapters/claudecode"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/harness"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The rule for what a message shows of the environment is written once, in pkg/spec/identity envtext.go. Leaf
// packages that may not import identity restate a part of it; this package may import them all (an adapter may import
// pkg/spec/**), so the parity of each restatement with the helper is held here, on one table of cases.

// TestEnvPlaceParity: config.EnvPlace, which decides once per layer whether the Load may name the file $TEGO_CONFIG
// names, gives identity.EnvPlace's answer for every value.
func TestEnvPlaceParity(t *testing.T) {
	for _, v := range []string{
		"", "/", "//", "/a", "/a/b", "/etc/tego/config.yaml", "a", "./a", "a/../b", "~/a", "/a/", "/a//b", "/a/./b",
		"/a/../b", "/..", "/a/..", "/a b", "/a\tb", "/a\nb", "/a\rb", "/a\x1bb", "/a\x7fb", "/a\x00b", "/caf\u00e9",
		"/\u202egnp", "/a\u00a0b", "/a=b", "/$HOME",
	} {
		if got, want := config.EnvPlace(v), identity.EnvPlace(v); got != want {
			t.Errorf("EnvPlace(%q): config says %v, identity says %v", v, got, want)
		}
	}
}

// TestEnvEntryNameParity: the four restatements of the name reading (the machine config's baseline.env.deny, a
// harness entry, the user's Claude Code settings, a record's secret env) give identity.EnvEntryName's answer, name
// and whether there is one, for every entry: an entry with a name is shown by its name alone, and one without is
// shown by its position.
func TestEnvEntryNameParity(t *testing.T) {
	readings := map[string]func(string) (string, bool){
		"config":     config.EnvEntryName,
		"harness":    harness.EnvEntryName,
		"claudecode": claudecode.EnvEntryName,
		"record":     record.EnvEntryName,
	}
	for _, e := range []string{
		"", "=", "==", "=x", "A", "A=", "A=b", "A=B=C", "_", "_=x", "__X=1", "a1=x", "z", "PATH", "TEGO_X=1",
		"1A=x", "9", "A-B=x", "A B=x", "A.B", " A=x", "A =x", "\nA=x", "A\n=x", "A\x00=x", "A\t=x", "\u00e9=x", "A\u00e9=x",
		"\uff21=x", "ghp_abc123", "sk-live-qz", "\"=sk\"", "$A=x", "A$=x", "{A}=x",
		strings.Repeat("A", 256) + "=x", strings.Repeat("A", 257) + "=x", strings.Repeat("_", 300),
	} {
		wantName, wantOK := identity.EnvEntryName(e)
		for pkg, read := range readings {
			if name, ok := read(e); name != wantName || ok != wantOK {
				t.Errorf("%s.EnvEntryName(%.40q) = %.40q, %v; identity says %.40q, %v", pkg, e, name, ok, wantName, wantOK)
			}
		}
	}
}
