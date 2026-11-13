// SPDX-License-Identifier: Apache-2.0

package execmatch_test

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

// nopt strips all leading dashes before resolving exact names and unique
// abbreviations. Its String value guard still re-enters an attached option.
func TestNpmExtraDashValueNames(t *testing.T) {
	for _, dashes := range []string{"---", "-----", strings.Repeat("-", 64)} {
		for _, name := range []string{"tag", "tag-v"} {
			for _, attached := range []bool{false, true} {
				argv := []string{"npm", dashes + name, "--global", "install", "x"}
				if attached {
					argv = []string{"npm", dashes + name + "=--global", "install", "x"}
				}
				for _, list := range []string{"deny", "ask"} {
					ix := index(t, list+": npm install --global")
					if got := decide(ix, argv...); !strings.HasPrefix(got, "refused exec."+list+"[") {
						t.Errorf("%s %q lost the global option: %s", list, argv, got)
					}
					f := execmatch.Facts{Requested: "npm", Image: "npm", Argv0: "npm", ArgvComplete: false}
					for end := 1; end < len(argv); end++ {
						f.Argv = argv[:end]
						if got := ix.Decide(&f); got.Final && got.Outcome != execmatch.OutcomeRefused {
							t.Errorf("%s %q settled before the global option: %+v", list, f.Argv, got)
						}
					}
				}
				if got := decide(index(t, "allow: npm install --global"), argv...); strings.HasPrefix(got, "allowed ") {
					t.Errorf("%q bypassed the released allow floor: %s", argv, got)
				}
			}
		}
	}
	for _, argv := range [][]string{
		{"npm", "---tag=--cache", "view", "install"},
		{"npm", "-----tag-v=--browser", "view", "install"},
	} {
		if got := decide(index(t, "deny: npm install"), argv...); !strings.HasPrefix(got, "refused ") {
			t.Errorf("%q hid the selected command: %s", argv, got)
		}
		if got := decide(index(t, "allow: npm view"), argv...); strings.HasPrefix(got, "allowed ") {
			t.Errorf("%q admitted install under view: %s", argv, got)
		}
	}
}

func TestNpmExtraDashUnknownAssignments(t *testing.T) {
	for _, spelling := range []string{"--future=--global", "---future=--global", "--------future=--global"} {
		if got := decide(index(t, "deny: npm install --global"), "npm", spelling, "install", "x"); got != "none" {
			t.Errorf("unknown assignment must keep its consumed value %q: %s", spelling, got)
		}
	}
	// Other tools keep their established name grammar.
	for _, tool := range []string{"git", "go", "systemctl", "pip", "aws", "npx", "pnpm", "yarn"} {
		for _, reading := range execmatch.NewNormalizer(rows.Builtin().Lookup(tool), nil).Normalize([]string{"---help"}) {
			for _, hit := range reading.Hits {
				if hit.Opt != nil {
					t.Errorf("%s inherited nopt's extra-dash lookup: %+v", tool, hit)
				}
			}
		}
	}
}
