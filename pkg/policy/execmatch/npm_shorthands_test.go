// SPDX-License-Identifier: Apache-2.0

package execmatch_test

import (
	compare "github.com/attention-span-ai/tego/test/execmatchdiff"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

// This inventory is npm 9.2.0 config/index.js, including definitions' short
// fields. d/q/s insert a loglevel value; n inserts a negation. Their existing
// pseudo-option representation is deliberately separate from one-to-one aliases.
var npmSourceShorts = map[byte]string{
	'a': "all", 'c': "call", 'f': "force", 'g': "global", 'L': "location", 'l': "long", 'm': "message",
	'p': "parseable", 'C': "prefix", 'S': "save", 'B': "save-bundle", 'D': "save-dev", 'E': "save-exact",
	'O': "save-optional", 'P': "save-prod", '?': "usage", 'H': "usage", 'h': "usage", 'v': "version",
	'w': "workspace", 'y': "yes", 'd': "loglevel-info", 'q': "loglevel-warn", 's': "loglevel-silent", 'n': "no-yes",
}

func TestNpmDeclaredShortSourceContracts(t *testing.T) {
	seen := map[byte]bool{}
	for _, o := range rows.Builtin().Lookup("npm").Root.Opts {
		for _, short := range []byte(o.Short) {
			if want, ok := npmSourceShorts[short]; !ok || want != o.Name {
				t.Errorf("short %c maps to %s, source maps to %s", short, o.Name, want)
			}
			seen[short] = true
		}
	}
	if len(seen) != len(npmSourceShorts) {
		t.Fatalf("declared/source shorthand count=%d/%d", len(seen), len(npmSourceShorts))
	}
}

func TestNpmShorthandValueTypes(t *testing.T) {
	for _, dashes := range []string{"-", "--", "---"} {
		for _, short := range []string{"c", "m", "C", "L", "w"} {
			for _, attached := range []bool{false, true} {
				argv := []string{"npm", dashes + short, "--global", "install", "x"}
				if attached {
					argv = []string{"npm", dashes + short + "=--global", "install", "x"}
				}
				stringType := short == "c" || short == "m"
				for _, list := range []string{"deny", "ask"} {
					got := decide(index(t, list+": npm install --global"), argv...)
					if refused := strings.HasPrefix(got, "refused "); refused != (stringType || compare.ReleasedRefuses("npm install --global", list, argv)) {
						t.Errorf("%s %q: %s, source global=%v", list, argv, got, stringType)
					}
				}
				if got := decide(index(t, "allow: npm install"), argv...); strings.HasPrefix(got, "allowed ") == compare.ReleasedRefuses("npm install", "allow", argv) {
					t.Errorf("%q violated the released allow floor: %s", argv, got)
				}
			}
		}
	}
}

// All simple pairs exercise nopt's expansion order: a path or union value can
// consume the next expanded long name, while exact String values leave it read.
func TestNpmSimpleShorthandClusters(t *testing.T) {
	const singles = "acfgLlmpCSBDEOP?Hhvwy"
	for _, a := range singles {
		for _, b := range singles {
			cluster := string([]rune{a, b})
			for _, dashes := range []string{"-", "--", "---"} {
				for _, attached := range []bool{false, true} {
					argv := []string{"npm", dashes + cluster, "--global", "install", "x"}
					if attached {
						argv = []string{"npm", dashes + cluster + "=--global", "install", "x"}
					}
					// ca is an exact config name, which wins before its c+a
					// shorthand cluster and consumes the following value.
					aConsumes := a == 'C' || a == 'L' || a == 'w'
					bConsumes := b == 'C' || b == 'L' || b == 'w'
					global := cluster != "ca" && (aConsumes || a == 'g' || !bConsumes)
					if got := decide(index(t, "deny: npm install --global"), argv...); strings.HasPrefix(got, "refused ") != (global || compare.ReleasedRefuses("npm install --global", "deny", argv)) {
						t.Fatalf("%q: %s, source global=%v", argv, got, global)
					}
					if got := decide(index(t, "allow: npm install"), argv...); strings.HasPrefix(got, "allowed ") == compare.ReleasedRefuses("npm install", "allow", argv) {
						t.Fatalf("%q violated the released allow floor: %s", argv, got)
					}
				}
			}
		}
	}
}

func TestNpmUnresolvedShorthandClusters(t *testing.T) {
	for _, token := range []string{"-Cd", "--dq", "---cn", "--q", "-" + strings.Repeat("c", execmatch.MaxReadings+1)} {
		readings := execmatch.NewNormalizer(rows.Builtin().Lookup("npm"), nil).Normalize([]string{token, "--global", "install", "x"})
		if len(readings) != 1 || !readings[0].Unlocatable {
			t.Errorf("unestablished pseudo expansion %q must fail closed: %+v", token, readings)
		}
	}
	// Source expansion -Cd => --prefix --loglevel info makes prefix consume
	// --loglevel, exposing info as the command. Reading d as an attached path
	// instead would silently select install and miss a denial of info.
	for _, token := range []string{"-Cd", "--Cd", "---Cd"} {
		if got := decide(index(t, "deny: npm info"), "npm", token, "--global", "install", "x"); !strings.HasPrefix(got, "refused ") {
			t.Errorf("%q hid the source-selected info command: %s", token, got)
		}
		if got := decide(index(t, "allow: npm install"), "npm", token, "--global", "install", "x"); strings.HasPrefix(got, "allowed ") {
			t.Errorf("%q admitted info under install: %s", token, got)
		}
	}
	// Preserve the established exact one-dash pseudo shorthand's old behavior.
	for _, token := range []string{"-d", "-q", "-s", "-n"} {
		if got := decide(index(t, "allow: npm install"), "npm", token, "install", "x"); !strings.HasPrefix(got, "allowed ") {
			t.Errorf("ordinary exact shorthand %q regressed: %s", token, got)
		}
	}
}

func TestNpmShorthandHitSpellings(t *testing.T) {
	nz := execmatch.NewNormalizer(rows.Builtin().Lookup("npm"), nil)
	for _, token := range []string{"-c", "--c", "---c", "--cc"} {
		calls := 0
		for _, reading := range nz.Normalize([]string{token, "--global", "install"}) {
			for _, hit := range reading.Hits {
				if hit.Opt == nil || hit.Opt.Name != "call" {
					continue
				}
				calls++
				want := token
				if token == "--cc" {
					want = "--call"
				}
				if hit.Raw != want {
					t.Errorf("%q hit spelling=%s want %s", token, hit.Raw, want)
				}
			}
		}
		wantCalls := 1
		if token == "--cc" {
			wantCalls = 2
		}
		if calls != wantCalls {
			t.Errorf("%q call hits=%d want %d", token, calls, wantCalls)
		}
	}
}

func TestNpmShorthandExpansionKeepsPrefixesPending(t *testing.T) {
	argv := []string{"npm", "install"}
	for range execmatch.MaxReadings {
		argv = append(argv, "-cc")
	}
	ix := index(t, "deny: npm publish")
	f := execmatch.Facts{Requested: "npm", Image: "npm", Argv0: "npm", Argv: argv, ArgvComplete: true}
	if got := ix.Decide(&f); got.Outcome != execmatch.OutcomeRefused {
		t.Fatalf("expansion bound must fail closed: %+v", got)
	}
	for end := 1; end < len(argv); end++ {
		f.Argv, f.ArgvComplete = argv[:end], false
		if got := ix.Decide(&f); got.Final && got.Outcome != execmatch.OutcomeRefused {
			t.Errorf("prefix %q settled before bound exhaustion: %+v", f.Argv, got)
		}
	}
}
