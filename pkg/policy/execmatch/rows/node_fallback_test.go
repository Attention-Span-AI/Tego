// SPDX-License-Identifier: Apache-2.0

package rows

import (
	"reflect"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

// The expected verdict comes from the frozen master row, not the new fallback.
// Compare all interpretations too: an allowed A must not hide a lost reading B.
func TestNodeUnknownBuildMatchesMaster(t *testing.T) {
	entries := []string{"allow: a.js *", "deny: b.js"}
	master := nodeMasterRules(t, entries...)
	candidate := rules(t, entries...)
	for _, line := range []string{
		"node ./a.js", "node ./b.js", "node ./a.js --ci --coverage --runInBand --silent --verbose --forceExit --detectOpenHandles",
		"node --expose-gc ./a.js --ci --coverage --runInBand --silent --verbose --forceExit --detectOpenHandles",
		"node -e 0 --ci --coverage --runInBand --silent --verbose --forceExit --detectOpenHandles",
		"node --future ./a.js ./b.js", "node --future=./b.js ./a.js",
		"node --a --b --c --d ./a.js", "node --a --b --c --d --f ./a.js", "node --a --b --c --d --f --g --j ./a.js",
		"node --title ./a.js ./b.js", "node --title=./a.js ./b.js", "node --inspect ./b.js ./a.js",
		"node --inspect=127.0.0.1:0 ./a.js", "node --max-old-space-size=128 ./a.js", "node --stack-trace-limit 12 ./b.js",
		"node -pe 0 -i ./b.js", "node -e 0 -i ./b.js", "node -p --title a.js ./b.js",
		"node -r ./b.js ./a.js", "node --import=./b.js ./a.js", "node --loader ./b.js ./a.js",
		"node -- ./a.js --env-file evil.env", "-- ./a.js --env-file=evil.env",
		"node ./a.js -- --env-file=evil.env", "node - -- --env-file=evil.env",
		"node ./a.js --other-experimental-config-file=evil.json",
		"node --test --test-global-setup=./b.js ./a.js", "node --test --test-isolation=none ./a.js ./b.js",
		"node ./a.js --experimental_config_file=evil.json", "node --experimental_config_file=evil.json ./a.js",
		"node ./a.js --env_file=evil.env", "node -- ./a.js --env-file-if-exists=evil.env",
	} {
		t.Run(line, func(t *testing.T) {
			for _, version := range []string{"", "18.20.8", "20.19.5", "24.22.2", "25.9.0", "99.0.0"} {
				f := facts("node", "node", words(line)...)
				f.NodeVersion = version
				want, got := master.Decide(&f), candidate.Decide(&f)
				if got.Outcome != want.Outcome || got.Rule() != want.Rule() || got.Final != want.Final {
					t.Fatalf("unknown %q: %s, master %s", version, decided(got), decided(want))
				}
				wantInv, gotInv := master.Interpretations(&f), candidate.Interpretations(&f)
				// Row pointers differ by construction. The remaining exported grammar
				// facts and normalized readings must match, including ambiguous forks.
				for i := range wantInv {
					wantInv[i].Row = nil
				}
				for i := range gotInv {
					gotInv[i].Row = nil
				}
				if !reflect.DeepEqual(wantInv, gotInv) {
					t.Fatalf("unknown %q: interpretations differ from master\ngot %+v\nwant %+v", version, gotInv, wantInv)
				}
			}
		})
	}
}

func nodeMasterRules(t *testing.T, entries ...string) *execmatch.Index {
	t.Helper()
	masterRows := execmatch.NewRows(masterNodeRow())
	var ps []*execmatch.Pattern
	for _, entry := range entries {
		list, body, _ := strings.Cut(entry, ": ")
		kind := execmatch.ListAllow
		if list == "deny" {
			kind = execmatch.ListDeny
		}
		p, err := execmatch.Parse(body, kind, masterRows)
		if err != nil {
			t.Fatal(err)
		}
		ps = append(ps, p)
	}
	return execmatch.NewIndex(masterRows, ps, execmatch.IndexOptions{})
}

func TestNodeUnknownBuildNodePatterns(t *testing.T) {
	for _, tc := range []struct{ entry, line string }{
		{"allow: node --require ./b.js *", "node -r ./b.js ./a.js"},
		{"allow: node --inspect *", "node --inspect=127.0.0.1:0 ./a.js"},
		{"deny: node --require ./b.js", "node -r ./b.js ./a.js"},
		{"deny: node --require ./b.js", "node ./a.js"},
		{"allow: node --require ./b.js *", "node ./a.js"},
		{"deny: node --experimental-permission", "node --experimental-permission ./a.js"},
		{"deny: node --stack-trace-limit", "node --stack-trace-limit=12 ./a.js"},
	} {
		t.Run(tc.entry, func(t *testing.T) {
			f := facts("node", "node", words(tc.line)...)
			f.NodeVersion = ""
			want := nodeMasterRules(t, tc.entry).Decide(&f)
			got := rules(t, tc.entry).Decide(&f)
			if got.Outcome != want.Outcome || got.Rule() != want.Rule() {
				t.Fatalf("%s: %s, master %s", tc.line, decided(got), decided(want))
			}
		})
	}
}

func TestNodeScansEveryBuild(t *testing.T) {
	ix := rules(t, "allow: a.js *", "deny: b.js")
	for _, version := range []string{"", "18.20.8", "20.19.4", "22.21.1", "24.22.2", "25.9.0", "99.0.0"} {
		for _, line := range []string{
			"node ./a.js --ci --experimental-config-file=evil.json",
			"node -- ./a.js --experimental-default-config-file",
			"node ./a.js x --experimental-default-config-file=1",
			"node ./a.js --experimental-config-file evil.json",
			"node - --experimental-config-file=evil.json",
			"node -- - --experimental-default-config-file-suffix",
			"node ./a.js --env-file evil.env", "node ./a.js --env-file-if-exists=evil.env",
			"node - --env-file=evil.env", "node ./a.js --env-file-suffix",
			"--experimental-config-file=evil.json ./a.js",
			"--experimental-default-config-file ./a.js",
			"--env-file=evil.env ./a.js",
		} {
			t.Run(version+"/"+line, func(t *testing.T) {
				argv := words(line)
				f := facts("node", "node", argv...)
				f.NodeVersion = version
				if got := ix.Decide(&f); got.Rule() != execmatch.RuleCommandUnresolved {
					t.Fatalf("%s, want command-unresolved", decided(got))
				}
				for k := 1; k < len(argv); k++ {
					f.Argv, f.ArgvComplete = argv[:k], false
					if r := ix.Decide(&f); r.Final && r.Outcome != execmatch.OutcomeRefused {
						t.Fatalf("prefix %q settled %s before the scan", f.Argv, decided(r))
					}
				}
			})
		}
	}
}

func TestNodeInventorySelection(t *testing.T) {
	ix := rules(t, "allow: a.js *", "deny: b.js")
	for _, version := range []string{"", "20.19.4", "22.21.1", "24.22.2"} {
		// Master lacks these flags and exhausts its 16 readings. The pinned
		// inventory proves their arity; unknown builds must keep the old bound.
		f := facts("node", "node", words("node --trace-gc-nvp --trace-gc-ignore-scavenger --trace-gc-verbose --trace-gc-freelists --trace-gc-heap-layout --trace-gc-freelists-verbose --trace-gc-object-stats ./a.js")...)
		f.NodeVersion = version
		r := ix.Decide(&f)
		if version == "20.19.4" || version == "22.21.1" {
			if r.Outcome != execmatch.OutcomeAllowed {
				t.Fatalf("pinned %q: %s", version, decided(r))
			}
		} else if r.Rule() != execmatch.RuleCommandUnresolved {
			t.Fatalf("unknown %q: %s", version, decided(r))
		}
	}
}

func TestNodeUnknownBuildInventoryOnlyRule(t *testing.T) {
	ix := rules(t, "allow: node --disable-sigusr1 *")
	for _, version := range []string{"", "22.21.1"} {
		f := facts("node", "node", "node", "--disable-sigusr1", "./a.js")
		f.NodeVersion = version
		r := ix.Decide(&f)
		if version == "" && r.Outcome != execmatch.OutcomeRefused || version != "" && r.Outcome != execmatch.OutcomeAllowed {
			t.Fatalf("inventory-only allow, %q: %s", version, decided(r))
		}
	}
}

// Master keeps one interpretation of the original script when its shebang
// interpreter dispatches back to it. Raw scan observations must not add copies.
func TestNodeUnknownBuildShebangMatchesMaster(t *testing.T) {
	ix := rules(t, "allow: runner *", "deny: b.js")
	master := nodeMasterRules(t, "allow: runner *", "deny: b.js")
	f := facts("runner", "runner", "runner", "arg")
	f.NodeVersion = ""
	f.Form = execmatch.FormScript
	f.Interp = []execmatch.Stage{{Path: "node"}}
	got, want := ix.Interpretations(&f), master.Interpretations(&f)
	n := 0
	for i := range got {
		if got[i].Tool == "runner" {
			n++
		}
		got[i].Row = nil
	}
	if n != 1 {
		t.Fatalf("original script interpreted %d times, master keeps one", n)
	}
	for i := range want {
		want[i].Row = nil
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("shebang interpretations differ from master: got %+v, want %+v", got, want)
	}
}
