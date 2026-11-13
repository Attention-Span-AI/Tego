// SPDX-License-Identifier: Apache-2.0

package execmatch_test

import (
	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"strings"
	"testing"
)

func TestTerminatorBeforeSubcommand(t *testing.T) {
	ix := index(t, "deny: systemctl reboot")
	if got := decide(ix, "systemctl", "--", "reboot"); got != "refused exec.deny[systemctl reboot]" {
		t.Fatalf("verb after option terminator: %s", got)
	}
}

// The vectors are parser contracts, not executable probes. They never start a tool.
func TestTerminatorParserContracts(t *testing.T) {
	cases := []struct {
		entry, line string
		allowed     bool
	}{
		{"systemctl reboot", "systemctl -- reboot", false},
		{"systemctl reboot", "systemctl -q -- reboot", false},
		{"systemctl reboot", "systemctl --future x -- reboot", false},
		{"go run", "go -- run main.go", false},
		{"go mod tidy", "go -C . -- mod tidy", false},
		{"go run -exec=driver", "go -- run -exec driver main.go", false},
		{"npm publish", "npm -- publish", false},
		{"npm publish", "npm --- publish", false},
		{"npm publish", "npm ---- publish", false},
		{"npm publish", "npm -ws -- pub", false},
		{"pip install", "pip -- install x", false},
		{"aws s3 rm", "aws -- s3 rm s3://b/x", false},
		{"aws s3 rm", "aws s3 -- rm s3://b/x", false},
		// Unestablished dispatchers retain the operand/default reading too.
		{"pnpm publish", "pnpm -- publish", false},
		{"yarn npm publish", "yarn npm -- publish", false},
		{"docker container rm", "docker -- container rm x", false},
		{"docker container rm", "docker -- unused container rm x", false},
		{"podman container rm", "podman container -- rm x", false},
		{"cargo publish", "cargo +nightly -- publish", false},
		{"terraform state rm", "terraform state -- rm x", false},
		{"tofu destroy", "tofu -- destroy", false},
		{"gcloud compute instances delete", "gcloud compute -- instances delete x", false},
		{"kubectl create secret generic", "kubectl create -- secret generic x", false},
		{"oc create secret generic", "oc create secret -- generic x", false},
		{"gh repo delete", "gh repo -- delete x", false},
		{"helm repo remove", "helm repo -- remove x", false},
		// An unknown option and its separate value do not end command search.
		{"npm publish", "npm --future value publish", false},
		{"go run", "go --future value -- run main.go", false},
		{"gh version", "gh - version", false},
	}
	for _, c := range cases {
		t.Run(c.line, func(t *testing.T) {
			for _, list := range []string{"deny", "ask"} {
				ix := index(t, list+": "+c.entry)
				argv := strings.Fields(c.line)
				f := execmatch.Facts{Requested: argv[0], Image: argv[0], Argv0: argv[0], Argv: argv, ArgvComplete: true}
				r := ix.Decide(&f)
				if r.Outcome != execmatch.OutcomeRefused || r.Rule() != "exec."+list+"["+c.entry+"]" || !r.Final {
					t.Fatalf("%s: %+v", list, r)
				}
			}
			ix := index(t, "allow: "+c.entry)
			got := decide(ix, strings.Fields(c.line)...)
			if strings.HasPrefix(got, "allowed ") != c.allowed {
				t.Fatalf("allow: %s (want admitted %v)", got, c.allowed)
			}
		})
	}
}

func TestTerminatorRefusedAndOperandRoots(t *testing.T) {
	for _, line := range []string{"git -- push", "git -C . -- push", "go mod -- tidy", "go work -- sync", "go telemetry -- off"} {
		argv := strings.Fields(line)
		row := rows.Builtin().Lookup(argv[0])
		rr := execmatch.NewNormalizer(row, nil).Normalize(argv[1:])
		if len(rr) != 2 || !rr[0].UnknownBefore || !rr[1].UnknownBefore {
			t.Errorf("%s: need flag and value readings: %+v", line, rr)
		}
	}
	for _, tool := range []string{"kubectl", "oc", "gh", "helm"} {
		if got := decide(index(t, "deny: "+tool+" version"), tool, "--", "version"); got != "none" {
			t.Errorf("%s Find root must not dispatch after --: %s", tool, got)
		}
	}
	// getopt and nopt end options for the whole invocation; Go reparses its command's flags.
	for _, c := range []struct{ rule, line string }{
		{"systemctl reboot --force", "systemctl -- reboot --force"},
		{"npm publish --force", "npm -- publish --force"},
		{"pip install --user", "pip -- install --user"},
		{"go test -race", "go test -- -race"},
	} {
		if got := decide(index(t, "deny: "+c.rule), strings.Fields(c.line)...); got != "none" {
			t.Errorf("%s: %s", c.line, got)
		}
	}
	ix := index(t, "deny: git push")
	argv := []string{"git", "--", "push"}
	f := execmatch.Facts{Requested: "git", Image: "git", Argv0: "git", Argv: argv, ArgvComplete: true}
	if r := ix.Decide(&f); r.Match != execmatch.MatchAmbiguous {
		t.Errorf("refused terminator record: %+v", r)
	}
}

func TestTerminatorPatterns(t *testing.T) {
	// A terminator already standing before operands keeps its exact contract meaning.
	for _, entry := range []string{"rm -- -r", "git push -- origin", "npm publish -- --force", "go test -- -race"} {
		for _, list := range []execmatch.List{execmatch.ListAllow, execmatch.ListDeny, execmatch.ListAsk} {
			if _, err := execmatch.Parse(entry, list, rows.Builtin()); err != nil {
				t.Errorf("%s: %v", entry, err)
			}
		}
	}
	// Established command-position separators have one enforceable meaning.
	for _, entry := range []string{"systemctl -- reboot", "go -- run", "git stash -- file", "aws -- s3 rm"} {
		for _, list := range []execmatch.List{execmatch.ListAllow, execmatch.ListDeny, execmatch.ListAsk} {
			if _, err := execmatch.Parse(entry, list, rows.Builtin()); err != nil {
				t.Errorf("%s: %v", entry, err)
			}
		}
	}
	// Nested gh dispatch is unestablished. ADR 0048 retains both command and
	// operand meanings for refusal; an allow cannot choose the broader grant.
	const ambiguous = "gh repo -- delete"
	if _, err := execmatch.Parse(ambiguous, execmatch.ListAllow, rows.Builtin()); err == nil || !strings.Contains(err.Error(), "more than one command or argument meaning") {
		t.Errorf("ambiguous allow must diagnose competing meanings: %v", err)
	}
	for _, list := range []string{"deny", "ask"} {
		ix := index(t, list+": "+ambiguous)
		for _, argv := range [][]string{{"gh", "repo", "delete"}, {"gh", "repo", "--", "delete"}} {
			if got := decide(ix, argv...); got != "refused exec."+list+"["+ambiguous+"]" {
				t.Errorf("%s lost a retained meaning for %q: %s", list, argv, got)
			}
		}
	}
	// Git rejects a global separator; its conservative unknown-option readings
	// cannot give a contract separator an enforceable command meaning.
	for _, entry := range []string{"git -- push"} {
		for _, list := range []execmatch.List{execmatch.ListAllow, execmatch.ListDeny, execmatch.ListAsk} {
			if _, err := execmatch.Parse(entry, list, rows.Builtin()); err == nil {
				t.Errorf("%s must diagnose a separator the tool rejects", entry)
			}
		}
	}
}

func TestUnknownBundleKeepsCommandReadings(t *testing.T) {
	// -zC may be -z (unknown flag), -C value, or -z with attached value C.
	// In the latter reading 'run' is the command, not -C's value.
	r := &execmatch.Row{Tool: "bundle", Root: &execmatch.Level{
		Syntax: execmatch.Syntax{Clusters: true, ShortAttach: true},
		Opts:   []execmatch.Opt{{Name: "C", Short: "C", Arg: execmatch.ArgRequired}},
		Subs:   map[string]*execmatch.Level{"run": {}, "other": {}},
	}}
	rs := execmatch.NewRows(r)
	p, err := execmatch.Parse("bundle run", execmatch.ListDeny, rs)
	if err != nil {
		t.Fatal(err)
	}
	ix := execmatch.NewIndex(rs, []*execmatch.Pattern{p}, execmatch.IndexOptions{})
	argv := []string{"bundle", "-zC", "run", "other"}
	f := execmatch.Facts{Requested: "bundle", Image: "bundle", Argv0: "bundle", Argv: argv, ArgvComplete: true}
	if got := ix.Decide(&f); got.Outcome != execmatch.OutcomeRefused {
		t.Fatalf("unknown cluster lost attached-value reading: %+v", got)
	}
}

func TestTerminatorPrefixes(t *testing.T) {
	for _, line := range []string{"systemctl -- reboot x", "go -- run -exec driver main.go", "npm --- publish x", "aws s3 -- rm x", "docker -- unused container rm x"} {
		argv := strings.Fields(line)
		var entry string
		switch argv[0] {
		case "systemctl":
			entry = "systemctl reboot"
		case "go":
			entry = "go run"
		case "npm":
			entry = "npm publish"
		case "aws":
			entry = "aws s3 rm"
		case "docker":
			entry = "docker container rm"
		}
		ix := index(t, "deny: "+entry)
		for n := 1; n < len(argv); n++ {
			f := execmatch.Facts{Requested: argv[0], Image: argv[0], Argv0: argv[0], Argv: argv[:n], ArgvComplete: false}
			r := ix.Decide(&f)
			if r.Final && r.Outcome != execmatch.OutcomeRefused {
				t.Errorf("%v settled before denied suffix: %+v", argv[:n], r)
			}
			if n == len(argv)-1 && (r.Outcome != execmatch.OutcomeRefused || !r.Final) {
				t.Errorf("%v has read the denied command and must refuse before its tail: %+v", argv[:n], r)
			}
		}
	}
}

func TestTerminatorRetainsOpenHold(t *testing.T) {
	// A correct complete-vector location must not turn the old open-prefix hold
	// into a final non-refusal. These are witnesses found by the base comparison.
	for _, c := range []struct{ entry, line string }{
		{"go telemetry local", "go -- local --future telemetry x --- --future -zC +nightly"},
		{"go bug", "go --C bug telemetry -- --h --help telemetry true --h"},
		{"npm access", "npm bugs --version=x --install-strategy -- remove --readonly=x access --- --searchopts"},
	} {
		argv := strings.Fields(c.line)
		ix := index(t, "deny: "+c.entry)
		f := execmatch.Facts{Requested: argv[0], Image: argv[0], Argv0: argv[0], Argv: argv, ArgvComplete: false}
		if r := ix.Decide(&f); r.Final && r.Outcome != execmatch.OutcomeRefused {
			t.Errorf("%s: settled non-refusal: %+v", c.line, r)
		}
	}
}

func TestUnknownBundleBound(t *testing.T) {
	r := &execmatch.Row{Tool: "bundle", Root: &execmatch.Level{
		Syntax: execmatch.Syntax{Clusters: true}, Subs: map[string]*execmatch.Level{"run": {}},
	}}
	rr := execmatch.NewNormalizer(r, nil).Normalize([]string{"-" + strings.Repeat("z", 10000), "run"})
	if len(rr) != 1 || !rr[0].Unlocatable {
		t.Fatalf("unbounded unknown cluster: %d readings", len(rr))
	}
}
