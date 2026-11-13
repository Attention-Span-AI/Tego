// SPDX-License-Identifier: Apache-2.0

package execmatch_test

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

func TestTerminatorOptionVocabulary(t *testing.T) {
	for _, c := range []struct{ entry, line string }{
		{"aws s3 rm", "aws -- s3 --profile rm s3://b/x"},
		{"aws s3 rm", "aws -- s3 --region rm ls"},
	} {
		for _, list := range []string{"deny", "ask"} {
			if got := decide(index(t, list+": "+c.entry), strings.Fields(c.line)...); !strings.HasPrefix(got, "refused exec."+list+"[") {
				t.Errorf("%s %s: %s", list, c.line, got)
			}
		}
	}
	if got := decide(index(t, "allow: aws s3 ls"), "aws", "--", "s3", "--profile", "rm", "ls"); strings.HasPrefix(got, "allowed ") {
		t.Fatalf("root globals after separator changed operation: %s", got)
	}
}

func TestDefaultChildOrdinaryOptions(t *testing.T) {
	ix := index(t, "allow: git reflog")
	for _, tail := range [][]string{{"-n", "5"}, {"--date=iso"}, {"-n", "1", "--date=iso"}} {
		if got := decide(ix, append([]string{"git", "reflog"}, tail...)...); !strings.HasPrefix(got, "allowed ") {
			t.Errorf("%q: %s", tail, got)
		}
	}
}

func TestOptionLookingValueNpm(t *testing.T) {
	for _, list := range []string{"deny", "ask"} {
		ix := index(t, list+": npm install --global")
		for _, line := range []string{"npm --tag --global install x", "npm install --tag --global x", "npm --tag=--global install x", "npm install --tag=--global x", "npm --tag=--tag=--global install x"} {
			if got := decide(ix, strings.Fields(line)...); !strings.HasPrefix(got, "refused exec."+list+"[") {
				t.Errorf("%s %s: %s", list, line, got)
			}
		}
	}
}

// nopt leaves --cache and --browser separate from the String-valued tag, then
// their path and Boolean/String types consume view. The command is install.
func TestNpmStringValueChainedOptions(t *testing.T) {
	for _, argv := range [][]string{
		{"npm", "--tag", "--cache", "view", "install"},
		{"npm", "--tag=--cache", "view", "install"},
		{"npm", "--tag", "--browser", "view", "install"},
		{"npm", "--tag=--browser", "view", "install"},
	} {
		for _, list := range []string{"deny", "ask"} {
			if got := decide(index(t, list+": npm install"), argv...); !strings.HasPrefix(got, "refused exec."+list+"[") {
				t.Errorf("%s %q must refuse the selected command: %s", list, argv, got)
			}
		}
		if got := decide(index(t, "allow: npm view"), argv...); strings.HasPrefix(got, "allowed ") {
			t.Errorf("%q admitted install under view's entry: %s", argv, got)
		}
	}
}

func TestNpmAttachedValueConsumption(t *testing.T) {
	ix := index(t, "deny: npm install --global")
	for _, line := range []string{
		"npm --fetch-retries=--tag=--global install x",
		"npm --fetch-retries --tag=--global install x",
		"npm --tag=--- install --global",
		"npm --tag=---x install x",
	} {
		want := "none"
		if line == "npm --tag=--- install --global" {
			want = "refused exec.deny[npm install --global]"
		}
		if got := decide(ix, strings.Fields(line)...); got != want {
			t.Errorf("consumed assignment or ended options %q: %s", line, got)
		}
	}
}

func TestNpmEqualsExpansionBound(t *testing.T) {
	rr := execmatch.NewNormalizer(rows.Builtin().Lookup("npm"), nil).Normalize([]string{
		strings.Repeat("--tag=", execmatch.MaxReadings+2) + "--global", "install", "x",
	})
	if len(rr) != 1 || !rr[0].Unlocatable {
		t.Fatalf("nested assignments must fail closed at the expansion bound: %+v", rr)
	}
}

func TestTerminatorDoubleMarkerCommands(t *testing.T) {
	for _, entry := range []string{"systemctl reboot", "go run", "npm publish", "pip install", "aws s3 rm"} {
		words := strings.Fields(entry)
		argv := append([]string{words[0], "--", "--"}, words[1:]...)
		if got := decide(index(t, "deny: "+entry), argv...); got != "none" {
			t.Errorf("the second marker occupies the command position %q: %s", argv, got)
		}
	}
}

func TestArgparseRejectedValueFailsClosed(t *testing.T) {
	for _, entry := range []string{"aws s3 ls", "aws s3 ls --debug"} {
		if got := decide(index(t, "allow: "+entry), "aws", "--region", "--debug", "s3", "ls"); strings.HasPrefix(got, "allowed ") {
			t.Errorf("missing argparse required value must not create an allow reading: %s", got)
		}
	}
	// Argparse errors on missing output before command selection. An invalid
	// value binding must not erase the released parser's conservative denial.
	if got := decide(index(t, "deny: aws x"), "aws", "-f", "--output", "--query", "x", "", "", ""); !strings.HasPrefix(got, "refused ") {
		t.Errorf("rejected required value lost refusal: %s", got)
	}
}

func TestArgparseRejectedValueKeepsPrefixPending(t *testing.T) {
	argv := []string{"aws", "+c0", "-", "alias.x", "--zz", "-e", "--endpoint-url", "--x=1", "", "rm"}
	for _, list := range []string{"deny", "ask"} {
		ix := index(t, list+": aws x")
		f := execmatch.Facts{Requested: "aws", Image: "aws", Argv0: "aws", Argv: argv, ArgvComplete: true}
		if got := ix.Decide(&f); got.Outcome != execmatch.OutcomeRefused {
			t.Fatalf("rejected required value must fail closed: %+v", got)
		}
		for end := 1; end < len(argv); end++ {
			f.Argv, f.ArgvComplete = argv[:end], false
			if got := ix.Decide(&f); got.Final && got.Outcome != execmatch.OutcomeRefused {
				t.Errorf("%s prefix %q settled before parser rejection: %+v", list, f.Argv, got)
			}
		}
	}
}

func TestValueAmbiguityKeepsPrefixPending(t *testing.T) {
	for _, c := range []struct {
		tool string
		tail []string
	}{
		{"npm", []string{"--tag=x"}},
		{"pnpm", []string{"--dir", "--help"}},
		{"yarn", []string{"--cwd", "--verbose"}},
	} {
		argv := []string{c.tool, "install"}
		for range execmatch.MaxReadings + 1 {
			argv = append(argv, c.tail...)
		}
		ix := index(t, "deny: "+c.tool+" publish")
		f := execmatch.Facts{Requested: c.tool, Image: c.tool, Argv0: c.tool, Argv: argv, ArgvComplete: true}
		if got := ix.Decide(&f); got.Outcome != execmatch.OutcomeRefused {
			t.Fatalf("%s must fail closed past its parse bound: %+v", c.tool, got)
		}
		for end := 1; end < len(argv); end++ {
			f.Argv, f.ArgvComplete = argv[:end], false
			if got := ix.Decide(&f); got.Final && got.Outcome != execmatch.OutcomeRefused {
				t.Errorf("%s prefix %q settled before budget exhaustion: %+v", c.tool, f.Argv, got)
			}
		}
	}
}

func TestUnestablishedValueModes(t *testing.T) {
	for _, tool := range []string{"pnpm", "yarn", "cargo", "gcloud", "npx", "node", "sh", "bash", "dash", "zsh", "ksh", "perl", "ruby"} {
		row := rows.Builtin().Lookup(tool)
		var walk func(*execmatch.Level)
		walk = func(lv *execmatch.Level) {
			if lv == nil {
				return
			}
			for _, o := range lv.Opts {
				if o.Arg != execmatch.ArgRequired {
					continue
				}
				mode := o.NextOption
				if mode == execmatch.NextOptionDefault {
					mode = lv.Syntax.NextOption
				}
				if mode != execmatch.NextOptionDefault && mode != execmatch.NextOptionBoth {
					t.Errorf("%s %s inferred a value rule from option spelling: %v", tool, o.Name, mode)
				}
			}
			for _, child := range lv.Subs {
				walk(child)
			}
			walk(lv.Wild)
		}
		walk(row.Root)
		if row.Interp != nil && row.Interp.Fallback != nil {
			walk(row.Interp.Fallback.Root)
		}
	}
}

func TestNpmBrowserValueType(t *testing.T) {
	for _, next := range []string{"--", "---", "--global", "---x", "-g"} {
		rr := execmatch.NewNormalizer(rows.Builtin().Lookup("npm"), nil).Normalize([]string{"--browser", next, "access", "--global"})
		if len(rr) != 1 {
			t.Errorf("browser %q must have one established type reading: %+v", next, rr)
			continue
		}
		var browser *execmatch.Hit
		for i := range rr[0].Hits {
			if rr[0].Hits[i].Opt.Name == "browser" {
				browser = &rr[0].Hits[i]
			}
		}
		consume := next != "-g"
		if browser == nil || browser.HasValue != consume || consume && browser.Value != next {
			t.Errorf("browser %q value binding: %+v", next, rr[0])
		}
		if len(rr[0].Path) != 1 || rr[0].Path[0] != "access" {
			t.Errorf("browser %q must leave access as command: %+v", next, rr[0])
		}
	}
}

// The released value binding exposed an empty token as a prefix of every npm
// command and overflowed. Nopt leaves the first call valueless, consumes that
// empty token with the next call, and has no command to dispatch.
func TestNpmStringValueCommandless(t *testing.T) {
	for _, list := range []string{"deny", "ask"} {
		ix := index(t, list+": npm x")
		for _, multicall := range []bool{false, true} {
			argv := []string{"npm", "-abc", "-c", "", "-0", "-c"}
			f := execmatch.Facts{Requested: "npm", Image: "npm", Argv0: "npm", Argv: argv, ArgvComplete: true}
			if multicall {
				f.Requested, f.Image, f.Argv0, f.Path, f.Links = "3", "ls", "xbox", "/proc/self/fd/3", 116
				f.Argv = append([]string{"xbox", "npm"}, argv[1:]...)
			}
			if got := ix.Decide(&f); got.Outcome != execmatch.OutcomeRefused || !got.Final {
				t.Errorf("%s multicall=%v lost the released refusal floor: %+v", list, multicall, got)
			}
			f.ArgvComplete = false
			if got := ix.Decide(&f); got.Final && got.Outcome != execmatch.OutcomeRefused {
				t.Errorf("%s multicall=%v settled with a required value still pending: %+v", list, multicall, got)
			}
		}
	}
}

// Argparse recognizes known assignments (and their prefixes) before its space
// fallback. Missing a required value must not invent a successful command path.
func TestArgparseSpacedAssignmentPrecedence(t *testing.T) {
	for _, tc := range []struct{ preceding, next, denied string }{
		{"--region", "--query=has space", "--query"},
		{"--query", "--region=has space", "--region"},
		{"--region", "--qu=has space", "--query"},
		{"--region", "--c=has space", "--query"}, // ambiguous declared prefixes also reject
	} {
		t.Run(tc.preceding+"/"+tc.next, func(t *testing.T) {
			argv := []string{"aws", tc.preceding, tc.next, "s3", "ls"}
			if got := decide(index(t, "deny: aws s3 ls "+tc.denied), argv...); !strings.HasPrefix(got, "refused ") {
				t.Errorf("missing required value erased the option denial: %s", got)
			}
			if got := decide(index(t, "allow: aws s3 ls"), argv...); strings.HasPrefix(got, "allowed ") {
				t.Errorf("missing required value widened the command allow: %s", got)
			}
			for _, r := range execmatch.NewNormalizer(rows.Builtin().Lookup("aws"), nil).Normalize(argv[1:]) {
				if !r.Unlocatable {
					t.Errorf("argparse rejection became successful dispatch: %+v", r)
				}
				assignment := false
				for _, h := range r.Hits {
					if h.Raw == tc.preceding && h.HasValue {
						t.Errorf("required option swallowed the following assignment: %+v", h)
					}
					assignment = assignment || h.Raw == tc.denied && h.HasValue && h.Value == "has space"
				}
				if strings.HasPrefix(tc.next, tc.denied+"=") && !assignment {
					t.Errorf("lost the independently recognized option assignment: %+v", r.Hits)
				}
			}
		})
	}
}

func TestArgparseUnknownSpacedWordKeepsBothReadings(t *testing.T) {
	for _, next := range []string{"-x y", "--future=has space"} {
		value, rejected := false, false
		for _, r := range execmatch.NewNormalizer(rows.Builtin().Lookup("aws"), nil).Normalize([]string{"--region", next, "s3", "ls"}) {
			for _, h := range r.Hits {
				if h.Opt != nil && h.Opt.Name == "region" {
					value = value || h.HasValue && h.Value == next && !r.Unlocatable
					rejected = rejected || !h.HasValue && r.Unlocatable
				}
			}
		}
		if !value || !rejected {
			t.Errorf("unlisted option classification %q: value=%v rejection=%v; need both", next, value, rejected)
		}
	}
}
