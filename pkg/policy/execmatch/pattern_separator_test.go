// SPDX-License-Identifier: Apache-2.0

package execmatch_test

import (
	compare "github.com/attention-span-ai/tego/test/execmatchdiff"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

// Pattern separators use the same command and operand boundaries as their row.
func TestPatternSeparatorRowSemantics(t *testing.T) {
	cases := []struct {
		entry string
		yes   []string
		no    []string
	}{
		{"systemctl -- reboot", []string{"systemctl reboot", "systemctl -- reboot"}, []string{"systemctl start reboot"}},
		{"go -- run", []string{"go run main.go", "go -- run main.go"}, []string{"go build run"}},
		{"npm -- publish", []string{"npm publish", "npm -- publish"}, []string{"npm install publish"}},
		{"aws -- s3 rm", []string{"aws s3 rm s3://b/x", "aws -- s3 rm s3://b/x"}, []string{"aws s3 ls rm"}},
		{"git stash --", []string{"git stash", "git stash push", "git stash --"}, []string{"git stash drop", "git stash drop drop"}},
		{"git stash -- drop", []string{"git stash -- drop", "git stash push -- drop"}, []string{"git stash drop", "git stash drop drop"}},
		{"gh -- version", []string{"gh -- version"}, []string{"gh version"}},
		{"gh --", []string{"gh", "gh --"}, []string{"gh version"}},
		{"npm -- publish --force", []string{"npm -- publish --force", "npm publish -- --force"}, []string{"npm publish --force"}},
		{"go -- run -exec=driver", []string{"go -- run -exec driver main.go", "go run -exec driver main.go"}, []string{"go run main.go"}},
	}
	for _, c := range cases {
		t.Run(c.entry, func(t *testing.T) {
			for _, list := range []string{"allow", "deny", "ask"} {
				ix := index(t, list+": "+c.entry)
				for _, line := range c.yes {
					got := decide(ix, strings.Fields(line)...)
					want := "refused exec." + list + "[" + c.entry + "]"
					if list == "allow" {
						want = "allowed exec.allow[" + c.entry + "]"
						if compare.ReleasedRefuses(c.entry, "allow", strings.Fields(line)) {
							want = "refused exec.args[" + strings.Fields(c.entry)[0] + "]"
						}
					}
					if got != want {
						t.Errorf("%s %q: %s, want %s", list, line, got, want)
					}
				}
				for _, line := range c.no {
					got := decide(ix, strings.Fields(line)...)
					if got == "allowed exec.allow["+c.entry+"]" || (got == "refused exec."+list+"["+c.entry+"]") != (list != "allow" && compare.ReleasedRefuses(c.entry, list, strings.Fields(line))) {
						t.Errorf("%s %q: entry matched a different operation: %s", list, line, got)
					}
				}
			}
		})
	}
}

// Generic separators are optional at their position and later dash words are operands.
func TestPatternSeparatorGenericMatrix(t *testing.T) {
	cases := []struct {
		entry string
		yes   []string
		no    []string
	}{
		{"tool --", []string{"tool", "tool --", "tool x", "tool -- x"}, nil},
		{"tool -- x", []string{"tool x", "tool -- x"}, []string{"tool y"}},
		{"tool -- -r", []string{"tool -r", "tool -- -r"}, []string{"tool -rf", "tool -- -rf"}},
		{"tool a -- -r", []string{"tool a -r", "tool a -- -r"}, []string{"tool a -rf"}},
		{"tool --force a -- -r", []string{"tool --force a -r", "tool --force a -- -r"}, []string{"tool a -- --force -r"}},
		{"tool -- --", []string{"tool -- --"}, []string{"tool", "tool --"}},
	}
	for _, c := range cases {
		t.Run(c.entry, func(t *testing.T) {
			for _, list := range []string{"allow", "deny", "ask"} {
				ix := index(t, list+": "+c.entry)
				for _, line := range c.yes {
					got := decide(ix, strings.Fields(line)...)
					want := "refused exec." + list + "[" + c.entry + "]"
					if list == "allow" {
						want = "allowed exec.allow[" + c.entry + "]"
						if compare.ReleasedRefuses(c.entry, "allow", strings.Fields(line)) {
							want = "refused exec.args[" + strings.Fields(c.entry)[0] + "]"
						}
					}
					if got != want {
						t.Errorf("%s %q: %s, want %s", list, line, got, want)
					}
				}
				for _, line := range c.no {
					got := decide(ix, strings.Fields(line)...)
					if got == "allowed exec.allow["+c.entry+"]" || (got == "refused exec."+list+"["+c.entry+"]") != (list != "allow" && compare.ReleasedRefuses(c.entry, list, strings.Fields(line))) {
						t.Errorf("%s %q: separator lost its boundary: %s", list, line, got)
					}
				}
			}
		})
	}
}

// With no invocation marker a generic tool supplies no operand boundary. Refusing
// predicates inspect both groups independently; an explicit marker supplies it.
func TestPatternSeparatorGenericRefusingRegions(t *testing.T) {
	cases := []struct {
		entry, argv string
		matches     bool
	}{
		{"tool pre -- post", "tool post pre", true},
		{"tool pre -- post", "tool pre post --", false},
		{"tool pre -- post", "tool pre -- post", true},
		{"tool pre -- post", "tool -- pre post", false},
		{"tool a -- -r", "tool -r a", true},
		{"tool --force a -- -r", "tool --force -r a", true},
		{"tool --force -- --force", "tool --force", true},
		{"tool --force -- --force", "tool --force --", false},
		{"tool --force -- --force", "tool --force -- --force", true},
		{"tool -- a --", "tool a --", false},
		{"tool -- a --", "tool -- a --", true},
	}
	for _, c := range cases {
		for _, list := range []string{"deny", "ask"} {
			t.Run(list+"/"+c.entry+"/"+c.argv, func(t *testing.T) {
				got := decide(index(t, list+": "+c.entry), strings.Fields(c.argv)...)
				want := "none"
				if c.matches {
					want = "refused exec." + list + "[" + c.entry + "]"
				}
				if got != want {
					t.Errorf("%q: %s, want %s", c.argv, got, want)
				}
			})
		}
	}
	// Allow keeps the positional prefix and skips a marker only at the pattern's
	// written boundary. A later marker remains an explicitly named literal operand.
	for _, c := range []struct {
		entry, argv string
		matches     bool
	}{
		{"tool -- a --", "tool a --", false},
		{"tool -- a --", "tool -- a --", true},
		{"tool a -- -r", "tool -r a", false},
		{"tool --force a -- -r", "tool --force -r a", false},
	} {
		want := "refused exec.args[tool]"
		if c.matches {
			want = "allowed exec.allow[" + c.entry + "]"
		}
		if got := decide(index(t, "allow: "+c.entry), strings.Fields(c.argv)...); got != want {
			t.Errorf("allow %q: %s, want %s", c.argv, got, want)
		}
	}
}

func TestPatternSeparatorDoesNotBroadenUnknownOptions(t *testing.T) {
	for _, entry := range []string{"go --future x -- run", "aws -- s3 --future rm"} {
		if _, err := execmatch.Parse(entry, execmatch.ListAllow, rows.Builtin()); err == nil {
			t.Errorf("%q admitted an option the row cannot bind", entry)
		}
	}
}

// A word spelled -- can instead be an option value or a literal operand. Only
// the separator parser branch may switch the pattern to separator semantics.
func TestPatternSeparatorOnlyAtParserBoundary(t *testing.T) {
	p, err := execmatch.Parse("git -C -- stash", execmatch.ListAllow, rows.Builtin())
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(p.Path, " "); got != "stash" {
		t.Errorf("option value changed a command-prefix pattern: path %q", got)
	}
	if got := decide(index(t, "allow: git -C -- stash"), "git", "-C", "--", "stash", "drop"); got != "allowed exec.allow[git -C -- stash]" {
		t.Errorf("option value selected an implicit default: %s", got)
	}
	for _, entry := range []string{"npm publish -- ---", "npm -- publish ---"} {
		if _, err := execmatch.Parse(entry, execmatch.ListAllow, rows.Builtin()); err != nil {
			t.Errorf("literal all-dash operand in %q: %v", entry, err)
		}
	}
}

func TestPatternSeparatorDescription(t *testing.T) {
	cases := []struct {
		entry string
		list  execmatch.List
		want  string
	}{
		{"gh -- version", execmatch.ListAllow, "no subcommand"},
		{"tool a -- -r", execmatch.ListAllow, "optional"},
		{"tool a -- -r", execmatch.ListDeny, "-r"},
		{"docker -- ps", execmatch.ListDeny, "separator readings"},
	}
	for _, c := range cases {
		p, err := execmatch.Parse(c.entry, c.list, rows.Builtin())
		if err != nil {
			t.Fatal(err)
		}
		if got := p.Reading(); !strings.Contains(got, c.want) {
			t.Errorf("%q description %q omits %q", c.entry, got, c.want)
		}
		if got := p.Canonical(); got != c.entry {
			t.Errorf("%q canonical %q loses separator meaning", c.entry, got)
		}
	}
}

// A glob cannot select a level's default while it is still an unresolved command
// token. It must not silently grant another explicit child through prefix matching.
func TestPatternSeparatorRejectsWildcardDispatch(t *testing.T) {
	for _, entry := range []string{"git st* --", "git sta?h --", "git sta[st]h --", "go -- r*", "gh r* --", "docker c* --"} {
		for _, list := range []execmatch.List{execmatch.ListAllow, execmatch.ListDeny, execmatch.ListAsk} {
			if _, err := execmatch.Parse(entry, list, rows.Builtin()); err == nil {
				t.Errorf("%s %q must diagnose an unresolved separator dispatch glob", list, entry)
				if list == execmatch.ListAllow && entry == "gh r* --" {
					t.Logf("widening witness: %s", decide(index(t, "allow: "+entry), "gh", "repo", "delete"))
				}
				if list == execmatch.ListAllow && entry == "docker c* --" {
					t.Logf("widening witness: %s", decide(index(t, "allow: "+entry), "docker", "container", "rm"))
				}
			}
		}
	}
	for _, entry := range []string{"git st*", "git push -- origin feature/*", "git push feature/* --", "tool -- feature/*"} {
		for _, list := range []execmatch.List{execmatch.ListAllow, execmatch.ListDeny, execmatch.ListAsk} {
			if _, err := execmatch.Parse(entry, list, rows.Builtin()); err != nil {
				t.Errorf("%s %q: ordinary command or operand glob: %v", list, entry, err)
			}
		}
	}
}

// A value-taking option can leave -- to its parser instead of consuming it as a
// value. The pattern must use the same typed rule before it selects a command.
func TestPatternSeparatorAfterValueOption(t *testing.T) {
	for _, entry := range []string{"npm --tag -- install", "npm --cache -- install", "npm --fetch-retries -- install"} {
		for _, list := range []string{"allow", "deny", "ask"} {
			ix := index(t, list+": "+entry)
			want := "refused exec." + list + "[" + entry + "]"
			if list == "allow" {
				want = "allowed exec.allow[" + entry + "]"
			}
			if got := decide(ix, strings.Fields(entry)...); got != want {
				t.Errorf("%s %q: %s, want %s", list, entry, got, want)
			}
		}
	}
	for _, list := range []execmatch.List{execmatch.ListAllow, execmatch.ListDeny, execmatch.ListAsk} {
		if _, err := execmatch.Parse("aws --region -- s3 rm", list, rows.Builtin()); err == nil {
			t.Errorf("%s accepted an inert pattern whose required argparse value is missing", list)
		}
	}
	// No marker means an ordinary parent entry still grants its explicit children.
	if got := decide(index(t, "allow: git stash"), "git", "stash", "drop"); got != "allowed exec.allow[git stash]" {
		t.Errorf("a plain parent entry selected its default: %s", got)
	}
}

func TestPatternSeparatorAfterUnestablishedValueOption(t *testing.T) {
	syn := execmatch.Syntax{LongSep: true, NextOption: execmatch.NextOptionBoth,
		Terminator: execmatch.TerminatorCommand, TerminatorOptions: execmatch.TerminatorOptionsNone}
	row := &execmatch.Row{Tool: "uncertain", Root: &execmatch.Level{Syntax: syn,
		Opts: []execmatch.Opt{{Name: "value", Long: []string{"value"}, Arg: execmatch.ArgRequired}},
		Subs: map[string]*execmatch.Level{"run": {Syntax: syn}}}}
	rs := execmatch.NewRows(row)
	tokens := []string{"--value", "--", "run"}
	inv := &execmatch.Invocation{Tool: "uncertain", Row: row, Tokens: tokens,
		Readings: execmatch.NewNormalizer(row, nil).Normalize(tokens)}
	if len(inv.Readings) != 2 {
		t.Fatalf("need both value and marker readings: %+v", inv.Readings)
	}
	for _, list := range []execmatch.List{execmatch.ListAllow, execmatch.ListDeny, execmatch.ListAsk} {
		p, err := execmatch.Parse("uncertain --value -- run", list, rs)
		if list == execmatch.ListAllow {
			// ADR 0048 requires every parser reading for a grant. The value
			// and valueless predicates differ even though both name run.
			if err == nil {
				t.Error("an allow cannot choose between required-value predicates")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := p.Match(inv); got == execmatch.MatchNone {
			t.Errorf("%s pattern lost its value-or-marker reading", list)
		}
	}
}

// Git's retained submodule source stops its dispatcher at -- and reports usage
// without a command (git-submodule.sh, dispatch loop and no-command branch).
// Unestablished rows retain that possibility; an allow must not select only the
// alternative that dispatches to a different operation (ADR 0048, terminators).
func TestPatternSeparatorAmbiguousAllowCannotGrantAnOperation(t *testing.T) {
	for _, entry := range []string{"git submodule -- update", "docker -- ps"} {
		t.Run(entry, func(t *testing.T) {
			if _, err := execmatch.Parse(entry, execmatch.ListAllow, rows.Builtin()); err == nil {
				t.Errorf("ambiguous allow %q must require an explicit operation before --", entry)
				plain := strings.Replace(entry, " --", "", 1)
				t.Logf("overgrant witness: %s", decide(index(t, "allow: "+entry), strings.Fields(plain)...))
			}
			for _, list := range []string{"deny", "ask"} {
				if got := decide(index(t, list+": "+entry), strings.Fields(strings.Replace(entry, " --", "", 1))...); got != "refused exec."+list+"["+entry+"]" {
					t.Errorf("%s lost a possible operation: %s", list, got)
				}
			}
		})
	}
	for _, entry := range []string{"go -- run", "aws -- s3 ls", "git stash -- drop", "npm -- publish --force"} {
		if _, err := execmatch.Parse(entry, execmatch.ListAllow, rows.Builtin()); err != nil {
			t.Errorf("established separator %q: %v", entry, err)
		}
	}
}

func TestPatternSeparatorIdenticalMeaningsRemainValid(t *testing.T) {
	for _, unknownDispatch := range []bool{false, true} {
		syn := execmatch.Syntax{Terminator: execmatch.TerminatorCommandFlags, TerminatorOptions: execmatch.TerminatorOptionsBoth}
		root := &execmatch.Level{Syntax: syn, Subs: map[string]*execmatch.Level{"run": {Syntax: syn}}}
		entry := "uncertain -- run"
		tokens := []string{"run"}
		if unknownDispatch {
			root.Syntax.Terminator = execmatch.TerminatorBoth
			entry = "uncertain --"
			tokens = nil
		}
		row := &execmatch.Row{Tool: "uncertain", Root: root}
		rs := execmatch.NewRows(row)
		p, err := execmatch.Parse(entry, execmatch.ListAllow, rs)
		if err != nil {
			t.Fatalf("identical parser meanings in %q: %v; readings=%+v", entry, err, execmatch.NewNormalizer(row, nil).Normalize(strings.Fields(entry)[1:]))
		}
		inv := &execmatch.Invocation{Tool: "uncertain", Row: row, Tokens: tokens, Readings: execmatch.NewNormalizer(row, nil).Normalize(tokens)}
		if got := p.Match(inv); got != execmatch.MatchDefinite {
			t.Errorf("%q: identical meanings lost ordinary invocation: %s", entry, got)
		}
	}
}

// A separator changes parser boundaries, not the existing spelling of a named
// option. In particular Go's flag parser reads -name and --name as long names.
func TestPatternSeparatorUnknownNamesAcrossRoutes(t *testing.T) {
	for _, spelling := range []string{"-future", "--future", "-X"} {
		entry := "go " + spelling + " x -- run"
		for _, list := range []string{"deny", "ask"} {
			ix := index(t, list+": "+entry)
			for route := range 4 {
				argv := []string{"go", spelling, "x", "--", "run"}
				f := execmatch.Facts{Requested: "go", Image: "go", Argv0: "go", Argv: argv, ArgvComplete: true}
				switch route {
				case 1:
					f.Requested, f.Image = "other", "other"
				case 2:
					f.Requested, f.Image, f.Argv0 = "ld-linux-x86-64.so.2", "ld-linux-x86-64.so.2", "ld-linux-x86-64.so.2"
					f.Argv = append([]string{f.Argv0, "/usr/bin/go"}, argv[1:]...)
					f.Loaded = &execmatch.Loaded{Path: "/usr/bin/go", Image: "go", Argv: argv}
				case 3:
					f.Requested, f.Image, f.Argv0 = "python3", "python3", "python3"
					f.Argv = append([]string{"python3", "/scripts/go"}, argv[1:]...)
				}
				if got := ix.Decide(&f); got.Outcome != execmatch.OutcomeRefused || got.Rule() != "exec."+list+"["+entry+"]" {
					t.Errorf("%s %q route %d became inert: %+v", list, entry, route, got)
				}
				// Once the relevant program is known, no proper prefix can settle
				// as admitted before the named option and command are read.
				for n := 0; n < len(argv)-1; n++ {
					prefix := f
					prefix.ArgvComplete = false
					if route >= 2 {
						prefix.Argv = f.Argv[:2+n]
					} else {
						prefix.Argv = f.Argv[:1+n]
					}
					if f.Loaded != nil {
						loaded := *f.Loaded
						loaded.Argv = argv[:1+n]
						prefix.Loaded = &loaded
					}
					if got := ix.Decide(&prefix); got.Final && got.Outcome != execmatch.OutcomeRefused {
						t.Errorf("%s %q route %d prefix %d admitted before refusal: %+v", list, entry, route, n, got)
					}
				}
			}
			other := "--" + strings.TrimLeft(spelling, "-")
			if got := decide(ix, "go", other, "x", "--", "run"); got != "refused exec."+list+"["+entry+"]" {
				t.Errorf("%s lost the same Go long name %q: %s", entry, other, got)
			}
			for _, argv := range [][]string{{"go", "-other", "x", "--", "run"}, {"go", spelling, "y", "--", "run"}} {
				if got := decide(ix, argv...); got != "none" {
					t.Errorf("%s broadened a name or value boundary for %q: %s", entry, argv, got)
				}
			}
		}
	}
}

func TestPatternSeparatorUnknownNameFields(t *testing.T) {
	for _, c := range []struct {
		entry, raw, long, value string
		hasValue                bool
	}{
		{"go -future x -- run", "-future", "future", "", false},
		{"go --future x -- run", "--future", "future", "", false},
		{"go -X x -- run", "-X", "X", "", false},
		{"go -future=x -- run", "-future", "future", "x", true},
	} {
		p, err := execmatch.Parse(c.entry, execmatch.ListDeny, rows.Builtin())
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Opts) != 1 {
			t.Fatalf("%s: options=%+v", c.entry, p.Opts)
		}
		o := p.Opts[0]
		if o.Opt != nil || o.Raw != c.raw || o.Long != c.long || o.Short != 0 || o.Value != c.value || o.HasValue != c.hasValue || o.Neg || o.Depth != 0 {
			t.Errorf("%s lost normalized binding or existing name grammar: %+v", c.entry, o)
		}
	}
	// Ended ancestors must not turn an unknown literal no-global into a
	// negated known global while recovering its pattern spelling.
	syn := execmatch.Syntax{Negatable: true, LongSep: true, Terminator: execmatch.TerminatorCommandFlags, TerminatorOptions: execmatch.TerminatorOptionsChild}
	row := &execmatch.Row{Tool: "boundary", Root: &execmatch.Level{Syntax: syn,
		Opts: []execmatch.Opt{{Name: "global", Long: []string{"global"}, Persistent: true}},
		Subs: map[string]*execmatch.Level{"service": {Syntax: syn, Subs: map[string]*execmatch.Level{"run": {Syntax: syn}}}}}}
	rs := execmatch.NewRows(row)
	for _, list := range []execmatch.List{execmatch.ListDeny, execmatch.ListAsk} {
		p, err := execmatch.Parse("boundary -- service --no-global run", list, rs)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range p.Opts {
			if o.Opt != nil || o.Raw != "--no-global" || o.Long != "no-global" || o.Short != 0 || o.Neg || o.Depth != 1 {
				t.Errorf("ended global vocabulary changed unknown spelling: %+v", o)
			}
		}
		for _, option := range []string{"--no-global", "--global"} {
			tokens := []string{"--", "service", option, "run"}
			inv := &execmatch.Invocation{Tool: "boundary", Row: row, Tokens: tokens, Readings: execmatch.NewNormalizer(row, nil).Normalize(tokens)}
			if got := p.Match(inv); (got != execmatch.MatchNone) != (option == "--no-global") {
				t.Errorf("%s matched wrong literal option %s: %s", list, option, got)
			}
		}
	}
}
