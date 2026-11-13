// SPDX-License-Identifier: Apache-2.0

package rows

import (
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

type parserLevel struct {
	row  *execmatch.Row
	lv   *execmatch.Level
	path []string
}

func parserLevels() []parserLevel {
	var out []parserLevel
	var walk func(*execmatch.Row, *execmatch.Level, []string)
	walk = func(r *execmatch.Row, lv *execmatch.Level, path []string) {
		if lv == nil {
			return
		}
		out = append(out, parserLevel{r, lv, slices.Clone(path)})
		var names []string
		for n := range lv.Subs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			walk(r, lv.Subs[n], append(slices.Clone(path), n))
		}
		if lv.Wild != nil {
			walk(r, lv.Wild, append(slices.Clone(path), "x"))
		}
	}
	for _, r := range Builtin().All() {
		walk(r, r.Root, nil)
	}
	return out
}

// TestOptionLookingValueSweep exercises every value-taking spelling at every
// declared level, including leaves. A leaf copy isolates option binding from
// command lookup: a later command can never hide a lost option predicate here.
// The expected sets are the source contracts recorded in exec-command-rows.md.
func TestOptionLookingValueSweep(t *testing.T) {
	nextWords := []string{"-x", "--future", "--", "---", "---x", "-1", "-x y"}
	checked := 0
	for _, c := range parserLevels() {
		if len(c.lv.Opts) == 0 {
			continue
		}
		lv := &execmatch.Level{Syntax: c.lv.Syntax, Opts: slices.Clone(c.lv.Opts)}
		r := &execmatch.Row{Tool: "probe", Root: lv}
		nz := execmatch.NewNormalizer(r, nil)
		for _, o := range c.lv.Opts {
			if o.Arg == execmatch.ArgNone {
				continue
			}
			var spellings []string
			if c.lv.Syntax.LongSep || c.lv.Syntax.SingleDashLong || o.SepOnly {
				for _, n := range o.Long {
					if c.lv.Syntax.SingleDashLong {
						spellings = append(spellings, "-"+n, "--"+n)
					} else {
						spellings = append(spellings, "--"+n)
					}
				}
			}
			for _, n := range o.Short {
				spellings = append(spellings, "-"+string(n))
			}
			mode := o.NextOption
			if mode == execmatch.NextOptionDefault {
				mode = c.lv.Syntax.NextOption
			}
			for _, spelling := range spellings {
				for _, next := range nextWords {
					wantValue, wantFlag := true, false
					switch o.Arg {
					case execmatch.ArgOptional, execmatch.ArgNextWord:
						wantValue, wantFlag = false, true
					case execmatch.ArgMaybe:
						if mode == execmatch.NextOptionNoptMaybe {
							wantFlag = len(next) > 1 && next[0] == '-' && next[1] != '-'
							wantValue = !wantFlag
						} else if len(o.Values) == 0 {
							wantFlag = true
						} else {
							wantValue = slices.Contains(o.Values, next)
							wantFlag = !wantValue
						}
					case execmatch.ArgNone, execmatch.ArgRequired:
						switch mode {
						case execmatch.NextOptionDefault, execmatch.NextOptionBoth:
							wantFlag = true
						case execmatch.NextOptionNopt:
							allDash := strings.Trim(next, "-") == ""
							oneDashName := len(next) > 1 && next[0] == '-' && next[1] != '-'
							twoDashName := len(next) > 2 && next[:2] == "--" && next[2] != '-'
							wantFlag = allDash || oneDashName || twoDashName
							wantValue = !wantFlag
						case execmatch.NextOptionNoptValue:
							wantFlag = strings.Trim(next, "-") == ""
							wantValue = !wantFlag
						case execmatch.NextOptionValue, execmatch.NextOptionNoptMaybe:
							// Required values consume; NoptMaybe is only used by ArgMaybe above.
						case execmatch.NextOptionArgparse:
							// The unlisted spaced word may be a declared option
							// before argparse reaches its positional fallback.
							wantFlag = true
							wantValue = strings.Contains(next, " ") || next == "-1"
						}
					}
					gotValue, gotFlag := false, false
					for _, reading := range nz.Normalize([]string{spelling, next, "operand"}) {
						for _, h := range reading.Hits {
							if h.Opt != nil && h.Opt.Name == o.Name {
								gotValue = gotValue || h.HasValue && h.Value == next
								gotFlag = gotFlag || !h.HasValue
							}
						}
					}
					if gotValue != wantValue || gotFlag != wantFlag {
						t.Fatalf("%s %s: %s %q mode=%v got value/flag=%v/%v want=%v/%v", c.row.Tool, strings.Join(c.path, " "), spelling, next, mode, gotValue, gotFlag, wantValue, wantFlag)
					}
					checked++
				}
			}
		}
	}
	if checked < 2000 {
		t.Fatalf("option corpus unexpectedly small: %d", checked)
	}
	t.Logf("checked %d option-looking values at every declared row level", checked)
}

// TestNoptTypeContracts pins the reviewed npm 9.2.0 definitions independently of
// the row's metadata: only an exact String type gets nopt's String guard.
func TestNoptTypeContracts(t *testing.T) {
	stringsOnly := strings.Fields("call diff-dst-prefix diff-src-prefix editor git heading init-author-email init-author-name init-license init.author.email init.author.name init.license message pack-destination preid save-prefix scope searchexclude searchopts shell tag tag-version-prefix user-agent viewer")
	seen := map[string]bool{}
	for _, o := range Builtin().Lookup("npm").Root.Opts {
		if o.Arg != execmatch.ArgRequired {
			continue
		}
		want := execmatch.NextOptionDefault
		if slices.Contains(stringsOnly, o.Name) {
			want = execmatch.NextOptionNopt
			seen[o.Name] = true
		}
		if o.NextOption != want {
			t.Errorf("npm %s: NextOption=%v want %v from npm 9.2.0 type", o.Name, o.NextOption, want)
		}
	}
	if len(seen) != len(stringsOnly) {
		t.Fatalf("String inventory=%d want %d", len(seen), len(stringsOnly))
	}
	for _, c := range []struct {
		line string
		want bool
	}{
		{"npm --tag --global install x", true},
		{"npm --tag=--global install x", true},
		{"npm --tag ---x install x", false},
		{"npm --fetch-retries --global install x", false},
		{"npm --fetch-retries=--global install x", false},
		{"npm --_auth --global install x", false},
		{"npm --cache --global install x", false},
	} {
		got := run(rules(t, "deny: npm install --global"), words(c.line)...)
		if (got.Outcome == execmatch.OutcomeRefused) != c.want {
			t.Errorf("%s: %s want refused=%v", c.line, decided(got), c.want)
		}
	}
}

// TestPostSeparatorOptionVocabulary puts every visible required option after a
// marker and before a second command word. A parser that ended cannot consume
// that word with its old global option. The ordinary unknown-option readings
// must preserve it, even when the option also appears at later row levels.
func TestPostSeparatorOptionVocabulary(t *testing.T) {
	checked := 0
	for _, c := range parserLevels() {
		if c.lv.Subs == nil || c.lv.Syntax.Terminator == execmatch.TerminatorOperands || c.lv.Syntax.Terminator == execmatch.TerminatorCommand || c.lv.Syntax.Terminator == execmatch.TerminatorUnknown {
			continue
		}
		if c.lv.Syntax.TerminatorOptions == execmatch.TerminatorOptionsInherit || c.lv.Syntax.TerminatorOptions == execmatch.TerminatorOptionsNone {
			continue
		}
		// Collect only options that are visible at this level before the
		// separator: local options and persistent declarations of its parents.
		var options []execmatch.Opt
		parent := c.row.Root
		for depth := 0; parent != nil; depth++ {
			for _, o := range parent.Opts {
				if depth == len(c.path) || o.Persistent {
					options = append(options, o)
				}
			}
			if depth == len(c.path) {
				break
			}
			if next, ok := parent.Subs[c.path[depth]]; ok {
				parent = next
			} else {
				parent = parent.Wild
			}
		}
		children := map[string]*execmatch.Level{}
		for n, lv := range c.lv.Subs {
			children[n] = lv
		}
		if c.lv.Wild != nil {
			children["service"] = c.lv.Wild
		}
		var childNames []string
		for child := range children {
			childNames = append(childNames, child)
		}
		sort.Strings(childNames)
		for _, child := range childNames {
			lv := children[child]
			if lv == nil || lv.Subs == nil {
				continue
			}
			var commands []string
			for n := range lv.Subs {
				commands = append(commands, n)
			}
			if lv.Wild != nil {
				commands = append(commands, "target", "other")
			}
			sort.Strings(commands)
			if len(commands) < 2 {
				continue
			}
			for _, o := range options {
				if o.Arg != execmatch.ArgRequired || len(o.Long) == 0 || !c.lv.Syntax.LongSep {
					continue
				}
				// A child can legitimately redeclare the same spelling.
				if slices.ContainsFunc(lv.Opts, func(local execmatch.Opt) bool { return local.Name == o.Name }) {
					continue
				}
				option := "--" + o.Long[0]
				if c.lv.Syntax.SingleDashLong {
					option = "-" + o.Long[0]
				}
				path := append(slices.Clone(c.path), child, commands[0])
				entry := c.row.Tool + " " + strings.Join(path, " ")
				argv := append([]string{c.row.Tool}, c.path...)
				argv = append(argv, "--", child, option, commands[0], commands[1])
				ix := rules(t, "deny: "+entry)
				if got := run(ix, argv...); got.Outcome != execmatch.OutcomeRefused {
					t.Fatalf("ended parser lost %s under %s: %q: %s", option, entry, argv, decided(got))
				}
				allow := rules(t, "allow: "+c.row.Tool+" "+strings.Join(append(append(slices.Clone(c.path), child), commands[1]), " "))
				if got := run(allow, argv...); got.Outcome == execmatch.OutcomeAllowed {
					t.Fatalf("ended parser admitted wrong command after %s: %q: %s", option, argv, decided(got))
				}
				checked++
			}
		}
	}
	if checked < 20 {
		t.Fatalf("post-separator vocabulary corpus unexpectedly small: %d", checked)
	}
	t.Logf("checked %d ended-parser option vocabularies on deny and allow sides", checked)
}

func TestSeparatorVocabularyModes(t *testing.T) {
	for _, c := range []struct {
		name                          string
		mode                          execmatch.TerminatorOptions
		wantKnown, wantUnknown, ended bool
	}{
		{"none", execmatch.TerminatorOptionsNone, false, false, true},
		{"child", execmatch.TerminatorOptionsChild, false, true, false},
		{"inherit", execmatch.TerminatorOptionsInherit, true, false, false},
		{"both", execmatch.TerminatorOptionsBoth, true, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			syn := execmatch.Syntax{LongSep: true, Terminator: execmatch.TerminatorCommandFlags, TerminatorOptions: c.mode, NextOption: execmatch.NextOptionValue}
			op := &execmatch.Level{Syntax: syn}
			service := &execmatch.Level{Syntax: syn, Subs: map[string]*execmatch.Level{"target": op, "other": op}}
			global := execmatch.Opt{Name: "global", Long: []string{"global"}, Arg: execmatch.ArgRequired, Persistent: true}
			root := &execmatch.Level{Syntax: syn, Opts: []execmatch.Opt{global}, Subs: map[string]*execmatch.Level{"service": service}}
			r := &execmatch.Row{Tool: "probe", Root: root}
			known, unknown, ended := false, false, false
			for _, reading := range execmatch.NewNormalizer(r, nil).Normalize([]string{"--", "service", "--global", "target", "other"}) {
				ended = ended || slices.Equal(reading.Path, []string{"service", "--global"})
				for _, h := range reading.Hits {
					if h.Raw == "--global" {
						known = known || h.Opt != nil
						unknown = unknown || h.Opt == nil
					}
				}
			}
			if known != c.wantKnown || unknown != c.wantUnknown || ended != c.ended {
				t.Fatalf("known/unknown/ended=%v/%v/%v want %v/%v/%v", known, unknown, ended, c.wantKnown, c.wantUnknown, c.ended)
			}
		})
	}
}

// TestSeparatorDenySweep keeps the review's class-wide attack check bounded and
// deterministic. Every named command and wildcard level gets all 13 spellings;
// every staged prefix of a later refusal must remain refused or unfinished.
func TestSeparatorDenySweep(t *testing.T) {
	forms := [][]string{
		{"--"}, {"--future", "--"}, {"--future=x", "--"}, {"--future", "x", "--"},
		{"-X", "--"}, {"-Xx", "--"}, {"-YX", "--"}, {"-YXx", "--"},
		{"", "--"}, {"-", "--"}, {"--future", "-X", "--"},
		{"--future=x", "-Xx", "--"}, {"--future", "x", "-YXx", "--"},
	}
	checked, prefixes := 0, 0
	for _, c := range parserLevels() {
		if c.lv.Subs == nil {
			continue
		}
		var names []string
		for n := range c.lv.Subs {
			names = append(names, n)
		}
		if c.lv.Wild != nil {
			names = append(names, "x")
		}
		sort.Strings(names)
		for _, n := range names {
			path := append(slices.Clone(c.path), n)
			entry := c.row.Tool + " " + strings.Join(path, " ")
			ix := rules(t, "deny: "+entry)
			for _, form := range forms {
				argv := append([]string{c.row.Tool}, c.path...)
				argv = append(argv, form...)
				argv = append(argv, n)
				f := execmatch.Facts{Requested: c.row.Tool, Image: c.row.Tool, Argv0: c.row.Tool, Argv: argv, ArgvComplete: true}
				whole := ix.Decide(&f)
				// A verified operand-only dispatcher need not name this child.
				// Every other grammar keeps the command reading, including
				// the value interpretation of unlisted prefix options.
				want := c.lv.Syntax.Terminator != execmatch.TerminatorOperands
				if want && whole.Outcome != execmatch.OutcomeRefused {
					t.Fatalf("%s missed direct separator: %q: %s", entry, argv, decided(whole))
				}
				if whole.Outcome == execmatch.OutcomeRefused {
					for end := 1; end < len(argv); end++ {
						f.Argv, f.ArgvComplete = argv[:end], false
						got := ix.Decide(&f)
						if got.Final && got.Outcome != execmatch.OutcomeRefused {
							t.Fatalf("%s: final non-refusal %s on prefix %q before refusal %q", entry, decided(got), f.Argv, argv)
						}
						prefixes++
					}
				}
				checked++
			}
		}
	}
	if checked < 10000 {
		t.Fatalf("separator corpus unexpectedly small: %d", checked)
	}
	t.Logf("checked %d deny vectors and %d staged prefixes", checked, prefixes)
}
