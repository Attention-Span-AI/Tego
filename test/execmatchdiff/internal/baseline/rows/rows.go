// SPDX-License-Identifier: Apache-2.0

// Package rows is the per-tool table of exec command rules (ADR 0048 (2)): one execmatch.Row per tool, as data, with
// the version it was checked against and whether it was probed against an installed binary or written from the
// manual only. docs/spec/exec-command-rows.md is the reference description; the tests here hold each probed row to
// the installed tool and to measured invocations.
package rows

import (
	"sync"

	"github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline"
)

// builtin is every row, built once on first use rather than at package init: every binary that links this package
// would otherwise build it at start, the launcher's child stage among them, which starts under the run's pids cap
// and must not spend its threads on a garbage collection the build's allocations set off.
var builtin = sync.OnceValue(func() *execmatch.Rows {
	return execmatch.NewRows(append(append(append([]*execmatch.Row{Git(), Rm()}, interpreters()...), multicall()...), more()...)...)
})

// Builtin is the row set every compile, decision and gate reads. It is immutable.
func Builtin() *execmatch.Rows { return builtin() }

// Syntaxes shared by rows.
var (
	// gnu is getopt_long: clusters, attached short values, --name=v and --name v, unique long prefixes, permutation
	// until `--`.
	gnu = execmatch.Syntax{Clusters: true, ShortAttach: true, LongEquals: true, LongSep: true, LongPrefix: true, Permute: true}
	// parseOptions is git's parse-options: getopt_long's spellings plus --no-<name>.
	parseOptions = execmatch.Syntax{Clusters: true, ShortAttach: true, LongEquals: true, LongSep: true, LongPrefix: true, Negatable: true, Permute: true}
)

// flag is an option without a value.
func flag(name, short string, long ...string) execmatch.Opt {
	if len(long) == 0 && len(name) > 1 {
		long = []string{name}
	}
	return execmatch.Opt{Name: name, Short: short, Long: long}
}

// val is an option that takes a value.
func val(name, short string, long ...string) execmatch.Opt {
	o := flag(name, short, long...)
	o.Arg = execmatch.ArgRequired
	return o
}

// opt is an option whose value must be attached.
func opt(name, short string, long ...string) execmatch.Opt {
	o := flag(name, short, long...)
	o.Arg = execmatch.ArgOptional
	return o
}

// ends marks an option after which every token is an operand, as after `--` (node's --prof-process, execmatch.Opt.Ends).
func ends(o execmatch.Opt) execmatch.Opt {
	o.Ends = true
	return o
}

// endsAttached marks an option after which every token is an operand when it is written with an attached value
// (node's --trace-events-enabled=v, execmatch.Opt.EndsAttached).
func endsAttached(o execmatch.Opt) execmatch.Opt {
	o.EndsAttached = true
	return o
}

// unlocatable marks an option whose every value makes an invocation unlocatable: the tool runs what a file names
// (node's --build-snapshot-config, execmatch.Opt.Rewrite).
func unlocatable(o execmatch.Opt) execmatch.Opt {
	o.Rewrite = func(string) bool { return true }
	return o
}

// nextWord is an option that takes the next token as its value only when that token is a word, not an option, and
// whose word is the option to's value as well (node's -p, whose word is --eval's: execmatch.ArgNextWord, Opt.WordTo).
func nextWord(name, short, to string) execmatch.Opt {
	o := flag(name, short)
	o.Arg, o.WordTo = execmatch.ArgNextWord, to
	return o
}

// leaf is a level with options and operands, no subcommands.
func leaf(syn execmatch.Syntax, opts ...execmatch.Opt) *execmatch.Level {
	return &execmatch.Level{Syntax: syn, Opts: opts}
}

// subs builds a subcommand map from names to levels; a nil level is a leaf with the parent's syntax and no options.
func subs(syn execmatch.Syntax, names ...string) map[string]*execmatch.Level {
	m := map[string]*execmatch.Level{}
	for _, n := range names {
		m[n] = leaf(syn)
	}
	return m
}
