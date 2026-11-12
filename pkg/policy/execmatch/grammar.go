// SPDX-License-Identifier: Apache-2.0

package execmatch

import (
	"sort"
	"strings"
	"sync"
)

// Source says how a row was checked (ADR 0048 (2), R12): against an installed binary, or written from the tool's
// manual only. Compile prints it on every entry's line.
type Source uint8

// Row sources.
const (
	// SourceGeneric is the generic fallback, a tool with no row.
	SourceGeneric Source = iota
	// SourceProbed rows were tested against an installed binary of the recorded version.
	SourceProbed
	// SourceDocumented rows were written from the tool's manual and help only.
	SourceDocumented
)

// String is the source as compile prints it.
func (s Source) String() string {
	switch s {
	case SourceGeneric:
		return "generic"
	case SourceProbed:
		return "probed"
	case SourceDocumented:
		return "documented"
	}
	return "unknown"
}

// Arg is how an option takes a value.
type Arg uint8

// Option value kinds.
const (
	// ArgNone is a flag.
	ArgNone Arg = iota
	// ArgRequired takes a value, attached (`--name=v`, `-nv`, as the level's Syntax allows) or as the next token.
	ArgRequired
	// ArgOptional takes a value only when it is attached (`--name=v`, `-nv`).
	ArgOptional
	// ArgMaybe may take the next token as its value: when Opt.Values lists the values it takes, a next token among
	// them; otherwise either reading, as for an option the row does not list (npm's --browser).
	ArgMaybe
	// ArgNextWord takes the next token as its value when that token is a word, not empty and not starting with '-',
	// and takes no other value: node's -p and --print, whose alias `--print <arg>` reads a word after them as -e's
	// code, while before an option they are a flag (`node -p --title t app.js` runs app.js). An attached `=value` is
	// no value of it, as node drops a boolean's, and its --no- form reads the same, as node applies the alias to the
	// negated name too (`node --no-print x` evaluates x).
	ArgNextWord
)

// Opt is one option a level reads.
type Opt struct {
	// Name is the canonical name compile prints, without dashes: "force", "recursive".
	Name string
	// Long are the long spellings without the leading "--" (or "-" under SingleDashLong).
	Long []string
	// Short are the one-letter spellings, each byte one spelling ("rR" for rm's -r and -R).
	Short string
	// Arg is how the option takes a value.
	Arg Arg
	// Values are the separate values an ArgMaybe option takes (npm's --color takes always, true and false).
	Values []string
	// WordTo names the option at this level whose value an ArgNextWord option's word is as well: node expands
	// `--print <arg>` to -pe, which is --print then --eval <arg>, so `node -p x` holds --eval x too, and an entry naming
	// -e matches it. "" for none.
	WordTo string
	// SepOnly is a value-taking option whose value is always the next token, never attached: git's global -C and -c,
	// where `-C.` is an unknown option.
	SepOnly bool
	// Persistent options are read at every level below the one that declares them (pflag persistent flags, aws and
	// gcloud globals, systemctl's options around its verb).
	Persistent bool
	// AsSub makes the option the subcommand it names: git's --help and --version run `git help` and `git version`.
	AsSub string
	// Stop ends option parsing at this level: every later token is an operand (python's -c and -m, after their
	// value).
	Stop bool
	// Ends ends the options after it as `--` does, negated or not: every later token is an operand, and the first is
	// an interpreter's script even when it starts with '-'. Node's --prof-process, whose alias is {--prof-process, --}
	// (`node --no-prof-process -x` loads -x as its main module, probed). Unlike Stop it leaves the script where a script
	// stands (Reading.Dispatch).
	Ends bool
	// EndsAttached ends the options as Ends does, only when the option is written with an attached value that is not
	// empty (`--name=v`): node's --trace-events-enabled, whose alias inserts the value node gives its categories. With
	// `=v` node takes the categories from v and leaves the inserted token unread, and a token that is no option ends
	// node's option loop, so `node --trace-events-enabled=v -x a.js` loads -x as its main module (src/node_options-inl.h,
	// probed on 20.19.4). Written without a value it is a flag.
	EndsAttached bool
	// Rewrite marks a visible rewrite trigger: an interpretation whose tokens hold this option with a value for which
	// Rewrite reports true is unlocatable (ADR 0048 (2): cargo's --config naming a file or an alias, gcloud's
	// --flags-file, node's --build-snapshot-config, and node's --import naming a module as a URL the row does not
	// resolve). nil for every other option.
	Rewrite func(value string) bool
}

// ends reports whether the options end after this option, written with the value it holds when hasValue: Ends, or
// EndsAttached and an attached value that is not empty.
func (o *Opt) ends(hasValue bool, value string) bool {
	return o.Ends || o.EndsAttached && hasValue && value != ""
}

// Syntax is how one level of a tool spells its options.
type Syntax struct {
	// Clusters reads -rf as -r -f.
	Clusters bool
	// ClusterWords permits only these exact clusters on a non-clustering row:
	// Node's -pe alias is --print --eval; -ep and -peCODE remain unknown.
	ClusterWords []string
	// ShortAttach reads -n5 as -n 5 for a value-taking short option.
	ShortAttach bool
	// ShortEquals reads -n=5 as -n 5 (pflag); elsewhere the value is "=5".
	ShortEquals bool
	// LongEquals reads --name=5.
	LongEquals bool
	// LongSep reads --name 5 for an ArgRequired option.
	LongSep bool
	// LongPrefix accepts a unique prefix of a long name (getopt_long, optparse, git parse-options, npm's nopt).
	LongPrefix bool
	// Negatable reads --no-<long> as the option turned off (git parse-options).
	Negatable bool
	// SingleDashLong reads -name as --name (Go's flag package, terraform); it disables Clusters.
	SingleDashLong bool
	// Permute keeps reading options after an operand (getopt, pflag, git parse-options); without it the first
	// operand ends option parsing (Go's flag package, python, docker run's image).
	Permute bool
	// DashDashUnknown means the tool refuses `--` here (git's global options), which the normalizer reads as an
	// unknown option rather than assuming the refusal.
	DashDashUnknown bool
	// PlusOptions reads +o and +x as options (sh, bash).
	PlusOptions bool
	// DashEnds reads a lone `-` as `--`: it ends the options and is no operand (bash(1), dash's options()).
	DashEnds bool
	// ShortWords reads a single-dash token that is a long name as that option before splitting it into letters
	// (npm's -ws, -dd and -iwr).
	ShortWords bool
	// BoolValues lets a flag take a following true or false (npm's nopt: --save false).
	BoolValues bool
	// Underscores reads `_` in a long option's name as `-`, before the name is looked up or read as a negation (node
	// replaces each `_` of an option's name, up to `=`, with `-` before anything else: `--build_snapshot` is
	// `--build-snapshot` and `--no_print` is `--no-print`, src/node_options-inl.h). An entry's option words are read the
	// same way.
	Underscores bool
}

// Level is one level of a tool's command line: the options it reads and, when it has them, its subcommands.
type Level struct {
	// Opts are the options read at this level; Persistent ones are read below it too.
	Opts []Opt
	// Subs are the subcommands, by canonical name; nil when this level takes operands, not subcommands.
	Subs map[string]*Level
	// Alias maps a built-in alias to its canonical subcommand name, or to a path of them written with spaces
	// (docker's rm is "container rm").
	Alias map[string]string
	// Wild is the level a word that names no subcommand here descends into, the word itself on the path: aws's
	// service and operation, gcloud's groups. nil makes such a word an unknown subcommand.
	Wild *Level
	// Skip are words read and dropped where a subcommand stands (gcloud's release tracks alpha, beta and preview);
	// SkipPrefix drops every such word that starts with it (rustup's +toolchain before a cargo command).
	Skip       map[string]bool
	SkipPrefix string
	// Fold rewrites a word before it is resolved as a subcommand (npm reads camelCase as kebab-case).
	Fold func(string) string
	// SubPrefix accepts a unique prefix of a subcommand name or alias, and a token that is the prefix of several
	// names reads as each of them (npm).
	SubPrefix bool
	// Syntax is how this level spells options.
	Syntax Syntax
	// Default is the subcommand a level with subcommands runs when none is named (`git stash` is `git stash push`).
	// It is informational: a pattern naming the default subcommand does not match the bare form.
	Default string

	parent *Level
	byLong map[string]*Opt
	short  [128]*Opt
	names  []string // sorted subcommand names and aliases, for SubPrefix
}

// Row is one tool's grammar (ADR 0048 (2), the per-tool table).
type Row struct {
	// Tool is the canonical tool name rules are keyed by: "git", "rm".
	Tool string
	// Names are the basenames that are this tool: the tool itself, its versioned and entry-script names
	// ("python3.12", "npm-cli.js").
	Names []string
	// Version is the tool version the row was checked against; Docs is the documentation it was written from.
	Version, Docs string
	// Source says whether the row was probed against an installed binary.
	Source Source
	// Dashed reads a name <tool>-<sub> as (tool, [sub] + argv[1:]).
	Dashed bool
	// DashedRepeat is a plugin that receives its subcommand again as argv[1] (cargo, docker), skipped when present.
	DashedRepeat bool
	// Argv0Dispatch: when argv[0]'s basename is <tool>-<sub>, the tool runs <sub> with argv[1:], whatever file it is
	// (git); the plain reading of argv[1:] is not one the tool makes then.
	Argv0Dispatch bool
	// Argv0Subs maps an argv[0] basename to the subcommand it runs (systemctl as reboot, poweroff, halt). When the file
	// that runs is the row's, a basename that contains a key runs it too: systemd's invoked_as is strstr, so
	// `exec -a xrebootx systemctl` reboots (probed on systemd 257).
	Argv0Subs map[string]string
	// Multicall dispatchers run the applet named by argv[1] (busybox, toybox, the uutils coreutils binary).
	Multicall bool
	// Argv0Prefix: a multicall dispatcher that is itself under any name starting with its tool name, whatever file it
	// is: a busybox hard link run as busybox.x dispatches on argv[1:] (is_prefixed_with in appletlib.c, probed).
	Argv0Prefix bool
	// ProgOption is a multicall dispatcher's option that names the applet: GNU coreutils' single binary runs PROG
	// for `--coreutils-prog=PROG` with argv[2:], and for `--<ProgOption>-shebang=PROG` (its #! form, where argv[2] is
	// the script) with argv[3:]. "" for none.
	ProgOption string
	// Argv0Strip is a prefix a multicall dispatcher drops from argv[0]'s basename before it looks the applet up: GNU
	// coreutils' single binary runs rm when called as lt-rm (src/coreutils.c, libtool's prefix). "" for none.
	Argv0Strip string
	// Interp is set for an interpreter row (python, node, sh, perl, ruby).
	Interp *InterpSpec
	// Autocorrect turns on the git help_unknown_cmd port for the first subcommand word.
	Autocorrect bool
	// Root is the top level of the grammar.
	Root *Level
	// Closure maps a subcommand to the subcommands and dashed helpers the tool runs for itself (ADR 0048 (2), the
	// helper closure); the transitive closure is taken when an index is built.
	Closure map[string][]string
	// HelperDirs are the row's usual helper directories (/usr/lib/git-core, /usr/libexec/git-core), for the docs:
	// compile derives the directory from where the resolved binary lies, and lists it for helper images and
	// autocorrect candidates.
	HelperDirs []string
	// Builtins and Common are the autocorrect candidate set and common-command group used when no helper directory
	// lists dashed built-ins: the intersection over every supported version.
	Builtins, Common []string
	// Residual is the R3 note: rewriting from outside argv that the row does not read.
	Residual string
	// Coverage maps a canonical pattern spelling to the note compile prints on its line ("rm -rf" does not cover
	// "rm -r").
	Coverage map[string]string

	once sync.Once
}

// ready indexes the row's levels for lookups, once; NewRows and NewNormalizer call it.
func (r *Row) ready() *Row {
	r.once.Do(func() { prepare(r.Root, nil) })
	return r
}

// InterpSpec is how an interpreter row dispatches to the tool it runs (ADR 0048 (2), interpretation 5).
type InterpSpec struct {
	// Versions selects this row only for these binary-attested runtime versions.
	Versions []string
	// Fallback is the compatibility row for other builds. Nil fails closed.
	// It has no version gate of its own.
	Fallback *Row
	// ArgvRewrite detects pre-scanners which can load code outside the entry
	// parser. It reads every token; an open prefix cannot settle dispatch.
	ArgvRewrite func([]string) bool
	// Module is the option that names a module to run (python's m), "" when none.
	Module string
	// Code are the options whose value is code (python's c, node's e and p, sh's c): opaque, no interpretation.
	Code []string
	// CodeUnless are options under which the interpreter runs its script though code is given, so a reading that holds
	// one, not negated, is read for its script: node's -i and --build-snapshot, with which `node -i -e x app.js` runs
	// app.js and leaves the code unrun (probed on 20.19.4). Node reads them after the code too, up to the script.
	CodeUnless []string
	// Preload are options whose value is a module the interpreter runs in the same process before its script or code,
	// with the script's arguments: node's -r and --import, so `node -r ./npm-cli.js app.js publish` runs npm publish
	// (probed on 20.19.4), and node's --test-reporter, whose module node imports in the same process when a test runs.
	// Each such module is read as a script the interpreter runs (scriptTools), and, when it starts with `\-`, without
	// the backslash too: node takes a separate value `\-x` as `-x` (src/node_options-inl.h), and a reading does not
	// keep whether a value was attached.
	Preload []string
	// Loaders are options whose value is a module the interpreter runs with no arguments of the script's: node's
	// --loader, whose module runs in node's hooks thread (process.argv holds nothing past the script there, probed).
	// Where one is given, that thread runs the Preload modules too, with no arguments (node's -r, probed).
	Loaders []string
	// Modules maps a module's top-level name to the tool it is (pip3 → pip); any other module is its own name.
	Modules map[string]string
	// Scripts maps an entry script's basename to the tool it is (npm-cli.js → npm); any other script is its
	// basename.
	Scripts map[string]string
	// Extensions are the extensions the interpreter tries on a script or module whose name, as given, names no file:
	// node runs `node ./deploy` as deploy.js when no file deploy exists (Module._findPath, probed on 20.19.4). A script
	// is read by its name and by its name with each of them.
	Extensions []string
}

// Rows is a set of rows, looked up by name.
type Rows struct {
	byName map[string]*Row
	list   []*Row
}

// NewRows builds a row set; each row's levels are prepared for lookups. A name claimed by two rows is a
// programming error and panics.
func NewRows(rows ...*Row) *Rows {
	rs := &Rows{byName: map[string]*Row{}}
	for _, r := range rows {
		r.ready()
		rs.list = append(rs.list, r)
		for _, n := range append([]string{r.Tool}, r.Names...) {
			if o, dup := rs.byName[n]; dup && o != r {
				panic("execmatch: name " + n + " claimed by rows " + o.Tool + " and " + r.Tool)
			}
			rs.byName[n] = r
		}
	}
	return rs
}

// Lookup is the row a basename names, nil when none does.
func (rs *Rows) Lookup(name string) *Row {
	if rs == nil {
		return nil
	}
	if r := rs.byName[name]; r != nil {
		return r
	}
	if NodeName(name) {
		return rs.byName["node"]
	}
	return nil
}

// dispatcherNamed is the Argv0Prefix row a name starts with, nil when there is none.
func (rs *Rows) dispatcherNamed(name string) *Row {
	for _, r := range rs.All() {
		if r.Argv0Prefix && strings.HasPrefix(name, r.Tool) {
			return r
		}
	}
	return nil
}

// All lists the rows in the order NewRows was given them.
func (rs *Rows) All() []*Row {
	if rs == nil {
		return nil
	}
	return rs.list
}

// prepare indexes a level's options and subcommand names, and links its children to it.
func prepare(lv *Level, parent *Level) {
	if lv == nil {
		return
	}
	lv.parent = parent
	lv.byLong = map[string]*Opt{}
	for i := range lv.Opts {
		o := &lv.Opts[i]
		for _, l := range o.Long {
			lv.byLong[l] = o
		}
		for j := 0; j < len(o.Short); j++ {
			if c := o.Short[j]; c < 128 {
				lv.short[c] = o
			}
		}
	}
	lv.names = lv.names[:0]
	for n, c := range lv.Subs {
		lv.names = append(lv.names, n)
		prepare(c, lv)
	}
	if lv.Wild != nil && lv.Wild != lv {
		prepare(lv.Wild, lv)
	}
	for a := range lv.Alias {
		lv.names = append(lv.names, a)
	}
	sort.Strings(lv.names)
}

// long finds a long option by exact name at this level or a persistent one above it.
func (lv *Level) long(name string) *Opt {
	for l := lv; l != nil; l = l.parent {
		if o := l.byLong[name]; o != nil && (l == lv || o.Persistent) {
			return o
		}
	}
	return nil
}

// rewrites reports whether an option read at this level (its own, or a persistent one above it) can make a reading
// unlocatable (Opt.Rewrite); false for nil.
func (lv *Level) rewrites() bool {
	for l := lv; l != nil; l = l.parent {
		for i := range l.Opts {
			if o := &l.Opts[i]; o.Rewrite != nil && (l == lv || o.Persistent) {
				return true
			}
		}
	}
	return false
}

// shortOpt finds a short option at this level or a persistent one above it.
func (lv *Level) shortOpt(c byte) *Opt {
	if c >= 128 {
		return nil
	}
	for l := lv; l != nil; l = l.parent {
		if o := l.short[c]; o != nil && (l == lv || o.Persistent) {
			return o
		}
	}
	return nil
}

// longPrefix resolves a unique prefix of a long name among the options this level reads. ok is false when no option
// or more than one starts with it.
func (lv *Level) longPrefix(p string) (o *Opt, ok bool) {
	for l := lv; l != nil; l = l.parent {
		for name, cand := range l.byLong {
			if l != lv && !cand.Persistent {
				continue
			}
			if strings.HasPrefix(name, p) {
				if o != nil && o != cand {
					return nil, false
				}
				o = cand
			}
		}
	}
	return o, o != nil
}

// sub resolves a subcommand token that is a canonical name or an alias: the names it adds to the path and the level
// it ends at. An alias may name a path ("container rm"), which is walked from this level.
func (lv *Level) sub(tok string) (path []string, child *Level, ok bool) {
	if lv.Fold != nil {
		tok = lv.Fold(tok)
	}
	if c, found := lv.Subs[tok]; found {
		return []string{tok}, c, true
	}
	a, found := lv.Alias[tok]
	if !found {
		return nil, nil, false
	}
	for i := 0; i < 4; i++ { // npm's aliases chain: sit is cit is install-ci-test
		if _, isSub := lv.Subs[a]; isSub {
			break
		}
		next, chained := lv.Alias[a]
		if !chained {
			break
		}
		a = next
	}
	path = strings.Fields(a)
	child = lv
	for i, n := range path {
		next, ok := child.Subs[n]
		if !ok {
			return nil, nil, false
		}
		if next == nil && i < len(path)-1 {
			return nil, nil, false
		}
		child = next
	}
	return path, child, true
}

// skip reports whether a word standing where a subcommand would is dropped.
func (lv *Level) skip(tok string) bool {
	return lv.Skip[tok] || lv.SkipPrefix != "" && strings.HasPrefix(tok, lv.SkipPrefix)
}

// prefixes appends to dst every subcommand name or alias a SubPrefix token is a prefix of, one per subcommand they
// resolve to.
func (lv *Level) prefixes(dst []string, tok string) []string {
	if lv.Fold != nil {
		tok = lv.Fold(tok)
	}
	var seen [8]string
	targets := seen[:0]
	i := sort.SearchStrings(lv.names, tok)
	for ; i < len(lv.names) && strings.HasPrefix(lv.names[i], tok); i++ {
		n := lv.names[i]
		target := n
		if a, isAlias := lv.Alias[n]; isAlias {
			target = a
		}
		dup := false
		for _, d := range targets {
			if d == target {
				dup = true
				break
			}
		}
		if !dup {
			targets = append(targets, target)
			dst = append(dst, n)
		}
	}
	return dst
}

// Sub returns a subcommand's level by canonical name, for tests and rows.
func (lv *Level) Sub(name string) *Level { return lv.Subs[name] }

// NodeName recognizes Node's standard and numeric versioned command names.
// Renamed copies remain the identity/copy residual of ADR 0048 R2.
func NodeName(name string) bool {
	if name == "node" || name == "nodejs" {
		return true
	}
	v, ok := strings.CutPrefix(name, "node-")
	if !ok || v == "" {
		return false
	}
	for _, c := range v {
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return v[0] >= '0' && v[0] <= '9'
}
