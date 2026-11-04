// SPDX-License-Identifier: Apache-2.0

package rows

import (
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

// pythonModules maps a module run with -m to the tool it is (ADR 0048 (2), interpretation 5); any other module is
// its own name.
var pythonModules = map[string]string{"pip": "pip", "pip3": "pip", "twine": "twine", "pipx": "pipx", "poetry": "poetry", "uv": "uv"}

// entryScripts maps an entry script's basename to the tool it is: `node /usr/share/nodejs/npm/bin/npm-cli.js publish`
// is `npm publish`. Node finds a script named without its .js too (`node .../npm-cli publish` runs npm-cli.js,
// probed), which the node row reads through its Extensions, so the table names each script once.
var entryScripts = map[string]string{"npm-cli.js": "npm", "npx-cli.js": "npx", "pnpm.cjs": "pnpm", "pnpm.js": "pnpm",
	"yarn.js": "yarn", "yarn.cjs": "yarn"}

// interpreters are the interpreter rows: python (probed 3.13), node (probed 20 and 22), sh, bash and dash (probed), zsh,
// perl and ruby (documented). Each reads its own options up to the script, module or code; dispatch is by the
// module and entry-script tables, else the script's basename. Code given with -c or -e is opaque (R1).
func interpreters() []*execmatch.Row {
	var py []string
	for i := 0; i <= 20; i++ {
		py = append(py, "python3."+strconv.Itoa(i))
	}
	py = append(py, "python3", "python2", "python2.7", "pypy3", "pypy")
	pythonSyn := execmatch.Syntax{Clusters: true, ShortAttach: true, LongEquals: true, LongSep: true}
	stop := func(o execmatch.Opt) execmatch.Opt { o.Stop = true; return o }
	python := &execmatch.Row{
		Tool: "python", Names: py, Version: "3.13.7", Docs: "python(1), Python/getopt.c", Source: execmatch.SourceProbed,
		Root: leaf(pythonSyn,
			stop(val("c", "c")), stop(val("m", "m")), val("W", "W"), val("X", "X"), val("check-hash-based-pycs", ""),
			flag("b", "b"), flag("B", "B"), flag("d", "d"), flag("E", "E"), flag("h", "h?", "help", "help-env", "help-xoptions", "help-all"),
			flag("i", "i"), flag("I", "I"), flag("O", "O"), flag("P", "P"), flag("q", "q"), flag("s", "s"), flag("S", "S"),
			flag("u", "u"), flag("v", "v"), flag("V", "V", "version"), flag("x", "x"), flag("R", "R")),
		Interp: &execmatch.InterpSpec{Module: "m", Code: []string{"c"}, Modules: pythonModules, Scripts: entryScripts},
	}
	// node reads each option as src/node_options-inl.h's OptionsParser::Parse does: `=` splits a value off a `--` option
	// only, `_` in the name is `-` (Underscores), and then --no-<name> is <name> negated: a boolean turns off, a V8
	// option goes to V8, and any other is refused, so --no-<name> takes no value. node expands its aliases on the
	// negated name too, so --no-print reads a word after it as code, as --print does (nextWord). It neither clusters
	// letters (except the exact -pe alias) nor takes a prefix of a name.
	nodeSyn := execmatch.Syntax{LongEquals: true, LongSep: true, Negatable: true, Underscores: true, ClusterWords: []string{"-pe"}}
	node := &execmatch.Row{
		Tool: "node", Names: []string{"nodejs"}, Version: "20.19.4 / 22.21.1", Source: execmatch.SourceProbed,
		Docs: "node(1), src/node_options-inl.h's parser, src/node_options.cc's options and aliases as its options binding lists them, node --v8-options",
		Root: leaf(nodeSyn, nodeOpts()...),
		// Under -i or --build-snapshot node runs the script after its options and leaves the code unrun, wherever they
		// stand among the options: `node -i -e x app.js`, `node -e x -i app.js` and `node --build-snapshot -p x app.js`
		// run app.js (probed). Before the script or code it runs each module -r and --import name, with the script's
		// arguments, and each --loader names, with none; and it imports each module --test-reporter names that is not
		// one of its own reporters when a test runs, with the script's arguments too (probed, with --test and with a
		// script that runs a test). It finds a script or a -r module named without its .js (probed).
		Interp: &execmatch.InterpSpec{Versions: []string{"20.19.4", "22.21.1"}, Fallback: fallbackNodeRow(), ArgvRewrite: nodeArgvRewrite, Code: []string{"eval", "print"}, CodeUnless: []string{"interactive", "build-snapshot"},
			Preload: []string{"require", "import", "test-reporter"}, Loaders: []string{"loader"}, Scripts: entryScripts,
			Extensions: []string{".js"}},
	}
	shSyn := execmatch.Syntax{Clusters: true, LongEquals: true, LongSep: true, PlusOptions: true, DashEnds: true}
	shOpts := func() []execmatch.Opt {
		return []execmatch.Opt{
			flag("c", "c"), flag("s", "s"), val("o", "o"), val("O", "O"), flag("i", "i"), flag("l", "l", "login"),
			flag("r", "r", "restricted"), flag("e", "e"), flag("u", "u"), flag("x", "x"), flag("v", "v", "verbose"),
			flag("n", "n"), flag("f", "f"), flag("a", "a"), flag("b", "b"), flag("h", "h"), flag("k", "k"), flag("m", "m"),
			flag("p", "p"), flag("t", "t"), flag("C", "C"), flag("E", "E"), flag("H", "H"), flag("P", "P"), flag("T", "T"),
			flag("B", "B"), val("rcfile", "", "rcfile", "init-file"), flag("norc", ""), flag("noprofile", ""), flag("posix", ""),
			flag("noediting", ""), flag("version", ""), flag("help", ""), flag("debugger", ""), flag("dump-strings", "D"),
		}
	}
	shell := func(tool string, names []string, src execmatch.Source, version string) *execmatch.Row {
		return &execmatch.Row{
			Tool: tool, Names: names, Version: version, Docs: tool + "(1)", Source: src,
			Root:   leaf(shSyn, shOpts()...),
			Interp: &execmatch.InterpSpec{Code: []string{"c", "s"}, Scripts: entryScripts},
		}
	}
	perl := &execmatch.Row{
		Tool: "perl", Names: []string{"perl5"}, Version: "5", Docs: "perlrun(1)", Source: execmatch.SourceDocumented,
		Root: leaf(execmatch.Syntax{Clusters: true, ShortAttach: true},
			val("e", "e"), val("E", "E"), val("I", "I"), opt("M", "M"), opt("m", "m"), opt("x", "x"), opt("i", "i"),
			opt("0", "0"), opt("C", "C"), opt("d", "d"), opt("D", "D"), val("F", "F"), opt("l", "l"),
			flag("n", "n"), flag("p", "p"), flag("a", "a"), flag("c", "c"), flag("s", "s"), flag("S", "S"), flag("T", "T"),
			flag("t", "t"), flag("u", "u"), flag("U", "U"), flag("v", "v"), flag("V", "V"), flag("w", "w"), flag("W", "W"), flag("X", "X")),
		Interp: &execmatch.InterpSpec{Code: []string{"e", "E"}, Scripts: entryScripts},
	}
	ruby := &execmatch.Row{
		Tool: "ruby", Version: "3", Docs: "ruby(1)", Source: execmatch.SourceDocumented,
		Root: leaf(execmatch.Syntax{Clusters: true, ShortAttach: true, LongEquals: true, LongSep: true},
			val("e", "e"), val("I", "I"), val("r", "r"), val("C", "C"), opt("x", "x"), opt("i", "i"), opt("0", "0"),
			opt("E", "E", "encoding"), opt("W", "W"), opt("enable", ""), opt("disable", ""),
			flag("a", "a"), flag("c", "c"), flag("d", "d", "debug"), flag("l", "l"), flag("n", "n"), flag("p", "p"),
			flag("s", "s"), flag("S", "S"), flag("v", "v", "verbose"), flag("w", "w"), flag("y", "y", "yydebug"),
			flag("version", ""), flag("help", "h")),
		Interp: &execmatch.InterpSpec{Code: []string{"e"}, Scripts: entryScripts},
	}
	return []*execmatch.Row{
		python, node,
		shell("sh", nil, execmatch.SourceProbed, "dash 0.5.12 (as /bin/sh)"),
		shell("bash", []string{"rbash"}, execmatch.SourceProbed, "5.2"),
		shell("dash", nil, execmatch.SourceProbed, "0.5.12"),
		shell("zsh", nil, execmatch.SourceDocumented, "5.9"),
		shell("ksh", []string{"mksh", "ksh93"}, execmatch.SourceDocumented, "93u+m"),
		perl, ruby,
	}
}

// nodeOpts combines the versioned inventories captured by scripts/node-options.py with the
// aliases whose expansions affect dispatch. Arity is Node's, not V8's: a forwarded
// V8 option never consumes Node's next token. See docs/spec/exec-command-rows.md.
func nodeOpts() []execmatch.Opt {
	opts := []execmatch.Opt{
		// -p and --print are a boolean, and node's alias `--print <arg>` is -pe, --print --eval <arg>: a word after them
		// is -e's code. Followed by an option they take none, and node runs the script after its options (`node -p
		// --title t app.js`, probed).
		val("eval", "e"), nextWord("print", "p", "eval"), flag("check", "c"), flag("interactive", "i"), flag("version", "v"), flag("help", "h"),
		val("require", "r"), val("conditions", "C"), esmModule(val("loader", "", "loader", "experimental-loader")),
		esmModule(val("import", "")), esmModule(val("test-reporter", "")),
		val("inspect-port", "", "inspect-port", "debug-port"), val("report-dir", "", "report-dir", "report-directory"),
		val("security-revert", "", "security-revert", "security-reverts"),
		flag("experimental-permission", "", "experimental-permission", "permission"),
		flag("network-family-autoselection", "", "network-family-autoselection", "enable-network-family-autoselection"),
		// The debugger's, which take a host:port only attached (--inspect=9229), through node's aliases.
		opt("inspect", ""), opt("inspect-brk", ""), opt("inspect-brk-node", ""), opt("inspect-wait", ""),
		// A boolean whose alias is {--prof-process, --}: node's options end after it, negated or not, so the token after
		// --no-prof-process is the script whatever it starts with (--prof-process runs V8's log processor on it).
		ends(flag("prof-process", "")),
		// An alias whose expansion is {--trace-event-categories, v8,node,node.async_hooks}: written bare it is a flag, as
		// the inserted value is the categories', and written with =v node takes the categories from v, leaves the
		// inserted token unread, and that token ends its options (execmatch.Opt.EndsAttached).
		endsAttached(flag("trace-events-enabled", "")),
		// Node builds a snapshot from the builder the file names, not from the script on its command line, and leaves the
		// script and -e's code unrun (probed): the script it runs is not in argv, so the row cannot read it.
		unlocatable(val("build-snapshot-config", "")),
		// The same for a single executable's configuration: with "useSnapshot": true node builds the snapshot by running
		// the file's "main" in its own process, whatever argv holds (probed); without it node writes the blob and runs
		// nothing, which the row cannot tell from argv either.
		unlocatable(val("experimental-sea-config", "")),
		// Node 22 reads options/preloads from config, resolves an entry as a URL,
		// or dispatches a package.json command. Their actual targets are not in argv.
		unlocatable(val("experimental-config-file", "")),
		unlocatable(flag("experimental-default-config-file", "")),
		unlocatable(flag("entry-url", "")),
		unlocatable(val("run", "")),
		unlocatable(val("env-file", "")), unlocatable(val("env-file-if-exists", "")),
		// With no process isolation, --test executes multiple operands (or
		// discovered tests) in this process, not just the first entry script.
		{Name: "experimental-test-isolation", Long: []string{"experimental-test-isolation"},
			Arg: execmatch.ArgRequired, Rewrite: func(v string) bool { return v == "none" }},
	}
	for _, name := range nodeFlags {
		opts = append(opts, flag(name, ""))
	}
	for _, name := range nodeV8Flags {
		opts = append(opts, flag(name, ""))
	}
	for _, name := range nodeValues {
		opts = append(opts, val(name, ""))
	}
	return opts
}

// esmModule marks an option whose value node resolves as an ES module specifier, a URL against its working directory
// (--import, --loader, --test-reporter): a reading in which node may resolve the value to another file than the
// basename of its path names is unlocatable (execmatch.Opt.Rewrite, esmUnlocatable), and in a run with command rules
// the exec is refused command-unresolved.
func esmModule(o execmatch.Opt) execmatch.Opt {
	o.Rewrite = esmUnlocatable
	return o
}

// esmUnlocatable reports whether node may resolve the ES module specifier v to a file other than the one the basename
// of its lexically cleaned path names (node 20.19.4's lib/internal/modules/esm/resolve.js, through the WHATWG URL
// parser; each spelling below probed):
//   - the URL parser drops leading and trailing C0 controls and spaces and every tab and newline (`./deplo<LF>y.js` is
//     deploy.js);
//   - a specifier with a scheme is a URL: data: is code, opaque as -e's is (R1), and node: a built-in, so neither names
//     a file; file: and any other scheme are unlocatable;
//   - in a path, `?` starts a query and `#` a fragment, both dropped from the file's name, `%` escapes a byte
//     (`./dep%6Coy.js`, and `%2e%2e` is a `..` segment), and `\` is `/` (`./x/..\deploy.js`): each is unlocatable, as is
//     a specifier starting with `#`, which package.json's imports map.
//
// Any other specifier names its file by its path, `/`, `./` or `../` against the working directory, or else inside a
// package node_modules holds (a bare name), and the row reads it by the basename of that path, as it reads a script.
func esmUnlocatable(v string) bool {
	trimmed := strings.TrimFunc(v, func(r rune) bool { return r <= ' ' })
	stripped := strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, trimmed)
	if scheme, _, ok := strings.Cut(stripped, ":"); ok && urlScheme(scheme) {
		s := strings.ToLower(scheme)
		return s != "data" && s != "node"
	}
	return stripped != v || strings.ContainsAny(v, `?#%\`)
}

// urlScheme reports whether s is a URL scheme as the WHATWG URL parser reads one: an ASCII letter, then ASCII letters,
// digits, '+', '-' and '.'.
func urlScheme(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z':
		case i > 0 && ('0' <= c && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return s != ""
}

// nodeFlags are node's options that take no value: its booleans and no-ops, the V8 options it lists, and V8's common
// flags. A V8 option is a flag here whatever V8's type: node hands it to V8 and leaves the next token alone, and V8
// takes a value only from the options node handed it, never the script, so `node --max-old-space-size --require
// ./x.js -0 app.js` runs app.js with -0 as V8's value.
var nodeFlags = []string{
	// booleans present in 22.21.1 but absent in 20.19.4 (which rejects them)
	"disable-sigusr1", "experimental-addon-modules", "experimental-async-context-frame",
	"experimental-global-navigator", "experimental-inspector-network-resource", "experimental-sqlite",
	"experimental-strip-types", "experimental-transform-types", "experimental-webstorage",
	"experimental-worker-inspection", "report-exclude-env", "test-update-snapshots", "trace-env",
	"trace-env-js-stack", "trace-env-native-stack", "use-env-proxy", "use-system-ca",
	"experimental-test-snapshots",
	// booleans shared with 20.19.4
	"addons", "allow-addons", "allow-child-process", "allow-wasi", "allow-worker", "build-snapshot", "completion-bash",
	"cpu-prof", "debug", "debug-arraybuffer-allocations", "debug-brk", "deprecation", "disable-wasm-trap-handler",
	"enable-fips", "enable-source-maps", "experimental-detect-module", "experimental-eventsource", "experimental-fetch",
	"experimental-global-customevent", "experimental-global-webcrypto", "experimental-import-meta-resolve",
	"experimental-network-imports", "experimental-network-inspection",
	"experimental-print-required-tla", "experimental-repl-await", "experimental-require-module",
	"experimental-shadow-realm", "experimental-test-coverage", "experimental-test-module-mocks",
	"experimental-vm-modules", "experimental-wasm-modules", "experimental-websocket", "expose-internals",
	"extra-info-on-fatal-exception", "force-async-hooks-checks", "force-context-aware", "force-fips",
	"force-node-api-uncaught-exceptions-policy", "frozen-intrinsics", "global-search-paths", "heap-prof",
	"insecure-http-parser", "node-snapshot", "openssl-legacy-provider", "openssl-shared-config", "pending-deprecation",
	"preserve-symlinks", "preserve-symlinks-main", "report-compact", "report-exclude-network",
	"report-on-fatalerror", "report-on-signal", "report-uncaught-exception", "test", "test-force-exit", "test-only",
	"test-udp-no-try-send", "throw-deprecation", "tls-max-v1.2", "tls-max-v1.3", "tls-min-v1.0", "tls-min-v1.1",
	"tls-min-v1.2", "tls-min-v1.3", "trace-atomics-wait", "trace-deprecation", "trace-exit", "trace-promises",
	"trace-sigint", "trace-sync-io", "trace-tls", "trace-uncaught", "trace-warnings", "track-heap-objects",
	"use-bundled-ca", "use-openssl-ca", "v8-options", "verify-base-objects", "warnings", "watch", "watch-preserve-output",
	"zero-fill-buffers",
	// no-ops, each a flag in every node that had it
	"experimental-abortcontroller", "experimental-json-modules", "experimental-modules", "experimental-report",
	"experimental-top-level-await", "experimental-wasi-unstable-preview1", "experimental-worker", "napi-modules",
	"node-memory-debug",
	// V8's, as node lists them
	"abort-on-uncaught-exception", "disallow-code-generation-from-strings", "enable-etw-stack-walking", "expose-gc",
	"harmony-shadow-realm", "huge-max-old-generation-size", "interpreted-frames-native-stack", "jitless",
	"max-old-space-size", "max-semi-space-size", "perf-basic-prof", "perf-basic-prof-only-functions", "perf-prof",
	"perf-prof-unwinding-info", "prof",
}

// nodeValues are node's options that take the next token as their value: the string, list and number options of its
// options binding. Node refuses one followed by a token that starts with '-' ("requires an argument"). Node runs none
// of these values as a module or a script: those it does are listed above, -r, --import, --loader and --test-reporter
// read as modules node runs and --build-snapshot-config and --experimental-sea-config refused (reviewed 2026-11-02
// over every option node 20.19.4's internal modules read with getOptionValue, and the files its snapshot and
// single-executable builders read). A snapshot file can still change what node runs, outside
// argv. Env files are separately refused by the pre-scan, even in script arguments.
// --snapshot-blob can restore code from a previously built snapshot (ADR 0048 R3).
var nodeValues = []string{
	// present in 22.21.1 but absent in 20.19.4
	"localstorage-file", "max-old-space-size-percentage",
	"test-coverage-branches", "test-coverage-exclude", "test-coverage-functions", "test-coverage-include",
	"test-coverage-lines", "test-skip-pattern", "watch-kill-signal",
	"allow-fs-read", "allow-fs-write", "cpu-prof-dir", "cpu-prof-interval", "cpu-prof-name", "diagnostic-dir",
	"disable-proto", "disable-warning", "dns-result-order",
	"experimental-default-type", "experimental-policy", "heap-prof-dir", "heap-prof-interval", "heap-prof-name",
	"heapsnapshot-near-heap-limit", "heapsnapshot-signal", "icu-data-dir", "input-type", "inspect-publish-uid",
	"max-http-header-size", "network-family-autoselection-attempt-timeout", "openssl-config", "policy-integrity",
	"redirect-warnings", "report-filename", "report-signal", "secure-heap", "secure-heap-min", "snapshot-blob",
	"test-concurrency", "test-name-pattern", "test-reporter-destination", "test-shard", "test-timeout", "title",
	"tls-cipher-list", "tls-keylog", "trace-event-categories", "trace-event-file-pattern", "trace-require-module",
	"unhandled-rejections", "use-largepages", "v8-pool-size", "watch-path",
}

// multicall are the multicall dispatchers: busybox and the uutils coreutils binary (probed where installed, both
// here), toybox (documented). Each runs the applet argv[1] names; one called by an applet's name is that applet,
// which the name interpretation already reads. The coreutils row also reads GNU coreutils' single binary (the
// coreutils-single package of Fedora, RHEL and UBI-minimal images), which dispatches on --coreutils-prog=PROG and
// --coreutils-prog-shebang=PROG, and runs PROG when called as lt-PROG (src/coreutils.c, documented: no GNU single
// binary is installed here; uutils 0.2.2 refuses all three, "function/utility not found" and "does not match
// executable name", so reading them adds no reading uutils makes).
func multicall() []*execmatch.Row {
	mc := func(tool, version string, src execmatch.Source) *execmatch.Row {
		return &execmatch.Row{Tool: tool, Version: version, Docs: tool + " --help", Source: src, Multicall: true,
			Root: leaf(execmatch.Syntax{}), Residual: tool + "'s sh runs its applets in process (R1)"}
	}
	coreutils := mc("coreutils", "uutils 0.2.2", execmatch.SourceProbed)
	coreutils.ProgOption, coreutils.Argv0Strip = "coreutils-prog", "lt-"
	coreutils.Docs = "coreutils --help; GNU coreutils src/coreutils.c (--coreutils-prog)"
	busybox := mc("busybox", "1.37.0", execmatch.SourceProbed)
	busybox.Argv0Prefix = true
	toybox := mc("toybox", "0.8", execmatch.SourceDocumented)
	toybox.Argv0Prefix = true // toy_find: the multiplexer's name works as a prefix
	return []*execmatch.Row{busybox, coreutils, toybox}
}

// nodeArgvRewrite mirrors the pre-scanners' reach, not OptionsParser's. Config
// prefixes are read even past -- and stdin; dotenv scanning stops only at --.
// Do not normalize underscores: these scans compare the raw bytes (C49 review).
func nodeArgvRewrite(args []string) bool {
	env := true
	for _, arg := range args {
		if strings.HasPrefix(arg, "--experimental-config-file") || strings.HasPrefix(arg, "--experimental-default-config-file") {
			return true
		}
		if arg == "--" {
			env = false
		}
		if env && strings.HasPrefix(arg, "--env-file") {
			return true
		}
	}
	return false
}
