// SPDX-License-Identifier: Apache-2.0

package rows

import "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline"

// Unknown builds retain the master Node grammar at 142497e8742906281a5c517af5b5254b9d6e180a.
// Do not add inventory options here: only an attested build gets those arities.
// The raw pre-scanners are the only additions to this compatibility row.
func fallbackNodeRow() *execmatch.Row {
	nodeSyn := execmatch.Syntax{LongEquals: true, LongSep: true, Negatable: true, Underscores: true}
	node := &execmatch.Row{
		Tool: "node", Names: []string{"nodejs"}, Version: "20.19.4", Source: execmatch.SourceProbed,
		Docs: "node(1), src/node_options-inl.h's parser, src/node_options.cc's options and aliases as its options binding lists them, node --v8-options",
		Root: leaf(nodeSyn, fallbackNodeOpts()...),
		// Under -i or --build-snapshot node runs the script after its options and leaves the code unrun, wherever they
		// stand among the options: `node -i -e x app.js`, `node -e x -i app.js` and `node --build-snapshot -p x app.js`
		// run app.js (probed). Before the script or code it runs each module -r and --import name, with the script's
		// arguments, and each --loader names, with none; and it imports each module --test-reporter names that is not
		// one of its own reporters when a test runs, with the script's arguments too (probed, with --test and with a
		// script that runs a test). It finds a script or a -r module named without its .js (probed).
		Interp: &execmatch.InterpSpec{ArgvRewrite: nodeArgvRewrite, Code: []string{"eval", "print"}, CodeUnless: []string{"interactive", "build-snapshot"},
			Preload: []string{"require", "import", "test-reporter"}, Loaders: []string{"loader"}, Scripts: entryScripts,
			Extensions: []string{".js"}},
	}
	return node
}

func fallbackNodeOpts() []execmatch.Opt {
	opts := []execmatch.Opt{
		// -p and --print are a boolean, and node's alias `--print <arg>` is -pe, --print --eval <arg>: a word after them
		// is -e's code. Followed by an option they take none, and node runs the script after its options (`node -p
		// --title t app.js`, probed).
		val("eval", "e"), nextWord("print", "p", "eval"), flag("check", "c"), flag("interactive", "i"), flag("version", "v"), flag("help", "h"),
		val("require", "r"), val("conditions", "C"), esmModule(val("loader", "", "loader", "experimental-loader")),
		esmModule(val("import", "")), esmModule(val("test-reporter", "")),
		val("inspect-port", "", "inspect-port", "debug-port"), val("report-dir", "", "report-dir", "report-directory"),
		val("security-revert", "", "security-revert", "security-reverts"),
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
	}
	for _, name := range fallbackNodeFlags {
		opts = append(opts, flag(name, ""))
	}
	for _, name := range fallbackNodeValues {
		opts = append(opts, val(name, ""))
	}
	return opts
}

var fallbackNodeFlags = []string{
	// booleans
	"addons", "allow-addons", "allow-child-process", "allow-wasi", "allow-worker", "build-snapshot", "completion-bash",
	"cpu-prof", "debug", "debug-arraybuffer-allocations", "debug-brk", "deprecation", "disable-wasm-trap-handler",
	"enable-fips", "enable-source-maps", "experimental-detect-module", "experimental-eventsource", "experimental-fetch",
	"experimental-global-customevent", "experimental-global-webcrypto", "experimental-import-meta-resolve",
	"experimental-network-imports", "experimental-network-inspection", "experimental-permission",
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
	"perf-prof-unwinding-info", "prof", "stack-trace-limit",
	// V8's common flags beyond node's list
	"allow-natives-syntax", "async-stack-traces", "harmony", "lazy", "maglev", "opt", "predictable", "single-threaded",
	"sparkplug", "stack-size", "trace-deopt", "trace-gc", "trace-opt", "turbofan",
}

var fallbackNodeValues = []string{
	"allow-fs-read", "allow-fs-write", "cpu-prof-dir", "cpu-prof-interval", "cpu-prof-name", "diagnostic-dir",
	"disable-proto", "disable-warning", "dns-result-order", "env-file", "env-file-if-exists",
	"experimental-default-type", "experimental-policy", "heap-prof-dir", "heap-prof-interval", "heap-prof-name",
	"heapsnapshot-near-heap-limit", "heapsnapshot-signal", "icu-data-dir", "input-type", "inspect-publish-uid",
	"max-http-header-size", "network-family-autoselection-attempt-timeout", "openssl-config", "policy-integrity",
	"redirect-warnings", "report-filename", "report-signal", "secure-heap", "secure-heap-min", "snapshot-blob",
	"test-concurrency", "test-name-pattern", "test-reporter-destination", "test-shard", "test-timeout", "title",
	"tls-cipher-list", "tls-keylog", "trace-event-categories", "trace-event-file-pattern", "trace-require-module",
	"unhandled-rejections", "use-largepages", "v8-pool-size", "watch-path",
}
