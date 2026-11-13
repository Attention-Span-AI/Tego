// SPDX-License-Identifier: Apache-2.0

package rows

import (
	"strings"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

// more are the rows after git, rm, the interpreters and the multicall binaries, in ADR 0048's landing order: npm and
// npx, go and systemctl (probed against the installed binaries), then the rows written from the manuals only.
func more() []*execmatch.Row {
	return []*execmatch.Row{
		Npm(), Npx(), Go(), Systemctl(),
		pnpm(), yarn(), kubectl("kubectl"), kubectl("oc"), docker(), podman(), pip(), cargo(), gh(), terraform("terraform"),
		terraform("tofu"), helm(), aws(), gcloud(),
	}
}

// Syntaxes of the rows below.
var (
	// goFlag is Go's flag package: -name and --name alike, =value or a separate value, no clusters, stop at the
	// first operand.
	goFlag = execmatch.Syntax{NextOption: execmatch.NextOptionValue, BundleValuesSettle: true, SingleDashLong: true, LongEquals: true, LongSep: true}
	// pflag is spf13/pflag under cobra: bool clusters, -n=v and -nv, --name=v and --name v, no prefixes,
	// interspersed options.
	pflag = execmatch.Syntax{NextOption: execmatch.NextOptionValue, Clusters: true, ShortAttach: true, ShortEquals: true, LongEquals: true, LongSep: true, Permute: true}
	// findRoot is cobra Find at the verified built-in root: stripFlags stops command search at --.
	findRoot = execmatch.Syntax{NextOption: execmatch.NextOptionValue, Clusters: true, ShortAttach: true, ShortEquals: true, LongEquals: true, LongSep: true, Permute: true, Terminator: execmatch.TerminatorOperands}
	// nopt is npm's option parser: options anywhere, read by their declared types, unique long prefixes, shorthand
	// words (-ws), a flag may take true or false.
	nopt = execmatch.Syntax{NextOption: execmatch.NextOptionNoptValue, Clusters: true, BundleValuesSettle: true, ShortAttach: true, LongEquals: true, LongSep: true, LongPrefix: true, Permute: true, ShortWords: true, BoolValues: true, Terminator: execmatch.TerminatorCommand, AllDashTerminator: true, SplitEquals: true, TrimOptionDashes: true, NoptShorthands: true}
	// clap is clap 4 (cargo): --name=v and --name v, -nv, bool clusters, options interspersed until `--`.
	clap = execmatch.Syntax{Clusters: true, BundleValuesSettle: true, ShortAttach: true, LongEquals: true, LongSep: true, Permute: true}
	// optparse is Python's optparse (pip): getopt_long's spellings with unique prefixes, interspersed.
	optparse = execmatch.Syntax{NextOption: execmatch.NextOptionValue, Clusters: true, BundleValuesSettle: true, ShortAttach: true, LongEquals: true, LongSep: true, LongPrefix: true, Permute: true}
)

// persistent marks options read at every level below the one that declares them.
func persistent(opts ...execmatch.Opt) []execmatch.Opt {
	for i := range opts {
		opts[i].Persistent = true
	}
	return opts
}

// maybe is an option that may take the next token: one of values when they are listed, else either reading.
func maybe(name, short string, values ...string) execmatch.Opt {
	o := flag(name, short)
	o.Arg = execmatch.ArgMaybe
	o.Values = values
	return o
}

// npmVals are npm 9.2.0's config options that take a value (its definitions' non-boolean types).
var npmVals = strings.Fields(`_auth access also audit-level auth-type before ca cache cache-max cache-min cafile call cert
ci-name cidr depth diff diff-dst-prefix diff-src-prefix diff-unified editor fetch-retries fetch-retry-factor
fetch-retry-maxtimeout fetch-retry-mintimeout fetch-timeout git globalconfig heading https-proxy include
init-author-email init-author-name init-author-url init-license init-module init-version init.author.email
init.author.name init.author.url init.license init.module init.version install-strategy key local-address location
lockfile-version loglevel logs-dir logs-max maxsockets message node-options noproxy omit only otp package
pack-destination prefix preid proxy registry replace-registry-host save-prefix scope script-shell searchexclude
searchlimit searchopts searchstaleness shell tag tag-version-prefix tmp umask user-agent userconfig viewer which
workspace`)

// npmFlags are npm 9.2.0's boolean config options.
var npmFlags = strings.Fields(`all allow-same-version audit bin-links commit-hooks description dev diff-ignore-all-space
diff-name-only diff-no-prefix diff-text dry-run engine-strict force foreground-scripts format-package-lock fund
git-tag-version global global-style if-present ignore-scripts include-staged include-workspace-root install-links json
legacy-bundling legacy-peer-deps link long offline omit-lockfile-registry-resolved optional package-lock
package-lock-only parseable prefer-offline prefer-online production progress read-only rebuild-bundle save save-bundle
save-dev save-exact save-optional save-peer save-prod shrinkwrap sign-git-commit sign-git-tag strict-peer-deps
strict-ssl timing unicode update-notifier usage version versions workspaces workspaces-update yes`)

// npmString lists exact String types in npm 9.2.0 config definitions, including
// singleton [String] types; [null, String] is deliberately absent (nopt 5.0.0).
func npmString(name string) bool {
	switch name {
	case "call", "diff-dst-prefix", "diff-src-prefix", "editor", "git", "heading", "init-author-email", "init-author-name", "init-license",
		"init.author.email", "init.author.name", "init.license", "message", "pack-destination", "preid", "save-prefix", "scope",
		"searchexclude", "searchopts", "shell", "tag", "tag-version-prefix", "user-agent", "viewer":
		return true
	}
	return false
}

// npmCommands and npmAliases are npm 9.2.0's lib/utils/cmd-list.js.
var npmCommands = strings.Fields(`access adduser audit bugs cache ci completion config dedupe deprecate diff dist-tag docs
doctor edit exec explain explore find-dupes fund get help help-search hook init install install-ci-test install-test
link ll login logout ls org outdated owner pack ping pkg prefix profile prune publish query rebuild repo restart root
run-script search set shrinkwrap star stars start stop team test token uninstall unpublish unstar update version view
whoami`)

var npmAliases = map[string]string{
	"author": "owner", "home": "docs", "issues": "bugs", "info": "view", "show": "view", "find": "search", "add": "install",
	"unlink": "uninstall", "remove": "uninstall", "rm": "uninstall", "r": "uninstall", "un": "uninstall", "rb": "rebuild",
	"list": "ls", "ln": "link", "create": "init", "i": "install", "it": "install-test", "cit": "install-ci-test",
	"up": "update", "c": "config", "s": "search", "se": "search", "tst": "test", "t": "test", "ddp": "dedupe", "v": "view",
	"run": "run-script", "clean-install": "ci", "clean-install-test": "cit", "x": "exec", "why": "explain", "la": "ll",
	"verison": "version", //nolint:misspell // npm's own typo alias (cmd-list.js)
	"ic":      "ci", "innit": "init", "in": "install", "ins": "install", "inst": "install",
	"insta": "install", "instal": "install", "isnt": "install", "isnta": "install", "isntal": "install",
	"isntall": "install", "install-clean": "ci", "isntall-clean": "ci", "hlep": "help", "dist-tags": "dist-tag",
	"upgrade": "update", "udpate": "update", "rum": "run-script", "sit": "cit", "urn": "run-script", "ogr": "org",
	"add-user": "adduser",
}

// npmOpts are npm's options: every config option, read anywhere, with its shorthands.
func npmOpts() []execmatch.Opt {
	var opts []execmatch.Opt
	short := map[string]string{"all": "a", "call": "c", "force": "f", "global": "g", "location": "L", "long": "l", "message": "m",
		"parseable": "p", "prefix": "C", "save": "S", "save-bundle": "B", "save-dev": "D", "save-exact": "E",
		"save-optional": "O", "save-prod": "P", "usage": "?Hh", "version": "v", "workspace": "w", "yes": "y"}
	for _, n := range npmVals {
		o := val(n, short[n])
		// nopt unwraps only a singleton String type before applying its dash
		// guard. Numeric, path and union types still consume option names.
		if npmString(n) {
			o.NextOption = execmatch.NextOptionNopt
		}
		opts = append(opts, o)
	}
	for _, n := range npmFlags {
		opts = append(opts, flag(n, short[n]))
	}
	// Shorthands that are words or that set a value (npm's shorthands table): -d, -q and -s set loglevel.
	opts = append(opts,
		maybe("browser", ""), maybe("color", "", "always", "true", "false"),
		flag("loglevel-info", "d", "dd", "ddd", "verbose"), flag("loglevel-warn", "q", "quiet"),
		flag("loglevel-silent", "s", "silent"), flag("workspaces-short", "", "ws"),
		flag("include-workspace-root-short", "", "iwr"), val("registry-short", "", "reg"),
		flag("description-short", "", "desc"), flag("parseable-short", "", "porcelain"), flag("read-only-short", "", "readonly"),
		flag("no-global", "", "local"), flag("no-yes", "n", "no"), val("before-short", "", "enjoy-by"), flag("usage-short", "", "help"),
	)
	for i := range opts {
		if opts[i].Name == "browser" {
			// npm 9.2.0: [null, Boolean, String]. nopt's Boolean union
			// branch returns before the required-value all-dash guard.
			opts[i].NextOption = execmatch.NextOptionNoptMaybe
		}
	}
	return persistent(opts...)
}

// kebab is npm's deref: a camelCase word is read as kebab-case (runScript is run-script).
func kebab(s string) string {
	if strings.IndexFunc(s, func(r rune) bool { return r >= 'A' && r <= 'Z' }) < 0 {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('-')
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Npm is the npm row, probed against npm 9.2.0 (Ubuntu 25.10): options anywhere, read by their declared types (an
// option the row does not list is read both ways, as npm 9.2 reads it as a flag and another version may not);
// commands and aliases from cmd-list.js, unique prefixes of either, camelCase read as kebab-case. A token that is a
// prefix of several names reads as each of them. npm runs scripts through a shell exec, which the rules see.
// Terminator evidence: npm/cli v9.2.0 lib/cli.js shifts npm.argv; lib/npm.js takes nopt's
// argv.remain. nopt v5.0.0 lib/nopt.js parse accepts /^-{2,}$/ and appends all later
// words to remain. The first still selects the command; later options stay operands.
func Npm() *execmatch.Row {
	root := &execmatch.Level{Syntax: nopt, Opts: npmOpts(), Subs: subs(nopt, npmCommands...), Alias: npmAliases, SubPrefix: true, Fold: kebab}
	return &execmatch.Row{
		Tool: "npm", Names: []string{"npm-cli.js"}, Version: "9.2.0", Docs: "npm(1), lib/utils/cmd-list.js, lib/utils/config/definitions.js",
		Source: execmatch.SourceProbed, Root: root,
		Residual: "NPM_CONFIG_* and .npmrc settings that change parsing are not read",
		Coverage: map[string]string{
			"npm publish": "does not cover npx, pnpm publish, yarn publish or yarn npm publish; a registry write is a net rule's to bound",
		},
	}
}

// Npx is the npx row (npm 9.2.0's npx-cli.js): npm's options, then the package to run and its arguments.
func Npx() *execmatch.Row {
	opts := append(npmOpts(), val("package", ""), flag("no-install", ""), flag("ignore-existing", ""), flag("quiet-npx", "q"))
	for i := range opts {
		// npx rewrites the argv handed to npm; do not infer its complete
		// value binding from npm's type table alone.
		opts[i].NextOption = execmatch.NextOptionBoth
	}
	return &execmatch.Row{
		Tool: "npx", Names: []string{"npx-cli.js"}, Version: "9.2.0", Docs: "npx(1)", Source: execmatch.SourceProbed,
		Root: &execmatch.Level{Syntax: execmatch.Syntax{Clusters: true, ShortAttach: true, LongEquals: true, LongSep: true, LongPrefix: true, ShortWords: true, BoolValues: true},
			Opts: opts},
	}
}

// Go is the go command's row, probed against go 1.27.1: `go <command>`, each command's flags with Go's flag
// package, which stops at the first operand, except go test, whose own parser reads known flags before and after the
// package list (cmd/go/internal/test/testflag.go) up to -args. mod, work and telemetry have a second level.
// Terminator evidence: cmd/go/main.go (go1.25.0, also probed go1.27.1) calls flag.Parse
// before lookupCmd. Go flag removes --; lookupCmd takes the next word as the command,
// whose invoke parses its own flags. Nested mod/work/telemetry lookup is raw, with no
// flag.Parse, and refuses --. The refused spelling retains flag and value readings.
func Go() *execmatch.Row {
	build := []execmatch.Opt{
		val("C", ""), val("o", ""), val("p", ""), val("asmflags", ""), val("buildmode", ""), val("buildvcs", ""),
		val("compiler", ""), val("gccgoflags", ""), val("gcflags", ""), val("installsuffix", ""), val("ldflags", ""),
		val("mod", ""), val("modfile", ""), val("overlay", ""), val("pgo", ""), val("pkgdir", ""), val("tags", ""),
		val("toolexec", ""), val("coverpkg", ""), val("covermode", ""), val("exec", ""),
		flag("a", ""), flag("n", ""), flag("race", ""), flag("msan", ""), flag("asan", ""), flag("v", ""), flag("work", ""),
		flag("x", ""), flag("trimpath", ""), flag("linkshared", ""), flag("cover", ""), flag("modcacherw", ""), flag("json", ""),
	}
	for i := range build {
		if len(build[i].Name) == 1 {
			build[i].Long = []string{build[i].Name}
		}
	}
	test := append(append([]execmatch.Opt{}, build...),
		val("run", ""), val("skip", ""), val("bench", ""), val("benchtime", ""), val("count", ""), val("cpu", ""),
		val("parallel", ""), val("timeout", ""), val("coverprofile", ""), val("cpuprofile", ""), val("memprofile", ""),
		val("blockprofile", ""), val("mutexprofile", ""), val("outputdir", ""), val("fuzz", ""), val("fuzztime", ""),
		val("fuzzminimizetime", ""), val("shuffle", ""), val("list", ""), val("vet", ""),
		flag("short", ""), flag("failfast", ""), flag("benchmem", ""), flag("c", "", "c"), flag("i", "", "i"), flag("fullpath", ""))
	endTestFlags := flag("args", "")
	endTestFlags.Stop = true
	goTest := goFlag
	goTest.Permute = true
	lv := func(opts []execmatch.Opt) *execmatch.Level { return leaf(goFlag, opts...) }
	plain := func(names ...string) map[string]*execmatch.Level { return subs(goFlag, names...) }
	rootFlags := goFlag
	rootFlags.Terminator = execmatch.TerminatorCommandFlags
	rootFlags.TerminatorOptions = execmatch.TerminatorOptionsChild
	nested := goFlag
	nested.Terminator = execmatch.TerminatorUnknown
	root := &execmatch.Level{Syntax: rootFlags, Opts: []execmatch.Opt{flag("help", "", "h", "help"), val("C", "", "C")}, Subs: map[string]*execmatch.Level{
		"build": lv(build), "install": lv(build), "run": lv(build), "test": leaf(goTest, append(test, endTestFlags)...), "vet": lv(build), "list": lv(append(append([]execmatch.Opt{}, build...), val("f", "", "f"), flag("m", "", "m"), flag("u", "", "u"), flag("e", "", "e"), flag("deps", ""), flag("find", ""), flag("export", ""), flag("compiled", ""), flag("retracted", ""), flag("reuse", ""))),
		"get":      lv(append(append([]execmatch.Opt{}, build...), flag("t", "", "t"), flag("u", "", "u"), flag("d", "", "d"))),
		"generate": lv(append(append([]execmatch.Opt{}, build...), val("run", ""), val("skip", ""))),
		"clean":    lv(append(append([]execmatch.Opt{}, build...), flag("cache", ""), flag("testcache", ""), flag("modcache", ""), flag("fuzzcache", ""), flag("i", "", "i"), flag("r", "", "r"))),
		"env":      lv([]execmatch.Opt{flag("json", ""), flag("u", "", "u"), flag("w", "", "w"), flag("changed", "")}),
		"fmt":      lv([]execmatch.Opt{flag("n", "", "n"), flag("x", "", "x"), val("mod", "")}),
		"doc":      lv(nil), "fix": lv(nil), "bug": lv(nil), "version": lv([]execmatch.Opt{flag("m", "", "m"), flag("v", "", "v")}),
		"tool": lv([]execmatch.Opt{flag("n", "", "n"), val("modfile", "")}),
		"help": lv(nil),
		"mod": {Syntax: nested, Subs: map[string]*execmatch.Level{
			"download": lv([]execmatch.Opt{flag("json", ""), flag("x", "", "x"), flag("reuse", "")}), "edit": lv(nil), "graph": lv(nil),
			"init": lv(nil), "tidy": lv([]execmatch.Opt{flag("v", "", "v"), val("go", ""), val("compat", ""), flag("e", "", "e"), flag("diff", "")}),
			"vendor": lv([]execmatch.Opt{flag("v", "", "v"), flag("e", "", "e"), val("o", "", "o")}), "verify": lv(nil), "why": lv(nil),
		}},
		"work":      {Syntax: nested, Subs: plain("edit", "init", "sync", "use", "vendor")},
		"telemetry": {Syntax: nested, Subs: plain("on", "off", "local")},
	}}
	return &execmatch.Row{Tool: "go", Version: "go1.27.1", Docs: "go help", Source: execmatch.SourceProbed, Root: root,
		Residual: "GOFLAGS adds flags from the environment, which the row does not read"}
}

// systemctlVerbs are systemd 257's systemctl verbs.
var systemctlVerbs = strings.Fields(`list-units list-automounts list-paths list-sockets list-timers is-active is-failed status
show cat help list-dependencies start stop reload restart try-restart reload-or-restart try-reload-or-restart isolate
kill clean freeze thaw set-property bind mount-image service-log-level service-log-target reset-failed whoami
list-unit-files enable disable reenable preset preset-all is-enabled mask unmask link revert add-wants add-requires edit
get-default set-default list-machines list-jobs cancel show-environment set-environment unset-environment
import-environment daemon-reload daemon-reexec log-level log-target service-watchdogs is-system-running default rescue
emergency halt poweroff reboot kexec soft-reboot exit switch-root sleep suspend hibernate hybrid-sleep
suspend-then-hibernate`)

// Systemctl is the systemctl row, probed against systemd 257: getopt_long options anywhere around the verb, which is
// the first operand; called as reboot, poweroff or halt it runs that verb.
// Terminator evidence: systemd v257 src/systemctl/systemctl.c parse_argv uses
// getopt_long; dispatch uses argv[optind] (dispatch_verb in src/shared/verbs.c).
// getopt(3) ends option scanning at --; optind still names the verb. Options remain
// ended after that verb. No system-changing probe is needed for this parser fact.
func Systemctl() *execmatch.Row {
	opts := persistent(
		val("type", "t"), val("state", ""), val("property", "p"), val("P", "P"), val("host", "H"), val("machine", "M"),
		val("root", ""), val("image", ""), val("image-policy", ""), val("output", "o"), val("lines", "n"), val("signal", "s"),
		val("kill-whom", ""), val("kill-value", ""), val("job-mode", ""), val("what", ""), val("when", ""), val("timestamp", ""),
		val("message", ""), val("preset-mode", ""), val("boot-loader-menu", ""), val("boot-loader-entry", ""),
		val("reboot-argument", ""), val("drop-in", ""), val("capsule", "C"), opt("legend", ""), opt("check-inhibitors", ""),
		flag("all", "a"), flag("recursive", "r"), flag("reverse", ""), flag("after", ""), flag("before", ""), flag("full", "l"),
		flag("value", ""), flag("show-types", ""), flag("ignore-inhibitors", "i"), flag("dry-run", ""), flag("quiet", "q"),
		flag("no-block", ""), flag("wait", ""), flag("no-wall", ""), flag("no-reload", ""), flag("no-ask-password", ""),
		flag("global", ""), flag("user", ""), flag("system", ""), flag("runtime", ""), flag("force", "f"), flag("now", ""),
		flag("plain", ""), flag("no-pager", ""), flag("no-legend", ""), flag("firmware-setup", ""), flag("show-transaction", "T"),
		flag("mkdir", ""), flag("marked", ""), flag("read-only", ""), flag("help", "h"), flag("version", ""),
	)
	syn := gnu
	syn.Terminator = execmatch.TerminatorCommand
	root := &execmatch.Level{Syntax: syn, Opts: opts, Subs: subs(gnu, systemctlVerbs...),
		Alias: map[string]string{"force-reload": "try-reload-or-restart", "condrestart": "try-restart", "condreload": "try-reload-or-restart", "reload-or-try-restart": "try-reload-or-restart", "condstop": "stop"}}
	return &execmatch.Row{Tool: "systemctl", Version: "systemd 257", Docs: "systemctl(1)", Source: execmatch.SourceProbed, Root: root,
		Argv0Subs: map[string]string{"reboot": "reboot", "poweroff": "poweroff", "halt": "halt"},
		Coverage:  map[string]string{"systemctl reboot": "does not cover shutdown(8), telinit or a kexec"}}
}

// pnpm is the pnpm row, documented from pnpm 9's manual.
// Terminator evidence: pnpm v9.0.0 cli/parse-cli-args/src/index.ts selects the command
// from @pnpm/nopt's argv.remain. Its fork, escapeArgs paths and recursive dispatch
// were not fully established here. Keep both command and default-operand readings.
func pnpm() *execmatch.Row {
	syn := pflag
	syn.NextOption = execmatch.NextOptionBoth // similar spelling does not establish this parser

	opts := persistent(val("dir", "C"), val("filter", "F"), flag("recursive", "r"), flag("workspace-root", "w"), flag("global", "g"),
		val("reporter", ""), flag("silent", "s"), val("loglevel", ""), flag("help", "h"), flag("version", "v"), flag("aggregate-output", ""),
		opt("color", ""), flag("no-color", ""), flag("stream", ""), flag("use-stderr", ""), flag("dev", "D"), flag("prod", "P"),
		flag("save-dev", "D"), flag("save-exact", "E"), flag("save-optional", "O"), flag("frozen-lockfile", ""), flag("force", "f"),
		flag("dry-run", ""), val("tag", ""), val("access", ""), val("otp", ""), flag("no-git-checks", ""))
	return &execmatch.Row{Tool: "pnpm", Names: []string{"pnpm.cjs", "pnpm.js", "pn"}, Version: "9", Docs: "pnpm.io/cli", Source: execmatch.SourceDocumented,
		Root: &execmatch.Level{Syntax: syn, Opts: opts, Subs: subs(syn, strings.Fields(`add install update remove link unlink import rebuild
prune fetch install-test patch patch-commit patch-remove audit list outdated why licenses run test exec dlx create start
publish pack recursive server store root bin setup init deploy doctor config env cat-file cat-index find-hash self-update`)...),
			Alias: map[string]string{"i": "install", "up": "update", "upgrade": "update", "rm": "remove", "uninstall": "remove", "un": "remove",
				"ln": "link", "rb": "rebuild", "it": "install-test", "ls": "list", "t": "test", "m": "recursive", "multi": "recursive", "c": "config"}}}
}

// yarn is the yarn row, documented for classic (1.x) and berry (2+): classic's publish and berry's npm publish are
// both listed.
// Terminator evidence: classic v1.22.22 src/cli/index.js splits argv at -- before
// command selection (commander); Berry uses Clipanion and nested plugin commands.
// The cross-version/nested behavior was not established. Keep both readings.
func yarn() *execmatch.Row {
	syn := pflag
	syn.NextOption = execmatch.NextOptionBoth // similar spelling does not establish this parser

	opts := persistent(val("cwd", ""), flag("verbose", ""), flag("offline", ""), flag("silent", "s"), flag("help", "h"), flag("version", "v"),
		flag("non-interactive", ""), flag("frozen-lockfile", ""), flag("immutable", ""), flag("dev", "D"), flag("exact", "E"),
		flag("peer", "P"), flag("optional", ""), val("tag", ""), val("access", ""), val("otp", ""), flag("json", ""))
	npm := &execmatch.Level{Syntax: syn, Subs: subs(syn, "publish", "login", "logout", "info", "whoami", "audit", "tag")}
	root := &execmatch.Level{Syntax: syn, Opts: opts, Subs: subs(syn, strings.Fields(`add remove install publish run exec dlx
workspace workspaces up upgrade cache config info init link unlink pack why version global login logout outdated
owner tag team unplug patch patch-commit constraints dedupe explain set plugin rebuild node bin stage`)...)}
	root.Subs["npm"] = npm
	return &execmatch.Row{Tool: "yarn", Names: []string{"yarn.js", "yarn.cjs", "yarnpkg"}, Version: "1.22 and 4", Docs: "classic.yarnpkg.com, yarnpkg.com/cli", Source: execmatch.SourceDocumented,
		Root: root, Coverage: map[string]string{"yarn publish": "does not cover yarn npm publish (berry)", "yarn npm publish": "does not cover yarn publish (classic)"}}
}

// kubectl is the kubectl row (and oc's, which shares its grammar), documented from kubectl 1.33: pflag globals
// anywhere, the cobra command tree three levels deep, kubectl-<plugin> dashed names.
// Terminator evidence: kubectl v0.33.0 pkg/cmd/cmd.go and oc release-4.19
// pkg/cli/cli.go use cobra Find at the built-in root. Cobra v1.9.1 command.go
// stripFlags stops command search at --: the root does not select the next word.
// Nested command overrides and plugin dispatch were not established; both readings
// remain at every nested level (the zero Terminator), for kubectl and oc separately.
func kubectl(tool string) *execmatch.Row {
	globals := persistent(val("namespace", "n"), val("context", ""), val("cluster", ""), val("user", ""), val("kubeconfig", ""),
		val("server", "s"), val("token", ""), val("as", ""), val("as-group", ""), val("as-uid", ""), val("certificate-authority", ""),
		val("client-certificate", ""), val("client-key", ""), val("cache-dir", ""), val("request-timeout", ""),
		val("tls-server-name", ""), val("v", "v"), val("vmodule", ""), val("password", ""), val("username", ""), val("profile", ""),
		val("profile-output", ""), val("log-flush-frequency", ""), flag("insecure-skip-tls-verify", ""),
		flag("match-server-version", ""), flag("warnings-as-errors", ""), flag("help", "h"), val("kuberc", ""),
		flag("all-namespaces", "A"), val("filename", "f"), val("selector", "l"), val("output", "o"), flag("all", ""),
		flag("force", ""), val("grace-period", ""), flag("now", ""), opt("cascade", ""), flag("recursive", "R"), opt("dry-run", ""),
		flag("wait", ""), val("container", "c"), flag("stdin", "i"), flag("tty", "t"), val("field-selector", ""))
	l := func(names ...string) *execmatch.Level {
		return &execmatch.Level{Syntax: pflag, Subs: subs(pflag, names...)}
	}
	tree := map[string]*execmatch.Level{
		"create": l("clusterrole", "clusterrolebinding", "configmap", "cronjob", "deployment", "ingress", "job", "namespace",
			"poddisruptionbudget", "priorityclass", "quota", "role", "rolebinding", "secret", "service", "serviceaccount", "token"),
		"rollout":     l("history", "pause", "restart", "resume", "status", "undo"),
		"certificate": l("approve", "deny"),
		"top":         l("node", "pod"),
		"auth":        l("can-i", "reconcile", "whoami"),
		"apply":       l("edit-last-applied", "set-last-applied", "view-last-applied"),
		"config": l("current-context", "delete-cluster", "delete-context", "delete-user", "get-clusters", "get-contexts",
			"get-users", "rename-context", "set", "set-cluster", "set-context", "set-credentials", "unset", "use-context", "view"),
		"plugin": l("list"),
		"set":    l("env", "image", "resources", "selector", "serviceaccount", "subject"),
	}
	tree["create"].Subs["secret"] = l("docker-registry", "generic", "tls")
	tree["create"].Subs["service"] = l("clusterip", "externalname", "loadbalancer", "nodeport")
	for _, n := range strings.Fields(`expose run explain get edit delete scale autoscale cluster-info cordon uncordon drain
taint describe logs attach exec port-forward proxy cp debug events diff patch replace wait kustomize label annotate
completion alpha api-resources api-versions version`) {
		tree[n] = leaf(pflag)
	}
	return &execmatch.Row{Tool: tool, Version: "1.33", Docs: "kubectl(1), kubectl --help", Source: execmatch.SourceDocumented, Dashed: true,
		Root: &execmatch.Level{Syntax: findRoot, Opts: globals, Subs: tree}, Residual: "kuberc aliases (alpha from 1.33) are not read"}
}

// docker is the docker row, documented from docker 28: globals before the command, management commands, top-level
// shortcuts folded onto them (rm is container rm, rmi is image rm), run, create and exec stopping at the image or
// container, docker-<plugin> names with the plugin repeated in argv[1].
// Terminator evidence: docker/cli v28.0.0 cmd/docker/docker.go enables cobra
// TraverseChildren and calls Traverse, unlike Find's stripFlags. Traverse can scan
// -- as a flag taking a value. Plugin/management levels were not all established;
// keep the command, default-operand and unknown-value readings at every level.
func docker() *execmatch.Row {
	globals := []execmatch.Opt{val("config", ""), val("context", "c"), flag("debug", "D"), val("host", "H"), val("log-level", "l"),
		flag("tls", ""), val("tlscacert", ""), val("tlscert", ""), val("tlskey", ""), flag("tlsverify", ""), flag("help", ""), flag("version", "v")}
	return &execmatch.Row{Tool: "docker", Version: "28", Docs: "docker(1)", Source: execmatch.SourceDocumented, Dashed: true, DashedRepeat: true,
		Root: containerTree(globals), Coverage: map[string]string{"docker rm": "does not cover docker container prune or docker system prune"}}
}

// podman is the podman row, documented from podman 5: the same tree with its globals read anywhere.
// Terminator evidence: podman v5.0.0 cmd/podman/root.go enables cobra
// TraverseChildren. The complete nested tree was not established; as for docker,
// retain command, default-operand and unknown-value readings at every level.
func podman() *execmatch.Row {
	globals := persistent(val("connection", "c"), val("url", ""), val("identity", ""), val("root", ""), val("runroot", ""),
		val("storage-driver", ""), val("storage-opt", ""), val("runtime", ""), val("log-level", ""), val("cgroup-manager", ""),
		val("conmon", ""), val("events-backend", ""), val("hooks-dir", ""), val("imagestore", ""), val("network-cmd-path", ""),
		val("network-config-dir", ""), val("module", ""), val("registries-conf", ""), val("ssh", ""), val("tmpdir", ""),
		val("volumepath", ""), val("out", ""), flag("remote", "r"), flag("transient-store", ""), flag("help", "h"), flag("version", "v"))
	return &execmatch.Row{Tool: "podman", Version: "5", Docs: "podman(1)", Source: execmatch.SourceDocumented, Root: containerTree(globals)}
}

// containerTree is docker's and podman's command tree.
func containerTree(globals []execmatch.Opt) *execmatch.Level {
	stop := execmatch.Syntax{Clusters: true, ShortAttach: true, ShortEquals: true, LongEquals: true, LongSep: true}
	runOpts := []execmatch.Opt{val("name", ""), val("env", "e"), val("volume", "v"), val("publish", "p"), val("workdir", "w"),
		val("user", "u"), val("network", ""), val("entrypoint", ""), val("mount", ""), val("label", "l"), val("env-file", ""),
		flag("detach", "d"), flag("interactive", "i"), flag("tty", "t"), flag("rm", ""), flag("privileged", ""), val("cap-add", ""),
		val("cap-drop", ""), val("security-opt", ""), val("device", ""), val("pid", ""), val("ipc", ""), val("platform", "")}
	mgmt := func(names ...string) *execmatch.Level {
		lv := &execmatch.Level{Syntax: pflag, Subs: subs(pflag, names...), Alias: map[string]string{}}
		for _, n := range names {
			switch n {
			case "rm":
				lv.Alias["remove"] = "rm"
			case "ls":
				lv.Alias["list"] = "ls"
				lv.Alias["ps"] = "ls"
			}
		}
		return lv
	}
	container := mgmt("attach", "commit", "cp", "create", "diff", "exec", "export", "inspect", "kill", "logs", "ls", "pause",
		"port", "prune", "rename", "restart", "rm", "run", "start", "stats", "stop", "top", "unpause", "update", "wait")
	for _, n := range []string{"run", "create", "exec"} {
		container.Subs[n] = leaf(stop, runOpts...)
	}
	image := mgmt("build", "history", "import", "inspect", "load", "ls", "prune", "pull", "push", "rm", "save", "tag")
	root := &execmatch.Level{Syntax: pflag, Opts: globals, Subs: map[string]*execmatch.Level{
		"container": container, "image": image,
		"network": mgmt("connect", "create", "disconnect", "inspect", "ls", "prune", "rm"),
		"volume":  mgmt("create", "inspect", "ls", "prune", "rm"),
		"system":  mgmt("df", "events", "info", "prune"),
		"builder": mgmt("build", "prune"), "buildx": mgmt("build", "bake", "create", "ls", "rm", "use", "prune"),
		"compose":  mgmt("up", "down", "build", "run", "exec", "rm", "ps", "logs", "pull", "push", "start", "stop", "restart"),
		"context":  mgmt("create", "export", "import", "inspect", "ls", "rm", "show", "update", "use"),
		"manifest": mgmt("annotate", "create", "inspect", "push", "rm"), "plugin": mgmt("create", "disable", "enable", "inspect", "install", "ls", "push", "rm", "set", "upgrade"),
		"secret": mgmt("create", "inspect", "ls", "rm"), "service": mgmt("create", "inspect", "logs", "ls", "ps", "rm", "rollback", "scale", "update"),
		"stack": mgmt("config", "deploy", "ls", "ps", "rm", "services"), "swarm": mgmt("ca", "init", "join", "join-token", "leave", "unlock", "unlock-key", "update"),
		"node": mgmt("demote", "inspect", "ls", "promote", "ps", "rm", "update"), "config": mgmt("create", "inspect", "ls", "rm"),
		"trust": mgmt("inspect", "revoke", "sign"), "login": leaf(pflag), "logout": leaf(pflag), "search": leaf(pflag),
		"version": leaf(pflag), "info": leaf(pflag), "inspect": leaf(pflag), "events": leaf(pflag),
	}, Alias: map[string]string{}}
	for _, n := range []string{"attach", "commit", "cp", "create", "diff", "exec", "export", "kill", "logs", "pause", "port",
		"rename", "restart", "rm", "run", "start", "stats", "stop", "top", "unpause", "update", "wait"} {
		root.Alias[n] = "container " + n
	}
	root.Alias["ps"] = "container ls"
	for n, t := range map[string]string{"build": "image build", "history": "image history", "images": "image ls", "import": "image import",
		"load": "image load", "pull": "image pull", "push": "image push", "rmi": "image rm", "save": "image save", "tag": "image tag"} {
		root.Alias[n] = t
	}
	return root
}

// pip is the pip row, documented from pip 25: optparse globals before the command, unique long prefixes, command
// options interspersed. python -m pip reaches it through the interpreter row's module table.
// Terminator evidence: pip 25.0 _internal/cli/main_parser.py parse_command uses
// optparse with disable_interspersed_args; parse_args removes -- and args_else[0]
// selects the command. It then removes that word from the ORIGINAL argv, retaining
// -- for the command parser. Thus options after the selected command stay operands.
func pip() *execmatch.Row {
	rootSyn := optparse
	rootSyn.Terminator = execmatch.TerminatorCommand
	globals := persistent(val("python", ""), val("log", ""), val("proxy", ""), val("retries", ""), val("timeout", ""),
		val("exists-action", ""), val("trusted-host", ""), val("cert", ""), val("client-cert", ""), val("cache-dir", ""),
		val("use-feature", ""), val("use-deprecated", ""), val("keyring-provider", ""), val("root-user-action", ""),
		flag("verbose", "v"), flag("quiet", "q"), flag("isolated", ""), flag("require-virtualenv", ""), flag("no-input", ""),
		flag("no-cache-dir", ""), flag("disable-pip-version-check", ""), flag("no-color", ""), flag("debug", ""), flag("help", "h"),
		flag("version", "V"))
	install := leaf(optparse, val("requirement", "r"), val("constraint", "c"), val("editable", "e"), val("target", "t"), val("prefix", ""),
		val("root", ""), val("index-url", "i"), val("extra-index-url", ""), val("find-links", "f"), val("upgrade-strategy", ""),
		flag("user", ""), flag("upgrade", "U"), flag("force-reinstall", ""), flag("no-deps", ""), flag("pre", ""),
		flag("break-system-packages", ""), flag("no-index", ""), flag("dry-run", ""), flag("ignore-installed", "I"))
	tree := subs(optparse, strings.Fields(`download uninstall freeze inspect list show check config search cache index wheel
hash completion debug help lock`)...)
	tree["install"] = install
	tree["uninstall"] = leaf(optparse, flag("yes", "y"), val("requirement", "r"), flag("break-system-packages", ""))
	return &execmatch.Row{Tool: "pip", Names: []string{"pip3", "pip3.10", "pip3.11", "pip3.12", "pip3.13", "pip3.14", "pip2"},
		Version: "25", Docs: "pip.pypa.io/en/stable/cli", Source: execmatch.SourceDocumented, Root: &execmatch.Level{Syntax: rootSyn, Opts: globals, Subs: tree},
		Residual: "PIP_* environment variables and pip.conf are not read"}
}

// cargo is the cargo row, documented from cargo 1.90: clap, built-in aliases, cargo-<ext> with the name repeated, a
// leading +toolchain (rustup) skipped. --config naming a file or an alias makes the command unlocatable.
// Terminator evidence: cargo 0.91.0 (Rust 1.90) src/bin/cargo/cli.rs uses clap and
// external subcommands, then expands aliases and maps back to built-ins. The full
// trailing-argument behavior was not established; keep both readings, including
// default operands. Rustup's +toolchain is already dropped by SkipPrefix.
func cargo() *execmatch.Row {
	config := val("config", "")
	config.Persistent = true
	config.Rewrite = func(v string) bool { return !strings.Contains(v, "=") || strings.HasPrefix(v, "alias.") }
	globals := append([]execmatch.Opt{config}, persistent(val("Z", "Z"), val("directory", "C"), val("color", ""),
		val("explain", ""), flag("verbose", "v"), flag("quiet", "q"), flag("frozen", ""), flag("locked", ""), flag("offline", ""),
		flag("list", ""), flag("version", "V"), flag("help", "h"), val("manifest-path", ""), val("package", "p"),
		flag("release", "r"), val("features", "F"), flag("all-features", ""), flag("workspace", ""), val("target", ""),
		val("jobs", "j"), flag("dry-run", ""), val("registry", ""), val("token", ""), flag("allow-dirty", ""), flag("no-verify", ""))...)
	return &execmatch.Row{Tool: "cargo", Version: "1.90", Docs: "doc.rust-lang.org/cargo/commands", Source: execmatch.SourceDocumented,
		Dashed: true, DashedRepeat: true,
		Root: &execmatch.Level{Syntax: clap, Opts: globals, SkipPrefix: "+", Subs: subs(clap, strings.Fields(`build check clean doc new init
add remove run test bench update search publish install uninstall fetch fix generate-lockfile help info locate-project
login logout metadata owner package pkgid read-manifest report rustc rustdoc tree vendor verify-project version yank`)...),
			Alias: map[string]string{"b": "build", "c": "check", "d": "doc", "t": "test", "r": "run", "rm": "remove"}},
		Residual: "[alias] entries in .cargo/config.toml and CARGO_ALIAS_* are not read"}
}

// gh is the GitHub CLI's row, documented from gh 2.7x: the cobra tree, gh-<ext> dashed names.
// Terminator evidence: cli/cli v2.74.0 pkg/cmd/root/root.go uses cobra Find.
// command.go stripFlags stops at --. Harmless gh 2.103.3 probes refused dispatch
// after root/nested -- and ran version after lone -. Only the built-in root is
// asserted here; all nested levels retain both readings pending a full tree audit.
func gh() *execmatch.Row {
	l := func(names ...string) *execmatch.Level {
		return &execmatch.Level{Syntax: pflag, Subs: subs(pflag, names...)}
	}
	withAlias := func(lv *execmatch.Level, alias map[string]string) *execmatch.Level { lv.Alias = alias; return lv }
	tree := map[string]*execmatch.Level{
		"auth":      l("login", "logout", "refresh", "setup-git", "status", "token", "switch"),
		"repo":      l("archive", "autolink", "clone", "create", "delete", "deploy-key", "edit", "fork", "gitignore", "license", "list", "rename", "set-default", "sync", "unarchive", "view"),
		"pr":        withAlias(l("checkout", "checks", "close", "comment", "create", "diff", "edit", "list", "lock", "merge", "ready", "reopen", "review", "status", "unlock", "update-branch", "view"), map[string]string{"co": "checkout", "new": "create", "ls": "list"}),
		"issue":     withAlias(l("close", "comment", "create", "delete", "develop", "edit", "list", "lock", "pin", "reopen", "status", "transfer", "unlock", "unpin", "view"), map[string]string{"new": "create", "ls": "list"}),
		"release":   withAlias(l("create", "delete", "delete-asset", "download", "edit", "list", "upload", "verify", "verify-asset", "view"), map[string]string{"new": "create", "ls": "list"}),
		"gist":      withAlias(l("clone", "create", "delete", "edit", "list", "rename", "view"), map[string]string{"new": "create", "ls": "list"}),
		"workflow":  withAlias(l("disable", "enable", "list", "run", "view"), map[string]string{"ls": "list"}),
		"run":       withAlias(l("cancel", "delete", "download", "list", "rerun", "view", "watch"), map[string]string{"ls": "list"}),
		"secret":    withAlias(l("delete", "list", "set"), map[string]string{"remove": "delete", "ls": "list"}),
		"variable":  l("delete", "get", "list", "set"),
		"cache":     l("delete", "list"),
		"codespace": l("code", "cp", "create", "delete", "edit", "jupyter", "list", "logs", "ports", "rebuild", "ssh", "stop", "view"),
		"extension": l("browse", "create", "exec", "install", "list", "remove", "search", "upgrade"),
		"label":     l("clone", "create", "delete", "edit", "list"),
		"ruleset":   l("check", "list", "view"),
		"project":   l("close", "copy", "create", "delete", "edit", "field-create", "field-delete", "field-list", "item-add", "item-archive", "item-create", "item-delete", "item-edit", "item-list", "link", "list", "mark-template", "unlink", "view"),
		"alias":     l("delete", "import", "list", "set"),
		"config":    l("clear-cache", "get", "list", "set"),
		"gpg-key":   l("add", "delete", "list"), "ssh-key": l("add", "delete", "list"),
		"org": l("list"), "attestation": l("download", "trusted-root", "verify"), "search": l("code", "commits", "issues", "prs", "repos"),
	}
	for _, n := range []string{"api", "browse", "completion", "status", "help", "version"} {
		tree[n] = leaf(pflag)
	}
	opts := persistent(val("repo", "R"), val("hostname", ""), flag("help", "h"), val("jq", "q"), val("template", "t"), val("json", ""), flag("yes", "y"), flag("web", "w"))
	return &execmatch.Row{Tool: "gh", Version: "2.7x", Docs: "cli.github.com/manual", Source: execmatch.SourceDocumented, Dashed: true,
		Root:     &execmatch.Level{Syntax: findRoot, Opts: opts, Subs: tree, Alias: map[string]string{"cs": "codespace", "ext": "extension", "extensions": "extension", "rs": "ruleset"}},
		Residual: "aliases set with gh alias set are not read"}
}

// terraform is the terraform row (and OpenTofu's), documented from terraform 1.13: -chdir, -help and -version before
// the command, Go flag options after it, state and workspace with a second level.
// Terminator evidence: mitchellh/cli v1.1.5 cli.go processArgs stops at -- before
// choosing a command; leaf options use Go flag. Terraform/OpenTofu dispatcher forks
// and their nested state/workspace/providers paths were not fully established.
// Both readings remain at every level, separately for terraform and tofu.
func terraform(tool string) *execmatch.Row {
	tf := []execmatch.Opt{val("var", ""), val("var-file", ""), val("target", ""), val("replace", ""), val("lock", ""), val("lock-timeout", ""),
		val("input", ""), val("parallelism", ""), val("refresh", ""), val("state", ""), val("state-out", ""), val("backup", ""), val("out", ""),
		flag("auto-approve", ""), flag("destroy", ""), flag("refresh-only", ""), flag("compact-warnings", ""), flag("json", ""), flag("no-color", "")}
	l := func(names ...string) *execmatch.Level {
		return &execmatch.Level{Syntax: goFlag, Subs: subs(goFlag, names...)}
	}
	tree := subs(goFlag, strings.Fields(`init validate plan apply destroy console fmt force-unlock get graph import login logout
metadata output refresh show taint test untaint version`)...)
	for _, n := range []string{"plan", "apply", "destroy", "refresh", "import"} {
		tree[n] = leaf(goFlag, tf...)
	}
	tree["state"] = l("list", "mv", "pull", "push", "replace-provider", "rm", "show", "identities")
	tree["workspace"] = l("delete", "list", "new", "select", "show")
	tree["providers"] = l("lock", "mirror", "schema")
	rootSyntax := goFlag
	rootSyntax.NextOption = execmatch.NextOptionBoth
	return &execmatch.Row{Tool: tool, Version: "1.13", Docs: tool + " -help", Source: execmatch.SourceDocumented,
		Root:     &execmatch.Level{Syntax: rootSyntax, Opts: []execmatch.Opt{val("chdir", ""), flag("help", "", "help", "h"), flag("version", "", "version", "v")}, Subs: tree},
		Coverage: map[string]string{tool + " destroy": "does not cover " + tool + " apply -destroy, which is a destroy"}}
}

// helm is the helm row, documented from helm 3.18: pflag globals anywhere, the cobra tree, uninstall's aliases.
// Terminator evidence: helm v3.18.0 cmd/helm/root.go uses cobra Find; cobra v1.9.1
// stripFlags stops command search at --. The built-in root leaves the word as an
// operand. Nested/plugin behavior was not established; both readings remain there.
func helm() *execmatch.Row {
	globals := persistent(val("kube-context", ""), val("kubeconfig", ""), val("namespace", "n"), val("registry-config", ""),
		val("repository-cache", ""), val("repository-config", ""), val("burst-limit", ""), val("qps", ""), val("kube-apiserver", ""),
		val("kube-as-group", ""), val("kube-as-user", ""), val("kube-ca-file", ""), val("kube-tls-server-name", ""),
		val("kube-token", ""), flag("kube-insecure-skip-tls-verify", ""), flag("debug", ""), flag("help", "h"))
	l := func(names ...string) *execmatch.Level {
		return &execmatch.Level{Syntax: pflag, Subs: subs(pflag, names...)}
	}
	tree := subs(pflag, strings.Fields(`completion create env history install lint list package pull push rollback status
template test uninstall upgrade verify version`)...)
	tree["dependency"] = l("build", "list", "update")
	tree["get"] = l("all", "hooks", "manifest", "metadata", "notes", "values")
	tree["plugin"] = l("install", "list", "uninstall", "update")
	tree["registry"] = l("login", "logout")
	tree["repo"] = l("add", "index", "list", "remove", "update")
	tree["search"] = l("hub", "repo")
	tree["show"] = l("all", "chart", "crds", "readme", "values")
	return &execmatch.Row{Tool: "helm", Version: "3.18", Docs: "helm.sh/docs/helm", Source: execmatch.SourceDocumented,
		Root: &execmatch.Level{Syntax: findRoot, Opts: globals, Subs: tree, Alias: map[string]string{"un": "uninstall", "delete": "uninstall",
			"del": "uninstall", "hist": "history", "ls": "list", "fetch": "pull", "inspect": "show", "dep": "dependency", "dependencies": "dependency"}},
		Residual: "plugins run commands from their own manifests, which are not mapped"}
}

// aws is the AWS CLI's row, documented from aws-cli 2: root globals, then a service and an operation (s3's
// high-level commands are operations too).
// Terminator evidence: aws-cli 2.27.0 awscli/argparser.py MainArgParser declares
// positional command, ServiceArgParser positional operation, using argparse.
// argparse -- ends option parsing and leaves these positional choices available;
// each parser consumes its own marker. Only the main parser declares globals;
// after its marker they are unknown to the service and operation parsers.
func aws() *execmatch.Row {
	globals := persistent(val("region", ""), val("profile", ""), val("output", ""), val("endpoint-url", ""), val("query", ""),
		val("ca-bundle", ""), val("cli-read-timeout", ""), val("cli-connect-timeout", ""), val("cli-binary-format", ""),
		val("color", ""), flag("debug", ""), flag("no-verify-ssl", ""), flag("no-paginate", ""), flag("no-sign-request", ""),
		flag("cli-auto-prompt", ""), flag("no-cli-auto-prompt", ""), flag("no-cli-pager", ""), flag("version", ""),
		flag("recursive", ""), flag("dryrun", ""), flag("force", ""))
	opSyn := gnuExact
	opSyn.NextOption = execmatch.NextOptionArgparse
	op := &execmatch.Level{Syntax: opSyn}
	dispatch := gnuExact
	dispatch.Terminator = execmatch.TerminatorCommandFlags
	dispatch.TerminatorOptions = execmatch.TerminatorOptionsChild
	dispatch.NextOption = execmatch.NextOptionArgparse
	svc := &execmatch.Level{Syntax: dispatch, Subs: map[string]*execmatch.Level{}, Wild: op}
	return &execmatch.Row{Tool: "aws", Version: "2", Docs: "docs.aws.amazon.com/cli", Source: execmatch.SourceDocumented,
		Root:     &execmatch.Level{Syntax: dispatch, Opts: globals, Subs: map[string]*execmatch.Level{}, Wild: svc},
		Residual: "aliases in ~/.aws/cli/alias are not read"}
}

// gnuExact is getopt_long's spellings without prefixes (aws, gcloud: exact option names, anywhere).
var gnuExact = execmatch.Syntax{LongEquals: true, LongSep: true, Permute: true}

// gcloud is the Google Cloud CLI's row, documented from gcloud 5xx: globals anywhere, an optional release track
// (alpha, beta, preview) dropped from the path, then groups and a command; --flags-file makes the command
// unlocatable.
// Terminator evidence: the gcloud reference documents gcloud-wide flags and
// --flags-file, but the full Calliope/argparse group dispatcher was not established
// from an authoritative versioned source. Retain both readings at all four levels.
func gcloud() *execmatch.Row {
	flagsFile := val("flags-file", "")
	flagsFile.Persistent = true
	flagsFile.Rewrite = func(string) bool { return true }
	globals := append([]execmatch.Opt{flagsFile}, persistent(val("project", ""), val("account", ""), val("configuration", ""),
		val("verbosity", ""), val("format", ""), val("billing-project", ""), val("impersonate-service-account", ""),
		val("flatten", ""), val("access-token-file", ""), val("trace-token", ""), flag("quiet", "q"), flag("help", "h"),
		flag("log-http", ""), flag("user-output-enabled", ""), flag("verbosity-debug", ""))...)
	cmd := &execmatch.Level{Syntax: gnuExact}
	g3 := &execmatch.Level{Syntax: gnuExact, Subs: map[string]*execmatch.Level{}, Wild: cmd}
	g2 := &execmatch.Level{Syntax: gnuExact, Subs: map[string]*execmatch.Level{}, Wild: g3}
	g1 := &execmatch.Level{Syntax: gnuExact, Subs: map[string]*execmatch.Level{}, Wild: g2}
	return &execmatch.Row{Tool: "gcloud", Version: "5xx", Docs: "cloud.google.com/sdk/gcloud/reference", Source: execmatch.SourceDocumented,
		Root: &execmatch.Level{Syntax: gnuExact, Opts: globals, Subs: map[string]*execmatch.Level{}, Wild: g1,
			Skip: map[string]bool{"alpha": true, "beta": true, "preview": true}}}
}
