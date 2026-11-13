// SPDX-License-Identifier: Apache-2.0

package rows

import (
	"strings"

	"github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline"
)

// gitBuiltins are git's built-in commands present in every supported version, 2.39 through 2.51 (the intersection;
// later additions such as backfill, diff-pairs, refs and replay are left out, so the set stays a subset of every
// supported git's own, ADR 0048 (2)). TestGitRowFresh holds the installed git to it.
var gitBuiltins = strings.Fields(`add am annotate apply archive bisect blame branch bugreport bundle cat-file check-attr
check-ignore check-mailmap check-ref-format checkout checkout--worker checkout-index cherry cherry-pick clean clone
column commit commit-graph commit-tree config count-objects credential credential-cache credential-cache--daemon
credential-store describe diagnose diff diff-files diff-index diff-tree difftool fast-export fast-import fetch
fetch-pack fmt-merge-msg for-each-ref for-each-repo format-patch fsck fsck-objects fsmonitor--daemon gc
get-tar-commit-id grep hash-object help hook index-pack init init-db interpret-trailers log ls-files ls-remote
ls-tree mailinfo mailsplit maintenance merge merge-base merge-file merge-index merge-ours merge-recursive
merge-recursive-ours merge-recursive-theirs merge-subtree merge-tree mktag mktree multi-pack-index mv name-rev notes
pack-objects pack-redundant pack-refs patch-id pickaxe prune prune-packed pull push range-diff read-tree rebase
receive-pack reflog remote remote-ext remote-fd repack replace rerere reset restore rev-list rev-parse revert rm
send-pack shortlog show show-branch show-index show-ref sparse-checkout stage stash status stripspace
submodule--helper switch symbolic-ref tag unpack-file unpack-objects update-index update-ref update-server-info
upload-archive upload-archive--writer upload-pack var verify-commit verify-pack verify-tag version whatchanged
worktree write-tree`)

// gitCommon is git's common-command group (command-list.txt's init, worktree, info, history and remote categories)
// in every supported version: 2.51 adds backfill, which is left out.
var gitCommon = strings.Fields(`clone init add mv restore rm bisect diff grep log show status branch commit merge rebase
reset switch tag fetch pull push`)

// gitExternals are the commands git ships as separate programs in its exec-path (git --list-cmds=main minus the
// built-ins): they are subcommands the row knows by name, never autocorrect candidates unless compile lists them.
var gitExternals = strings.Fields(`daemon difftool--helper filter-branch http-backend http-fetch http-push imap-send
instaweb merge-octopus merge-one-file merge-resolve mergetool quiltimport remote-ftp remote-ftps remote-http
remote-https request-pull sh-i18n--envsubst shell submodule subtree web--browse backfill diff-pairs refs replay`)

// Git is the git row, probed against git 2.51.0 (Ubuntu 25.10); its second levels also hold the verbs later gits add,
// through 2.56.0 (the CI runners'). Global options stand only before the subcommand and are exact (git.c
// handle_options: no prefixes, no clusters, `-C.` and `--` are unknown options); each subcommand parses with
// parse-options. git autocorrects an unknown first word in process (the help_unknown_cmd port), runs <cmd> when
// argv[0] is git-<cmd> whatever file it is, and re-executes itself for helpers (the closure, measured with strace -f
// against a local bare repository).
func Git() *execmatch.Row {
	globalSyn := execmatch.Syntax{LongEquals: true, LongSep: true, DashDashUnknown: true}
	sepOnly := func(o execmatch.Opt) execmatch.Opt { o.SepOnly = true; return o }
	asSub := func(o execmatch.Opt, sub string) execmatch.Opt { o.AsSub = sub; return o }
	root := &execmatch.Level{
		Syntax: globalSyn,
		Opts: []execmatch.Opt{
			sepOnly(val("C", "C")),
			sepOnly(val("c", "c")),
			val("config-env", ""),
			val("git-dir", ""),
			val("work-tree", ""),
			val("namespace", ""),
			val("attr-source", ""),
			val("shallow-file", ""),
			opt("exec-path", ""),
			opt("list-cmds", ""),
			flag("html-path", ""), flag("man-path", ""), flag("info-path", ""),
			flag("paginate", "p"), flag("no-pager", "P"),
			flag("no-replace-objects", ""), flag("bare", ""),
			flag("literal-pathspecs", ""), flag("glob-pathspecs", ""), flag("noglob-pathspecs", ""), flag("icase-pathspecs", ""),
			flag("no-optional-locks", ""), flag("no-lazy-fetch", ""), flag("no-advice", ""),
			asSub(flag("help", "h"), "help"),
			asSub(flag("version", "v"), "version"),
		},
		Subs:  map[string]*execmatch.Level{},
		Alias: map[string]string{"stage": "add", "init-db": "init", "fsck-objects": "fsck", "pickaxe": "blame"},
	}
	ps := parseOptions
	for _, n := range gitBuiltins {
		if _, aliased := root.Alias[n]; aliased {
			continue
		}
		root.Subs[n] = leaf(ps, gitCommonOpts()...)
	}
	for _, n := range gitExternals {
		root.Subs[n] = leaf(ps)
	}
	for name, lv := range gitLevels(ps) {
		root.Subs[name] = lv
	}
	return &execmatch.Row{
		Tool:          "git",
		Names:         []string{},
		Version:       "2.51.0",
		Docs:          "git(1), git.c handle_options, parse-options, help.c help_unknown_cmd",
		Source:        execmatch.SourceProbed,
		Dashed:        true,
		Argv0Dispatch: true,
		Autocorrect:   true,
		Root:          root,
		HelperDirs:    []string{"/usr/lib/git-core", "/usr/libexec/git-core"},
		Builtins:      gitBuiltins,
		Common:        gitCommon,
		Closure: map[string][]string{
			// Measured with strace -f, git 2.51.0, against a local bare repository; the remote helpers per transport.
			"fetch":        {"maintenance", "rev-list", "index-pack", "unpack-objects", "fetch-pack", "upload-pack", "remote-http", "remote-https", "remote-ftp", "remote-ftps"},
			"clone":        {"rev-list", "index-pack", "unpack-objects", "fetch-pack", "upload-pack", "pack-objects", "remote-http", "remote-https", "remote-ftp", "remote-ftps"},
			"pull":         {"fetch", "merge", "rebase", "maintenance"},
			"push":         {"pack-objects", "rev-list", "unpack-objects", "index-pack", "for-each-ref", "maintenance", "receive-pack", "send-pack", "remote-http", "remote-https", "remote-ftp", "remote-ftps"},
			"commit":       {"maintenance"},
			"merge":        {"maintenance"},
			"rebase":       {"maintenance"},
			"am":           {"maintenance"},
			"maintenance":  {"gc", "commit-graph", "multi-pack-index", "pack-refs", "prune-packed", "repack"},
			"gc":           {"pack-refs", "reflog expire", "repack", "pack-objects", "prune", "worktree prune", "rerere gc", "commit-graph", "multi-pack-index", "prune-packed"},
			"repack":       {"pack-objects", "prune-packed", "multi-pack-index", "commit-graph"},
			"upload-pack":  {"pack-objects", "rev-list"},
			"receive-pack": {"unpack-objects", "index-pack", "rev-list", "for-each-ref", "maintenance"},
			"send-pack":    {"pack-objects", "rev-list"},
			"fetch-pack":   {"index-pack", "unpack-objects"},
		},
		Residual: "GIT_CONFIG_PARAMETERS and other environment that changes parsing (aliases re-exec and are seen; autocorrection is read)",
		Coverage: map[string]string{
			"git push":         "does not cover send-pack or http-push",
			"git push --force": "does not cover +<ref> refspecs, --force-with-lease, --force-if-includes or --mirror",
			"git reset --hard": "does not cover checkout -f, restore, clean or stash drop",
			"git clean":        "a deny on clean -f also needs -x, -d and their clusters named separately to narrow it",
			"git config set":   "does not cover the option forms (git config user.name x, --add, --replace-all) of git before 2.46",
		},
	}
}

// gitCommonOpts are the options every git subcommand reads.
func gitCommonOpts() []execmatch.Opt {
	return []execmatch.Opt{flag("quiet", "q"), flag("verbose", "v"), flag("help", "h")}
}

// gitLevels are the subcommands whose options or second level the row lists: at least the options people write in
// patterns, each with its value form, from git 2.51.0's documentation, and the verbs added since, from 2.56.0's.
func gitLevels(ps execmatch.Syntax) map[string]*execmatch.Level {
	c := gitCommonOpts
	with := func(opts ...execmatch.Opt) *execmatch.Level { return leaf(ps, append(c(), opts...)...) }
	sub := func(def string, opts []execmatch.Opt, children map[string]*execmatch.Level) *execmatch.Level {
		return &execmatch.Level{Syntax: ps, Opts: append(c(), opts...), Subs: children, Default: def}
	}
	aliased := func(l *execmatch.Level, alias map[string]string) *execmatch.Level { l.Alias = alias; return l }
	remote := []execmatch.Opt{flag("ipv4", "4"), flag("ipv6", "6"), flag("progress", ""), val("upload-pack", ""), val("receive-pack", "", "receive-pack", "exec")}
	return map[string]*execmatch.Level{
		"push": with(append(remote,
			flag("force", "f"), opt("force-with-lease", ""), flag("force-if-includes", ""), flag("mirror", ""),
			flag("delete", "d"), flag("tags", ""), flag("all", "", "all", "branches"), flag("dry-run", "n"),
			flag("set-upstream", "u"), val("repo", ""), val("push-option", "o"), flag("verify", ""), flag("atomic", ""),
			flag("prune", ""), flag("follow-tags", ""), opt("signed", ""), flag("porcelain", ""), flag("thin", ""),
			opt("recurse-submodules", ""))...),
		"fetch": with(append(remote,
			flag("all", ""), flag("prune", "p"), flag("prune-tags", "P"), flag("force", "f"), flag("tags", "t"), flag("no-tags", "n"),
			val("depth", ""), val("deepen", ""), val("shallow-since", ""), val("shallow-exclude", ""), flag("unshallow", ""),
			flag("dry-run", ""), flag("append", "a"), val("jobs", "j"), flag("multiple", ""), val("refmap", ""),
			opt("recurse-submodules", ""), flag("update-head-ok", ""), val("server-option", "o"), val("negotiation-tip", ""),
			flag("atomic", ""), flag("keep", "k"), val("filter", ""))...),
		"pull": with(append(remote,
			opt("rebase", "r"), flag("ff-only", ""), flag("ff", ""), flag("no-ff", ""), flag("squash", ""), flag("commit", ""),
			flag("edit", "e"), flag("autostash", ""), val("strategy", "s"), val("strategy-option", "X"), flag("force", "f"),
			flag("all", ""), flag("tags", "t"), val("depth", ""), flag("unshallow", ""), flag("dry-run", ""), flag("prune", "p"),
			flag("verify", ""), flag("signoff", ""), opt("gpg-sign", "S"))...),
		"clone": with(append(remote,
			flag("bare", ""), flag("mirror", ""), flag("local", "l"), flag("no-hardlinks", ""), flag("shared", "s"),
			val("reference", ""), val("origin", "o"), val("branch", "b"), val("template", ""), val("config", "c"),
			val("depth", ""), val("shallow-since", ""), flag("single-branch", ""), opt("recurse-submodules", ""),
			val("jobs", "j"), val("separate-git-dir", ""), val("filter", ""), flag("no-checkout", "n"), flag("sparse", ""))...),
		"commit": with(flag("all", "a"), flag("amend", ""), val("message", "m"), val("file", "F"),
			val("reuse-message", "C"), val("reedit-message", "c"), val("fixup", ""), val("squash", ""), val("author", ""),
			val("date", ""), flag("no-verify", "n"), flag("allow-empty", ""), flag("allow-empty-message", ""), flag("signoff", "s"),
			opt("gpg-sign", "S"), flag("edit", "e"), flag("patch", "p"), flag("include", "i"), flag("only", "o"),
			flag("dry-run", ""), val("template", "t"), opt("untracked-files", "u"), val("cleanup", ""), flag("reset-author", ""),
			val("trailer", ""), flag("no-edit", "")),
		"reset": with(flag("hard", ""), flag("soft", ""), flag("mixed", ""), flag("keep", ""), flag("merge", ""),
			flag("patch", "p"), opt("recurse-submodules", ""), val("pathspec-from-file", "")),
		"clean": with(flag("force", "f"), flag("d", "d"), flag("x", "x"), flag("X", "X"), flag("dry-run", "n"),
			flag("interactive", "i"), val("exclude", "e")),
		"checkout": with(val("b", "b"), val("B", "B"), flag("force", "f"), val("orphan", ""), flag("detach", ""),
			flag("merge", "m"), flag("ours", ""), flag("theirs", ""), flag("patch", "p"), opt("track", "t"), flag("no-track", ""),
			opt("conflict", ""), opt("recurse-submodules", ""), flag("overlay", ""), val("pathspec-from-file", "")),
		"switch": with(val("create", "c"), val("force-create", "C"), flag("force", "f", "force", "discard-changes"),
			val("orphan", ""), flag("detach", "d"), flag("merge", "m"), opt("track", "t"), flag("guess", "")),
		"restore": with(val("source", "s"), flag("staged", "S"), flag("worktree", "W"), flag("patch", "p"),
			flag("ours", ""), flag("theirs", ""), flag("merge", "m"), flag("overlay", ""), opt("recurse-submodules", "")),
		"branch": with(flag("delete", "d"), flag("D", "D"), flag("force", "f"), flag("move", "m"), flag("M", "M"),
			flag("copy", "c"), flag("C", "C"), flag("all", "a"), flag("remotes", "r"), flag("list", "l"),
			opt("set-upstream-to", "u"), flag("unset-upstream", ""), opt("track", "t"), opt("contains", ""), opt("merged", ""),
			opt("no-merged", ""), val("format", ""), val("sort", ""), opt("color", ""), flag("show-current", ""), opt("edit-description", "")),
		"tag": with(flag("annotate", "a"), flag("sign", "s"), val("local-user", "u"), flag("force", "f"), flag("delete", "d"),
			flag("verify", "v"), opt("list", "l"), val("message", "m"), val("file", "F"), opt("sort", ""), opt("contains", ""),
			val("format", ""), opt("n", "n")),
		"rebase": with(flag("interactive", "i"), val("onto", ""), flag("continue", ""), flag("abort", ""), flag("skip", ""),
			flag("quit", ""), flag("autosquash", ""), flag("autostash", ""), val("exec", "x"), flag("root", ""),
			opt("rebase-merges", "r"), val("strategy", "s"), val("strategy-option", "X"), flag("force-rebase", "f"),
			flag("update-refs", ""), opt("gpg-sign", "S"), flag("signoff", "")),
		"merge": with(flag("commit", ""), flag("no-commit", ""), flag("ff", ""), flag("no-ff", ""), flag("ff-only", ""),
			flag("squash", ""), val("message", "m"), val("file", "F"), val("strategy", "s"), val("strategy-option", "X"),
			flag("abort", ""), flag("continue", ""), flag("quit", ""), flag("edit", "e"), flag("no-edit", ""), flag("autostash", ""),
			flag("allow-unrelated-histories", ""), opt("gpg-sign", "S"), flag("signoff", ""), flag("no-verify", "")),
		"rm": with(flag("force", "f"), flag("cached", ""), flag("r", "r"), flag("dry-run", "n"), flag("ignore-unmatch", "")),
		"mv": with(flag("force", "f"), flag("k", "k"), flag("dry-run", "n")),
		"add": with(flag("all", "A"), flag("update", "u"), flag("force", "f"), flag("patch", "p"), flag("interactive", "i"),
			flag("dry-run", "n"), flag("intent-to-add", "N"), flag("edit", "e"), val("chmod", ""), flag("ignore-errors", ""),
			val("pathspec-from-file", "")),
		"log": with(flag("oneline", ""), opt("pretty", ""), val("format", ""), val("max-count", "n"), flag("patch", "pu"),
			flag("stat", ""), flag("graph", ""), flag("all", ""), val("author", ""), val("committer", ""), val("grep", ""),
			val("since", "", "since", "after"), val("until", "", "until", "before"), opt("decorate", ""), flag("follow", ""),
			flag("name-only", ""), flag("name-status", ""), flag("reverse", ""), opt("abbrev-commit", ""), opt("color", ""),
			flag("no-merges", ""), flag("merges", ""), flag("first-parent", ""), val("skip", ""), opt("date", ""),
			flag("number", "0123456789")), // -<n> is --max-count=<n>: its digits read as one option
		"show": with(flag("oneline", ""), opt("pretty", ""), val("format", ""), flag("stat", ""), flag("name-only", ""),
			flag("name-status", ""), flag("s", "s"), flag("patch", "p"), opt("color", "")),
		"diff": with(flag("cached", "", "cached", "staged"), flag("stat", ""), flag("name-only", ""), flag("name-status", ""),
			flag("patch", "pu"), opt("unified", "U"), flag("exit-code", ""), flag("quiet", ""), flag("no-index", ""),
			opt("color", ""), opt("word-diff", ""), flag("check", ""), opt("diff-filter", ""), val("output", ""), flag("R", "R"),
			flag("ignore-all-space", "w"), flag("ignore-space-change", "b"), flag("no-ext-diff", ""), flag("ext-diff", "")),
		"status": with(flag("short", "s"), flag("branch", "b"), opt("porcelain", ""), flag("long", ""), opt("untracked-files", "u"),
			opt("ignored", ""), opt("ignore-submodules", ""), flag("z", "z"), flag("ahead-behind", ""), opt("column", "")),
		"rev-parse": with(flag("short", ""), flag("abbrev-ref", ""), flag("show-toplevel", ""), flag("git-dir", ""),
			flag("is-inside-work-tree", ""), flag("verify", ""), flag("symbolic-full-name", "")),
		"stash": sub("push", []execmatch.Opt{val("message", "m"), flag("keep-index", "k"), flag("include-untracked", "u"),
			flag("all", "a"), flag("patch", "p"), flag("staged", "S")}, map[string]*execmatch.Level{
			"push": with(val("message", "m"), flag("keep-index", "k"), flag("include-untracked", "u"), flag("all", "a"),
				flag("patch", "p"), flag("staged", "S"), val("pathspec-from-file", "")),
			"save": with(flag("keep-index", "k"), flag("include-untracked", "u"), flag("all", "a"), flag("patch", "p")),
			"pop":  with(flag("index", "")), "apply": with(flag("index", "")), "list": with(), "show": with(flag("patch", "p"), flag("stat", "")),
			"drop": with(), "clear": with(), "branch": with(), "create": with(), "store": with(val("message", "m")),
			"export": with(flag("print", ""), val("to-ref", "")), "import": with(),
		}),
		// git-remote(1) documents "remove, rm": rm is remove's alias (git 2.51 runs `git remote rm`), so a deny or
		// allow entry for `git remote remove` must cover `git remote rm` too.
		"remote": aliased(sub("", nil, map[string]*execmatch.Level{
			"add":    with(val("t", "t"), val("m", "m"), flag("f", "f"), flag("tags", ""), opt("mirror", "")),
			"rename": with(), "remove": with(), "set-head": with(flag("auto", "a"), flag("delete", "d")),
			"set-branches": with(flag("add", "")), "get-url": with(flag("push", ""), flag("all", "")),
			"set-url": with(flag("push", ""), flag("add", ""), flag("delete", "")), "show": with(flag("n", "n")),
			"prune": with(flag("dry-run", "n")), "update": with(flag("prune", "p")),
		}), map[string]string{"rm": "remove"}),
		"worktree": sub("", nil, subs(ps, "add", "list", "lock", "move", "prune", "remove", "repair", "unlock")),
		"submodule": sub("status", nil, subs(ps, "add", "status", "init", "deinit", "update", "set-branch", "set-url",
			"summary", "foreach", "sync", "absorbgitdirs")),
		"notes": sub("list", []execmatch.Opt{val("ref", "")}, subs(ps, "list", "add", "copy", "append", "edit", "show",
			"merge", "remove", "prune", "get-ref")),
		"bisect": sub("", nil, subs(ps, "start", "bad", "new", "good", "old", "terms", "skip", "next", "reset", "visualize", "view",
			"replay", "log", "run", "help")),
		"config": sub("", []execmatch.Opt{flag("global", ""), flag("system", ""), flag("local", ""), flag("worktree", ""),
			val("file", "f"), val("blob", ""), flag("list", "l"), flag("get", ""), flag("get-all", ""), flag("add", ""),
			flag("unset", ""), flag("unset-all", ""), flag("replace-all", ""), flag("edit", "e")},
			subs(ps, "list", "get", "set", "unset", "rename-section", "remove-section", "edit")),
		// Verbs newer than 2.51.0, each a verb of its own and no alias of another: sparse-checkout clean (2.52) removes
		// working-tree files outside the sparse-checkout definition; maintenance is-needed (2.53) only answers by its
		// exit status; reflog write (2.51.1) appends an entry to a ref's reflog through a ref transaction and leaves
		// the ref where it is; hook list (2.54) prints the hooks configured for an event and changes nothing;
		// multi-pack-index compact (2.54) writes a new multi-pack-index layer over a range of the chain's layers into
		// the object directory, and the chain file. Listed, each reads as its own verb whatever the level does with a
		// word it does not know: git before 2.51.1 runs `git reflog write` as reflog's default, show, with write as
		// its first operand.
		"sparse-checkout":  sub("", nil, subs(ps, "list", "set", "add", "reapply", "disable", "init", "check-rules", "clean")),
		"maintenance":      sub("", nil, subs(ps, "run", "start", "stop", "register", "unregister", "is-needed")),
		"bundle":           sub("", nil, subs(ps, "create", "verify", "list-heads", "unbundle")),
		"reflog":           sub("show", nil, subs(ps, "show", "list", "expire", "delete", "exists", "drop", "write")),
		"hook":             sub("", nil, subs(ps, "run", "list")),
		"rerere":           sub("", nil, subs(ps, "clear", "forget", "diff", "remaining", "status", "gc")),
		"commit-graph":     sub("", nil, subs(ps, "write", "verify")),
		"multi-pack-index": sub("", nil, subs(ps, "write", "verify", "expire", "repack", "compact")),
	}
}
