# Exec command rows

The per-tool table of exec command rules (ADR 0048 (2)). The rows are Go data in `pkg/policy/execmatch/rows`; this
page is their reference description, kept beside the code because rows change with tool releases (R4) and ADR 0048's
text should not. Compile prints, on every command pattern's line, the row that read it, its version, and whether the
row was **probed** (tested against an installed binary of that version) or **documented** (written from the manual
only, R12).

## What a row says

A row is one tool's grammar, as the matcher (`pkg/policy/execmatch`) needs it to find the subcommand in an argv:

- **Names**: the basenames that are the tool (`gnurm` is rm, `npm-cli.js` is npm, `python3.13` is python), whether
  `<tool>-<sub>` names are the tool (`git-push`, `kubectl-foo`, `cargo-clippy`), whether argv[0] picks what it runs
  (git run as `git-<cmd>` runs `<cmd>`; systemctl run as `reboot` reboots), and whether it is a multicall binary
  (busybox, the uutils `coreutils` binary, toybox) or an interpreter (python, node, sh and the other shells, perl,
  ruby).
- **Levels**: the options each level reads, which take a value and how (`-n v`, `-nv`, `-n=v`, `--name v`,
  `--name=v`), whether short options cluster, whether long options take unique prefixes, whether options permute past
  operands, what `--` does, the subcommand names, built-in aliases (an alias may name a path: docker's `rm` is
  `container rm`), whether subcommand names take unique prefixes (npm), and a default subcommand (`git stash` is
  `git stash push`).
- **The helper closure**: for a tool that runs itself, the subcommands it runs for its own work (git only; measured
  with `strace -f` against a local bare repository).
- **Coverage notes and residuals**: what a natural pattern does not cover (`rm -rf` does not cover `rm -r`), and the
  rewriting from outside argv the row does not read (R3).

An option a row does not list is read both ways where a subcommand could still stand, or, on an interpreter row, where
the script could still stand (it may take the next token as its value, or not). A deny or ask entry matches when any
reading matches; a constrained allow entry only when every reading matches. So a missing option can cost an allow
entry its match; it never costs a deny entry one. Past 16 readings an interpreter's dispatch is not read at all and
the exec is refused `command-unresolved`, in a run with command rules. The count runs over bare flags on both sides
of the script: a value reading can take the script itself, that reading still has no script, and the script's own
flags are then read both ways too. So one such option in front of the script with seven bare flags after it reaches
the bound, as do six in front with none after; an `=value` spelling does not count (docs/GAPS.md, C-section row on
interpreter options). The node row reads node's options as node 20.19.4 does, every option and alias of its table and
V8's common flags (see node below), so node reaches the bound only through a spelling the row leaves out: an option a
later node adds, another V8 flag or V8 spelling (`-expose-gc`, `--noexpose-gc`), `-pe`, or one of the three node 20
no-ops. `--trace_exit` is no such spelling: node reads `_` as `-`, and so does the row.

## The rows

| Row | Source | Version | Names and forms | Before the subcommand | Subcommands | Not read (R3) |
|---|---|---|---|---|---|---|
| git | probed | 2.51.0 | `git`; `git-<sub>`; argv[0] `git-<sub>`; the exec-path `git` by identity | exact global options (`-C`, `-c`, `--config-env`, `--git-dir`, `--work-tree`, `--namespace`, `--attr-source` and the flags); `--help` and `--version` are `git help` and `git version`; `--` and unknown options read both ways | built-ins; two levels for stash, remote, worktree, submodule, notes, bisect, config, sparse-checkout, maintenance, bundle, reflog, hook, rerere, commit-graph, multi-pack-index; aliases stage, init-db, fsck-objects, pickaxe, and `git remote rm` for `git remote remove`; autocorrect (the help_unknown_cmd port) | aliases re-exec and are seen; `GIT_CONFIG_PARAMETERS` |
| rm | probed | GNU coreutils 9.5 | `rm`, `gnurm`; busybox, toybox and uutils through dispatch | (none) | (none) | `POSIXLY_CORRECT` |
| npm | probed | 9.2.0 | `npm`, `npm-cli.js` | every config option, anywhere, by its declared type; `--color` takes always, true or false; `--browser` and unlisted options read both ways | cmd-list.js's commands and aliases (alias chains followed), unique prefixes of either, camelCase read as kebab-case; a token that prefixes several names reads as each | `NPM_CONFIG_*`, `.npmrc` |
| npx | probed | 9.2.0 | `npx`, `npx-cli.js` | npm's options | the package is the first operand | as npm |
| go | probed | go1.27.1 | `go` | `-C dir` | build, run, test, install, get, list, vet, generate, clean, env, fmt, doc, fix, bug, version, tool, help; mod, work and telemetry with a second level; Go's flag package stops at the first operand, except `go test`, which reads its flags after the package list too, up to `-args` or `--` | `GOFLAGS` |
| systemctl | probed | systemd 257 | `systemctl`; argv[0] `reboot`, `poweroff`, `halt`; the file being systemctl, an argv[0] that contains one of them (`xrebootx`, systemd's `invoked_as` is strstr) | getopt_long options anywhere around the verb | the verb is the first operand; condrestart, condreload, condstop and force-reload fold onto their verbs | `shutdown(8)` is not covered |
| python | probed | 3.13.7 | `python`, `python3`, `python3.N`, `python2`, `pypy3` | its own options; `-m module` and `-c code` end them | interpreter: `-m` through the module table (pip, pip3 → pip; twine, pipx, poetry, uv), else the first operand's basename | `-c` code (R1) |
| node | probed | 20.19.4 | `node`, `nodejs` | every option and alias of node 20.19.4 by its type, `_` read as `-`, and `--no-<name>`; V8's options as flags; `-e` takes code, and `-p` a word after it; `--prof-process` and `--trace-events-enabled=v` end the options (node, below) | interpreter: entry scripts (npm-cli.js, npx-cli.js, pnpm.cjs, yarn.js), else the script's basename, of its path cleaned and with `.js` too; the modules `-r`, `--import`, `--loader` and `--test-reporter` name, read as scripts, and refused where node reads the module's name as a URL; `--build-snapshot-config` and `--experimental-sea-config` refused | `-e` and `-p` code (R1); `NODE_OPTIONS`, also from an `--env-file` file (node, below) |
| sh, bash, dash | probed | dash 0.5.12, bash 5.2 | `sh`, `bash`, `rbash`, `dash` | clusters, `+o`; a lone `-` ends the options, as `--` does; `-c` and `-s` are opaque | interpreter: the script's basename | `-c` code (R1) |
| zsh, ksh | documented | 5.9, 93u+m | `zsh`, `ksh`, `mksh`, `ksh93` | as sh | as sh | as sh |
| perl, ruby | documented | 5, 3 | `perl`, `perl5`, `ruby` | own options, perl's `-I` with a separate value too; `-e` is code | interpreter: the script's basename | `-e` code (R1) |
| busybox, coreutils | probed (GNU's single binary documented) | 1.37.0, uutils 0.2.2 | multicall | (none) | the applet is argv[1], or argv[0], a leading `-` dropped (`-rm` is rm, read for every exec); an argv[0] starting `busybox` is the dispatcher on any file, also as an applet of itself; for `coreutils` also GNU's single-binary forms: `--coreutils-prog=PROG` (argv[2:]), `--coreutils-prog-shebang=PROG` (argv[3:]; argv[2] is the script) and argv[0] `lt-PROG` | busybox sh runs applets in process (R1) |
| toybox | documented | 0.8 | multicall | (none) | as busybox, an argv[0] starting `toybox` | as busybox |
| pnpm | documented | 9 | `pnpm`, `pnpm.cjs`, `pnpm.js`, `pn` | `-C`, `--filter` and the rest, anywhere | commands and aliases (i, up, rm, ln, ls, t, m, c) | |
| yarn | documented | 1.22 and 4 | `yarn`, `yarn.js`, `yarn.cjs`, `yarnpkg` | `--cwd` and the rest, anywhere | classic's `publish` and berry's `npm publish` both listed | |
| kubectl, oc | documented | 1.33 | `kubectl-<plugin>` | pflag globals anywhere: `-n`, `--context`, `--cluster`, `--user`, `--kubeconfig`, `-s`, `--token`, `--as*`, certificate files, `-v` | the cobra tree, three levels (`create secret generic`) | kuberc aliases |
| docker | documented | 28 | `docker-<plugin>`, the plugin name repeated in argv[1] | `--config`, `-c`, `-H`, `-l`, TLS files; before the command only | management commands; top-level shortcuts folded (`rm` = `container rm` = `container remove`; `rmi` = `image rm`); run, create and exec stop at the image or container | |
| podman | documented | 5 | `podman` | its globals, anywhere | as docker | |
| pip | documented | 25 | `pip`, `pip3`, `pip3.N`, `python -m pip` | optparse globals (`--python`, `--log`, `--proxy`, `--cert`, `--cache-dir` and the rest) | the command list; unique long prefixes, command options interspersed | `PIP_*`, pip.conf |
| cargo | documented | 1.90 | `cargo-<ext>` with the name repeated; a leading `+toolchain` dropped | `--config` (a file or an `alias.` value makes the command unlocatable), `-Z`, `-C`, `--color`, `--explain` | built-ins and aliases b, c, d, t, r, rm | `[alias]`, `CARGO_ALIAS_*` |
| gh | documented | 2.7x | `gh-<ext>` | `-R`, `--hostname` | the cobra tree (`repo delete`, `pr merge`, `release create`, `api`) with its aliases | `gh alias set` |
| terraform, tofu | documented | 1.13 | `terraform`, `tofu` | `-chdir=DIR`, `-help`, `-version` | top level, `state`, `workspace`, `providers`; Go flag options | `apply -destroy` is a destroy |
| helm | documented | 3.18 | `helm` | pflag globals anywhere | the cobra tree; uninstall = un = delete = del | plugins' own commands |
| aws | documented | 2 | `aws` | globals anywhere (`--region`, `--profile`, `--endpoint-url`, `--query`, `--cli-*`) | a service, then an operation (s3's high-level commands are operations) | `~/.aws/cli/alias` |
| gcloud | documented | 5xx | `gcloud` | globals anywhere; `--flags-file` makes the command unlocatable | an optional release track (alpha, beta, preview, dropped), then groups and a command | |
| (any other tool) | generic | | its basename | | | |

## The generic fallback

A tool with no row is read by the generic fallback:

- an **allow** entry is an exact token prefix: its words equal argv[1..k] position by position, each a glob over one
  token. An option before the entry's words means no match.
- a **deny or ask** entry matches anywhere before the first `--`: its non-option words as an ordered subsequence of
  the tokens; a long option as an equal token, one starting with it and `=`, or an abbreviation of it; a one-letter
  short option as `-x`, `-x<value>`, or any single-dash token of letters holding `x`. It over-matches by design:
  `deny: [mytool -r]` refuses `mytool -prefix`.

## git

- **Global options** stand only before the subcommand and are exact: git.c's handle_options takes no prefixes and no
  clusters, `-C.` and `--` are unknown options, and `-C` and `-c` take the next token whatever it is.
  `TestGitRowFresh` runs every spelling of every global option the row lists against the installed git (with a value
  where it takes one) and fails when git answers `unknown option`: git 2.49 removed `--super-prefix`, which the row
  listed as taking a value, so the next word was eaten as that value (dropped 2026-10-16). An option a newer git adds
  and the row lacks is not a failure: an unknown option is read both ways.
- **Two-level commands**: `TestGitRowFresh` reads the verbs the installed git lists for every command the row gives
  a second level (stash, remote, bisect, ...), in `git <cmd> -h` and in parse-options' completion listing (`git
  <cmd> --git-completion-helper-all`: the command's subcommand table, hidden entries such as `git remote rm`
  included), and fails when one is neither a subcommand nor an alias of the row's level; a verb the row has and the
  installed git lacks (another supported version's) is not a failure. A word a level lacks is read as an unknown
  subcommand, matched as written, so a new alias of a verb escapes a rule on that verb until the row lists it (`git
  remote rm`, fixed 2026-10-06). `git bisect next` was missing (added 2026-10-16), and so were three verbs of later
  gits, which the first CI run, on git 2.56.0, named (added 2026-11-02): `git reflog write` (git 2.51.1; appends an
  entry to a ref's reflog and leaves the ref where it is), `git hook list` (2.54; prints the hooks configured for an
  event and changes nothing) and `git multi-pack-index compact` (2.54; writes a new multi-pack-index layer into the
  object directory). `git maintenance -h` names no verb in any supported git, so maintenance's verbs come from the
  completion listing alone, and a command whose usage hides its verbs and whose listing names none fails the test
  rather than going unchecked. `TestGitVerbsRecorded` runs the same reading over recorded output of git 2.51.0 and
  2.56.0.
- **Autocorrect**: a first word that is not a built-in is also read as the built-in git would autocorrect it to under
  `help.autocorrect=immediate`. The port of help_unknown_cmd counts a prefix of a common command as score 0 and
  scores the rest `levenshtein(token, candidate; swap 0, substitution 2, insertion 1, deletion 3) + 1`, and corrects
  only to a unique best candidate below 7. Its candidates are a subset of every supported git's (the built-ins of
  2.39 through 2.51, or compile's listing of the exec-path), so it reaches every target git reaches.
  `TestGitAutocorrectDifferential` holds it to the installed git; `TestGitRowFresh` fails the build when the
  installed git's built-ins or common group stop being supersets of the row's.
- **The helper closure** (allow side only; a deny entry still refuses every member):

  | Allowed | Also admits |
  |---|---|
  | fetch | maintenance (and through it gc, repack, pack-objects, ...), rev-list, index-pack, unpack-objects, fetch-pack, upload-pack, remote-http(s), remote-ftp(s) |
  | clone | rev-list, index-pack, unpack-objects, fetch-pack, upload-pack, pack-objects, the remote helpers |
  | pull | fetch, merge, rebase and their closures |
  | push | pack-objects, rev-list, unpack-objects, index-pack, for-each-ref, maintenance, receive-pack, send-pack, the remote helpers |
  | commit, merge, rebase, am | maintenance |
  | gc | pack-refs, reflog expire, repack, pack-objects, prune, worktree prune, rerere gc, commit-graph, multi-pack-index, prune-packed |
  | maintenance | gc, commit-graph, multi-pack-index, pack-refs, prune-packed, repack |

  `TestGitHelperClosureFresh` reads every git child of push, fetch, pull, commit, gc and repack from GIT_TRACE against
  a local bare repository and fails when one is not in its operation's closure. An operation the closure misses fails
  closed: its helper is refused as unlisted until the row lists it.
- **Layouts**: Debian and Ubuntu keep git's helpers in `/usr/lib/git-core`, RHEL in `/usr/libexec/git-core`. Both
  re-execute a `git` there that is another inode than `/usr/bin/git`.

## node

- **How node reads its options**, as node 20.19.4's OptionsParser::Parse does (src/node_options-inl.h, shipped in
  libnode-dev): up to the first token that is not an option, which is the script, or up to `--`. Only a `--` option
  splits an `=value` off. `_` in an option's name is `-` (`--build_snapshot` is `--build-snapshot`, `--no_print` is
  `--no-print`), and then `--no-<name>` is `<name>` negated. Node expands its aliases next, some of which insert tokens,
  and an option it does not know goes to V8 and takes no token of node's. It neither clusters letters nor takes a
  prefix of a name. The row reads each step as node does (`Syntax.Underscores` and `Negatable`, and the alias forms
  below), and `TestNodeRowTable` holds it to node's own tables: every option of node's options binding with its type,
  every alias by its form, and every spelling of the row's own in node's tables or V8's (`node --v8-options`). Until
  2026-11-02 the row read a `_` spelling as an option it did not list, both ways.
- **Options** are node 20.19.4's own, typed as its options binding types them: a string, list, number or host:port
  option takes the next token or an attached `=value`, and node refuses one followed by a token that starts with `-`
  (`requires an argument`); a boolean or a no-op takes none. Node's plain aliases are spellings of their options
  (`--loader`, `--debug-port`, `--report-directory`, `--security-reverts`, `--enable-network-family-autoselection`,
  and the letters `-e`, `-p`, `-r`, `-C`, `-c`, `-i`, `-h`, `-v`). `--inspect`, `--inspect-brk`, `--inspect-brk-node`
  and `--inspect-wait` take a host:port only attached, through their `--inspect=` aliases (`--inspect-port=v
  --inspect`). `--no-<name>` takes no value: a boolean turns off, a V8 option goes to V8, and any other is refused.
- **Aliases that insert tokens.** `--prof-process` is `{--prof-process, --}`, so node's options end after it, negated
  or not, as after `--`: the row reads the token after it as the script whatever it starts with (`node --no-prof-process
  -x a.js` loads `-x` as its main module, and `node --no-prof-process ./--title t a.js` runs `./--title`, probed), while
  `--prof-process` itself runs V8's log processor on that token. `--trace-events-enabled` is
  `{--trace-event-categories, v8,node,node.async_hooks}`: written bare it is a flag, since the inserted token is the
  categories' value, and written with `=v` node takes the categories from v, leaves the inserted token unread, and that
  token, being no option, ends node's options (`node --trace-events-enabled=v -x a.js` loads `-x`, probed;
  `Opt.EndsAttached`). Until 2026-11-02 the row read node's options on past both. `-pe` is `--print --eval`; the row
  leaves it out, which only over-refuses (the token after it is code, never a script).
- **Code**: `-e` and `--eval` take the next token as code. `-p` and `--print` are a boolean, and node's alias `--print
  <arg>` is `-pe`, `--print --eval <arg>`: a token after them that is not empty and does not start with `-` is `-e`'s
  code, and the row reads it as `-e`'s too (`Opt.WordTo`), so `deny: [node -e *]` refuses `node -p x`. Followed by an
  option or `--` they take none, and node runs the script after its options (`node -p --title t app.js` runs app.js,
  probed). An attached `=value` is no code, as node drops a boolean's (`node --print=v app.js` evaluates `app.js`, and
  `node --print=v --title t app.js` runs it), and `--no-print` reads the same way. Code is opaque (R1): the row reads
  no script past it. Under `-i` (`--interactive`) or `--build-snapshot`, not negated, node runs the script after its
  options and leaves the code unrun, wherever they stand among the options (`node -i -e x app.js`, `node -e x -i
  app.js` and `node --build-snapshot -p x app.js` run app.js, probed), and the row reads that script. A line that holds
  an option the row does not list is read for its script past the code too: that option could be another spelling of
  `-i` or `--build-snapshot`, as `--build_snapshot` was. Until 2026-11-02 the row read `-p` and `--print` as taking code
  always, and read code under `-i` and `--build-snapshot`, so it read no script in `node -p --title t npm-cli.js
  publish` or `node -i -e 1 npm-cli.js publish`, which run npm publish. A staged prefix that ends at `-p`, or at `-e`
  before its code, has not read whether code follows, and one that ends after the code but before the script has not
  read whether `-i` follows: the decision reads the rest of argv.
- **`--build-snapshot-config <file>`** and **`--experimental-sea-config <file>`**: node runs a script the file names,
  not the script on its command line. Under the first it builds a snapshot from the file's builder and leaves the
  script and any code unrun (`node --build-snapshot-config cfg.json -e 0 a.js` runs cfg.json's builder with a.js as its
  argument, probed). Under the second, with `"useSnapshot": true`, it builds a single executable's snapshot by running
  the file's `main` in its own process (`node --experimental-sea-config sea.json` runs it, probed), and without it
  writes the blob and runs nothing. The script that runs is not in argv, so the row cannot read it: in a run with
  command rules the exec is refused `command-unresolved` (`Opt.Rewrite`), which refuses a single executable's build
  there too. Node refuses both in `NODE_OPTIONS`. Until 2026-11-02 the row read a.js as the script under the first, and
  the file or no script under the second.
- **V8's options are flags**, whatever V8's type: node hands an option of V8's to V8 and leaves the next token alone,
  and V8 takes a value only from the options node handed it, never the script. So `node --max-old-space-size --require
  ./x.js -0 app.js` runs app.js with -0 as V8's value. Until 2026-11-02 the row read `--max-old-space-size` and
  `--stack-size` as taking the next token, which read x.js as the script there. The row lists the V8 options node lists
  and V8's common flags (`--allow-natives-syntax`, `--trace-gc`, `--no-opt` and the rest).
- **Left out**, and so read both ways: `--experimental-specifier-resolution`, its alias
  `--es-module-specifier-resolution`, and `--http-parser`, no-ops in node 20 that took a value in an older node; `-pe`;
  V8's other flags, and V8's own spellings of its flags (`-expose-gc`, `--noexpose-gc`); and what a later node adds.
  The row is node 20.19.4's: an option whose kind a later node changed would be read as node 20 reads it.
- **Modules before the script.** Node runs each module `-r` (`--require`) or `--import` names before its script or code,
  in the same process, with the script's arguments (the ones past the first operand), and each `--loader` names in its
  hooks thread with none: `node -r /usr/share/nodejs/npm/bin/npm-cli.js app.js publish` and `node
  --require=.../npm-cli.js -e 0 x publish` run npm publish (probed). It imports each module `--test-reporter` names in
  its own process too, with the script's arguments, whenever a test runs: under `--test`, and in a script that runs a
  test with `node:test` (`node --test --test-reporter ./deploy.js` runs deploy.js, probed); node's own reporters (spec,
  tap, dot, junit, lcov) load no module. The row reads each such module as a script node runs, through the entry-script
  table (`InterpSpec.Preload`, `InterpSpec.Loaders`); until 2026-11-02 it read none of them. Given a loader, node runs
  each `-r` module in its hooks thread too, with no arguments (`node -r ./p.js --loader ./h.mjs app.js a` runs p.js with
  `[a]` and with `[]`, probed), and the row reads every preloaded module that way then, `--import`'s and
  `--test-reporter`'s too, which only refuses more. A module's value written `\-x.js` as a separate token is `-x.js` to
  node (its parser's escape of a leading `-`), and the row reads both.
- **Module names as URLs.** `--import`, `--loader` and `--test-reporter` name an ES module specifier, which node reads as
  a URL against its working directory, so the file it runs can differ from the name argv spells: the URL parser drops a
  query (`./deploy.js?x`) and a fragment (`#x`), decodes `%` escapes (`./dep%6Coy.js`, and `%2e%2e` is `..`), reads `\`
  as `/` (`./x/..\deploy.js`), and drops a space or control at either end and every tab and newline; a `file:` URL names
  a path; and a specifier starting with `#` is one package.json's imports map (each run deploy.js, probed). The row
  refuses a line that holds such a spelling `command-unresolved`, in a run with command rules (`Opt.Rewrite`): it
  does not decode URLs. A `data:` URL is code, opaque as `-e`'s is (R1), and `node:` a built-in; neither names a file.
  Any other specifier is a path, read by the basename of its cleaned path as a script is, or a bare package name,
  which node resolves inside node_modules and the row reads by its basename. `-r` is CommonJS and reads its value as a
  path, `?`, `#` and `%` included (`-r ./deploy.js?x` loads no deploy.js, probed).
- **The script's name.** Node resolves its script with `path.resolve`, which cleans the path lexically, so `node
  ./deploy.js/. publish` and `node ./deploy.js/x/.. publish` run deploy.js (probed), and the row reads the basename of
  the cleaned path; a module path's `..` segments are cleaned the same way. For a script, and a `-r` module, named
  without its `.js`, node runs the name with `.js` when no file has the name as written (`node ./deploy publish` and
  `node -r ./deploy app.js` run deploy.js, `node .../npm-cli publish` npm, probed), and the row reads both
  (`InterpSpec.Extensions`). It reads neither `.json`, which runs no code, nor `.node`, a native addon node loads as a
  library (R1). Cleaning changes a name only where the path ends in `.` or `..`, which python and the shells run as a
  directory or not at all, so every interpreter row reads its script that way. Until 2026-11-02 the row read the
  basename as written, so `node ./deploy.js/. publish` was not deploy.js and `node .../npm-cli publish` was not npm.
- **Not read:** `NODE_OPTIONS`, from the environment or from a file `--env-file` (or `--env-file-if-exists`) names,
  which node 20 applies (probed), can name a module node preloads; node refuses `-i`, `-e`, `-p`, `--build-snapshot` and
  `--prof-process` there, so it never changes which script argv names (ADR 0048 R3). A script named through a package's
  metadata is not read either: a directory node runs by its package.json `main` or its index.js, a bare module name
  resolved through a package's `exports`, or a name a loader's resolve hook maps (the loader is code, R1); these are
  R9's named entry points. `--snapshot-blob` without `--build-snapshot` runs the code a snapshot holds, which a `node
  --build-snapshot` line built and the decision read then. Node's other values name data or output (a policy, an OpenSSL
  configuration, which can name a library to load, ICU data, report and profile paths): no option of node 20.19.4's runs
  its value as a module or a script but those above (reviewed 2026-11-02 over every option node's internal modules read
  with getOptionValue, and the files its snapshot and single-executable builders read). docs/GAPS.md A2 covers what an
  allowed interpreter does in-process.
- **Tests.** `TestNodeRowTable` holds the row to node's tables, as above; it fails only under node 20.19.4, the row's
  version, and logs what differs under another. `TestNodeRowReadsWhatNodeLoads` holds the reading of each file node
  loads, above, on lines probed against node, under `-short` too. Four differentials hold the row to what the installed
  node runs, each through scripts that print their name and arguments when node runs them, as its main module, its
  snapshot builder, or a module it loads first: wherever node runs a script, a deny entry naming it must refuse the
  line, the dispatch must give it node's arguments, and no prefix of the line may be settled as anything but refused.
  They run only under node 20.19.4 and skip under another node, as on a CI runner whose node is not pinned: another
  node's table differs (a later node drops options the lines hold). `TestNodeRowSpellingsDifferential` runs every
  spelling of every option the row lists, as written and with `_` for `-`, negated, with an attached value, and as a
  letter, in front of a word and a script, and in front of a script whose name starts with `-`, which node runs only past
  the end of its options; an option that checks its value gets one node accepts, a module option a module (and
  `--test-reporter` `--test`), and a configuration option a file that names a script. `TestNodeRowCodeDifferential`
  runs the code options' forms, alone and with `-i`, `--interactive=1`, `--build_snapshot`, `--no-interactive` and both
  orders of `-i` and `--no-interactive`, before and after the code, in front of `a.js b.js`, `--title t a.js b.js` and
  `-- a.js b.js`, and `--build-snapshot-config` and `--experimental-sea-config`. `TestNodeRowModulesDifferential` runs
  each module option in front of each spelling of a module above (a path, without `.js`, with dot segments, a trailing
  slash, absolute, a `file:` URL, `//localhost`, a query, a fragment, a `%` escape, a backslash, a space or tab, a
  newline, `data:`, `node:`, a bare name, `#`, `\-x.js`) and the script in the spellings of a path.
  `TestNodeRowGeneratedDifferential` runs seeded random lines of one to four units, each a mechanism of node's parser, a
  module spelling or a spelling of a listed option, then a tail; it runs 300 lines by default, and was run over 60,000
  lines and three seeds when the row was written and over 24,000 lines and four seeds on 2026-11-02
  (`TEGO_NODE_DIFF_LINES`, `TEGO_NODE_DIFF_SEED`). Not run: the debugger's options, `--watch`, V8's perf options (they
  write `/tmp/perf-<pid>.map`), `--abort-on-uncaught-exception`, and the options whose value is a file of another
  format (a policy, an OpenSSL configuration) or `--snapshot-blob`'s.

## Adding or changing a row

1. Write the row in `pkg/policy/execmatch/rows` from the tool's manual and `--help`, with its version and the
   documentation it was written from. It is `documented`.
2. Add a test of real invocations to `more_test.go` (or the row's own test file): each pattern that should refuse,
   each near-miss that should not.
3. A row becomes `probed` only with a test that runs the installed binary (skipped where it is absent) and holds the
   row to it, as `TestNpmRowDifferential` and `TestRmRowDifferential` do. A helper closure is added only from a
   measurement.
4. Update this table and the CHANGELOG.
