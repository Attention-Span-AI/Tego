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
interpreter options). For exactly pinned builds, the node row inventories Node 20.19.4 and 22.21.1, including
their full canonical V8 option lists (see node below). Only unknown spellings fork: version-dependent `--stack-trace-limit`, three legacy no-op names,
alternate V8 spellings (`-expose-gc`, `--noexpose-gc`), or future option spellings **within an attested build**.
An unknown executable build/version uses the master Node row, including its bounded two-way readings,
plus the universal raw scans below. Unknown attached options retain the documented preload residual.
`--trace_exit` is no such spelling: Node reads `_` as `-`, and so does the row.

On a staged prefix of argv (ADR 0048 (3)) a decision is final only when no later token can change a reading. A
reading is pending, and the decision reads on, while the prefix ends at an option that takes the next token as its
value (python's `-m`, whose value is the module), or while the reading still reads options and a later one could fork
it past 16 readings (sh's `-c`, perl's and ruby's `-e`, before the first operand) or make it unlocatable (cargo's
`--config` and gcloud's `--flags-file`, read after the subcommand too). `--`, a value that ends the options (python's
`-c` and `-m`) and an interpreter's script end that (amended 2026-11-11).

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
| node | probed | 20.19.4, 22.21.1 | `node`, `nodejs`, numeric `node-N` / `node-N.N.N` | exact pinned builds: the versioned union by Node argv arity (conflicts unknown); unknown builds: master row plus universal scans; `_` read as `-`, and `--no-<name>`; all inventoried canonical V8 names as flags; `-e` takes code, and `-p` a word after it; `--prof-process` and `--trace-events-enabled=v` end the options (node, below) | interpreter: entry scripts (npm-cli.js, npx-cli.js, pnpm.cjs, yarn.js), else the script's basename, of its path cleaned and with `.js` too; the modules `-r`, `--import`, `--loader` and `--test-reporter` name, read as scripts, and refused where node reads the module's name as a URL; `--build-snapshot-config`, `--experimental-sea-config` refused on both paths; pinned inventory also refuses `--run`, `--entry-url`, non-isolated tests; raw config/dotenv prefixes refuse on every build | `-e` and `-p` code (R1); `NODE_OPTIONS` from the environment (env-file options refuse; node, below) |
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

The option details below describe the pinned inventory unless a paragraph explicitly discusses the
master compatibility row. Build selection and the universal scans apply as specified below.

`node-22`, `node-20.1` and other numeric versioned names now select this row, on pinned
and unknown builds alike. Master sent those names to the generic fallback: for example,
`node-22 b.js` under `deny: b.js` now refuses where master had no command match;
`node-22 a.js` under `allow: a.js` now matches that allow. Master-equivalence below concerns
the names master recognized as Node (`node` and `nodejs`), not this added name dispatch.

- **How node reads its options**, as Node 20.19.4 and 22.21.1's OptionsParser::Parse do
  (src/node_options-inl.h): up to the first token that is not an option, which is the script, or up to `--`. Only a `--` option
  splits an `=value` off. `_` in an option's name is `-` (`--build_snapshot` is `--build-snapshot`, `--no_print` is
  `--no-print`), and then `--no-<name>` is `<name>` negated. Node expands its aliases next, some of which insert tokens,
  and an option it does not know goes to V8 and takes no token of node's. It neither clusters letters nor takes a
  prefix of a name. The row reads each step as node does (`Syntax.Underscores` and `Negatable`, and the alias forms
  below), and `TestNodeRowTable` holds it to node's own tables: every option of node's options binding with its type,
  every alias by its form, and every spelling of the row's own in node's tables or V8's (`node --v8-options`). Until
  2026-11-02 the row read a `_` spelling as an option it did not list, both ways.
- **Options** are the compatible union of both installed versions, typed as their options bindings type them: a string, list, number or host:port
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
  `Opt.EndsAttached`). Until 2026-11-02 the row read node's options on past both. `-pe` is exactly `--print --eval`;
  `Syntax.ClusterWords` permits that exact cluster without accepting other clusters or attached short values.
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
  `--stack-size` as taking the next token, which read x.js as the script there. The row lists the union of canonical names
  from both binaries' full `--v8-options` output.
  **Exception:** `--stack-trace-limit` is a V8 option in Node 20 but a native integer option in Node 22;
  its bare spelling stays unknown and forks. Node 22 rejects its separate-value spelling at the
  subsequent V8 validation stage; `--stack-trace-limit=N` works in both versions and reads one way.
  **Contract compatibility change:** master accepted `allow: node --stack-trace-limit=5 a.js`;
  it now fails compilation, "row node does not list the option". The conflicting option is
  unknown to the contract grammar, so no predicate for it can be proved. This is distinct from
  CLI dispatch: attached `=N` still reads one way at run time, but a constrained Node allow
  requiring an unlisted option refuses `exec.args[node]`. Bare runtime spellings retain both
  arity readings on pinned builds; the unknown-build row keeps master's flag reading.
- **Left unknown**, and so read both ways: `--experimental-specifier-resolution`, its alias
  `--es-module-specifier-resolution`, and `--http-parser` (legacy no-ops with historical value arities);
  bare `--stack-trace-limit` (a measured arity conflict between 20 and 22); alternate V8 spellings
  (`-expose-gc`, `--noexpose-gc`); and future additions. Past 16 readings the dispatch fails closed,
  including after code: an unknown could override code. Once a reading finds its entry script, every
  subsequent token belongs to that script's **main-parser** argv and cannot fork that reading.
  The pre-scanners below are an exception: a script argument can still load code. Neither `-e`, `-p`, `-c`,
  `-i`, `--test` nor `--watch` is treated as a generic option terminator: Node still reads options up
  to the entry operand. `--` ends options; `-` selects stdin and ends Node's option reading too.
- **Build selection and universal pre-scanners (round 3, 2026-11-03).** Only the two standalone
  Linux x64 executable hashes in `node_builds_generated.go` select the full 20.19.4/22.21.1
  inventory. The supervisor hashes the walk's reopened regular-file descriptor, verifies its
  identity and unchanged size/mtime/ctime, and bounds hashing at 256 MiB. A process-local FIFO
  cache holds at most 64 digests keyed by `(dev, ino, size, mtime, ctime)` (both timestamps
  include nanoseconds). Concurrent misses for a key share one hash outside the cache mutex.
  Hits and waiting callers re-stat their own reopened descriptor before accepting the digest;
  failed or unstable reads are not retained. Stable unrecognized digests are cached too.
  A same-inode rewrite invalidates the entry through ctime even if size and mtime are restored.
  No command rules means no head/attestation request and no hash. Any command rule can name a
  Node entry script, so attestation is not skipped merely because no rule literally names node.
  A cold/evicted/changed file still hashes synchronously in a notification worker; cache churn
  can still consume that bounded work, and no background worker is introduced. A digest miss,
  unreadable/changed file or absent attestation selects **the master Node row**, preserved from
  commit `142497e8742906281a5c517af5b5254b9d6e180a` in `node_fallback.go`, plus the raw scans
  below. Its unknown options retain both readings, bounded at 16; past the bound they fail closed.
  Round 2's unconditional `command-unresolved` on an unknown build is removed: an unknown build
  must not add refusals over master for `node`/`nodejs` except for these scans. In particular ordinary distro Node,
  nvm patch versions, arm64 and Node in a Lima VM keep master's command behavior.
  No process is started to identify a binary; neither reported nor embedded version strings
  select the inventory. This host's small shared-libnode `/usr/bin/node` is unpinned because
  hashing its launcher does not identify its library. Node 18/24/25 are also unknown, regardless
  of the review probes. A hash identifies a build, not every binary reporting that semver.
  Selection is independent for the direct image, each shebang interpreter and a loader program;
  duplicate invocations with different selected rows retain both interpretations. Raw scans run
  before deduplication so every argv[0] is checked without duplicating ordinary shebang scripts.
  Command patterns are compiled against the compatibility row too, preserving its option and
  alias matching. An inventory-only allow predicate that master could not compile stays unproved
  on this path and does not admit an exec. Compile-time facts (`compile --test` and own-command preflight) have no
  attestation and use this same fallback; ordinary Node commands are no longer refused merely
  for that absence. `node`, `nodejs`, and numeric `node-N` / `node-N.N.N` names use the Node row.
  Arbitrarily renamed copies remain ADR 0048 R2. Hashing a descriptor adds no atomic kernel
  check of the content the eventual exec loads: the userspace image/content race remains.

  **On every Node build**, the config-file pre-scanner compares raw prefixes **anywhere in argv**, even after the entry
  script, `--`, or stdin `-`: any token, **including argv[0]**, starting with `--experimental-config-file` or
  `--experimental-default-config-file` makes the dispatch unlocatable. The separate value and
  attached/prefix spellings all refuse. Underscores are not normalized by this scan. Node's
  dotenv scan reaches past the entry script and stdin but stops at `--`; any raw `--env-file*`
  token before that boundary refuses, including `--env-file-if-exists`. Their files can inject
  `NODE_OPTIONS` preloads. All Node argv must therefore be read before settling an allow; an
  unreadable suffix or a vector past the existing bound refuses `args-unreadable`. Ordinary
  script flags continue to belong to the script and do not consume the ambiguity budget.
- **Node 22 dispatch changes (pinned inventory).** `--permission` aliases the same boolean as Node 20's
  `--experimental-permission`. New options with compatible arities are included even when absent in
  the other version, which rejects them. `--entry-url` makes entry resolution URL-based, and
  `--experimental-config-file` / `--experimental-default-config-file` can inject preloads from a file.
  They are unlocatable and refused `command-unresolved`, even when no explicit script follows.
  `--run` takes a package.json command name, not an entry-script path; it too fails closed rather
  than pretending its value or next operand is the code that runs. `--experimental-test-isolation=none`
  is refused too: with `--test`, it executes multiple operands or discovered tests in the current
  process, outside the single-entry-script model. The `process` value keeps normal dispatch.
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
- **Residuals, including unknown builds:** `NODE_OPTIONS` from the environment (raw env-file options
  before the first `--` are refused on every build),
  which node 20 applies (probed), can name a module node preloads; node refuses `-i`, `-e`, `-p`, `--build-snapshot` and
  `--prof-process` there, so it never changes which script argv names (ADR 0048 R3).
  **Unknown builds also retain master's option-semantics residual:** an unknown attached `=value`
  does not fork or identify a module loaded in process. On Node 24/25,
  `node --test --test-global-setup=./b.js ./a.js` can load denied B in the parent process while
  the resolver names and allows A. `node --test --test-isolation=none ./a.js ./b.js` can similarly
  run both scripts in the parent while only A is identified. These are deliberately still open
  for unknown builds; the bounded arity fallback does not establish future options' semantics.
  This also includes inventory-only features absent from master, such as Node 22's
  `--experimental-test-isolation=none`, when that build is unpinned.
  A script named through a package's metadata is not read either: a directory node runs by its package.json `main` or its index.js, a bare module name
  resolved through a package's `exports`, or a name a loader's resolve hook maps (the loader is code, R1); these are
  R9's named entry points. `--snapshot-blob` without `--build-snapshot` runs the code a snapshot holds, which a `node
  --build-snapshot` line built and the decision read then. Node's other values name data or output (a policy, an OpenSSL
  configuration, which can name a library to load, ICU data, report and profile paths): no option of node 20.19.4's runs
  its value as a module or a script but those above (reviewed 2026-11-02 over every option node's internal modules read
  with getOptionValue, and the files its snapshot and single-executable builders read). docs/GAPS.md A2 covers what an
  allowed interpreter does in-process.
- **Inventory and proof (2026-11-03).** `scripts/node-options.py NODE20 NODE22` captures the installed
  official standalone v20.19.4 and v22.21.1 Linux x64 binaries' `--help`, `--v8-options`,
  `node -p 'JSON.stringify([...process.allowedNodeEnvironmentFlags].sort())'`, and the typed
  `internalBinding('options').getCLIOptionsInfo()` options/aliases under `--expose-internals`.
  The snapshots are `pkg/policy/execmatch/rows/testdata/node-v*.json`; `--check` reproduces them and
  `node_v8_generated.go` and `node_builds_generated.go` byte for byte. Shared-libnode launchers are
  rejected as pin inputs. Only these exact captured executable hashes select the expanded inventory;
  it never invokes Node or trusts a reported version. The standalone builds are from Node's official
  [20.19.4 distribution](https://nodejs.org/download/release/v20.19.4/) and
  [22.21.1 distribution](https://nodejs.org/download/release/v22.21.1/). Their **bin/node** SHA-256
  digests (not the archive digests) are:

  | Version / build | Executable SHA-256 |
  | --- | --- |
  | 20.19.4 Linux x64 | `43d6cf63f2a460b463eba6b19df5e9a259771c56f11b5130e04178a15bb99490` |
  | 22.21.1 Linux x64 | `92181daccf61361e7c54d6404a3e2c2307a916d076492e3c0b388e6e5f86a854` |

  Arity references are the [20.19.4 CLI](https://nodejs.org/download/release/v20.19.4/docs/api/cli.html),
  [22.21.1 CLI](https://nodejs.org/download/release/v22.21.1/docs/api/cli.html), and their
  [20 parser](https://github.com/nodejs/node/blob/v20.19.4/src/node_options-inl.h) /
  [22 parser](https://github.com/nodejs/node/blob/v22.21.1/src/node_options-inl.h) for hidden aliases,
  V8 forwarding and underscore/negation semantics. Inspector optional values are proved by the
  `[=[host:]port]` syntax and the `--inspect*=` aliases: bare inspector options never consume a separate value.
  The raw pre-scanner exceptions are implemented in Node 22's
  [node_config_file.cc](https://github.com/nodejs/node/blob/v22.21.1/src/node_config_file.cc) and
  [node_dotenv.cc](https://github.com/nodejs/node/blob/v22.21.1/src/node_dotenv.cc), called with the full
  argument vector in [node.cc](https://github.com/nodejs/node/blob/v22.21.1/src/node.cc).
  There are **1,028 canonical options: 954 flags, 69 required values, four attached-only optional
  values, and one next-word option in the pinned inventory**. Plain aliases are additional spellings of these options;
  exact `-pe`, `--`, and stdin `-` are parser forms rather than additional canonical options.
- **Attestation cache proofs.** `TestNodeBuildCacheRewrite` rewrites a real file in place with
  identical size and restored mtime, and verifies the digest changes through ctime. Key-field,
  four-caller coalescing, FIFO bound, failed-read retry and no-command-rule tests cover reuse.
  `BenchmarkNodeExecImage` measures the pinned Node 22 walk; `BenchmarkNodeSupervisorPool4`
  measures batches of four exec notifications through the actual four-worker `Loop.Run` pool,
  with real fd walks and argv reads but synthetic notification transport (no seccomp ioctl or
  JavaScript launch). `BenchmarkNodeSeccompPool4` also measures four real parallel Node
  processes through a real seccomp listener and the four-worker pool, including startup and
  exit, with a TSYNC filter covering all target threads. Cold misses still cost a full hash;
  the cache adds no kernel content pin.
- **Tests.** `TestNodeRowTable` checks the versioned union offline, all native arities, alias expansions,
  and V8 coverage. `TestNodeOptionDenyContract` checks every known spelling against allow A / deny B,
  with B positioned to expose either arity error, attached values, negations, code overridden after
  its value, script-owned flags, and every staged prefix. `TestNodeUnknownStillFailsClosed` holds
  unknown/version-conflicting readings and overflow, plus C49's Jest and code regressions.
  `TestNodeInventoryDifferential` checks the installed inventories exactly on either pinned version
  and runs real scripts that print their own paths, checking dispatch, denial and staged reads;
  it skips only without Node. The existing code, spelling, module and generated differentials now
  run on both pinned versions. Arbitrary V8 diagnostic flags are checked against the complete typed
  inventories and offline arity contracts; only a safe sample is executed. Skips are recorded in
  both unit and integration skip lists. The module, URL, snapshot, path-cleaning and code-override
  adversarial cases from the earlier reviews remain in `node_test.go` and `more_test.go`.
  `TestNodeUnknownBuildMatchesMaster` compares verdicts and script interpretations against a
  frozen master-row oracle, including code, aliases, arities, attached unknowns and overflow.
  `TestNodeUnknownBuildNodePatterns` checks compatibility option matching; `TestNodeInventorySelection`
  proves unknown builds cannot borrow full-inventory arities. `TestNodeScansEveryBuild` and
  `TestNodeReviewPrescans` reproduce the exact pre-scan vectors, argv[0], stdin, `--`, suffix/prefix
  spellings and staged reads on known and unknown builds. `TestNodeReviewDifferential` runs those vectors on the installed Node and
  optional distributions under `TEGO_NODE_REVIEW_DIR`; probing 18/24/25 never pins them. It requires
  B to execute where the reviewed runtime supports the spelling (24.22.2 rejects the default-config
  `=1` form, while 22/25 execute B), then requires the resolver to refuse the raw scans.
  The pinned CLIs must also reject the Node 24/25-only reviewer spellings as `bad option`,
  before JavaScript runs; these are not added to the arity inventory.
  The Node 24/25 attached-option cases explicitly record B executing with a master-compatible
  allow on unknown builds, rather than claiming those residuals are closed. `TestNodeImageBuildPin`
  exercises the supervisor's real opened-file producer against pinned builds, unknown builds,
  forged version strings and wrong-inode reads. CI's `node-options` job installs 20.19.4 and
  22.21.1 using a full-SHA-pinned setup action and checks pass events for all live differentials;
  a skipped test fails that job.

## Adding or changing a row

1. Write the row in `pkg/policy/execmatch/rows` from the tool's manual and `--help`, with its version and the
   documentation it was written from. It is `documented`.
2. Add a test of real invocations to `more_test.go` (or the row's own test file): each pattern that should refuse,
   each near-miss that should not.
3. A row becomes `probed` only with a test that runs the installed binary (skipped where it is absent) and holds the
   row to it, as `TestNpmRowDifferential` and `TestRmRowDifferential` do. A helper closure is added only from a
   measurement.
4. Update this table and the CHANGELOG.
