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
interpreter options).

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
| node | probed | 20.19.4 | `node`, `nodejs` | its own options, `--env-file` and `--inspect-port` with a separate value too; `-e` and `-p` take code | interpreter: entry scripts (npm-cli.js, npx-cli.js, pnpm.cjs, yarn.js), else the script's basename | `-e` code (R1) |
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
- **Two-level commands**: `TestGitRowFresh` reads the verbs `git <cmd> -h` lists for every command the row gives a
  second level (stash, remote, bisect, ...) and fails when one is neither a subcommand nor an alias of the row's
  level; a verb the row has and the installed git lacks (another supported version's) is not a failure. `git bisect
  next` was missing (added 2026-10-16). `git maintenance -h` lists no verb, so its level is not checked this way.
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

## Adding or changing a row

1. Write the row in `pkg/policy/execmatch/rows` from the tool's manual and `--help`, with its version and the
   documentation it was written from. It is `documented`.
2. Add a test of real invocations to `more_test.go` (or the row's own test file): each pattern that should refuse,
   each near-miss that should not.
3. A row becomes `probed` only with a test that runs the installed binary (skipped where it is absent) and holds the
   row to it, as `TestNpmRowDifferential` and `TestRmRowDifferential` do. A helper closure is added only from a
   measurement.
4. Update this table and the CHANGELOG.
