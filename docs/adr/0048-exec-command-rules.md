# ADR 0048: exec rules name commands and subcommands; one argv matcher decides them, and at a decision plane the kernel holds every exec to the facts that were decided

Status: **accepted 2026-10-06**. P1 implemented 2026-10-06, **P1 acceptance not met**: reviews found bypasses, all fixed since, and the ADR 0017 conformance cells are built, but no review of probes against a real run has yet found nothing on the fixed code. P2 partly built: K0, the kernel facts it rests on, verified 2026-10-19 on every matrix row; K1 to K5 built, so a run with command rules or an exec gate that can escalate is pinned at a plane tier where its plane mode passed doctor's exec pin cell (`plane.exec_pin`) and its slot is pinned; all sixteen K6 run tests pass in both boots on 6.17, 6.1 (AL2023), 6.8 (Ubuntu 24.04) and 6.12 (Debian 13), one skipping for binfmt_misc off 6.17, and on RHEL 9's 5.14 they skip for the disclosed fallback (pins off: its recorder has no exec outcomes), with 7.0 not yet read; K7's check (`execbench`, perfsuite's `exec`) is built and not yet measured in a guest; **P2 acceptance is not met**. Implementation notes at the end.
Amended in part by ADR 0044 (accepted 2026-10-16, not built): `exec.ask` is no longer reserved; in a restricted section an ask entry admits its tool at the launch-time floor and constrains it where it is what admits the tool (where a bare path or directory allow entry already grants the tool's file, and in a deny-list section, it only adds the ask step and grants no image, helper images included), an ask entry's helper closure is admitted only for the process tree an approval of it released (never statically, so R11 does not extend to ask entries), a match is held and asked and completed through the trace-gate, the precedence gains standing answers and passes at the ask step, and P2's `exec-traced` step spares a pin carrying the `trace_gate` flag.

The aim is to deny whole commands and subcommands, not only programs. Two phases ship it: **P1** (contract, matcher, compiler, supervisor, ledger, `compile --test`, docs) and **P2** (the
kernel argv pin at plane tiers).

This ADR amends five others. P1's first commit adds the forward links, each reading "Amended in part by 0048":

- **ADR 0007.** The gate's `exec matches` reads its pattern with the shared command matcher as well as its glob (5).
  The gate still only escalates.
- **ADR 0016 (4).** The producer table gains the supervisor's command-rule refusals and the plane's pin refusals and
  kills, with a fail-closed fold (8).
- **ADR 0019.** `compile --test` cells gain the command-rule fields, and the exec warnings are scoped per tier (9).
- **ADR 0024 (5), (11).** Steps join bprm_check, one `tp_btf/sched_process_exec` program and three maps join the
  plane, and the plane's ptrace hooks refuse one more case (7).
- **ADR 0041 D1.** New rows for command rules (6). At C+ and B, once pins run, the `gate.exec` row's argv and names
  are pinned by the kernel and leave `best_effort`.

**ADR 0044 (accepted later, 2026-10-16) is not amended by this ADR.** Its Rejected option 11 ("an `exec.ask` list now") stands. Here `exec.ask` is a
reserved key that refuses at every tier (5). Only an amendment to 0044 can give list asks
a completion.

## Context

### What existed when this ADR was written

- **`exec.allow` grants images, never arguments.** Entries are paths or bare names (agent-contract R8). A bare name
  resolves on the run's `PATH`. Tier 1 grants `EXECUTE` on the inode (Landlock). Tier 2 adds `FAN_OPEN_EXEC_PERM` on
  the fallback. The plane's `bprm_check` matches inode, directory and name for each binfmt stage (SEMANTICS §4).
  `ExecSection` has `allow`, the schema-only `privileged`, and `anonymous` (`pkg/spec/agent/agent.go`). There is no
  `exec.deny` and no `exec.ask`.
- **`Canonical` is a yaml.v3 encode of the struct, and `ExecSection.Allow` is `omitempty`** (`agent.go`). It drops
  `allow: []`. `FSSection.MarshalYAML` (`deny_read: []`) and `EnvSection.MarshalYAML` (`pass: []`) exist because
  dropping an empty list once flipped a section's meaning across a recompile (agent-contract R13).
- **The only argv control is the gate's `exec matches "<glob>"`** (gate.md R2, `pkg/policy/gate/gate.go`).
  - `Evaluate` builds up to three strings, one per copied name (requested pathname basename, resolved image
    basename, argv[0] basename), each followed by argv[1:] joined with single spaces.
  - A pattern without glob characters matches when a string equals it or starts with it plus a space. A pattern
    with them goes through `filepath.Match` with `/` projected to NUL.
  - `gate.New` rejects a `/` in an exec pattern's first word, with a fix that names the basename.
  - So `exec matches "git push"` misses `git -C . push`, `git -c x=y push`, `git --git-dir=.git push` and
    `/usr/lib/git-core/git-push`. `exec matches "rm -rf"` misses `rm -fr`, `rm -r -f`, `rm -Rf`,
    `rm x --recursive --force` and `busybox rm -rf`. Joining with spaces makes `["git", "push origin"]` and
    `["git", "push", "origin"]` the same string.
  - Bounds: 128 arguments and 4096 bytes (`gate.MaxArgs`, `gate.MaxText`). Past them the action is
    `gate.unreadable` and refused.
- **The supervisor decides exec on copied facts** (`internal/runtime/supervisor/exec.go` `recordExec`).
  - It reads the pathname and argv with `process_vm_readv` under `ID_VALID`. It walks the image as the task would
    (R16b) and decides the image (`decideExec`, `execGranted`).
  - Without an exec gate, at a plane tier with live kernel recording, it hands the exec over (`handOverExec`, T16):
    it captures naming and answers `CONTINUE`. An exec gate disables that fast path until the exec is scored.
  - Ordinary recording reads up to 8192 pointers and `DefaultMaxArgv` (128 KiB). It makes one `process_vm_readv` per
    string plus one per 64 pointers (`read.go` `argvLimited`, `cstring`). Under `record: off` an allowed exec reads
    no argv (R16, `TestExecQuietReadsNoArgv`).
- **The kernel copies argv again after `CONTINUE`.** ADR 0041's table says so: "exec: argv — no [race-free
  completion], at any tier — the kernel re-reads argv after any decision". Its D1 makes `gate.exec` a disclosed
  best-effort cell at every tier (`pkg/spec/agent/best_effort.go`, `BestEffortGateExec`).
- **The recorder already reads the kernel's own argv** at `tp_btf/sched_process_exec` (`bpf/trace_proc.bpf.c`
  `tego_sched_exec`): `[mm->arg_start, mm->arg_end)` of the new image, clamped to `TEGO_ARGV_MAX` (512 bytes),
  with the binfmt marker `interpreted = bprm->interp != bprm->filename`. It decides nothing.
- **The plane's process controls** (enforce-plane §2.20). `ptrace_access_check` (ATTACH mode) and `ptrace_traceme`
  refuse a peer outside the run and gen. A peer inside the run passes.
- **Arming** (ADR 0021 (2)). The plane is armed after the stage's own exec of the tego binary and before the ack.
  The agent does not exist before the ack.
- **ADR 0044 (proposed)** designs exec approval at plane tiers. It refuses now, and the retry runs under a one-shot
  per-task claim bound to the approved file. It keeps argv a copied fact, proved after the fact by the record. Its
  reason: "the arguments sit in the new `mm`, and no non-sleepable helper reads it before `begin_new_exec`". Its
  Rejected option 11 rejects an `exec.ask` list: the list's floor would be refused, so a claim would have to admit
  rather than narrow.

### Known bypasses of command rules

  - options before the subcommand (`git -C`, `kubectl -n x`);
  - config-driven rewriting (`git -c alias.*`, `--config-env`, cargo/gh/aws aliases);
  - wrappers and indirection (`env`, `timeout`, `xargs`, `sh -c`, `busybox rm`);
  - interpreters (`python -m pip`, `node npm-cli.js`, `-c`/`-e` code);
  - renamed copies;
  - races between the check and the use.

### Measured on the test machine (Ubuntu 25.10, 6.17.0-41), 2026-10-06

Rows marked † were measured independently. The others were measured while drafting.

| Probe | Result | What it decides |
|---|---|---|
| `GIT_TRACE=1 git -c alias.st=status st` (git 2.51.0) | `trace: alias expansion: st => status`, then `trace: exec: git status` | a git alias of a built-in runs as a **child exec** `git <builtin>`, which the rules see |
| `GIT_TRACE=1 git -c 'alias.sh2=!echo hi' sh2` | `start_command: /bin/sh -c 'echo hi'` | a shell alias is a child exec of `sh` |
| `GIT_TRACE=1 git -c help.autocorrect=immediate stauts` | "Continuing under the assumption that you meant 'status'", then `trace: built-in: git status` | autocorrection runs the built-in **in process**: no exec carries the real subcommand |
| † `git -c help.autocorrect=immediate <token>` | `psh`, `pusg`, `psuh`, `puhs`, `Push`, `push ` (trailing space), `pυsh` → push; `pus` → nothing runs (push and pull tie); `lfs` → refs | git autocorrects only to a **unique** best candidate (`help.c` `help_unknown_cmd`) |
| † a port of `help_unknown_cmd` (candidates from `git --list-cmds=main,builtins` plus the `list-*` groups) | agrees with the real binary on 417 of 417 tokens; a "distance < 7 to any built-in, or a prefix" rule flags 54 tokens as reaching push where git reaches 11 | the autocorrect reading must be the port, not a distance bound |
| `exec -a git-status /usr/bin/git` | runs `git status` | git dispatches on argv[0]'s `git-<cmd>` form |
| `exec -a foo /usr/bin/git status` | runs `git status` | any other argv[0] runs as plain git: a renamed copy is still git |
| `git -- status`, `git -C. status`, `git --frobnicate status` | `unknown option` each | git's global options are exact, and value-taking options take the next token |
| `git status --shor` | accepted as `--short` | git abbreviates long options of a subcommand |
| `ls -la /usr/lib/git-core/git-push` | symlink to `git` | the dashed form is reachable by path |
| † `ls -i /usr/bin/git /usr/lib/git-core/git` | 60556732 and 3085 | git re-execs **another inode** than `/usr/bin/git` (Debian and Ubuntu; RHEL uses `/usr/libexec/git-core`) |
| † `strace -f` of git 2.51.0 | `commit` and `fetch` run `git maintenance run --auto`; `fetch` runs `git rev-list --objects ...` and, for a URL, `git remote-https <url> <url>`, then `git-remote-https`; a push over the file transport runs `sh -c git-receive-pack`, `git pack-objects`, `unpack-objects`, `rev-list`, `for-each-ref`, `maintenance`; `gc` runs `pack-refs`, `reflog expire`, `repack`, `pack-objects`, `prune`, `worktree prune`, `rerere gc`; an alias of a built-in re-execs `/usr/lib/git-core/git push origin` without the `-c` | **git runs git**: an allow list keyed by subcommand must admit git's own helpers |
| † status, log, diff, rev-parse, branch, checkout, stash, merge | no git child | a read-only allow list of status, diff and log works |
| `rm rmprobe --rec --forc` (GNU coreutils 9.5) | removes the tree | GNU `rm` permutes options after operands and accepts unique long prefixes |
| † `rm -r <tree with read-only files> </dev/null` | removes it, rc 0 | without a tty, plain `rm -r` does what `rm -rf` does |
| `/usr/bin/rm` | symlink to `gnurm`, one link | the resolved image's basename is `gnurm`, not `rm`: identity has to count |
| `/usr/bin/ls`, `/usr/bin/cat` | one inode, 115 links (uutils multicall) | identity cannot name a multicall binary's applet; argv[0] does |
| `npm vie --help` (npm 9.2.0) | runs `view` | npm resolves unique prefixes of command names |
| `npm --foo version`; `npm --loglevel warn version` | both run `version` | npm 9.2 reads an unknown option as a flag and a known one by its type. The row needs npm's option types, and an older or newer parser may differ |
| `readlink -f /usr/bin/npm`; its first line | `/usr/share/nodejs/npm/bin/npm-cli.js`; `#!/usr/bin/env node` | `npm publish` is a script exec, then `node .../npm-cli.js publish` |
| † one `process_vm_readv` of a short string | 0.75 to 0.95 µs | `git status` costs about 4 µs to read; 8192 arguments read one string at a time cost 6 to 9 ms |
| † installed tools | git, rm, npm/npx, node, python3, systemctl, go present; kubectl/oc, docker/podman, pnpm/yarn, pip, cargo, gh, terraform/tofu, helm, aws, gcloud absent | rows for the absent tools are **documented**, not probed |

### The two problems

1. **Locating the subcommand.** A command line is not a string. The word that decides what the program does moves
   with global options that take values, with clustered, permuted and abbreviated options, with dashed and argv[0]
   forms, and with multicall binaries, interpreters and in-process autocorrection. A matcher that does not know a
   tool's grammar either misses (an allow-shaped prefix rule used for deny) or refuses everything (a substring
   rule).
2. **Deciding on the right copy.** The supervisor decides on its own copy of argv. After `CONTINUE` the kernel
   copies argv again, from memory that a sibling thread, a `CLONE_VM` child or a vfork parent's other threads can
   rewrite. It also resolves the pathname again, through links any peer can swap. A refusal on the copy is honest;
   an allow is a prediction (ADR 0041's principle).

## Decision

### (1) The contract

```yaml
exec:
  allow:                 # images, as today; a word after the command constrains its argv
    - git status         # git runs, but only as `git status ...` (and git's own helpers, below)
    - git diff
    - git log
    - python3 -m pytest  # python3 runs only as `python3 -m pytest ...`
    - make               # bare: any arguments, as today
  deny:                  # new: never runs, at any specificity
    - git push           # any `git push`, wherever git's global options put it
    - rm -r              # any recursive rm; `rm -rf` would need both options and leave `rm -r` open
    - kubectl delete
    - npm publish
  ask:                   # reserved: refused at every tier until ADR 0044 accepts a list floor (5)
    - npm install
```

**Entries.** An entry is a *command pattern*: a command word, then zero or more words.

- **Classification is a pure function of the text.**
  - An entry with no unquoted space is one word: a bare name or a path, exactly as today. An entry with no space or
    tab at all is that word as written, quote characters included (amended 2026-10-06).
  - An entry with unquoted spaces or tabs is a pattern, and its first word is the command word.
  - A path that contains spaces must be quoted as a whole (`'/opt/My Tools/run'`).
  - Compile uses the filesystem only to improve an error. If an unquoted entry with spaces names an existing file as
    a whole, the error says "quote the path".
  - A bare entry with a space has never resolved (`exec-not-on-path`), so the only contracts this changes are those
    with an unquoted path containing spaces. They now fail to compile (fail closed). The CHANGELOG says so.
  - The saved contract.yaml is recompiled later by drift and the ledger on other machines (agent-contract R13), and this reading
    gives the same classification on every machine.
- **The command word** is a bare name (no `/`) or a path.
  - In `exec.allow` a path command word grants that file, as today. With words, it also constrains the tool that
    file is.
  - In `exec.deny` and `exec.ask` a `/` in the command word is an `exec-rule` error. The error carries a fix that
    names the basename, as `gate.New` does: "a deny entry matches every file of a name; write `git push`". A path
    there would broaden the entry, not narrow it.
  - A glob in the command word is an `exec-rule` error.
- **Option words** start with `-`: `--force`, `-f`, `-rf` (a cluster of the options `r` and `f`, where the tool
  clusters), and `--namespace=prod*` or `-n=prod*` (an option and a glob over its value).
  - A pattern is parsed with the same row as an invocation, so `-n prod`, `-n=prod`, `-nprod` and
    `--namespace prod` are one option word wherever the tool accepts them.
  - Placement follows the row. Where a tool reads global options anywhere (pflag and cobra tools, aws, gcloud), a
    global option word matches anywhere. Where globals stand only before the subcommand (git, pip, cargo, go), an
    option word before the first subcommand word is a global option, and one after it belongs to that subcommand.
- **Other words** are subcommand words while the tool's grammar (2) says the level has subcommands, and operands
  after that. A word may hold `*`, `?` and `[...]` globs over one token, with no special `/`.
- **A lone `*`** is allowed only as the last word, where it means "any further tokens". Elsewhere it is an
  `exec-rule` error.
- **Spelling.** Words are split on ASCII spaces and tabs. A word that holds a space is quoted with `"..."` or
  `'...'`. No other escape exists.
- **Shell syntax lint.** Nothing is expanded or split by a shell, so shell syntax in an entry is inert text.
  - Whole words `&&`, `||`, `|`, `;`, `<` and `>` are an `exec-rule` error. So is a trailing `:*` or `(...)`
    (Claude Code's rule syntax). The fix names the separate entries to write.
  - `$`, `$(` and a backtick inside a word are an `exec-rule` warning: the word is matched literally.
- **Errors name the word and the fix**, as `gate.New`'s errors do.
- **Directories** take no words: a directory entry with words is an `exec-rule` error.
- **Keys.** Allow constraints are keyed by tool: the row, or the generic tool of that name. Every allow entry that
  names `git` with words adds a pattern to git, whichever file it resolves.
  - A **bare name** entry equal to the tool's name (`git`) lifts the constraint.
  - A **bare path** entry grants that file only. It never lifts a constraint, and compile notes it: "grants the file;
    git stays constrained by its word entries; write `git` bare to lift the constraint".
  - The image rule that grants a constrained tool's file is named by the command word (`exec[git]`). The pattern
    that admitted the exec goes in `command_rule` (8). Otherwise `byPath` would keep the first spelling and every
    git exec would carry `exec[git status]`.

**What a word means in each list.** A pattern constrains only what it names.

| Pattern part | `exec.allow` (grants) | `exec.deny` and `exec.ask` (refuse or ask) |
|---|---|---|
| subcommand words | the invocation's subcommand path starts with them (`git stash` allows `git stash push`; `git push` does not match `git stash push`) | same |
| option words | each named option is **required**, in a position where the tool reads it as an option. This is not a whitelist: `allow: [git log --oneline]` refuses plain `git log` | each named option is present anywhere the tool could read it as one (an over-approximation). Each option word narrows the entry (AND) |
| operand words | the invocation's operands equal them in number and order; a trailing `*` allows more | the operands contain them as an ordered subsequence |
| nothing after the subcommand | any options and operands | any options and operands |

Options a pattern does not name are free. `git push origin feature/*` allows `git push --force origin feature/x`
and `git push --repo=URL origin feature/x`. To close those, deny `git push --force` and `git push --repo` (R10).
Compile prints each entry's exact reading (9), for example "requires: --oneline; every other option free". It warns
(`exec-rule-coverage`) when an allow entry names options. Docs tell authors to name, in a deny entry, the fewest
options that still describe what they never want.

**Precedence.** In order:

1. **The image floor** decides first, unchanged: exec rows, Landlock, the supervisor's `execGranted`, anonymous
   images, `deny_read` on the exec open. A refused image is never asked about.
2. **Command rules** decide on the facts of (2):
   - any `exec.deny` match, definite or ambiguous, refuses;
   - else any `exec.ask` match refuses as a reserved ask (5);
   - else the exec is refused as unlisted when the tool is *constrained* and two things hold: no allow pattern
     matches definitely, and the invocation is not in the helper closure (2) of an allowed pattern.
     - A tool is constrained when some `exec.allow` entry names it with words and no bare name entry or implicit
       grant names it.
     - The implicit grants keep "any arguments": the contract's `command`, each `mcp[].command[0]`, a `#!`
       interpreter of either, and the command given to `tego run` under R8. Compile notes the constraint each one
       shadows.
   - else allowed.
3. **The gate** escalates the result, unchanged in role (5).

Specificity never changes the order, and **no exception syntax exists**. `allow: [git push --dry-run]` cannot carve
a hole in `deny: [git push]`.

**The run's own commands.** Compile evaluates the command rules on the contract's `command` and on each
`mcp[].command`.

- A deny or ask entry that matches `command` is an `exec-rule` error, because the run could not start.
- One that matches an `mcp[].command` is a warning that names the server that cannot start.

**Deny-list mode and the mode bit.** The mode is decided by which keys are present, never by whether a list is
empty:

| Section | Mode |
|---|---|
| no `exec:` section | images unrestricted, no command rules (today) |
| an `allow` key, even `allow: []` | images restricted (today), plus any command rules |
| no `allow` key, and a `deny` or `ask` key, even empty | **deny-list**: images unrestricted, command rules apply |
| neither (`exec: {}`, `exec: {anonymous: true}`) | images restricted (today) |

- So `exec: {deny: [git push]}` means "anything but `git push`", not "nothing but the agent command". Commenting out
  the last entry of a list keeps the mode. Only removing the `allow:` key itself changes it.
- *Amended 2026-10-06:* a key left with no value (its last block entry commented out) is a
  `schema` error with the `[]` fix, for `allow` as for `deny` and `ask`. YAML reads it as absent, so a null `allow`
  beside a `deny` key made a deny-list in which every image may run. *Amended 2026-10-06:*
  narrowed for `allow`. A null `allow` alone reads as absent, as it did before this ADR: a restricted section, the
  same as `exec: {}`, which fails closed. It is a `schema` error only where the merged section is a deny-list, that
  is where a `deny` or `ask` key stands anywhere in the `extends` chain; the check runs after the merge
  (`TestExecModeByKeyPresence`, `TestExecNullAllowAcrossExtends`). A null `deny` or `ask` stays a `schema` error.
- An empty deny-list section restricts nothing and gets an `exec-rule` warning: "this section restricts nothing;
  add entries or an `allow` key".
- **Presence is carried, not inferred.** yaml.v3 decodes a present empty list to a non-nil empty slice, and `Load`
  asserts that this holds. `merge.go`'s `exec()` keeps non-nil through `extends`, as `m.strings` already does.
- **Canonical form.** A new `ExecSection.MarshalYAML`, like `FSSection`'s and `EnvSection`'s, emits an empty list
  only where dropping it would change the mode:
  - `allow: []` when the section is restricted, `Allow` is empty and `deny` or `ask` has entries;
  - `deny: []` when the section is a deny-list with no deny or ask entries.

  Every other section encodes byte for byte as today, so **every existing contract's canonical bytes and
  `contract_hash` are unchanged**. A golden holds that, over every contract in the repo's examples and testdata.
  - Goldens also hold that `exec: {allow: [], deny: [git push]}` and `exec: {deny: [git push]}` hash differently.
  - Each round-trips Canonical → Load → Compile to the same mode.
- **One method.** `RuleTable.ExecUnrestricted()` becomes "the mode is not restricted". Today the same bit is spelled
  `Contract.Exec == nil` directly at seven other sites:
  - `enforce/landlock/landlock.go` (the EXECUTE grant at 220, and the memfd arm at 440);
  - `enforce/cgroup/plane.go:138` (`TEGO_SLOT_EXEC_DECIDES`) and `policy.go:140` (the fanotify `execOpen`);
  - `decide/planerows.go:393` (`ExecPolicy`);
  - `supervisor.go:608` (`execUnrestricted`);
  - `compile_execmap.go:46` (E39's `exec-map` warning).

  `compile_exec.go`'s two `Exec != nil` tests only guard loops over the entries and are unaffected. P1 routes every
  one of the seven through the method, and an `Exec.Anonymous` reader through a sibling. A source test fails on a
  new direct spelling. Otherwise one enforcer would read a deny-only section as restricted and another as
  unrestricted.
- **`extends` can set the mode.** A child that adds `allow` to a deny-list parent makes the merged section
  restricted. Compile prints the mode on its own line, with the file that set it: "exec: images unrestricted
  (deny-list, set by base.yaml), 3 command rules". A test covers both directions.

**Composition.** `extends` concatenates `exec.deny` and `exec.ask` as it does `exec.allow` (R5). Nested runs
compose them as SEMANTICS §3 says: deny and ask lists union, and an inner contract's allow constraints
intersect the outer's, so an inner run can only narrow.

**Bounds.** At most 512 command patterns across the three lists after `extends`. Each has at most 32 words of at
most 256 bytes each and 1024 bytes in all, all valid UTF-8 with no NUL. Past a bound: `exec-rule` error.

**Unresolved names.** A deny or ask command that is not on the run's `PATH` is no error. It is matched by name only,
and compile notes it. An allow entry keeps today's `exec-not-on-path` error, since it grants a file.

### (2) Matching semantics: one matcher, `pkg/policy/execmatch`

A new package, standard library only, no I/O. It is imported by `pkg/spec/agent`, `pkg/policy/gate`,
`internal/policy/decide` and, through the decision core, the supervisor. REPO-LAYOUT gains the row
"`pkg/policy/execmatch` → standard library only".

**Facts.** The matcher takes the exec's *facts* and never reads anything:

- **names:** The requested pathname's basename (absent for `execveat(fd, "", AT_EMPTY_PATH)`), the resolved image's
  basename (the walk's link), and argv[0]'s basename;
- **identity:** The image's `(dev, ino)`;
- **form:** `direct`; `script`, with the `#!` interpreter chain (each stage's path, optional argument and identity);
  or `unknown`;
- **argv:** The copied vector, as byte strings, or the prefix of it the decision needed (3). There is no shell
  parsing: quoting was the shell's, and `git 'push'` arrives as `push`.

**Interpretations.** The facts yield a set of *invocations* `(tool, tokens)`. The verdict is the strictest over all
of them. Any interpretation a deny entry matches refuses, and a constrained tool must be allowed under every
interpretation that names it. A caller-chosen argv[0] can add an interpretation; it cannot remove one.

1. **By name.** Each name maps to a tool row (the table below) by its listed names, or to a generic tool of that
   name. Tokens are argv[1:].
2. **By identity.** Compile resolves every command a rule names on the run's `PATH`, follows links, and adds the
   row's helper images (below). If a resolved file has exactly one link and its row is not a multicall dispatcher,
   an exec of that `(dev, ino)` is also that tool. This catches `/usr/bin/gnurm` for `rm`, a symlink or bind mount
   under another name, a distribution's versioned binary, and `/usr/lib/git-core/git`. A multicall binary (more than
   one link, or a dispatcher row) gets no identity reading: it dispatches on argv[0], which (1) reads.
3. **Dashed forms.** Where a row allows them, a name `<tool>-<sub>` is `(tool, [sub] + argv[1:])`: `git-push`,
   `kubectl-foo` (a plugin), `docker-compose`, `cargo-clippy`, `gh-foo`. A cargo or docker plugin receives its
   subcommand again as argv[1], which is then skipped.
4. **Multicall dispatch.** `busybox`, `toybox` and the uutils `coreutils` binary with an applet as argv[1] are
   `(applet, argv[2:])`. *Amended 2026-10-06:* GNU coreutils' single binary (the coreutils-single package,
   as UBI-minimal images install it) is the same `coreutils` row and dispatches three more ways (src/coreutils.c):
   `--coreutils-prog=PROG` is `(PROG, argv[2:])`, its `#!` form `--coreutils-prog-shebang=PROG` is `(PROG,
   argv[3:])` (argv[2] is the script), and argv[0] `lt-PROG` is `(PROG, argv[1:])`.
5. **Interpreter dispatch.** For `python*`, `node`/`nodejs`, `sh`/`bash`/`dash`/`zsh`, `perl` and `ruby`:
   - `python -m <module>` is `(tool of module, tokens after it)`, through a module table (`pip`, `pip3` → pip;
     `twine` → twine; `pipx`, `poetry`, `uv` where installed as modules);
   - The first operand that is a script path is `(tool of its basename, tokens after it)`. That goes through an
     entry-script table (`npm-cli.js` → npm, `npx-cli.js` → npx, `pnpm.cjs` → pnpm, `yarn.js` → yarn) or the
     basename itself (`node /usr/bin/npm publish` is `npm publish`; `bash ./deploy.sh prod` is `deploy.sh prod`);
   - `-c` and `-e` code strings are opaque, with no interpretation (a residual, R1).
6. **The `#!` interpreter.** For a `script` form, each stage's `(interpreter, [arg?, script path] + argv[1:])` is
   an interpretation too: exactly the argv binfmt_script gives the interpreter. *Amended 2026-10-06 (final
   review):* a stage is read as a direct image is, by three names: the `#!` line's path (the interpreter's argv[0]),
   the basename of the file its walk reached (the walk's link), and that file's identity (2). Each name gets (1),
   (3) and (4)'s readings. Read by the `#!` spelling alone, `#!/tmp/x -rf` with `/tmp/x` a symlink to rm was `x`,
   unguarded, and ran `rm -rf` under `deny: [rm -r]`.
7. **The program a dynamic loader runs.** *Added 2026-10-06.* A dynamic loader run as a
   command (`ld-linux-x86-64.so.2 /usr/bin/rm -rf tree`) maps its program and jumps to it in-process, so the
   program's own invocation makes no execve. Its program is read as a direct image is (1, 2, 3, 4), by the
   operand's name, the walked file's name and its identity, with the argv the loader gives it: argv[0] the operand,
   or `--argv0`'s value, then the words after the operand (`command_via: loader`). The loader's vector is read as
   glibc's rtld (`dl_main`) and musl's ldso (`__dls3`) read it (`execmatch.LoaderProgram`). The image is a loader
   when its basename is a loader's (`ld-linux*.so*`, `ld-musl-*.so*`, `ld64.so.*`, `ld.so`), as requested, as
   walked or as a `#!` line names it, or when its identity is one of the host's loaders that compile lists from the
   library directories (`ExecCommands.Loaders`). *Amended 2026-10-06:* never by its ELF
   type. An earlier fix also read any `ET_DYN` image with no `PT_INTERP` as a loader, which is every
   static-pie program, whose first word is an operand: `rg git push` was refused under `deny: [git push]`.

Wrappers that exec need no rule: `env`, `nice`, `timeout`, `nohup`, `stdbuf`, `xargs`, `setsid`, `flock`, `ionice`,
`chrt`, `taskset`, and `sudo` where `setuid: true`. The wrapped program is its own exec and meets the rules itself.
The same holds for `sh -c 'git push'`, git hooks, pagers, editors, `core.sshCommand`, credential helpers and `npm run`
scripts. This is the structural advantage of deciding at `execve` rather than on a shell string.

**Normalizing one interpretation.** The tool's row parses the tokens into a subcommand path (canonical names, aliases
resolved), options per level (canonical names, with values), operands, and the readings that make it *ambiguous*.
The row gives:

- The options each level takes, which take a value, and how (`-n v`, `-nv`, `-n=v`, `--ns v`, `--ns=v`);
- whether short options cluster;
- whether long options take unique prefixes (getopt_long, optparse and git parse-options do; pflag does not);
- whether options permute past operands, per level (pflag, getopt and git do; Go's `flag` and docker
  `run`/`create`/`exec` stop at the first operand);
- whether global options stand only before the subcommand or anywhere;
- what `--` does;
- subcommand names and built-in aliases, and whether names take unique prefixes (npm does);
- multi-level subcommands (`git stash push`, `kubectl config set-context`, `aws s3 rm`, `gcloud compute instances
  delete`, `terraform state rm`);
- The helper closure, for a tool that runs itself (below).

**Ambiguity, decided from argv alone.** Where the row cannot be sure how the tool reads a token, the normalizer keeps
every reading the tool could make. Each list takes the readings in its own fail-closed direction.

- **An unknown option** is one the row does not list for its level. It may be a flag, or it may take the next token.
  A table older than the tool can miss a new value-taking option, which would move the subcommand or swallow an
  option word (`rm --newopt -rf x`).
  - Before the subcommand, the normalizer keeps every word that either reading could make the subcommand. That set is
    small and found in one pass: each unknown option may or may not skip the token after it.
  - A deny or ask entry reads every unknown option as a flag. That reading keeps the most option and operand words,
    since a value-taking reading only removes words. *Amended 2026-11-01:* not where position picks the tool: in front
    of an interpreter's script, the value reading picks a different script, so both readings dispatch.
  - A constrained allow entry does not match in two cases: when an unknown option stands before the subcommand, and
    anywhere when the entry names options or operands, since either reading could change what they bind. Unknown
    options after the subcommand do not matter to an entry that names only subcommand words: `allow: [git log]`
    admits `git log --any-option`.
- **`--` where the tool refuses it** (git: "unknown option") is read the same way. The tool would refuse it, but the
  row does not assume so.
- **A visible rewrite trigger** makes the interpretation *unlocatable* for that tool. Examples: cargo `--config`
  whose value is a path or names `alias.`, and gcloud `--flags-file`.
- **git autocorrect** is a pure-function port of git 2.51.0's `help.c` `help_unknown_cmd`, not a distance bound:
  - A candidate in git's common-command group that starts with the token scores 0. Any other candidate scores
    `levenshtein(token, candidate; swap 0, substitution 2, insertion 1, deletion 3) + 1`.
  - Candidates that score 0 are counted first, then the candidates with the best non-zero score.
  - git autocorrects only when exactly one candidate is counted and its score is below `SIMILARITY_FLOOR` (7). Any
    prefix match of a common command, or any tie, means no correction (`pus` ties push and pull).
  - The matcher assumes `help.autocorrect` is on, since it reads no config. A subcommand token that is not a built-in
    and that the port corrects to built-in X also reads as X (ambiguous). So `deny: [git push]` refuses `git psh`,
    `git psuh`, `git pusg`, `git Push` and `git pυsh`, and leaves `git lfs`, `git gui`, `git ls` and `git sh` alone.
  - **Candidate set.** git's own candidates are its exec-path commands, `git-*` on `PATH`, and aliases. The matcher
    uses a set B that is a **subset** of git's:
    - the `git-*` names compile finds in the resolved git's exec-path directory (the row's locations:
      `/usr/lib/git-core`, `/usr/libexec/git-core`, or the directory the resolved binary names). Compile lists a
      directory and runs nothing;
    - where that directory has no dashed built-ins (`SKIP_DASHED_BUILT_INS` builds), the row's built-in list. That
      list, and the row's common-command group, are the intersection over every supported git version (2.39
      through 2.51), so each is a subset of every supported git's own.
  - **Why a subset is sound.** Suppose git, with its full set R ⊇ B, corrects a token to X. Then no candidate in R
    scores 0, and X is R's unique best, so the same holds in B. The matcher therefore reaches every target git
    reaches. Candidates outside B (aliases, externals, later built-ins) can only block or retarget a correction. The
    matcher keeps the reading git would not make, so the over-approximation lives in the candidate set only.
  - **Bounded work.** A token longer than the longest candidate plus one cannot score below 7, because each surplus
    byte is a deletion at 3. The dynamic program runs only for shorter tokens: at most |B| × 32 × 32 cells. It runs
    only for a token that is not a built-in, and only under a deny or ask entry on git or a constrained git.
  - **Drift is a fail-open regression**, not a coverage note. A differential test against the installed git (skipped
    when absent) runs every single and double edit of every built-in and known external, plus random tokens. Any
    target git reaches that the port misses fails the build. A freshness test fails when the installed git's
    built-ins or common group are not a superset of the row's (R4).
- **An unknown subcommand** outside git's reach is not ambiguous by itself. It is a plugin or an external command,
  which runs as its own exec, or an error.

So a deny or ask entry matches when **any** reading matches, and an unlocatable interpretation matches every deny and
ask entry naming its tool. A constrained allow entry matches only when **every** reading matches, and never on an
unlocatable interpretation. Both are the fail-closed direction. The record says `command_match: ambiguous` when the
readings disagree. A bare-command entry matches whatever the readings: `deny: [git]` refuses every git exec.

A row therefore lists two things, each with its value form, taken from the tool's own help or manual at the pinned
version: the complete global option set (everything that can stand before the subcommand), and, for each
subcommand, at least the options people write in patterns. An unlisted option can cost a constrained allow entry its
match, before the subcommand or under an entry that names options or operands. It never costs a deny entry one.

**Tools that run themselves: the helper closure.** git runs git (measured above). Under a constrained git, each
helper exec is `(git, [helper...])`. Without a model, every one of them would be refused as unlisted, and
`allow: [git fetch]` (or commit, pull, push, clone, gc) would fail on every network or maintenance path.

- A row may carry a **helper closure**: for each subcommand path, the subcommand paths and dashed helpers that the
  tool runs for itself. It is measured per version with `strace -f` against a local bare repository and computed
  transitively (`maintenance` runs `gc`, which runs `repack`, which runs `pack-objects`).
- An allowed constrained pattern admits its subcommand's closure.
  - `allow: [git fetch]` also admits `git maintenance`, `git rev-list`, `git index-pack`, `git remote-https` and
    `git-remote-https`.
  - Closure invocations are admitted on the allow side only. Deny and ask entries match them as any other exec:
    `deny: [git gc]` still refuses the `git gc` that auto-maintenance would run.
- **The image floor follows.** Both bare and constrained entries of a row with a closure grant the helper images
  that compile finds in the row's exec-path directory (`/usr/lib/git-core/git`, `git-remote-https`, ...). Compile
  prints them.
  - This widens today's floor for a bare `git` entry, but only by git's own files. Today those operations fail with
    `EACCES` at tier 1 on Debian, because `/usr/lib/git-core/git` is another inode. The CHANGELOG states the change.
- **Aliases under a constrained git.** The first exec names the alias (`git st`), which is unlisted, so it is
  refused. To use an alias, list it.
- **Direct use is a residual (R11).** A closure is admitted whoever runs it: under `allow: [git fetch]` the agent can
  run `git rev-list` or `git maintenance run` itself. Compile prints each entry's closure.
- Only the git row carries a closure in P1; it is the only probed tool that re-execs itself. A documented row gains
  one only from a measurement.

**What is deliberately not modeled: rewriting from outside argv.** git aliases need nothing: they re-exec (measured
above). `-c alias.*` and `--config-env` are parsed as the value-taking global options they are, so the subcommand is
located correctly.

These are not seen:

- cargo `[alias]` entries and `CARGO_ALIAS_*`;
- `gh alias set` aliases;
- aws `~/.aws/cli/alias`;
- kubectl `kuberc` aliases (alpha from 1.33);
- environment variables that change parsing (`POSIXLY_CORRECT`, `GIT_CONFIG_PARAMETERS`, `NPM_CONFIG_*`).

The alternative is to treat every unknown subcommand of those tools as ambiguous. That would refuse `cargo clippy`,
`cargo fmt`, kubectl plugins and `git lfs` under any deny entry on those tools, and it would stop only an alias the
agent must first write into a config file. That is rejected option 9. These are stated residuals (R3), and compile
prints the note on the line of every entry whose tool has one.

**The generic fallback**, for a tool with no row:

- An **allow** pattern is an exact token prefix. Its words equal argv[1..k] position by position, with
  globs per token. An option before the pattern's words means no match.
- A **deny or ask** pattern matches anywhere before the first `--`:
  - its non-option words as an ordered subsequence of the tokens;
  - a long option as a token equal to it, a token that starts with it and `=`, or a prefix of it with at least one
    letter after `--` (a getopt_long abbreviation: `--forc` for `--force`);
  - a one-letter short option as `-x`, `-x<value>`, or any single-dash token of letters that contains `x`.

  This over-matches: `deny: [mytool -r]` refuses `mytool -prefix`. Compile prints the generic reading and example
  near-misses on the entry's line (9).

**Lookup failures keep their errno.** Command rules apply only to an exec whose walk reached an image. A lookup that
fails answers the lookup's own errno, as `decideExec` does today: `ENOENT` for a `PATH`-search candidate, or for
git's own probe of a dashed external (`trace: exec: git-st` above, before alias expansion). Turning that `ENOENT`
into `EACCES` would break git's alias fallback under a constrained git. The same holds for a `#!` interpreter whose
walk fails (3).

**The per-tool table.** One row per tool, as data in `pkg/policy/execmatch/rows/` with its own tests. The
authoritative description moves to a reference doc, `docs/spec/exec-command-rows.md`, because rows change with tool
releases (R4) and this ADR's text should not. Each row records the tool version, the documentation it was checked
against, and whether it is **probed** (tested against an installed binary) or **documented** (written from the
manual only). Compile prints which. The table below is the seed for P1. Rows land in this order: git, rm and the
generic fallback first (they cover the three motivating examples), then the probed rows (npm/npx, go, systemctl, interpreters
and multicall), then the documented rows.

| Row | Source at seed | Names, dashed and argv[0] forms | Before the subcommand | Subcommands | Options | Rewriting outside argv (R3) |
|---|---|---|---|---|---|---|
| git | probed 2.51.0 | `git`, `git-<sub>` (argv[0], requested or image name); identities of `/usr/bin/git` and the exec-path `git` | `-C`, `-c`, `--config-env`, `--git-dir`, `--work-tree`, `--namespace`, `--attr-source` take a value (`=` forms where git has them); `--exec-path[=]`, `--list-cmds=`; no prefixes; `--` and unknown options ambiguous | built-ins; two levels for `stash`, `remote`, `worktree`, `submodule`, `notes`, `bisect`, `config`, `sparse-checkout`, `maintenance`, `bundle`, `reflog`, `hook`; the helper closure | parse-options: permute until `--`, unique long prefixes, clusters | autocorrect is ported; aliases re-exec; hooks, pager, editor, ssh, fsmonitor and credential helpers are execs |
| rm | probed coreutils 9.5 | `rm` plus the identity of the resolved file (`gnurm` here); busybox, toybox and uutils through dispatch | (none) | (none) | `-f`/`--force`, `-r`/`-R`/`--recursive`, `-i`, `-I`, `--interactive[=]`, `-d`/`--dir`, `-v`, `--one-file-system`, `--[no-]preserve-root[=]`; permute until `--`, unique prefixes, clusters | none; coverage note: `rm -rf` does not cover `rm -r`, which does the same without a tty |
| npm, npx | probed 9.2.0 | entry scripts `npm-cli.js`, `npx-cli.js` | npm config options anywhere, read by their declared types (`--loglevel warn` takes a value; an unknown `--key` is a flag in npm 9.2 and is read both ways) | npm commands, aliases (`i`, `add`, `un`, `rm`, ...) and unique prefixes. A token that is a command or alias is that command. Any other token matches a denied name it is a prefix of. Allow needs a unique resolution | nopt: anywhere | scripts run through a shell exec (seen) |
| pnpm, yarn | documented | entry scripts `pnpm.cjs`, `yarn.js` | as npm | yarn classic `publish` and berry `npm publish` both listed | anywhere | none |
| go | probed | `go` | (none) | `build`, `run`, `test`, `install`, `get`, `mod <sub>`, `work <sub>`, `tool`, `env`, `vet`, `generate`, `clean`, `fmt`, `list`, `version`, `doc`, `fix`, `bug`, `telemetry` | Go `flag`: stop at the first operand, `-x` or `--x`, `=` or separate value; `go test` reads its flags after the package list too, up to `-args` or `--` (*amended 2026-11-01*) | none |
| systemctl | probed | `systemctl`; argv[0] forms `reboot`, `poweroff`, `halt`, and on systemctl itself any argv[0] containing one (*amended 2026-11-01*) | getopt_long value options (`-t`, `--state`, `-p`, `-H`, `-M`, `--root`, `--image`, `-o`, `-n`, `-s`, `--kill-whom`, `--job-mode`, `--what`, `--when`, `--timestamp`, `--message`) | the verb is the first operand | permute, unique prefixes, clusters | none |
| busybox, toybox, coreutils | probed where installed | multicall | (none) | the applet is argv[1] or argv[0] | the applet's row | busybox sh's in-process applets (R1) |
| python, node, sh, bash, dash, zsh, perl, ruby | probed (python3, node, sh, bash, dash) | interpreters (5) | per interpreter: options before the script, module or code | n/a | n/a | code strings (R1) |
| kubectl, oc | documented | `kubectl-<plugin>` | pflag globals anywhere: `-n`/`--namespace`, `--context`, `--cluster`, `--user`, `--kubeconfig`, `-s`/`--server`, `--token`, `--as`, `--as-group`, `--as-uid`, cert and key files, `--cache-dir`, `--request-timeout`, `--tls-server-name`, `-v` take a value | the cobra tree, three levels deep (`create secret generic`), built-in aliases | interspersed, no prefixes, bool clusters | `kuberc` aliases |
| docker, podman | documented | `docker-<plugin>` with the name repeated in argv[1] | docker `--config`, `-c`/`--context`, `-H`/`--host`, `-l`, TLS files; podman `--connection`, `--url`, `--identity`, `--root`, `--runroot`, `--storage-driver`, `--storage-opt`, `--runtime`, `--log-level` and the rest of its globals | management commands; aliases folded (`rm` = `container rm` = `container remove`; `rmi` = `image rm`) | cobra; `run`, `create` and `exec` stop at the image or container | none |
| pip | documented | `pip`, `pip3`, `pip3.N`, `python -m pip` | optparse globals before the command: `--python`, `--log`, `--proxy`, `--retries`, `--timeout`, `--exists-action`, `--trusted-host`, `--cert`, `--client-cert`, `--cache-dir`, `--use-feature`, `--use-deprecated`, `--keyring-provider` | command list | unique long prefixes; command options interspersed | none |
| cargo | documented | `cargo-<ext>` with the name repeated in argv[1]; a leading `+toolchain` (rustup) skipped | `--config`, `-Z`, `-C`, `--color`, `--explain` take a value; `--config` naming a path or `alias.` is ambiguous | built-ins and aliases `b`, `c`, `d`, `t`, `r`, `rm` | clap: interspersed until `--` | `[alias]`, `CARGO_ALIAS_*` |
| gh | documented | `gh-<ext>` | (cobra) | the cobra tree (`repo delete`, `pr merge`, `release create`, `api`) | interspersed, bool clusters | `gh alias set` |
| terraform, tofu | documented | `terraform`, `tofu` | `-chdir=DIR`, `-help`, `-version` | top level, `state <sub>`, `workspace <sub>` | Go `flag` | none; note: `apply -destroy` is a destroy |
| helm | documented | plugins run commands from their own manifests (not mapped) | `--kube-context`, `--kubeconfig`, `-n`/`--namespace`, `--registry-config`, `--repository-cache`, `--repository-config`, `--burst-limit`, `--qps`, `--kube-*` take a value | cobra tree; `uninstall` = `un` = `delete` = `del` | interspersed | none |
| aws | documented | `aws` | globals anywhere: `--region`, `--profile`, `--output`, `--endpoint-url`, `--query`, `--ca-bundle`, `--cli-*` take a value | `<service> <operation>`, s3's high-level commands | exact | `~/.aws/cli/alias` |
| gcloud | documented | `gcloud` | globals anywhere: `--project`, `--account`, `--configuration`, `--verbosity`, `--format`, `--billing-project`, `--impersonate-service-account`, `--flatten`; `--flags-file` ambiguous | optional release track (`alpha`, `beta`, `preview`), then groups and a command | exact | none |

Coverage notes come from the same rows and print on each entry's line (9). Examples:

- `git push --force` does not cover `+<ref>` refspecs, `--force-with-lease` or `--mirror`, and `git push` does not
  cover `send-pack` or `http-push`;
- `rm -rf` does not cover `rm -r`, `rm -R` or `rm -dr`;
- `terraform destroy` does not cover `apply -destroy`;
- `yarn publish` (classic) does not cover `yarn npm publish` (berry).

### (3) Enforcement per tier, and the outcome of each cell

**P1: the supervisor decides at every tier.** In `recordExec`, after the image floor and before the gate:

- **What every exec reads.** In a run whose table has command rules, every exec reads its names and argv[0], with
  `record: off` included. That is one bracketed read, within R7's budget. An exec whose argv[0] that read did not
  reach (its pointer array or string unreadable, or past the budget) is refused `args-unreadable`, guarded or not:
  no answer on the names alone holds, because argv[0] can add an interpretation and a lost one must not remove it.
  An exec that no interpretation guards reads nothing more. An
  exec that some interpretation *guards* (a command rule could match it) reads as much argv as its decision needs,
  in stages:
  1. **The prefix.** The pointer array and strings up to the located subcommand: global options, the subcommand
     token, and for dispatch rows the applet, module or script token.
  2. **The tail**, only when the decision can still change. That is when a pattern for the located tool and
     subcommand path names options or operands, when the gate scores the exec, when a reading is ambiguous past the
     prefix, or for a script form. The supervisor stops as soon as the verdict cannot change. `git push ...` is
     refused on its prefix, and `git add <9k paths>` under `allow: [git add]` is allowed on its prefix.
  3. **Batched.** Pointers are read up to 1024 per call, as one contiguous range. Strings are read with up to 1024
     iovecs per `process_vm_readv` (`IOV_MAX`), each covering up to 256 bytes. A second batch completes the longer
     strings. This replaces one call per string.

  The decision records `k`, the number of argv elements it read. P2's pin covers exactly those (below).
  supervisor.md R16 and `TestExecQuietReadsNoArgv` are amended to "reads no argv beyond what a command rule or a
  gate needs".
- **Bounds.** The tail read keeps R16's budget: 8192 arguments and `DefaultMaxArgv` (128 KiB). An exec whose
  verdict depends on a part of the tail past that budget is refused under `args-unreadable` (reason
  `exec-not-allowed`, the bound named). An exec whose decision is complete on what was read is never refused for its
  length. The gate's own 128-argument, 4 KiB bound is unchanged for gate predicates.
- **The `#!` header.** *Amended 2026-10-06:* the header is read for every exec of a run with command rules.
  As first written it was read only when a rule could be reached through an interpreter (a rule named an
  interpreter, or a ruled tool had interpreter dispatch). But any ruled binary can itself be a `#!` interpreter, and
  the kernel loads it inside the same execve, with no notification of its own: `#!/usr/bin/rm -rf` run as `./out/s
  out/tree` deleted the tree under `deny: [rm -r]`, on a line that said `allow unmatched`, and the system's own rm
  slipped past ADR 0027's mitigation for copies. Reading it costs about 3.5 µs an exec (C8).
  - The supervisor reads the image's first 256 bytes (`BINPRM_BUF_SIZE`) through **the walk's own descriptor**: it
    reopens the held `O_PATH` descriptor with `open("/proc/self/fd/<n>", O_RDONLY)`. That is a reopen of the same
    inode, never a re-resolution of the path, and an `fstat` identity check against the walk confirms it.
  - For a script, it walks the `#!` interpreter path as the task would (R16b: an absolute path, or one relative to
    the task's cwd) under `ID_VALID`. It keeps each stage's identity and repeats for an interpreter that is itself a
    script, up to the kernel's depth limit (`exec_binprm`, `-ELOOP`).
  - A failed interpreter walk answers that walk's errno, as the kernel would.
  - *Amended 2026-10-06:* the line is parsed exactly as `fs/binfmt_script.c` parses it
    (`agent.ShebangLine`): only spaces and tabs are trimmed from its end, so a CRLF line's `\r` is part of the
    interpreter's name; a NUL ends the name and leaves no argument, while a NUL after the spaces that follow the name
    is an argument that is there and empty, an empty element of the vector (*amended 2026-11-01*,
    `agent.ShebangArgv`, `Stage.EmptyArg`); with no newline in the 256 bytes the name must
    end before the last byte, or the file is no script. The first parser also trimmed `\r`, so `#!<dir>/y\r`, with
    `y` any file and `y\r` a symlink to rm, was walked as `y` while the kernel ran rm.
  - *Amended 2026-10-06:* only a regular file is reopened. The walk's `fstat` of the `O_PATH`
    descriptor gives the mode, and anything that is not `S_IFREG` keeps no header and is never opened: the kernel
    answers its exec `EACCES` before it reads a byte (`do_open_execat`), and an open of a device can act. As first
    written the reopen came before the type check, so at tier 2, where the supervisor is root, `execve("/dev/watchdog")`
    made the supervisor open a root-only device for the agent.
  - When the header read is refused (an execute-only file at tier 1), the form is `unknown`. In P1 such an exec is
    refused, rule `image-unreadable`, `EACCES`: its `#!` line could name any ruled tool, and the kernel reads it
    whatever the file's read bit says. The same holds for an interpreter whose own header cannot be read. An
    execute-only file is rare (RHEL's and Fedora's `sudo` is mode 4111, and gains nothing under the run's
    `no_new_privs`); an empty file reads as no script.
  - Identity, form and the interpreter chain are copied facts at tier 1 and the fallback. At a plane tier the pin
    binds them (P2).
- **The dynamic loader.** *Added 2026-10-06.* When the program the kernel finally runs (the
  image, or a script's last `#!` interpreter) is a dynamic loader (interpretation 7), its program is decided as the
  exec's image: the loader's vector is read in the same stages, the operand walked from the task's cwd as the loader's
  `open` walks it, and its name, image and identity are facts like the image's. Before this,
  `ld-linux-x86-64.so.2 /usr/bin/rm -rf tree` was decided under the loader's name alone and allowed unmatched under
  `deny: [rm -r]`. The supervisor fails closed, `loader-unresolved`, where it cannot read the program as the loader
  will: an option neither glibc's nor musl's loader has (a later version's option could take a value and move the
  operand), an operand with no `/` (glibc then searches library paths for it), a walk that fails, and an operand that
  is itself a loader. In a run whose images are restricted the program must be granted as an exec of it would be,
  `loader-program-unmatched` otherwise: the loader opens it `O_RDONLY` and maps it `PROT_EXEC`, which no `EXECUTE`
  right governs. A copy of a loader under another name is a new file, R2's copy.
- **Handover.** Command rules disable the fast handover until the exec is decided, as an exec gate does
  (`handOverExec`'s gate branch extends to "gate or command rules").
- **Refuse.** A refusal answers `EACCES` (`refusalErrno`) and writes the supervisor's line (8). The syscall never
  runs: the outcome is **(R)**.
- **Allow.** An allow answers `CONTINUE`. At tier 1 and on tier 2's fanotify fallback, the kernel then copies argv
  and resolves the pathname again. The allow is a copied fact, so the outcome is **(D)**. It is disclosed as the cell
  `exec.rules/argv` (D7: compile warning per tier, `run_start.best_effort`, status, drift).
- **Ask.** An `exec.ask` match is refused (5).
- **Cost.** P1's acceptance holds per-exec budgets (P1 below). A guarded exec of more than 128 arguments can exceed
  supervisor.md R22's 200 µs soft ceiling while it holds one of the default workers (R21). R22 is amended to name
  that case, and such decisions are counted in status.

**P2: at a plane tier the kernel holds the exec to the decided facts (exec pins).** The matcher is not re-implemented
in BPF. Instead the kernel checks that every fact the supervisor's decision read is the fact the kernel used. If one
differs, the exec is refused, or killed before the new program's first instruction. The supervisor stays the one
decider; the kernel enforces equality.

- **When.** Pins run in a run whose table has command rules, or an exec gate that can escalate (`MayEscalate(Exec)`).
  There, every exec the supervisor continues after arming carries a **pin**. Prepare writes the slot flag
  `TEGO_SLOT_EXEC_PIN` (0x100; ADR 0044's draft uses 0x80).
- **Arming.** The plane is armed after the stage's own exec of the tego binary and before the ack (ADR 0021 (2)).
  The agent does not exist before the ack, so its first exec (its `command`) and every later one are pinned. The
  supervisor decides every exec it is notified of, and an exec it continues before arming carries no pin.
  - In today's launcher no agent exec happens before arming, and a test asserts that no agent exec line precedes it.
  - Should one occur, its line carries `argv_facts: copied_syscall`, never `kernel_pinned`. `ExecPins()`,
    `best_effort`, the capability row and status claim pins from the arming point on, and say so.
- **Maps.** A pin crosses from the supervisor to the kernel in a per-slot inner hash, `tego_plane_exec_pins`
  (HASH_OF_MAPS by `run_idx`, inner `HASH`, `BPF_F_NO_PREALLOC`, 4096 entries, kept with the run's gen like ADR
  0025's row maps). bprm_check moves it into the task's own storage, `tego_plane_exec_armed` (TASK_STORAGE), where
  `sched_process_exec` finds it.
  - **The key** is `{tid as the launcher's pid namespace numbers it, task start time in clock ticks}`.
    - The plane computes it with `bpf_get_ns_current_pid_tgid`, the namespace identity Prepare records in the slot,
      and `current->start_boottime`.
    - The supervisor has both from the notification (whose pid is in the reader's namespace) and from
      `/proc/<tid>/stat`.
    - A tid cannot be reused while its task waits in `execve`. A reuse within one 10 ms tick needs a pid-space wrap.
  - **Time namespaces.** `/proc/<tid>/stat`'s start time is shifted by the *reading* process's time-namespace
    boottime offset, while the plane reads the raw `start_boottime`. The supervisor reads from the launcher's time
    namespace. A run whose supervisor sees a non-zero boottime offset (`/proc/self/timens_offsets`) does not pin. The
    doctor cell's time-namespace probe fails to "pins off" for that mode and the cell stays disclosed. Pins never
    turn on in a state that would refuse every exec.
  - **Why not a pidfd-keyed TASK_STORAGE write** (ADR 0044's claim form). For a non-leader thread it needs
    `PIDFD_THREAD` (6.9). That would refuse every non-leader exec (Go `syscall.Exec` shims, a Python thread's
    `os.execv`) on RHEL 9's 5.14 and AL2023's 6.1. Rejected option 13. Inside the kernel the move needs no pidfd,
    because the program stores on `current`.
- **Pin value.** `struct tego_exec_pin`, about 640 bytes. It lives only in map values and task storage, never on
  the 512-byte BPF stack. It holds:
  - `gen`, `seq` (a per-run counter);
  - `form` (direct, script, unknown);
  - `guard`: set when the exec is guarded, or when its image identity is in the run's **dispatch-sensitive set**.
    That set holds the resolved identities of every tool a rule names, including its helper images, and of every
    multicall or argv[0]-dispatching binary through which a ruled tool is reachable (git, busybox, toybox, uutils
    coreutils, systemctl);
  - `k` (the argv elements the decision read) and `argc`. A guarded exec always has `k` equal to what its decision
    read, which includes argv[0]. An unguarded exec has `k = 1` unless its guardedness itself read further (a
    multicall applet in argv[1], `python -m`, an entry script). A script form always covers the whole mapped vector;
  - The image `(s_dev, i_ino)` as the kernel holds it: fdinfo's `ino` of the walk's descriptor and the `s_dev` of
    its `mnt_id`'s superblock (mountinfo). That is the view the plane's fill already checks against, never `fstat`'s
    overlay-mapped values;
  - The requested basename and the image's final name (at most 255 bytes each; a flag when the exec named its image
    by descriptor);
  - the `#!` interpreter chain: for each stage, up to the kernel's depth limit, the interpreter's `(s_dev, i_ino)`
    taken the same way;
  - `interp_ok` (unknown form only): set when no rule of the run is reachable through an interpreter. Since every
    ruled tool can be a `#!` interpreter, that is a run with no command rules (an exec gate alone);
  - `argv0_filename` (unknown form only; *added 2026-10-19*): set when the decided argv[0] is
    the filename (`bprm->filename`'s spelling);
  - `len_cov`, `len_tail`, `mac_cov` and `mac_tail`.
- **MACs.** Both are SipHash-2-4 under a per-run 128-bit key. Prepare writes the key into `tego_plane_pin_keys`
  (ARRAY of 128 `{gen, key}` values). The launcher generates it with `getrandom` and hands it to the supervisor.
  No process of the run can read either: the plane refuses `bpf(2)` in the run, and the launcher is another uid.
  The key is never written to the ledger, the run directory or a log.
  - **Domain separation.** Each MAC's input starts with a one-byte domain tag (1: covered prefix of a direct vector,
    2: whole script vector, 3: tail), then the input's length as 4 little-endian bytes, then the bytes. No MAC of
    one kind can stand for another.
  - `mac_cov` covers the first `k` NUL-terminated strings of the vector the kernel maps. For the direct form that is
    argv. For the script form it is exactly binfmt_script's whole vector, `[interp, arg?, filename, argv[1:]...]` for
    each stage.
  - `mac_tail` covers argv[1:] (unknown form only). *Amended 2026-10-19:* it covers the
    filename, which binfmt_script and binfmt_misc put directly in front of argv[1:], then argv[1:].
  - The strings are NUL-terminated and back to back, which is the layout of `[arg_start, arg_end)`.
- **Write.** The supervisor writes the pin with `BPF_ANY`, through a seam (`ExecPinner`, (11)), after its decision
  and `ID_VALID`, immediately before `CONTINUE`.
  - A failed write refuses the exec: rule `exec.pin`, `pin_unavailable: true`.
  - A full map triggers one sweep of pins whose task is gone, then the refusal.
  - Nothing else needs a pin: a refusal, a lookup errno or a `PATH`-search candidate runs nothing.
  - A pin whose exec failed before bprm_check stays until the same task's next exec overwrites it, or until the
    sweep removes it.
- **bprm_check, first stage** (`bprm->interp == bprm->filename`). In a slot with the flag, this comes before the
  `TEGO_SLOT_EXEC_DECIDES` return and before the `#!` pass, so deny-list runs are pinned too:
  1. Clear the task's armed pin (below), so no earlier exec's state survives into this one.
  2. Look up the pin by the task's key. If it is missing, return `-EACCES` with plane reason `pin-missing`. A lookup
     error returns `pin-unverifiable`.
  3. Compare with the pin: the gen, the image's `(s_dev, i_ino)`, the dentry's final name, and the basename of
     `bprm->filename` unless the pin says the exec named its image by descriptor. For `execveat` that is the
     kernel's `/dev/fd/<n>/<name>`, whose basename is the name passed. Any difference returns `-EACCES`,
     `pin-mismatch`. A swapped symlink or descriptor ends here with a clean errno.
  4. A pin with `guard` set, of a task with `PT_PTRACED` set, returns `-EACCES`, `exec-traced`. A tracer attached
     before the exec would get the exec stop and could rewrite argv, argv[0] included, in the new image before the
     program reads it.
  5. **Move the pin into the task's own storage** (`tego_plane_exec_armed`, TASK_STORAGE, the full value, with a
     stage counter at 0 and, *since 2026-10-19*, `bprm->argc`: the vector's length as the
     kernel copied it, before any binfmt stage changes it) and delete the hash entry. The hash key cannot be used
     again: for a non-leader thread's exec, `de_thread` gives the task the leader's tid and start time before
     `sched_process_exec`, while the `task_struct`, and so its storage, stays the same. A NULL from the storage
     helper (its busy lock below 6.2) returns `-EACCES`, `pin-unverifiable`, as a NULL scratch already does in
     bprm_check.
- **bprm_check, each later stage** (an interpreter's, after a `#!` or binfmt_misc stage). Take the armed pin and
  increment its stage counter. Then:
  - Script pin: the file's `(s_dev, i_ino)` must equal the pinned chain's identity at that stage, else `-EACCES`,
    `pin-mismatch`. A stage past the pinned chain is also `pin-mismatch`. This catches an interpreter swapped
    between the supervisor's walk and the kernel's load, a `#!` line rewritten in place to name another interpreter,
    and a same-named file replaced in an agent-writable directory. Each ends with a clean errno.
  - Unknown-form pin: refused `pin-mismatch` unless `interp_ok` is set. In a run whose rules are reachable through
    an interpreter, an interpreter the supervisor did not decide never runs. *Amended 2026-10-19:* at the first later stage it is also refused `pin-mismatch` when the first handler was a
    binfmt_misc entry with the P flag (`BINPRM_FLAGS_PRESERVE_ARGV0` in `bprm->interp_flags`) and `argv0_filename` is
    clear. That handler keeps argv[0] in front of the tail, where the tail holds it only to the filename.
  - Direct pin: any later stage is `pin-mismatch`. binfmt_misc took an image the supervisor read as direct (R6c).
- **`tp_btf/sched_process_exec`** is a new plane program, loaded in both modes alongside the recorder's. It runs
  after the binfmt load and before the return to user mode, with `current->mm` the new image's:
  - Take the task's armed pin. If there is none, kill.
  - `interpreted := bprm->interp != bprm->filename` (the recorder's marker).
  - **Direct pin, not interpreted.** Read `len_cov` bytes from `arg_start`. The last must be NUL, and `mac_cov` must
    equal the MAC over them. When `k = argc`, also require `arg_end - arg_start == len_cov` and `bprm->argc ==
    argc`.
  - **Script pin, interpreted.** Require `arg_end - arg_start == len_cov` and `mac_cov` over the whole area (each
    stage's interpreter identity was checked at its stage).
  - **Unknown form.** If not interpreted, check it as direct. If interpreted (and admitted by `interp_ok`), check
    `mac_tail` over the last `len_tail` bytes, whose preceding byte must be a NUL. *Amended 2026-10-19:* the first stage's `bprm->argc` must equal `argc` first. Without it a racing thread could put
    arguments in front of the decided argv[1:] and keep the area's last bytes. With it, the last `len_tail` bytes
    after a NUL are exactly the area's last `argc` strings (the decided tail holds `argc` NULs), which binfmt filled
    with the filename and argv[1:].
  - **Any other form mismatch is a mismatch.** An ELF the supervisor read that the kernel then interprets, or the
    reverse, means the file changed under the decision, or binfmt_misc took it (R6).
  - **On a mismatch, an unreadable area or a missing pin:** `bpf_send_signal(SIGKILL)`, and the plane's kill sample
    with plane reason `argv-changed`, `argv-unreadable` or `pin-missing`. SIGKILL is pending before the return to
    user mode, so the new program runs no instruction. The exec itself has completed and the old image is gone
    (R6d).
  - **If `bpf_send_signal` returns an error**, the kill sample carries `kill_failed` and the error. For a user task in
    process context the helper should not fail. Its failure paths are a kernel thread or global init, a failing
    `nmi_uaccess_okay`, and a busy irq_work in IRQ or NMI context. K0 must show zero send failures on every matrix
    row.
    - On a `kill_failed` sample, the supervisor sends SIGKILL through the task's pidfd and writes a **detected
      bypass** (8). That is a late backstop, not a guarantee: the program may run some instructions first.
    - Putting argv enforcement at the only hook that can read the kernel's argv, and so making it kill-only, is an
      accepted inherent limit (R6h).
  - **On a match:** record the outcome in the task's storage, then delete the armed pin. If `guard` is set, mark the
    task argv-guarded. Every exec rewrites the mark.
  - **The MAC loop** is a `bpf_loop` callback, a global function verified once, as `decide.bpf.c` already does.
    The plane needs `bpf_loop` anyway, so a 5.14 row without the backport has no plane at all. The loop reads the
    area in 256-byte chunks through `bpf_probe_read_user` into the task's own storage buffer, as
    `tego_plane_path_buf` does, never a per-CPU buffer (a preempted program shares it). It is bounded by `len_cov`,
    at most 128 KiB. Without `bpf_loop`, 128 KiB of SipHash would be about 16k words at 50 to 60 instructions each,
    near the verifier's 1M limit. The program builds in both reader builds (`TEGO_PLANE_RDONLY` 0 and 1).
- **After the check.** The plane's `ptrace_access_check` and `ptrace_traceme` also refuse, `process-scope`, when the
  target is argv-guarded. In ATTACH mode `ptrace_access_check` covers `PTRACE_ATTACH`/`SEIZE`, `process_vm_writev`,
  `process_vm_readv` and `/proc/<pid>/mem`. Today these hooks admit any peer of the same run and gen. With the mark,
  a guarded process's argv, argv[0] included, cannot be rewritten between the check and its `main`. (An open
  `/proc/<pid>/mem` descriptor from before the exec names the old mm, which the exec released.) *Amended 2026-10-19:*
the mark is stored on the task that exec'd, which `de_thread` makes its thread group's
  leader, and a thread the new program starts later shares the leader's mm with no mark of its own; so the hooks
  read the mark of the target and, when the target is another thread, of its group leader.
- **Off.** A task in no run returns after the run-set lookup the recorder already pays. A run without the flag
  returns after one header read.

**Outcomes per cell.** The tiers are ADR 0041 D1's: L landlock, C⊘ cgroup fanotify fallback, C+ cgroup with a plane,
and B bpflsm.

| Rule → action | L | C⊘ | C+ | B |
|---|---|---|---|---|
| `exec.deny` or constrained `exec.allow` → an exec whose copied facts match (refuse) | (R) | (R) | (R) | (R) |
| `exec.ask` → match | (R), `completion_unsupported` | (R) | (R) | (R) |
| the same rules → an exec allowed on copied facts (argv and names) | (D) `exec.rules/argv` | (D) | (D) until P2. With P2, **kernel-pinned** after arming: bprm_check `EACCES`, or SIGKILL before the first user instruction | same as C+ |
| gate `exec matches` → an exec allowed (argv and names) | (D) `gate.exec` | (D) | (D) until P2; with P2, kernel-pinned | same as C+ |
| gate → score in the ask range | ADR 0044: (R) unsupported | (R) | ADR 0044's retry | same as C+ |
| a guarded process's memory, by another process of the run | not governed | not governed | P2: refused (`ptrace_access_check`) | same |

"Kernel-pinned" is neither (A) nor (D) in ADR 0041's sense. The supervisor still answers `CONTINUE`, but the kernel
refuses any exec, after arming, whose covered facts changed. So the decision binds what runs, which is the property
(A) exists for. The cell leaves `best_effort` exactly when the run's handle reports `ExecPins()`.

**`exec.assurance: kernel`** (P2). Like `fs.assurance` and `net.assurance`, it is opt-in and defaults to
`best-effort`. It refuses the run before the child starts (exit 125) unless the selected tier pins execs. A contract
with no command rules and no exec gate gets a `redundant-rule` warning.

### (4) The decision core and `compile --test`

- **The core.** `internal/policy/decide` gains `ExecCommand(rt, facts) CommandResult`. The result carries the
  verdict, the rule, the list, the match (`definite` or `ambiguous`), the interpretation that decided, and `k`. The
  supervisor and `compile --test` both call it (ADR 0028: one core).
  - `RuleTable` gains `ExecCommands`: compiled patterns **indexed by tool**, the constrained-tool set, the helper
    closures, the dispatch-sensitive identity set, and resolved identities with their link counts.
  - Normalization runs once per exec per row, never once per rule. An exec whose tool has no pattern costs one index
    lookup.
- **Rows.** `compile --test` exec rows already carry `path`, `argv` and `script:` (`testtable.go`; `decide.evalExec`
  reads `script:` as the `#!` interpreter path). P1 extends `script:` with an optional `script_arg:`. Each row runs
  through the floor, then `ExecCommand`, then `EvaluateGateRow`.
- **One-liner.** `tego compile c.yaml --exec 'git -C . push'` parses the argument with the pattern spelling of (1)
  and prints each interpretation, its readings, `k`, and the deciding rule per tier column. No YAML table is needed
  to try one command. A command given by path has its `#!` line read as the row's `script:` and `script_arg:`
  (amended 2026-10-06).
- **Cells.** A cell gains `command_rule`, `command_match` and `argv_facts`. `argv_facts` is `test_row` here, and
  `--json` reports `argv_assurance: copied|kernel` per column. The plane column says `kernel` with the note "if the
  run's plane pins execs (doctor's pin cell)". *As built in P1:* `copied` in every column, the plane's included,
  since no tier pins exec facts until P2.
- **Asks.** A gate ask-range cell reads as ADR 0044 sets it per column. An `exec.ask` cell is `refused` with
  `completion_unsupported` in every column.
- **No answers.** `compile --test` never supplies a human answer.

### (5) The gate and `exec.ask` share the matcher

- **The gate's `exec matches "<p>"`.** It matches when the legacy glob matches, as today, **or** when `p` parses as a
  command pattern whose command word has no glob and that pattern matches under (2)'s deny semantics. That is the
  union, so no gate rule matches less than before. `exec matches "rm -rf": 95` now also scores `rm -fr`,
  `rm --recursive --force` and `busybox rm -rf`. The gate still only escalates. gate.md R2 is amended.
  - **Upgrade visibility.** Existing gate rules start matching more (`rm -fr`, `npm i`, `git -C . push`, autocorrect
    reach). That fails closed, but it is a behavior change. The CHANGELOG says so. Compile lists each existing gate
    rule whose reading broadened, with example near-misses.
  - **What the gate reads.** `gate.Action` carries names and argv only, with no identity and no `#!` form. So the
    gate's command reading uses interpretations 1, 3, 4 and 5, not 2 or 6.
  - **An overflow matches** (*amended:* the gate compared each interpretation's tool
    to the rule's, and the `ViaOverflow` sentinel names none, so `busybox` nested past the dispatch depth then
    `rm -rf x` escaped `exec matches "rm -rf"` where `busybox rm -rf x` met it, in a run with gate rules and no
    `exec:` command rules, where the gate is the only check). A reading that ends in the sentinel scores as a match
    of every command-pattern rule: the readings that were dropped may reach any of their tools, and the worst case of
    them is that all match. Each rule adds its own weight, so a light rule asks rather than refuses. Rejected:
    refusing such an exec as `gate.unreadable` at the maximum score (a contract whose only exec rule weighs 60
    would refuse what its author scored as an ask). A legacy glob rule reads no interpretations and is unchanged
    (`TestExecMatchesFailsClosedOnOverflow`).
  - Gate rules are indexed by first word, so 256 rules do not each re-normalize.
- **`exec.ask` is reserved.** P1 parses and validates `exec.ask` entries, and every match is refused at every tier:
  reason `exec-not-allowed`, rule `exec.ask[<entry>]`, `completion_unsupported: true`.
  - Compile prints, per entry and per tier, "ask → refuses here (completion_unsupported)". It warns `unenforced`
    once for the list.
  - This does not amend ADR 0044. Its Rejected option 11 stands: an `exec.ask` list's floor is refused, so a
    one-shot claim would have to admit rather than narrow, and that would break 0044's only-narrowing argument.
  - A later amendment to 0044, may give list asks a completion. It must state how the
    claim composes with the refused list floor and restate 0044's security argument.
- **What pins offer ADR 0044**, not decided here. Under pins, a gate-approved retry could be held to the approved
  argv by its own pin. That would remove 0044's `argv-unproven` case in pinned runs, and the pin map's `(tid,
  start)` key would remove 0044's residual 4 (non-leaders below 6.9). If 0044 is built first, its claim and P2's pin
  are written side by side.

### (6) Best-effort cells

`BestEffortCellsAt` gains `exec.rules/argv`, listed when the table has command rules and the run's handle does not
pin execs. `gate.exec` stays listed under the same condition and leaves the list when the handle pins execs. The
compile warning goes out once per tier where it can hold (`Diagnostic.Tier`):

- landlock: "best effort: argv is copied";
- cgroup: "best effort unless the decision plane pins execs (doctor's pin cell); on the fanotify fallback, best
  effort";
- bpflsm: "kernel-pinned when doctor's pin cell passes, else best effort".

### (7) What the plane gains (P2), for ADR 0024

- **Programs.** `tego_plane_exec_pin` (`tp_btf/sched_process_exec`, both modes); the bprm_check first-stage and
  later-stage steps; and the argv-guarded refusal in `ptrace_access_check` and `ptrace_traceme`.
- **Maps.** `tego_plane_exec_pins` and `tego_plane_pin_keys`, both pinned, root-only, and cleared per slot by
  Detach, the reaper's purge and the next Prepare. `tego_plane_exec_armed` (TASK_STORAGE) holds a task's armed pin,
  its stage counter, its last outcome and its argv-guarded mark. Each value carries `run_idx` and `gen`, so a value
  from another run or gen reads as absent.
- **Codes and samples.**
  - New plane reason codes: `pin-missing`, `pin-mismatch`, `pin-unverifiable`, `argv-changed`, `argv-unreadable`,
    `exec-traced`. They take the next free numbers at merge.
  - A bprm_check refusal is the existing `TEGO_EV_PLANE_EXEC` sample.
  - A kill is a new sample kind, `TEGO_EV_PLANE_EXEC_KILL`. It carries `seq`, the reason, and `kill_failed` with
    the helper's error.
- **ABI.** `tego_ev_exec` gains `pin_seq` (u32, appended). The ring ABI steps once (`TEGO_EVENTS_VERSION`, the
  next free number at merge).
- **Doctor.** An optional known-answer cell, `plane.exec_pin`, in the class ADR 0044 adds to R21:
  1. a pinned exec of identical facts runs;
  2. an exec with no pin gets `EACCES`;
  3. a pin whose `mac_cov` differs is killed with SIGKILL before the probe binary's first `write` (its first
     instruction writes to a pipe, which must stay empty);
  4. a pin whose image identity differs gets `EACCES`;
  5. a pin whose interpreter identity differs gets `EACCES` at the interpreter's stage;
  6. a traced exec with `guard` set gets `EACCES`, for a `k = 1` dashed-form exec (`exec -a git-status`) as well as
     a long vector;
  7. `process_vm_writev` into an argv-guarded probe is refused, including into argv[0] of a `k = 1` probe;
  8. the time-namespace probe: the supervisor's start time and the plane's agree. If not, the cell fails to "pins
     off".

  The mode's cache entry keeps the cell's result. The run's handle reports `ExecPins()` when its slot carries the
  flag and the cell passed.

### (8) The record (ADR 0016)

**Producers.** One line per action (ADR 0016 (4), (5)):

| Action | Producer | Line |
|---|---|---|
| refused by a command rule (any tier) | supervisor | `exec`, `refused`, authority `rule`, reason `exec-not-allowed`, rule `exec.deny[<entry>]`, `exec.ask[<entry>]` or `exec.args[<tool>]` (unlisted under a constrained tool), plus the fields below |
| allowed, tier 1 or the fallback | supervisor, as today | `allow`, the copied argv, `argv_facts: copied_syscall` |
| allowed, plane tier, kernel recording live | kernel terminal line, named by the supervisor (T16) | `allow`, with `argv_facts: kernel_pinned` only under the fold rule below |
| refused by a bprm_check pin step | the plane's exec sample, folded into the exec's one terminal line as §2.19 folds every plane refusal | `refused`, reason `exec-not-allowed`, rule `exec.pin`, `plane_reason` |
| killed at sched_process_exec | the plane's kill sample, folded by `(run, seq)` | `refused`, rule `exec.pin`, `plane_reason`, `argv` = the kernel's mapped argv (512 bytes, truncation marked), `argv_decided` = the supervisor's copy, `signal: SIGKILL` |
| kill attempted, send failed | the plane's kill sample (`kill_failed`), then the supervisor's pidfd kill | `refused`, rule `exec.pin`, `plane_reason`, `kill_failed: <errno>`, `detected_bypass: true`; the run gains the integrity gap `exec-pin-kill-failed` |
| pin write failed | supervisor | `refused`, rule `exec.pin`, `pin_unavailable: true` |

**The fold is fail-closed.** It keys on `(run, seq)`. `seq` is unique per run, and unlike `(tid, start)` it survives
`de_thread`.

- A kill sample for `seq` S always makes S's terminal line `refused`, whatever success record arrives. If no
  success record for S arrives, the kill sample produces its own kernel-producer `refused` line.
- A success record whose `pin_seq` is S gets `argv_facts: kernel_pinned` only after the observer has drained the
  ring past it with no kill sample for S. The pin program and the recorder run in the same tracepoint invocation
  on the same CPU, so the kill sample, if any, is reserved within the same window.
- A ring loss (ADR 0016's lost-sample gap) in that window, or a success record whose `pin_seq` does not match the
  naming's, gives the line `argv_facts: unproven`. The run gains the gap `exec-pin-unproven`. No line in a window
  with loss claims `kernel_pinned`.
- An exec line never says `allow` for an exec the mechanism killed: the verdict is what the mechanism answered
  (ADR 0016).

**Fields.** Additive and optional on `exec` and `refused` lines, in one `record_minor` step (the next free number at
merge):

- `command_rule`: the entry as compiled;
- `command_list`: `deny`, `ask`, `allow` or `unlisted`;
- `command_match`: `definite` or `ambiguous` (absent on an unlisted refusal, which no entry matched; *amended
  2026-10-06, second review*);
- `command_via`: `name`, `image`, `argv0`, `identity`, `dashed`, `multicall`, `interpreter`, `shebang` or `closure`
  (with `closure_of`: the allowed entry whose helper closure admitted it), and *(added 2026-10-06)* `loader`, the program a dynamic loader run as a command runs in-process (interpretation 7), and `overflow`, a dispatch the matcher could not resolve within its
  depth or interpretation bound;
- `argv_facts`: `copied_syscall`, `kernel_pinned` or `unproven`;
- `argv_read`: how many argv elements the decision read (*added 2026-10-06, second review*: P1 writes it,
  and this list did not name it);
- `argv_decided`, `pin_unavailable`, `kill_failed`, `detected_bypass`.

`RefusedPayload` gains `command_rule` and `command_match`. `plane_reason` gains P2's values; it is an open field.

**What stays the same.** `reason`'s closed set is unchanged: REASON-CHANNEL says "the rule name carries the
specifics". *As built in P1 (2026-10-06):* besides `exec.deny[<entry>]`, `exec.ask[<entry>]` and
`exec.args[<tool>]`, a command-rule refusal's `rule` is one of the sentinels `args-unreadable` (the bound),
`interpreter-unresolved` (a `#!` interpreter's walk failed; its errno), `image-unreadable` (R13),
`loader-unresolved` (a loader's program cannot be read as the loader will: an option neither loader has, an operand
with no `/`, a walk that fails, an operand that is itself a loader), `loader-program-unmatched` (in a run whose
images are restricted, no `exec.allow` entry grants the loader's program) and `command-unresolved` (a dispatcher
re-dispatches deeper than the matcher resolves, so the applet it runs could be a denied one), each `exec-not-allowed`
with `EACCES`.
REASON-CHANNEL, the record README and supervisor R29 list them. `run_end` gains `exec_rules{refused, ambiguous, asked, killed, kill_failed, pin_refused}`, additive.

**Who sees it.** `status` and `events` print the cell and the fields. `drift` treats the lists differently:

- **Deny and ask entries are guards.** An entry that no line named in the window is reported as "guard not
  exercised", an informational bucket like `UnobservableFS`. It never makes `Drifted()` true, since a run where the
  agent behaved leaves every deny entry unfired. Their refusals count as refusals.
- **Constrained allow entries** are tracked one by one through `command_rule`, so `git status` and `git log` each
  report their own use and an unused one is undone. *Amended 2026-10-06:* this is
  use tracking, not a per-entry verdict count: an allowed exec's `allow` count sits on the image floor's rule (the
  line's `rule`, `exec[git]`), the one entry the ledger line names, since a constrained allow does not change the
  verdict. A helper admitted by an allowed entry's closure (R11) marks that entry used, through `command_rule` (the
  `closure_of` entry), because the grant did admit it.

### (9) Compile, capabilities, doctor

- **Compile's print.** One line per command pattern, followed by its notes, then the mode line of (1). Each line
  gives the list, the canonical form, the row with its version and source (probed or documented, or "generic"), and
  the exact reading. The notes under it:
  - near-misses it also matches: git autocorrect tokens, npm prefixes, option abbreviations, generic over-matches;
  - for an allow entry, the helper closure it admits and the helper images it grants;
  - The coverage notes of (2) and the R3 note for its tool.

  For example:

  ```
  exec deny  git push       row git 2.51.0 (probed)   subcommand push; any options and operands
             also refuses (autocorrect): psh, psuh, pusg, puhs, Push
             not covered: send-pack, http-push
  exec allow git fetch      row git 2.51.0 (probed)   subcommand fetch; any options and operands
             also admits (helpers): maintenance, rev-list, index-pack, remote-https, git-remote-https
             grants: /usr/lib/git-core/git, /usr/lib/git-core/git-remote-https
  exec allow git log --oneline  row git 2.51.0 (probed)  subcommand log; requires --oneline; every other option free
  ```

  Notes stay on the print line, so a contract with many entries does not drown in warnings.
- **Diagnostic codes.** Only error and warning severities exist (`diagnostic.go`), and warnings exit 0. So warnings
  are kept for findings an author can act on. Two new codes:
  - `exec-rule`. Error: syntax, bounds, shell operators, a `/` in a deny or ask command word, a directory with words,
    an unquoted path with spaces, or a deny or ask entry that matches the contract's `command`. Warning: `$` or a
    backtick in a word, an empty deny-list section, or a deny entry that matches an `mcp[].command`.
  - `exec-rule-coverage`, warning only:
    - deny-list mode with any `fs.write`; *amended 2026-10-16:* and deny-list mode without one,
      whose warning names the memfd, the deleted file and the mapped program;
    - a constrained tool shadowed by an implicit grant;
    - an allow entry that names options (they are required, not whitelisted).

  The `fs.write` warning says it outright: "the agent can write files and run them; a copy of git under another name
  is not git to these rules; restrict images with `exec.allow` (and a plane tier for native code under write
  entries, ADR 0027)".
- **Existing codes.** `redundant-rule` covers a constrained allow beside a bare one, and a deny made unreachable
  because the image floor never grants the command. `unenforced` covers (6)'s cells and `exec.ask`.
- **Capabilities.** One row is appended last (R23): "exec command rules: argv". Cells:
  - landlock: "best effort (copied argv)";
  - cgroup: "conditional (decision plane with exec pins; best effort on the fanotify fallback)";
  - bpflsm: "conditional (doctor's pin cell)".

  `run_start.capabilities` sets it true only when the run's handle reports `ExecPins()`. `TestMatrixGolden` holds
  the md/go pair.
- **Doctor.** (7)'s cell, printed under the plane's clause.

### (10) What this amends

- **ADR 0007's note.** The gate's exec predicate reads command patterns too (5). It is still escalation only.
- **ADR 0016 (4).** (8)'s producers and fold. A kill is the kernel's line with the kernel's argv. The decided copy is
  kept beside it, never in its place.
- **ADR 0019.** (4)'s cell fields and one-liner; (6)'s per-tier warnings.
- **ADR 0024.** (7)'s program, steps, maps, codes and ABI step. A kill is the plane's own sample under (11), as
  bprm_check's refusals are. It is the only refusal possible after the point of no return.
- **ADR 0041 D1.** (3)'s table rows. The context table's "exec: argv — no, at any tier" becomes "no at L and C⊘;
  kernel-pinned at C+ and B once P2 runs, from the arming point".
- **Specs.**
  - SEMANTICS §1 (deny-list mode and the mode table), §3 (precedence), and §4 (a new subsection, "Command rules").
  - agent-contract: R2's consumed set gains `exec.deny`, `exec.ask` and P2's `exec.assurance`. R8 gains (1)'s
    classification. A new rule covers the matcher.
  - gate.md R2. supervisor.md R16, R16b and R22. enforce-plane: a new §2.21 and rules. record-ledger. The record
    README. CAPABILITIES. REPO-LAYOUT.
  - The new reference doc `docs/spec/exec-command-rows.md`.
  - FEATURES: S1's field list, and a new E-row "exec command rules".

### (11) Interfaces

```go
// pkg/policy/execmatch (stdlib only)
type Pattern struct{ /* compiled; constructed by Parse */ }
func Parse(entry string, list List, rows *Rows) (Pattern, error) // List: Allow | Deny | Ask; parsed with the row
type Stage struct{ Path, Arg string; Dev, Ino uint64 }
type Facts struct {
	Requested, Image, Argv0 string // basenames; Requested "" for an fd-named image
	Dev, Ino                uint64
	Form                    Form    // Direct | Script | Unknown
	Interp                  []Stage // the #! chain, Script form
	Argv                    [][]byte
	ArgvComplete            bool // false when Argv is a prefix
}
func Interpretations(f Facts, ids IdentityTable) []Invocation // (2)'s set; allocation-bounded
func (p Pattern) Match(inv Invocation) Match                   // None | Definite | Ambiguous
func (ix *Index) Need(f Facts) (guarded bool, need Need)       // which execs need argv, and how much (prefix, tail)
func Autocorrect(token string, c *Candidates) (target string, ok bool) // the help_unknown_cmd port

// internal/runtime/supervisor (primitive types only; depguard supervisor-imports holds)
type ExecPinner interface {
	ExecPins() bool
	Pin(tid uint32, startTicks uint64, pin []byte) (seq uint32, err error) // the encoded struct tego_exec_pin
	Sweep(live func(tid uint32, startTicks uint64) bool) error
	Kill(tid uint32, startTicks uint64) error // the pidfd backstop for a kill_failed sample
}
```

`Options` gains `ExecPinner` (nil: no pins) and the run's MAC key. `internal/runtime` adapts the cgroup or bpflsm
handle to it, as it does `KernelExecs`. `ExecNaming` gains `PinSeq`, `CommandRule`, `CommandMatch` and `CommandVia`.

## Why

**[documented, code]**

- gate R2's matcher works on joined strings and literal prefixes (`pkg/policy/gate/gate.go` `Evaluate`, `matches`).
  It cannot locate a subcommand behind options, and its own text calls its facts "a notification-time snapshot".
- The supervisor already reads, under `ID_VALID`, every fact (2) needs: the pathname, argv, and the walk's link and
  identity. It already disables the fast handover for scored execs. So P1 adds a decision and a staged read, not a
  new read path.
- The recorder already reads the kernel's argv at `sched_process_exec` with `bpf_probe_read_user`, which lockdown
  allows in both builds (`trace_proc.bpf.c`'s header). The plane already compares an exec's inode, directory and
  name at bprm_check, keeps per-slot inner maps with a gen, and refuses ptrace by run.
- "No `exec:` section" is one bit spelled at eight places: the `ExecUnrestricted()` method and seven direct
  `Contract.Exec == nil` tests. Deny-list mode changes the bit, so P1 must make every place ask the method. A missed
  one would split the enforcers.
- `Canonical` drops empty slices, and `FSSection`/`EnvSection` show that a dropped empty list can flip a recompiled
  contract's meaning. The mode bit must be carried by key presence and kept by `MarshalYAML`.

**[documented, kernel, P2's first commit verifies each on every matrix row, both modes]**

- `bprm_check_security` runs before `begin_new_exec`'s `exec_mmap`. At that point the kernel's copy of argv is in
  `bprm->mm`, which no task runs, and no non-sleepable helper reads another mm. So bprm_check can compare names and
  identity but not argv (0044 says the same). It runs once per binfmt stage, so each interpreter's identity can be
  compared at its own stage.
- `begin_new_exec` sets `point_of_no_return` before `exec_mmap`. After it, an LSM error becomes a forced SIGSEGV,
  and `bprm_committing_creds` is void. So an argv refusal after the copy can only be a kill.
- `sched_process_exec` fires in `exec_binprm` after the binfmt load, with `current->mm` the new image's and
  `[arg_start, arg_end)` its argv. The recorder reads exactly that.
- binfmt_script maps `[i_name, i_arg?, filename, argv[1:]]`. binfmt_misc maps `[interpreter, filename, argv[0]
  (P flag), argv[1:]]`. Both keep argv[1:] as the tail, which `mac_tail` relies on. *Amended 2026-10-19:* both put the filename directly in front of it, except binfmt_misc's P flag, which puts argv[0]
  there and sets `BINPRM_FLAGS_PRESERVE_ARGV0` (since 5.12) before the interpreter's bprm_check.
- `bpf_send_signal` is offered to tracing programs. It fails only for a kernel thread or global init, a failing
  `nmi_uaccess_okay`, or a busy irq_work in IRQ or NMI context. A pending SIGKILL is acted on before the return to
  user mode. A ptrace exec stop with a fatal signal pending does not let a tracer freeze the task:
  `ptrace_freeze_traced` refuses under `__fatal_signal_pending`.
- `ptrace_access_check` is the hook behind `PTRACE_ATTACH`/`SEIZE` and behind `mm_access` (`process_vm_readv`,
  `process_vm_writev`, `/proc/<pid>/mem`). `PTRACE_POKEDATA` by a tracer attached before the exec does not pass it,
  hence bprm_check's `exec-traced` step.
- `de_thread` ends every other thread of the exec'ing process before `exec_mmap`, and the new mm is private to the
  task until it runs. For a non-leader exec, `de_thread` also gives the task the leader's pid and `start_boottime`,
  on the same `task_struct`. So a key by tid and start time is valid only before it (bprm_check), and task storage
  carries the pin across it.
- `/proc/<pid>/stat`'s start time is reported through the reader's time namespace, so it carries the reader's
  boottime offset.

**[measured, the test machine, 2026-10-06]** The table under Context:

- git aliases re-exec, autocorrect runs in process to a unique best candidate only, and git re-execs a different
  inode for its helpers;
- git abbreviates long options and dispatches on argv[0];
- GNU rm permutes and abbreviates, and `rm -r` without a tty does what `rm -rf` does;
- npm abbreviates commands and reads options by declared type;
- `/usr/bin/rm` resolves to `gnurm`, and the uutils multicall binary has 115 links;
- one `process_vm_readv` per string costs about 1 µs.

**[documented, product]**

- SEMANTICS §3: lists decide in the kernel, the gate only escalates, and nested runs union deny and ask lists.
- ADR 0041's principle: a refusal on copied bytes is honest; an allow is disclosed or completed.
- ADR 0044's Rejected option 11.

**[inference]**

- A command rule names what a program is asked to do, and only the program's grammar knows where that word is. A
  per-tool table plus a fail-closed generic reading is the smallest thing that is correct for the common tools and
  safe for the rest.
- Enforcing equality of facts in the kernel, instead of re-deciding there, keeps one implementation of a matcher
  that has to evolve with tools. The BPF side stays small enough to verify on 5.14.

### Security argument

- **The refusal direction is exact for every invocation the matcher interprets, at every tier.** An invocation is
  interpreted when its copied facts are read by one of (2)'s interpretations: names, identity, dashed forms,
  multicall dispatch, the named interpreter entry points, and the `#!` chain. If such an invocation matches a deny
  entry, the supervisor refuses it before the syscall runs. A refused exec never runs, so a race cannot help it.
  Some effects are not an invocation of the named command at all, and this claim says nothing about them: an
  in-process effect (R1), a renamed or copied binary (R2), rewriting from outside argv (R3), and an interpreter form
  outside the tables (R9). The fs and net rules bound those.
  *Amended 2026-10-06:* the claim holds only because nothing escapes the decision. In a run with command
  rules the supervisor continues no exec unless its walk reached an image that the rules then decided. A failed
  walk or an unreadable pathname is answered by the loop (`unwalkedExec`), never continued for the kernel's own
  lookup to resolve again. Every image's `#!` line is read, since any ruled tool can be the interpreter the kernel
  loads inside the same execve. An image whose line cannot be read is refused. A decision on an argv prefix never
  reads the prefix's end as the command line's end (a level's default subcommand). The review that found these four
  gaps is in the implementation notes.
- **P2 binds the allow direction at plane tiers, from the arming point.** In a run whose handle reports
  `ExecPins()`:
  - Every exec after arming needs a pin. A missing pin refuses at bprm_check or kills at sched_process_exec.
  - A pin holds every fact the decision read: identity and names (compared at bprm_check); the form and each
    interpreter's identity (compared at its own stage); and the first `k` argv elements (compared at
    sched_process_exec on the kernel's own copy).
  - Guardedness and the verdict are functions of exactly those facts. Elements past `k` were not read, and by the
    staging rule of (3) they cannot change the verdict. So a race that would change the verdict must change a
    covered fact, and the kernel then refuses or kills.
  - After the check, a pin with `guard` set (every guarded exec, and every exec of a dispatch-sensitive image)
    protects its covered argv, argv[0] included, until `main`. A pre-attached tracer meets `exec-traced`, and a
    peer's attach, `process_vm_writev` or `/proc/<pid>/mem` meets the argv-guarded refusal.
  - So within that scope the kernel runs only an exec whose decided facts it verified, or nothing. Execs before
    arming (none of the agent's in today's launcher), and runs or tiers without `ExecPins()`, stay (D) and say so.
- **The kill can fail.** If `bpf_send_signal` fails, the exec runs. The line still says refused with
  `detected_bypass`, the run carries a gap, and the supervisor kills the task late. K0 must show this never happens
  on a supported row (R6h).
- **The MAC.** It is keyed, and the key never enters the run. SipHash-2-4 is a PRF built for exactly this
  adversary: one who picks the inputs and wants a collision without the key. An unkeyed hash fails here (rejected
  option 6). Lengths are compared separately, and a domain byte separates covered-prefix, script and tail MACs.
- **Only narrowing.** No new path returns 0 because of a pin. The bprm_check steps and the new program only refuse,
  and the record fold only turns `allow` into `refused` or `unproven`. A bug in pins costs availability, never a
  grant. The P2 source tests hold this, as for ADR 0044's claims.
- **Interpretations only add.** argv[0] spoofing, dashed names, dispatch and autocorrect add readings, and the
  strictest reading wins. The autocorrect port uses a subset of git's candidates, so it reaches every target git
  reaches.
- **Fail closed on ambiguity.** Unknown options keep both readings (*amended 2026-11-01:* also in front of an
  interpreter's script, which is its subcommand, so a row that is a leaf still forks there), and visible rewrite triggers make an
  interpretation unlocatable. Deny and ask entries match any reading; a constrained allow needs every reading.
- **Fail closed on dispatch overflow.** Interpretations are bounded (a dispatch depth and a count). A dispatcher the
  bound stops before it resolves — a multicall binary that re-dispatches to itself, busybox's own `busybox` applet
  nested past the depth, or a fan-out that reaches the count — could still reach a ruled tool, so the matcher leaves
  an overflow sentinel and the exec is refused `command-unresolved`, never read as unmatched. The
  bound is an argv-length-style limit (R7), not a place to fail open. *Amended 2026-10-16:* the count is held where
  every interpretation is added, so any distinct interpretation past it (a name, a `#!` stage, a dispatch) overflows,
  not only a dispatcher the loop stops; and a directly-invoked loader's program, read by a nested pass, passes that
  pass's sentinel on. Both had been dropped in silence (the count kept the first 32 and the exec was decided on them;
  the nested sentinel names no tool and was discarded when re-added).
- **The helper closure only widens the allow side, and by a fixed list.** It never exempts an exec from a deny
  entry, and it is data measured per version, not a property an agent can steer through config (rejected
  option 18).
- **Out of scope** (ADR 0024 (15)): root outside the run can write pins or detach the plane.

### Adversarial checks

- **`git -C . push`, `git -c push.default=x push`, `git --git-dir=.git push`, `git 'push'`?** Located by git's row:
  denied.
- **`/usr/lib/git-core/git-push`, `exec -a git-push git`?** Dashed form: denied.
- **`git -c alias.p=push p`?** `p` is not a built-in. git re-execs `git push` (measured), and that exec is denied.
  Under a constrained git, `p` is unlisted, so it is refused at the first exec.
- **`git -c help.autocorrect=immediate psuh`?** The port corrects `psuh` to `push`: ambiguous, denied.
- **`git lfs`, `git gui`, `git sh` under `deny: [git push]`?** The port does not reach push (`lfs` → refs): not
  matched. These are external commands that run as their own execs.
- **`git pυsh`, `git Push`, `git 'push '`?** git compares bytes, and none is a built-in. The port corrects each to
  push (measured): denied.
- **`git stash push` under `deny: [git push]`?** The subcommand path is `[stash, push]`: not matched (correct).
- **`rm -fr`, `rm x --rec --forc`, `rm -Rf`, `busybox rm -rf`, `/usr/bin/gnurm -rf` with argv[0] `gnurm`?** Option
  set, abbreviations, multicall dispatch and identity: denied by `rm -rf`, and by `rm -r`. `rm -r x </dev/null` is
  denied by `rm -r` only, which is why the examples use it. `rm -- -rf` (a file named `-rf`) is allowed, because
  after `--` it is an operand.
- **`kubectl -n prod delete pod x`, `kubectl --context=c delete`?** pflag globals located: denied.
- **`npm pub`, `node /usr/share/nodejs/npm/bin/npm-cli.js publish`, `npm --foo publish`?** Prefix, entry script, and
  the flag reading of an unknown option: denied. One matching reading suffices for a deny entry.
- **A new value-taking global option the row does not know** (`git --newopt push status`)? Two readings, `push` and
  `status`. One matches `deny: [git push]`: denied.
- **`python3 -m pip install x` under `deny: [pip install]`?** Module dispatch: denied.
- **`sh -c 'git push'`, `timeout 5 git push`, `xargs git push`?** The inner exec is denied.
- **`allow: [git fetch]` and a fetch over https?** `git remote-https` and `git-remote-https` are in fetch's closure,
  and their images are granted: allowed. A direct `git rev-list` is allowed too (R11). A direct `git push` is not in
  fetch's closure: refused.
- **`git -c diff.external=git diff` under `allow: [git diff]`?** git execs `git <path> <old-file> ...` directly,
  with no shell. That child's subcommand is the file's path, which is neither allowed nor in diff's closure, so it
  is refused. This is why the closure is a fixed list and not "any child of git" (rejected option 18).
- **A sibling rewrites argv after the supervisor's copy?** At L and C⊘ it can win: (D), disclosed, measured by P1's
  race test. At C+ and B a covered element differs, so the MAC differs and the exec is killed before user code.
- **`exec -a git-status /usr/bin/git` (allowed as `git status`, `k = 1`), then a peer rewrites argv[0] to
  `git-push` after sched_process_exec?** The exec is guarded, so `guard` is set. The peer's `process_vm_writev` is
  refused by the argv-guarded mark, and a pre-attached tracer was refused at bprm_check with `exec-traced`.
- **An unguarded exec of a renamed git copy `/tmp/x` with argv[0] `foo`, rewritten to `git-push` after the check?**
  The copy's identity is not in the dispatch-sensitive set, so `guard` is clear. That is R2's class: the agent could
  as well run the copy directly, and compile warns in deny-list mode.
- **A symlink swapped between the walk and the kernel's lookup?** At C+ and B identity or name differs:
  `pin-mismatch`.
- **A script's `#!` interpreter swapped for another file of the same name** (`#!./tools/python` in a writable
  directory)? The interpreter's `(s_dev, i_ino)` differs at its bprm_check stage: `pin-mismatch`, `EACCES`.
- **A script's `#!` line rewritten in place after the supervisor read it?** A different interpreter fails its
  stage's identity check (`EACCES`). Another argument, or the same interpreter with another vector, fails the MAC:
  killed.
- **A script read between the identity walk and the header read, and swapped by path?** The header is read through
  the walk's own descriptor, so it is the same inode.
- **An execute-only script whose header the supervisor cannot read, in a run whose rules reach interpreters?** The
  form is unknown, `interp_ok` is clear, and its interpreter stage is refused: `pin-mismatch`.
- **A non-leader thread's exec on 5.14?** Keyed by tid and start before `de_thread`, and carried in task storage
  after it: decided and pinned like any other.
- **An exec with no notification** (a process moved into the run's cgroup from outside, a forged path)? No pin:
  refused.
- **Two execs on one pin?** The first consumes it. Every exec is notified, so every exec writes its own.
- **A kill sample lost in the ring?** The window has a loss gap, so the line is `unproven`, never `kernel_pinned`.
  A kill sample that arrives is never folded into `allow`.
- **`exec: {allow: [], deny: [git push]}` saved and recompiled elsewhere?** `MarshalYAML` keeps `allow: []`. The
  recompile is restricted, as the original run was.
- **A renamed copy of git?** Not git to the rules: residual R2, warned in deny-list mode.
- *Added 2026-10-06, each measured on the real kernel before its fix:*
  - **A symlink to git renamed in and out of existence while it is execed as `git push`?** The supervisor's walk
    finds nothing, so it answers ENOENT itself and nothing runs. Before the fix, the walk's failure was continued
    as "allow unmatched", and the kernel's lookup found the link: 1020 of 3000 attempts ran git push.
  - **`git` plus 15 `-c a.b=c` pairs plus `stash drop` (33 elements, so the 32-element prefix ends at `stash`)?**
    The prefix stays at `stash`, unlocated, and the whole vector is read: refused under `deny: [git stash drop]`.
    It had read as `stash push` and settled.
  - **A script `#!/usr/bin/rm -rf` run as `./out/s out/tree` under `deny: [rm -r]`?** The header is read for every
    exec: `rm -rf ./out/s out/tree` via `shebang`, refused. It ran, and deleted the tree. An execute-only copy is
    refused `image-unreadable` at tier 1.
  - **`coreutils --coreutils-prog=rm -r x`, its `-shebang` form, or argv[0] `lt-rm`** (GNU's single binary)? The
    coreutils row reads all three: refused under `deny: [rm -r]`.
- **The agent fills the pin map?** It is per run: execs past 4096 in-flight pins refuse that run's own execs. A
  slot's map never touches another run.

## Residuals, stated plainly

- **R1. Command rules see execs, not effects.** These perform the effect with no exec of the named command, so no
  command rule sees them:
  - a program that implements the command in process: Python, Node, Perl or Ruby code, a library such as `dulwich`,
    bash loadable builtins (`enable -f /usr/lib/bash/rm rm`), busybox `sh` running its applets in process;
  - a program that talks to the service directly: `curl` to the registry or the Git server.

  The boundary for effects is the fs and net rules: `deny_write`, `net` to the registry or remote, and `net.http`
  method and path rules.
- **R2. Name, not identity.** A copy of a binary under another name is matched by its names. Identity covers links
  and bind mounts of single-link binaries, but not copies or multicall binaries.
  - In deny-list mode the agent can run a copy, and compile says so. *Amended 2026-10-16:* with or
    without a write entry, since images are unrestricted: a copy in a memfd, or in a file the agent wrote and
    deleted, runs as an image with no name, and a program's own file can be mapped into a process with no exec, so
    `exec-rule-coverage` warns on every deny-list, not only one beside `fs.write`.
  - In allow-list mode at tiers 1 and 2, a copy is not granted (inode rules), unless a directory entry lies under a
    write entry (E38 warns).
  - At tier 3, a bare-name allow entry admits any file of that name (SEMANTICS §4), and ADR 0027's mmap policy
    admits it under that name. A copy of git named after an allowed tool runs as that tool.
  - At a plane tier, argv[0] of an unguarded exec of an image outside the dispatch-sensitive set is not protected
    after the check. Such an image is R2's copy.
- **R3. Rewriting from outside argv.** cargo, gh and aws config aliases, kubectl `kuberc` aliases, and environment
  variables that change parsing are not read. git aliases and git autocorrect are covered. Compile notes it on each
  affected entry.
- **R4. Tables are versioned data.** A tool release can add a value-taking global option, a subcommand alias, a
  helper, or a parse rule, and that can mislocate a subcommand until the row learns it.
  - Unknown options fail closed for deny entries.
  - A new built-in alias of a denied subcommand is missed until the row lists it.
  - A new helper fails closed: an allowed operation is refused until the closure lists it.
  - For git's autocorrect, drift in the candidate set or the scoring is a fail-open regression. The freshness and
    differential tests fail the build on it.
  - Compile prints the row's version and source.
- **R5. Tier 1 and the fanotify fallback.** An allow is a copied fact. Between the copy and the kernel's, a sibling
  thread, a `CLONE_VM` child or a vfork parent's other thread can rewrite argv, and any peer can swap a link on the
  image's path. P1's race test measures the rate. The cell is disclosed, and `exec.assurance: kernel` (P2) refuses
  those tiers. No unprivileged kernel mechanism compares argv: a seccomp filter sees only the pointer, Landlock has
  no argv rule, and unprivileged BPF is off on the supported distributions (`unprivileged_bpf_disabled`).
- **R6. Plane tiers, the known gaps.**
  - (a) A fault reading the new argument area kills (fail closed, counted). It needs the just-written pages to be
    reclaimed within microseconds.
  - (b) Identity is `(dev, ino)`, so reuse of a freed inode number on one device between the walk and the load is not
    detected. It needs the walked file to be deleted.
  - (c) An image binfmt_misc hands to its interpreter (qemu-user, a jar or exe handler) is refused at its interpreter
    stage when the supervisor read it as a direct ELF. P2 measures whether reading `/proc/sys/fs/binfmt_misc` can
    predict it. Until then, such images fail in pinned runs.
  - (d) A killed exec has already replaced its process image, so its parent sees SIGKILL, not `EACCES`. That happens
    only on a race or a forged exec.
  - (e) A guarded process cannot be debugged, profiled or `process_vm_readv`'d by another process of the run. A
    traced exec of a guarded image is refused. The mark protects the decided argv until the program reads it,
    nothing more. A process of the run may still ptrace an unguarded process of the same run (the plane confines
    ptrace to the run, enforce-plane §2.20), or a guarded one's forked child, and run code inside it. That is the
    agent running its own code, R1's class. *Amended 2026-10-19:* a thread the guarded
    program starts after its exec is guarded with it, by its group leader's mark.
  - (f) argv[0] of a script exec is not compared: the kernel replaces it, and the program never sees it.
  - (g) Root outside the run (ADR 0024 (15)).
  - (h) **The kill is the only enforcement after the point of no return.** If `bpf_send_signal` fails, the program
    runs until the supervisor's pidfd kill lands. The line is still `refused` with `detected_bypass`, and the run
    carries `exec-pin-kill-failed`. K0 must show zero failures on every row. This is an accepted inherent limit:
    the only hook that can read the kernel's argv runs after the point of no return.
  - (i) A run whose supervisor sees a non-zero time-namespace boottime offset does not pin, and its cells stay (D).
  - (j) *Added 2026-10-19.* In a run pinned in the unknown form (an exec gate alone), an exec
    that a root-registered binfmt_misc entry with the P flag takes is refused at its interpreter stage,
    `pin-mismatch`, unless its decided argv[0] is its filename: argv[0] then reaches the interpreter, and the tail
    holds it only to the filename. Under an entry without P it runs pinned. R9 leaves binfmt_misc unmodeled.
- **R7. Bounds.** An exec whose verdict depends on argv past 8192 arguments or 128 KiB is refused, and the refusal
  names the bound. Example: `find ... | xargs rm -f` under `deny: [rm -r]` can pass 8192 short arguments, and `-r`
  could stand anywhere; `xargs -n 4096` avoids it. An exec decided on its prefix (`git add <9k paths>`) is not
  refused for its length.
- **R8. The gate.** Its glob reading is unchanged. Its exec cell stays best effort where no pins run. Its command
  reading has no identity or `#!` interpretation.
- **R9. Interpreter dispatch is table-driven.** It covers named entry points only. A renamed or copied script, and
  code passed with `-c` or `-e`, are not commands. *Amended 2026-10-06:*
  `binfmt_misc` dispatch is not modeled at any tier. The kernel routes a file whose magic or extension a
  `binfmt_misc` entry registers to that entry's interpreter inside the same execve, with no separate notification,
  the same shape R6(c) states for plane tiers. Relying on it needs a root-installed `binfmt_misc` entry whose
  interpreter is a ruled tool; an agent cannot register one (root only, and the filter refuses the mount), and a
  registration to a non-ruled interpreter (the common `python3` one) only runs that interpreter, whose own execs are
  seen and decided. Where such a registration exists, name its interpreter in the rules or remove the registration.
- **R10. Options a pattern does not name are free on the allow side.** `git push origin feature/*` does not stop
  `--force` or `--repo=URL`. Deny the option.
- **R11. A helper closure admits direct use.** Under `allow: [git fetch]` the agent can run `git rev-list`,
  `git index-pack` or `git maintenance run` itself. Compile prints each entry's closure, and a deny entry still
  refuses any of them.
- **R12. Documented rows are unverified against a binary.** A documented row stays documented until a test probes
  an installed binary. Compile prints the source, and docs state it. GNU coreutils' single-binary dispatch is one of
  these: no GNU single binary is installed on the test machine.
- **R13. An image whose first bytes cannot be read is refused** (added 2026-10-06, review). In a run with command
  rules, an exec whose image (or `#!` interpreter) the supervisor cannot read is refused `image-unreadable`: its
  `#!` line could name any ruled tool. At tier 1 the supervisor runs as the agent's user, so that covers every
  execute-only file the user cannot read, such as RHEL's and Fedora's `sudo` (mode 4111). sudo gains nothing under
  the run's `no_new_privs` anyway. At root tiers the supervisor reads every file on a local file system. *Amended
  2026-10-06:* a remote or user-space file system can refuse root. An NFS export with
  `root_squash` serves root as its anonymous user, and a FUSE mount without `allow_other` or `allow_root` refuses
  every user but its owner, root included [documented: nfs(5) and exports(5); fuse(8) and fs/fuse/dir.c
  `fuse_allow_current_process`]. There an exec of a run with command rules whose image the supervisor cannot read is
  refused `image-unreadable`, or answered `EACCES` where the walk itself is refused (`unwalkedExec`), even in a
  deny-list run. The compile warning, agent-contract R25, SEMANTICS §4, OPERATIONS and the CHANGELOG say so.
- **R14. A `#!` chain past the kernel's depth records the decision, not the kernel's `ELOOP`** (added 2026-10-06). The supervisor follows a `#!` chain to the kernel's own limit (five stages). A
  chain one hop deeper is read as a final program, and where no rule names it its line is `allow unmatched`, while
  the kernel answers the execve `ELOOP` and nothing runs. This is the supervisor recording its decision, not the
  exec's outcome, as it does for any allowed exec that then fails `ENOEXEC` or `ELOOP`; the deepest runnable
  interpreter (at the limit) is read and decided, so it is no rule bypass, and the line misreports no refusal.

## Options rejected

1. **String or glob matching on the joined command line** (today's gate R2, Claude Code's shape). Option placement,
   clustering, permutation and abbreviation defeat it, and joining makes `["push origin"]` equal to `["push",
   "origin"]`. Claude Code's own documentation lists the bypasses.
2. **An exact token prefix for every tool.** `git -C . push` is not `git push`. It is kept
   as the generic allow semantics only, where a miss fails closed.
3. **The matcher in BPF** (tokenizer, per-tool grammars, clusters and abbreviations at `sched_process_exec`). That
   means two implementations of a matcher that must follow tool releases, a verifier budget on 5.14, and divergence
   between compile, supervisor and kernel. Pins keep one implementation and an equality check.
4. **Hold the new process with SIGSTOP and verify in userspace.** Any process of the run can `SIGCONT` it (Landlock
   scopes signals by domain, not by process), and it adds a round trip to every exec.
5. **Exact argv bytes in kernel maps instead of a MAC.** TASK_STORAGE values stop near 64 KiB, below the 128 KiB
   budget. A HASH value of 128 KiB is an order-5 allocation per exec that fails under fragmentation, and every such
   failure is a spurious refusal.
6. **An unkeyed or non-cryptographic hash** (FNV, xxhash, seeded Murmur). The agent chooses both vectors. It can
   build collisions offline, and seed-independent collisions are known for seeded non-cryptographic hashes.
7. **Kill from `bprm_committing_creds` or `bprm_committed_creds`.** These are void hooks in LSM mode only. fmod_ret
   mode cannot attach to a void `security_*` function, and a sleepable fentry needs the error-injection list. The
   kill has the same effect as at `sched_process_exec`, which runs in both modes and is where the recorder already
   reads argv.
8. **Refuse with an errno after reading argv.** No hook can both return an error and read the kernel's argv copy:
   the copy is readable only after the point of no return.
9. **Fail closed on every unknown subcommand of alias-capable tools** (cargo, gh, aws, kubectl). This refuses
   `cargo clippy`, `cargo fmt`, kubectl plugins and `git lfs` under any deny entry on those tools, to stop an alias
   the agent must first write into a config file. The same agent can reach the service directly (R1). Kept as R3,
   with a note on each entry. git autocorrect is modeled because its trigger set is computable from argv.
10. **Make a deny-only `exec:` section restrict images.** `exec: {deny: [git push]}` would mean "nothing but the
    agent command", which no author means.
11. **Most-specific-wins precedence.** An allow could carve holes in a deny, nested runs could not union deny
    lists.
12. **Match renamed copies by content hash.** That hashes every exec'd image, and a one-byte patch defeats it.
    Image restriction (allow-list mode at a plane tier) is the control that holds.
13. **Write pins from userspace into TASK_STORAGE by pidfd** (0044's claim form). Non-leader threads need
    `PIDFD_THREAD` (6.9), so every non-leader exec would be refused on 5.14 and 6.1. The kernel itself moves the
    pin into the task's storage at bprm_check, where no pidfd is needed.
14. **Pin only guarded execs and give the kernel the guarded name set.** Guardedness depends on dispatch (busybox's
    argv[1], `python -m`, entry scripts, `#!` lines), which the kernel would have to re-implement. Pinning every
    exec keeps the kernel to equality, and an unguarded pin costs one argv[0] MAC.
15. **Pin the environment too.** No rule reads the environment. Add it when one does.
16. **Express denials as gate scores of 100.** The gate sums scores against thresholds, and its ask range has its
    own completion rules. A list decides as a floor (SEMANTICS §3). The gate keeps its role and shares the matcher.
17. **At tier 1, refuse guarded execs from a task that shares its memory** (more than one thread, or a `CLONE_VM`
    peer). Agents spawn through vfork-style `clone(CLONE_VM|CLONE_VFORK)` (glibc `posix_spawn`, Go's `os/exec`,
    CPython's `subprocess`), so the exec'ing child shares a multithreaded parent's memory, and every allowed
    `git status` they start would be refused. Sharing cannot be read race-free from userspace either: a `CLONE_VM`
    peer outside the thread group shows in no count.
18. **Exempt from allow constraints every exec by a task whose current image is the tool's own**
    (alternative to a closure). git runs single-word configured commands directly, without a shell
    (`diff.external=git`, `core.pager=git`, `core.editor=git`), with words the agent chooses through file names.
    The exemption would admit those. A closure is a fixed, measured list.
19. **Guard every pin** (every exec'd process of a pinned run unattachable, every traced exec refused). In-run
    debuggers and tracers (strace, gdb, py-spy) would fail on every exec. The `guard` bit covers every exec whose
    verdict or dispatch depends on its argv, and the rest is R2's class.
20. **Always pin the whole vector** (no prefix pins). That means a MAC over up to 128 KiB for every exec, and a
    refusal past the bound for `git add <9k paths>`, to cover elements no decision read.
21. **git autocorrect as "weighted distance below 7 to any built-in, or a prefix"** (the first draft). It ignores
    git's uniqueness rule and its prefix rule. On 417 tokens it flagged 54 as reaching push where git reaches 11,
    refusing `git lfs`, `git gui`, `git ls` and `git sh` under `deny: [git push]`. That is option 9's collateral.
22. **The mode bit by emptiness** (`Allow == nil && len(Deny)+len(Ask) > 0`). Commenting out the last entry would
    flip the mode, and `Canonical` would drop `allow: []` and turn a restricted run's recompile unrestricted.
23. **Path-or-pattern by file existence.** contract.yaml is recompiled on other machines (agent-contract R13), where the file may
    not exist, so the same text would classify differently.
24. **`exec.ask` completing through 0044's mechanism now.** That contradicts 0044's Rejected option 11 and its
    only-narrowing argument. The key is reserved and refuses until an amendment to 0044 accepts a list floor.
25. **Refuse every guarded exec past 8192 arguments or 128 KiB.** ARG_MAX is about 2 MiB, and `git add` of many
    paths is legitimate. Only a verdict that depends on the unread part refuses.
26. **A distance-based autocorrect reach kept as a safety margin on top of the port.** The port with a subset
    candidate set already reaches every target git reaches. The margin adds only collateral.

## Implementation plan

### P1: contract, matcher, compiler, supervisor, ledger, `compile --test`, docs

- **C0, docs first**. This ADR's index row; forward links on 0007, 0016, 0019, 0024, 0041;
  FEATURES' new row.
- **C1a, `pkg/policy/execmatch` core**.
  - The parser (row-aware option words, shell-syntax lint, errors with fixes), facts, interpretations (2), the
    normalizer, the ambiguity rules and the generic fallback.
  - Rows: git (with the `help_unknown_cmd` port, its candidate sets and the helper closure), rm, interpreters and
    multicall.
  - Index by tool, with zero allocations per `Match` over a pre-split argv (benchmark).
  - A fuzz target: no panic, bounded work, and deny-side monotonicity. Inserting an unknown option token, or a
    complete known option with its value, anywhere before `--` never turns a deny match into a miss. For allow
    entries that name no option, the same insertion never turns a miss into a match.
  - **Differential and freshness tests against installed tools**, skipped when absent:
    - git autocorrect: every target git reaches is reached by the port, and the false positives against git's own
      `--list-cmds` set are zero;
    - `--list-cmds` built-ins and the common group are a superset of the row's;
    - rm's option behavior;
    - each probed row's measured cases.
- **C1b, the remaining rows**. npm and npx (probed), go and systemctl (probed), then the documented rows. Each
  row is data in `rows/` with its version, source and probed or documented flag, plus a test file of real
  invocations. Write `docs/spec/exec-command-rows.md`.
- **C2, the contract**.
  - Schema: `exec.deny`, `exec.ask`, and string patterns in `exec.allow`.
  - `Load` and validation: `exec-rule`, the syntactic classification of (1), the path-in-deny error, presence
    tracking, `extends` concatenation and the mode's source file.
  - The mode bit by key presence; `ExecSection.MarshalYAML`; goldens that every existing contract's canonical bytes
    and `contract_hash` are unchanged; the two-contract hash and round-trip goldens of (1).
  - `ExecUnrestricted()` and the seven direct sites moved onto it (landlock.go 220 and 440, plane.go:138,
    policy.go:140, planerows.go:393, supervisor.go:608, compile_execmap.go:46), with a source test that fails on a
    new direct spelling. A table test runs one deny-only contract through the Landlock builder, the plane's slot
    flags, the fanotify policy, the decision core and the supervisor, and requires one answer.
  - agent-contract R2, R5 and R8 and the new rule; SEMANTICS §1, §3 and §4.
- **C3, the compiler**.
  - `RuleTable.ExecCommands`: patterns indexed by tool, constrained tools, closures and helper images, the
    dispatch-sensitive set, and identities with link counts. A constrained `exec.allow` entry grants its image as a
    bare one does; the image rule is named `exec[<command word>]`.
  - The print lines of (9), with readings, near-misses, closures, row source and notes.
  - The warning policy of (9): `exec-rule-coverage` only for actionable findings; `redundant-rule`; per-tier
    `unenforced`; `BestEffortCellsAt`'s `exec.rules/argv`.
  - The run's own `command` and `mcp[].command` checked against the rules.
  - Gate rules whose reading broadened are listed.
- **C4, the decision core and `compile --test`**. `decide.ExecCommand`; `script_arg:`; the `--exec`
  one-liner; cell fields; the gate's union reading and first-word index (gate.md R2); goldens.
- **C5, the supervisor**.
  - Guarded detection; the staged, batched argv read (prefix, then tail only when needed; iovec batches);
    `record: off` reads only what a rule needs.
  - The fd-pinned `#!` read and the interpreter-chain walk; the handover bypass; the decision; refusal lines and
    fields; `ExecNaming`'s fields.
  - `exec.ask` refused with `completion_unsupported`.
  - Lookup errnos preserved, interpreter walks included.
  - Record minor step, `RefusedPayload`, `run_start.best_effort`, the capability row, `run_end` counters, and status,
    events and drift output (deny and ask entries as guards not exercised; constrained allow entries counted one by
    one).
- **C6, tests on a real kernel, tier 1, unprivileged**.
  - TestIntegrationExecDenySubcommand: every Context bypass of `git push` and `rm -r` is refused, with its rule
    and `command_via`.
  - TestIntegrationExecAllowListSubcommands: status, diff and log run; push is unlisted; the `git-st` probe keeps
    `ENOENT`, and an alias still re-execs.
  - TestIntegrationExecAllowHelperClosure: against a local bare repository, `allow: [git fetch, git push,
    git commit, git gc]` runs fetch, a push over the file transport, a commit with auto-maintenance, and gc. Each
    helper exec's line says `command_via: closure`. The test is layout-aware: it finds git's exec-path from the
    resolved binary, and a hermetic variant uses fixture binaries, so it does not depend on Ubuntu's layout.
  - TestIntegrationExecRuleAmbiguous.
  - **TestIntegrationExecRuleRaceTier1, the TOCTOU test.**
    - A compiled fixture binary installed as `git` in a scratch `PATH` directory records its argv[1] and exits.
    - The contract is in deny-list mode and denies `git push`.
    - Each attempt forks a child that starts a thread flipping a 5-byte buffer between `diff\0` and `push\0` (both
      git built-ins, so git's row reads both definitely). Meanwhile the main thread calls
      `execve(git, ["git", buf])`. Up to 5000 attempts.
    - **The closed direction, asserted:** every attempt whose copy read `push` is refused `EACCES`, and its line is
      `refused` with rule `exec.deny[git push]` and `argv_facts: copied_syscall`. No line ever says `allow` for a
      copy that read `push`.
    - **The disclosed race, measured:** The test prints how many attempts ran the fixture with `push` while their
      line says `allow` with `diff`. On zero wins (a single-vCPU CI runner) it logs and skips that sub-assertion; it
      never fails on it.
    - `run_start.best_effort` lists `exec.rules/argv`.
  - Conformance cells (ADR 0017) for the command-rule grid at tier 1.
  - A P1 smoke cell (deny `git push`, allow `git status`) in every `make vm-matrix` row. RHEL's 5.14 has git 2.43 to
    2.47 and `/usr/libexec/git-core`.
- **C7, docs and examples**.
  - gate.md R2; supervisor R16, R16b and R22; record-ledger and the record README; REASON-CHANNEL (rule names, no new
    codes); CAPABILITIES; REPO-LAYOUT; CHANGELOG (gate union, path-with-spaces, helper images).
  - The operator README section on residuals R1–R12, with the "use fs and net rules for effects" guidance and the
    git layout differences (`/usr/lib/git-core` on Debian, `/usr/libexec/git-core` on RHEL, and git re-execing a
    different file than `/usr/bin/git`).
  - A recipes table: deny push, no recursive deletes, no publish, and read-only git. Each recipe states what it does
    not cover.
  - A read-only-git example profile built from measured data. It needs more than status, diff and log: rev-parse,
    branch, ls-files, config reads, remote, show and others that Claude Code runs. `examples/agents/claude-code.yaml`
    gains a commented upgrade path from its bare `git`.
- **C8, P1 performance**. Supervisor and `decide.ExecCommand` benchmarks plus an allocation test, measured
  interleaved A/B with Min-of-N as `test/perf/perf.go` and BENCHMARKS.md do. Each figure has a Target
  (`TARGET-MISS`) and a Limit at about twice it (fails the suite):

  | Case | Target | Limit |
  |---|---|---|
  | unguarded exec, run with command rules (with its `#!` header read, as amended) | +6 µs | +12 µs |
  | a `#!/bin/sh` script, run with command rules | +15 µs | +30 µs |
  | guarded exec, ≤ 16 arguments | +15 µs | +30 µs |
  | guarded exec, ≤ 128 arguments | +0.15 ms | +0.3 ms |
  | guarded exec, 8192 arguments / 128 KiB (worst case, batched) | +1 ms | +2 ms |
  | `ExecCommand`, 512 patterns plus 256 gate rules, exec whose tool has none | +0.5 µs | +1 µs |
  | allocations per `Match` | 0 | 0 |

**P1 acceptance.**

- Gate (precommit) green with `-count=1`.
- C6 passes on 6.17, and the matrix smoke cell passes on every row.
- The root suites on both KVM boots show no regression.
- `compile --test` goldens are updated in the same commits, and the existing contracts' `contract_hash` goldens are
  unchanged.
- C8 meets its Limits.
- A review finds no matcher bypass among the probed rows' tools that the residuals do not name.

### P2: the kernel pin at plane tiers

- **K0, verification on every matrix row**: 5.14 RHEL 9.x, 6.1 AL2023, 6.8, 6.12, 6.17 and 7.0, in both
  plane modes and both reader builds (`TEGO_PLANE_RDONLY` 0 and 1), under `lockdown=confidentiality`. It must show:
  - `tp_btf/sched_process_exec` in the plane object loads; the verifier's instruction count is recorded, 5.14
    included;
  - `bpf_send_signal(SIGKILL)` from it kills before a static probe's first instruction (the probe's first act is a
    `write` to a pipe, which stays empty), with **zero send failures** over 10,000 kills per row;
  - `bpf_probe_read_user` over `[arg_start, arg_end)`;
  - `bpf_get_ns_current_pid_tgid` in LSM and fmod_ret bodies;
  - `task->ptrace` read at bprm_check;
  - each later binfmt stage reaches bprm_check with the interpreter's file;
  - the NULL path of the task-storage helper on 5.14 and 6.1 refuses cleanly;
  - SipHash-2-4 in BPF, with the domain byte, equals the Go implementation on the 64 reference vectors;
  - a traced exec with a pending SIGKILL never lets the tracer `PTRACE_POKEDATA`;
  - The time-namespace probe: a supervisor in a time namespace with a boottime offset makes the doctor cell report
    "pins off", never a run that refuses every exec.

  No other commit lands before K0 passes everywhere. A failing row decides that row's fallback: the pin flag off,
  and the cell disclosed.
- **K1, BPF**.
  - The three maps; the slot flag; bprm_check's first-stage and later-stage steps (interpreter identity,
    `interp_ok`); `tego_plane_exec_pin` with the `bpf_loop` MAC callback, prefix and whole checks, and
    `kill_failed`; the `guard` bit and the argv-guarded ptrace refusal; codes, samples and `pin_seq`.
  - Source tests in `bpf/tests`: only-narrowing (no path returns 0 because of a pin), the bounded loop, no per-CPU
    buffer, and no pin on the stack.
- **K2, the loader and Prepare**.
  - Inner maps per slot with gen; the key array; the namespace identity in the slot; clears on Detach, purge and
    Prepare; adoption; `bpf.PlaneHooks`; the ring ABI step.
- **K3, the supervisor**.
  - The `ExecPinner` seam and its `internal/runtime` adapter; pin encoding with `k`, the `guard` bit, the
    dispatch-sensitive set and the interpreter chain; the Go SipHash with domain bytes and reference vectors.
  - A pin for every continued exec; `pin_unavailable` refusals; the sweep; `PinSeq` in the naming; the pidfd kill on
    a `kill_failed` sample; the time-namespace check.
- **K4, observe**.
  - The fail-closed fold by `(run, seq)` of (8); `argv_decided`; `kernel_pinned`, `unproven` and the gaps
    `exec-pin-unproven` and `exec-pin-kill-failed`.
  - Tests inject ring loss, reordering, a kill sample with no success record, and a mismatched `pin_seq`, and require
    that no line says `allow` for a killed exec and none says `kernel_pinned` under loss.
- **K5, doctor, capabilities, assurance**.
  - (7)'s optional cell and its cache; `ExecPins()` from the handle; the capability row; `BestEffortCellsAt` drops
    `exec.rules/argv` and `gate.exec` when pinned; `exec.assurance: kernel` in schema and run start (exit 125).
- **K6, KVM tests, both boots** (`lsm=...,bpf` for C+ lsm and B; the default boot for C+ fmod_ret) and the matrix rows:
  - TestPlaneRunExecPinRace: C6's race fixture. Zero runs of `push` in 5000 attempts per mode. Every racy attempt
    is refused by the supervisor or killed by the kernel, and every kill's line carries both vectors.
  - TestPlaneRunExecPinSymlinkSwap (`pin-mismatch`, `EACCES`).
  - TestPlaneRunExecPinScriptRewrite (killed) and TestPlaneRunExecPinInterpreterSwap (a same-named interpreter
    replaced in a writable directory: `pin-mismatch`, `EACCES`).
  - TestPlaneRunExecPinUnpinned (a test hook skips the write: `EACCES`).
  - TestPlaneRunExecPinTraced and TestPlaneRunExecPinGuardedPtrace (`PTRACE_ATTACH` and `process_vm_writev`
    refused), each also for a `k = 1` dashed-form exec, where argv[0] alone decided.
  - TestPlaneRunExecPinInterpreted (`#!/usr/bin/env node`, and a two-stage script).
  - TestPlaneRunExecPinNonLeader (a non-leader exec on 5.14 and 6.1 succeeds).
  - TestPlaneRunExecPinPrefix (`git add` with 10,000 paths under `allow: [git add]` runs; a tail rewrite after the
    supervisor's prefix read does not change the verdict).
  - TestPlaneRunExecPinLargeArgv (a tail-dependent decision: 128 KiB passes, one byte more is refused with its
    bound).
  - TestPlaneRunExecPinKillFailed (a test hook makes the send fail: refused line, `detected_bypass`, the gap, and
    the pidfd kill).
  - TestPlaneRunExecPinOff (no rules: no pins, no kills).
  - The root-skips allowlist is not widened.
- **K7, performance**. A new `execbench` in `make vm-perf`: fork+exec of a static `/bin/true`-like binary,
  10,000 iterations per mode, with and without command rules, p50 and p99. It is measured interleaved A/B with
  Min-of-N, and P1's supervisor cost is reported separately from P2's kernel cost. Each figure has a Target
  (`TARGET-MISS`) and a Limit at about twice it (fails the suite):

  | Case | Target | Limit |
  |---|---|---|
  | pinned exec, argv ≤ 1 KiB, p50 over the same mode without rules | +15 µs | +30 µs |
  | the same, p99 | +50 µs | +100 µs |
  | 128 KiB argv, whole pin | +1.5 ms | +3 ms |
  | a run without rules, per exec | +100 ns | +200 ns |
  | doctor's cell, cold probe (nothing warm) | +30 ms | +60 ms |

  Pin map memory is the 4096-entry ceiling at about 640 bytes each, allocated on use.
- **K8, docs**. enforce-plane §2.21 and its rule numbers, SEMANTICS §4's tiers 2 and 3 paragraph,
  CAPABILITIES, TIER3-PLAN, record-ledger, and the ADR 0024 and 0041 notes.

**P2 acceptance.**

- K0 holds on every row.
- K6 passes on both boots and on the matrix rows the plane supports.
- K7 meets its Limits.
- A review reproduces no exec, after arming in a pinned run, whose covered facts differ from the decided ones
  at C+ and B.

### Ordering and coordination

- P1 has no dependency and goes first. Within P1, C1a's git, rm and generic reading land first, because they cover the
  three motivating examples: deny a whole command, deny a subcommand, and allow only
  some subcommands.
- P2 follows the plane's open items that touch bprm_check (ADR 0039's name rows, 0044's claims). At merge it takes
  slot flag 0x100 and the next free plane reason codes, record minor and ring ABI version.
- If 0044 lands first, P2 writes pins beside 0044's claims and offers it the `(tid, start)` key (5).

## Consequences

- **Authors.** A contract can say "never `git push`", "never a recursive `rm`" and "only `git status`, `git diff`
  and `git log`". The rules hold against option placement, dashed and argv[0] forms, wrappers, multicall binaries,
  git autocorrect and named interpreter entry points, at every tier. `exec.ask` parses and refuses until ADR 0044
  gives it a completion.
- **The race.** At tier 1 and the fanotify fallback the allow direction stays a disclosed race. At a plane tier with
  P2 it is closed from the arming point on: the kernel runs only an exec whose covered facts it verified, kills one
  whose argv changed, and records a detected bypass in the case K0 must show never happens.
- **What remains.** Command rules remain launch rules. The effects (deletions, pushes, publishes) are bounded by the
  fs and net rules. Compile, the residual list and the README say so.
- **Cost.** In a run with command rules, every exec reads its names and argv[0], and a guarded exec reads as much as
  its decision needs, `record: off` included, within C8's budgets. At plane tiers every exec writes a pin (one
  `bpf(2)` call) and pays a MAC over the elements its decision read. Runs without rules pay nothing measurable.
- **Compatibility.** Every existing contract keeps its `contract_hash`. Existing gate rules match more (fail
  closed). A bare `git` entry also grants git's own helper images. An unquoted path with spaces in `exec.allow` must
  now be quoted.
- **Who maintains what.** The per-tool rows are maintained data with freshness tests. A tool release can need a row
  update, and compile prints which row, version and source read each entry.

## Implementation notes (P1, 2026-10-06)

**Acceptance, item by item.**

| P1 acceptance item | State |
|---|---|
| precommit green with `-count=1` | met on the branch head |
| C6 passes on 6.17 | met, unprivileged here and as root in both KVM boots (lsm with bpf, and the default list) |
| the matrix smoke cell on every row | met: ubuntu-24.04, debian-13, rhel-9, al2023, al2023-6.12, fedora-7.0 and host, as the user at tier landlock and as root at tier cgroup (`VM_ONLY=smoke`). Each guest's git is this host's |
| root suites on both KVM boots show no regression | met for the command-rule tests and the plane's end-to-end test; the whole root suite was not rerun after the fixes |
| `compile --test` and `contract_hash` goldens | met |
| C8 meets its Limits | met, with the unguarded case's budget raised for the `#!` read (below) |
| ADR 0017 conformance cells for the command-rule grid | met 2026-10-06 (below): both runners, every tier and plane mode, in both KVM boots, with two ledger cells baselined |
| a review finds no unnamed bypass | **open**: reviews found the four below, two more, one (the `#!` line's `\r`, below) besides an undercount of R13's cost and record gaps, and two (a directly-invoked loader, a 255-byte `#!` line). All are fixed. One review ran no probe, and a later one found none but probed the matcher in-process, not a run, so probes against a real run on the fixed code have still to find nothing |

**The first review (2026-10-06).** Each finding was confirmed on the real kernel, and each is fixed with a
test that fails without its fix:

1. **Fail-open on a failed walk** (tier 1, every mode). A deny-list run continued an exec whose walk failed, as
   "allow unmatched". A run with nothing to match continued it as observed. An allow list continued a grant matched
   on the spelling alone. The kernel's own lookup then ran with no command rule deciding: a symlink to git renamed in
   and out of existence while it was execed as `git push` ran git push in 1020 of 3000 attempts. Now a run with
   command rules answers every such exec from the loop (`unwalkedExec`). A failure the task's own lookup would meet
   keeps its errno (ENOENT, ELOOP, and EFAULT for an unreadable pathname) and is observed. Any other failure is
   refused `path-unreliable`. `TestIntegrationExecRuleLinkRaceTier1`: 0 runs of 3000 here and in both boots (about
   1000 refused and 2000 ENOENT each time). It ran 97 times with the fix taken out.
2. **Fail-open in the staged read.** The normalizer entered a level's default subcommand at the end of an argv
   prefix, so a 32-element prefix that ended at `git stash` read as `stash push`, located, and settled. git, 15
   `-c a.b=c` pairs and `stash drop` ran under `deny: [git stash drop]`. On the matcher, `allow: [git stash push]`
   admitted it and `deny: [git reflog expire]` missed `reflog expire`. Now an incomplete vector's invocations are
   `Open`, and their end enters no default subcommand. `TestPrefixEndEntersNoDefault` covers every row level with
   a default (stash, submodule, notes, reflog).
3. **An undisclosed bypass through the `#!` line.** The header was read only when a rule named an interpreter.
   `#!/usr/bin/rm -rf`, run as `./out/s out/tree` under `deny: [rm -r]`, deleted the tree. Option (a) was taken:
   every image's header is read in a run with command rules (section (3) as amended), and an image whose header
   cannot be read is refused `image-unreadable` (R13).
4. **A multicall gap.** GNU coreutils' single binary dispatches on `--coreutils-prog=PROG`, on its `-shebang` form
   and on argv[0] `lt-PROG`, and the coreutils row read none of them. It reads all three now (interpretation 4, as
   amended), from GNU's source; no GNU single binary is installed here (R12).

What differs from the plan above, and what is still open:

- **C0.** The forward links are on 0007, 0016, 0019, 0024 and 0041.
- **C1a/C1b.** As planned. git's helper directory is derived only from the resolved binary, as
  `<prefix>/lib/git-core` or `<prefix>/libexec/git-core`. There is no fallback to the host's own directories: a
  fixture with no exec-path next to its git gets no helper images (`TestCompileExecHelperImages`).
- **C5.** The `exec_rules` counters are written under `run_end`'s `supervisor` object (`Supervisor.ExecRules`), beside
  the supervisor's other counters, not at the top of `run_end`. `tego status` does not yet show the
  `exec.rules/argv` cell.
- **C4.** `compile --test` and `compile --exec` do not read the identity interpretation (link counts, bind mounts).
  Only the supervisor decides it. Since the third review, `compile --exec` reads the `#!` line of a command
  given by path, with `agent.ShebangLine`, and resolves the image and the interpreter as a `--test` row's path and
  `script:` are resolved; it prints the line as `script:`. It reads the first stage only (an interpreter that is
  itself a script is not followed), and a bare command word is not looked up, so its `#!` line is not read, which
  the output says.
  - *Amended 2026-10-06.* `compile` is a static preview; the run
    is authoritative and fails closed. `compile` can say `allow` where the run refuses on a fact it does not read,
    all in the safe direction (the run is stricter):
    - a `#!` interpreter that does not exist or that the task cannot read: the run refuses `interpreter-unresolved`
      (the walk's errno) or `image-unreadable`; `compile` does not walk it;
    - an execute-only image (mode 4111): the run refuses `image-unreadable`; `compile` cannot read its head and says
      so;
    - a dynamic loader whose program `compile` resolves by name but the run cannot read as the loader will (an
      operand with no `/` that glibc searches library paths for, or one reached through a symlink or a renamed or
      hard-linked loader): the run refuses `loader-unresolved` or, in a restricted run, `loader-program-unmatched`;
      `compile` reads neither the identity nor the walk (O2);
    - a second `#!` stage (an interpreter that is itself a script), the identity interpretation, and a loader's
      identity: the run reads them, `compile` does not.
  - `command_via` can differ between `compile` and the run for the same exec: `compile` names the interpretation it
    reached by the spelling it has (name, argv0), the run the one its walk reached (image, dashed, identity,
    loader). The rule and verdict agree where both resolve the command. The one disagreement in the over-refusing
    direction, a directory `exec.allow` entry read as its own basename, is fixed (F4g).
- **C6.**
  - `TestIntegrationExecDenySubcommand`, `TestIntegrationExecAllowListSubcommands`,
    `TestIntegrationExecAllowHelperClosure`, `TestIntegrationExecRuleAmbiguous` and
    `TestIntegrationExecRuleRaceTier1` run unprivileged. They pass on the 6.17 test machine, and as root in both KVM
    boots (lsm with bpf, and the default lsm list).
  - The race test makes 3000 attempts (300 under `-short`), not up to 5000. The disclosed race won 406 to 430 of
    3000 in a 4-vCPU guest, and 379 to 440 after the review fixes.
  - The review added `TestIntegrationExecRuleLinkRaceTier1` and `TestIntegrationExecRuleShebangInterpreter`.
    Both pass unprivileged here and as root in both KVM boots.
  - `TestPlaneExecCommandRulesEndToEnd` passes in every plane mode and on the fanotify listener in both boots.
  - The guest base image now carries the host's git (test/vm/kvm-run.sh), and `test/workloads/execracer` is a
    prebuilt VM helper.
  - The matrix smoke cell is `test/e2e/smoke-exec-rules.sh`. test/vm/run-matrix-row.sh runs it as the user at
    tier landlock and as root at tier cgroup, under a deny-list (`rm -r` in three spellings, `git push`) and an
    allow-list (`/bin/sh`, `rm -f`, `git status`). After the review fixes, both halves pass on every row of `make
    vm-matrix` and on the host's kernel. `VM_ONLY=smoke` runs only this cell on each row.
  - The ADR 0017 conformance cells for the command-rule grid are built (2026-10-06, below).
- **C7.** As planned. The recipes, residuals and git layouts are in docs/OPERATIONS.md, the profile is
  `examples/profiles/base/read-only-git.yaml` (`TestReadOnlyGitProfile`), and the field list is in
  docs/p0/record-ledger.md.
- **C8.** `TestExecCommandCostBudget` measures on real `process_vm_readv` reads of the test process, interleaved
  A/B, Min-of-N. Measured on the test machine:

  | Case | Added | Target |
  |---|---|---|
  | unguarded exec | +2.0 µs (+5.3 to +5.5 µs with the `#!` read of the review fix) | +3 µs (+6 µs since) |
  | a `#!/bin/sh` script (added with the fix) | +12.7 to +13.1 µs | +15 µs |
  | 16 arguments | +5.1 µs | +15 µs |
  | 128 arguments | +17 µs | +0.15 ms |
  | 8192 arguments / 112 KiB | +0.74 ms | +1 ms |
  | past the bound, refused | +0.70 ms | +1 ms |

  The first measurement of the 8192-argument case was +9 ms. The record re-read argv one string at a time, and the
  staged read used one iovec per string. Now the record reuses the copy that was decided on, and the staged read
  coalesces the strings into runs of up to 64 KiB, with up to 1024 iovecs per call. `TestExecCommandIndexCostBudget`
  times the index over 512 patterns for an exec whose tool has none at 476 to 499 ns, inside the 1 µs limit; the
  256 gate rules of the plan's case are not in that measurement. `Match` allocates nothing
  (`TestMatchAllocatesNothing`).
- **P2** (the kernel pin and `exec.assurance`) is not built.

**The final review (2026-10-06).** It required two changes. Each was confirmed on the real kernel or by a test that
fails without its fix, and each is fixed:

1. **A `#!` interpreter reached through a symlink got past every command rule.** `Index.Guarded` and
   `Interpretations` read each `#!` stage only by `base(st.Path)`, and never used the stage's identity, though the
   supervisor's interpreter walk filled it in. Under `deny: [rm -r]`, a script whose line is `#!<dir>/x -rf`, with
   `x` a symlink to rm, ran `rm -rf` on a line that said `allow unmatched`. Now `Stage` carries the walked
   interpreter's basename (`Image`, from the walk's link, as `Facts.Image` does for the direct form) and `HasID`,
   and both functions read each stage by its `#!` path, by that name and by its identity, with the same name
   readings a direct image gets (interpretation 6, as amended). `TestShebangStageByImageAndIdentity`;
   `TestIntegrationExecRuleShebangInterpreter` gains `ln -s rm out/x` with `#!<abs>/out/x -rf`, which deleted its
   tree without the fix and is refused `exec.deny[rm -r]` via `shebang` with it.
2. **The supervisor opened whatever an exec named before checking its type.** In a run with command rules every
   exec asks for its image's header, and `readHead` reopened the walk's `O_PATH` descriptor `O_RDONLY|O_NONBLOCK`
   through `/proc/self/fd` before it `fstat`ed for `S_IFREG`. At tier 2 the supervisor is root, so `execve` of a
   root-only device made it open the device (a confused deputy). Now `describeImage` keeps the mode it already
   reads, and only a regular file is reopened; anything else keeps no header and is refused `image-unreadable` with
   `EACCES`, the kernel's own answer ((3) as amended). `TestExecImageHeadOpensOnlyRegular` wraps the reopen and
   watches a FIFO with inotify: a FIFO and `/dev/null` were both opened before the fix and are never opened now.
   `TestIntegrationExecRuleNonRegularImage` runs a FIFO and `/dev/null` (exit 126, `image-unreadable`).

**The ADR 0017 cells (2026-10-06).** `test/conformance/execrules_test.go` holds two fixtures that both runners run at
every tier and plane mode.

- `execrules` is a deny-list contract (`deny: [git push, rm -r]`, `ask: [npm install]`). Its cells:
  - a subcommand, behind git's global options, by the dashed name, under a spoofed argv[0], and through a symlinked
    image;
  - rm's `-fr` cluster and `--recursive`;
  - `exec.ask`;
  - a `#!` line naming rm, and one naming a symlink to rm;
  - a FIFO, refused `image-unreadable` with `EACCES`;
  - `git status` and `rm -f`, which run.
- `execrules-allow` constrains git through path entries with words. Listed subcommands run. An unlisted one, and
  one missing a required option, are `exec.args[git]`. A deny entry beats an allow entry, and the image floor
  decides first.

An exec cell carries its whole argv (compile --test's `argv:`), a script's `#!` argument (`script_arg:`) and the
interpreter its walk reaches. The actor runs a copy of itself under each tool's name. `invariants_exec.go` adds an
invariant read from the contract and the cell alone, never the matcher: no exec runs a program a deny or ask entry
names with that entry's words.

In both KVM boots every cell passes on tier landlock, the fanotify listener, `fmod_ret`, `lsm` and tier bpflsm,
except the two allowed cells of the deny-list fixture on the plane axes. Their kernel line says `observed
unmatched`, while the supervisor's line and compile --test's plane column say `allow unmatched`: observe's
`matchExec` names every exec no entry matches `observed`. That is a ledger split of every run whose images are
unrestricted, with or without command rules, and not a fail-open. It is baselined (`testdata/baseline.json`, six
entries) and open. Not built as cells, each in `Deferred`: the execute-only image (`image-unreadable` only where the
supervisor runs as the agent's user), the argv race (`TestIntegrationExecRuleRaceTier1`), and an invariant for a
constrained tool's unlisted invocation.

*Amended 2026-10-16 (the rhel-9 row):* the split needs the kernel's exec line to be the terminal one, which
it is only where the exec outcome links (`tracepoint/syscalls/sys_exit_execve` and `sys_exit_execveat`, attached as
BPF perf links, upstream 5.15) attach. On RHEL 9's 5.14 doctor reports them unavailable ("supervisor retains exec
ownership"), the supervisor writes every exec's line, and both cells pass on every axis, so the six entries failed
`TestConformanceKernel` there as entries that now pass. They carry `where: {kernel_min: "5.15"}`, checked in KVM on
rhel-9 (5.14: no entry applies, the cells pass), al2023 (6.1), al2023-6.12 and 6.17 (the split, baselined). Rejected:
a machine fact for the links themselves in `Where`, which is the exact condition but adds a probe the conformance
harness would have to keep in step with the loader's `ExecResultAttachUnavailable`; a kernel bound that is wrong on
some machine fails the suite there as a stale or missing entry, never silently.

**The second review (2026-10-06).** It is not clean. One pass ran no probe, so it tested none of the vectors (links, `#!` chains,
ld.so, memfd and execveat, `exec -a`, multicall forms, wrappers, git config, alias and environment vectors, npm and
kubectl plugins, option abbreviations, long argv) at any tier. That pass's "nothing found" is no evidence, and
the acceptance row stays open. The other findings were each reproduced and fixed, each with a test that fails
without its fix:

1. **A command-rule bypass through a CRLF `#!` line** (every tier). `parseShebang` trimmed a trailing `\r`, which
   `binfmt_script` keeps. Under `deny: [rm -r]`, a script `#!<dir>/y\r`, with `<dir>/y` a symlink to true and
   `<dir>/y\r` a symlink to rm, run as `./c -r tree`, was walked as `y` and allowed `unmatched` while the kernel ran
   `rm -r` and deleted the tree. The interpreter is reached through a symlink, so this is not R2's copy residual.
   `agent.ShebangLine` is now the one port of `load_script`, and the supervisor reads every stage with it ((3) as
   amended). `TestExecCommandShebangKernelParse`, `TestParseShebangAsKernel`, and
   `TestIntegrationExecRuleShebangCRLF`, which deleted its tree on the test machine with the fix taken out.
2. **A null `exec.allow` failed open.** `exec:\n  allow:\n  deny: [git push]` (every allow entry commented out)
   loaded as a deny-list, every image unrestricted, though an allow key, even `allow: []`, restricts images ((1)).
   A null allow is now a `schema` error with the `allow: []` fix, as a null deny or ask already was
   (`TestExecModeByKeyPresence`).
3. **R13's cost was not where a user reads.** Only docs/OPERATIONS.md said that at tier landlock run unprivileged
   every image the agent's user cannot read is refused `image-unreadable`, even one no rule names. compile now
   warns at tier landlock (`exec-rule-coverage`, `TestCompileWarnsImageUnreadableAtLandlock`), and the CHANGELOG,
   SEMANTICS §4 and agent-contract R25 say it.
4. **The refused mirror carried no command rule.** `refusedPayload` copied op and target only, though (8) and
   record-ledger say the mirror carries `command_rule` and `command_match`. It copies both now
   (`TestTheRefusedMirrorNamesTheCommandRule`, through the ledger).
5. **`command_match: none`.** An unlisted refusal wrote `none`, outside the `definite | ambiguous` set. It writes no
   `command_match` now (`Result.MatchName`; (8) as amended). record-ledger's `run_end` supervisor shape lists
   `exec_rules`, its exec row `closure_of`, and (8)'s field list `argv_read`.
6. **ENAMETOOLONG.** A pathname with no NUL in PATH_MAX bytes was answered `EFAULT` in a run with command rules,
   where the kernel's `getname` answers `ENAMETOOLONG`. A cut that read PATH_MAX bytes is now `ENAMETOOLONG`, and a
   read that faults stays `EFAULT` (`TestExecCommandNeverContinuesUnwalked`; supervisor.md as amended). The change
   holds for every run with an `exec:` section, with or without command rules, since recordExec sets the errno
   before either is asked (`TestExecPathnamePastPathMaxEveryRun`, and supervisor.md's failure
   table, which still said `EFAULT`).
7. **A conformance cell claimed more than it covers.** `execrules/fifo-image-unreadable` cited the final review's
   second finding, but it passed before that fix too: the FIFO was opened, `fstat` found it not regular, and the
   exec was refused `image-unreadable` with `EACCES` all the same. Its Source now says what it covers, and
   `TestExecImageHeadOpensOnlyRegular` is the test that holds the open.

**A further review (2026-10-06).** It found two
more bypasses and five other faults; each was reproduced and is fixed with a test that fails without its fix:

1. **A directly-invoked dynamic loader ran a denied command** (every tier). A loader run as a command maps its
   program and jumps to it in-process, with no execve of the program's own, so under `deny: [rm -r]`
   `ld-linux-x86-64.so.2 /usr/bin/rm -rf tree` was decided under the loader's name alone and deleted the tree on a
   line that said `allow unmatched`. The loader's program is now decided as the exec's image (interpretation 7 and
   (3) as amended), with `loader-unresolved` where it cannot be read as the loader will and
   `loader-program-unmatched` in a restricted run (`TestExecCommandLoaderProgram`, `TestLoaderProgram`,
   `TestEvaluateExecCommandLoader`, `TestIntegrationExecRuleLoader`). 
2. **A 255-byte `#!` script was no script to the parser** (every tier). `binfmt_script` scans for the name's end up
   to and including the buffer's last byte, and `agent.ShebangLine` stopped before it, so a 255-byte
   `#!<253-byte path to rm>` with no newline read as a direct image named `s`, and `./s -r tree` was allowed
   unmatched under `deny: [rm -r]` while the kernel ran rm (`TestParseShebangAsKernel`,
   `TestExecCommandShebangKernelParse`). 
3. **A null `exec.allow` alone no longer loaded.** An earlier fix refused it whatever its siblings were,
   with a message that called the section a deny-list. It is refused now only where the merged section is a
   deny-list ((1) as amended).
4. **A quote character in an `exec.allow` path changed its meaning.** `/home/me/O'Brien/bin/tool` became a pattern
   refused `unterminated ' quote`, and `/opt/a'b'c/tool` granted `/opt/abc/tool`. An entry with no space or tab is
   the path as written, as every entry was before this ADR (`TestCompileExecPathWithQuoteCharacters`).
5. **`compile --exec` did not read a script's `#!` line**, so it said allow for a script the run refuses via
   `shebang`. It reads the first stage now ((4) and C4 as amended, `TestCompileExecReadsShebang`).
6. **ENAMETOOLONG held in every run, not only one with command rules**, as the note above said; the
   failure table still gave EFAULT. Both say every run with an `exec:` section now
   (`TestExecPathnamePastPathMaxEveryRun`).
7. **An errno oracle at the root tiers.** The supervisor read and parsed the head of any regular file, so a root
   supervisor's answer (ENOENT, ELOOP against EACCES) told the agent whether a root-only file starts with a `#!`
   line. A file the kernel's `do_open_execat` refuses the task (no execute bit, `noexec`, permission bits that give
   the task none) is now answered EACCES before its head is read (`execRefused`,
   `TestExecImageRefusesWhatTheKernelRefuses`, `TestIntegrationExecRuleNotExecutable`).

**A further review (2026-10-06).** It found no bypass, but probed the matcher in-process
(`execmatch.Index.Decide`, `decide.ExecCommand`) on the code before these fixes, not a real run, so it does not
meet the acceptance row. It found six faults, none a bypass; each is fixed:

1. **Every static-pie program was read as a loader.** An earlier fix also read any `ET_DYN` ELF with no
   `PT_INTERP` as one, so a static-pie program's first word was read as a program to load: under `deny: [git
   push]`, `rg git push` was refused, and `compile --test` and `--exec`, which knew loaders by name, said allow. A
   loader is now known by its name or by the identity of one of the host's loaders (`ExecCommands.Loaders`), never
   by its ELF (interpretation 7). `TestIntegrationExecRuleLoader` runs a minimal static-pie program on the real
   kernel; it was refused 126 via `loader` before the fix.
2. **The loader's ledger values were in no spec**: the rules `loader-unresolved` and `loader-program-unmatched` and
   `command_via: loader`. REASON-CHANNEL, the record README, supervisor R16b and R29, SEMANTICS §4, OPERATIONS, the
   CHANGELOG and (3) and (8) here name them now.
3. **This ADR left out the last fixes** and still described the null-allow rule it narrowed, said the plane
   column of `compile --test` reports `argv_assurance: kernel` (P1 writes `copied` in every column, (4) as
   amended), and cited agent-contract's R13 as plain "R13", which is now also this ADR's residual. Each is amended.
4. **A conformance cell held no precedence.** `execrules-allow/image-floor-first` ran `git status`, an admitted
   invocation, so it passed with the floor-first guard taken out. It runs `git push` now.
5. **`compile --exec --json` printed text.** It is a usage error now, as `--exec` with `--test` is.
6. **R13 said a root supervisor reads every image.** Not on an NFS export with `root_squash` or a FUSE mount without
   `allow_other` or `allow_root` (R13 as amended).

P1's acceptance still needs a review on this code that finds no unnamed bypass, run by reviewers who probe a
real build under `tego run`.

**A review of a real run (2026-10-06).** Three independent reviewers probed a frozen build under `tego run` at tier
landlock (no root), each with its own isolated ledger, running real argv tricks, wrappers, interpreters, multicall
binaries, loaders, links, descriptor execs (`fexecve`, `execveat`, memfd), the TOCTOU link race and the record. One (program identification: links, cwd, descriptors,
identity, the loader, the decision-to-exec race) **found no bypass** across about 42 runs, and confirmed the earlier
fixes have not regressed. The other two found two bypasses and a set of correctness and record faults; each
was reproduced and is fixed with a test that fails without its fix, each security guard mutation-checked:

1. **A nested multicall binary bypassed a deny** (every tier). A multicall binary with a `busybox` applet
   re-dispatches to itself, and the matcher dropped the dispatch once it passed its depth bound, so
   `busybox busybox busybox busybox busybox rm -r <tree>` ran a recursive rm in-process and was read `allow
   unmatched` under `deny: [rm -r]` (the tree was deleted; one execve of busybox, no execve of rm). The bound now
   fails closed: an unresolved dispatch is refused `command-unresolved` (`command_via: overflow`), as interpretation
   7 and (2)'s security argument now state (`TestDispatchDepthFailsClosed`, `TestIntegrationExecRuleDispatchDepth`).
2. **`git remote rm` was not denied by `git remote remove`** (every tier). git documents "remove, rm" and runs
   `git remote rm`, but the git row lacked the alias, so under the read-only-git profile `git remote rm` deleted a
   remote's refs on a line that said `allow`. The row aliases `rm` to `remove` now, the freshness test holds the
   installed git to it (`TestMotivatingExamples`, `TestReadOnlyGitProfile`, `TestGitRowFresh`).
3. **A sentinel refusal carried a stale command rule.** An `args-unreadable` refusal (and its mirror, and
   `last-refusal.json`) carried the `command_rule` the staged read matched on the prefix; the mirror of a gate
   refusal of a command-allowed exec carried the allowing entry. A sentinel refusal writes no command fields now, and
   the mirror copies them only for a command-rule refusal (`TestExecCommandUnreadableWritesNoCommandRule`, the mirror
   test).
4. **An observe run counted refusals that ran.** `run_end.supervisor.exec_rules.refused` counted a command rule's
   would-be refusal in an `--observe` run, where the exec actually runs; it counts only enforced refusals now
   (`TestExecCommandObserveDoesNotCount`).
5. **`compile` misread a directory entry's grant** as the directory's own basename, so it refused `<dir>/mytool push`
   from an allowed `<dir>/` whose last component was `git`, where the run allows it. Fixed; the image is the requested
   file's basename (`TestCommandFactsDirEntry`). This was the only compile/run disagreement in the over-refusing
   direction; the rest (a missing or unreadable `#!` interpreter, an execute-only image, a loader's program by name,
   a second `#!` stage, the identity interpretation) are `compile` saying `allow` where the run fails closed, now
   listed in the C4 note.
6. **Smaller record and print faults, fixed or disclosed:** a `command-unresolved` refusal's values are in every
   spec; `compile`'s exec heading names a deny-list a deny-list, not "no exec: section" (F7); `drift` tracks a
   constrained allow entry's use one by one (its verdict count sits on the image floor's rule, (8) as amended, F5);
   `binfmt_misc` dispatch is unmodeled at every tier (R9); a `#!` chain past the kernel's depth records
   its decision, not the kernel's `ELOOP` (R14).

Probes against a real run found the remaining bypasses, and they are fixed. The
Status line flips to **P1 acceptance met** only once the repo gate is green with shellcheck and actionlint, the
conformance cells are built, and the root suites pass on both KVM boots for the packages these fixes touched; until
that run completes it stays **not met**.

**Follow-ups (2026-10-16).** A later review (about 210 probes against a real run) found no
bypass and no ledger lie. These are the follow-ups it and a trial with a custom agent left; the Status line is unchanged
(it flips after the whole integration passes KVM):

1. **The git row's global options are held to the installed git.** git 2.49 removed `--super-prefix`, which the row
   still listed as taking a value, so `git --super-prefix push` read push as that value and no subcommand (unmatched
   under `deny: [git push]` on a git that still has the option; git 2.49 and later refuse the word and run nothing).
   It is dropped: the word is now unknown and read both ways, which covers every supported git. `TestGitRowFresh` runs
   every spelling of every global option of the row's root level against the installed git and fails on `unknown
   option`; an option a newer git adds and the row lacks is not a failure (an unknown word is read both ways), and
   the test skips without git.
2. **Two-level verbs are held to the installed git.** The bisect level lacked `next`. `TestGitRowFresh` now reads the
   verbs `git <cmd> -h` lists for every command the row gives a second level and fails on one that is neither a
   subcommand nor an alias there; a verb the row has and the installed git lacks is another supported version's and
   not a failure. `git maintenance -h` lists no verb, so that level is not checked this way (logged). *Amended
   2026-11-02:* the probe also reads parse-options' completion listing (`git <cmd> --git-completion-helper-all`),
   which names maintenance's verbs and the hidden aliases, so maintenance's level is checked too, and a command whose
   usage puts `<subcommand>` where its verbs stand and whose listing names none fails; docs/spec/exec-command-rows.md
   lists the verbs added since.
3. **The interpretation count fails closed where it is held.** `builder.add` dropped every invocation past the
   32nd in silence, and the loader pass discarded a nested pass's `ViaOverflow` sentinel (it names no tool). The
   builder now overflows on a distinct invocation past the count, the loader pass carries a nested overflow, and the
   exec is refused `command-unresolved` via `overflow` (the security argument, as amended).
   `TestBuilderOverflowFailsClosed` is the invariant; `TestInterpretationsOverflowSentinel` drives a 40-stage `#!`
   chain ending in `#!/usr/bin/rm -rf` (unmatched before) and a loaded busybox nested past the dispatch depth.
   *Fixed since:* the gate, the sentinel's other consumer, ignored it (it names no tool); a reading
   that overflowed now matches every command-pattern gate rule ((5), `TestExecMatchesFailsClosedOnOverflow`; the
   gate is handed no `#!` form, so its cases are busybox nested past the depth, with and without a ruled tool at
   the end).
4. **A pathname that names nothing writes no line** (supervisor R16b (0), record minor 8). `execvp` makes one
   `execve` per `PATH` directory, and each miss was a line: refused `unmatched` in a restricted run, observed in a
   run with command rules or for an R28 candidate, allowed in a run with no `exec:` section. In that trial
   seven tries of `git push` made 133 refused exec lines, and `drift` read `exec[bash]` as 25 allowed and 300
   observed for 25 starts. Now, in every run and at every tier (the root tiers share the supervisor's exec path), an
   exec whose walk meets `ENOENT` or `ENOTDIR` is answered with that errno by the supervisor, never continued, and
   writes no line at any record level; `run_end.supervisor.exec_missing` counts them, and where a kernel recorder
   follows execs the supervisor-owned marker drops the kernel's sample of the failed syscall. Answered rather than
   continued, there is no race: a file created at the path later is a later syscall's. *Amended:* that held only in an enforcing run. The answer was a refusal, which an observe run continues
   (R30), so the kernel looked the path up again, a file renamed into place in between ran, and the marker had
   dropped the kernel's record of it: an agent racing a rename ran 44 of 129 execs with no line at tier landlock
   under `--observe`, 22 to 32 of about 100 per plane mode at tier cgroup. A miss is now answered by `respMiss`,
   which is no refusal, so an observe run answers the errno too; the kernel answers the same errno, so nothing is
   enforced. Rejected: continuing in observe and writing the observed line there (a miss would then be an action in
   an observe run's drift and learn, and the line names a file that did not exist when it was written).
   Decided:
   - *What is a miss:* only the exec's own pathname. A path that names something keeps its decision and line, so no
     refusal is weakened: an unlisted file, a command rule's refusal, an R28 candidate that holds a file, a missing
     `#!` interpreter (`interpreter-unresolved`), a loader's missing program (`loader-unresolved`), an unreadable
     head (`image-unreadable`), `ELOOP`, `EACCES`, `EMFILE`, `EXDEV`, an empty or unreadable pathname
     (`TestExecMissKeepsEveryRefusal`).
   - *The record per level:* no line at `off`, `summary` or `full`, and the count. Rejected: an `observed` line at
     `full` only (the record level gates bodies, never events, record-ledger R12, and drift and measure would still
     count it as an action); collapsing a search into its start (state across notifications, R28's argument);
     keeping the refused line and teaching drift, measure and learn to skip it (the line cannot say a miss from a
     refusal of a file that exists).
   - *Who misses (amended):* the residual first written here was wrong. The walk runs
     with the supervisor's credentials, and at a root tier a missing name under a directory the task cannot search
     was answered `ENOENT` where the kernel answers `EACCES`; the existence answer did not predate this change in five
     of six plane cells (no `exec:` section, or a restricted one under lsm or fmod_ret, handed the exec to the kernel,
     which answered 126 for both a present and an absent name in a root-owned 0700 directory). Where the supervisor
     holds `CAP_DAC_OVERRIDE` or `CAP_DAC_READ_SEARCH`, the walk of an exec's pathname now holds the task's own search
     permission to every directory it looks a component up in, as `may_lookup` does: a directory the task is sure not
     to search ends the walk with `EACCES`, and one whose answer is not sure (an access ACL, FUSE, NFS, SMB, Ceph,
     procfs, a DAC capability in another user namespace, unreadable credentials) turns a failed walk into `EACCES`.
     This also closes the older cells (fanotify with a restricted `exec.allow`, a command rule's refusal carrying the
     walk's errno, an unreachable script's missing interpreter answered `ENOENT`). Rejected: `EACCES` for every exec
     under an unsure directory (an ACL that grants the task would refuse what the kernel runs); a check made only
     after a miss (the descriptors are gone, and the interpreter case is no miss); a walker thread that takes the
     task's credentials (per-thread credentials in a Go process, for every exec). Residual: a MAC module that refuses
     the task a directory its bits open is not read (supervisor R16b, *the walk*). Tests:
     `TestExecImageHoldsTheTaskToSearchPermission`, `TestSearchCheckedMeansTheSupervisorBypassesDAC`,
     `TestPlaneExecSearchOracle` (KVM, each plane mode and the listener, no `exec:` section and a restricted one).
     Cost where the check runs (`BenchmarkExecImageSearchCheck`, 0755 directories walked for another user): a miss
     in `/usr/local/bin` 6.2 to 11.2 us, a hit on `/usr/bin/env` 17.1 to 29.3 us, most of it the access-ACL read of
     each directory (`fgetxattr` refuses an `O_PATH` descriptor, so it goes through `/proc/self/fd`); a directory
     whose bits give every class execute and that has no ACL reads no credentials. Tier landlock is unchanged.
   Tests: `TestExecMissWritesNoLine` (four run shapes by three record levels), `TestExecMissUnderKernelRecorder`,
   `TestExecMissObserveAnswersErrno`, `TestIntegrationExecMissWritesNoLine` (tier landlock, `env` searching a `PATH`
   with missing directories and a file on it, and drift over the ledger), `TestIntegrationExecMissObserveRace`
   (tier landlock under `--observe`, the rename race: every exec that ran has its line),
   `TestPlaneExecMissWritesNoLine` and `TestPlaneExecMissObserveRace` (tier cgroup in each plane mode and on the
   listener, in KVM).
   - *Who misses (amended):* an earlier fix closed the existence oracle
     only for directories the task is sure not to search, and only where the walk passed one; three cases stayed
     open, and the text above claimed more.
     (a) *Magic links* (high, introduced by this follow-up). The walk followed `/proc/<pid>/cwd`, `root`,
     `exe`, `fd/N` with the supervisor's own ptrace rights; the kernel follows them for the task only when
     `ptrace_may_access` lets it at that process. A miss behind one was `ENOENT` with no line: 127 for an absent name
     and 126 for a present one, in every plane cell in KVM (a root `sleep` whose cwd sits under a 0700 directory;
     `/proc/1/root`) and at tier landlock, where Landlock scopes the agent's ptrace and the supervisor is outside the
     domain. A magic link of a process other than the task's own thread group is now an unsure step at every tier:
     a walk through it that fails is `EACCES`, decided and recorded; one that reaches a file is decided as before.
     The task's own links (`/proc/self`, `/proc/thread-self`, `/dev/fd`, `/proc/<tgid>`, any of its threads) are
     followed as before. Rejected: `EACCES` for every such link (it refused a granted file reached through a run
     process's descriptor the kernel lets the task follow, and recorded a memfd reached so by its spelling rather
     than as fileless); reading `ptrace_may_access`'s credential and dumpability rules (the LSMs stay unread).
     (b) *Unsure directories* (low). The check stopped at the first unsure directory, so a 0700 directory
     below an ACL'd one was walked through, and a script reached through an unsure step had its head read and a
     missing interpreter answered `ENOENT` where the kernel answers `EACCES`. The check now goes on past an unsure
     directory, and a walk that reached a file through an unsure step (an unsure directory or another process's
     magic link) marks the image so; a failed interpreter walk of its chain is then answered `EACCES` under
     `interpreter-unresolved`. The cost: a script reached through an ACL that grants the task, with a missing
     interpreter, exits 126 where the kernel gives 127.
     (c) *Autofs* (low). The walk opens each component `O_PATH` as a final lookup, so an idle direct or
     systemd automount point is not mounted (`follow_automount` wants `LOOKUP_PARENT`, `LOOKUP_DIRECTORY` or
     `LOOKUP_AUTOMOUNT` for a positive dentry), and the next name was a miss with no line, also under `--observe`,
     where before this follow-up the exec was continued and ran. A walk that failed in an autofs directory is no
     miss now: it keeps its errno and is decided as before (continued under a contract with no `exec:` section or a
     granted spelling, refused with the errno otherwise, recorded). Rejected: triggering the mount from the walk (a
     root supervisor mounting filesystems for an exec it may refuse).
     Tests: `TestExecImageMagicLinksOfAnotherProcessAreUnsure`, `TestIntegrationExecMagicLinkOracle` (tier landlock,
     no `exec:` section and a restricted one), `TestPlaneExecMagicLinkOracle` (KVM, each plane mode and the
     listener), `TestExecImageHoldsTheTaskToSearchPermission`'s access-ACL cases, the unsure-interpreter and autofs
     cases of `TestExecMissKeepsEveryRefusal`, `TestExecImageAutofsFailureIsNoMiss`,
     `TestExecAutofsFailureIsContinuedWhereItWas`. Residual: an autofs case is unit-tested only (the guest has no
     automounter).
   - *Who misses (amended 2026-10-16):* three more places where the
     walk's answer differed from the kernel's.
     (a) *A non-leader thread's own directory* (low). The top-level `/proc/<tid>` of a non-leader thread of
     the task's group (a pid directory of its own, hidden from readdir) and the `task/<tid>` entries beneath it were
     not the task's own, so a miss behind their links was `EACCES` with a refusal line where the kernel answers
     `ENOENT`. They are its own now, known by the `Tgid` line of the `status` file read through the directory.
     (b) *Automount points beyond autofs* (medium). Only autofs was recognised; under any other idle
     automount point (NFS crossmnt and referral submounts, CIFS DFS links, FUSE submounts, debugfs's `tracing`) the
     walk missed a file that exists and answered `ENOENT` or `ENOTDIR` with no line. A failure at an inode `statx`
     reports `STATX_ATTR_AUTOMOUNT`, or in an autofs directory, is no miss now and is decided as (c) above says (where
     a decision plane takes the run's execs through the fast handover, the kernel decides it: in the guest it mounts
     tracefs and answers `EACCES`). This replaces (c)'s residual: the guest has debugfs's `tracing` stub, and the root
     unit test and the plane test run there.
     (c) *Mode bits that allow on a filesystem that decides by caller* (low). The search check answered a
     directory whose bits give every class execute sure before it asked which filesystem it was on, so a FUSE, NFS,
     SMB or Ceph directory the server refuses the task was walked through at the root tiers; and a procfs directory
     of another process (`/proc/<pid>/fdinfo`, 0555, whose permission operation asks `ptrace_may_access`) was walked
     through at every tier, so a miss there told the agent which descriptors that process holds open (reproduced at
     tier landlock, unprivileged: 127 for an absent descriptor, 126 for a present one). Both are unsure now. The
     cost: a failed walk through a `PATH` directory on NFS or FUSE at the root tiers is `EACCES`, not a miss, and is
     decided as any failed walk is (*amended 2026-10-16:* this said a refusal line for
     every run). Where the supervisor decides the run's execs (an `exec:` section on the listener, or command rules
     or an exec gate) it answers `EACCES` with a refused line (observed for a `PATH` candidate or under command
     rules), so a command found nowhere exits 126 rather than 127; with no `exec:` section the exec is continued under
     an `allow` line, and in a plane run without command rules or a gate it is handed to the kernel, which answers its
     own errno in both (`TestExecUnsureWalkPerRunShape`). Rejected: procfs as a whole in the server list (the task's
     own `/proc/self` and `/dev/fd` walks would all be unsure). Residual: under `hidepid=invisible` another user's
     pid directory is reached by the walk where the kernel answers `ENOENT`, so whether a pid exists is answered 126
     rather than 127 (it is public through `kill(pid, 0)`).
     Tests: `TestExecImageMagicLinksOfAnotherProcessAreUnsure` (the non-leader cases),
     `TestExecImageProcDirsOfAnotherProcessAreUnsure`, `TestExecImageServerFSDirectoriesAreUnsure`,
     `TestIntegrationExecProcDirOracle` (tier landlock), and in KVM `TestExecImageAutomountPointFailureIsNoMiss`
     (with an autofs-only control that still misses), `TestPlaneExecProcDirOracle` and `TestPlaneExecAutomountIsNoMiss`
     (each plane mode and the listener). No NFS, CIFS or FUSE server ran: their stubs are recognised by the same
     `S_AUTOMOUNT` flag as debugfs's, read from the kernel source, and their permission operations likewise.
   - *Who misses (amended 2026-10-16, low):* (c)'s list of
     filesystems that decide by the caller was open, and every filesystem it did not name was read by its mode bits:
     kAFS (`afs_permission` asks the cell with the caller's key), 9p mounted `access=user`, Coda and eCryptfs (which
     asks its lower inode as the caller) were sure on 0755 bits, so a root walk's miss there still told the agent
     whether a name exists in a directory the server refuses it. The list is closed now, the other way round
     (`modeBitsFS`): a directory is read by its bits only on a filesystem whose permission operation, for `MAY_EXEC`
     on a directory, is `generic_permission` over what the walk reads (ext2/3/4, xfs, btrfs, f2fs, tmpfs, ramfs,
     overlayfs, squashfs, erofs, isofs, vfat and msdos, exfat, udf, sysfs and the cgroup hierarchies, debugfs,
     autofs); procfs keeps its own reading; every other directory is unsure whatever its bits, ntfs3, ZFS and any
     filesystem the list does not name included. The cost is (c)'s on more filesystems (a `PATH` on ZFS or a 9p share
     leaves lines for an `execvp` caller's misses where the supervisor decides the run's execs). Rejected: adding
     kAFS, 9p and Coda to the server list (still open); every directory unsure (a line for every `PATH` miss on ext4
     at the root tiers). Residual: the list is read from the kernel source, not measured (no AFS, 9p, Coda or ZFS ran
     here); a MAC module stays unread on a listed filesystem. Test: `TestExecImageServerFSDirectoriesAreUnsure` (kAFS,
     9p, Coda, eCryptfs, ZFS and an unknown type unsure; each listed type sure).
   - *Who misses (amended 2026-10-17, low and nit):* (b) of the
     earlier note covered a failed name lookup at an automount point, not a failed `..` step out of one. An NFS
     crossmnt or referral stub has no lookup operation, so `..` from it fails `ENOTDIR` too, and at tier landlock,
     where no search check makes the walk unsure there, `sub/../tool` through an idle stub was a miss with no line
     where the kernel's walk mounts the submount and climbs back out to the tool. A `..` that fails at an automount
     point is no miss now (`TestExecImageDotDotOutOfAnAutomountStubIsNoMiss`, with the stub stood in for). And (b)'s
     wording, "does not mount an idle automount point", holds for a positive dentry only, as (c) first said: an
     indirect autofs map's key is a negative dentry, which `follow_automount` mounts on any lookup, so the walk's own
     lookup has the automounter mount it, as root at the root tiers, and misses nothing beneath. Residual: past a
     directory the walk is not sure the task may search, it can ask for such a mount the task's own lookup would not
     have reached.
5. **The static-pie fix is complete.** The fix removed the ELF-shape reading everywhere (no code reads `ET_DYN` or
   `PT_INTERP` to find a loader; the supervisor, `compile --test` and `compile --exec` know a loader by name or by a
   host loader's identity). Re-checked where it had not been: in a run whose images are restricted a granted
   static-pie program with a ruled tool's name, a ruled tool's path or an ungranted path as its first word is allowed
   on its own grant, never `loader-program-unmatched`, and a `#!` script whose interpreter it is reads no loaded
   program (`TestExecCommandStaticPieIsNoLoader`, `TestIntegrationExecRuleStaticPieRestricted`, beside the deny-list
   cases of `TestExecCommandLoaderProgram` and `TestIntegrationExecRuleLoader`).

*Amended 2026-10-16, revised 2026-10-17 (implementation note): where C8's Targets and Limits are
asserted.* The full gate failed `TestExecCommandCostBudget`'s unguarded case at +12.247 µs against its +12 µs Limit
while other jobs loaded the reference machine; alone it passed. The figures were already the fastest of hundreds of
interleaved A/B rounds, which escapes a preemption but not a lower all-core clock or a busy sibling hyperthread: under
16 busy loops on the reference machine the cases took 2.3 to 4.9 times their quiet figures even in the handling thread's own
CPU time, up to 2.2 times their Limits, and with only other jobs' work on the machine (load average 6 to 8) the unmodified
cases missed their Limits in 3 runs of 12. The Targets and Limits above are unchanged, and so is their statistic. They
are now asserted where the machine is quiet: with `TEGO_TIMING_BUDGETS=1` both tests hold every case to its Limit (over
it fails) and Target (`TARGET-MISS`) on the wall clock, the exec cases the fastest of their interleaved A/B rounds (the
side that goes first now alternates from round to round), the index the median of seven 100 ms `testing.Benchmark` runs,
as before. `scripts/timing-budgets.sh` runs them so, and CI's bench-gate job runs it first on its own runner, before the
gate's builds and rounds; `make budgets` runs it on a developer's idle machine. Every other run, the unit gate, holds
the same measurement to ten times the Limit (`testutil.CeilingFactor`), on the handling thread's own time
(`testutil.MinOfThread`; the index: the fastest of 1000 batches of 256 decisions): each sample's wall clock less the
thread's run-queue delay over it (`/proc/thread-self/schedstat`) beyond the CPU time the process's other threads had
over it, where the thread never blocked, and the whole wall clock of a sample in which it did. That leaves out every
wait for a CPU another process adds, which nothing bounds, and keeps the code's work, the work it hands to other
goroutines and the waits the code makes, so only a regression of several times the budget reaches the ceiling on a
busy machine, whether it works or waits; it prints no `TARGET-MISS`. A wait can still hide whole in the own time where
another process's work fills it and the thread never blocks (a thread that process preempts just as it parks, or a
wait that yields its CPU instead of sleeping), so the same measurement's wall clock
is held to a hundred times the Limit (`testutil.WallCeilingFactor`), which no run under the busy loops came near (the
worst fastest wall-clock sample was 6.1 times a Limit, the 8192-argument cases', in a 4-vCPU KVM guest with 16 busy
loops; every other case's stayed under 2.3 times) and which any wait of more than a hundred times the budget fails on
any machine. The first version of the unit gate (2026-10-16) held CPU time alone, and a review found it blind to
waits: a copy that slept 2 ms in every command-rule decision read +43 to +57 µs of CPU time and passed, as did one that
slept 20 ms; held on the own time they fail, +2.08 to +2.17 ms and +20.1 to +20.2 ms under the busy loops, and so does
one sleeping 500 µs (+573 µs to +1.08 ms). Proof (docs/BENCHMARKS.md, "Timing budgets in the test suites", has the
figures): a copy slowed by about 7 µs before every command-rule decision fails budget mode in 12 runs of 12 with the machine
as found (the unguarded case +14.8 to +32.7 µs) and in 22 of 22 in an idle 4-vCPU KVM guest (+18.8 to +36.9 µs), and 12
of 12 there on the tip after its rebase (+18.0 to +35.7 µs), where in every round it read more than the unmodified run
of the same round, though the host's load let the unmodified cases meet their Limits in only 9 of those 22; one slowed
by about 130 µs fails the unit gate under the busy loops (+220 to +237 µs of own time), and so do the sleeping copies
above; the index copies likewise. Under 16 busy loops in that guest the touched packages' unit and unprivileged
integration suites passed 28 runs of 28 each before this change's rebase, 252 of 252, the
C8 cases' own time at most 2.0 times their Limits; on the rebased tip the five packages whose test binaries the rebase
changed passed 139 of 140, the other a load-dependent test of the cgroup package's own, since fixed (the package then
passed 28 of 28), with the C8 cases' own time at most 2.3 times their Limits. An earlier build's sweep failed two of
internal/testutil's new tests, since corrected. Measured 2026-10-16 at load average 2.5: unguarded +6.9 µs, the script
+15.6 to +16.4 µs, 16 arguments +10.8 to +11.8 µs, 128 arguments +22 to +23 µs, 8192 arguments +0.67 to +0.82 ms, past
the bound +0.63 to +0.72 ms: the unguarded and script cases miss their Targets and meet their Limits. Rejected: judging
a figure against a yardstick workload probed beside or around the code, with the machine's slowdown divided out (review
measured it loosening the Limits twice, and once fixed it still failed 15 runs of 28 under the busy loops, the
with-rules path slowing to +56 to +75 µs at the same probe readings: the code's sensitivity to a busy core is not the
yardstick's); the Limits held in CPU time in the unit gate (CPU time still slows two to five times under load); the unit
gate on CPU time alone (blind to a wait the code makes, above); the unit gate on the wall clock alone at ten Limits (it
counts every wait for a CPU, which on a machine with more runnable threads than CPUs has no bound); the own time alone
(a wait preempted as it parks hides in it whole); the run-queue delay taken out of every sample, blocked or not (a delay
that overlaps a sleep hides part of it, and the fastest sample is the one that hid most: the 2 ms sleep read +1.30 ms
so); retrying the comparison (a sustained slowdown is over on every attempt); hardware counters (`perf_event_open` is
refused unprivileged on Ubuntu and on many CI runners); skipping a budget when the machine looks loaded (nothing would
check it on a shared runner); the B side as the yardstick (it is Tego code); raising a Limit. *Amended 2026-10-17:*
the own time first took the run-queue delay out whole, and a wait for work handed to
another goroutine hid in it wherever the process had fewer CPUs than runnable threads, even on an idle machine (the
helper's wake-up takes the CPU from the waiting thread before it parks, so the thread never blocks): a copy of this
path that hands 500 µs of work off in every command-rule decision passed the unit gate beside one busy loop on its CPU
(+26 µs of own time), and a 500 µs hand-off in a process held to one CPU read 3.7 µs. The delay the process's other
threads' CPU time accounts for now stays in the own time (`CLOCK_PROCESS_CPUTIME_ID` less the thread's own, read around
each sample), and the copy fails at +524 µs; under 16 busy loops in the 4-vCPU guest the four packages whose figures
this changes passed 112 runs of 112, the C8 cases' own time at most 1.9 times their Limits. Between ten and a hundred
Limits, a wait another process fills without the thread blocking still passes the unit gate (a 1 ms `sched_yield` loop
read +27.9 µs beside the busy loop); budget mode sees it. Rejected: the process's CPU time over the sample as a floor on
the own time (another goroutine of the process working on another CPU at once would raise the own time past the wall
clock); a sample with an involuntary switch and CPU time far under the wall clock less its delay counted whole (a
hand-off's sample has neither: its own time equals its CPU time).

## Implementation note (2026-10-16)

R2's deny-list bullet said compile discloses a copy, but `exec-rule-coverage` fired only for a deny-list beside
`fs.write`. A deny-list with no write entry still runs a copy: `memfd_create`, the bytes of `/usr/bin/git` written in,
and an exec of `/proc/self/fd/N` ran git's code (allowed `unmatched`, `fileless: true`) under `deny: [git]`, because
images are unrestricted there at every tier (no memfd arm, `decideExec` allows a fileless image, the plane's
`bprm_check` and ADR 0027's `exec-map` decide only an exec-restricted run). The warning now fires on every deny-list;
beside `fs.write` it adds the memfd to the copy on disk, and without it it names the memfd, the deleted file and a
program's file mapped into the agent's own process (`TestCompileExecCommandsWarnings`). Rejected: giving deny-list
runs the restricted run's memfd arm and fileless refusal. It would refuse every `memfd_create` on a kernel without
`MFD_NOEXEC_SEAL`, and every unnamed image an agent's runtime makes, in the mode meant to rule named commands, while a
program's own file mapped executable where it lies stays ADR 0027's residual in a restricted run too. Command rules
are launch rules (R1), and the disclosure says so where an author reads it.

## Implementation note (2026-10-17)

An ask-only `exec:` section (`exec: {ask: [git push]}`) is a deny-list too (R2), and the warning above named its tool
"a denied program" and said "a deny entry refuses", though nothing there is denied. It now names the first deny
entry's tool, else the first ask entry's, and says what that entry decides ("an ask entry decides a command by its
name, argv[0] and identity, not the program's code"). A deny-list that sets `exec.anonymous` was told that `exec.allow`
refuses images with no name "unless exec.anonymous is set", which it already was; its fix now says to drop
`exec.anonymous` as well (`TestCompileExecCommandsWarnings`).

## Implementation note (2026-10-17)

(3)'s "every exec reads its names and argv[0]" was true only of an exec the image floor allowed: `recordExec` called
`decideCommand` after the floor and only on its allow, so the `#!` chain and a directly-invoked loader's program were
never walked for an exec the floor refused or, in an observe run, would refuse and runs. The `dropped` flag
(supervisor R16b) judges what that walk reaches, so an observe run's would-be refusal that ran a binary it wrote
carried no flag. The walk now runs for every exec of a run with command rules whose own walk reached an image; of an
exec the floor did not allow only its `dropped` is kept, and the command rules still decide only an exec the floor
allows (`TestExecCommandRulesLeaveTheFloorsDecisionAlone`). `dropped` is judged once per exec and copied by every
owner of the line, the naming a kernel recorder's line takes included (`TestExecDroppedIsOneFactEveryOwnerCarries`).
Rejected: disclosing that the walk follows the floor's verdict. It keeps a flag whose coverage depends on a decision
it does not describe, and each such condition was a place where the text and the code had already parted. Rejected
too: walking only an exec that will run (allowed, or observed). A refused exec's line already judges its own image,
refused or not, and its loads are the same kind of fact. Rejected as well: narrowing `dropped` to the exec's own image
everywhere, which has one rule but lets the agent strip the flag by naming its binary as a loader's operand. The cost falls on refused and observed execs, and is the walk alone (*amended 2026-10-19*:
this said such execs "read argv for their line anyway"; in fact `decideCommand` went on, for a guarded
tool, to the whole staged argv read and the match, whose answer was thrown away, and the line then read argv a second
time, +460 to +790 µs at 8192 arguments). `decideCommand` now takes `walkOnly` for an exec the floor did not allow and
stops once the `#!` chain and a loader's program are walked, before `Guarded`, so such an exec reads argv[0] for the
walk and the whole vector once, for its line. `TestExecCommandCostBudget` holds a floor-refused guarded tool to +10 µs
(limit +20 µs) at 8 arguments, and at 8192 to at most 4 KiB more read of the target's memory than the same exec
without command rules (the fix reads some 270 bytes more, argv[0] again; before it, some 240 KiB), its time reported
against a +30 µs target only: both sides pay the line's own copy of the vector, 5 to 7 ms, whose minimum varies by
tens of µs with the host's load. An exec that has no line is not walked at all: under
`record: off` with no exec gate, a PATH-search candidate or an observed exec (an unreadable pathname with no `exec:`
section) is quiet, and `dropped` is read by a line only, while the command rules never change the verdict the floor
gave such an exec, so whether it is quiet is known before the walk. Rejected: keeping the decision's argv copy for the
line when the decision is dropped, which spares the second read but still pays the staged read and the match that
nothing uses.

## Implementation note (2026-10-19, P2 K0: the kernel facts, measured on every row)

K0 is built as a test-only probe, not as plane code: `bpf/testonly/exec_pin_facts.bpf.c` (its binding builds with
`-tags integration,tegobpf` only, once per reader as the plane is), the pin MAC both halves share
(`bpf/include/exec_pin.h`, `internal/execpin`), and `internal/bpf` `TestExecPinKernelFacts`, a root-must-pass test.
It ran in KVM guests on 6.17 (the host's kernel, also under `lockdown=confidentiality`, where the probe-read build is
refused and the rd build ran), RHEL 9's 5.14, AL2023's 6.1 and 6.12, Debian 13's 6.12, Ubuntu 24.04's 6.8 and
Fedora's 7.0 and 7.2, each on the `lsm=...,bpf` boot (both modes) and the default boot (fmod_ret), in both reader
builds. Every fact (3) and (7) rely on held on every row (the test logs each figure below):

- `tp_btf/sched_process_exec` with the MAC loop loads in both builds. Verified instructions for a 128 KiB-capable
  check (a `bpf_loop` over 256-byte chunks, each chunk's 32 words unrolled): about 13,400 on 6.1, 20,200 on 5.14,
  6.12 and 6.17, 51,600 on 6.8, 77,500 on 7.2 and 279,900 on 7.0. That is under the 1M limit everywhere, but 7.0's
  figure says the plane's own program should keep the unrolled part small (K1 measures it against the plane's load
  budget).
- `bpf_send_signal(SIGKILL)` from it kills before the probe's first instruction (a static x86-64 program whose first
  system call writes a byte to a pipe, which stayed empty): 60,000 kills per row (six build and mode runs of 10,000),
  zero send failures on every row.
- `bpf_probe_read_user` over `[arg_start, arg_end)` reads the vector the exec passed, whole or as a covered prefix,
  across chunk boundaries and up to the 128 KiB bound; one byte past it is not read (`-E2BIG`, the plane refuses).
- The pin MAC in BPF equals the Go implementation on the 64 published SipHash-2-4 vectors, in each domain and under
  two keys; the Go half is checked against the vectors themselves.
- Each later binfmt stage reaches bprm_check with its own file (a two-stage `#!` chain gives three stages, the
  script's, the interpreter script's and the program's), only the first has `interp == filename`, and the area at
  sched_process_exec is binfmt_script's vector, `[interp, arg, filename, argv[1:]...]` per stage.
- `bpf_get_ns_current_pid_tgid` in both modes' bprm_check answers the task's ids in the launcher's namespace. For a
  task in a child pid namespace it answers `-EINVAL` (the helper names only the task's active namespace), so such a
  task would get no key and every exec of it would be refused `pin-unverifiable`: fail closed, and unreachable in a
  run, whose supervisor refuses every `CLONE_NEW*` (supervisor `topology.go`). The helper compares its `dev` with
  nsfs's `s_dev` in the kernel's encoding (`major << 20 | minor`), not `stat`'s `st_dev`: Prepare must convert, since
  the two agree only for a minor below 256.
- `current->ptrace` at bprm_check says `PT_PTRACED` for a traced exec only.
- `current->start_boottime` at bprm_check, divided to clock ticks, is `/proc/<pid>/stat`'s start time read outside a
  time namespace; read inside one with a boottime offset it is shifted by exactly the offset (R6(i)'s premise). On 6.1
  a child that shares its parent's memory cannot enter the new time namespace (`clone` with `CLONE_VM` answers
  `EINVAL`), and Go forks with `CLONE_VM`: K5's doctor probe must start its reader without it, as the test does.
- A traced exec killed at sched_process_exec never gives its tracer a stop: on every row the tracer's wait saw the
  SIGKILL death first, so `PTRACE_POKEDATA` had no stop to write in, and the pipe stayed empty.
- Not provoked: task storage's NULL answer on 5.14 and 6.1 (its busy lock, taken only when a task-storage program
  nests on the same CPU). The probe checks every answer; the plane's refusal on NULL is K1's source test.

Not yet built: K1 to K8. ADR 0044's `trace_gate` pin flag is not reserved in code until K1 lays out the pin.

## Implementation note (2026-10-19, P2 K1: the kernel half of the pins)

K1 is built: `bpf/decide_execpin.h` (included by `decide.bpf.c`), the pin types in `bpf/include/events.h`, the three
maps in `maps.h`, the two MAC domains it adds to `exec_pin.h` and `internal/execpin`, the argv-guarded refusal in
`decide_control.h`, the recorder's `pin_seq`, their Go mirrors in `internal/bpf`, the loader keeping and attaching
the pin program in both modes (`enforce/cgroup` plane.go), and the observer's naming of a pin step's refusal
(`exec`, `refused`, `exec-not-allowed`, rule `exec.pin`, `plane_reason`). Nothing sets `TEGO_SLOT_EXEC_PIN` yet: K2's
Prepare and K3's supervisor turn it on together, so no run is pinned and every run's behaviour is unchanged (the
programs return after one header read). enforce-plane §2.22 describes it. Where it departs from (3) and (7), and why:

- **Names are pinned as keyed MACs, not bytes.** The pin holds `mac_name` (domain 4, the image's final name as its
  dentry holds it) and `mac_path` (domain 5, over `bprm->filename` with its length `len_path`), each SipHash-2-4 under
  the run's key, instead of two 255-byte strings. No process of the run has the key, so equal MACs say equal bytes; the
  pin is 160 bytes instead of about 640, and bprm_check compares two words instead of 64. Rejected: the bytes (a
  640-byte value copied into task storage per exec and two 32-word compares in bprm_check).
- **The whole spelling, not its basename.** bprm_check MACs all of `bprm->filename` and checks the NUL after it, which
  is stronger than (3)'s basename and needs no search for its last `/`. The supervisor knows the exact spelling: the
  path the exec passed, or `/dev/fd/<n>` and `/dev/fd/<n>/<name>` for an `execveat` relative to a descriptor
  (`alloc_bprm`); "named by descriptor" needs no flag. A spelling rewritten after the supervisor's read ends in
  `pin-mismatch`.
- **No hash-entry key reuse and a stage count.** As (3) says; the task's state also keeps `cur_seq` from bprm_check to
  the next exec, which the recorder reads into `tego_ev_exec.pin_seq` whichever of the two `sched_process_exec`
  programs runs first.
- **The area MAC and the kill are global functions,** each verified once, and the MAC has one call site whichever area
  the form names: as static code the program verified in 16,251 instructions on 6.17 and 22,971 on Fedora's 7.0,
  over `planeVerifiedBudget` (20,000); as built it verifies in 8,733 on 6.8 and 6.17 and 11,800 on 7.0. The chunk is
  64 bytes (eight words), and the last chunk's words go through a second `bpf_loop`, not an unrolled chain.
- **Reason codes and ABI** take the next free numbers: 14 to 19 (`pin-missing`, `pin-mismatch`, `pin-unverifiable`,
  `argv-changed`, `argv-unreadable`, `exec-traced`), the kill sample's kind 30 (26 to 29 were taken since the ADR was
  written), `TEGO_EVENTS_VERSION` 4. ADR 0044's `trace_gate` is reserved as pin flag 0x04, read by no program.
- **A kill with no slot header** (a slot cleared between bprm_check and `sched_process_exec`) is `pin-unverifiable`;
  a dying task is marked argv-guarded so no peer writes into it while the kill lands.

Tests: `bpf/tests` `TestExecPinOnlyNarrows`, `TestExecPinLoopsAreBounded`, `TestExecPinKeepsNoPinOnTheStack` and
`TestExecPinStorageNullRefuses` (the four source rules K1 names); the layout parity rows of every new struct;
`TestPlaneObjectShape` (the pin program per mode, its section and attach type) and `TestPlaneLoadsAndAttaches` (it
loads, attaches and stays under the budget, and an exec outside every run still runs); `observe`
`TestRecorderNamesExecPinRefusals`. In KVM guests on the host's 6.17, both boots and under `lockdown=confidentiality`,
the plane's tests (`TestPlaneLoadsAndAttaches`, the step A to C, unix and name `HooksDecide` tests, the object shape and
parity) pass in both reader builds, the pin program verifying in 8,733 instructions and bprm_check in 6,411 (probe-read)
and 8,386 (rdonly); a narrowed load test gives 8,733 on Ubuntu 24.04's 6.8 and 11,800 on Fedora's 7.0, where
`socket_listen` verifies in 43,850, over the budget, in code K1 does not touch (an open item of its own).

*K1 matrix (2026-10-19).* The same tests and K0's `TestExecPinKernelFacts` ran on every row, both boots
(`lsm=...,bpf` for both modes, the default boot for fmod_ret), in both reader builds where the kernel has the rd
reader: they pass on RHEL 9's 5.14, AL2023's 6.1 (pr build only, as before), AL2023's and Debian 13's 6.12, Ubuntu
24.04's 6.8 and the host's 6.17 (also under lockdown). The pin program loads and attaches on every row in both modes,
verifying in 5,438 instructions on 6.1, 8,733 on 5.14, 6.8, 6.12 and 6.17, and 11,800 on 7.0 and 7.2; bprm_check with
the pin step verifies in 5,898 (6.1) to 11,813 (7.2). On Fedora's 7.0 and 7.2 the load and decide tests fail on
`socket_listen` alone (43,818 to 44,096 instructions against the 20,000 budget), in code K1 does not touch.

## Implementation note (2026-10-19, P2 K2 and K3: Prepare's and the supervisor's halves)

K2 and K3 are built together, as (P2's plan) says they must be: `enforce/cgroup` `execpins.go` (Prepare's key, pin
map and header; `Handle.ExecPins`, `PinExec`, `SweepExecPins`; the slot's clear), `supervisor` `exec_pin.go` (the
`ExecPinner` seam and the pin written before `CONTINUE`), `internal/execpin` `pin.go` (the pin's encoding, which both
halves share), and the runtime's adapter (`internal/runtime` `exec_pins.go`). A run is pinned only when its caller
asks (`cgroup.Run.ExecPin`), and the runtime asks for none yet: a kill must never read `allow` in the ledger, so the
request is turned on with K4's fail-closed fold of the kill sample, and until then no run is pinned and every run's
behaviour is unchanged. Where it departs from (3), (8) and (11), and why:

- **The seam is smaller.** `ExecPinner` has `Pin` and `Sweep`; `Options.ExecPinKey` carries the key. `ExecPins()` is
  the handle's (the claim waits for K5's doctor cell, which (7) makes its condition), and `Kill` joins with K4's
  `kill_failed` backstop, its only caller. The pin's `gen` and `seq` are the handle's: the supervisor encodes a pin
  with both zero and the handle writes the run's gen and its next seq, so a supervisor cannot write a pin of another
  run's gen.
- **What a pin covers, per run.** In a run with command rules the form and `#!` chain are the ones the matcher read,
  `k` is the result's `K` (at least argv[0]) and `guard` is `Index.Guarded`'s answer (its dispatch-sensitive set). A
  script pin covers binfmt_script's whole vector, so the supervisor reads the whole vector (to the 128 KiB bound) for
  a script whose decision needed argv[0] alone, and refuses the exec when that read's first `K` elements differ from
  the ones decided. Under an exec gate the pin covers the whole vector the gate scored (an incomplete one is already
  `gate.unreadable`) with `guard` set. In a run with an exec gate and no command rules the image's head is not read:
  the pin is the unknown form with `interp_ok`, which (3) admits for exactly that run (no rule is reachable through an
  interpreter), so the gate-only path pays no extra read.
- **Facts no pin can carry are refused, not only a failed write.** A final name past 255 bytes, a `bprm->filename`
  past 4,095, a covered area past 128 KiB, an image (or interpreter) whose identity as the plane holds it cannot be
  read, and a vector that changed between two reads are each `exec.pin`, `pin_unavailable`, with `EACCES`: the kernel
  would refuse or kill them. The identity is fdinfo's `ino` and the device of the mount fdinfo's `mnt_id` names, from
  the supervisor's kept mountinfo (`MountDev`), in the kernel's encoding.
- **The script's own name in the vector is the kernel's spelling.** binfmt_script puts `bprm->interp`, which is
  `bprm->filename` at the first stage, in the vector: an `execveat` relative to a descriptor maps
  `/dev/fd/<n>/<path>` there, so the pin MACs that spelling (`execpin.ScriptVector` over `execpin.FilenameOf`). P1's
  matcher reads the raw path in that slot (`Facts.ScriptArgv`); the two name the same file, which the pin's image and
  chain identities hold.
- **The time namespace check** reads `/proc/self/timens_offsets`, which shows the namespace the launcher's children
  get: pins are off unless `/proc/self/ns/time` and `time_for_children` are one namespace and its boottime offset is
  zero (or the kernel has no time namespaces). K5's doctor cell adds the known-answer probe.
- **An empty vector** is pinned as `[""]`, which the kernel maps since 5.18; on RHEL 9's 5.14 such an exec would be
  killed `argv-changed`, fail closed (K6 checks it).
- **The record** takes `record_minor` 12 for `pin_unavailable`; K4's fields join the same step.

Tests: `internal/execpin` `TestBuild*`, `TestFilenameOfIsAllocBprmsSpelling`, `TestEncodeLayout`; `internal/bpf`
`TestExecPinEncodingIsTheMapsLayout` (the encoding is `bpf.ExecPin`'s layout); `supervisor` `TestExecPin*` (a pin
before the answer, its key, identity, name, filename, MACs, forms and flags; a refusal writes none; an observe run
none; a write or build failure refuses `exec.pin` with `pin_unavailable`; a full map swept of dead threads' pins
once) and `TestPinName`; `cgroup` `TestSlotHeaderCarriesExecPin`, `TestBootOffsetZero`,
`TestLaunchPidnsIsTheKernelsEncoding`, `TestPinExecWritesGenAndSeq`, `TestPreparePinsAPinnedRun`; `runtime`
`TestExecPinnerOnlyForAPinnedHandle`; and in KVM guests `TestPlaneExecPinsOnRealKernel` (a pinned exec runs, an
unpinned one and one of another image are refused `EACCES`, one whose argv[0] differs is killed by SIGKILL, a script
runs under a script pin and is refused under one naming another interpreter).

## Implementation note (2026-10-19, P2 K4: the ledger's fold, and pins turned on)

K4 is built: the plane's held sample (`TEGO_EV_PLANE_EXEC_HELD`, kind 31, `struct tego_ev_exec_held`), the
recorder's fold (`internal/runtime/observe` `exec_pin.go`), the record fields of (8) at `record_minor` 12, and the
activation: `enforce` asks Prepare to pin every run whose table has command rules or an exec gate that can escalate
(`execPinWanted`, since K5 `RuleTable.ExecFactsDecided`), and the runtime tells the recorder (`SetExecPins`) when the handle pinned its slot. Where it departs
from (8), and why:

- **`kernel_pinned` rests on a positive sample, not on a drained ring.** (8) gives an exec record `kernel_pinned` once
  the observer drained the ring past it with no kill sample for its seq and no loss in the window. That needs a loss
  counter that names the window, which the ring does not keep: a loss is counted per run, after the fact. The pin
  program instead reserves a held sample after a match, and only there (`bpf/tests` `TestExecPinHeldOnlyAfterTheMatch`):
  every exec it checks has exactly one held or kill sample, and the line says `kernel_pinned` only when the held sample
  of the pin the decision wrote arrived (its seq, the exec record's `pin_seq` and the naming's `PinSeq` are one). A
  lost held sample (a full ring counts a lost sample) is `unproven` with the gap `exec-pin-unproven`, as (8) says of
  loss; the cost is one 48-byte ring sample per pinned exec. Rejected: the drained-ring rule (it cannot name the
  window, so it would either claim under loss or never claim).
- **The fold pairs by process, and checks by seq.** The two halves are reserved in one tracepoint invocation of the
  exec's own task, so nothing else of that process lies between them in the ring; the fold pairs them by `(pid,
  start)`, and a later record of the process (its next exec, a file it opens, its exit) or the final drain settles a
  half whose partner never came. A kill of an exec no pin was armed for carries no seq, so seq alone cannot pair it.
- **A kill always has its line.** A kill whose exec record was lost is its own `refused` line (the naming joined by the
  old tid when it can be); a kill in a run the recorder was not told is pinned is still a refused line, never nothing.
- **Pins only where a kill can be recorded.** Prepare grants pins only when the kernel recorder has exec outcomes (the
  exec-result programs attached), and the supervisor refuses a pinned exec it would continue while no recorder reads
  the run (`exec.pin`, `pin_unavailable`): a pinned exec's line is the kernel's (the supervisor hands its naming over),
  and with no kernel line a kill would leave the supervisor's `allow` standing. The MCP start line of an exec whose
  line the kernel owns is the recorder's alone, written after the exec's own and, in a pinned run, only after the held
  sample (P1 had the supervisor write it too for a run with command rules).
- **The backstop.** A kill sample with `kill_err` makes the line `kill_failed` and `detected_bypass`, adds the gap
  `exec-pin-kill-failed`, and the launcher sends SIGKILL through the process's pidfd, opened before it checks that
  `/proc`'s start time is the sample's. The recorder calls it (`SetExecPins`' kill function); `ExecPinner` keeps `Pin`
  and `Sweep` only.
- **`run_end`.** `exec_rules` counts `killed`, `kill_failed` and `pin_refused` (the supervisor's `pin_unavailable`
  refusals and the plane's bprm_check pin refusals); it is present in a pinned run with no command rules too.

Tests: `observe` `TestExecPinFoldHeldIsKernelPinned` (both orders), `TestExecPinFoldKillIsRefused` (both orders, and
with the exec record lost), `TestExecPinFoldKillFailed`, `TestExecPinFoldUnproven` (the held sample lost and drained at
stop or settled by the exit, a held sample of another pin, a decision that wrote another pin, a record with no pin),
`TestExecPinFoldKillOutsideAPinnedRun`; `supervisor` `TestExecPinRefusedWithoutAKernelLine`; `enforce`
`TestExecFactsDecided`; `cgroup` `TestPreparePinsAPinnedRun` (no pins without exec outcomes); and in KVM guests
`TestPlaneExecPinsOnRealKernel`, whose pinned and script cells now require the held sample.

## Implementation note (2026-10-19, P2 K5's claim side and K6's first run tests)

*K6, first part.* `enforce/cgroup` `plane_execpin_run_integration_test.go` drives `tego run` (the tegobpf build, as
root) at each plane cell a guest passes, tier cgroup in lsm and fmod_ret mode and tier bpflsm.
`TestPlaneRunExecPinned`: a run with command rules is pinned, each continued exec has one kernel `allow` line that
says `kernel_pinned`, an exec a deny entry names is the supervisor's `EACCES` and never reaches the pin, and
`run_end` counts no kill and no pin refusal. `TestPlaneRunExecPinOff`, the control: no command rules and no exec gate,
no pins, no `argv_facts`, no `exec_rules`. `TestPlaneRunExecPinRace`, P2's acceptance race: C6's `execracer` in a run
that denies `git push`, 5000 attempts per cell. In KVM on the host's 6.17, both boots, `push` ran 0 times in every
cell; every refused attempt was the supervisor's (`exec.deny[git push]`, `copied_syscall`) or the plane's kill
(`exec.pin`, `argv-changed`, SIGKILL before the script's first instruction, with both vectors on the line); every
attempt that ran was one `observed` line that says `kernel_pinned`; and the ledger's counts equal the racer's own
(cgroup@lsm: refused 2047, killed 2358, ran 595; bpflsm@lsm: 2097, 2351, 552; cgroup@fmod_ret: 2068, 2457, 475 on
the lsm-bpf boot). The kill share is far above C6's tier-1 win rate (about 400 in 3000) because the pin holds the
whole covered vector: a torn read of the flipping word (`difh`, `puff`) is a changed vector too.

The first runs found a gap: a second run on a plane another launcher had loaded (tier bpflsm after a tier cgroup run
in the same boot) ran unpinned, "the plane object has no exec pin maps", because an adopted plane's compact load keeps
its maps' inner definitions unloaded until a slot map is made. `pinsReady` now accepts a plane that can load the
definition (`TestAdoptedPlaneIsReadyForPins`).

*K5, the claim side.* A run claims that the kernel holds its execs to the decided facts (`Handle.ExecPinClaim`,
read by the runtime through `enforce.ExecPinClaimer`) only when a plane mode decides it, doctor's exec pin cell passed
in that mode (`PlaneModeResult.ExecPin`, carried as `PlaneChoice.ExecPins` and `PlaneSetup.ExecPins`), and, for a run
that asked to be pinned, its slot is pinned; a run with nothing to pin on such a plane rests on no copied exec fact
and claims too. The claim, never the slot flag alone, drives (6) and (9): `run_start.capabilities` sets
`exec.command_argv` (and `gate.exec_completion` with an escalating exec gate) for a pinned run that claims,
`BestEffortCellsRun` drops `exec.rules/argv` and `gate.exec` for it, and `exec.assurance: kernel` (schema, merge
with the stricter value winning, `redundant-rule` with nothing to hold, the print line) refuses any run that does not
claim, after Prepare and before the child starts (`ErrExecAssurance`, exit 125, the reason in the message).
Departures, and why:

- **`gate exec` becomes conditional at tiers 2 and 3.** (9) names only the new row, but ADR 0041 D7 keeps each row
  and its `best_effort` cell in agreement, and (6) takes `gate.exec` out of `best_effort` under pins; the row's cells
  now say so (`TestCompletionRowsOfADR0041` amended).
- **A run with nothing to pin claims.** (3) says `exec.assurance: kernel` "refuses the run unless the selected tier
  pins execs"; a run without command rules or an exec gate asks for no pins, so the claim reads the tier's ability
  (the cell) there, and the compile warning says the key holds nothing.
- **The doctor cell is not built.** `PlaneModeResult.ExecPin` is nil on every machine, so `ExecPins` is false
  everywhere, no run claims, and every `exec.assurance: kernel` run is refused: fail closed until the cell lands. The
  pinned plane answer (`PinPlaneAnswer`) does not carry the cell's result either, so a run adopting a pinned build
  claims nothing until the answer's layout gains it.

Tests: `doctor` `TestPlaneForExecPins`; `cgroup` `TestExecPinClaim`; `runtime` `TestExecAssuranceNeedsTheHandlesClaim`,
`TestExecAssuranceUnwindsBeforeChild`; `agent` `TestExecAssuranceKey`, `TestExecAssuranceSurvivesCanonical`,
`TestExecAssuranceMergeKeepsKernel`, `TestBestEffortDropsPinnedExecCells`; `enforce` `TestExecFactsDecided`;
`backend` `TestMatrixGolden` and `TestCompletionRowsOfADR0041`.

*K6 on the matrix (2026-10-19).* `TestPlaneExecPinsOnRealKernel` and the three run tests pass in both boots on the
host's 6.17 (a second run: race cgroup@lsm refused 2091, killed 2135, ran 774) and on AL2023's 6.1 (cgroup@lsm 2078,
2485, 437; bpflsm@lsm 2008, 2540, 452; cgroup@fmod_ret 1998, 2529, 473 and, on the default boot, 2017, 2516, 467),
`push` running 0 times in every cell. A run Prepare cannot pin is unpinned and claims nothing (the fallback K0 gives a row
that cannot hold pins), and the run tests now skip such a cell only when the reason is the one below, failing on any
other (`requirePinsOn`; `TestPlaneExecPinsOnRealKernel` likewise). On RHEL 9's 5.14 (lsm-bpf boot) the kernel
recorder had no exec outcomes (`sys_exit_execve` and `sys_exit_execveat` did not attach in the guest), so Prepare
pinned no run, "the kernel recorder has no exec outcomes, so a kill would have no line": the race there ran `push`
(the disclosed R5 residual of an unpinned run) and killed nothing. Why that row has no exec outcomes is open; until it
is answered, 5.14 is a row without pins. The compile warning per tier now says what (6) says: argv is copied unless
the plane pins the run's execs (the cell not built yet).

A draft of three more K6 cells (the large argv, prefix and non-leader cells of the list above, in one test) ran on
6.17 and found two over-refusals the ADR says must not happen: under a tail-dependent deny entry (`tool log --force`)
a vector of exactly 128 KiB, NULs counted, was refused `EACCES`, and `tool add` with 10,000 paths under a deny
entry that reads two words was refused `EACCES` as well. Both are fail-closed; the draft is kept out of the tree until
the cause (the supervisor's staged read bounds, `cmdPrefixArgs`/`ptrBatch`, or the area bound at exactly
`execpin.MaxArea`) is found and fixed.

Not yet built (at this note): doctor's cell `plane.exec_pin` ((7)'s eight known answers, its cache entry and the
pinned answer's bit; built since, next note), the rest of K6 (symlink swap, script rewrite, interpreter swap, unpinned hook, traced and guarded ptrace,
interpreted, non-leader, prefix, large argv, kill failed) and the matrix rows beyond 6.17, K7's `execbench`, K8's
documents, and the review.

## Implementation note (2026-10-19, P2 K5: doctor's exec pin cell)

`internal/doctor` planeexecpin.go builds (7)'s cell, `plane.exec_pin`. Once a mode's known answers all matched, doctor
fills their slot of the probe's own maps again, at the next gen, as Prepare fills a pinned run's (`enforce/cgroup`
`ProbeRows.FillPinned`: a key of doctor's own with its gen, an empty pin map, the pin flag and doctor's pid namespace
in the header; the known answers' preload made the slot's pin map with its row maps, off the probe's path), loads
and attaches the mode's pin program in the probe's own collection over those maps, starts one gate per try into a
scratch cgroup, arms it as the slot's run, writes each try's pin (`ProbeRows.PutPin`) and lets the gate exec. The
gate and the probe are two static x86-64 images doctor writes into memfds: the gate says ready, waits for one byte,
then `execveat(4, "", argv[1:], envp, AT_EMPTY_PATH)` and exits with the errno; the probe's first instruction writes
one byte to a pipe doctor reads. Eleven tries answer (7): (1) a pinned exec runs; (2) no pin, `EACCES`; (3) a covered
vector that differs is killed by SIGKILL with the pipe empty; (4) another image identity, `EACCES`; (5) a `#!` script
whose interpreter is the probe (`/proc/self/fd/5`) runs under its chain and is refused `EACCES` under another
interpreter identity; (6) a guarded exec doctor traces with `PTRACE_SEIZE` is refused `EACCES`, for a k = 1 dashed
vector (`git-status`) and a 100 KiB one; (7) a writer child in the run (`__doctor-plane-probe pin-writer`) writes one
byte at the running probe's `arg_start` with `process_vm_writev`: refused into the guarded long vector and into
argv[0] of a guarded k = 1 probe, passed into an unguarded probe (the control); (8) `BootOffsetZero` (Prepare's own
check, now exported) holds and answer 1 found its pin by the start time doctor read from `/proc`. The mode's
`PlaneModeResult.ExecPin` carries the result; doctor's line says "exec pins off" and why for a mode that decides but
failed the cell. The result is kept with the known answers (`plane-known-*.json` gains `exec_pin`; answers kept with
no cell answer are none), and the pinned answer gains a flags byte (`planePinVersion` 2, 12 bytes; a version 1 answer
is no answer, so a run probes rather than adopt one that cannot say), so an adopting run claims pins exactly when the
cell passed (`TestAdoptedPlaneCarriesExecPins`). The compile warnings and the capability rows no longer say the cell is
not built. Where it departs from (7), and why:

- **process_vm_writev reports the refusal as `EPERM`.** `mm/process_vm_access.c` maps `mm_access`'s `EACCES` (a
  refused access check, the plane's hook included) to `EPERM`, so answer 7 cannot read the hook's errno; the
  unguarded control is what ties the refusal to the guard (measured first in KVM: without the control the cell read
  `EPERM` and failed).
- **Answer 8 is not a second time namespace.** The cell runs in doctor's own namespaces, which are a run's launcher's:
  `BootOffsetZero` refusing is the cell failing with "8 (time namespace)", and answer 1 passing shows the plane's start
  time is the one doctor reads. K0's guest test already measured a supervisor inside a time namespace with an offset.
- **x86-64 only.** The images are hand-assembled; another architecture's cell fails "the cell's gate and probe are
  x86-64 code" (pins off, disclosed), until it has images of its own.
- **A cell that cannot run is not kept.** A stage that fails (a fork, a pipe, a timeout) is "the cell could not run"
  for that probe (pins off) and nothing is kept, so the next probe runs the cell again; an answer that differs is the
  kernel's and is kept with its detail for the boot.

Tests: `doctor` `TestPlanePinImagesRun` (the gate, probe, script, traced and refused paths on the host, no plane),
`TestPlaneKnownCacheKeepsOnlyAFullMatch` (the cell kept, passed or failed; none without it), `TestPlanePinCodec`
(the flag, a version 1 and a reserved byte), `TestAdoptedPlaneCarriesExecPins`, `TestPlaneSummaryDisclosesExecPinsOff`;
in KVM `TestIntegrationPlaneExecPinCell` (root-must-pass: every mode the boot passes passes the cell, nothing left
behind). In KVM the cell passes in every mode each boot passes (lsm and fmod_ret on the `lsm=...,bpf` boot, fmod_ret
on the default boot) on every row it ran on, the cell itself taking, a mode, cold: RHEL 9's 5.14 7 to 27 ms, AL2023's
6.1 8 to 27 ms, Ubuntu 24.04's 6.8 8 to 25 ms, Debian 13's 6.12 10 to 13 ms and the host's 6.17 11 to 20 ms. An earlier build filled a fresh slot of its own and took 199 to 265 ms on 6.1
(each map-in-map insert waits for an RCU grace period below 6.7), over K7's +60 ms limit; the cell now reuses the
known answers' slot, whose maps, its pin map included, the preload makes beside the modes' loads, so the pin map's
insert moved to the preload (one more insert per mode there; what that adds to a whole cold probe on 6.1 is not
measured yet). K7 measures the cell's cold cost against its +30 ms target in `execbench`'s harness.

## Implementation note (2026-10-19, P2 K6: eight more cells, and the decision budget)

*A fix the large argv cell found.* Under a tail-dependent rule a vector of exactly 128 KiB whose elements were each
longer than 16 KiB was refused `args-unreadable`: the supervisor's batched decision read (`argvBatched`) bounded each
element by the recorder's per-string limit (`argMax`, 4 x PATH_MAX), a third bound R7 does not have. The decision's
budget is now the vector's bytes, each element's NUL counted, whatever its elements' sizes, so one element may take
all of it (`TestExecCommandBudgetIsTheWholeVector`, which failed before the change). The 10,000-path cell the first
draft refused was not a bug: under a deny entry on a tool no row knows (`tool add`), the generic fallback reads an
option anywhere, so the verdict needs the whole vector, and past 8192 elements R7 refuses it; the cell now uses
(3)'s own example, `allow: [git add]` (written `./bin/git add`).

*The cells.* `enforce/cgroup` `plane_execpin_cells_integration_test.go` and `plane_execpin_peer_integration_test.go`,
each at every plane cell the boot passes (cgroup at lsm and fmod_ret, bpflsm at lsm):

- `TestPlaneRunExecPinLargeArgv`: 128 KiB runs, pinned whole; one byte more is the supervisor's `args-unreadable`.
- `TestPlaneRunExecPinPrefix`: `git add` with 10,000 paths of 20 bytes (about 210 KB) runs pinned on its prefix;
  `execracer -tail` flips the 43rd element 500 times and every attempt runs. A departure: the pin covers the `k`
  elements the decision *read* (this ADR's (3): "P2's pin covers exactly those"), and the prefix stage reads 32
  elements, so a rewrite inside the first 32 of a vector that short is a changed vector and is killed; the cell
  rewrites past them, which is what "a tail rewrite after the supervisor's prefix read" means.
- `TestPlaneRunExecPinNonLeader`: an exec from a thread that is not its process's leader runs pinned.
- `TestPlaneRunExecPinScriptRewrite`: `execracer -flip` rewrites the option on a script's `#!` line in place while
  the script is exec'd 1000 times: 437 to 488 of the attempts in each cell were killed (`argv-changed`, SIGKILL), every
  kill and every pinned run has its line, and the attempts the racer's own write made fail `ETXTBSY` are lines with
  that return.
- `TestPlaneRunExecPinTraced`: a guarded exec under `PTRACE_TRACEME` is refused `exec-traced` (EACCES), so is a
  `k = 1` dashed exec (`git-status`); the unguarded control runs.
- `TestPlaneRunExecPinGuardedPtrace`: after a guarded exec (and a `k = 1` one) a peer's `process_vm_writev` into its
  argument area answers EPERM and its `PTRACE_ATTACH` EACCES (the hook's errno; `process_vm_writev` maps it, as doctor's
  cell found), each a `process-scope` refusal line; the unguarded control takes both.
- `TestPlaneRunExecPinInterpreted`: `#!/usr/bin/env python3` (env, then python3: two execs, two pins) and a two-stage
  script (two binfmt_script stages in one exec) run pinned. A departure: (K6) names `node`, which the guest does not
  have; the shape (env resolving an interpreter) is the same.
- `TestPlaneRunExecPinUnpinned`: an exec whose pin the supervisor did not write (a test hook,
  `TEGO_TEST_EXEC_PIN_SKIP`, in the `tegotesthooks` build) is refused `pin-missing`; the run's other exec runs.

The peer cells' images are `execracer` run as a sleeper (`execracer <seconds>` under any argv[0]): Ubuntu 25.10's
`/bin/sleep` is a multi-call binary that dispatches on argv[0] and exits 1 under another name.

In KVM on the host's 6.17 all eight pass in both boots.

*Found, open.* Two more cells were run and are not in the tree: K6's symlink swap (a symlink swapped between two
images) and interpreter swap (an interpreter swapped behind a `#!` line), 1000 attempts a cell. The plane refused every swapped exec `pin-mismatch` (run_end's `pin_refused` equals the
attempts that answered EACCES) and none ran on the other image, but about one refusal line in ten came out
`observed`, `unmatched`, `syscall_ret: -13`, without the plane's attribution, and a few lines of execs that ran said
`unproven`. The ledger then under-says what the plane did, never that a refused exec ran; until the handover join is
fixed the two cells are kept out of the tree. Not built yet: the kill-failed cell (a send failure has to be made),
and the cells on the matrix rows beyond 6.17.

## Implementation note (2026-10-19, P2 K6: the swap cells)

`TestPlaneRunExecPinSymlinkSwap` and `TestPlaneRunExecPinInterpreterSwap` are in the tree: `execracer -swap` makes
`./out/l` a symlink to one copy of an image (or of `/bin/sh`, named on a script's `#!` line) and `./out/l.2` one to
another, and exchanges the two names (one `renameat2` `RENAME_EXCHANGE`) every 20 µs while an exec is in flight. In
KVM on 6.17, both boots, every cell: of 1000 attempts 473 to 523 were refused `pin-mismatch` (EACCES) and the rest ran
pinned; each has its one line (refused, `exec.pin`; or `kernel_pinned`), and run_end's `pin_refused` equals the
refusals.

*What the earlier gap was.* The first draft of the racer renamed a fresh symlink over the link as fast as it could,
whether or not an exec was in flight: hundreds of thousands of fs actions a run, each a ledger line under
`record: full`. The record overran: the run's gap lines said `ringbuf-full` (up to 6680), `channel-full` and
`exec-fragment-overflow`. A refusal whose plane sample was lost in the ring is an exec result with no plane fragment,
so its line can only say `observed`, `syscall_ret: -13`; a pinned exec whose held sample was lost says `unproven`;
lines the events channel dropped are missing. Each of those is what (8)'s fold is specified to say under loss, and
each loss was disclosed by its gap, so the fold and the handover join are unchanged. The racer now swaps only while
an exec is in flight, one rename a swap, and the race cells (`checkPinRace`) fail on any loss gap first
(`ringbuf-full`, `channel-full`, `exec-fragment-overflow`), so a cell's exact counts are never compared over a lossy
record, and log the exec lines by shape when a count differs.

## Implementation note (2026-10-19, P2 K6: the kill-failed cell)

`TestPlaneRunExecPinKillFailed` runs the script rewrite race with a binary whose test hook,
`TEGO_TEST_EXEC_PIN_KILL_ERR` (`observe/exec_pin_testhook.go`, `tegotesthooks` builds only, never under AT_SECURE),
says every kill sample's `bpf_send_signal` failed with that errno. Each kill's line is then refused with
`kill_failed: -1` and `detected_bypass: true`, the run has one `exec-pin-kill-failed` gap a kill, run_end's
`exec_rules.kill_failed` equals the kills, and the run's own log has one pidfd backstop line a kill (the recorder now
logs a sent backstop kill as well as a failed one: either is an exec the kernel did not stop). In KVM on 6.17, both
boots, every plane cell: 461 to 554 kills of 1000 attempts, each so.

*A departure, decided.* (K6) says "a test hook makes the send fail". No send failure can be made on a real kernel
from user space: `bpf_send_signal` from sched_process_exec fails only for a kernel thread, an exiting task, global
init or a busy per-CPU irq work, and K0 found no failure in 10,000 kills a row. The hook therefore injects the error
where the sample is read, so the kernel did kill and the backstop finds a dying process; the backstop's own kill of
a live process is `TestKillPinnedExecKillsTheSampledProcess` (`internal/runtime`): SIGKILL through the pidfd when
/proc's start time is the sample's, and no signal to a pid whose start time is another process's. Rejected: a
load-time `.rodata` knob in the plane object that skips the send. It would put a branch that leaves a changed exec
running into the production object (dead only while the loader leaves the knob at 0), add a loader mechanism no
other program uses, and need every row's load test again, to test a path whose BPF half is one assignment
(`kill_err = bpf_send_signal(...)`).

## Implementation note (2026-10-19, P2 K7: the exec check, built)

`make vm-perf` has an `exec` check (`test/perf/cmd/perfsuite/exec.go`, between socket and conc). `execbench`
(`test/perf/cmd/execbench`) forks and execs a minimal static image (`perf.TrueImage`: one PT_LOAD segment and
exit(0), no runtime start-up) from one pinned CPU and prints the loop's p50 and p99. Each of 5 rounds runs every mode,
rotated, under four contracts alternated: 512 bytes and 128 KiB of argv, each without command rules and with
`deny: ["./true push"]` (a tool no row knows, so the generic fallback reads and pins the whole vector), 10,000 execs a
sample (1,000 at 128 KiB). Each figure is its best round (Min-of-N), and the budgets are (P2)'s table:
`exec.pinned.<mode>.p50_excess_us` (target 15, limit 30) and `p99_excess_us` (50, 100), `exec.argv128k.<mode>.excess_ms`
(1.5, 3), `exec.norules.<mode>.pin_check_ns` (100, 200) and `doctor.exec_pin.<cgroup-lsm|cgroup-fmod_ret>.cold_ms` (30,
60). Two departures, decided. P1's supervisor cost is landlock's same difference (printed as `p1.landlock`, no budget:
P1's acceptance holds its own), and a plane mode's excess less it is printed as P2's kernel cost; the budget is on the
whole excess, which is what (P2)'s table names. "A run without rules, per exec" is measured where P2 puts its cost, the
sched_process_exec pin programs, from the kernel's `bpf_stats` (their run time over their run count while a run
without rules execs, both programs summed): a difference of two exec loops cannot resolve 100 ns. Doctor's cell is its
`probe.plane.<mode>.exec_pin` phase in a doctor run, which keeps no cell answer, so each is cold. The figures are not
yet measured: the next guest run records them here and in enforce-plane §10.

## Implementation note (2026-10-19, P2 K6 on the matrix rows)

`TestPlaneRunExecPin*` (all fourteen: pinned, off, the race to `push`, large argv, prefix, non-leader, script rewrite,
symlink swap, interpreter swap, traced, guarded ptrace, interpreted, unpinned, kill-failed) and
`TestPlaneExecPinsOnRealKernel`, in KVM, both boots (`lsm=...,bpf`: cgroup at lsm and fmod_ret, bpflsm at lsm; the
default boot: cgroup at fmod_ret): every one passes on 6.1 (AL2023), 6.8 (Ubuntu 24.04) and 6.12 (Debian 13), as on
6.17; the race to `push` ran it in none of 5000 attempts a cell (on 6.1, for instance, 1950 to 2059 refused and 2444
to 2484 killed a cell). On RHEL 9's 5.14 the recorder's `sys_exit_execve` and `sys_exit_execveat` programs do not
attach, so Prepare pins no run there (a kill would have no line), the run says `exec pins off`, and the pinned cells
skip for that reason only (the K0 rule: a failing row's fallback is the pin flag off, disclosed); why those two
programs do not attach on 5.14 is open. Fedora's 7.0 row was not read.

## Implementation note (2026-10-19: the fold pairs one exec's halves)

K4's fold paired a waiting half with the next half of the other kind for the same process, whatever their seqs. Under a
ring loss of one half of one exec and the other half of the next, it paired two execs: exec 1's record lost and its held
sample (seq 7) waiting, exec 2's record (`pin_seq` 8) took that sample and said `argv_facts: unproven` with the
mechanisms' verdict, and exec 2's kill then became a second, refused line, so a killed exec also had a line that did not
say refused, which (8) forbids under loss. The fold now pairs a record only with the sample of the same pin: the
sample's seq is the record's `pin_seq`, or the sample is a kill that names no pin (no pin was armed for that exec, so it
carries no seq; a kill the kernel sent is its process's last exec). A waiting half of another seq is an earlier exec's
whose partner the ring lost: it is settled alone (a record says `unproven`, a kill is its own refused line, a held
sample says nothing), and the new half waits for its own. Both pairing sites (`holdExec`, `handleExecPin`) use one
rule (`samePin`); no other fold of `observe` pairs halves by process alone (the exec fragments join by thread and
time). Tests: `TestExecPinFoldKillIsRefused`'s held(7), exec(8), kill(8) gives one refused line, and
`TestExecPinFoldPairsOneExec` gives an earlier exec's record and a later exec's kill two lines, each its own, and a kill
of no pin one line in either order; the first two failed before the change.

## Implementation note (2026-10-19: an interpreted unknown-form exec is held to its length)

In a run with an exec gate and no command rules every exec is pinned in the unknown form with `interp_ok`, and (3)
held an interpreted one by `mac_tail` over the last `len_tail` bytes after a NUL. That check read neither the vector's
length nor what stood in front of the tail, so a thread that put arguments in front of the decided argv[1:] after the
CONTINUE passed it: decided `[./deploy.sh, staging]`, mapped `[/bin/sh, ./deploy.sh, --prod, --force, staging]`, the
last bytes still `staging\0`; a decided `[./x.sh]`, whose tail is empty, passed any vector. The exec said
`kernel_pinned` and the gate's exec cell left `best_effort` on arguments the gate never scored. Three changes:

- **The vector's length.** bprm_check's first stage keeps `bprm->argc` in the task's armed state (`argc0`; the state is
  248 bytes), and `tego_pin_area` refuses an interpreted unknown-form area whose `argc0` is not the pin's `argc`,
  `argv-changed`. The decided tail holds `argc` NULs, so the last `len_tail` bytes after a NUL are exactly the area's
  last `argc` strings: no suffix of more strings, and none of fewer that a NUL precedes, can MAC to it.
- **The filename.** `mac_tail` covers the filename (domain 3, unchanged), then argv[1:]. binfmt_script and binfmt_misc
  put the filename, from `bprm->filename`, which the first stage held, directly in front of argv[1:], so the filename
  slot holds no argument. A binfmt_misc entry with the P flag puts argv[0] there instead, and the tail then holds
  argv[0] to the filename.
- **binfmt_misc's P flag.** So the first later stage refuses `pin-mismatch` when the first handler set
  `BINPRM_FLAGS_PRESERVE_ARGV0` (bit 3 of `bprm->interp_flags`, since 5.12, so on every row) and the pin lacks the new
  flag `argv0_filename` (0x08: the decided argv[0] is the filename). A P handler later in the chain keeps an earlier
  stage's interpreter name, not argv[0], so only the first later stage reads the flag.

Rejected: that check alone (the bytes in front of the tail held to the filename). A racer that repeats the
filename as an argument (`[./deploy.sh, --prod, ./deploy.sh, staging]`) passes it: the length is what closes the
insertion, and the filename places argv[0]. A refusal on `bprm->argc` at the first stage's bprm_check (a clean errno
rather than a kill) was rejected because the fold reads bprm_check's reasons as identity reasons and `argv-changed`
as a kill's (`planeExecReason`), and the direct form already holds `argc` at `sched_process_exec`, so argv is checked
in one place. Holding argv[0] under P with a second MAC (the decided vector after the filename) was rejected: a second
MAC site in `tego_pin_area` doubles its verified loops for a root-registered handler that R9 leaves unmodeled, and
the refusal fails closed (R6(j)).

The class: the direct form holds the covered prefix from `arg_start` and, when `k = argc`, the area's length and
`bprm->argc`; the script form holds the area's whole length and MAC. Only the unknown form checked a suffix, and only
its interpreted branch read no length. Tests: internal/execpin `TestUnknownTailHoldsOnlyTheDecidedVector` models
`tego_pin_later`'s first stage and `tego_pin_area`'s branch byte for byte over every vector of up to four elements
from a four-word alphabet, under five binfmt shapes (`#!`, `#!` with an argument, two `#!` stages, binfmt_misc, and
binfmt_misc with P) and five decided vectors: it holds exactly when the vector the interpreter sees is the decided one,
but for the P case it refuses. It and `TestBuildUnknownCoversTheTail` failed before the change, and so did bpf/tests
`TestExecPinUnknownTailHoldsTheVector`. K6's `TestPlaneRunExecPinGateInsert` runs the race: `execracer -insert` execs
`[./out/deploy.sh, staging]` 2000 times a cell while a thread puts `--prod` in front of `staging` and takes it out
again, under a gate that refuses `deploy.sh --prod*`. On the code before the fix, in the three cells of 6.17's lsm-bpf
boot, a vector holding `--prod` ran 71, 74 and 80 times, each such line saying `kernel_pinned`; with the change it never
ran, and 671 to 695 attempts a cell were killed `argv-changed` (the rest: the gate's refusals, about 520, about 500
pinned runs, and execs the racer made fail `EFAULT` by clearing a slot the kernel had counted).
`TestPlaneRunExecPinGateMiscP` registers two binfmt_misc entries run by `/bin/sh`: under the P entry an exec whose
argv[0] is its filename runs pinned and one whose argv[0] is another word is refused `pin-mismatch`, and under the entry
without P that second shape runs pinned. It needs binfmt_misc, which every matrix row's guest lacks (no module loaded),
so it skips there (root-skips.txt) and runs in a guest whose `VM_MODULES` names `binfmt_misc` and on a hosted runner.

## Implementation note (2026-10-19: the argv-guarded mark covers the program's threads)

`tego_pin_guarded` read the mark from the task storage of the ptrace target it was given. Only the task that exec'd
holds the mark (`sched_process_exec` writes it), and a thread the new program starts has no storage, so a peer of the
run could `PTRACE_ATTACH` that thread's tid, or `process_vm_writev` or open `/proc/<tid>/mem` against it, and write the
shared mm, argv area included, before a program that reads its argv after starting a thread (a Go program: its
runtime starts threads before `main`) read it. The guard now answers for the target or, when the target is not its
group's leader, for `target->group_leader`: the exec'ing task, which `de_thread` made the leader of a non-leader's exec
and whose mark every exec rewrites. A forked child is a new group, its own leader, unguarded as R6(e) states.
Rejected: marking each new thread at its creation (a new hook on every clone of every run, and a window before it ran)
and reading the mm's owner (`mm->owner` exists only with `CONFIG_MEMCG` and is reassigned when the owner exits). Tests:
bpf/tests `TestExecPinGuardReadsTheLeader` (failed before), and K6's `TestPlaneRunExecPinGuardedPtrace` gains a
`guardthread` case, `process_vm_writev` and `PTRACE_ATTACH` against a thread of a guarded Go sleeper that is not its
leader: on the code before the change both succeeded in the three cells of 6.17's lsm-bpf boot (the case exited 0);
with it both are refused `process-scope` (EPERM, EACCES).

## Implementation note (2026-10-19: the K6 run tests must pass as root)

The K6 run tests (`TestPlaneRunExecPin*`) were built with `integration` alone, so the plain build compiled them and
they skipped there (`untagged:` entries in root-skips.txt), and none was in `test/vm/root-must-pass.txt`: a CI row on
which all of them skipped, for the recorder's reason of 5.14 say, passed. They now build with `integration &&
tegobpf`, as `TestPlaneExecPinsOnRealKernel` does. The plain build no longer has them, their fifteen `untagged:`
entries and their entries in test/integration-skips.txt are gone, and fifteen are root-must-pass. Each of those
passed, in its fmod_ret cell, in a KVM guest placed as a hosted runner is (`VM_CGROUP=service`, `TEGO_VM_LSM=kernel`,
`TEGO_VM_LOCKDOWN=none`, 6.17), with `TestPlaneExecPinsOnRealKernel`.
`TestPlaneRunExecPinGateMiscP` is not one: it needs binfmt_misc, which a guest has only when `VM_MODULES` names it,
and no run has yet shown it on a hosted runner. Its root-skips entry says why it may skip. On RHEL 9's 5.14, where
pins are off (the disclosed fallback above), each of the fifteen passes with its cells skipped, and the row's strict
skip gate reports those cell skips, which no root-skips entry allows, as it did before; a row whose cells all skipped
was never silent there, and the must-pass list adds that a test the run did not reach fails it too.

## Implementation note (2026-10-20, P2 K6, on the matrix rows)

With the first fixes, in KVM: the sixteen K6 run tests and
`TestPlaneExecPinsOnRealKernel` pass in both boots on 6.17 with `VM_MODULES` naming binfmt_misc
(`TestPlaneRunExecPinGateMiscP` included), and on 6.1 (AL2023), 6.8 (Ubuntu 24.04) and 6.12 (Debian 13), 332 passes and
no failure a row, where `TestPlaneRunExecPinGateMiscP` skips for its binfmt_misc reason. The gate-only insertion cell
killed 635 to 748 attempts a cell `argv-changed` on every pinned row and never ran `--prod`. In the hosted-runner
placement on 6.17 the fifteen root-must-pass tests and `TestPlaneExecPinsOnRealKernel` pass (fmod_ret cells). On RHEL
9's 5.14 the run tests pass with their cells skipped for the disclosed fallback. `TestPlaneLoadsAndAttaches` (both
modes, the 20,000 budget) passes on every row booted: the pin program verifies in 8,840 instructions on 6.8, 6.12 and
6.17 (8,733 before this change) and 5,539 on 6.1; on RHEL 9's 5.14 it verifies in 8,840 as well, so the plane loads there.
The Fedora 7.0 and 7.2 rows were not booted (their `socket_listen` verifier budget is another package's).

## Implementation note (2026-10-20: a kill names its exec's seq)

The first fold let a kill that names no pin (seq 0) pair with whatever exec record of the process waited. The
pin program sent seq 0 on two kill paths, a slot cleared between bprm_check and `sched_process_exec`
(`pin-unverifiable`) and an exec with no armed pin (`pin-missing`), while the recorder's exec record of that same exec
read the task's `cur_seq`, which bprm_check's first stage had set. So with exec 7's record waiting (its held sample
lost) and exec 8's kill read before exec 8's record (the two `sched_process_exec` programs run in either order), exec 7
took the kill: its line said `refused`, rule `exec.pin`, with exec 8's mapped vector, though exec 7 ran, and exec 8's
record then said `unproven` with the mechanisms' verdict. "A kill the kernel sent is its process's last exec" holds of
the killed exec, not of the record that waits.

Two changes, so that the seq alone pairs an exec's halves:

- **The kill names the record's seq.** `tego_exec_pin_check` reads the task's armed state before its first branch
  and names its `cur_seq` on every sample path: the value `tego_exec_pin_seq` gives the exec record, read from the same
  task storage under the same run and gen. `cur_seq` is written only by bprm_check's first stage (reset, then the
  armed pin's seq), and no bprm_check of the task runs between the two programs of one `sched_process_exec`, so both
  halves name one value in either order: the armed pin's seq, the seq that stage left, or 0 when the task holds no
  state of the run. The held sample names `st->pin.seq`, the pin the check read, so the fold's held proof still
  compares it with the record's `cur_seq` and the decision's seq. The cleared-slot path now also disarms and marks
  the dying task as the other kill paths do.
- **The fold pairs by seq alone.** `samePin` is the seq's equality, 0 included: a half of another seq is an earlier
  exec's, settled alone, and the new half waits for its own.

Rejected: a one-way wildcard (a waiting kill of seq 0 takes the next record of its process). It rests on a killed
process execing no more, which a failed send (`kill_err`, the pidfd backstop's case) breaks, and it would leave a kill
of seq 0 ambiguous wherever a record waits. Clearing `cur_seq` in the pin check once read: the recorder's program may
run after it and would read 0 for an exec the plane held, so a held exec's line would never say `kernel_pinned`. Sending
`cur_seq` only on the cleared-slot and unarmed paths was rejected too: on the armed paths `cur_seq` and
the pin's seq are set together, so one read for every kill is the same value with one rule.

The class: both pairing sites (`holdExec`, `handleExecPin`) use `samePin`; the held sample already named its pin;
bprm_check's refusal samples (`tego_exec_sample`) are never folded with an exec record, since no exec record follows
a refusal; no other fold of `observe` pairs by a wildcard (the exec fragments and the naming join by thread and time).
Tests: `observe` `TestExecPinFoldPairsOneExec` feeds exec 7's record, a kill and then the killed exec's record, the
kill and record naming 0 or 8, and wants two lines, exec 7's not refused and unproven, the killed exec's refused with
its plane_reason and the kernel's vector; with seq 0 it failed before the change (exec 7's line refused, rule
`exec.pin`, with the kill's vector, and the killed exec's line the mechanisms' verdict, unproven). Its
cases of a kill of no armed pin now name the task's seq, as the kernel does, and pair in either order. `bpf/tests`
`TestExecPinKillNamesTheRecordsSeq` holds the check to reading `cur_seq` before the cleared-slot branch, the kill to
naming it, the held sample to naming the pin it checked, the record to reading the same field, and `cur_seq` to one
writer, bprm_check's first stage; it failed before the change.
In KVM on 6.17 (`VM_MODULES` naming binfmt_misc), the sixteen K6 run tests and `TestPlaneExecPinsOnRealKernel` pass
in both boots (168 subtests on the lsm-bpf boot, 136 on the default one), the race to `push` running it in none of
5000 attempts a cell (2414 to 2585 killed a cell). On 6.1 (AL2023), 6.8 (Ubuntu 24.04) and 6.12 (Debian 13) they
pass in both boots, 332 passes and no failure a row, `TestPlaneRunExecPinGateMiscP` skipping for its binfmt_misc
reason; on RHEL 9's 5.14 they pass with their cells skipped for the disclosed fallback (pins off). The pin program
verifies in 8,885 instructions on 5.14, 6.8, 6.12 and 6.17 and 5,585 on 6.1 (8,840 and 5,539 before), under the
20,000 budget (`TestPlaneLoadsAndAttaches`, both modes).

## Implementation note (2026-10-25, ADR 0064: a runtime exact pattern)

`pkg/policy/execmatch` gains `ExactPattern`, a command rule the runtime makes on its own authority and no contract can
write: the harness hook's grant ([ADR 0064](0064-harness-hook-exec-grant.md)). It is an allow pattern keyed like any
other (by name and identity, (2)) that matches an invocation only when the whole vector equals its own, argv[0]
included, read to its end, with no glob and no trailing token, and only on the exec's own image (`Pattern.Runtime`,
`Invocation.Argv0`). A tool only runtime patterns constrain is refused unlisted under the grant's rule
(`exec.harness-hook[<binary>]`, `Result.Grant`) rather than `exec.args[<tool>]`. The generic fallback's prefix
reading, the rows and every contract pattern are unchanged (`TestExactPattern*`).

*Amended 2026-10-27 (implementation note):* the
`#!` case's interpreter walk. Re-measured before this change: the component walk of `/bin/sh`
(`/bin -> usr/bin`, `sh -> dash`) with its head took 21.6 µs, the two-`openat2` lookup and the same head read 12.9 µs.
Now at tier landlock the image walk of an absolute pathname that follows its final symlink and that the walk does
not name is first `lookupInOne` (an RCU-only `RESOLVE_CACHED|RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS` lookup, then
`RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV`, then `fstatfs` to leave a procfs root to the walk), and a run
with command rules holds the task's root for one exec's walks (`taskRoot`). `BenchmarkExecImageInterpreter` after this
change, load average 2.9, fastest of 10: head 14.1 µs, held 12.9 µs, components 24.3 µs. *Residual:* C8's `#!` case
still answers its interpreter's walk from the fake kernel (it has no walk of the real tree
yet), so the budget test does not yet see this cut; the root tiers keep the component walk (their search check is
the task's, which one lookup with root's credentials cannot make). *Not in this change:* further cuts (the held
`/proc/self/fd` directory, the staged argv read, the sorted-vector check, the `stage` walk flag, the reused
`fstat`/`fstatfs`) were not measured on this tree.

*Amended 2026-11-01 (implementation note): a vector of
exactly the bound is decided.* The staged read read the pointer array in batches of 1024 words, each one word longer
than the pointers it still needed so the NULL after the bound was read with them, but the batch cap took that word off
the last batch whenever the bound fell on a batch end, which 8192 does. A guarded exec of exactly 8192 arguments within
128 KiB was refused `args-unreadable`, though R7 refuses only past the bound and the record's own read
(`pointersLimited`) reads that NULL; C8's 8192-argument case measured that refusal, its line's JSON encoding included,
about a quarter of the case. The read now reads the word after a last batch that ended on the bound
(`TestExecCommandReadsAVectorOfExactlyTheBound`: 8191 and 8192 operands decided, 8193 refused), and
`TestExecCommandCostBudget` checks each case's answer before it measures it. The 8192-argument figures above were taken
on that refusal; one later unit run read +451 µs of the thread's own time, inside the case's 2 ms Limit.
