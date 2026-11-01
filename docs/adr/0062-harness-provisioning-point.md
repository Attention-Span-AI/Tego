# ADR 0062: The harness provisioning point

Status: **accepted 2026-10-24** (a technical decision). Implemented 2026-10-24: the
`harness:` key, `pkg/spec/harness`, the launcher's provisioning point with read-only files and the hook-state grant,
`run_start.harness` at record minor 14, the registry in `internal/adapters` and compile's harness
lines. The hook's exec grant for allow-list contracts is ADR 0064's; the first provisioner (Claude Code) is ADR 0063's. Adds agent-contract R27 and amends R10a; adds record minor 14.

## Context

The reason channel (REASON-CHANNEL.md) tells an agent why tego refused something. A harness such as Claude Code reads
that only if it is told to: a per-run settings file naming a hook, a `--settings` argument, an environment variable,
and a directory where the hook keeps its cursor between calls. Each is a file or an argument the launcher must make
before the agent exists, and each carries a guarantee only the launcher can hold: the settings file must be one the
agent cannot rewrite (or it could unhook itself, or hook in a program of its choosing), and the hook's state directory
must be the one place in the run's runtime directory the agent can write. `internal/runtime/codexhome.go` already does
this for one harness, by hand: a `CODEX_HOME` made by directory descriptor, `O_EXCL|O_NOFOLLOW`, its identity kept for
the grant. Every later harness (Claude Code, Codex's hooks, the Agent SDK) would add another such file to the engine.

## Decision

**D1. One point, in the launcher.** `prepare` calls `provisionHarness` once, after `createRuntimeDir` and before
`Prepare`, since the hook-state grant is one every backend builds with. It is the only place a harness's files are made.

**D2. The key.** The contract takes `harness: auto | claude-code | codex | generic | none` (merge class
`contract-wins`, ADR 0065). `auto` (the key absent) is the harness the resolved command's basename names
(`harness.Detect`: `claude` is Claude Code, `codex` is Codex, anything else generic) of the command the run executes:
compile resolves it from the command `tego run` was given after the contract, else the contract's own, and the
launcher resolves the contract's declared value again from the command it runs, never taking the compiled name for a
command that replaced the contract's. `none` provisions nothing, records nothing, and is
the run as it was before this ADR: the same argv, environment, rule table and filter.

**D3. Layers.** The interface is defined where it is used: `internal/runtime.Provisioner`, one method,
`Provision(harness.Run) (harness.Provision, error)`. Its parameter and result are Layer 0 (`pkg/spec/harness`, standard
library only): `Run` is what the launcher says of the run (its id, tier, runtime directory, reason file, hook-state
path, the run's own `CODEX_HOME`, the tego binary, the resolved argv, the agent's environment, whether images are
restricted, and a `ReadUserFile` the launcher controls); `Provision` is what the harness needs (the whole new argv,
`TEGO_` environment additions, files as a directory, one path element and bytes, the hook's exact argv, a summary).
Implementations are Layer 3 (`internal/adapters/*`: `pkg/spec/**`, `golang.org/x/sys/unix` and the standard library);
`internal/adapters.For(name)` is the registry, one map entry per provisioner (it holds the Claude Code provisioner; it was empty when this ADR was written); `internal/cli`
connects it to `Deps.Harness` and to compile.

**D4. The engine makes every file.** A provisioner returns bytes. The launcher makes `hook-state/` (`0700`, by the
runtime directory's descriptor, beside `last-refusal.json`, never above it or a harness file) and then each file with
`O_CREAT|O_EXCL|O_NOFOLLOW` relative to its directory's descriptor: `0444` in the runtime directory, `0600` in the run's
own `CODEX_HOME` (only the one `writeCodexHome` made, checked by device and inode). The agent's Landlock domain grants
no write in the runtime directory except `CODEX_HOME` and `hook-state/`, so the files are read-only to it whatever their
mode. `hook-state/` is granted as the runtime rule `fs.harness-state[<path>]` with its device and inode, as
`fs.codex_home` is, refused when an exec directory entry covers it (`ErrHookStateExecutable`), and in a deny-list run
with command rules the supervisor refuses an exec or a loader's program there (`harness-state-exec`), as it refuses one
in the `CODEX_HOME`.

**D5. What refuses the run.** Before `run_start`, exit 125 (`ErrHarnessProvision`): a provisioner's error; a file name
holding `/` or a NUL, or `.`/`..`; a name given twice; a runtime-directory name the engine reserves, whether it exists
yet or not (`last-refusal.json`, which the ledger first writes at the run's first refusal, and its temporary names
`.last-refusal.json.*`, `.lock`, `hook-state`, `codex`); any other name that already exists
(`O_EXCL`); a `CodexHome` file for a run with none; an environment name without the `TEGO_` prefix, one the launcher
reserves whether the environment holds it or not (the identity set, `TEGO_DNS_BROKER_DIR`, `TEGO_DNS_BROKER_PID`,
`TEGO_HELPER_UNPLACED`, `TEGO_CONFIG` and the `TEGO_TEST*` hooks), or one the contract's `env.set` gives (never
silently replaced; an inherited one, such as a parent run's provision, is replaced, as the identity set replaces
`TEGO_RUN_ID`); an argv whose argv[0] is not the resolved command. A provision is all or nothing. One function,
`CheckProvision`, decides every one of these that the table and the provision decide alone, for the run and for
`tego compile`, which prints `harness <name> provisions nothing: <why> (a run is refused)`; only a name that already
exists is the run's alone. Compile asks the provisioner as for a run with a `CODEX_HOME` (a run has one only when it
routes codex through the forwarder, which compile cannot know) and says so on each such file's line.

**D6. What drops the provision (the run carries on).** The provision is made only when the run's compiled exec rules
admit `Provision.Hook.Argv` exactly, judged by the decision `compile --test`'s exec row uses (the tier's floor on an
exec of the hook's argv[0] with that argv, the plane's rows at `bpflsm`, command rules included, then the gate,
`agent.EvaluateGateRow`, whose ask the supervisor's `gateExec` refuses); otherwise it is dropped whole (no file, no
hook-state, no argv or environment change), `run_start.harness` says `provisioned: false` with `why: hook-refused`
(the rules or the gate refuse or ask), and the run and compile warn
`harness-hook-refused` naming the rule. A hook the rules refuse would add a refused exec to every tool call. An
allow-list contract always drops it (`why: hook-not-granted`) until the hook's exec grant grants the hook's exact argv
(done 2026-10-25, [ADR 0064](0064-harness-hook-exec-grant.md): the launcher grants it, and drops the provision only
when no exact grant can be made).

**D7. What the record says.** `run_start.harness` (record minor 14): `{name, provisioned, why, files, reason_file,
state_dir}`, absent for `harness: none` and for an adopted run. With no usable runtime directory (no absolute
`XDG_RUNTIME_DIR`, or a root launcher) nothing is provisioned (`why: reason-unavailable`) and a `gap what=record
why=reason-unavailable` follows `run_start`; a harness with no provisioner is `why: no-provisioner`.

**D8. Reading the user's files.** `Run.ReadUserFile` is the only way a provisioner reads a file of the user's (a
settings file to merge): refused at euid 0, for a relative path, under any `deny_read` entry of the run (the copy would
sit where the agent reads it, the original not, as `writeCodexHome` refuses), for anything but a regular file (a final
link not followed, a FIFO not waited on) and above 2 MiB.

## Consequences

- A new harness is a Layer 3 package and one registry entry; the engine is not edited for it.
- `run_start.command` is the argv the agent was given (the provision's, argv[0] resolved, when one was made).
- `childSpec`'s environment is `agentEnv`, the environment the provisioner is told; the two cannot differ.
- MCP provisioning reuses this point for provisioning MCP configuration; it adds files, not a second path.
- Codex routing is unchanged: `writeCodexHome` still writes the `CODEX_HOME` and its tests pass unchanged; a Codex
  provisioner may add files there through D4.

## Rejected options

- **Per-harness code in `internal/runtime`, as `codexhome.go` is.** Every harness would grow the engine, and Layer 1
  would import knowledge of each harness's settings format; the engine's part is the guarantees, not the formats.
- **Adapters writing their own files.** An adapter cannot hold the runtime directory's descriptors, so it would write
  by path: a link swapped into the directory could redirect the write, and nothing would keep the file read-only or
  hook-state the only writable place. Returning bytes keeps every create in the one process that can make them safe.
- **A second provisioning path inside MCP provisioning.** Two points would each need the D4 guarantees and the D6 check, and
  could disagree about what the agent sees; MCP provisioning reuses this one.
- **Keeping `internal/runtime/reason` as the adapters' import.** An adapter would then import the engine (depguard
  `adapters-never-import-engine`); the contract between them is Layer 0 (`pkg/spec/harness`, `pkg/spec/reason`).
- **Making hook-state for every run.** It would add a writable directory to runs that provision nothing; it is made only
  with a provision, so `harness: none` and an unprovisioned harness keep master's rule table.

## Implementation notes

- 2026-10-24: `auto` was resolved at compile from the contract's own command, and
  the launcher kept that name, so `tego run c.yaml -- claude` for a contract whose command is `sh` was asked of the
  `generic` provisioner and recorded so (and a `claude` contract run as `codex` would have been given Claude Code's
  provision). Compile now resolves from the command the run was given, and the launcher from the contract's declared
  value and the command it runs (`declaredHarness`; `TestHarnessAutoFollowsTheCommandTheRunExecutes`,
  `TestRunConnectsTheHarnessProvisioners`, `TestCompileHarness`).
- 2026-10-24: `HookAdmitted` judged the hook on `decide.Evaluate` alone, so a gate
  exec rule scoring it into the ask or the refused band left the provision made, and the supervisor's `gateExec` then
  refused the hook on every tool call. It now takes `compile --test`'s exec row: the tier's floor, then the gate
  (`TestHarnessHookUnderTheGate`; compile's warning in `TestCompilePrintsTheHarness`).
- 2026-10-24: D5 counted `last-refusal.json` among the names that already exist, but
  the ledger first writes it at the run's first refusal, so a provision could make the file `TEGO_REASON` names and
  hold forged bytes there until then; and a provision's `TEGO_DNS_BROKER_DIR` passed the "already holds" check because
  `dnsBrokerEnv` had stripped the inherited one. The engine's own names are now refused whether they exist or not
  (`CheckReserved`, used by the run and by compile; `TestHarnessReservedNames`, `TestCompilePrintsTheHarness`).
- 2026-10-24: a provision's variable the agent's environment already held refused the
  run, so a `tego run` started inside a provisioned run, which inherits the parent provision's variables, exited 125
  once a provisioner set any. An inherited value is now replaced, one entry, as the identity set's are; only a name the
  contract's `env.set` gives still refuses (`TestHarnessNestedRunReplacesTheParentsVariables`).
- 2026-10-25: the run refused a provision variable the contract's `env.set`
  gives, but compile checked only the provision's shape and the reserved names, so it printed such a provision as made
  for a contract every run of which exits 125. Every refusal the table and the provision decide alone is now one
  function, `CheckProvision` (the shape, the reserved names, `env.set`), called by the run and by compile; compile also
  asks the provisioner as for a run with a `CODEX_HOME`, which it had refused as "this run has none" though a run
  routed through the forwarder makes the file (`TestCompilePrintsTheHarness`).
- 2026-10-25: the bpflsm branch of `HookAdmitted` (the plane's rows, not the policy
  model's) had no test. `TestHookAdmittedAtBPFLSM` holds it with a table the plane cannot hold, which the bpflsm
  column refuses every exec of (`plane-unbuildable`) while the policy model admits the hook.
- 2026-10-25: claudecode was the first provisioner to read
  a user file and to read `Run.Env`, and compile gave it neither: a `--settings` path a run reads and merges was
  printed `provisions nothing ... (a run is refused)`, and an `env.set CLAUDE_CODE_SIMPLE` contract showed
  `--mode json` where a run uses stderr. Compile now gives `Run.Env` the contract's `env.set` (without `env.deny`'s
  names, as `buildEnv` makes them) and prints `from env.set alone: a variable the run inherits can change what a run
  provisions` for a contract that inherits anything; its `ReadUserFile` makes the run's lexical checks
  (`CheckUserFile`, now `readUserFile`'s own, so the two cannot drift: absolute, not under `deny_read`), refusing as
  the run would, and otherwise prints `provisions from <path>, which a run reads` and no refusal. The refusal line
  is escaped for the terminal like the provision's lines (an error can quote the user's command).
  `TestCompilePrintsTheHarness` holds each case.
- 2026-10-25 (ADR 0063): the `provisions from <path>` line stopped compile before
  `CheckProvision` and `HookAdmitted`, so a `--settings` path under an allow-list showed no `harness-hook-refused`
  (`hook-not-granted`) warning and one with `env.set TEGO_CLAUDE_SETTINGS` showed no refusal, both of which a run
  makes. Compile's `ReadUserFile` now answers `{}` once the run's checks of the path pass, the provision is checked
  and printed as a run's is, and the line `harness <name> merges <path> into the file at run time (...)` sits beside
  the provision's lines (the file's size there is without the user's file). The path is escaped where the line is
  written, since a newline in it would split the line before the per-line escaping; TestCompilePrintsTheHarness
  holds both cases and the escaping.
