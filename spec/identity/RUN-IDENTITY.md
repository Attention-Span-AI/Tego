# Run identity (spec v0)

## Ids
- `run id`: `r-<host8>-<time36>-<rand6>`; `host8` is the first 8 hex of sha256(machine-id). `runslug` is the run id
  with dashes removed, used wherever a systemd slice segment must name the run.
- `agent id`: the contract `name`, `[a-z0-9-]{1,40}`.
- `exec id`: `<run id>/<pid>/<start-boot-ns>` for every process in the run; stable across pid reuse.
  `<start-boot-ns>` is the process's start (`task->start_boottime`) rounded down to a whole USER_HZ tick (10 ms): the
  `/proc/<pid>/stat` field-22 value times 10^7. A producer with the exact start rounds it the same way
  (`internal/platform/proc.ExecID`). Without that, the seccomp supervisor (from `/proc`) and the tier-2 recorder (from
  the kernel) named one process with two ids, and a `parent_exec_id` from one never matched an `exec_id` from the
  other. Two processes share a `(pid, tick)` only if the pid space wraps within 10 ms.

## Cgroup
- Unprivileged launcher: `<delegated user subtree>/tego.slice/tego-<agent>.slice/run-<id>.scope`.
- Privileged launcher: `/sys/fs/cgroup/tego.slice/tego-<agent>.slice/run-<id>.scope`.
- Container parent pre-created for Docker: `tego-<agent>-<runslug>.slice` in the daemon's manager (systemd driver)
  or `/sys/fs/cgroup/tego/<agent>/<run>` (cgroupfs driver); a `descendants` member of the run set.

## Run directory
`~/.tego/runs/<id>/`; a `tegod`, which ADR 0042 keeps unbuilt, would use `/var/lib/tego/runs/<id>/`. Never under a
declared write directory.

## Environment set in the run (identity propagation)
| Variable | Value | Purpose |
|---|---|---|
| `TEGO_RUN_ID` | run id | the identity |
| `TEGO_AGENT` | agent id | |
| `TEGO_PARENT_RUN` | the run's `run_start.parent_run`: the enclosing run's `TEGO_RUN_ID` when the `tego run` was started inside a governed agent, else the `TEGO_PARENT_RUN` its environment named, else empty (still set). *Amended 2026-10-25 (ADR 0073 D3):* a nested agent used to see the inherited `TEGO_PARENT_RUN`, its enclosing run's own parent | nested and cross-host linking; a `tego run` records as `run_start.parent_run` the enclosing run's `TEGO_RUN_ID` when its environment has one (it was started inside a governed agent, whose `TEGO_PARENT_RUN` is that run's own parent), else the `TEGO_PARENT_RUN` its environment named, and refuses one that is not a run id (exit 125, ADR 0073 D3); the agent sees the value recorded (`TestTheAgentsParentRunIsDepsParentRun`) |
| `TEGO_LEDGER` | run directory | where the record is; read-denied to the run itself (agent-contract R6a), so for readers outside it |
| `TEGO_REASON` | the run's readable copy of `last-refusal.json`, in its runtime directory; unset when the run has none (a root launcher makes no runtime directory) | the reason channel for a harness inside the run (REASON-CHANNEL §2); added 2026-09-24. *Amended 2026-10-24 (ADR 0061):* the file is the reason file v1 (`pkg/spec/reason`): the latest refusal at the top level plus `v`, `run`, `seq`, `ts`, `pid`, `text`, `refusals` and the newest 32 in `recent`; a reader keeps `refusals` as its cursor |
| `TEGO_CLAUDE_SETTINGS` | the run's provisioned Claude Code settings file, `<runtime dir>/claude-settings.json` (0444): the reason hook for each of its events, and the command's own `--settings` merged in; set only in a run provisioned for harness `claude-code` | for a wrapper or the Agent SDK to pass on as `--settings "$TEGO_CLAUDE_SETTINGS"`; a resolved `claude` command is given `--settings` itself. Not in the identity set: the harness provision adds it (agent-contract.md R27, ADR 0063); added 2026-10-25 |
| `TEGO_TIER` | `landlock`, `cgroup`, `bpflsm`, `observe` | what enforces |
| `OTEL_RESOURCE_ATTRIBUTES` | `tego.run=<id>,tego.agent=<name>` appended with `,` to any existing value (`,` and `=` percent-encoded) | OpenTelemetry SDKs merge it as the secondary resource |
| `PGAPPNAME` | `tego:<id>`, only if unset | Postgres `pg_stat_activity` (first 63 bytes), CSV log and `log_line_prefix %a` (full; pgaudit lines only through `%a`); honoured by libpq, pgx, node-postgres; a DSN `application_name` wins; asyncpg ignores it |
| `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, `OPENAI_API_BASE`, `GOOGLE_GEMINI_BASE_URL`, `GOOGLE_VERTEX_BASE_URL`, `CODE_ASSIST_ENDPOINT`, `CODEX_HOME` | the forwarder listeners (Codex through a generated `config.toml`), only when `capture: forwarder` | capture without a CA; the OpenAI names listed 2026-09-29 |
| `NO_PROXY`/`no_proxy` | `127.0.0.1,localhost` appended, only when a `*_PROXY` variable is passed in | the forwarder's plaintext URL must not go to a proxy |
| `DOCKER_HOST` | `unix://$XDG_RUNTIME_DIR/tego/<run>/docker.sock`, only when the contract has `docker:` (`DOCKER_CONTEXT` is unset) | container adoption |
| `CONTAINERS_CONF_OVERRIDE` | a per-run file, only with `containers: rootless` | identity into podman containers |
| `RAY_RUNTIME_ENV_HOOK`, `RAY_ENABLE_UV_RUN_RUNTIME_ENV=0` | the Ray adapter, only when the profile enables it | `TEGO_PARENT_RUN` into Ray workers |

`env.pass`, `env.deny`, `env.set` apply first (SEMANTICS §9); runtime variables are applied last and win.

## Who launched the run (ADR 0073)
`run_start` records, from record minor 17, what the launcher read when the run started (`identity.LauncherOf`): its
real uid (`launcher_uid`, always) and passwd name (`launcher_user`); when its real and effective uid are 0 in the
initial user namespace and its own `SUDO_UID` (the one its drop reads, never the agent's environment) is the plain
decimal of a uid, that uid (`sudo_uid`) and its passwd name (`sudo_user`, never `SUDO_USER`); the kernel nodename
(`host`, at most 255 bytes with no control, format, line or paragraph separator character); the run its environment
says it is nested in (`parent_run`: the enclosing run's `TEGO_RUN_ID`, else `TEGO_PARENT_RUN`; a claim, not a
verified link, until nested runs are verified); the caller's `labels` (at most 32, key `^[a-z0-9][a-z0-9._-]{0,62}$` outside the reserved `tego.` prefix,
value at most 256 bytes of UTF-8 with no control, format, line or paragraph separator character); the `role` (reserved: `check`
marks a run a checking command started, and no shipped command sets it; absent for the agent's own); and the contract's `revision` (`contract_revision`). None
is a verified fact about a person: `sudo_uid` is sudo's claim, which any root process can set.

## Headers added by the forwarder
`X-Tego-Run: <run id>`. `traceparent`: when the client sent none or an invalid one, `00-<first 16 bytes of
sha256(run id), hex>-<fresh random non-zero 8 bytes>-01` and any incoming `tracestate` is discarded; when the client sent
a valid one, its trace id and flags with the parent id replaced by the forwarder's fresh span id. `tracestate`:
`tego=<run id>` prepended, any prior `tego` member removed, the right-most member dropped past 32. Recorded on
`ssl_request` as `trace_id`, `span_id`, `parent_span_id`.

## Exit codes of `tego run`
The convention `docker run`, GNU `timeout` and the shell use, so CI needs no new rule. Never the LSB/systemd range
200–254 (rendered by name in `systemctl status`).

| Code | Meaning | Ledger |
|---|---|---|
| agent's code (0–255) | the agent exited; passthrough | `run_end reason=exit exit_code=n` |
| 128+n | the agent died by signal n (synthesised from the wait status) | `run_end reason=exit signal=n` |
| 124 | Tego ended the run on a limit (`tokens`, `cost_usd`, `wall`, `stall_after`, repeats); the agent was killed via `cgroup.kill` | `run_end reason=limit` + `limit` event |
| 125 | Tego failed before exec: contract invalid (incl. `contradiction`: a write entry contains the run directory or the contract file), tier or capture unavailable, machine config untrusted, cgroup, ledger or program-load error; one sentence on stderr with the diagnostic code | none |
| 126 | the command was found but could not be executed (`EACCES`/`ENOEXEC`, or the tier cannot grant exec on it) | `run_end reason=exec-failed` |
| 127 | the command was not found | `run_end reason=exec-failed` |
| 137 / 143 | passthrough when someone else ended it: `tego stop` or a signal to the launcher (143 after SIGTERM, 137 after `cgroup.kill` at `stop_grace`), memory or pids cap (137) | `run_end reason=stopped|oom|pids` |
| 125 with code `config-untrusted` | machine config invalid or untrusted (path, owner and mode follow) | none |
| 125 with code `tier-unavailable` | the contract pins a tier the machine cannot provide (`doctor --require <tier>` exits 211 for the same condition) | none |
| 125 with code `privileged-path-unsupported` | the launcher gained privilege without being root of the initial user namespace: a file-capability, setuid or setgid copy of tego (`AT_SECURE`), a real and effective uid or gid that differ, or a privileged inherited capability set. Every subcommand but `version` refuses the same way, before anything runs; a launcher holding only incidental capabilities (`CAP_NET_BIND_SERVICE` and the like) has them cleared and runs at tier `landlock` (ADR 0042 (3)(a); *added 2026-10-05*) | none |
| 125 with code `budget-unmetered` | the run's contract declares a `tokens`, `cost_usd` or `repeats` budget and nothing would count it: no capture runs for it (`capture: off`, a machine `capture:` ceiling of `off`, the forwarder with no `models:` endpoint, `record: off` under uprobe capture), or no price table that lists a model loads for `cost_usd`, or the table that loads prices no model (every entry lacks `input_per_mtok` or `output_per_mtok`) (limits-check-doctor-cli.md R32; *amended 2026-10-17:* the table that prices no model added); the message names the cause and the fix | none |
| 125 with code `capture-unavailable` | the run has a `tokens`, `cost_usd` or `repeats` budget and the capture mechanism that would meter it could not start (limits-check-doctor-cli.md R32); the message names the cause and the fix | none |

An ask timeout is a refusal (`ask-timeout`), never an exit code. Other subcommands: 0 ok; 1 a finding (`drift` found
drift, `status` shows `stalled` or `lost`, `doctor` finds no tier this machine can run, `compile` found an error);
211 `doctor --require <tier>` on a machine that cannot reach that tier; 2 usage; 125 Tego's own error. Warnings
never change the code, nor does a stderr `tego run` cannot write them to (*amended 2026-10-05:* it turned the
agent's 0 into 125; limits-check-doctor-cli.md R25). (*Amended 2026-09-24:* this said `doctor` exits 1 below `--require`; it exits 211, as the
table above and `doctor`'s own code do)

## Signals
The agent shares the launcher's process group. Terminal-generated `SIGINT`/`SIGQUIT`/`SIGTSTP`/`SIGWINCH` reach it
directly and are not re-sent; `tego run` forwards `SIGTERM`/`SIGHUP`/`SIGUSR1`/`SIGUSR2` always and
`SIGINT`/`SIGQUIT` only when stdin is not a terminal. `SIGINT`/`SIGTERM`/`SIGHUP` start `stop_grace` (machine config,
default 10 s); a second `SIGINT` within 2 s or expiry writes `cgroup.kill`. Ledger: `run_end reason=signal signal=<n>
escalated=<bool>`; exit code: passthrough. `reason=stopped` is reserved for `tego stop`.

## Messages
One sentence on stderr per error, in `<file>:<line>[:<col>]: <what is wrong> [<code>]` form followed by the fix, so
editors can jump to it. `compile` codes are `agent.Diagnostic` (`schema`, `path-missing`, `host-unresolvable`,
`exec-not-on-path`, `limit-above-machine`, `contradiction`, ...); refusal reasons are `record.Reason` and are never
mixed with them. `doctor` and `run` refusals name the tier and the one command that fixes it.
