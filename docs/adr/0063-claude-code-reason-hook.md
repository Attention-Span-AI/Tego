# ADR 0063: The Claude Code reason hook: one command for five events, each refusal told exactly once

Status: **accepted 2026-10-24**.
Implemented 2026-10-24: `tego hook claude-code` (`internal/adapters/claudecode`, dispatched by `cmd/tego` before the
command line) and `reason.HookInstructions`. Amends the reason channel's channel 3 (spec/reason/REASON-CHANNEL.md §3).
Builds on ADR 0061 (the reason file v1) and ADR 0062
(hook-state/, which the launcher makes and grants). Amended 2026-10-25:
(8) delivery, the Claude Code provisioner (`claudecode.Provisioner`): a per-run settings file passed with
`--settings`, never a file of Claude Code's own; (5) a `--reason` that is `$TEGO_REASON`. Amended 2026-10-25
(measured against the real Claude Code 2.1.310): (3) and (8), a bare session runs no hook at all, so
it is refused like safe mode and the provisioner writes `--mode json` only.

## Context

The reason file (ADR 0061) tells a reader inside the run what Tego refused, with a count cursor, but nothing put
it in front of the agent: a refused write reached Claude Code as `EACCES: permission denied` and the model retried,
worked around, or gave up without knowing that a contract had decided. Claude Code runs command hooks on documented
events with a JSON payload on stdin, and a hook's `hookSpecificOutput.additionalContext` reaches the model as a
system reminder on its next request (hooks reference, Claude Code 2.1.310, read 2026-10-24).

Three facts of that protocol shape the design. Hooks for the calls of one parallel batch run concurrently, so any
hook that reads "what is new" races its siblings. A failed Bash call comes as PostToolUseFailure, not PostToolUse.
And exit 2 means different things per event: stderr to Claude on PostToolUse and PostToolUseFailure, "do not stop"
on Stop, the end of the agentic loop on PostToolBatch, and the user only on SessionStart.

The hook runs as the agent, inside the run, on every tool call. A system call the run refuses (reading ~/.tego, the
ledger root, the machine config) would itself be a refusal, which the next hook would report, on every call.

## Decision

1. **One command, five events.** `tego hook claude-code [--reason FILE] [--mode json|stderr]` reads one payload
   (at most 1 MiB, one JSON object with `hook_event_name`) and routes by its event, so a settings file lists one
   argv for all of them, in exec form (`args` set: no shell, so no shell needs an exec grant):
   - **SessionStart** prints the run's facts, `reason.HookInstructions(<reason file>)`: Tego enforces the run's
     contract and the run cannot change it; a refusal fails with EACCES or EPERM (a refused command commonly exits
     126); the reason file's path; and that each refusal is also reported once beside the tool result that follows
     it or at the end of the turn. It counts the session.
   - **PostToolUse, PostToolUseFailure, PostToolBatch, Stop** each claim the refusals no hook of the run has shown
     yet and print them as `reason.Render` text; with nothing new they print nothing and exit 0.
   Wording comes from `pkg/spec/reason` only (Layer 0); the adapter adds none.
2. **Claim once, under a lock.** The cursor is `hook-state/state.json` beside the reason file:
   `{v: 1, run, cursor, sessions, deliveries, refusals_delivered}`, at most 4 KiB. `cursor` is the highest seq
   shown; `refusals_delivered` is the reason file's `refusals` at the last claim, which is `File.Since`'s cursor, so
   a cursor older than the ring's oldest entry yields every listed refusal and the count of those no longer listed
   (Render's "N more not listed."). A hook takes `flock(LOCK_EX)` on the hook-state directory (polled, a 2 s
   budget), reads the reason file and the state, claims, writes the state to `state.json.tmp` and renames it over
   `state.json`, releases the lock, and only then prints. Of hook processes started at once, each refusal is printed
   by exactly one. A hook killed between its write and its print loses that note: at most once, and the ledger
   still holds every refusal.
3. **Output.** `--mode json` (the default) prints
   `{"hookSpecificOutput":{"hookEventName":<event>,"additionalContext":<text>}}` and exits 0. `--mode stderr`, for a
   hook wired by hand (*amended 2026-10-25, the reason end-to-end test:* this said "for a bare session that drops system
   reminders"; a bare session runs no hook at all, measured, and (8) refuses it, so no provision writes this mode),
   prints the text on stderr and exits
   2 for PostToolUse, PostToolUseFailure and Stop, and prints nothing, claims nothing and exits 0 for PostToolBatch
   and SessionStart. Text is at most 4000 characters (`reason.MaxRenderBytes`), well under the 10,000 at which
   Claude Code moves context to a file.
4. **Stop never loops.** Context on Stop keeps the turn going; a Stop with `stop_hook_active` (Claude Code runs it
   after a Stop hook kept the turn going) prints nothing and claims nothing, new refusals or not, so the agent stops
   and the turn goes on at most once per end of turn. Refusals that land meanwhile stay unclaimed for the next
   PostToolUse or the next turn's first Stop. *Amended 2026-10-24:* this said the next Stop
   "has nothing new unless the run refused again" and that the loop is "bounded by refusals": a process the contract
   kept refusing, and a model that checked by a tool call each time (which resets Claude Code's 8-continuation cap),
   gave a turn that never ended (`TestStopHookActiveClaimsNothing`).
5. **Discovery.** The reason file is `--reason` when given (even empty, which is refused), else `$TEGO_REASON`.
   Neither means the hook runs outside any tego run: a silent exit 0 with no output, so a hand install is safe. A
   path is used only when it is absolute, clean, named `last-refusal.json`, in a directory that is a run's runtime
   directory by convention (`reason.DirFor`, `/run/user/<uid>/tego/<run>/`, or `$XDG_RUNTIME_DIR/tego/<run>/` for the
   XDG_RUNTIME_DIR the hook inherited), and the file's `run` names that directory. `$TEGO_REASON`, which the
   launcher installs last and no contract sets (`TEGO_` is runtime-reserved), is also taken as
   `<base>/tego/<run>/last-refusal.json` under any absolute base but the root, the shape of every runtime directory
   the launcher makes; a `--reason` value, a settings file's, is held to the two conventions above. The hook writes
   only beside it, in hook-state/. *Amended 2026-10-24:* `$TEGO_REASON`
   was held to the two conventions too, so a run under a non-default XDG_RUNTIME_DIR whose contract's `env.pass`
   leaves that variable out (it is not in the identity set) got one stderr line per event and no note for the whole
   run (`TestDiscover`'s "TEGO_REASON under a base not inherited"; the integration test's hook now has no
   XDG_RUNTIME_DIR). *Amended 2026-10-25:* a `--reason` value that is exactly
   `$TEGO_REASON` is taken under `$TEGO_REASON`'s rule. The settings file the launcher provisions names the reason
   file with `--reason`, and the same run's agent has it as `$TEGO_REASON`; held to the two conventions, a run under
   a non-default XDG_RUNTIME_DIR whose `env.pass` leaves the variable out got one stderr line per event and no note,
   the case this item's first amendment closed for `$TEGO_REASON` alone (`TestDiscover`'s "--reason that is
   TEGO_REASON, under a base not inherited"). A `--reason` that differs from `$TEGO_REASON` is held to the two
   conventions as before.
6. **Fail open for the harness, never for the boundary.** Its arguments, the payload, an unreadable or invalid
   reason file (a link, a FIFO, not v1, another run's), a missing or linked hook-state, a lock not taken within 2 s, a
   state file that is a link, too long, garbage or another run's: each gives exit 0, nothing on stdout and one line on
   stderr. JSON mode never exits 2. The agent loses a note; the run loses nothing, and its kernel rules are untouched.
7. **What it touches.** Its own executable, its own /proc/self entries (`exe`, its user namespace's `uid_map` for
   `cli.GuardPrivilege`, and the Go runtime's `cgroup`, `mountinfo` and `auxv`; a descriptor's `fd/N`, never
   `root`, `cwd` or a path below `fd/N`, which reach any file), the reason file and hook-state, and the Go runtime's
   own reads at start (`/sys/kernel/mm/transparent_hugepage/hpage_pmd_size`, and its cgroup's CPU limit under
   `/sys/fs/cgroup` for GOMAXPROCS: `cpu.max`, or `cpu.cfs_quota_us` and `cpu.cfs_period_us` on a cgroup v1 cpu
   controller), which every Go program makes and no tier refuses. No `bpf(2)`, no machine config, no ledger, no
   ~/.tego, no HOME, no network, no process of its own (it starts none, so no helper's calls either), no other tego
   subcommand: `cmd/tego` dispatches `hook` before the
   command line, as it does the run's other helpers, and the verb is not in `tego -h`. The set holds for the whole
   process, the init functions of every package `cmd/tego` links included. *Amended 2026-10-24:* this
   listed only the first four, and `cmd/tego` linked `github.com/cilium/ebpf/rlimit`
   (through `internal/doctor`), whose init function opens `/sys/fs/bpf` and makes a `bpf(BPF_MAP_CREATE)` probe in
   every tego process, the hook and the child stage included; tiers 2 and 3 answer `bpf(2)` with EPERM (ADR 0033
   (3)), so each hook call made a call the run refuses. The doctor now lifts `RLIMIT_MEMLOCK` itself where a probe
   loads, and only below 5.11 (`raiseMemlock`); depguard's `no-init-syscalls` keeps the package out of every
   non-test file, and `TestHookMakesOnlyItsDocumentedSyscalls` traces the built release binary's hook from exec to
   exit. *Amended 2026-10-25:* this said "/proc/self", which the audit admitted
   as a prefix, so `/proc/self/root/<any path>` and `/proc/self/cwd/...` passed it; it named cgroup v2's `cpu.max`
   only, so on a cgroup v1 host the audit failed a correct hook; and it said nothing of processes, while the trace
   followed the hook's threads and not its children, so a hook that started a helper (`sh -c 'read x
   </etc/hostname'`, or one making `bpf(2)`) passed both tests. The set now names its /proc/self entries and both
   cgroup versions' files, a path with a `.` or `..` element is outside it, the tracer follows forks and vforks, and
   the audit fails on any call that starts a process or runs a program.

8. **Delivery: a per-run settings file.** *Added 2026-10-25.* `claudecode.Provisioner`, the
   registry's `claude-code` row (`internal/adapters/registry.go`), has the launcher make
   `<runtime dir>/claude-settings.json` (0444, by the launcher, ADR 0062) and nothing else. The hook argv is
   `<tego executable, absolute> hook claude-code --reason <the reason file> --mode json`; the file lists it in exec
   form, `{type: command, command: <exe>, args: [hook, claude-code, --reason, <file>, --mode, json], timeout: 10}`,
   on SessionStart, PostToolUse (matcher `*`), PostToolUseFailure (matcher `*`), PostToolBatch and Stop, and
   `Provision.Hook.Argv` is that exact argv, so the launcher's exec check (HookAdmitted) judges what Claude Code will
   spawn. For a resolved `claude` command (basename `claude`) the argv becomes `claude --settings <that file>
   <the user's arguments>`: inserted at index 1, so neither a trailing `--` nor a positional prompt takes the flag,
   and the arguments are read as whole elements only (*amended 2026-10-25:* this said "and only before
   a `--`"; Claude Code's option parser, commander, takes the next element as the value of an option that takes one
   before it looks for `--`, so after `--model --` the elements are still options, and the provisioner, with no table
   of Claude Code's options, reads past every `--`). **Bare** (*amended 2026-10-25, the reason end-to-end test:* this gave a
   bare session `--mode stderr` on PostToolUse, PostToolUseFailure and Stop, since "`--bare` still loads
   `--settings`", the default the measurement was to confirm or flip; Claude Code 2.1.310 loads the file and skips
   its hooks, "Minimal mode: skip hooks (those defined in settings and by installed plugins ...)", and the run said
   provisioned while no hook ran, test/e2e/reason-claude/RESULTS.md R2): `--bare` in that argv, or
   `CLAUDE_CODE_SIMPLE` truthy (1, true, yes, on) in the agent's environment (a wrapper's too) or in the env block of
   the user's `--settings`, is refused as safe mode is, with exit 125 and "drop --bare and CLAUDE_CODE_SIMPLE, or set
   harness: none"; a `--bare` after a `--` is refused as ambiguous, as `--safe-mode` there is. Neither mode is a
   flip: json mode reaches no one in a bare session either, and disclosing and continuing would treat two classes of
   session that load no hook (safe and bare) two ways. **The user's own `--settings`** is taken out of the argv and merged into the file: inline JSON (a value
   that starts with `{`) as given, a path through `Run.ReadUserFile` (absolute only; refused under the run's
   `deny_read`, for anything but a regular file and above 2 MiB, and for a root launcher, a guard kept as defence in
   depth: a root run makes no runtime directory, so it is recorded `reason-unavailable` before the provisioner is
   asked, and its command, the user's `--settings` included, runs as given). Every key and hook of theirs is kept,
   tego's entry appended to each event's array (Claude Code merges hook entries across levels and runs both). Every
   event's value must be an array of matcher groups, tego's events and the others alike (*amended 2026-10-25:*
   each an object whose `matcher`, when present, is a string and whose `hooks` is an array of objects with
   a string `type`; any event name is kept, for events newer than the code), and the user's `env` an object of
   strings: the user's entries share the file
   with tego's, and a value Claude Code's schema rejects is a Settings Error, which a `-p` run answers by skipping
   "the broken file or values", tego's hook possibly with them (whether one bad value costs the whole `--settings`
   value is not documented; the reason end-to-end test runs a merged file holding an invalid value against the real binary;
   *amended 2026-10-25, the reason end-to-end test:* it does: with `{"cleanupPeriodDays": "soon"}` merged, Claude Code 2.1.310
   says "These settings files did not load, so nothing in them is in effect, including hooks" and no hook runs,
   while run_start says provisioned, as under a managed policy; the agent keeps `$TEGO_REASON`, and the run's own
   account of whether the hook ran is reason delivery's run_end `reason_delivery`; RESULTS.md R9).
   **`disableAllHooks: false`** is always written at the top level (*amended 2026-10-25*): Claude Code
   reads the value left after settings precedence, and `--settings` outranks user, project and local settings, so a
   `true` in `~/.claude/settings.json`, `$CLAUDE_CONFIG_DIR/settings.json`, or the project's `.claude/settings.json`
   or `.claude/settings.local.json` (committed in a cloned repository, or written by the agent mid-run, which Claude
   Code reloads) cannot turn the hook off in a run recorded provisioned. The same `false` lets the user's own hooks at
   those levels run in a governed run although they turned them off there. **The mode variables** are pinned in the
   file's `env` for the same reason (*amended 2026-10-25*): `CLAUDE_CODE_SAFE_MODE` is `"0"`, and
   `CLAUDE_CODE_SIMPLE` is `"0"` (in every run, there being no bare provision). Claude Code reads a settings file's env block as it reads the shell's, and the
   environment-variables page gives the settings value precedence over the shell's in most sessions, so a project's
   env block could otherwise turn on safe mode or bare mode (no hook in either) in a run whose provision saw
   neither. Whether the real binary
   honours either variable from a settings env block, and whether the flag level's value outranks a project's there,
   is not documented: the reason end-to-end test measures both (*2026-10-25*: it measured the outcome, not each: implementation notes, scenario p). A managed `disableAllHooks` or
   `allowManagedHooksOnly` outranks `--settings` and cannot be overridden from it (Consequences). Refused, so the run
   is refused with exit 125 before run_start: a path `deny_read` covers or that cannot be read (the error says "pass
   it inline or set harness: none"), a relative path, `--settings` twice, with no value or an empty one, a value that
   is not one JSON object, a `hooks` that is not an object of arrays of objects, `disableAllHooks` set to anything
   but `false` (under which no hook runs, so the run would claim a delivery it cannot make), **safe mode** for the
   same reason (`--safe-mode` in a `claude` argv, or `CLAUDE_CODE_SAFE_MODE` truthy in the agent's environment,
   wrapper or not, or in the env block of the user's `--settings`: Claude Code then loads no hook but a managed
   policy's; "drop --safe-mode and CLAUDE_CODE_SAFE_MODE, or set harness: none"), a `--settings`,
   `--settings=<value>` or `--safe-mode` after a `--` (*amended 2026-10-25:* the flag when that `--` is
   an option's value, a prompt otherwise, and tego cannot tell which: one would replace tego's file, as the last
   `--settings` wins, or turn the hook off, in a run recorded provisioned), and a merged file past 2 MiB.
   **A wrapper** (`harness: claude-code` on a command not named `claude`) keeps its argv; every claude-code run's
   environment gains `TEGO_CLAUDE_SETTINGS`, the file's path, for a wrapper or the Agent SDK to pass on as
   `--settings "$TEGO_CLAUDE_SETTINGS"`. An allow-list contract gets the provision dropped (`hook-not-granted`)
   until the hook's exec grant grants the hook (done 2026-10-25, [ADR 0064](0064-harness-hook-exec-grant.md): the launcher
   grants its exact argv, and drops the provision only when no exact grant can be made). Rejected: writing `~/.claude/settings.json` or
   `.claude/settings.local.json` (user files every later session loads, governed or not, against ADR 0059; the
   shipped interactive contract read-denies `~/.claude`); a `--plugin-dir` plugin (a manifest and an enablement for
   no gain); redirecting `CLAUDE_CONFIG_DIR` (it replaces the user's configuration and login); passing two
   `--settings` (how Claude Code merges two is not documented); a root launcher reading a path the user names; and
   resolving a relative path against the launcher's directory (`harness.Run` carries no working directory, and the
   agent's may differ).

### Which events

Claude Code exposes 33 hook events (hooks reference, 2.1.310); those that accept `additionalContext` are
SessionStart, SubagentStart, UserPromptSubmit, UserPromptExpansion, PreToolUse, PostToolUse, PostToolUseFailure,
PostToolBatch, Stop, SubagentStop and PostModelSwitch. The Agent SDK runs the same settings-file command hooks
(`settingSources`, on by default for `query()`), and its own callbacks cover PreToolUse, PostToolUse,
PostToolUseFailure, UserPromptSubmit, Stop, SubagentStart, SubagentStop, PreCompact, PermissionRequest and
Notification in both SDKs; PostToolBatch, SessionStart and SessionEnd are TypeScript-only callbacks (in Python only
as settings-file hooks). Tego uses five: **PostToolUse** and **PostToolUseFailure**, the note beside the result of the
call that was refused, whichever way that call ended; **PostToolBatch**, the last point before the next model request
after a parallel batch, one routing case on top of the cursor that makes every event safe; **Stop**, for refusals that
land after the last tool result (the 10 ms coalescing window, a background process); and **SessionStart**, for the
facts the notes refer to. The settings file that names them is the Claude Code provisioner's.

## Rejected options

- **PostToolUse only** (the first idea): it runs concurrently for parallel calls, so without a cursor the
  siblings race and repeat or drop refusals; and a failed Bash call comes as PostToolUseFailure, which it never sees.
- **PreToolUse**: it fires before the call, when the refusal has not happened yet; telling the agent there would mean
  predicting verdicts, which only the kernel and the supervisor make.
- **`decision: "block"`**: on PostToolUse it is a "reason" shown to Claude, but on PostToolBatch and Stop it ends or
  holds the turn; a hook that changes control flow per event is more than a note. Context does what is needed and
  never stops the agent.
- **`updatedToolOutput`**: it must match each tool's own output shape, and rewriting a tool result is a second
  account of what happened beside the ledger's.
- **A cursor per process or per session (no lock)**: two siblings read the same "new" refusals; a per-session cursor
  still races within a session, and a subagent shares the run's refusals.
- **Holding the lock until the print, or printing before the write**: printing before the write repeats a note when a
  hook dies after its print; holding the lock across a pipe write lets a reader that does not read hold every other
  hook. Commit, then print.
- **Making hook-state/ when it is missing**: the runtime directory is read-only to the agent, so the mkdir would be a
  refusal on every call. The launcher makes it (ADR 0062); without it the hook
  prints nothing and says so on stderr.
- **Dropping PostToolBatch** (proposed once): it saves no measurable time, and it is the last delivery point
  before the next model request.
- **`--print-settings` and run discovery from /proc/self/cgroup** in this package: only adopted runs need them; cut to
  the root reason file, later.

## Consequences

- One argv in the settings serves every event, and refusals reach the model once each, beside the call that caused
  them, in the sentence `pkg/spec/reason` defines for the code.
- The cursor lives in agent-writable state. A forged cursor only hides refusals from the agent itself; the ledger
  stays authoritative, and the counts the launcher reads from it at run end are labelled `reported_by: hook`.
- A payload over 1 MiB (a PostToolUse whose tool_response is a large file) gets no note; its refusals stay unclaimed
  for the next event, and Stop's payload carries no tool output.
- A claude-code run of a deny-list contract is provisioned (8); installed by hand inside a run without hook-state/
  the hook prints nothing and one stderr line. *Amended 2026-10-25:* this said nothing
  installs the hook until the harness provisioning point and the Claude Code provisioner merge; both are merged.
- What the provisioner cannot see stays a gap, disclosed (*added 2026-10-25*): a managed settings
  policy's `disableAllHooks: true` or `allowManagedHooksOnly` outranks the `--settings` file, so under such a policy
  the run records `provisioned: true` and the hook does not run; the agent keeps `$TEGO_REASON` and the ledger keeps
  every refusal. The provisioner reads no managed settings (an administrator's files and a server's policy are not
  the run's to read), and the reason end-to-end test's run against the real binary is where a policy's effect can be measured.
- A root launcher provisions nothing: it makes no runtime directory, so run_start's harness says
  `reason-unavailable` and a `claude` command runs with its arguments, its own `--settings` included, as given.

## Tests

`internal/adapters/claudecode`: TestEachEventGolden (every documented payload under `testdata/payloads`, goldens under
`testdata/golden`), TestNoRefusalYet, TestNewRefusalsOnly, TestCursorOlderThanTheRing, TestStopNeverLoops,
TestStderrMode, TestFailOpen (one case each), TestJSONModeNeverExitsTwo, TestOutputBound, TestOutsideAnyRun,
TestExactlyOnceAcrossProcesses (8 processes, 50 refusals), TestExactlyOnceWhileTheRunRefuses (8 workers while the
file grows), TestDiscover, FuzzHookInput, TestNamesMatchTheEngines; with the integration tag,
TestHookUnderTegoRunIsRefusedNothing (the built hook under `tego run`, tier landlock, `record: full`, found through
`TEGO_REASON` with no XDG_RUNTIME_DIR, run twice: with HOME's `.tego` the run's read-denied tego directory, holding
the machine config `TEGO_CONFIG` names and the ledger root `TEGO_LEDGER` names, so that any read of them is a refused
line, and with HOME unreadable, where it still works; no refused line but a deliberate one. *Amended 2026-10-24:*
it ran with the unreadable HOME only, where DAC stops a read of `$HOME/.tego` before any
Tego rule, so a hook that read the machine config passed it; that mutant, and one reading `$TEGO_CONFIG` and
`$TEGO_LEDGER`, now fail it) and TestHookMakesOnlyItsDocumentedSyscalls (the release build's hook traced from
exec to exit, its children included: no path outside (7)'s set, no `bpf(2)`, no socket, no fork, vfork, process
clone or exec), TestHookMayNameIsTheDocumentedSet (that set, both cgroup versions, no way out through a /proc link
or a `..`); TestStopHookActiveClaimsNothing (unit). `internal/testutil`: TestSysTraceCommandFollowsChildren,
TestSysTraceFollowsAGoExecChild, TestSpawnsTellsAThreadFromAProcess. `test/sysaudit`: TestThroughALinkCatchesTheWaysOut.
`internal/doctor`: TestMemlockNeeded. `cmd/tego`: TestHookIsDispatchedBeforeTheCLI, TestHelpDoesNotListHook.
`pkg/spec/reason`: TestHookInstructionsAreInstructionsAndTheNote.
(8), added 2026-10-25: `internal/adapters/claudecode` TestProvisionGoldens (`testdata/golden/provision-*.golden`:
a claude command, inline and path `--settings` merged, a wrapper; *amended 2026-10-25, the reason end-to-end test:* the
`--bare` and `CLAUDE_CODE_SIMPLE` goldens are gone, those runs being refused), TestProvisionArgv,
TestProvisionRefuses, TestProvisionSizeLimit; with the integration tag TestProvisionedClaudeHearsOfItsRefusal (the
stand-in Claude Code, `test/e2e/reason-claude/fakeclaude`, under `tego run` at tier landlock: its next model request
carries the refused write's text, rule and target, no refused line is the hook's, and `~/.claude`,
`CLAUDE_CONFIG_DIR` and the project's `.claude/` are unchanged), TestProvisionRefusesADeniedSettingsPath (exit 125),
TestProvisionAllowListIsGranted (TestProvisionAllowListIsNotGranted until the hook's exec grant merged).
`internal/adapters`: TestForNamesEachBuiltProvisioner. *Amended 2026-10-25:* every provision TestProvisionGoldens and TestProvisionArgv make has `disableAllHooks: false` (a user
value without the key included), and TestProvisionRefuses also refuses `--safe-mode`, `CLAUDE_CODE_SAFE_MODE` (a
wrapper's too), a non-boolean `disableAllHooks`, and an event entry that is not an object, on an event tego registers
and on one it leaves alone; its root case is reachable only with a hand-set `Run.Root` (a root run never asks the
provisioner). *Amended 2026-10-25:* TestProvisionRefuses also refuses `--safe-mode` and `--settings`
after a `--` (`claude --model -- --safe-mode`, `claude --model -- --settings /p`), `CLAUDE_CODE_SAFE_MODE` in the
user's env block, an `env` that is not an object of strings, and a matcher group with no `hooks` array, with a
`hooks` string, with a hook that is not an object or has no string `type`, or with a non-string `matcher`;
TestProvisionArgv reads `--bare` after a `--` as bare; TestProvisionPinsTheModeVariables holds the file's `env`
(`CLAUDE_CODE_SAFE_MODE` `"0"` always, `CLAUDE_CODE_SIMPLE` `"0"` in json mode, a truthy `CLAUDE_CODE_SIMPLE` of
the user's giving stderr mode; *amended 2026-10-25, the reason end-to-end test:* TestProvisionRefuses now refuses `--bare`, a
`--bare` after a `--`, and a truthy `CLAUDE_CODE_SIMPLE` in the agent's environment, a wrapper's and the user's env
block, TestProvisionArgv holds json mode for every argv it provisions, and TestProvisionPinsTheModeVariables both
variables `"0"` in every file); and `internal/cli` TestCompilePrintsTheHarness holds a `--settings` path under an
allow-list (`hook-not-granted`) and with `env.set TEGO_CLAUDE_SETTINGS` (a refusal), and an ESC or a newline in the
path escaped on both the refusal and the merge line.

## Implementation notes

- 2026-10-25: (8) built, and (5) amended. Departures from the first design, each for the code
  as it is: the hook's `--reason` was held to the two runtime-directory conventions, so the settings file's argv
  would have failed in every run under a non-default XDG_RUNTIME_DIR whose `env.pass` leaves the variable out (the
  integration test's own case); a `--reason` equal to `$TEGO_REASON` now takes `$TEGO_REASON`'s rule, which keeps
  the first design's argv. A relative `--settings` path is refused rather than read (`Run.ReadUserFile` takes
  absolute paths, and the run's working directory is not in `harness.Run`). `disableAllHooks` and a merged file past
  2 MiB are refused (not in the package; both would give a run that says it delivers what it cannot).
  `TEGO_CLAUDE_SETTINGS` is set for a direct `claude` command too, not only for a wrapper, so one name always holds
  the file. Compile prints a claude-code contract's provision, and a `--settings` path in the contract's command as
  "provisions nothing ... (a run is refused)", since compile reads none of the user's files.
- 2026-10-25: the settings file always sets `disableAllHooks: false` (a
  project's, `CLAUDE_CONFIG_DIR`'s or the user's `true`, even one the agent writes mid-run, turned the hook off in a
  run recorded provisioned); safe mode (`--safe-mode`, `CLAUDE_CODE_SAFE_MODE`) is refused like `disableAllHooks`;
  every event entry of the user's `hooks` must be an object, and the shared-file risk is stated in (8). The docs no
  longer promise exit 125 for a `--settings` path under a root launcher: a root run is `reason-unavailable` before
  the provisioner is asked, and the `Run.Root` guard is defence in depth. Compile (ADR 0062's implementation note of
  this date) prints a readable `--settings` path as read at run time, not as a refusal, and shows the mode a
  contract's `env.set` (`CLAUDE_CODE_SIMPLE`, `CLAUDE_CODE_SAFE_MODE`) gives.
- 2026-10-25: a `--` no longer ends the argv scan (a `--` can be an option's
  value, after which `--safe-mode`, `--settings` or `--bare` are flags: the run was recorded provisioned while Claude
  Code loaded no hook, or the user's file in place of tego's); `--settings` and `--safe-mode` after one are refused
  and `--bare` after one gives stderr mode. The user's `--settings` env block is read for `CLAUDE_CODE_SAFE_MODE`
  (refused) and `CLAUDE_CODE_SIMPLE` (stderr mode), and the file pins both variables (8). Matcher groups are checked
  one level deeper. Compile (ADR 0062's note of this date) checks the provision of a `--settings` path as a run does.
- 2026-10-25 (measured against the real Claude Code 2.1.310 under `tego run` at tier landlock with
  the model stub, test/e2e/reason-claude/RESULTS.md): the hook's text reaches the model's next request for a refused
  write, a refused exec and two refusals of one parallel turn, each once, and an allowed write's next request holds no
  tego text. What the measurement changed or found: **R2**, bare mode runs no hook at all (not a session that drops
  reminders), so (3) and (8) are amended: a bare session is refused with exit 125, and the provisioner writes json
  mode only (one decision for both classes of session that load no hook; the first design's "one line in argv.go if
  it must flip" became the refusal, since neither mode reaches a bare session). **R1**, 2.1.310 sends the tool
  events' and SessionStart's `additionalContext` as a system-role message "`<event>:<tool> hook additional context:
  <text>`" after the tool results, and Stop's as a `<system-reminder>`; fakeclaude models it, and the CI twin holds it to the golden. **R3**, Claude
  Code's Write writes `<name>.tmp.<pid>.<hex>` through an `O_PATH` descriptor of the directory (`/proc/self/fd/N/`)
  and unlinks it after a failure, so one refused Write is two refusals told under that path, true to ADR 0016 but
  to be matched by file name. **R4**, a runtime directory under tego's own state directory leaves the settings file
  unreadable to the agent while the run says provisioned (the harnesses keep it beside; the launcher does not refuse
  it yet: known limitation). **R7**, a refusal reaches the reason file up to 10 ms after its system call
  (the ledger's refusal window), so the hook that starts right after a call can miss it and a later hook tells it:
  the real binary's PostToolUseFailure hook started 4 ms after the Write's unlink and told only the open, its
  PostToolBatch hook 13 ms after and told the unlink. A refusal in the last 10 ms before a turn's last hook is told
  one request late, still once (reason delivery's to close). **Scenario p**: a project `.claude/settings.json`
  holding `disableAllHooks: true` and both mode variables truthy, which the real binary read, did not turn tego's
  hook off; that is the outcome, and the run does not show which mechanism gives it (the file's
  `disableAllHooks: false`, its `"0"` values, or Claude Code not taking the variables from a settings env block). **R9** (scenario v): one value of the user's that Claude Code's schema
  rejects drops the whole merged file, tego's hook with it, while run_start says provisioned (8). The CI twin (`test/e2e/reason-claude/fakeclaude`,
  TestReasonEndToEndThroughTheStandIn) runs a, c, d and e through the stand-in on every CI run and holds the next
  request to the golden the real binary wrote; a mutation that sends the notes as a user message fails it.
- 2026-10-25 : an allow-list contract
  keeps the provision, its hook granted by ADR 0064, so compile of a `--settings` path under an allow-list prints the
  hook grant line where it warned `hook-not-granted`, and warns `harness-hook-writable` where a write entry holds the
  tego binary (`TestCompilePrintsTheHarness`); a learned Claude Code contract compiles with no warning
  (`TestLearnProposalsLoadAndCompile`, whose one-warning exception for it is gone); acceptance (7)'s run of an
  allow-list contract is provisioned with its hook granted (`TestProvisionAllowListIsGranted`, which held it dropped).
- 2026-10-25 : ADR 0062 is merged, so its citations no
  longer say "not merged yet". The launcher now makes and grants hook-state/ beside the reason file, under the name
  this hook reads (`hook-state`); no provisioner writes the settings yet, so a run still
  provisions no Claude Code hook (`run_start.harness.why` is `no-provisioner`) and nothing installs it. No change to
  the hook.
- 2026-10-25: the syscall audit of (7) followed the hook's threads only and
  admitted `/proc/self/` and `cpu.max` by prefix and base name. `internal/testutil`'s tracer now follows forks and
  vforks (PTRACE_O_TRACEFORK, PTRACE_O_TRACEVFORK: the kernel reports a clone with CLONE_VFORK, as os/exec makes, as
  a vfork and one with exit signal SIGCHLD as a fork, neither as the clone event it traced) for every audit,
  `test/sysaudit`'s config audits included; `Syscall.Spawns` names a fork, vfork, process clone, clone3 or exec
  (clone3's flags read from its `clone_args`), and the hook's audit fails on one. `hookMayName` admits the
  /proc/self entries the release build names (measured: `exe`, `uid_map`, and the runtime's `cgroup` and
  `mountinfo`; `auxv` is the runtime's fallback) and `fd/N`, cgroup v1's two CPU files beside `cpu.max`, and no path
  that is not clean. `status` and `maps` were proposed too; the release hook names neither, so they stay
  out. No cgroup v1 host was booted: `TestHookMayNameIsTheDocumentedSet` pins the v1 names, and the Go 1.27 runtime's
  `internal/runtime/cgroup` is the source of them.

- 2026-10-24: built as decided. Departures from the first design, each for the code as it is: the runtime directory
  convention also accepts `$XDG_RUNTIME_DIR/tego/<run>/` (the launcher's RuntimeDirBases; the tests and every
  launcher whose XDG_RUNTIME_DIR is not the systemd default make it there); the not-listed line is Render's
  "N more not listed." rather than "N earlier refusals are not listed" (one wording, Layer 0's); the state keeps
  `v` and `run` beside the four counters the package named, so a state of another run or format is refused. The
  integration test hands the hook a runtime directory of its own, because the launcher on this base makes no
  hook-state/ yet; the hook's system calls are the same.
