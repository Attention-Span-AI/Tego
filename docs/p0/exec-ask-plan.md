# Exec approval (ADR 0044) implementation plan

Written 2026-10-16 against the tree where ADR 0048 P1 (exec command rules) is merged and `exec.ask`
is reserved: parsed, and every match refused with `completion_unsupported: true`. The design is
[ADR 0044](../adr/0044-ask-before-a-command-runs.md); this plan sequences it into work packages. Nothing here is built. Section numbers in "ADR (n)" refer to ADR 0044's Decision.

*Amended 2026-10-16 (ADR 0044):* WP1 grants nothing for an ask entry that only adds the ask step,
helper images included, and reports `AskClosuresOf` as a set with `ClosureSubs` beside it; WP3
records a release before the detach and writes its outcome on the approved exec's terminal line; WP5
carries `release_closure`; WP7 builds and tests the release of an approved `exec.args[<tool>]` exec.

*Amended 2026-10-16:* WP1's ask verdict says whether the tool is constrained, and
ask closures are kept for every constrained tool, whichever entry constrains it; WP3 records a release for an
approval of any constrained tool whose row has a helper closure, so a worded allow entry beside a path or directory
grant no longer fails an approved push (TestExecReleaseWordedAllowConstrains and a third section in
TestIntegrationExecAskApprovedPushCompletes); WP7's `file://` push test says why `git-receive-pack`
passes the floor, a link to git, and what it expects where it is a copy.

*Amended 2026-10-17:* WP1's acceptance asks for the closure
line only where the tool is constrained and WP1 tests that an implicit grant's tool stays
unconstrained under an ask entry (TestExecAskImplicitGrantDoesNotConstrain); WP3 and WP5 count
the approvals that recorded no release in `run_end`'s `exec_asks`, the cause that survives `record: off`;
WP7 records no release for an `exec.args[<tool>]` approval whose readings disagree, so it takes no slot and always says
`readings_disagree`.

## 1. Goals and non-goals

**Goals**

- An exec matched by `exec.ask`, by `exec.unlisted: ask`, or scored into the gate's exec ask range pauses the agent,
  asks a person, and runs only if the person approves and the kernel's own facts at the exec stop equal the approved
  facts (the trace-gate, ADR (1)), at every tier: landlock, cgroup (fanotify fallback and plane) and bpflsm.
- Allow once, always allow, deny, deny always (exact or by command pattern), wait; a timeout always refuses.
- One `ask` and `answer` pair per decision in the ledger, one terminal line per exec, and the agent told why
  (`$TEGO_REASON`).

**Non-goals**

- No BPF object change. ADR 0048 P2 (kernel pins) stays its own work; this plan only reserves its `trace_gate` pin flag
  (ADR (13)).
- No answer persists across runs. No model call anywhere (ADR 0003).
- No control outside the governed run; the supervisor traces only processes of the run it launched.

## 2. Rules every package follows

- **Gates per commit.** `gofmt -l .` prints nothing; `go vet` passes in the four tag sets (`""`, `integration`,
  `tegobpf`, `integration tegobpf`) for the touched packages; `go run ./tools/rulecheck` passes; before a package
  closes, `make lint` and the unit and `-tags integration` tests of every touched package pass, once also with a
  minimal `PATH`.
- **Spec with behaviour.** Every behaviour change lands with its amendment in the same commit (section 7 lists which
  document each package touches), each amended spec section gaining a dated Changes entry.
- **A test that fails without the change**, for every fix and every guard. Each compared fact of the trace-gate has
  its own mutant: change that one fact alone, and the exec must be killed.
- **Root and kernel tests run in the KVM guest**, never on the host (`test/vm/root-suites.sh`), and root-only tests
  are listed in `test/integration-skips.txt`; new must-pass root tests join `test/vm/root-must-pass.txt`.
- **Isolation.** Manual runs use a `tegotesthooks` build, a scratch `machine.yaml` with `ledger_root`, and
  `TEGO_CONFIG`, `TEGO_TEST_CHAIN_ANCHOR` and `TEGO_TEST_OWN_LOG_HOME` under a scratch directory; agent harnesses run
  offline against the local model stand-ins with an isolated home and no credential.
- **Until WP3 lands, `exec.ask` keeps refusing at runtime.** WP1 may admit ask tools at the floor before then: the
  supervisor still refuses every ask match, so the admission is inert, and the reservation's compile warning stays
  until WP3 replaces it.

## 3. Order and dependencies

| Package | Depends on | Can run beside |
|---|---|---|
| WP0 evidence spikes | — | WP1, WP2 |
| WP1 contract and compile | — | WP0, WP2 |
| WP2 broker and CLI | — | WP0, WP1 |
| WP3 supervisor trace-gate | WP0 (go/no-go), WP1, WP2 | WP4, WP5 |
| WP4 integrity guard and launch checks | WP1 | WP3, WP5 |
| WP5 record and readers | WP2 | WP3, WP4 |
| WP6 gate ask range | WP3 | WP7 |
| WP7 catch-all (`exec.unlisted`, `exec.ask_paths`) | WP3, WP4 | WP6 |
| WP8 acceptance | WP3 to WP7 | WP9 |
| WP9 operator docs and rows | WP8's results | — |
| WP10 `exec.assurance: verified` (after the first cut) | WP8 | — |

WP3 does not start until WP0's go/no-go (section 6) is green. ADR 0044's Status changes to "built" only after WP8.

## 4. Budgets

Measured on a 6.17.0-41 host and in the 6.17 guest in both boots, against a baseline recorded in each package's
first commit. A budget that fails blocks the package; it is never raised in the same commit.

| Measure | Budget |
|---|---|
| A run with no exec ask: filter, notification path, allocations | unchanged: the filter goldens are byte-identical, `BenchmarkNotificationRoundTrip` shows no more allocs/op or B/op on every case |
| An exec that matches no ask, in a run that can ask | no more allocs/op than the same exec under ADR 0048 alone; p50 at most +1 µs |
| Trace-gate, seize to detach, argv and environment of 4 KiB together | supervisor CPU p50 at most 60 µs, p99 at most 200 µs; added wall time to the exec p50 at most 300 µs |
| Trace-gate compare at the read budget (128 KiB argv and 128 KiB environment) | at most 2 ms |
| A vfork parent of an exec held at the exec stop | released within 1 ms p99 |
| Answer line accepted to the program's first instruction | at most 5 ms p99 |
| A parked exec hold | no worker or standby held; at most 8 KiB of supervisor memory beyond its facts |
| Run start with an exec ask (Yama read and the stage child's seize) | at most +2 ms p50 |
| `exec.assurance: verified` (WP10), per guarded exec | supervisor CPU at most +60 µs p50, +200 µs p99; unguarded execs unchanged |

## 5. Work packages

### WP0: evidence spikes (scratch code, never embedded)

The ADR's "Evidence not yet run", each with a written result.

- **Go tracer.** One locked OS thread owning every trace: seize a task held in a real seccomp notification from the
  supervisor's listener, queue the interrupt, `CONTINUE`, wait by thread group id with `__WALL|WUNTRACED`, read
  `/proc/<pid>/exe`, `cwd` and the new mm's argv and environment with `process_vm_readv`, detach or kill. Cases:
  success, `ENOENT`, `ENOEXEC`, `EACCES`, a non-leader thread's exec, SIGSTOP and SIGTERM during the exec stop, the
  tracer thread's exit with `PTRACE_O_EXITKILL`, and two hundred concurrent traces. It must show that the tracer never
  takes an exit owned by `internal/runtime/launch/reap.go` (orphan reaping) or by the main child's `waitid(P_PIDFD)`,
  and that the launcher's job-control handling (`jobcontrol_integration_test.go`) still passes with traces live.
- **Root tiers in the guest.** The same at C⊘, C+ in LSM and fmod_ret mode, and B: the plane's `ptrace_access_check`
  must not refuse the launcher's seize; a run member's `PTRACE_SEIZE` of a sibling must still be refused by the plane
  where it was before.
- **The hold-point switch.** `kcmp(KCMP_VM)` against the parent for glibc `posix_spawn`, CPython `subprocess`, Go
  `os/exec`, Node `child_process` and bash, end to end through the supervisor.
- **`#!` chains.** One- and two-stage scripts and `#!/usr/bin/env node`: the expected vector built from the approved
  chain equals the kernel's at the stop; a rewritten `#!` line and a swapped interpreter are caught.
- **The integrity guard.** ADR (7)'s outright refusals with a static seccomp errno action: `PTRACE_ATTACH`,
  `PTRACE_SEIZE` and `process_vm_writev` from a run member fail; `PTRACE_TRACEME` works and makes the later seize fail;
  `clone(CLONE_FS)` without `CLONE_THREAD` fails; the shared-`fs` probe no longer wins.
- **Codex.** The offline Codex harness (OpenAI Responses stand-in, isolated `CODEX_HOME`, no credential): a 20 s hold
  and a hold past the shell tool's timeout; what the model is told; whether the held process survives; the environment
  of two consecutive commands.
- **Go/no-go.** Go when every case above holds. If the tracer cannot be made to leave the launcher's exits alone, WP3
  refuses a traced exec of the agent's main process (`trace_unavailable: error`) and the rest goes ahead. If the
  trace-gate fails at a tier, exec asks at that tier are refused with `completion_unsupported` and the capability cell
  says `no`; if the integrity guard does not hold, no exec ask completes at any tier until it does. The plan never
  falls back to an unverified `CONTINUE` (ADR 0044's "Evidence not yet run" records the same outcomes).

### WP1: contract and compile

**Files.** `pkg/spec/agent/agent.go` (`ExecSection` gains `Unlisted` and `AskPaths`), `pkg/spec/agent/ask_config.go`
(`exec_hold`, `exec_volatile_env`; incompatibility with observe, setuid, io_uring), `pkg/spec/agent/merge.go` (stricter
`unlisted` wins, `ask_paths` concatenate), `pkg/spec/agent/compile_execcommands.go` (in a restricted section, ask
entries resolved and admitted like bare allow entries, unless an explicit allow entry (a bare path or a directory)
already grants one of the files the command word resolves to: then the entry grants nothing, neither the tool's
files nor the row's helper images, the ask entry constrains nothing, and the entry's line notes "<file> is granted by
exec.allow[<entry>]; <tool> stays unconstrained; this entry adds the ask step and grants nothing", with "<tool> is
constrained by exec.allow[<worded entry>]" in place of "<tool> stays unconstrained" where a worded allow entry names
the tool, and, when the row has helper images that no allow entry grants, "not granted:
<images>; <command> runs them: grant <helper dir>, or allow <tool> bare" (ADR (4)); the set of tools
whose ask entries admit them goes to the index as `IndexOptions.AskAdmits`, empty in a deny-list section; the
reservation warning replaced by the per-entry print line "admits at launch: ...", the line "helpers admitted under
an approval: ..." with the entry's closure where its tool is constrained, and the debugger note),
`pkg/policy/execmatch/index.go` (`constrained` is "not lifted, and an allow pattern names the tool or the tool is in
`AskAdmits`"; `toolRules` keeps each ask pattern's closure beside the allow closures for every constrained tool,
whichever entry constrains it; `Decide`'s ask result gains `Constrained`, whether the tool is constrained, which
decides whether an approval of it records a release (WP3); `Decide`'s unlisted result gains
`AskClosuresOf`, every ask pattern whose closure holds all readings of the unlisted invocation
(a set: git's fetch and push closures share `index-pack`, `rev-list` and the remote helpers), and
`ClosureSubs`, every subcommand of the row whose closure holds all its readings (WP7's `exec.args` releases), so the
supervisor can apply the release rule; allow closures keep precedence), `internal/policy/decide/execcommand.go`
(verdict `ask` with the reading), the Landlock and plane grant builders
(`internal/runtime/enforce/landlock/landlock.go`, `internal/policy/decide/planerows.go`, the fanotify grant in
`internal/runtime/enforce/cgroup/policy.go`),
`internal/cli/compile.go` and `compile_exec.go` (`completion: trace` cells), `pkg/spec/backend/matrix.go` and
`spec/backend/CAPABILITIES.md` (the `exec.ask_trace` row, appended last).

**Change.** ADR (4) and (5)'s precedence. The `/proc` write refusal (`exec-rule` error) for a contract that can ask
about an exec. `exec.unlisted` and `exec.ask_paths` parse and validate here but stay refused until WP7 (`unenforced`
warning naming WP7).

**Tests.** TestExecAskAdmitsToolAtFloor (Landlock grant set, plane rows and fanotify grants contain the ask tool's
files, `#!` chain and loader), TestExecAskConstrainsTool (a restricted section with `ask: [npm install]` refuses
`npm run` as unlisted), TestExecAskDenyListDoesNotConstrain (a deny-list section with only an ask entry for one
subcommand of a tool: that subcommand asks, every other subcommand of the tool runs unasked, and no grant is added),
TestExecAskBareAllowLifts (`allow: [npm]` with `ask: [npm publish]`: only `npm publish` asks),
TestExecAskImplicitGrantDoesNotConstrain (a restricted section whose `mcp[].command` is
`node server.js`, with `ask: [node --inspect]`: `node --inspect` asks with `Constrained` false, every other node
command runs unasked, no closure line is printed, and the grant set is that of the same section without the ask
entry; the same for a `#!` interpreter of the contract's `command`),
TestExecAskPathGrantDoesNotConstrain (`allow: [/usr/bin/git], ask: [git push]` and `allow: [/usr/bin], ask: [git
push]`: `git status` is allowed, `git push` asks with `Constrained` false, the compile note is printed, and the grant
set, the plane rows and the fanotify grants are exactly those of the same section without the ask entry),
TestExecAskPathGrantGrantsNoHelper
(`allow: [/usr/bin], ask: [git push]` grants nothing under `/usr/lib/git-core`, so
`git-remote-http` and `/usr/lib/git-core/git` stay refused at the floor, unasked and inside a release alike, and the
entry's line names them as not granted; with `allow: [/usr/bin/git]` the helper images are the bare path entry's
grant, as ADR 0048 (2) gives, and the ask entry adds none), TestExecAskPartialGrantAddsNoImage (two gits on `PATH`,
only one granted by a directory entry: the other stays refused at the floor and git is unconstrained),
TestExecAskWordedAllowStillConstrains (`allow: [/usr/bin/git, git status], ask: [git push]` and `extends:
base/read-only-git` plus `allow: [/usr/bin, /bin]` and `ask: [git push]`: `git commit` is refused as unlisted, as is
`git log` in the first section; `git push` asks with `Constrained` true; `git pack-objects` decides unlisted with
`AskClosuresOf` holding the push pattern; the ask entry adds no grant, and its line says git is constrained by the
worded entry and prints the helpers admitted under an approval), TestExecAskClosureReported (a
restricted section with `ask: [git push]` and with `extends: base/read-only-git` plus `ask: [git push]`: `git
pack-objects`, `git send-pack`, `git remote-https` and `git-remote-https` decide unlisted with `AskClosuresOf` holding
the push pattern; `git log` decides unlisted with none; with `allow: [git fetch]` also listed, `git rev-list` is allowed
by fetch's allow closure, not reported under push; with `ask: [git fetch, git push]`, `git index-pack` reports both
patterns and `git send-pack` only push's; and `ClosureSubs` of `git send-pack` holds push and not fetch, that of `git
log` nothing), TestExecAskDenyBeatsAsk, TestExecAskOnCommandIsError, TestExecAskIncompatibleModes,
TestExecAskProcWriteRefused (`fs.write: [/]`, `[/proc]`, `[/proc/self]`), TestExecUnlistedMergeStricterWins,
TestExecHoldBounds (0 to `ask.timeout`; above it a `schema` error), TestExecVolatileEnvBounds (32 exact names),
TestCompileTestExecAskCell (`verdict: ask`, `completion: trace` per column, no answer simulated), `TestMatrixGolden`
updated, canonical-form goldens: every existing contract's `contract_hash` unchanged.

**Acceptance.** Compile prints every admission and the helper closure of every ask entry whose tool is constrained
; an ask entry in a deny-list section, for a tool whose file a path or directory allow
entry grants, or for a tool an implicit grant names, constrains no tool and adds no grant, helper images included; a contract with `exec.ask` still refuses every ask match at runtime (the supervisor is unchanged in
this package); goldens hold.

### WP2: broker and CLI

**Files.** `internal/runtime/ask/broker.go` and `socket.go` (hold `exec`; the exec fact fields with bounds in
`validRequest`; the bounded exec summary; `list_v2`, `detail_v2`, `answer_v2`; `client-too-old`; the exec hold cap at
`ceil(max_pending / 2)`; coalescing by exact key, at most 64 waiters per ask, a plain approve releasing only the longest
waiter and re-asking the rest with `follows`, deny, timeout and `--always` answering every waiter; the pass store, at
most 64 live, valid `ask.timeout` after the answer; standing answers keyed on the exact key; the refusal of `--always`
for `agent_writable`; deny-side `--command` patterns compiled with `execmatch` at the ask step), `internal/cli/ask.go`
(the detail view: indexed, injectively quoted argv and environment, secret-looking values as SHA-256 prefixes,
highlighted names first, `agent_writable` on its own line; `deny --always --command`), `internal/check/status/ask.go`
(the `exec` hold; `waiting approval` only for `requester: held`).

**Tests.** TestExecAskRequestBounds, TestExecAskListFits64Maximal (64 maximal exec asks fit the 128 KiB reply),
TestV1ClientOmitsExecAsks, TestV1ClientCannotAnswerExecAsk, TestExecHoldCapLeavesFileAsks (the 33rd exec hold is
`ask-unavailable` while file asks still open), TestExecHoldCapRoundsUp (`max_pending` 1, 2, 3 and 64 give caps 1, 1, 2
and 32; at `max_pending: 1` one exec ask opens, never zero), TestExecAskCoalescesByKey,
TestExecAskApproveOnceReleasesOneWaiter (two coalesced waiters and one plain approve: exactly one released, the other
re-asked under a new `ask_id` with `waiters: 1` and `follows`), TestExecAskDenyAndAlwaysAnswerEveryWaiter,
TestExecAskWaiterCap (the 65th waiter is `ask-unavailable`), TestExecAskListShowsWaiters, TestExecAskKeyDiffersByEach
(image, stamp, chain, argv element boundary, cwd, a non-volatile environment value; a volatile name does not split the
key), TestExecPassOneUse, TestExecPassNeverFromTimeout, TestExecPassExpires, TestExecPassCap,
TestExecAlwaysRefusedAgentWritable, TestExecDenyAlwaysCommandPattern (any reading; acts at the ask step only),
TestExecStandingLedgerOrder (ADR 0054's rules: installed only after the answer line), TestExecAskDisplayInjective
(`["push origin"]` and `["push", "origin"]`, bidi and control characters, invalid bytes),
TestExecAskSecretValuesDigested (display and `--json`).

**Acceptance.** An older CLI still lists and answers file and network asks; no exec ask is answerable without its
facts; one plain approve releases exactly one waiter, whatever the waiter count; the exec hold cap is never 0 for any
valid `max_pending`.

### WP3: the supervisor's trace-gate (the critical path)

**First commit: baselines.** `BenchmarkNotificationRoundTrip` gains exec-ask cases (no match in a run that can ask; a
coalesced join; an approved trace-gated exec with a fake tracer) and records their numbers.

**Files.** New `internal/platform/sys/ptrace.go` (seize, interrupt, detach, kill, waits by pid, `kcmp`), new
`internal/runtime/supervisor/tracegate.go` (the tracer thread, ADR (1) steps 1 to 6, the comparison, the
non-leader and failed-exec handling, `WUNTRACED`), new `internal/runtime/supervisor/exec_ask.go` (facts, exact key,
hold-point choice, parked holds answered later by notification id, the `ID_VALID` ticker, the 2 s same-thread rule,
the `#!/usr/bin/env` continuation, passes and standing answers at the ask step, `ask.exec_hold` release), new
`internal/runtime/supervisor/exec_release.go` (ADR (4)'s releases: a table of at most 256 live entries, each the
released process's tgid and start time, the ask entry and the `ask_id`, added for an approval whose ask verdict has
`Constrained` set (WP1: whichever entry constrains the tool) and whose row has a helper closure,
at the exec stop once the facts compare equal and before the detach, so the program's first helper exec finds it,
and pruned when the process has exited, a failed detach included; for an unlisted result with a non-empty
`AskClosuresOf`, one parent walk over `/proc/<pid>/stat` of at most 16 levels matching pid and start time, then
`ID_VALID`, taking the nearest ancestor's release whose entry is in the set; an empty table answers without a walk; the
outcome, `release_closure` `admitted` or `table_full`, goes on the approved exec's terminal line), edits
to `exec.go` and `exec_commands.go` (the ask verdict goes to `exec_ask.go` instead of the reservation refusal),
`execimage.go` (the walk returns the image's stamp and owner), `read.go` (the environment through `envp` under the
read budget), `notif.go` and `ask_hold.go` (exec holds leave the worker pool), `exec_naming.go` (`AskID`, trace
fields), and `internal/runtime/run_workers.go` (the tracer's lifetime is the run's).

**Tests (unit, with a fake kernel and fake tracer).** TestExecAskHeldAtNotification, TestExecAskVforkHeldAtExecStop,
TestExecAskDenyIsEACCES, TestExecAskDenyAtStopIsSIGKILL, TestExecAskTimeoutRefuses, TestExecAskHoldReleasePending
(`ask.exec_hold` shorter than `ask.timeout`), TestExecAskHoldZeroRefusesAtOnce, TestExecAskRequesterGonePass,
TestExecAskPathCandidateNotAsked (`ENOENT` kept), TestExecAskSameThreadBurst (two `execvp` candidates, one ask),
TestExecAskRestartIsSameWaiter (a withdrawn and restarted notification of one task adds no waiter),
TestExecAskEnvContinuation, TestExecAskLoaderRefused, TestExecAskArgsUnreadable, TestTraceGateMutant* (one per compared
fact: image identity, stamp, each `#!` stage, an argv byte, an argv element boundary, an environment byte, cwd, form;
each must kill), TestTraceGateFailedExecDetaches, TestTraceGateNonLeaderWaitsOnTgid, TestTraceGateSeizeEPERMRefuses,
TestTraceGateUnreadableKills, TestTraceGateOneThread (every ptrace call on the tracer thread),
TestExecHoldParksNoWorker, TestExecReleaseAdmitsDescendantHelper (an approved `git push` release: a child's and a
grandchild-through-`sh`'s `git pack-objects` are allowed with `command_via: closure`, `closure_of` the ask entry and
`release_of` the `ask_id`, and the approved exec's terminal line says `release_closure: admitted`),
TestExecReleaseWordedAllowConstrains (`allow: [/usr/bin/git, git status], ask: [git push]` and
`extends: base/read-only-git` plus `allow: [/usr/bin, /bin]` and `ask: [git push]`, where a worded entry constrains
git and a path or directory entry grants its file: an approved push records a release and its terminal line says
`release_closure: admitted`; a descendant's `git pack-objects` is allowed, `command_via: closure`, `closure_of`
`exec.ask[git push]`, `release_of` the `ask_id`; the agent's own `git pack-objects` and `git send-pack` stay
unlisted; under an earlier rule, which recorded no release there, the descendant's `git pack-objects` was
refused as unlisted and the test fails), TestExecReleaseOverlappingClosures (`ask: [git fetch, git
push]` and an approved fetch: a descendant's `git index-pack`, which lies in both closures, is allowed by the fetch
release, `closure_of` `exec.ask[git fetch]`; with a push release live in the same ancestry the nearest ancestor's
release names it; a descendant's `git send-pack` under the fetch release alone is refused as unlisted),
TestExecReleaseBeforeDetach (a fake tracer whose released program execs a helper at once: the helper finds the release;
a detach that fails leaves no live release once the process is gone), TestExecReleaseRefusesOutsideTree (the same helper
from a sibling of the released process, from a task reparented away from it, after the released process exited, from a
reused pid with another start time, and through a chain deeper than 16: each refused as unlisted),
TestExecReleaseNoReleaseRefuses (no approval yet: `git send-pack` from the agent is refused as unlisted),
TestExecReleaseDenyStillRefuses (`deny: [git gc]` and an approved push: the push's `git gc` is refused),
TestExecReleaseAskStillAsks (a `git push` from a descendant of an approved push opens its own ask),
TestExecReleaseTableFull (the 257th live release admits no helper, its terminal exec line says `release_closure:
table_full`, its answer line carries no closure field, and `run_end`'s `exec_asks.release_table_full` counts it;
under `record: off` the approved exec's line is not written and the counter still is).

**Tests (`-tags integration`, tier landlock, unprivileged, the real listener).** TestIntegrationExecAskApprove (the
ledger reads `ask`, `answer`, one `exec allow` with authority `human` and `argv_facts: verified_trace`),
TestIntegrationExecAskDeny, TestIntegrationExecAskTimeout, TestIntegrationExecAskCoalescedApproveOnceRunsOnce (two
tasks exec the same command, one ask, one plain approve: the command runs exactly once, verified, and the second task
is still held under the follow-up ask until it is answered), TestIntegrationExecAskPosixSpawnNotFrozen (the parent
returns within 1 ms while the child is held), TestIntegrationExecAskArgvRace and TestIntegrationExecAskLinkRace (1000
iterations each, a sibling rewriting argv and a symlink swapped: zero runs of an unapproved fact, every one
`trace_mismatch`), TestIntegrationExecAskFdSwapRace (`execveat` with `AT_EMPTY_PATH`), TestIntegrationExecAskAlways,
TestIntegrationExecAskPassAfterKill, TestIntegrationExecAskApprovedPushCompletes (restricted sections `allow: [sh],
ask: [git push]`, `extends: base/read-only-git` plus `allow: [sh]` and `ask: [git push]`, and `allow: [sh, <the git
on the run's PATH, by path>, git status], ask: [git push]`, where the bare path grants git's helper images (ADR 0048
(2)) and the worded entry constrains git: an approved `git push` to a local bare repository over
`file://`, whose `git-receive-pack` runs through `sh -c`, completes and the bare repository has the commit; where
`git http-backend` is installed, the same over a loopback `http://` server, through `git-remote-http`; no network beyond
loopback; and `git send-pack` run by the agent itself is refused as unlisted),
TestIntegrationExecAskPathGrantGrantsNoHelper (`allow: [/usr/bin, /bin], ask: [git push]`:
`/usr/lib/git-core/git-remote-http` run by the agent is refused at the floor, before any approval and by a child of an
approved push alike, and the approved push's line carries no `release_closure`: git stays unconstrained, so no release
is recorded).

**Acceptance.** Budgets of section 4; the races at zero; an approved `git push` under a constrained git completes
through its helpers, whichever entry constrains git, and the agent's own `git send-pack` stays refused;
`TestExecQuietReadsNoArgv` amended only as ADR 0048 amended it (an exec ask reads what its facts need).

### WP4: the integrity guard and launch checks

**Files.** `internal/runtime/enforce/landlock/filter.go` (in a run that can ask about an exec: errno arms for
`ptrace` with `PTRACE_ATTACH` or `PTRACE_SEIZE` in `args[0]`, for every `process_vm_writev`, and for `clone` with
`CLONE_FS` and without `CLONE_THREAD`, both architectures), its `testdata` filter goldens (new goldens for a run that
can ask; the existing goldens unchanged), the launcher's pre-start check (`internal/runtime`: refuse with exit 125
when a write grant covers a procfs mount point in `/proc/self/mountinfo`), and the Yama check and stage-child seize
that set `exec.ask_trace` in `run_start.capabilities`.

**Tests.** TestFilterExecAskArms (both architectures), TestFilterNoExecAskUnchanged (every existing golden
byte-identical), TestIntegrationExecAskPtraceAttachRefused, TestIntegrationExecAskProcessVMWritevRefused,
TestIntegrationExecAskTracemeThenSeizeRefused, TestIntegrationExecAskCloneFSRefused,
TestIntegrationExecAskProcMemWriteRefused,
TestLaunchRefusesProcfsWriteGrant (a second procfs mounted under a written directory, in the guest),
TestRunStartExecAskTraceCapability (Yama 1 at tier landlock true; Yama 2 at tier landlock false and every exec ask
refused with `completion_unsupported`).

**Acceptance.** The shared-`fs` probe's cases, rerun against a real run, all refused.

### WP5: record and readers

**Files.** `pkg/spec/record` (the optional fields of ADR (8), `argv_facts: verified_trace`, `trace_mismatch`,
`trace_unavailable`, `ask_state`, `count`, `release_of`, `release_closure` (closed: `admitted`, `table_full`,
`readings_disagree`; on the approved exec's terminal line only), an ask entry or `exec.args[<tool>]`
in `closure_of`, `exec_asks` counters with `released_helpers`, `release_table_full` and `release_readings_disagree`
(the approvals that recorded no release, written in every record mode); `RefusedPayload`
additions; one `record_minor` step),
`spec/record/v1/README.md` and its producer table, fixtures under `spec/record/v1/fixtures` (approved, approved with
the release table full (`release_closure: table_full`), a `record: off` run's `run_end` counting that approval in
`release_table_full`, denied at the notification, denied at the exec stop, mismatch, unavailable, pass, standing,
released by `ask.exec_hold`, a helper of a release and a helper of an `exec.args[<tool>]` release, aggregate),
`docs/VERSIONING.md` §2 (the closed-field value rule), the mirror and `last-refusal.json` writer in
`internal/runtime`, `internal/check/status`, `events`, `drift` and `measure` (held time only).

**Tests.** TestRecordExecAskFieldsOptional, TestRecordReleaseClosureClosedSet (a value outside the three, or the field
on an `ask` or `answer` line, fails validation), TestRecordHoldExecOlderReaderFailsClosed (golden output of the previous
minor's status reader), TestLedgerOneLinePerExecAsk (supervisor `ledgertruth`: one terminal line per exec, the plane's
terminal record of a trace-gated attempt consumed), TestRefusedPayloadAskState, TestStatusExecHoldWaiting,
TestMeasureExecHoldTime, TestRecordNoSecretEnvValue (no environment value of a secret-looking name in any line).

**Acceptance.** Every fixture validates against the new `record_minor`, and the previous minor's reader validates
every older fixture unchanged; the previous minor's `tego status` fails closed on a `hold: exec` line (it reports
that run's status as an error, never as an idle run), with `events`, `verify` and the hash chain unaffected; the
`ledgertruth` property holds (one terminal line per exec at every tier, the plane's record of a trace-gated attempt
consumed); no line in any fixture or test ledger carries a secret-looking environment value.

### WP6: the gate's exec ask range

**Files.** `internal/runtime/supervisor/gate.go` (an exec scored into the ask range goes to `exec_ask.go` with the
gate's rule and score; never remembered; a pass delivered only when the passing exec's own re-score is in the ask
range), `pkg/spec/agent/gate_config.go` (the exec gate starts the broker), `pkg/spec/agent/gate_evaluate.go` (the
cell reads `completion: trace`).

**Tests.** TestGateExecAskHolds, TestGateExecAskNeverStanding, TestGateExecPassNeedsAskScore,
TestIntegrationGateExecAskApprove.

**Acceptance.** An exec scored into the gate's ask range runs end to end at tier landlock, unprivileged, through the
hold, the answer and the trace-gate, with the gate's rule and score on the ask line; `approve --always` on it is
refused and no standing answer is installed; a pass is delivered only to an exec whose own re-score is in the ask
range; compile's gate cell reads `completion: trace`.

### WP7: the catch-all

**Files.** The WP1 files for `exec.unlisted` and `exec.ask_paths` (Landlock `EXECUTE|READ_FILE` beneath each path;
ask-only plane rows; the fanotify grant), `exec_ask.go` (rules `exec.args[<tool>]` and `exec.unlisted`), compile's
warning for an `ask_paths` entry at or beneath an `fs.write` entry, and `exec_release.go` with
`pkg/policy/execmatch/index.go` for ADR (4)'s release of an approved `exec.args[<tool>]` exec: the
release records the subcommand every reading of the approved exec agrees on; when they disagree no release is
recorded and no slot of the table taken, and the approved exec's terminal line says `release_closure:
readings_disagree` whether or not the table had room; the release step admits an unlisted
helper whose `ClosureSubs` (WP1) holds a live ancestor release's subcommand, with `closure_of` and `command_rule`
`exec.args[<tool>]` and `release_of` the `ask_id`, through the same parent walk and nearest-ancestor rule as an ask
entry's release. The release answers the command step only: a helper whose image only an `ask_paths` entry admits is
still asked (`exec.unlisted`), and one outside the floor stays refused there.

**Tests.** TestExecUnlistedAskConstrainedTool, TestExecUnlistedAskPathProgram, TestExecUnlistedOutsideAskPathsRefused,
TestExecUnlistedDenyListIsError, TestExecAskPathsUnderWriteWarns, TestIntegrationExecUnlistedAgentWrittenProgram (the
agent writes a program under an `ask_paths` entry that is also written: asked, `agent_writable: true`, `--always`
refused, approve once runs it verified), TestExecReleaseUnlistedAskAdmitsClosure (`allow: [sh, git status]` and
`exec.unlisted: ask`, an approved unlisted `git push`: a descendant's `git pack-objects` runs, `command_via:
closure`, `closure_of: exec.args[git]`, `release_of` the `ask_id`, and the push's line says `release_closure:
admitted`; a descendant's `git log`, outside push's closure, is asked; an approved unlisted exec whose readings
disagree on its subcommand records no release, its helpers are asked, its line says `release_closure:
readings_disagree` and `exec_asks.release_readings_disagree` counts it, and with the table full it says the same and
the live release count is unchanged; a helper whose image only an `ask_paths` entry admits is asked under a live
release),
TestIntegrationExecUnlistedApprovedPushCompletes (tier landlock, the same section: one approval of `git push` to a
local bare repository over `file://` completes through its helpers, `git-receive-pack` through `sh -c` included, with
exactly one ask. `git-receive-pack` passes the floor because it is a link to git in git's helper directory (measured
on Ubuntu 25.10: a symbolic link to `git` in `/usr/lib/git-core`), so the kernel loads `/usr/lib/git-core/git`,
which `git status`'s helper grant admits, and the release admits it at the command step (`receive-pack` lies in
push's closure). The test first checks that the helper
directory's `git-receive-pack` resolves to the inode of its `git`; where it is a copy, a file of its own, it expects
instead the floor refusal ADR (4) gives, the push failing at `git-receive-pack` after its one ask).

**Acceptance.** At tier landlock, unprivileged, an agent-written program under an `ask_paths` entry is asked with
`agent_writable: true`, `--always` on it is refused and approve-once runs it verified; a program outside every grant
and every `ask_paths` entry is refused unasked; `exec.unlisted: ask` in a deny-list section is an `exec-rule` error;
an approved unlisted `git push` completes through its helpers after one ask, and a helper outside its closure is
asked; WP1's `unenforced` warning for the two keys is gone.

### WP8: acceptance

- **Root suites** in the 6.17 guest, both boots (`VM_BPF=yes VM_BOOTS=both`), at C⊘, C+ (LSM and fmod_ret) and B:
  WP3's integration cases, WP4's guard cases and the races at 1000 iterations per tier.
- **Kernel rows**: RHEL 9 5.14 (no `WAIT_KILLABLE_RECV`: a signalled hold rejoins its ask), AL2023 6.1, Ubuntu 24.04
  6.8 and Debian 13 6.12: approve, deny, the races at 200 iterations, a non-leader exec.
- **Agents, offline**: the Claude Code harness (`test/poc/interactive-claude`) with a held command inside the Bash
  tool (interface live), a held direct spawn (held at the exec stop, interface live), a hold past
  `BASH_DEFAULT_TIMEOUT_MS`, a denial at each hold point (what the model is told); the Codex harness, the same where
  it applies.
- **Conformance** (ADR 0017): exec ask cells at every axis read `ask` with `completion: trace`, or `refused` with
  `completion_unsupported` where `exec.ask_trace` is false.
- **Perf**: section 4's table, with `-benchmem` before and after for the notification path.

**Acceptance.** Every case above passes on every row it names, with zero unapproved runs in every race cell; a kernel
row where the trace-gate cannot run shows `exec.ask_trace: false` and refuses every exec ask, never runs one
unverified; the results are written in `test/vm/README.md`.

### WP9: operator documents and rows

`docs/OPERATIONS.md` gains "Approving a command": the flow, the facts shown, what `agent_writable` and `requester:
gone` mean, `ask.exec_hold`, the debugger note, the tiers (`exec.ask_trace` in `run_start`), and that Claude Code in
`--permission-mode default` asks its own question first. FEATURES W8 and E76, GAPS, CAPABILITIES and the CHANGELOG
are updated; ADR 0044 gets its implementation note and Status.

**Acceptance.** `go run ./tools/rulecheck` and `make lint` pass; every claim in the new operator section names the
WP8 result it rests on; ADR 0044's Status says what is built and what is not.

### WP10: `exec.assurance: verified`

**Files.** `pkg/spec/agent` (the new value; refuses the run when `exec.ask_trace` is false), the supervisor (every exec
a command rule or the exec gate allows goes through the trace-gate; the integrity guard is on for such runs),
`pkg/spec/agent/best_effort.go` (`exec.rules/argv` and `gate.exec` leave `best_effort` under it), compile's print and
the capability row's note.

**Tests.** TestExecAssuranceVerifiedTracesAllowed, TestExecAssuranceVerifiedRefusesWithoutTrace,
TestExecAssuranceVerifiedLeavesBestEffort, the races of WP3 against a command-rule allow, and the section 4 budget.

**Acceptance.** With `exec.assurance: verified`, WP3's argv, link and descriptor races run against a command-rule
allow and a gate allow are at zero (every one `trace_mismatch`) at every tier in the guest; the run is refused before
the child starts (exit 125) where `exec.ask_trace` is false; `exec.rules/argv` and `gate.exec` are absent from
`best_effort` under it and unchanged without it; the per-exec cost is within section 4's budget and unguarded execs
show no change in `-benchmem`.

## 6. Risks and stop conditions

- **The tracer and the launcher's waiters.** The highest risk. WP0 settles it before WP3; the fallback refuses the one
  case that cannot be made safe (the agent's main process), never weakens the gate.
- **A comparison bug runs an unapproved exec.** Mitigated by the one-mutant-per-fact rule, and the race cells.
- **Agents behave differently under long holds.** Measured for Claude Code only; WP0's Codex run may change the
  operator advice, not the design (`ask.exec_hold` already covers short holds).
- **Kernel rows without ptrace for the unprivileged supervisor** (Yama 2): exec asks refuse there by design; WP8
  records which rows those are.

## 7. Documents each package amends

| Package | Documents |
|---|---|
| WP1 | SEMANTICS §1, §3, §4 (command rules), §6; `docs/p0/agent-contract.md` (consumed set, the new keys); CAPABILITIES; FEATURES E76 |
| WP2 | SEMANTICS §6; `docs/p0/limits-check-doctor-cli.md` (the `ask` commands, `--command`, `client-too-old`) |
| WP3 | `docs/p0/supervisor.md` (a new rule for exec asks and the trace-gate, the read budget rule, the worker rule); SEMANTICS §4, §6; ADR 0008 and 0041 implementation notes |
| WP4 | `docs/p0/enforce-landlock.md` (the filter arms); `docs/p0/runtime-launch.md` (the procfs check, the capability check) |
| WP5 | `spec/record/v1/README.md`; `docs/p0/record-ledger.md`; `docs/VERSIONING.md` §2; REASON-CHANNEL (the `ask_state` field, no new code) |
| WP6 | `docs/p0/gate.md` (the ask range row); SEMANTICS §6 |
| WP7 | SEMANTICS §1, §4; `docs/p0/agent-contract.md` |
| WP8 | `test/vm/README.md` results; ADR 0044's implementation note |
| WP9 | `docs/OPERATIONS.md`; FEATURES W8; GAPS; CAPABILITIES; `docs/CHANGELOG.md` |
| WP10 | SEMANTICS §4; `docs/p0/agent-contract.md`; ADR 0048 and 0041 notes |

