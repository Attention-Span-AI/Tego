# ADR 0073: run_start records who launched the run, on which host, and the identity its caller gave it; a Started hook runs before the agent is released

Status: **accepted 2026-10-25**; implemented 2026-10-25: D1 to D5. Refines
spec/record/v1 (record_minor 17, `MinorRunIdentity`), record-ledger.md §2.2, runtime-launch.md §4.1 (steps 9 and
9a), agent-contract.md R5 and R28 (new), spec/identity/RUN-IDENTITY.md.

## Context

A ledger said what a run did, under which contract and binary, but not who started it or where. `launcher_pid` named a
process that is gone after the run; nothing named the account, and under `sudo` the account that matters (the person
who typed `sudo tego run`) was invisible behind uid 0. A ledger copied off a machine named no host. `TEGO_PARENT_RUN`
was passed to the child (identity env) and never recorded, so a nested run could not be joined to its parent from the
ledger. The later packages that build on the record need
these facts fixed, with their names and types, before they can rely on them: labels a caller attaches to a run, a role
that tells a checking command's run from the agent's own, and the contract author's name for the version of the file that
ran. And the run interface needs one point where the run id and its directory exist and the agent has not run yet, to
print or hand off the id before anything the agent does can race it.

These facts must be written by the launcher on the hash-chained `run_start`: a field the agent or a later reader
supplies is a claim about the run, not a record of it.

## Decision

**D1. The identity is part of `run_start` (record minor 17).** `run_start` gains, additively within v1:

| Key | Type | Written |
|---|---|---|
| `launcher_uid` | integer | on every `run_start` at minor 17 or later, 0 included (a pointer in Go, so 0 is written); the real uid as the launcher's user namespace numbers it |
| `launcher_user` | string | `launcher_uid`'s passwd name (`config.LookupPasswd`, never `$USER`); absent when none, or when it is not UTF-8 or breaks `host`'s character rule |
| `sudo_uid` | integer | only when the launcher's real and effective uid are 0 in the initial user namespace (not under `unshare -r`, ADR 0042 (5)(d)) and the launcher process's own `SUDO_UID` is the decimal of a uid other than `4294967295`, read as identity-config E8 and the launcher's drop reads it (`config.InvokingUID`: the process's `SUDO_UID`, never `Deps.Environ`, the agent's environment template an embedder may fill from its caller), so the record names the account the agent is dropped to |
| `sudo_user` | string | `sudo_uid`'s passwd name, never the `SUDO_USER` string; absent when none |
| `host` | string | the kernel nodename (`os.Hostname`, `/proc/sys/kernel/hostname`), at most 255 bytes of UTF-8 with no control (Cc), format (Cf), line or paragraph separator character (D2's label value rule: the nodename is whoever holds the UTS namespace's to set, an unprivileged user in its own user and UTS namespace included); absent when unreadable or when it breaks that rule |
| `parent_run` | string | the valid run id of `Deps.ParentRun` (D3: for `tego run`, the enclosing run's `TEGO_RUN_ID`, else `TEGO_PARENT_RUN`); absent when none |
| `labels` | object | the caller's labels (D2); absent when none |
| `role` | string | reserved: `check` marks a run a checking command started, and no shipped command sets it; absent for the agent's own run |
| `contract_revision` | string | the contract's `revision` (D5); absent when none |

`pkg/spec/identity.LauncherOf(uid, euid, passwd, environ, hostname)` computes the first five, pure and table-tested, in
the Layer 0 leaf; the runtime's one filler (`fillRunIdentity`) calls it with the process's real uid, its effective uid
under the drop's gate (a non-zero real uid or a child user namespace is passed as no root), the passwd lookup, the
launcher process's own environment (`os.Environ`) and `os.Hostname`, for a run and an adoption alike. Each value is what the
launcher read when the run started and none is a verified fact about a person: `sudo_uid` is sudo's claim, which any
root process can set; a reader shows it as "via sudo from", never as an authenticated identity. `host` and `role` are
`run_start` payload keys, as `host` already is of `net` and `ssl_request`, never common fields.

The revision is the lowest free number at
merge, and 17 was free at merge (ADR 0070's host sockets took 16 first), so `MinorRunIdentity` is 17 and the
numbers have no gap. A gap would be a ledger lie: a
ledger at revision N promises every lower revision's fields, so a reader would take a later package's absent field
(held reads, deny-write, host sockets) for "the run had none" in a ledger whose writer never knew it.
`TestRecordMinorsHaveNoGap` checks that the `Minor*` constants are exactly 1 to the highest and that `record.Minor`
is the highest; the packages that reserved 16 to 19 take the next free numbers when they merge.

**D2. Labels, role and parent are checked before the run exists.** `Deps.Labels` (map), `Deps.Role`
(`identity.Role`) and the existing `Deps.ParentRun` are checked in `newRunner`, before `mintRun` makes the run
directory: a non-empty parent run that is not a run id, labels `identity.ValidLabels` refuses, or a role this version
does not know (only `""` and `check`) are `ErrDeps`, exit 125, and nothing of the run exists. Labels: at most 32; key
`^[a-z0-9][a-z0-9._-]{0,62}$`, the `tego.` prefix reserved; value at most 256 bytes of valid UTF-8 with no control
(Cc), format (Cf), line or paragraph separator character, so a value can neither break a view's line nor reorder or hide
what is printed beside it (the separators are added to the two classes, for the same reason). No
shipped command sets labels or a role: both are reserved.

**D3. `parent_run` is a claim until nested runs.** The launcher records what its environment said; it does not check
that the parent run exists, is live, or is an ancestor of this process. A reader joins runs on it as a declared link.
nested runs (later) verifies it (the parent's cgroup contains the launcher) and says so in its own field; until then
documentation calls it the environment's claim. `tego run` takes it from the enclosing run's `TEGO_RUN_ID` when its
environment has one, else from `TEGO_PARENT_RUN` (`parentRunFrom`): inside a governed agent the identity set gives
`TEGO_PARENT_RUN` the inherited value, the enclosing run's own parent, so reading it there would record the
grandparent, and a run started in another with no parent would record none. The enclosing run is also the run whose
cgroup holds the nested launcher, the link nested runs checks. An orchestrator with no run around it hands the parent
as `TEGO_PARENT_RUN`, on this host or another. The agent's own `TEGO_PARENT_RUN` stays `Deps.ParentRun`, its run's
parent, as RUN-IDENTITY.md has it.

**D4. The Started hook.** `Deps.Started func(StartedRun{ID, Dir}) error` is called exactly once per run, in `run()`,
after `run_start` is durable and after `emitPostStartGaps` has queued every post-`run_start` gap (one ordered list,
`postStartGaps`, so a gap a package adds is a row there and still precedes the hook), and before the group check and
the child's `Ack` (runtime-launch.md §4.1 step 9a). It is the one point where the run id and its directory exist and
the agent has not run. Fail closed: an error ends the run as a failed ack does: the child is killed before it execs,
`run_end reason=error` with `detail` `started hook: <error>` (cut to `record.MaxDetailBytes`, ending
` [cut N bytes]`, so the hook's error cannot make `run_end` longer than a ledger line), exit 125. A panic is not
recovered (runtime-launch R14):
it ends the launcher before the Ack, so the child stage never execs the agent (ADR 0020) and the sweep closes the run.
nil changes nothing. An adoption calls no Started hook: its process is already running. The
gaps are queued, not yet durable, when the hook runs; only `run_start` is guaranteed on disk.

**D5. The contract key `revision`.** Optional, a YAML string (an unquoted number or boolean, and a null value, are
`[schema]` errors, as the JSON Schema's `{"type": "string"}` refuses them), `^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`, merge class
`refused-in-profile` (ADR 0065's first such row): it names the top-level file, so a profile's would name another file's.
It is part of the canonical bytes (a contract without one keeps its bytes and hash), kept in the run directory's
contract copy, printed by `tego compile` (a `revision` line under `hash`, and `revision` in `--json`) and written as
`run_start.contract_revision`. tego never orders revisions; `contract_hash` remains what says two contracts are the same.
Built-in presets never carry one (asserted by the presets).

**Compact per-line stamps** (a short host or launcher tag on every line, for joining lines across ledgers) are not
here, and none ships.

## Rejected

- *Common fields on every line* (`host`, `uid` beside `run`): the record's common set is closed in v1 (adding one is a
  v2 change, VERSIONING §2), the values cannot change within a run, and `run_start` is hash-chained to every line, so
  the first line says it for all of them.
- *Recording `SUDO_USER` as given*: any string in the environment, not a passwd name; `SUDO_UID` resolved through
  passwd is the same fact with one fewer place to forge it.
- *Recording `SUDO_UID` whatever the euid*: an unprivileged launcher's environment can carry any `SUDO_UID`; only a
  root launcher was plausibly started by sudo.
- *Cutting a long nodename to 255 bytes*: a cut can split a character and names another host; absent says "unknown".
  So for a nodename holding a control or format character: escaping or stripping it would record another name.
- *`parent_run` from `TEGO_PARENT_RUN` alone*: a nested run would record its enclosing run's parent, and read as that
  run's sibling. *Setting the agent's `TEGO_PARENT_RUN` to its own run id instead*: the same join, but it changes the
  identity variables other tools key on (RUN-IDENTITY.md), which is not this ADR's to change.
- *Refusing a bad `TEGO_PARENT_RUN` in the CLI only*: the runtime is the engine every launcher goes through, so the
  check lives in `newRunner`, and the CLI reports its `ErrDeps`.
- *A `Started` hook after `Ack`*: the agent would race whatever the caller does with the id.
- *Recovering a panic in the hook into a run_end*: R14 keeps every panic in the launcher fatal (no `recover()` in the
  package family, `TestRunInstallsNoRecover`); the agent is still never released, since only the Ack releases it.
- *Ignoring a hook's error*: a caller that could not note the run (write the id where a supervisor reads it) would be
  running an agent it cannot account for; fail closed.
- *A merge class `own` for `revision`*: `own` silently drops a profile's value; a profile that names a revision is a
  mistake worth a `[schema]` error.

## Consequences

- Every run at minor 17 or later names its launcher's uid and host; a ledger is attributable without the machine.
- A run started with a malformed `TEGO_PARENT_RUN` (or, inside a governed agent, `TEGO_RUN_ID`) in its environment
  is now refused (exit 125) where it used to pass the value to the agent unrecorded.
- Whatever later sets labels or a role, or adds per-line stamps, builds on fixed names and types; none of it ships.

## Implementation notes

- 2026-10-25: `pkg/spec/identity/launcher.go` (`Launcher`, `LauncherOf`, `ValidLabels`, `Role`),
  `record.MinorRunIdentity` and the `RunStartPayload` fields, `fillRunIdentity` in `run_ledger.go` (used by
  `adopt_start.go` too), `validIdentity`, `postStartGaps`/`emitPostStartGaps` and `notifyStarted` in `run.go`,
  `Contract.Revision` with its schema entry, JSON Schema property and merge row, compile's `revision` line (in
  `pkg/spec/agent/print.go`'s header, beside `hash`, rather than an added line in `compile.go`: the header is where
  the table's contract lines are printed) and `--json` key. Fixture `spec/record/v1/fixtures/run-identity.jsonl`
  (`internal/ledger` `TestFixturesFrozen`), replayed through every view (`test/fixtures`). Tests:
  `TestLauncherOf`, `TestValidLabels`, `TestRoles`, `TestRecordMinorCoversTheRunIdentity`,
  `TestReadmeNamesTheRunIdentityMinor`, `TestRunIdentityFixture`, `TestRunRefusesABadIdentityBeforeTheRunExists`,
  `TestRunStartCarriesTheRunIdentity`, `TestIntegrationStartedRunsOnceBetweenRunStartAndTheAgent`,
  `TestIntegrationStartedErrorEndsTheRunBeforeTheAgent`, `TestRevisionIsTheContractsOwn`,
  `TestRevisionIsRefusedInAProfile`, `TestRevisionIsInTheCanonicalBytes`, `TestRevisionIsShownAndKept`.
- 2026-10-25: `SUDO_UID` is read as identity-config E8 and the launcher's drop read it (an
  unsigned 32-bit decimal other than `4294967295`), and only for root of the initial user namespace (ADR 0042
  (5)(d)): under `unshare -r` no `sudo_uid` is recorded, as no drop is made to it. The root arm,
  `TestRootRunStartNamesTheSudoAccount` (root-must-pass), passed in the KVM guest on 6.17 under both boots
  (lsm=…,bpf and the default LSM list): `sudo tego run --tier cgroup` recorded `launcher_uid` 0 with the invoking
  account's `sudo_uid` and `sudo_user`, the same contract run by that account at tier landlock its own uid and no
  `sudo_uid`, and both `host` equal to `uname -n`.
- 2026-10-25: `fillRunIdentity` read `SUDO_UID` from `Deps.Environ` when it was set, the agent's
  environment template, while the drop reads the launcher process's own (`os.Getenv` in `config.InvokingUID`), and
  gated it on the euid alone where the drop's gate is the real uid. An embedder passing its caller's environment
  would have recorded the caller's `sudo_uid`, on the hash-chained `run_start`, while the agent was dropped to another
  account. It now passes `os.Environ()` and the drop's gate (`launcherCreds`; `TestRunStartReadsSudoFromTheLauncherProcess`).
- 2026-10-25: `host` takes the label value's character rule (`viewUnsafe`, shared by `hostOf` and
  `validLabelValue`); a nodename with ESC, CR, LF, U+202E or U+2028 was recorded as it was (`TestLauncherOf` rows).
  So do `launcher_user` and `sudo_user`, with valid UTF-8: the passwd database is the mount namespace's, which a user
  in its own user and mount namespace can replace. A value that breaks the rule is absent, never cleaned.
- 2026-10-25: a Started hook error of 3 MiB made `run_end` longer than the ledger's `MaxLineBytes`:
  the write was refused, the run had no `run_end` and its live entry was cleared. Every `run_end.detail` a launcher or
  an adoption's reaper writes is now cut by `record.CutDetail` to `MaxDetailBytes` (4096) with a ` [cut N bytes]`
  marker (`TestCutDetail`, the over-bound row of `TestIntegrationStartedErrorEndsTheRunBeforeTheAgent`; the
  adoption's two sinks are cut the same way, `TestAdoptionEndCutsALongDetail` over both of `end`'s arms that carry a caller's
  text and `TestReleaseOrphanCutsALongDetail`, each red with its cut removed). The hook,
  the group check and the Ack moved into `releaseAgent` over an `agentGate` (`*launch.Child`), so the order is tested
  on fakes: `TestReleaseAgentRunsStartedBeforeTheGroupCheckAndTheAck` (fails when the hook moves after the Ack or
  after the group check) and `TestReleaseAgentLeavesAStartedPanicUnrecovered`.
- 2026-10-25: `revision:` with no value, `~` or `null` loaded as no revision, and `revision: 1.50`
  (a float to YAML, refused by agent.schema.json) loaded as the text `1.50`. The schema walk now marks `revision`
  `nullRefused` and `text` (a plain scalar YAML resolves to anything but `!!str` is refused with the fix to quote
  it), and so `name` and `mcp[].name`, whose all-digit spelling had the same mismatch (`TestRevisionIsAYAMLString`,
  `TestNamesAreYAMLStrings`). `command` items and `env.set` values (`command: [sleep, 5]`, `DEBUG: 1`) keep Go's
  reading: refusing those common spellings is a separate decision about which side of the agreement moves.
- 2026-10-25: `tego run` read `Deps.ParentRun` from `TEGO_PARENT_RUN` alone, which inside a governed
  agent is the enclosing run's own parent, so a nested run recorded its grandparent, or none, and read as its
  enclosing run's sibling. It now reads the enclosing run's `TEGO_RUN_ID` first (D3, `parentRunFrom`,
  `TestParentRunIsTheEnclosingRun` over environments built by `identity.Env.Apply`). The nested agent's own
  `TEGO_PARENT_RUN` is `Deps.ParentRun` too, so it changed with it, to the enclosing run (an earlier
  note said it was unchanged; spec/identity/RUN-IDENTITY.md and the CHANGELOG now say so,
  `TestTheAgentsParentRunIsDepsParentRun`).
- 2026-10-25: after these fixes `TestRootRunStartNamesTheSudoAccount` passed again in the KVM guest
  on 6.17, both boots (lsm=…,bpf and the default list), plain and `tegobpf` builds: the drop's gate and the process's
  own `SUDO_UID` record the invoking account under real `sudo`.
- 2026-10-25: ADR 0070's host sockets reached the branch first and took
  record minor 16 (`MinorHostSockets`), so `MinorRunIdentity` is 17 and `record.Minor` is `MinorRunIdentity`, the
  lowest free revision at merge as D1's rule says. The run identity fixture (`run-identity.jsonl` and its chain log)
  was regenerated at 17 with `TestFixturesFrozen -update`; `TestRecordMinorsHaveNoGap` holds 1 to 17.
