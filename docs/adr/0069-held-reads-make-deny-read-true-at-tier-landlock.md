# ADR 0069: held reads make a deny_read inside a write entry true at tier landlock

Status: **accepted 2026-10-24**; implemented 2026-10-24: D1 to D6, verified
2026-10-25 (KVM: AL2023 6.1 and the host row). Rule (b) of D3, the targets' identities pinned at launch, and
D5's created-then-moved residual are not built (GAPS A11). Amends ADR 0041 D4's one re-pin
(the 2026-10-25 note). Builds on ADR 0041 Stage B (held completion) and ADR 0043 (name entries); refines
SEMANTICS §1, §2 and §7, supervisor.md R15 and R22, enforce-landlock R10 and R16, agent-contract R5 and R6,
CAPABILITIES (three rows) and spec/record/v1 (record_minor 18).

## Context

Landlock unions the rights of every rule on a path. A `deny_read` target that lies at or beneath a write entry,
`./.env` under `fs.write: ["./"]`, is therefore readable at tier landlock: the write entry's rule grants `READ_FILE`
over its whole subtree, and no second rule can take it away (SEMANTICS §2, enforce-landlock R4). Until now compile
warned `unenforced`, the record carried the gap, and the root tiers alone refused the read. The commonest contract
shape, a repository the agent writes with a `.env` in it, was exactly the one the unprivileged tier could not
protect; and a `.env.local` made during the run, which no ruleset row names, was readable at every tier.

ADR 0041 Stage B built the one race-free primitive the tier has: the **open deputy**, a process of the run's own
Landlock domain and cgroup, pins what the task's lookup reaches, the supervisor checks the pinned object, the deputy
opens it with the task's flags and the descriptor, verified to be the pinned inode, is delivered with
`SECCOMP_IOCTL_NOTIF_ADDFD|SEND`. Its held opens matched the kernel's own answers over 395 open shapes
(`TestHeldOpenDifferential`, the conformance `-held` variants). It shipped as the opt-in `gate.completion: held`
for gate opens; this ADR uses it for reads.

## Decision

**D1: `fs.reads: auto | held | direct`.** `auto`, the default, holds the run's read opens at tier landlock exactly
when a `deny_read` target lies at or beneath a write entry: a declared entry, a file a declared glob expanded to, a
built-in entry, or a `.env` the scan found (`RuleTable.Reads.Nested`). `held` holds them at every enforcing tier,
so a file a deny_read name rule covers is refused whenever it was made. `direct` never holds: a nested target stays
`unenforced (landlock: parent writable)`, warned and recorded, as before this ADR. Records-only runs (`tego watch`,
`--observe`) never hold. The merge class is `stricter`, `held` over `auto` over `direct`, `direct` loosening (ADR
0065): only the top-level contract's `direct` counts, and a profile's is ignored with `profile-cannot-loosen`.
Compile prints which reads are held and why, with the cost ("each read open about 0.1 ms more"), and warns
`held-reads` at each nested target; `compile --test` answers a nested deny_read at landlock refused when reads are
held (decide's held-read floor, D3); `--json` carries `reads`.

**D2: every read-capable open is held.** While reads are held the seccomp filter notifies every open (the arm
`record: full` and `fs.ask_read` already use, set through `filterOpts`), and the supervisor completes every
read-capable open (`O_RDONLY`, `O_RDWR`, a directory, `O_CREAT` with read access) through the deputy exactly as
`gate.completion: held` completes one: pin, object class (ADR 0041 D4), floors (D3 below), the deputy's open in
the run, identity check, `ADDFD|SEND`. No gate is needed. `O_WRONLY` and `O_PATH` opens stay as they were: an
`O_WRONLY` open reads nothing, and an `O_PATH` descriptor reads nothing either (every read through one is another
open, held; `ADDFD` cannot deliver one). `uselib(2)`, which opens a file by a pathname no arm of the filter sees, is
answered `ENOSYS` at every tier on x86_64, as `openat2` and `open_by_handle_at` are. *Amended 2026-10-25:*
`fs.reads: held` is refused with `io_uring: true` at compile, as `gate` and `ask` are: a ring's `IORING_OP_OPENAT`
never passes the filter, and a root tier's plane admits io_uring for such a contract, so the held floor would never
see it. `auto` holds only at tier landlock, where io_uring stays `ENOSYS` whatever the contract says. *Amended
2026-10-25:* `fs.reads: held` is refused with `setuid: true` too, as `gate` and `ask` are: the deputy
completes every read with the credentials it was exec'd with, which is right only while no task of the run can change
its own (ADR 0041's notes), and `setuid: true` leaves `no_new_privs` unset at a root tier, so a setuid program's
read would be answered as the agent's. `auto` needs no check: tier landlock sets `no_new_privs` whatever the contract
says.

**D3: the floor, on the object reached.** A held read is refused `read_denied`, naming the entry, when the pinned
object

- (a) lies at or beneath a deny_read entry's resolved path, nested in a write entry or not, that is the nearest
  entry deciding a read there (a write entry nested inside a deny_read still reopens its own subtree, SEMANTICS §2);
  opening a nested deny_read directory itself is refused, so its file names stop showing at tier landlock;
- (b) is one of the nested targets by identity pinned at launch, under another name;
- (c) has a final name a deny_read name rule covers in its scope, whether or not it existed at compile: a
  `RuleTable.DenyReadPatterns` entry the table's deny_read entries stand for (a declared glob; the built-in home
  paths while the built-in list is on), at the object or an ancestor no nearer write entry lies beneath (as in (a),
  a write entry inside such a tree reopens its own subtree; amended 2026-10-25), ASCII folded too; or, for a file,
  the built-in `.env` names (`.env`, `.env.<x>` but the example files) ASCII folded, beneath the `.env` scan's roots
  and outside ADR 0043 F3's dependency directories, less ADR 0043 D3's exemptions;
- (d) lies in tego's own state (`RuleTable.OwnState`, the runtime parent), except beneath the run's own runtime
  directory (its reason file, its `CODEX_HOME`) and beneath a write entry nearer than that state.

The floor is `decide.HeldReadIndex.Refusal` for (a) and (c), one function the supervisor and `Evaluate` share (ADR
0028), plus the supervisor's (d). It is added to the copied path's floor (`heldFloors`); the comment there that said
a nested deny_read refuses nothing is replaced.

**D4: the record.** Allowed held reads follow the record mode: no line under `summary` or `off` unless a read gate
scores them (`heldQuiet`, as `quietRead` keeps `fs.ask_read` runs). Every refusal has its line, rule and authority
(`rule`), and reaches the reason file through the ordinary refusal path. `run_start.fs_reads` is
`{"reads": "held"|"direct", "why": ..., "nested": [rules]}` on every run at `record_minor` 18
(`record.MinorHeldReads`). The run's capability line sets the new rows `fs.deny_read.nested` and
`fs.deny_read.created_later` (and `fs.deny_read`) true only where the run holds its reads and its deputy serves the
supervisor; `fs.deny_read.moved` is false at landlock. *Amended 2026-10-25:* so does an open the
filter notifies only because reads are held and that held reads leave as it was, an `O_PATH` open (D2): under
`summary` or `off` it has no line unless it is refused or a read gate scores it (`quietRead` now covers held runs as
it covers `fs.ask_read` ones), beneath a `deny_read` or not. It reads nothing, and no tier's recorder sees one, so a
`summary` run kept no line of it before held reads either; under `full` its line is kept.

**D5: what held reads do not catch (stated residuals).**

1. A nested target renamed or hard-linked to another name inside the write entry, then read by that name: the floor
   checks the object's path and name, not its identity. `fs.deny_read.moved` is false at landlock, and compile's
   warning says so, until the targets' identities are pinned at launch.
2. A target written or replaced during the run by a process outside the run, then moved by the agent before it
   reads it.
3. ADR 0041 Stage B's disclosed residual: D2's LSM label check is not built.
4. Opens of device files outside the mem and tty classes are refused `held-unsupported` while reads are held (ADR
   0041 D4: the deputy's open would act in its own context); a GPU or other device the agent reads needs
   `fs.reads: direct` or a root tier.

**D6: the deputy is required.** A run that holds its reads starts the deputy with its runtime exec grant
(`RuleTable.NeedsOpenDeputy`), and its processes make no Landlock domain of their own (`landlock_*` answer
`ENOSYS`, enforce-landlock R10). A deputy that does not start refuses the run before `run_start`, exit 125
(`ErrHeldReadsUnavailable`): held reads are what makes the target hold, so the gate's degrade (best effort,
disclosed) is not available to them. `fs.reads: direct` runs such a contract with the target unenforced.
`fs.ask_read` beneath a write entry stays refused at compile (ADR 0057 D3).

## Rejected options

1. **A second Landlock layer withholding `READ_FILE` beside the target**, with the deputy completing new files.
   Exec needs `READ_FILE` (the kernel opens a program `O_RDONLY|__FMODE_EXEC`), so a binary, a
   `node_modules/.bin` script or a fresh `target/` build made during the run beside the target could not run.
2. **Continuing the open on the copied path** once the copied name passes: a sibling thread that rewrites the
   pathname after the check, or a symlink swapped between two targets, makes the kernel open the secret
   (`TestHeldReadsRaceIsDecidedOnThePin`; ADR 0041's own race test reached the secret 390 times in 3,200 so).
3. **A single-thread fast path** that continues opens of a task with no sibling: agents are multi-threaded (Node,
   Python with threads, Go), the check is itself racy against `clone`, and a `vfork` child shares the memory.
4. **Refusing such contracts at compile**: every repository with a `.env` and `fs.write: ["./"]` would stop
   compiling; held reads make the contract true instead, and `direct` keeps the old behaviour for those who choose it.
5. **Holding reads on every tier-landlock run**: the cost (Performance) would be paid where nothing is nested; `auto` pays it only
   where the hole exists or the contract asks.

## Performance

The cost per held read is ADR 0041 §Performance's held completion: two cross-process wakeups (the deputy's and the
worker's), the deputy's lookup and reopen, and the pinned path's identity, about 0.1 ms over the gated path's round
trip on a quiet host. `BenchmarkHeldReadOpen` reports it at tier landlock with p99 against supervisor R22's 200 µs
soft ceiling; docs/OPERATIONS.md "Cost per open" gives `grep -r` over 10,000 files, held against direct.

Measured 2026-10-24/25 (6.17, 16 CPUs): `BenchmarkHeldReadOpen` held p50 52 µs, p99 77 µs (R22's 200 µs met; no
TARGET-MISS), the notified-and-continued path's p50 32 µs; `grep -r` (ugrep 7.8, multi-threaded) over 10,000 small
files through the real binary, seven alternated runs at load 2 to 4: 605 ms held, 35 ms `fs.reads: direct` (medians),
about 57 µs more per open, 10 of 10,170 notifications over 200 µs. The 0.1 ms compile states is the rounded bound.

## Implementation notes

*2026-10-24 (built):*
- **Compile (Layer 0).** `FSSection.Reads`, the schema's `fs.reads`, the merge row; `compile_heldreads.go`
  (`RuleTable.Reads`: the effective value, the nested targets, the patterns and the built-in `.env` names a held read
  is refused by; `ReadsHeldAt`, `ReadsWhy`); `compile_fs.go`'s `unenforced` keeps the covering write entry and no
  longer warns itself; `heldReadsDiagnostics` warns `held-reads` or, under `direct`, the old `unenforced` text.
  `NeedsOpenDeputy` is `gate.completion: held`'s escalating gate or held reads; the gate's best-effort cells still
  follow the gate's own key (`GateOpensHeld`). Departure from the first design: `FSRule.Unenforced` stays true for a
  nested target, since it is the Landlock ruleset's fact (I5 compares it with the backend's plan), and held reads
  are a layer above it, not a change to it.
- **Decision core.** `decide.HeldReadIndex` (literal patterns in a folded set, globs matched, the names climbed);
  `Evaluate` and the indexed `Evaluator` put a read the tier allows to it where the table holds reads at that tier;
  `decide.LandlockRuleset` is the ruleset alone, which the supervisor's `listenerRefuses` and the kernel recorder's
  `listenerRefused` ask (they mean the inherited ruleset, not the tier).
- **Supervisor.** `held_reads.go` (`readCapable`, `readHeld`, `heldReadFloors`, `heldOwnState`, `heldQuiet`);
  `heldOpen` and `heldDirect` hold an open when the gate holds it or the run holds its reads; an open the gate does
  not score carries no gate decision; `Options.RuntimeDir`.
- **Landlock backend.** `filterOpts.askRead` is also set when reads are held (no change to `buildFilter`'s body);
  `uselib` (134) joins x86_64's ENOSYS set; the filter goldens are regenerated.
- **Runtime.** The deputy starts for held reads; `deputyUnavailable` refuses the run then (D6); `run_start.fs_reads`;
  the capability lines; `emitWatchedReadGap` no longer counts deny_read entries for a run whose refusals are recorded.
- **Tests that fail without it.** `TestHeldReadsTriggerPerTargetKind`, `TestHeldReadsValues`, `TestHeldReadsMergeOrder`,
  `TestHeldReadsPrint`, `TestHeldReadsNameRules` (agent); `TestHeldReadRefusal`, `TestEvaluateHeldReads` (decide);
  `TestHeldReadFloorsOnThePinnedObject`, `TestHeldReadsRaceIsDecidedOnThePin`, `TestHeldReadsRefuseTegosOwnState`,
  `TestHeldReadsLeaveWriteOnlyAndOPathOpens` (supervisor); `TestHeldReadsNotifyEveryOpen`, `TestUselibIsAbsent`
  (landlock); the conformance cells `fs/read-deny-read-nested-in-write` (landlock now refused),
  `fs/create-env-later` and `fs/read-env-created-later`, `filesystem/nested-denied-read`.

*2026-10-25 (built):*
- **Through the real binary.** `TestIntegrationHeldReadsAtLandlock` (internal/runtime): with `fs.write ["./out/"]`
  and an `out/.env` the scan finds, `cat`, python's `open`, `grep -r`, `cp`, `tar`, `ln -s` then `cat` and
  `cat /proc/self/cwd/out/.env` are each refused (seven `read-denied` lines by the nested entry), `out/src/a.txt`
  reads with no line under `record: summary`, a `.env.local` a process outside the run makes during it is refused by
  the name rule, the reason file read inside the run names the refusal, and `run_start` says held/nested with the
  capability rows; under `held` with nothing nested the late `.env.local` is refused (`contract`); under `direct` the
  nested `.env` is read, as compile warned (the pre-fix outcome, kept as the contrast).
- **Races.** `TestHeldReadsRaceFree` (supervisor harness: real kernel, filter, loop and deputy): 10,000 opens against
  a sibling flipping the path buffer between `a.txt` and the nested `.env`, 10,000 against a symlink swapped between
  the two: none read the secret held; without a deputy 10,000 of the 20,000 did.
- **A regression the first part left.** `heldOpen` holds a gate's opens only under `gate.completion: held` (a run
  that holds its reads may have a deputy beside a copied gate, whose O_WRONLY opens stay copied, as its best-effort
  cells say); the Stage B harness's gate had never set that key, since a deputy implied it, so
  `TestGateFSOpenRaceIsHeldAndRaceFree` went red. The harness gate now carries it. The label warning names the key
  that holds the run's opens (`fs.reads: auto: this host runs apparmor; ...`), not a `gate.completion` the contract
  lacks. The run's `gate.fs_open_completion` row read the deputy's presence (`NeedsOpenDeputy`), so a run that held
  only its reads claimed the gate's completion; it reads `RuleTable.GateOpensHeld` now
  (`TestCapabilityLineHeldReadsClaimNoGateCompletion`; the conformance capability cross-check caught it).
- **Conformance oracle.** The model reads the contract's `fs.reads`; `denyReadEnforced` (reads) holds a nested
  deny_read enforced at tier landlock unless it is `direct`, `denyReadRulesetEnforced` (the ruleset: compile's
  `unenforced` marker and the modifications beneath the entry, which held reads leave alone) does not; compile's
  `reads.landlock` is cross-checked. The landlock axis: 85 runs, no fail-open, no problem.
- **Root tiers.** `TestIntegrationHeldReadsAtRootTier`: `fs.reads: held` from a root launcher at tier cgroup and
  bpflsm refuses a `.env.local` made during the run by the name rule (root-must-pass). The Stage B mount suite's
  overlay cases became the subtest `TestHeldOpenDifferentialAcrossMounts/overlay`, a listed skip on a kernel that
  mounts no overlayfs (a matrix row's guest loads no module): on AL2023 6.1 the whole test had failed `ENODEV`.
- **Record.** `record.FSReadsWhy*` define `fs_reads.why`'s values (agent's `ReadsWhy*` are those); the frozen fixture
  `held-reads.jsonl` (`TestHeldReadsFixture`, replayed through every view by `test/fixtures`).

*2026-10-25 (built):*
- **A rename over a file the run reads.** The minimal-PATH run of the touched packages failed the reason-file check
  of `TestIntegrationHeldReadsAtLandlock` once (3 times in 140 tries alone): the run's `cat "$TEGO_REASON"` met the
  ledger's rename of a new `last-refusal.json` over the old one between the deputy's walk and this loop's read of the
  pin. The pinned inode had lost its last link, so ADR 0041's GD-5 rule refused it `gate.unreadable`, a gate's line
  in a run with no gate. The task's own open, made then, would have opened the new file. Such a pin (a name that
  names no inode, or another one, when the pin is read) now takes ADR 0041 D4's one re-pin, shared with a create's
  leaf that appeared: the second pin is checked and scored, and its answer stands. A second such pin is refused
  `gate.unreadable` where a gate scores the open and `held-unsupported` (no gate fields, authority `rule`) where the
  open is held only as a read: the held-read floor needs a name. 100 tries out of 100 pass after it. Tests:
  `TestHeldReadOfAFileReplacedAfterThePinIsRepinned`, `TestHeldReadWhoseNameKeepsBeingReplacedIsRefused` (both
  failed before); `TestHeldPinWhoseNameIsRemovedIsUnreadable` keeps GD-5's property with two siblings, one removing
  the target once (the second walk's `ENOENT`, nothing delivered) and one replacing it after every pin (refused).
  Rejected: refusing as before (every read racing an editor's save or a package manager's rename fails `EACCES`
  under held reads, a fail-closed answer the kernel never gives); retrying without a bound (a sibling replacing the
  file in a loop would hold a worker).
- **Cost.** The re-pin is off the hot path (only a pin whose name moved takes it). `BenchmarkHeldReadOpen -benchmem`,
  three runs each on 4 CPUs of the shared 6.17 host: before 17.06-17.15 held allocations an open, 56.51-56.63 MB a
  run, held p99 76-89 µs; after 17.04-17.05, 56.47-56.67 MB, 82-94 µs (R22's soft ceiling is 200 µs).
- **Verified 2026-10-25** in KVM, both boots (`lsm=...,bpf` and without bpf), at this note's commit: the host row
  (6.17) and AL2023 6.1, every held, deputy, supervisor, landlock and conformance test selected passed
  (`TestConformanceKernel` 455 and 273 subtests); the minimal-PATH run of every touched package's unit and
  integration tests passed with no unlisted skip. On the 6.1 row `internal/runtime/launch`'s
  `TestDeputyDescriptorCarriesTheDomainsFileRights` skips (Landlock ABI 2 has neither TRUNCATE nor IOCTL_DEV) and no
  root-skips entry allows it; that test and its package are older than this ADR and untouched by it.

*2026-10-25 (built):*
- **A write entry inside a name rule's tree.** D3 (c)'s pattern walk climbed every ancestor, so once reads
  were held (a `.env` elsewhere in the project, under `auto`) a read the contract's own `~/.ssh/out/` or
  `~/.config/gh/out/` write entry granted was refused by the built-in home path above it, at tier landlock alone.
  `HeldReadIndex.Refusal` now stops the walk at the nearest write entry deciding a read there: a rule matched farther
  up is outvoted, one matched at the entry or beneath it still refuses (a tie refuses). Tests:
  `TestHeldReadNearerWriteReopens` (literal and glob patterns, with and without the advisory list, `Evaluate` at
  every enforcing tier) and `TestHeldReadsKeepAWriteEntryInsideABuiltInHomePath` (a compiled contract, landlock
  against bpflsm), both failing before. The alternate guard (ADR 0057 D2) refuses any file beneath a deny_read
  whatever lies between on purpose and is unchanged.
- **`held` with `io_uring: true`.** Such a contract compiled cleanly, and at tier cgroup or bpflsm,
  where the plane admits io_uring and the filter drops its io_uring arms, a ring's open of a `.env.local` made during
  the run never reached the held floor, while `run_start`'s `fs.deny_read.created_later` (which only held reads
  provide at the root tiers) said true. `validateFSReads` now refuses the pair, `schema`, as gate and ask refuse
  `io_uring: true` (D2's amendment): the io_uring rows of `TestHeldReadsRefuseIOUringAndSetuid` (named for them alone
  until a later fix) failed before. Rejected: keeping the pair and setting the rows false when the filter admits io_uring
  (a contract that asks to hold every read would get a run that holds some of them, and the refusal of a later
  `.env.local` would depend on which syscall the agent used).
  With the pair refused no compiled table reaches `capabilityLine` holding reads beside an admitted ring, so the
  line needs no check of its own.
- **What compile says of a file made later.** Under held reads compile printed the name entries as "not
  enforced by this build: no tier applies them yet" and warned at a deny_read glob that "files created later are not
  covered", beside a reads line saying such a file is refused whenever it was made. The `names` heading
  (`namesWhere`) now names the tiers whose runs hold their reads, where a file the built-in `.env` entries name, or
  one a declared glob matches as written, is refused when made during the run; the glob warning (`heldGlobNotes`,
  which rewords compile_fs's text from compile_heldreads.go so compile_fs.go keeps only `unenforced`) says the same
  and keeps "not covered" for the tiers that read direct. Tests: `TestHeldReadsPrintTheNamesTheyApply`,
  `TestHeldReadsGlobWarningSaysWhereLaterFilesAreRefused`, both failing before; `TestLandlockOnlyReachPrintsNothingNew`
  keeps the old heading for a table that holds nothing.
- **An `O_PATH` open's line.** A held run (D2: every open notified, `O_PATH` not held) recorded an `O_PATH`
  open of a nested deny_read directory `allow` by `fs.deny_read[...] (unenforced: parent writable)` while its
  capability line said `fs.deny_read.nested` true; the same open beneath an enforced deny_read was recorded `refused`
  although it was continued and the kernel, which runs no `file_open` hook for `O_PATH`, let it through. At tier
  landlock `decide.AdvisoryFS` now records such an open `allow` by the entry with `agent.OPathSuffix`
  (` (O_PATH: reads nothing)`), in every run where one is notified (`record: full` and `fs.ask_read` runs too, the
  class's other instances). Tests: `TestHeldReadsOPathLinesSayWhatHappened` (supervisor),
  `TestAdvisoryOPathOpenUnderADenyRead` (decide), both failing before.
- **What the root tiers catch of D5.** OPERATIONS said "the root tiers' kernel refuses both" of D5.1 and D5.2,
  and GAPS A11 told users to pin a root tier for both. The matrix says otherwise: a rename or link out of a
  `deny_read` tree is refused on the inode at tier bpflsm and at tier cgroup in a plane mode, and only best effort by
  the copied names on cgroup's fanotify listener; a file replaced from outside during the run is a new inode no row
  keyed at launch names, so no tier's kernel refuses it once moved. Both now say so (docs only).
- **Checked on the kernel.** Landlock lets an `O_PATH` open through where it refuses the read: on the 6.17 host
  (ABI 7), a process under a ruleset granting nothing on a directory opened a file and the directory there `O_PATH`
  and was refused `EACCES` opening the file `O_RDONLY`. `AdvisoryFS`'s read arm now asks `nearestReadIn` once where
  it asked twice. `-benchmem`, 4 CPUs of the shared host, before against after: `BenchmarkAdvisoryFS` 6.3-7.0 µs
  against 6.3-6.8 µs, `BenchmarkAdvisoryFS50k` 0.93-1.47 µs against 0.89-0.99 µs, both 0 B/op;
  `BenchmarkHeldReadOpen` 56.50-56.66 MB a run and 17.07-17.08 held allocations an open both times, held p50 46-47 µs
  against 41-47 µs, p99 63-64 µs against 68-93 µs at load 3 to 4 (R22's soft ceiling is 200 µs).
- **Verified 2026-10-25** in KVM, both boots, the host row (6.17): every `Held`, `OPath`, `AskRead` and
  `Conformance` test of `internal/runtime/supervisor` (94 passed a boot) and `test/conformance` (457 and 275
  subtests, `TestConformanceKernel` among them) passed, with no unlisted skip; the unit and integration tests of
  decide, supervisor, agent, cli, runtime, conformance and fixtures passed with the full and a minimal PATH, and
  `make lint` passed.

*2026-10-25 (built):*
- **`held` with `setuid: true`.** An earlier fix refused `held` beside `io_uring: true` and missed the other half of
  the check `gate` and `ask` make. `setuid: true` leaves `no_new_privs` unset at tier cgroup or bpflsm, so a setuid
  program of the run (sudo reading the 0440 `/etc/sudoers`, or one that lowers its euid) holds other credentials than
  the deputy, which completes every held read with the ones it was exec'd with: the kernel's answer and the deputy's
  would differ, both ways. `validateFSReads` now refuses the pair, `schema` ("fs.reads: held requires setuid
  disabled"), D2's second amendment; `auto` holds only at tier landlock, where `no_new_privs` is mandatory, and is not
  refused. The class's other users of held completion, `gate` (`validateGate`) and `ask` with `fs.ask_read`
  (`validateAsk`, and `ask_lifecycle`'s runtime check), already refuse both. Test:
  `TestHeldReadsRefuseIOUringAndSetuid` (an earlier fix's test, renamed, with setuid rows: held at bpflsm, cgroup and auto
  refused; auto and direct beside setuid accepted), failing before on the three held rows.
- **What a summary run records of an `O_PATH` open.** `quietRead`, which keeps an `fs.ask_read` run's record
  what it would be without the hold, asked for `fs.ask_read` entries alone, so a held run under `summary` wrote an
  `allow by fs.write[...]` line for every `O_PATH` open of a benign file or directory, and its `(O_PATH: reads
  nothing)` line beneath a `deny_read`: lines a summary run without held reads was never told of, against D4. It now
  covers held runs too (D4's amendment); a refusal, a read gate's score and `record: full` keep their lines. Section
  7's rule that reads beneath a `deny_read` are individual events is about the reads a run records; an `O_PATH` open
  reads nothing and no tier's recorder sees one, so the record mode decides (SEMANTICS §7's amendment). Test:
  `TestHeldReadsOPathLinesSayWhatHappened` under `full`, `summary` and `off`, a benign file and directory added; the
  summary rows failed before, and an earlier fix's version of the test had asserted the summary line.
- **An `O_PATH` open at a root tier.** An earlier fix's `O_PATH` answer stopped at tier landlock. At tier
  cgroup and bpflsm `decide.AdvisoryFS` still answered `refused` for an `O_PATH` open beneath an enforced
  `deny_read`, which a held run notifies (D2) as `record: full` does, and which no mechanism of those tiers refuses:
  `do_dentry_open` returns for `O_PATH` before `security_file_open` and the fanotify permission event, and the
  decision plane's only open hook is `file_open`. Where no kernel recorder read, the line said `refused` and reached
  the reason file; where one read, `settleFS` handed the open to a recorder whose `fexit/security_file_open` never
  sees it, so it had no line, and at tier cgroup `listenerRefuses` left it to a listener that never sees it either.
  `AdvisoryFS` now gives an `O_PATH` open beneath a `deny_read` the `(O_PATH: reads nothing)` answer at every tier,
  `settleFS` keeps its line, leaving a tombstone in the thread's naming as a refusal does, and `listenerRefuses`
  never answers one: the class's three sites. Tests: `TestHeldReadsOPathAtARootTier` (supervisor: cgroup and bpflsm,
  `full` and `summary`, with and without a recorder; it failed before on every full row and on every row with a
  recorder), `TestAdvisoryOPathOpenUnderADenyRead`'s root-tier rows (one asserted the old `refused`), and on the
  kernel `TestIntegrationHeldReadsAtRootTier`'s O_PATH run (`record: full`, python's `O_PATH` opens of a file and a
  directory beneath a nested `deny_read`: each succeeds with one `allow` line from seccomp, and a `cat` stays
  refused). Rejected: asking each tier whether a `file_open`-level mechanism decides the open (no tier has one that
  sees `O_PATH`; the question would have one answer).
- **Verified 2026-10-25** in KVM, both boots: on the host row (6.17) every `Held`, `OPath`, `AskRead` and
  `Conformance` test of `internal/runtime` (23 a boot, both builds), `internal/runtime/supervisor` (44) and
  `test/conformance` (455 and 273 subtests, the same known baseline cells as before) passed, with no unlisted skip;
  with the source fix reverted, `TestIntegrationHeldReadsAtRootTier` failed at tier cgroup and bpflsm with no line
  for either `O_PATH` open, which succeeded. On the AL2023 6.1 row the same selection passed on both boots, except
  one `TestConformanceKernel/landlock/control` run whose ptrace host process failed to start (`ETXTBSY` on the
  actor binary, a fork racing a parallel subtest's write; nothing this change touched), which passed when rerun. The
  unit and integration tests of decide, supervisor, agent, cli, runtime, conformance and fixtures passed with the
  full and a minimal PATH, and `make lint` passed.

*2026-10-26 (built; the deny_read enumeration that froze at launch):*
- **What was wrong.** Landlock is an allow-list, so an enforced `deny_read` is built by granting every sibling of
  each ancestor of the target as one listing at launch named them, and the ancestor itself `READ_DIR` only
  (enforce-landlock R3, E28); the domain cannot change after `landlock_restrict_self`. A name made beside an ancestor
  after that listing has no rule, and Landlock refuses a read of any file beneath it for the rest of the run (E10). The
  decision core reasons on the contract's paths and answered allow, so every line of such an open was false: under
  `record: full` (and wherever an `fs.ask_read`, a read gate or held reads notify opens) the supervisor continued it,
  the kernel answered `EACCES` and the line said `allow`; under held reads the deputy, which opens in the run's own
  domain, met the same `EACCES` and the line said `allow` with `syscall_ret: -13` (no line at all under `summary`);
  an exec of an image there (the kernel's exec open needs `READ_FILE`) was recorded `allow`. The always-on audit of
  2026-10-25 found 8 such lines in one run; with the built-in `~/.ssh` entry `$HOME` is an ancestor, so a top-level
  entry made in `$HOME` during a run is one.
- **Built.** `landlock.Snapshot` (the handle's `DenyReadSnapshot`): each enumerated ancestor's one listing by name and
  the identity of every inode the ruleset grants `READ_FILE` on, copied at the end of Prepare and immutable after.
  `Refuses(p)` answers, for a resolved path the core allows, what Landlock's union along `p`'s chain will answer: true
  only when no inode from `p` up to `/` is one the ruleset grants `READ_FILE` on, `p` lies beneath an ancestor through a
  name the listing did not grant, and `p` is no directory (`READ_DIR` is the ancestor's). The fast path is one
  `fstatat` of the name beneath the deepest ancestor. The supervisor (`Options.DenyReadSnapshot`, wired from the
  tier-1 handle only, never for a records-only run) refuses such a read-capable open itself with the kernel's own
  `EACCES` and records it `refused`, `read-denied`, rule `deny-read-snapshot`, before an ask, a held completion or a
  gate could take it (`snapshotRead`); explains a held read's `EACCES` the same way (`heldKernelErrno`); and refuses an
  exec whose image it covers (`recordExec`). The reason file and the hook carry it as any refusal.
- **Why this is safe.** It never widens anything: it adds refusals of opens the kernel refuses anyway and grants no
  right; the agent gets the errno it got before. It cannot refuse what the kernel allows except through a race with
  the tree it stats (a file moved between the check and the open), because every doubt answers false and leaves the
  open to the kernel with the core's line: a component that cannot be stat'ed or is now a symlink, and, on an overlayfs
  only, a file named at launch whose inode changed (a copy-up can renumber it, ADR 0010). Identity, not name, decides:
  a granted sibling renamed stays granted, a write entry moved into a new directory stays readable, a sibling replaced
  by a new directory of the same name is refused, as Landlock decides on inodes. `TestIntegrationSnapshotAgreesWithTheKernel`
  compares `Refuses` with the real domain's answer over 24 random trees changed after Prepare (about 870 paths, 170 of
  them refused): they agree on every path.
- **Rejected.** (1) Granting the ancestor `READ_FILE`: Landlock rights are hierarchical, so it would grant the target
  beneath it. (2) Letting the supervisor, outside the domain, open such names for a held read: the path floor would be
  the only check, and a hard link to the target placed in a new directory by a process outside the run, which the
  domain refuses by identity, would be read; the deputy opens in the run's domain by design (ADR 0041 D2).
  (3) Re-enumerating during the run: a domain takes no new rule after `landlock_restrict_self` (a nested domain only
  restricts), so nothing could grant the new name. (4) A new record reason code: `read-denied` is the fact, and "the
  rule name carries the specifics" (spec/reason/REASON-CHANNEL.md's closed set), so no record minor.
- **Left.** `run_start` does not name the frozen ancestors (a record minor); the root
  tiers keep the inherited ruleset's enumeration and are not wired or verified in KVM; under `record: summary` with no
  arm that notifies opens the open is not seen at all, as every tier-landlock read refusal there; the remedy for a
  long run is a restart (docs/OPERATIONS.md, "Names made after a run started").
