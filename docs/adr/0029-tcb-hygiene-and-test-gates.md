# ADR 0029: one implementation per TCB syscall wrapper, test gates that cannot pass vacuously, real compiled fixtures

Status: proposed 2026-09-23; part (1) implemented 2026-09-29 (go.mod toolchain, checkLeaks fails without the profile; pkg/spec/agent not gated), part (2) implemented 2026-10-04; parts (3) and (4) implemented 2026-10-04 with the departures in the 2026-10-05 note; part (5) implemented in part 2026-10-04, its step-5 acceptance not met (2026-10-05 note); part (2) extended to every Landlock syscall and part (4) amended to a gating classification ratchet 2026-10-19 (note of that date); the test-isolation gate extended to the runtime parent 2026-10-24. Lands first: every later ADR's tests use its fixtures and its leak gate.

Decision: (1) go.mod declares go 1.27 and toolchain go1.27.1. internal/testutil's checkLeaks fails when the goroutineleak profile is missing. LeakCheckMain gates internal/runtime/enforce/cgroup, internal/doctor, internal/platform/sys, internal/runtime/cgroup and pkg/spec/agent. (2) There is one landlock_restrict_self wrapper, sys.RestrictSelf in internal/platform/sys. It takes the caller's flags; drops only the flags the probed ABI lacks; retries without LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS only when the kernel answers EINVAL; runs the I8 PR_GET_NO_NEW_PRIVS cross-check whenever NO_NEW_PRIVS was requested; and returns an error, never proceeding unrestricted, on every other failure. The child stage (launch/child.go, today restrictSelfDegrading) calls it; enforce/landlock/restrict.go is deleted. The wrapper executes the caller's no_new_privs policy and never decides it (ADR 0033 decides it). (3) Test-only wrappers leave production files: BuildFilterMemfd, buildFilter, assembleFilter*, ledger.HandOverRun, MakeDirs, enforce/cgroup reason.go's Reason and ReasonCode, and the unused pkg/spec/backend functions move to _test.go files or are deleted. (4) deadcode runs in CI as a report, not a gate, with an allowlist of the P1+ placeholder packages (ADR 0015: review, not gate). (5) internal/testutil/contracttest (real agent.Compile over a temp tree) and internal/testutil/ledgertest (an event builder) replace hand-built RuleTables and the duplicated fixture helpers in supervisor, enforce/cgroup and observe. Migration changes how tables are built, never what a test expects; fs_test.go:69's wrong expectation is flipped by ADR 0016 step 1 in its own diff.

Why: [measured] deadcode v0.50.0 finds 74 unreachable functions, among them enforce/landlock restrict.go:20, which carries the I8 cross-check, while the live restrictSelfDegrading (launch/child.go:309) lacks it. checkLeaks returns 0 (pass) when the profile is absent; go.mod says go 1.26.0 with no toolchain line while CI pins 1.27.1, where the profile exists (go1.26 has it only under GOEXPERIMENT=goroutineleakprofile, documented). Five packages that start goroutines have no gate (enforce/cgroup has five spawn sites). Fixture helpers are duplicated four and five times, and fs_test.go:69 pinned a wrong answer with a hand-built table that a differential test with real Compile found in 0.03 s.
[documented] The two wrappers differ in more than I8: the live one takes the caller's flags and drops only what the probed ABI lacks, and the privileged path deliberately requests no NO_NEW_PRIVS; the dead one always requests it first. Taking the dead wrapper's shape would change tier 2 on ABI-11 kernels; taking the live shape without I8 keeps the missing cross-check.
[inference] Every later ADR in this set is proved by tests; a leak gate that passes vacuously and fixtures no compiler produces would let those tests pin fail-open answers.

Security argument: The child stage (TCB) loses an untested alternative path and gains the I8 cross-check on the path that runs. The wrapper cannot proceed unrestricted on an unexpected error and cannot switch no_new_privs on or off behind its caller. Goroutine leaks in the fanotify listener and the backends become test failures. Tests exercise compiled contracts, so they can no longer pin a fail-open answer to a table no user can write.

Options considered: Rejected:
- Gate CI on deadcode: P1 placeholders are legitimately unreachable (ADR 0015).
- Keep both restrict_self implementations: the live one lacks the cross-check.
- Adopt the dead RestrictSelf's shape (NNP always requested first): changes tier 2's semantics on ABI-11 kernels.
- Keep hand-built RuleTables: they pinned wrong answers.

Consequence: Test churn in three packages. The leak gate is meaningful on every toolchain. One restrict_self in the tree, with the cross-check on the path that runs.

Implementation plan:

Five PRs, each green on its own:
1. go.mod (go 1.27, toolchain go1.27.1); internal/testutil/leak.go fails on a missing profile; LeakCheckMain in the five packages. Acceptance: go test -race ./... passes on go1.27.1; a deliberately leaking self-test of the gate fails. Release notes tell packagers that GOTOOLCHAIN=auto downloads go1.27.1 or fails offline.
2. internal/platform/sys RestrictSelf(rulesetFD, flags, abi) with the rules of item (2); launch/child.go calls it; delete enforce/landlock/restrict.go and port its I8 test. Tests: a fake-syscall unit table (EINVAL retry without the NNP flag, any other errno fails, per-ABI flag dropping, I8 mismatch fails); kernel tests on this host for the unprivileged path (NNP by prctl on ABI 7); as root in GUEST the privileged path (Landlock before the uid drop, NNP per ADR 0033) through TestIntegrationRestrictSelf and the privileged child-stage tests. The ABI-11 flag branch is covered by the fake until a matrix row runs 7.3+ (stated in the test).
3. Move the test-only wrappers; the build proves no production caller.
4. CI job: deadcode report with tools/deadcode-allow.txt (internal/runtime/ask, harness adapters), non-gating.
5. internal/testutil/contracttest (Build(t, yaml, tree) returning the real compiled contract over t.TempDir()) and ledgertest; migrate supervisor, enforce/cgroup and observe unit tests. Acceptance: a grep test finds no RuleTable literal outside pkg/spec/agent; every expectation is unchanged.
Docs: ADR 0029; runtime-launch §5 and I8 name sys.RestrictSelf as the one wrapper; REPO-LAYOUT lists the two testutil packages.

*Amended 2026-09-24 (step 1 landed, two packages short):* go.mod says `go 1.27` and `toolchain go1.27.1`, the release every workflow pins, so no job downloads another toolchain; `checkLeaks` fails on a toolchain without the profile (`TestNoProfileFailsTheGate`); `LeakCheckMain` gates internal/doctor, internal/platform/sys (both builds) and internal/runtime/cgroup, and passed there unprivileged, raced and as root in the guest. internal/runtime/enforce/cgroup and pkg/spec/agent are not gated yet: another change to both packages was in flight, and their gate lands with or after it.

*Note 2026-09-29:* enforce/landlock/restrict.go and its test are deleted as dead code, and the I8 `PR_GET_NO_NEW_PRIVS` cross-check is ported into the live wrapper, launch's `restrictSelfDegrading`, which is now the one `landlock_restrict_self` wrapper in the tree. Moving it into internal/platform/sys as `sys.RestrictSelf` is still open.

*Note 2026-10-04 (step 2):* the live child now calls `internal/platform/sys.RestrictSelf`; the ABI flag split and fallback/I8 implementation have one owner. The original fake-syscall cases moved with the implementation, preserving flag behavior, and the real-kernel write-floor test applies this production wrapper. ABI-11 flag acceptance remains covered by injected syscall responses until a suitable kernel runs it. The remaining wrapper hygiene, deadcode report and broader fixture migration are still separate work.

*Note 2026-10-04 (steps 3–5):* the production cgroup reason mapper is private; its public test aliases, Landlock enumeration compatibility helpers and unused backend report/capture-parser helpers live in `_test.go`. Ledger's `HandOverRun` test bridge was already there. The live `MakeDirs`, `BuildFilter` and private filter assembly implementations remain. The report-only CI job analyzes the production CLI for Linux amd64/arm64, with and without `tegobpf`, using pinned deadcode v0.50.0. Raw output, stderr and exit status are retained for each profile; unavailable analysis cannot become an empty successful report. Both the analyzer and report formatter execute for the host architecture, independent of the package target. Exact placeholder classification does not remove findings from the report.

`contracttest` now builds the common observe and cgroup backend fixtures and the supervisor's real-tree mutation fixture through the public loader/compiler with private HOME, explicit PATH and deterministic DNS/clock inputs. `ledgertest` supplies typed validated unchained events and shared typed decoding; the ledger writer still owns chain hashes. The fixture inventory checks the three compiler-backed entry points and currently classifies 119 direct table literals in 94 functions by path, function, count and purpose. Changing those counts or adding an unclassified literal fails the test. This is a direct-literal inventory, not a claim that every synthetic mutation or test alias is statically discoverable. Actual privileged CLI fixtures provide separate production policy proof.

*Amended 2026-10-05:* "explicit PATH" did not keep the host out: the observe fixture's PATH began with /usr/bin and its exec.allow [git] compiled to the host's git, so all of that suite's fixture tests failed as root in the KVM guest, which has no git (root-suites R1). `BuildAt` now fails a fixture whose command, exec.allow or MCP entry compiles to a file outside its private tree (`TestBuildRefusesAHostExecutable`); only the interpreter a fixture script names (the default `#!/bin/sh`) may be the host's.

*Amended 2026-10-05 (the 2026-10-04 notes):* the decided text above stands; what was built, and where it departs, is here.

- (1) `LeakCheckMain` now gates internal/runtime/enforce/cgroup; pkg/spec/agent still has no `TestMain` and no
  leak gate, though compile_net.go starts goroutines. Part (1) stays open for that package.
- (3), correction of fact: `BuildFilter`, `buildFilter`, `assembleFilter` and `MakeDirs` have production callers, so
  they stay production code; "the build proves no production caller" was wrong for them. What moved to `_test.go`
  is listed in the 2026-10-04 note (the cgroup reason aliases, `HandOverRun`, the Landlock enumeration
  compatibility helpers, the unused pkg/spec/backend helpers); `BuildFilterMemfd` is reached through an
  integration-only bridge.
- (4), correction of fact: internal/runtime/ask is live code, so the allowlist names
  internal/runtime/reason and internal/adapters.
- (5) is implemented in part. Three compiler-backed entry points exist (`newFixture` in observe and enforce/cgroup,
  `TestFallbackMutationConverges` in supervisor), and an AST inventory
  (internal/testutil/contracttest/migration_test.go) classifies 119 direct `RuleTable` literals in 94 functions of
  those three packages; a new unclassified literal there fails it. Step 5's acceptance, "a grep test finds no
  RuleTable literal outside pkg/spec/agent", is not met and no test checks it: when this note was written 58 test files in the
  three packages hold 122 `RuleTable{` literals, 189 test files under internal/ hold one, and the supervisor's 246 hand-built `testPolicy(` call sites are outside the inventory. The
  inventory's "calls Build" check is syntactic: a fixture may call `contracttest.BuildAt`, discard the result and
  return a hand-built table.
- The 2026-10-04 text also argued that kernel wire/map oracles, isolated pure queries and malformed-input tests
  need tables no compiler produces. That is a proposed refinement of (5) and of the rejected option above (keep
  synthetic inputs, classified per function, for those purposes only); it is not decided here. Until it is, (5)
  and step 5 stay open against the acceptance as written.

*Amended 2026-10-05:* a fixture can also diverge from production by keeping its own copy of a choice production makes. The observe integration fixtures attached `trace_proc`'s programs with a private copy of the backend's attach choice, written when the exec-result programs were the only syscall tracepoints, and attached the listener programs as tracing programs, so fifteen tests of the tegobpf observe suite failed on each boot as root in the KVM guest ("invalid program type TracePoint, expected Tracing"). `bpf.AttachTrace` is now the one place a host-wide tracing program is attached, called by the backend and by those fixtures, and `TestTraceProgramsAttachByTheirProgramType` holds each program's attach kind to the type its `SEC()` compiles to (enforce-cgroup-observe.md R14).

*Amended 2026-10-05 (plane fixtures):* behind that failure the same suite's two plane tests (`TestIntegrationPlaneRefusalIsOneLine`, `TestIntegrationPlaneFallbackIsOneLine`) failed in their own loader of the plane fill build, with "pin by name: missing MapOptions.PinPath": `fillSlot` named two of the three row outers the fill declares, and the third, the Unix listener rows (`tego_plane_listen_rows`), is pinned by name. It now gives the slot an inner map in each of the three and names each as a replacement, as `newPlaneFiller` does, and both tests pass in the guest.

*Amended 2026-10-19:* part (4) is now a
gate on classification, not on a count, so the rejected option "Gate CI on deadcode" stays rejected: what fails
is a function nobody has accounted for, never the number of them. `tools/deadcodereport -gate` fails on (a) an
unreachable function in any of the eight analyzed profiles (linux amd64/arm64 x plain, integration, tegobpf,
integration+tegobpf) that `tools/deadcode-allow.txt` does not name by exact function, (b) a classification no
profile finds (stale, judged only when every profile was analyzed) and (c) a profile the tool could not analyze,
which stays "unavailable", never zero findings. CI's deadcode-report job no longer has `continue-on-error`. A
P1 placeholder (ADR 0015) is a `placeholder` line, so the ratchet cannot misfire on it.
- Classes: `public-api` (pkg/ only: nothing outside the module can import internal/), `placeholder`, `pending`
  (built ahead of an accepted migration; the reason names the ADR commit, here ADR 0023's C5, C8, C9, C11, C14),
  `tag-only` (tegotesthooks code and integration-tag bridges), `test-api` (exported for another package's
  tests), `tool-only` (tools/adoptiongen's share of internal/bpf/adoptionmeta), `control-only` (added 2026-11-01: a
  function of a package both binaries share that only `cmd/tego-control` calls, since the profiles analyze
  `./cmd/tego` alone) and `reflection`
  (`derive.ServerToolUse.UnmarshalJSON`, which encoding/json reaches inside `anthropic.Usage.UnmarshalJSON`). A
  function only its own package's tests call is not classified; it lives in that package's `_test.go` files.
- Triage: 104 findings. 34 moved into their package's tests, and where such a wrapper carried the
  only description of its production sibling, that text moved onto the sibling (events.JSONOf/TableOf,
  runtime.RequestStopGraceThen and OpenStopTargetFor, ledger.placeNewFileAt; and, later,
  supervisor.deputyPin and DeputyPinner, enforce/cgroup's acquireGen, anthropic's classifyPathOn and
  validateRequest, derive's Steps.byTime, drift.ComputeCtx, measure.ComputeAt, runtime/cgroup's
  delegatedSubtreeIn, decide's rowIndex.rows and FSIndex.NewFSMatch, agent's readSmallErr and listDir); tests of
  other packages that called a moved wrapper now call the function the binary calls, and the specs and ADRs that
  named a moved wrapper as the API name the survivor, each with a dated note. The doctor run cache's shorthands and decide's root
  reference oracles (`RootRows`, `RootDecide`, `RootExecRows`, `RootExecMatch`) moved into their tests too; the
  oracles live in `rootoracle_test.go`, not a `decidetest` package as planned, because they use decide's
  unexported walk, and `RootIndex` (which the plane's name-row compaction uses) stays production code. The remaining
  70 (66 in the plain and tegobpf profiles) are classified one by one. Rejected: moving cross-package test
  helpers into `tegotesthooks` files, which would compile the calling tests only under that tag and drop them
  from every default `go test` run; and a test-support package, which cannot reach the unexported state several of
  them read (Registry.Len, Tree.PIDs, proc.Armed) and would part each helper from the type it describes.
- Part (2) now covers every Landlock syscall, not only `landlock_restrict_self`: `sys.LandlockCreateRuleset`,
  `sys.LandlockAddRule` and `sys.LandlockRestrictSelf` (which `sys.RestrictSelf` calls) in internal/platform/sys are the only Go code that names the three
  syscall numbers (`TestOneLandlockWrapperPerSyscall` walks the tree), and enforce/landlock's syscall seam, the
  ABI probe and the descriptor kind check call them. The wrappers return the kernel's errno unwrapped and pass the
  whole attribute struct, whose tail past the probed ABI the caller leaves zero, as enforce/landlock already did.

*Amended 2026-10-20:* six more
functions had become unreachable from the binary, which the ratchet found.
decide's `RenameGains`, `RenameGained` and `LinkGains`, which only decide's tests call, moved into decide's
`export_test.go`, and their contracts onto `RenameGainedBy`, `ReferRefuses` and `LinkGainsBy`; agent's
`TestRow.action`, which only agent's tests call, moved into agent's `export_test.go` and its contract onto
`TestRow.build`. decide's `LandlockLinkRefusal` and `LandlockRenameRefusal` are classified `test-api`: the
recorder's tests in internal/runtime/observe name the refusal by the scan, the oracle for the recorder's indexed
answer, which decide's own test files cannot serve.

*Amended 2026-10-24 (toolchain patch release):* go.mod's toolchain and every workflow's `GO_VERSION` move from
go1.27.1 to go1.27.3. govulncheck found eleven standard-library vulnerabilities in go1.27.1 that Tego's code reaches:
ten fixed in go1.27.2 (the HTTP/2 flaws GO-2026-6617, -6612, -6611, -6610 and -6603 on the forwarder's and the ledger
reader's paths, the HTTP/1 CONNECT desynchronizations GO-2026-6613 and -6605, mime/multipart's GO-2026-6608, crypto/tls's
GO-2026-6607 and the Windows-only GO-2026-6604) and crypto/x509's GO-2026-6809 in go1.27.3. Step 1's rule holds: one
patch release is pinned in go.mod and in every workflow, and the pin moves when a newer patch release fixes a
vulnerability the code reaches.

*Amended 2026-10-24 (ADR 0061):* the 2026-10-05 note's correction of fact under (4) names an allowlist of
internal/runtime/reason and internal/adapters. internal/runtime/reason is removed: the reason file it was kept for is
`pkg/spec/reason`, live code. The other two stay placeholders.
*Amended 2026-10-24 (step list):* the gates these steps build are joined by the test-isolation gate's
runtime-parent clause (identity-config.md R27 clause b4), as step 1b: no test, and no tego a test starts, makes or
writes the developer's `$XDG_RUNTIME_DIR/tego` or `/run/user/<uid>/tego`, where each run keeps its CODEX_HOME and
each launch sweeps the directories of runs whose launcher is gone. A reproduction with the guard extended and no
prevention made that parent from `internal/runtime`'s unit tests (in-process runs) and its and `test/conformance`'s
integration tests (the tego binaries they start), and a planted crashed run's directory there was swept. Prevent:
the `TestMain` of each package that starts a run (`internal/runtime`, `internal/cli`, `test/conformance`) calls
`testutil.PrivateRuntimeDir`, and `testutil.TegoEnv` sets `XDG_RUNTIME_DIR=<OwnStateDir>/run` (0700) after the
inherited environment and before `extra`. Detect, narrowly: `GuardRealTego` snapshots the parents
`internal/realtego.RuntimeDirs` names (the effective uid's and `SUDO_UID`'s logind parent, and the parent under the
absolute `XDG_RUNTIME_DIR` the binary started with) and reports a parent made, removed or replaced, a new entry whose
lock no live run holds at the check (the sweep's own predicate) and a crashed run's entry gone; a live run's entry,
the developer's, is never reported. The acceptance is a deliberately leaking unit test of the guard
(`TestGuardedRunFailsTheBinaryOnALeakedRuntimeDir`), not a failing test in the tree. Rejected: diffing the whole
parent (it fails whenever the developer has a run going), and a path refusal in the product binary (a Layer 1 change
for a hazard only tests have).

*Amended 2026-10-24 (step 1b):* the prevention reaches the shell and Python harnesses too,
which no Go guard sees: `kt_config` and `lib_init` export `XDG_RUNTIME_DIR=<dir>/run` (0700), the other scripts that
start runs name one of their own, and `tools/isocheck` SH-7 refuses a script that starts a run without one or hands
tego the inherited one (a kill test at tier landlock had made and swept `/run/user/<uid>/tego`). The guard's report
of a crashed run's entry gone is now the sweep's exact predicate (a run id's private directory whose regular lock
takes the flock), held to a real sweep by `internal/runtime`'s `TestTheGuardsSweepableEntriesAreWhatASweepRemoves`;
its report of an entry made stays stricter, any entry not held.

*Amended 2026-10-24 (step 1b):* SH-7 also refuses a launch handed `/run/user/<uid>` by a
literal path or the inherited value copied through another name, and a quoted Python mention no longer counts as
giving tego a directory unless the script also refuses the login session's. identity-config.md R27 clause b4 states
SH-7's limit (it reads a script and does not evaluate it) and the guard's two reports a developer's own launch or
killed run during the tests causes.

*Amended 2026-11-04 (fast-path timing gates):* `TestIntegrationFastPath` and
`TestIntegrationFastPathOps` now use the same budget/unit-gate split as the other absolute timing tests
(`docs/BENCHMARKS.md`). Their pipe ping-pong gauge measures scheduling, not the handler's instrumented CPU
work: a tagged race run on the shared host measured common operations at 276–411 µs while the gauge stayed
at 11–19 µs, so an otherwise correct run failed the 200–228 µs ceiling. The unit/race gate now uses the
existing `testutil.CeilingFactor` times R22's 200 µs limit, on the same wall-clock round trip; its operation and
notification assertions still run. `scripts/timing-budgets.sh` includes both tests, in an uninstrumented
build, and budget mode keeps the original best of three against max(200 µs, 12 pipe ping-pongs). The existing
slowdown hook can refute both modes. No production threshold, ownership proof or skip list changes. Rejected:
skip these tests under `-race`, which would lose their notification checks; change R22's production limit;
keep asserting a production latency figure on instrumented code using a gauge that does not measure that work.
