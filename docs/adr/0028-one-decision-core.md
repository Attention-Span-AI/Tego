# ADR 0028: one pure decision core, with a model per tier, used by every component that decides or predicts

Status: accepted 2026-09-29; S1, S3, S5 and S6 implemented 2026-10-04 with the held-descriptor plan, immutable indexed queries, caller convergence and independent conformance fixtures. S2 and S4 retain their previously recorded implementations. Scoped source/behavior checks pass; final expanded candidate acceptance remains pending. Proposed 2026-09-23. Amends SEMANTICS §2 (one statement per tier) and enforce-landlock I5.

Decision: internal/policy/decide is pure: no I/O, no goroutines, no allocation on its query path. Built from the compiled contract, it holds the path index (enforce/cgroup's pathSet moves here); the Landlock rule plan (enumeration, unenforced marks and ADR 0025's neutral rules, computed by the core and applied by the builder, which computes nothing); and the exec, net and socket-family matchers, with one exact-before-LPM net matcher. The plan is computed by one function in two places: at compile time over resolved paths (the prediction compile --test prints) and at Prepare over the held O_PATH descriptors' identities (the plan the builder installs and the supervisor reads). I5 stays, as a runtime assertion comparing the two: a containment change between compile and run (for example a symlinked write entry that now encloses a deny_read target) is reported as today. Models: landlock (the union of grants over the plan, plus the rules the supervisor enforces itself: deny_write, exec, net, socket families); root (ADR 0024's walk intersected with landlock); and fanotify (the fallback's current semantics) until S3 makes it equal to root. Consumers: compile --test (internal/cli calls the core; pkg/spec/agent.Evaluate becomes a one-release deprecated shim, so the public package holds types, validation and loading, ADR 0031); the supervisor's verdicts and own refusals; the fallback's decideOpen and decideExec; the plane's row compiler; the recorder, for rule attribution only (ADR 0016). Deleted in S5: fsVerdict/fsVerdictIn, observe's inferFS and matchNet, Evaluate's evalFSLandlock and evalFSRoot bodies, and the three unenforced computations.

Why: [measured] Five implementations of the fs verdict and three of unenforced; the watch-entry fix reached only two of three copies. Evaluate(cgroup) models tier 3 (evaluate.go:160 sends every non-landlock tier to evalFSRoot). With about 47 entries the supervisor's fsVerdict takes 762 ns and 19 allocations, Evaluate 2461 ns and 21.
[documented] Two earlier commits record components answering absent sections three ways.
[documented] I5 compares compile's unenforced decision with Prepare's over the held descriptors, which catches containment that changed between compile and run; it is true by construction only if the Prepare plan were the only plan.
[documented, ADRs 0019 and 0028] 0019 kept pkg/spec/agent free of internal imports while 0028 had Evaluate delegate into internal; moving evaluation behind the CLI resolves the contradiction.

Security argument: One reviewed decision function replaces five, so compile --test, the tier-1 record, the fallback and the plane's rows cannot disagree about the contract; the kernel still judges it, and ADR 0017's contract-derived invariants catch an error the core would otherwise spread everywhere at once. I5 keeps catching a plan that changed between compile and run. The core is pure, so it adds no I/O or concurrency to the TCB.

Options considered: Chosen: one decision core, after the independent invariants of ADR 0017, then decision tables.
Rejected:
- The conformance suite alone: every semantic fix would need N edits forever.
- Promoting Evaluate unchanged: allocates, takes 2.5 µs, wrong for tier 2 and for Landlock's union.
- The core in public pkg/spec: a compatibility surface for code that changes with kernel behaviour.
- Deleting I5 as true by construction: compile's prediction is a second computation over paths that can change before the run.

Consequence: compile --test gives exactly the answer the runtime records for each tier. Several thousand lines of duplicate matching go. The 12 of 768 Evaluate(landlock) disagreements close with S1/S2. pkg/spec/agent.Evaluate is deprecated for one release.

Implementation plan:

S1 (M): internal/policy/decide with the index, the plan (compile-time and Prepare-time entry points) and the three models; compile --test and the Evaluate shim use it; enforce/landlock's builder applies the core's plan and keeps I5's comparison. Benchmarks with a realistic enumeration ($HOME with about 50 siblings, deny_read on ~/.ssh and .env, 47 entries): zero allocations on the query path, under 1 µs; CI runs benchstat against the parent commit with a threshold wider than measured noise. Gate: ADR 0017's baseline unchanged or smaller, no invariant failure.
S2 (S): with ADR 0016 step 1, the supervisor's verdicts.
S3 (M): the fallback's decideOpen/decideExec on the core (allocation-free; BenchmarkFanotifyRoundTrip no slower) and ADR 0021 item 5's convergence in the supervisor; compile --test's fanotify column disappears. Tests at tier cgroup in GUEST with the plane disabled (bpf.plane unset on a build without it, before ADR 0024).
S4: the plane's row compiler, inside ADR 0024 step A.
S5 (S, after ADR 0016 step 2 and ADR 0024 step A): delete the duplicates.
S6 (M): spec/policy/conformance/*.yaml decision tables run by the core's unit tests and by ADR 0017; they supply SEM rule citations (ADR 0030).
Docs: ADR 0028; SEMANTICS §2; enforce-landlock I5 (assertion kept) and R4; REPO-LAYOUT.

*Amended 2026-09-28 (S1):* what S1 built, and where it departs from the text above.
- The code moved; no verdict changed. Evaluate and its walks left pkg/spec/agent for internal/policy/decide, and so did tier 2's listener index and open/exec decisions (from enforce/cgroup policy.go), the supervisor's advisory fs verdict and its tables (from supervisor fs.go and supervisor.go), the recorder's inference and exact-before-LPM net matcher (from observe rules.go), and the plan's pure questions (from enforce/landlock enumerate.go). The consumers call the core; the models that S3 and S5 are to merge (the advisory tables beside the root walk, the listener's index beside ListenerOpenRefused, MatchNetLPM beside Evaluate's first-match matcher) are still separate functions, side by side in the core, with cross-checks holding them to one answer (TestListenerOpenMatchesTheTableWalk, enforce/cgroup TestCrossCheckTiers).
- pkg/spec/agent may not import internal (ADR 0019), so the Evaluate shim cannot call the core. The core registers itself instead (agent.RegisterDecider, once, from its init): RuleTable.Evaluate, FSDecider, ListenerOpenRefused and ExecReadGrant delegate to it, and panic when no core is linked rather than answer. compile --test passes the core's Evaluate explicitly (agent.TestTable.RunBy). pkg/spec/agent's own tests link the core from one external test file, the one exception to depguard's spec-is-pure; the shims carry no "Deprecated:" marker until ADR 0031 (c) moves the tests that call them.
- The root model's rows: RootRows keys one row per canonical path an entry names, with the read and modification answers the walk takes there; RootIndex.Walk is the plane's walk over the rows alone, bounded at MaxWalk; RootExecRows are the exec rows ({parent, name}, a directory, or a bare name). TestRootWalkMatchesEvaluate holds the walk to Evaluate's bpflsm column over every generated table. The row compiler itself is S4.
- Open in S1: the plan at Prepare over the held descriptors' identities (the builder still resolves and walks paths, asking the core's plan functions), and the 1 µs gate. The runtime query paths allocate nothing (TestQueryPathsAllocateNothing), but FSDecider and Evaluate still walk the table and clean each entry's paths per question, tens of µs on the 47-entry benchmark table (BenchmarkFSDecider); the index that meets the gate is the next S1 change.

*Amended 2026-09-29 (T1, TIER3-PLAN §11; accepted):* accepted as written, with the 2026-09-28 note's departures.
What was built at that date is S1 in part: internal/policy/decide holds every tier's model and the root
model's rows (RootRows, RootIndex.Walk, RootExecRows); the Prepare-time plan over held descriptors and the 1 µs gate
remain S1's open items. S4, the row compiler, is TIER3-PLAN T5 and emits rows with ADR 0025's gen (as amended);
ADR 0019's 2026-09-29 note makes the root model the single column for tier cgroup with a plane and tier bpflsm.

*S4 status, 2026-09-29 (TIER3-PLAN T5):* the row compiler is built: `decide.CompilePlane` turns a RuleTable into the
plane's rows keyed by canonical path (T4's fill keys them by inode), exec rows, the keyed-inode list and ADR 0025 (3)'s
neutral Landlock rules (`PlaneRows.Neutral`, read rights only), and refuses a table over the slot maps' sizes (4096 fs
rows, 1024 exec rows) as a compile error at bpflsm (`decide.PlaneDiagnostic`, called by `tego compile`). Each row is
complete, the root model's answer at its own path for every question, because the kernel's walk stops at the first row;
the row's `rule_idx` is its position, resolved per question by the ledger. Checked: the rows, walked as the kernel walks
them and by RootIndex.Walk, equal Evaluate's bpflsm column over every generated table with and without deny_write
targets (TestPlaneRowsMatchEvaluate), and the neutral rules leave a Landlock plan model's grant unchanged at every path
(TestNeutralRulesKeepTheUnion); the query paths allocate nothing. docs/p0/enforce-plane.md §2.4 records the layout and
six conditions (deep paths past the 64-step bound, a rename above every write entry named differently, a hard link of a
keyed file, two exec names of one inode, neutral rules on sealed deny nodes, compile cost at the cap).

T10 (2026-09-29): `compile --test`'s bpflsm column is `decide.PlaneEvaluator`, the rows themselves (`PlaneRows.Decide`, `ExecMatch`) plus the REFER and exec-stage sequencing, not `Evaluate`; `Evaluate` at bpflsm stays the oracle, and `TestPlaneEvaluatorMatchesEvaluate` and `TestPlaneEvaluatorExecMatchesEvaluate` hold the two equal over the generated tables (one stated rename-naming difference).

*Note 2026-09-29 (tier 2):* the net matchers no longer differ on overlapping entries. Evaluate took the
first declared covering entry and tier 2's rows the exact row, then the longest prefix, so an ask literal inside an
allowed CIDR was allowed by one and refused by the other. SEMANTICS §5 now states one rule (a refusing covering entry,
else the first declared); `matchNet`, `MatchNetLPM`, `dns.Set.Match` apply it and `BuildRuleMaps` composes each row by
it, checked by enforce/cgroup's `TestNetPrecedenceMatchesEvaluate`. A compiled P0 table holds only allow entries
(`net.ask` is not yet supported), so only the entry a line names changes there.

*Amended 2026-10-04 (S1/S3/S5/S6 implemented):* Prepare creates one filesystem plan from held identities, and the callers use the shared immutable decision queries instead of parallel matchers. Held Landlock descriptors are compared with the plan under I5; the actual symlink-retarget test fails closed. An independent static YAML oracle and kernel row/source parity checks retain the tier distinctions. The indexed-query benchmark on the recorded host remains below 1 µs with no allocations; this is not a cold-start or unmeasured-platform claim. The new full candidate's manual/review/automated acceptance remains pending.

*Amended 2026-10-05 (net.ask):* an earlier note's last sentence held when written. Since 2026-10-04 `net.ask` compiles: its entries are separate `NetAsk` destination rules in supervised scopes, never allow rows (agent-contract R22), and an approval is a one-shot credit bound to the destination and the socket, consumed by the connect hook, not a persistent allow row (ADR 0008's 2026-10-04 note). So a compiled table still holds only allow entries in the rows an earlier rule composes.

*Amended 2026-10-19 (the deadcode ratchet, ADR 0029 (4)):* the reference rows the notes above name (`RootRows`, `RootExecRows`,
with `RootDecide` and `RootExecMatch`) are test oracles in decide's `rootoracle_test.go`; the binary builds the root
model's rows through `CompilePlane` (`rowIndex.rows`, `PlaneRows.RootRows`) and walks them with `RootIndex.Walk`, as
before. No verdict changed.
