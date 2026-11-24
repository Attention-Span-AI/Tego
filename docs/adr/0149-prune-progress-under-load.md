# ADR 0149: Journal pruning commits progress after taking its lock

Status: accepted 2026-11-12; implemented. Host unit tests cover controlled deadlines and cleanup progress.
Actual startup, dead-mount and cross-owner checks are owed in a guest; see the
[steps and expected results](../testing/prune-budget-guest.md).

A run start shares a cooperative two-second retention budget between run sweeping and journal pruning.
Reading and filtering a journal can consume what the sweep left. Checking the deadline during that work
discards the entire proposed rewrite. Every short pass can restart from zero forever, although it took
the journal lock each time. An atomic rename alone preserves consistency but does not ensure progress.

Prune checks the context before taking journal.lock. It removes abandoned temporary files before that
lock, while holding prune.lock exclusively, with cancellation checks between removals. Once journal.lock
is held, the journal read, filter, write, file sync, rename and directory sync form one operation with
no cancellation checkpoint inside it. Ordinary I/O and journal validation errors still stop it.
Cancellation is checked after the operation, before blob or contract-lock cleanup. Completed counts
accompany that error; retained lines always keep their blobs. Cleanup checks between entries and later
passes select leftovers from current disk state.

This guarantees a successfully locked, valid journal rewrite completes despite deadline expiry. It does
not guarantee journal work starts if run sweeping or earlier operations always spend the whole budget.
A filesystem call blocked in the kernel can delay return indefinitely. Manual `tego gc` has no startup
two-second budget. No retention selection, contract, run record or receipt format changes.

A deadline log includes the prune error's own cause. In particular, a busy lock remains named as busy
alongside the context deadline, including expiry while opening a retry after contention was observed.
The retry-open regression test spends the remaining budget in that open boundary; the previous
post-open cancellation branch discarded the known busy cause. The usual lock wait is 3 s, but a start's remaining 2 s budget can end
it sooner. `TestRunStartRetentionLogsBusyLockAtItsBudget` holds prune.lock through the start pass and
checks that its new log line carries both causes after exactly 2 s of controlled time. The same test
fails against the reviewed caller via an overlay.

`TestPruneLockedRewriteOutlastsBudget` spends controlled time filtering with journal.lock held and checks
four lines are committed after expiry. `TestPruneShortBudgetsMakeProgress` expires the budget at the checkpoint after the journal
rewrite is visible, then after each cleanup entry: six passes remove four lines, three blobs and two
contract locks. Its old lock-hook counter expired before acquisition, so it did not model an expiry
inside the locked operation. The separate locked-filter test above proves that boundary. The journal cleanup subcase in `TestPruneCancellationBetweenCleanupOperations`
is a regression guard of existing behaviour, not proof of a newly fixed defect.
