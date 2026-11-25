# ADR 0159: `tego run` keeps the run's bound receipt as receipt.json, and `tego receipt --verify` compares it

Status: **accepted 2026-11-24**; built. The number is the next free one under `docs/adr`. Builds on
ADR 0004 (the ledger is the only store) and ADR 0143's binding; adds no record field and no receipt field.

## Context

The receipt of a run is built from its ledger on every read: `tego receipt`, `tego run`'s end summary and the dashboard's
Receipt tab all run `receipt.Compute`. The V1 receipt specification (accept items 5 and 6) also asked for a copy
written into the run directory when the run ends, and for `--verify` to compare that copy with a rebuilt receipt. Neither
was built: a person who wanted the receipt as a file ran `tego receipt <run> --json > receipt.json` by hand and kept the
two together (OPERATIONS, "Keeping a receipt").

## Decision

1. **When.** After `runtime.Run` returns and the end summary's one pass over the record has finished, `tego run` and
   `tego watch` place `receipt.json` in the run's directory. The pass that makes the summary also binds the receipt
   (`receipt.Options.Bind`) and prices it from the machine's table, so a long record is still read once
   (`TestEndSummaryReadsTheLedgerOnce`) and the summary's words do not change. The file's bytes are exactly what
   `tego receipt <run> --json` prints for that record. `--no-summary` silences the summary; it does not stop the copy.
2. **How.** `ledger.PlaceRunFile` (the one placing function `tego stop`'s marker uses): a new name only, never over a
   file or a link already there, no link followed, mode 0600, handed to the directory's owner when the launcher is root.
   A name already taken is left as it is and one warning line says so.
3. **When not.** No run id (the run never started); a record that could not be completed (`Result.RecordErr`); a tego
   run that was interrupted; a tego that is no exact build (`receipt.Exact`: a version with `+dirty`, or no version or
   commit stamp), whose figures no tego could compare, so it keeps none and says nothing; a receipt that could not be built or bound (the binding's own words are the warning),
   which includes a tego whose own executable cannot be read to hash it (the hash is read before the one pass, so the end
   summary is the one it would be without keeping; only the copy is not kept, with one warning). A
   failure to build or write is one warning line on stderr and never changes `tego run`'s exit code: the run's own
   outcome is the exit, and the receipt can be rebuilt at any time.
4. **`--verify`.** After the chain and its `chain.log` anchor, a run directory that holds `receipt.json` has it checked
   with `receipt.Check`, the comparison `tego receipt --check` makes: the checksum, the binding, the build, and every
   figure recomputed from the record (what only the price table or the clock of the machine that made it gives is not
   compared). The chain has just verified, so everything said here is about the kept copy only, and the message says so
   (`the record verified; only the kept receipt <path> differs from it: ...`, code `[receipt-differs]`).
   - `Kept receipt: <path> matches the record.`, exit 0.
   - A difference names the first check that failed, exit 1. So does a name that holds no regular file (a link, a pipe, a
     directory: none is opened), and a file that is no receipt this tego reads (text, an empty file, another JSON object).
   - A receipt of a receipt or binding version this tego does not read (a later release's form) is exit 125 with the
     words that say only the copy is unchecked and who can check it. It is not a pass: any file can claim a later version.
   - `made_by` is the one check that may not run for a copy that is the run's own. `receipt.Check` compares the figures
     only for the exact build that made the receipt, so after an upgrade, from a dirty build or one with no stamp,
     `made_by` and `facts` are not-checked while `run`, `chain`, `head` and `bytes` pass. That is a note, not a failure,
     but only for a copy that names the right maker: the record's `run_start` names the tego build that ran the run, and a
     copy `tego run` keeps was made by that build. `--verify` therefore compares `binding.receipt_by` with `run_start`
     before it gives the note. A copy that names another maker, or one no tego keeps a copy for (no exact build), was not
     kept by `tego run`: exit 1, `it names tego X as its maker, and this run was made by tego Y`. So is a copy in a run whose
     record is of an older revision than the first that keeps a copy (`run_start`'s `record_minor` below 41: every release
     up to v0.1.3): that build is named exactly and may be as exact as any, but it never kept a copy, so whatever its agent
     left at the name is not tego's, however its seal and its maker read; exit 1, `the run was made by tego X at record
     revision N, a build that keeps no receipt`. The revision is read from the chained record, where the agent cannot change
     it (`CheckResult.RecordMinor`, never written into the check's output). Only a copy that names
     the run's own build, in a run of a build that keeps a copy, checked by another exact build, gets `Kept receipt: <path>: the record's chain, head and bytes
     are the ones it names; its figures were not compared: <why>.` and exit 0 (the chain it verified just above is the
     proof), never `matches the record`.
   - Any other check that did not run keeps 125, and a changed count, head or byte count is exit 1 for every build.

   A run with no `receipt.json` says nothing more than before. The CI action's collect step never reads the kept copy: it
   builds its own receipt from the record, so a `--verify` that exits 1 or 125 only because of a planted `receipt.json`,
   on a record whose own chain verifies, is a warning there and not a failure.
5. **Retention.** The file is part of the run directory, so `tego gc` removes it with the run. A temporary file a crash
   leaves between the write and the link (`.receipt.json.<n>`) is removed by the next `Open` of that run, which for an
   ended ledger never comes: it stays until `tego gc` removes the run. It is hidden and holds a partial copy of what the
   record already holds.

## What it is not

The kept copy is a convenience, not evidence. The launching user can rewrite the record and the copy together, and
`receipt.json` says so in its own `limits`; `--verify`'s chain check against `chain.log` is what vouches for the record,
and the comparison shows only that the copy is the receipt that record gives. A run in a record-only mode, whose agent
may write its own run directory, can delete the copy, or write its own before the run ends (the run's end then says once
that the name was taken and leaves the file): the comparison finds a changed figure, a maker the record does not name, a
file that is no receipt, and a deleted copy is told by silence only. What the comparison cannot do is tell a forged copy of
the run's own build from the real one when the checking tego is another build: it cannot compute that build's figures, and
says so in the note. Run the check with the build named in the note for a verdict on the figures. The CI receipt (ADR 0143)
is a different file with a different job: it is made in a separate job from a frozen copy of the run and signed there.

## Proof

`TestRunEndKeepsTheBoundReceipt`, `TestKeptReceiptDoesNotChangeTheSummary`, `TestKeptReceiptIsNeverReplacedOrFollowed`,
`TestKeptReceiptIsSkippedWhenTheRunHasNoCompleteRecord` and `TestVerifyComparesTheKeptReceipt` (clean, a changed figure,
another receipt version, absent, a changed ledger line), `TestVerifyAnotherBuildIsANoteNotAnError` (a later release, a
dirty build, no stamp: exit 0 with the note; a changed count exit 1; a file that is no receipt exit 1),
`TestVerifyRefusesAKeptReceiptThatNamesAnotherMaker` (a figure and `receipt_by` edited and sealed again, for five makers
under three checking builds, with the controls),
`TestVerifyRefusesAKeptReceiptOfABuildThatKeepsNone`, `TestVerifyRefusesAKeptReceiptInARunOfAnOlderRevision` (a copy
planted in a run of revision 0, 30 and 40 that names the run's own exact build, with and without edited figures, under
three checking builds, with the controls at revision 41), `TestCheckReportsTheRevisionRunStartOpens` in
`internal/check/receipt`, `TestVerifyKeptReceiptOfALaterFormat`,
`TestVerifyAPlantedFileIsOnlyTheCopyThatDiffers` (text, empty, another JSON object, another run's receipt, a link, a pipe,
a directory), `TestSummaryKeepsItsReceiptWhenTheExecutableCannotBeHashed`,
`TestRunKeepsNoReceiptFromABuildNoTegoCanCheck` and `TestRunRunPlacesTheReceipt` (`runRun` itself, for `tego run`,
`--no-summary` and `tego watch`; red with the placement call replaced through `go test -overlay`) in `internal/cli`;
`TestPlaceRunFile` and `TestOpenSweepsTheTempFilesOfADeadWriter` in `internal/ledger`; the action's offline suite for the
collect step. Owed in a guest and built as one script: a root launcher placing the file in a user's ledger root (the
handover is `placeNewFileAt`'s, proved for the stop marker by `TestPlaceNewFileAsRootRefusesALinkedRunDirectory`), the
upgrade with a second exact build, the forge, an agent that plants the file in a record-only run, and the same write
refused under an enforcing tier.
