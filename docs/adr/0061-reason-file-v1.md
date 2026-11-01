# ADR 0061: Reason file v1: each refusal gets a number, a time and a pid, and the newest 32 are kept

Status: **accepted 2026-10-24**.
Implemented 2026-10-24: `pkg/spec/reason`, `spec/reason/v1/reason-file.schema.json`, and the ledger Writer's
`lastRefusal` (internal/ledger/writer.go). Amends the reason channel's channel 2 (spec/reason/REASON-CHANNEL.md §2)
and the Last refusal row of docs/p0/record-ledger.md §3. Removes the `internal/runtime/reason` placeholder.

## Context

`last-refusal.json` (and its run-readable copy, `TEGO_REASON`) held one thing: the latest refusal's
`RefusedPayload` with the line's reason and rule. A harness inside the run that tells the agent why it was refused
(the Claude Code hook) could not use it: two reads that saw the same op and target could not
say whether it was one refusal or two; a tool call that was refused three times showed only the last; and nothing
said whether a refusal had already been reported. The file is rewritten at most every 10 ms (`refusalWindow`,
2026-09-24), so a burst inside one window kept only its last refusal. And the definition had no home a Layer 3
adapter may import: `internal/runtime/reason` was an empty placeholder under the engine, which depguard keeps
adapters out of.

## Decision

1. **The file has its own version, v1, and one definition in Layer 0.** `pkg/spec/reason` (standard library and
   `pkg/spec/record` only) defines `File` and `Entry`, the codec (`Encode`, `Decode`, and `MinEntryBytes` for a
   writer that stops decoding early), `File.Since`, the sentences (`Text`), the agent's text (`Render`), the setup
   paragraph (`Instructions`) and the runtime-directory convention (`DirFor`). The engine writes through it and an
   adapter reads through it; neither imports the other. The file is not a ledger line: no record minor, its own
   `v`.
2. **Shape.** The top level is the latest refusal, with every key the file had before v1 (`op`, `target`,
   `reason`, `rule`, `mechanism`, `decision_plane`, `command_rule`, `command_match`) keeping its meaning, so a reader
   of the old shape reads the latest refusal as before. v1 adds `v` (1), `run`, `seq` (the refused line's ledger
   seq), `ts` (RFC 3339 with nanoseconds, UTC, the line's), `pid` (the line's), `text` (`reason.Text`), `refusals`
   (refused lines the run's ledger has written so far) and `recent`: the newest refusals, at most 32, oldest first,
   the latest last, each `{seq, ts, pid, op, target, reason, rule, text}` plus `mechanism`, `command_rule` and
   `command_match` when set. No other ledger field is copied: both key lists are fixed by a test, so a common field
   a later record minor adds, or a payload field, never reaches an agent-readable file unreviewed.
3. **Guarantees.** The file is always one whole file (temp file and rename). Its `seq` and `refusals` only grow from
   one write to the next, so a newer refusal is never followed by an older one. The 10 ms coalescing window, Close
   and Abandon behave as before. The mirror gets the same bytes as the run directory's copy. `recent` is contiguous:
   the refusals before its first entry are the run's first `refusals - len(recent)`.
4. **Off Append's path.** The ring of the newest 32 is filled in `post()`, under the refusal lock, with no file I/O
   and no decoding: what a payload costs to decode is the agent's to choose (a path within PATH_MAX made of control
   bytes is a 24 KiB payload, each byte escaped as six). `post()` copies a payload of at most 32 KiB into the
   slot's own buffer, kept from one refusal to the next, so the steady state allocates nothing; a longer one gets a
   copy of its own, as every refusal had before the ring. The flush copies the ring under the lock and decodes,
   words and encodes off the path, on its timer. Each refusal is decoded once, by the first write that lists it,
   which keeps its fields, cut, for the writes after; and a write takes the ring newest first and stops once the
   refusals it took pass the file even at their smallest (`MinEntryBytes`, a lower bound of an entry's encoded
   size), since `Encode` would list none older: the file is the same, and a flood of long targets costs a few
   decodes a write, not 32. *Amended 2026-10-24:* this first decoded a payload
   over 8 KiB in `post()`; see the implementation notes.
5. **The cursor is a count.** `File.Since(seen)` takes the `refusals` of the file the reader read last (0 for none)
   and returns the refusals after them that the file lists, and exactly how many more it no longer lists. A reader
   keeps its cursor in its own state; a forged cursor only hides refusals from the agent itself, and the ledger stays
   authoritative.
6. **Bounds.** The file is at most 64 KiB (`Decode` refuses a longer one). A target is a string the agent chose, up
   to the ledger's 2 MiB line, so `Encode` cuts every payload string past 4096 bytes, saying its length
   (`…(N bytes)`), leaves older refusals out of `recent` while the file is too long (the counts stay exact), and cuts
   a single refusal that still does not fit to 512-byte fields. The ring's memory is bounded whatever the agent
   refuses: 32 slot buffers of at most 32 KiB, their cut fields, and at most 2 MiB (the ledger's line bound) of
   longer payloads waiting whole for the write that decodes them. When the next long one would pass 2 MiB, the oldest
   refusals leave the ring instead, so `recent` stays contiguous, its last entry the latest, and the counts exact. The
   ledger line keeps every field whole.
7. **Wording.** `Text(reason, op, target, rule)` is one plain sentence for every code of the closed set ("Tego
   refused open "/home/u/.ssh/id_ed25519": files under that path are not readable in this run (rule
   fs.deny_read[~/.ssh])."): facts, never commands (Claude Code's hook documentation warns that command-like text
   can trip its prompt-injection defences). Every agent-chosen string is quoted with non-printable bytes escaped
   and `<` and `>` as `\u003c` and `\u003e`, and cut at 200 bytes with an ellipsis and its length. `Render` makes
   each line again from the entry's fields, never from the file's `text`, collapses identical refusals into one line
   marked `xN`, and stops at 4000 bytes with an "N more not listed." line. The goldens
   under pkg/spec/reason/testdata are the review surface for the strings, and a wording change changes only them.
8. **Paths.** `DirFor(uid, run)` is the unprivileged convention `/run/user/<uid>/tego/<run>/` only (TEGO_REASON
   names the file and wins). A root run's form is the root reason file's; root file modes stay `0600` here.

## Rejected options

- **A separate `refusals.json` beside `last-refusal.json`.** Two files double the flush cost (four with the mirror)
  and a reader could see them at different moments; one file renamed whole is one consistent view.
- **An append-only log on tmpfs.** Unbounded under a refusal flood, and tmpfs is RAM: the agent would choose how much
  of the machine's memory the log takes. The ring is bounded at 32 in memory and the file at 64 KiB.
- **Time windows from `duration_ms`** (a refusal belongs to the tool call whose time span holds it). `duration_ms` is
  optional in the harness's payload and parallel tool calls overlap, so a window cannot say which call a refusal was.
- **Transcript markers** (find what was reported by scanning the harness transcript). Transcripts are large and
  racy across parallel hooks, and Tego cannot know what the harness delivered.
- **A seq cursor** (`Since(seq)`). A seq says which refusals are newer but not how many of the ones the file no
  longer lists came after it; the count does, exactly. Each entry still carries its seq, which identifies it.
- **Embedding `RefusedPayload` in `File`.** It would put any field a later payload gains at the top level of an
  agent-readable file without review; the fields are listed instead, and a test fails when RefusedPayload gains one.
- **Decoding the payload in `post()`.** Allocations and microseconds on Append's path, at a cost the agent chooses.
  The first version decoded a payload over 8 KiB there to bound the ring's memory; review found a PATH_MAX path of
  control bytes takes that branch and doubles Append, so the bound is now the 2 MiB of waiting payloads (6).
- **Cutting the payload's JSON bytes in `post()` without decoding.** The cut strings' lengths, which the file
  states, would have to match what `encoding/json` decodes (invalid UTF-8 and lone surrogates become U+FFFD) byte for
  byte: a second JSON decoder to keep in step, for a case the waiting budget already bounds.
- **Keeping `internal/runtime/reason`.** depguard matches `internal/runtime` by prefix, so an adapter importing the
  placeholder would import the engine; the definition is Layer 0 data and lives in `pkg/spec`.

## Consequences

- The Claude Code hook reads `$TEGO_REASON` with `reason.Decode`, keeps `refusals` as its
  cursor, and shows `reason.Render(f.Since(cursor))`; `Instructions` is its setup paragraph.
- `spec/reason/v1/reason-file.schema.json` publishes the shape. Here an agreement test keeps the schema's keys and
  required keys equal to the Go types'; the JSON Schema validator over the writer's output lands with
  the record schema work, which adds the validator to go.mod.
- The depguard rule `reason-spec-is-leaf` (pkg/spec/reason imports the standard library and pkg/spec/record only)
  lands with the run plumbing; the package holds to it now.
- Performance (BenchmarkRefusalFlood, landed before the change, and BenchmarkRefusalHostileTarget, landed before
  a later fix, both gated in scripts/bench-gate.sh): the parent and the change measured in separate trees under
  the capped slice, compared with benchstat; the numbers are in the implementation notes below.

## Tests

pkg/spec/reason: TestEntryFieldsAreTheListedOnes, TestTheTopLevelIsTheFileBeforeV1, TestSinceCountsWhatIsNotListed,
TestEncodeBoundsTheFile, TestDecodeRefusesWhatIsNotAWholeFile, TestEveryReasonCodeHasASentence, TestSentencesAreFacts,
TestTextGolden, TestQuoteNeutralizesWhatTheAgentChose, TestRenderGolden, TestRenderAccountsForEveryRefusal,
TestReasonFileSchemaMatchesGo, FuzzDecode, FuzzEncodeFits. internal/ledger: TestRefusedWritesLastRefusal,
TestLastRefusalIsRewrittenNotAppended, TestLastRefusalIsCoalescedOffTheAppendPath,
TestLastRefusalIsMirroredWhereTheRunCanReadIt, TestReasonFileListsTheNewest32 (100 refusals in one window: 32 listed,
100 counted, 68 not listed), TestReasonFileOrderUnderConcurrentAppends (-race), TestAppendDoesNoReasonFileIO,
TestReasonFileBoundsAnAgentsLongTarget, TestPostNeverDecodesOnAppendsPath, TestEachRefusalIsDecodedOnce,
TestReasonFileStaysContiguousWhenLongRefusalsOutrunItsWrites, TestAResumedWriterCountsTheRefusalsTheLedgerHolds,
TestAbandonWritesThePendingRefusalAndNothingAfter, TestAWriteDecodesOnlyTheRefusalsTheFileCanList (the file is
Encode's of the whole ring); FuzzEncodeFits also checks that `MinEntryBytes` never exceeds an entry's encoded size.
internal/runtime (integration): TestTheAgentCannotReadTheLedgerButReadsItsReason reads seq, refusals and recent from
inside the run.

## Implementation notes

- 2026-10-24, performance. The parent (BenchmarkRefusalFlood already in) and the change, in two trees,
  test binaries run alternately under `taskset -c 0-3` in the capped slice, `-benchtime 1s -count 10 -benchmem`,
  compared with benchstat. ns/op: no difference at p<0.05 on any of Append (10.72 → 10.23 µs, p=0.80),
  AppendRefused mirror=false (14.00 → 13.96 µs, p=1.00), mirror=true (14.06 → 17.04 µs, p=0.44) and RefusalFlood
  (12.43 → 12.50 µs, p=0.58); the machine was shared with other jobs, so the spread was ±40–60%, and an earlier
  interrupted run (n=5–6) read 5.97 → 6.67, 9.09 → 8.11, 8.39 → 8.37 and 7.06 → 6.33 µs, also with no significant
  difference. allocs/op: Append unchanged (15); a refused line falls from 21 to 19 (RefusalFlood 17 to 15) and
  B/op by 12–19%, because a ring slot reuses its payload buffer where post() had allocated an Event and a payload
  copy for every refusal.
- 2026-10-24, an agent's long targets. `post()` decoded a payload over 8 KiB on Append's path; a
  PATH_MAX path of control bytes is 24 KiB and took that branch, and BenchmarkRefusalHostileTarget (landed first) showed it: against the parent, pathmax 136 → 294 µs/op and long 2.1 → 4.6 ms/op. Now `post()` copies,
  the write decodes once, newest first, and stops where the file is full. Three trees (the parent with the new
  benchmark, the code before the fix, the fix), `taskset -c 0-3`, `-count 20`, alternating, benchstat. Fix against
  before: pathmax −47% ns/op, −69% B/op, 29 → 16 allocs; long −49%, −49%, 177 → 36 (all p=0.000). Fix against the
  parent: no ns/op difference at p<0.05 on any benchmark (Append 5.33 → 5.56 µs p=0.68, AppendRefused 7.27 → 7.21
  and 7.20 → 8.29 µs p=0.66 and 0.10, RefusalFlood 5.37 → 5.90 µs p=0.23, pathmax 136 → 156 µs p=0.09, long 2.12 →
  2.34 ms p=0.31); B/op −13 to −21% on every refused benchmark but long (unchanged, p=0.93); allocs/op Append 15 =
  15, refused lines 21 → 19, RefusalFlood 17 → 15, pathmax 17 → 16, long 25 → 36. The benchmarks count the write's
  goroutine too: long's extra allocations are its decodes (up to three a write, where the parent decoded one), with
  its bytes unchanged; on Append's path `post()` allocates nothing up to 32 KiB and only the copy past it
  (TestPostNeverDecodesOnAppendsPath), one allocation fewer than the parent's Event and copy. The spread (±7–32%)
  on this shared machine is wider than the 5% bar, so `-count 20` shows no regression at p<0.05 but cannot exclude one
  under 5%; this was the machine's quietest measurement (load average 2.5–5 on 16 threads).
- 2026-10-24, resume. `refusals` is the run's refused lines: a Writer that resumes a run (today only
  gc's, which appends no refused line) counts those already in events.jsonl while it walks them, so the count keeps
  growing across the resume and a reader's cursor still sees the next refusal. The ring starts empty; `Since`
  reports the refusals before the resume as not listed. TestAResumedWriterCountsTheRefusalsTheLedgerHolds.
- 2026-10-24, the placeholder's name. After the deletion, `git grep internal/runtime/reason`
  finds only historical text carrying an Amended note.
- 2026-10-24, a cut's length. The writer keeps every refusal's fields cut to 4096 bytes once
  it decoded them, and a second cut of that copy stated the copy's length: the single refusal's tight form said
  `…(4096 bytes)` of a 100004-byte field, and the sentence's 200-byte cut said `… (4096 bytes)` of any target past
  4096 bytes (from `Encode` itself, which built the sentence from the cut fields). `Refusal.Cut` is now that first
  cut and keeps each cut field's length beside it; every later cut, and `text`, states the real length, so the file
  is the bytes `Encode` makes of the uncut refusals (TestAReasonFileCutStatesTheFieldsRealLength,
  TestEncodeStatesACutFieldsRealLength, and FuzzEncodeFits checks it). Rejected: reading the length back from a
  string's `…(N bytes)` end, since an agent's own string can end the same way; keeping the decoded fields whole in
  the ring, which undoes the ring's memory bound. `Render`, which has only the file, quotes a cut field as the file
  holds it, so its `… (N bytes)` is the field's length in the file; the real length is the field's own end and
  `text`, which `Render` does not take for the same reason.
- 2026-10-24, wording. `Instructions` says `recent` lists *up to* the newest 32: under the 64 KiB bound `Encode`
  may list fewer when targets are long.
