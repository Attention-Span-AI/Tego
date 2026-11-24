# ADR 0170: Live ledger segments and a rebuildable history index

Status: **proposed 2026-11-24**; designed, not built. Record revision stays 41: nothing here adds a kind or a field.

## Context

One run is one `events.jsonl`, one hash chain, one lock (ADR 0004). A 24/7 agent either runs without a ceiling or ends at
`record.max_run_bytes` and restarts as a new run with new budgets and answers. `tego status`, `measure` and `drift` read the whole
file: `BenchmarkDerive` on this tree is linear (9,800 events 0.34 s, 137,200 events 6.4 s on a loaded box; OPERATIONS.md
has 24.7 s for 2.64 million events). The public v0.1.3 verifier reads only `events.jsonl`, and its `chain.log` is closed: any
line that is not `<run> <head>` makes the whole file `anchor-malformed`. So a design that writes segment lines into `chain.log`, as
an earlier sketch did, would turn every v0.1.3 verification red.

## Decision

1. **A segment boundary is a plain line boundary.** `events.jsonl` stays segment 0. Later segments are
   `events.NNNNNN.jsonl` (six digits, 1 to 999999, consecutive). The next segment's first line continues the chain: `seq` plus one,
   `prev` the last id. There is no marker line and no new kind. The concatenation of the segments is byte-identical to the file a
   never-rotating writer would write. `verify(run directory)` is defined as `verify(concatenation)` under the v0.1.3 rules and
   reason codes, plus the naming rules: a hole is `chain-broken` at the first line after it, a non-last segment without its
   final newline is `line-malformed`, a segment after `run_end` is `after-run-end`, empty segments contribute nothing.
2. **One read path.** `ledger.Segments` and `ledger.Stream` (a reader over the concatenation with global byte offsets) are the only
   way outside `internal/ledger` to read a ledger, so every offset a consumer holds keeps its meaning. A structure test forbids
   naming `EventsFile` elsewhere. Exports (`tego events`, the dashboard's download, the CI receipt's `run/events.jsonl`) stream the
   concatenation, which an unchanged v0.1.3 verifier verifies.
3. **The writer ships last and off.** It rotates before a line when the segment is at `RotateBytes` (128 MiB), fsyncs the old
   segment, creates the next with `O_EXCL`, then writes. A crash at any step leaves a consistent prefix: an empty trailing segment
   is reused, a torn first line is cut, a torn tail in a middle segment refuses the resume. A failed rotation is soft. Retiring the
   oldest segments of a live run needs a record revision and is not part of this decision.
4. **The index is a cache of carried folds**, one record per sealed segment (`fold(carried state, segment)`), kept in a user cache
   outside the ledger root, rebuilt from the ledger whenever missing or stale, versioned by the fold's code. It is used by `status`,
   `measure`, `drift` and the dashboard's historical tabs, which say so (`from_index`, a footer line, `--no-index`). `events --verify`,
   `receipt`, the Binder, the CI receipt and every decision never read it. Validation on use is size, inode, mtime, ctime, the last
   line's recomputed id and the boundary link: it does not prove a segment's interior, and says so.

## Consequences

- A rotated ended run read by a v0.1.3 tool is reported unverified (anchored head not the ledger head, measured on this tree), and
  `status` calls it `lost`; a rotated live run reads as a valid prefix. Hence the writer is opt-in first.
- `tego measure` is "recomputed from the ledger alone" today. An index-backed report weakens that for speed; the maintainers decide.
- Six slices, each green alone: read path, moved readers, spec and public tools, writer, index, faster resume. The first three change no
  run and no record.
- Rejected: marker kinds (a record minor and different bytes), chain.log lines (breaks v0.1.3), an index validated by hashing the
  prefix (sha256 runs near 154 MB/s here, about half the decode), an index inside the run directory (the ledger root is the
  integrity boundary and the control process cannot write there).
- C66 is not reproduced as worded: the dashboard's Signal is folded incrementally (`BenchmarkSignalLiveAppend` 0.58 ms for ten lines
  against 18.4 ms for a full pass of 100,000).
