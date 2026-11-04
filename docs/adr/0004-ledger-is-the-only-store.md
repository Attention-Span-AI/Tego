# ADR 0004: the ledger is the only store

Status: accepted 2026-09-21.
Decision: one append-only `events.jsonl` per run plus content-addressed blobs; every view is recomputable from it; no database in the binary. An index for `serve` may be added later as a cache, never as a source of truth.


Amended 2026-11-03 (dashboard correctness review M2/M5): the dashboard cache keeps
bounded recent event windows and incremental run totals, with byte offsets into the
ledger. Eviction includes active runs. A derived view over a window must disclose
that earlier history is absent; full history stays authoritative on disk and can be
streamed or scanned with bounded retention. Cache estimates charge every retained
event string, including envelope fields absent from the payload, and reserve space
for indexes and folds. They are not an RSS cap or a full-history Signal summary.

The pipeline and DNS writer prepare each refused action and its mirror before
`Writer.AppendBatch` appends both under one writer mutex. Each retains its own
sequence, hash and write; concurrent writers cannot interleave them. A failed batch
can leave an already written prefix and requires the same fail-stop handling as a
failed append. No record field changes; old displaced mirrors remain ambiguous.

Amended 2026-11-03 (dashboard correctness review, round 2): pending approvals
outlive event windows, so their separate 8 MiB estimate charges every retained
string (`Run`, `Agent`, `AskID`, `Hold`, `Op`, `Target`, `Rule`). The receipt's
streaming pass needs pending identities to compute exact unanswered totals. It
tracks at most 32,768 identities and 8 MiB estimated identity state (128 bytes per
entry plus ID bytes), independently of its 1,000-row display cap. Answers release
that state. If either pending limit would be exceeded, the pass stops with
`receipt.ErrAskLimit` and returns no receipt, including when later lines could
answer the oversized prefix. The CLI and Receipt tab surface the error. There is
no disk-backed identity index and no partial receipt with claimed exact counts.
