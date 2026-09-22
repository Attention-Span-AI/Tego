# ADR 0004: the ledger is the only store

Status: accepted 2026-09-21.
Decision: one append-only `events.jsonl` per run plus content-addressed blobs; every view is recomputable from it; no database in the binary. An index for `serve` may be added later as a cache, never as a source of truth.
