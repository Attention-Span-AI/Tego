<!-- SPDX-License-Identifier: Apache-2.0 -->

# Chain vectors

The shared vectors of the chain check ([`../../CHAIN.md`](../../CHAIN.md)). Each `NNN-<name>.json` is a run directory's
files and the answer the spec gives for them, written by hand (ADR 0017: no expectation is computed by an
implementation). Two Go runners read them: the pure check (`pkg/spec/record/chaincheck`,
`TestSharedChainVectors`) and the reader over real files (`internal/ledger`, `TestSharedChainVectorsOnDisk`).
`vectors.go` embeds them for these runners. Go remains the only enforcer; this release extracts pure chain
checking and publishes shared vectors. A second, independent checker is planned, not shipped.

## A vector

| Key | Meaning |
|---|---|
| `name`, `rule` | The case, and the CHAIN.md section it is written from. |
| `dir` | The run directory's name. |
| `events` | `events.jsonl` as segments, or `null` for a run directory without one. |
| `anchor` | `chain.log` as segments; `null` for no anchor given; `"absent"` for an anchor path that names no file. |
| `expect` | `verdict` and `reason` (CHAIN.md §8), and, when stated: `line` (the line a finding names, from 0; absent means the finding names none), `lines`, `head_line` (the head is the id written on that line of `events`), `anchored`, `torn_bytes`, `newer`. A cannot-check is judged on verdict and reason alone. |
| `finding` | Only on a vector where Go and the spec disagree: `label`, `why`, and `go`, Go's answer today. Go's runners hold Go to `go` and log the finding, so they fail the day Go changes; every other runner holds `expect`. A finding is open until one side changes; it is never a skip. |

A segment is `{"text": s}` (UTF-8), `{"hex": h}` (raw bytes) or `{"repeat": s, "count": n}`.

## Making them

`make_inputs.py` builds every file from the frozen fixture run `../../fixtures/profiles.jsonl` and its anchor. The
`expect` and `finding` literals in it are the handwritten content; the script computes only what a writer would
have, the ids of the lines a case rewrites, with Python's `hashlib` (a third implementation of the digest). Add a
case there and run `python3 -I make_inputs.py`; it rewrites every `NNN-*.json`. A minimised input a differential run
finds becomes a case the same way, labelled Go bug, Rust bug or spec gap.

## Findings

None open. Closed:

- `go-ts-lenient` (077, 078), found 2026-11-11: Go read `ts` with `time.Parse(time.RFC3339Nano)`, whose fallback took a
  comma before the fraction, a one-digit hour and offsets with hour 24 or minute 60, where CHAIN.md §3 refuses them.
  Decided the same day: Go is strict (`pkg/spec/rfc3339`; ADR 0146, "First finding"). Vectors 087 to 102 also hold
  complete final record lines to the timestamp profile with or without a newline and with stale or recomputed ids:
  a refused timestamp cannot hide the final record as a torn tail. Vectors 106 through 129 retain a closed final
  value with trailing garbage, an opened second object or JSON whitespace, with no anchor, an empty anchor and a
  populated anchor. They include refused timestamps and stale/recomputed whitespace digests. Vectors 127 through
  129 retain the closed zero prefix before another digit. The suite has 129 vectors.
- Attribution names use the released Go reader's Unicode simple case folding (080, 081, 086). U+0130 and U+0131
  stay unknown member names; U+017F can name the `s` of `step`.
- The version gate reads signed 64-bit integers (082 to 085); values 2 through 2^63-1 are newer versions, and
  values below 1 or outside that integer range are malformed.
