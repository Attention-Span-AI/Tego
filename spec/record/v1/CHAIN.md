<!-- SPDX-License-Identifier: Apache-2.0 -->

# The chain check (record v1, integrity scope)

What a reader checks to say "the chain of these record bytes matches", and the reason code it gives when it does
not. This is the integrity of the bytes only: a match says the lines are the chain a writer made and, with an
anchor, that none was cut from its end. It does not say the record is true or complete, that a receipt's totals
are right, or who wrote the files: whoever can write both `events.jsonl` and `chain.log` can make a matching pair.

Go's `pkg/spec/record/chaincheck` is held to this page by the shared vectors in
[`vectors/chain`](vectors/chain/README.md). `tego events <run> --verify` uses it with the schema check of
`Event.ValidateAt` on top. Added 2026-11-11 (ADR 0146): Go remains the only enforcer; this release extracts pure
chain checking and publishes shared vectors. A second, independent checker is planned, not shipped.
Each rule below that `README.md` did not state, and that was read from Go, is marked *(written down 2026-11-11)*.

## 1. Inputs

A run directory and, optionally, an anchor file. The run directory holds `events.jsonl`; its lock file is `lock`.
The anchor is the `chain.log` its writer appended the run's head to (`README.md`, `run_end`).

## 2. Framing

A file is split at each `\n` (0x0A); a line is the bytes before it. Only the last line can lack its `\n`.
*(written down 2026-11-11)*:

- A line whose bytes, its `\n` included, number more than 2 MiB (2,097,152) is a finding (`line-too-long`) wherever it
  is, the last line too; `chain.log` is held to the same bound (`anchor-malformed`).
- `\r` is an ordinary byte of a line: a `\r\n` line's digest covers its `\r`, and JSON reads the `\r` as white space
  after the object.
- Once a top-level JSON value has closed on an unterminated final chunk, the entire chunk is a record line and is
  checked, whatever follows that value on the same chunk. For an object or array, closure is matching brackets
  outside strings, independently of grammar, nesting depth, field types, version, timestamp or digest. For a scalar,
  its grammar must read one value; the rest of the chunk is still retained. In particular, `0` and `-0` close before
  a following digit; the entire chunk still fails the record's object requirement. A closed container with bad grammar
  or excessive depth is `line-malformed`. Non-whitespace bytes after the closed value, including an opened second
  object, make the line `line-malformed`; they cannot hide the line as a torn tail.
- Trailing JSON whitespace (space, tab or carriage return) after a closed value without a newline is a complete
  line, permitted by §3. Its bytes remain covered by the digest (§4); appending whitespace without updating the id
  gives `id-mismatch`. A refused v1 timestamp in such a line gives `line-malformed` even with a stale digest.
- A torn tail is only a final chunk in which no top-level value has closed: not a line, its size reported, and the
  check goes on without it (record-ledger.md E6, E8). `README.md` points to this rule.
- An empty line (`\n\n`) is a line, and is malformed.

## 3. A v1 line's structure

*(written down 2026-11-11)* A line is one JSON object (RFC 8259) with white space allowed around it and nothing else,
read with these rules:

- Its arrays and objects nest at most 10,000 deep, the line's object counted as 1.
- Its top-level keys are unique after decoding (an escaped spelling of a key is that key). Keys and values nested
  deeper are payload content and are not held to uniqueness.
- A byte inside a string that is not part of a well-formed UTF-8 sequence reads as U+FFFD, one per byte; a `\u`
  escape naming a surrogate that is not the first half of a pair followed at once by an escape of the second half
  reads as U+FFFD. Neither is an error. The digest covers the bytes as they are.
- `v` is present and is a signed 64-bit JSON integer (-2^63 to 2^63-1, an optional `-` and digits, no fraction or exponent).
  The value 1 is this version; values 2 to 2^63-1 are newer lines (§5). A value below 1 or outside the signed
  64-bit range is malformed. This range preserves the released Go reader's version gate.
- The twelve common fields `seq id prev ts mono_ns run agent pid tid cgroup kind source` are present. `seq`,
  `mono_ns` and `cgroup` are integers written with digits only, 0 to 2^64-1; `pid` and `tid` are integers, -2^63 to
  2^63-1 (a `-` and digits; no fraction or exponent); `id`, `prev`, `run`, `agent`, `kind` and `source` are strings;
  `ts` is a string holding an RFC 3339 date-time: `YYYY-MM-DDTHH:MM:SS`, an optional `.` and one or more digits, then
  `Z` or `+HH:MM`/`-HH:MM`, a real Gregorian day, hours 00 to 23, minutes and seconds 00 to 59, an offset's hours 00
  to 23 and minutes 00 to 59. This is a profile of RFC 3339: of the choices the RFC leaves to a specification it takes
  `T` and `Z` upper case only (RFC 3339 §5.6) and no leap second; every Tego writer writes UTC with `Z` and an optional `.`
  fraction, inside it. (Go's reader also took a comma fraction, a one-digit hour, offset hour 24 and offset
  minute 60 until 2026-11-11, ADR 0146 "First finding"; no Tego writer ever wrote these forms.)
- `rule`, `verdict`, `authority` and `reason`, when present, are strings. `attribution`, when present, is `null` or an
  object in which a member named `thread`, `tool_use_id`, `confidence` or `method` holds a string or `null` and one
  named `step` an integer (-2^63 to 2^63-1) or `null`. Attribution member names match by Unicode simple case folding,
  as the released Go reader's `encoding/json` struct decoder has always matched them: each Unicode scalar is replaced
  by the smallest scalar in its simple-fold equivalence class, without normalization or multi-character expansion.
  Thus `Step`, `STEP` and `ſtep` (U+017F) name `step`; `confıdence` (U+0131) and `confİdence` (U+0130) do not name
  `confidence`. For these ASCII field names, only ASCII letter case and U+017F for `s` can change a match (U+212A
  also simple-folds to ASCII `k`, which none of these names contains). Every member that matches is held to the type.
  Other members are not read. Top-level member names use exact equality after JSON string decoding and UTF-8 repair;
  attribution's folding rule does not apply to them.
- Every other key is payload and is not read by this check (a validating reader holds it to `README.md`).

A line that breaks any of these is `line-malformed`.

## 4. The digest

`id` is `hex(sha256(line))`, lower-case, where `line` is the line's bytes without its `\n` and with the id's 64
characters replaced by 64 `0` characters in place (`fixtures/README.md`; record-ledger.md R2). *(written down
2026-11-11)*: a reader finds the id where the canonical writer puts it and nowhere else: the line starts with exactly
`{"v":1,"seq":` (no white space), then one or more digits, then exactly `,"id":"`, then 64 characters of
`0-9a-f`, then `"`. A line not of that shape is `line-malformed`; one whose id is not the digest is `id-mismatch`.
The reader never re-serializes a line. The JSON object/unique-key gate precedes the digest, so malformed trailing
content gives `line-malformed` even with a stale digest. A v1 line's timestamp is also checked before the digest and
the other common fields; a refused timestamp gives `line-malformed` even if the digest is stale. Otherwise the
digest is checked before the remaining structure: a line that fails both reads as its digest's finding. The version
gate precedes the timestamp check; a newer version's timestamp is not interpreted.

## 5. The chain

Line *n* (from 0) has `seq` *n* and `prev` the id of line *n*-1; line 0's `prev` is the empty string `""` (written,
not absent) *(written down 2026-11-11)*. A line that breaks either is `chain-broken`.

A line whose `v` is an integer from 2 to 2^63-1 was written by a newer binary (limits-check-doctor-cli.md §6 case 20). Its
content is not read; its link is: it is one JSON object with unique top-level keys, its bytes start with exactly
`{"v":<v as written>,"seq":`, its id is the digest of its bytes (§4, from that prefix), `seq` is an integer 0 to
2^64-1 and `prev` is present and a string. Its `run` and `kind` are read when they are strings (else they are empty).
It then links as any line does and counts in `newer`.

## 6. The run

*(written down 2026-11-11; record-ledger.md §4)*

- The run checked is the run directory's name: the last component of the path given, made absolute (from `$PWD` when
  it names the working directory) and lexically cleaned, when that is a run id (`r-` + 8 of `[0-9a-f]` + `-` + 13 of
  `[0-9a-z]` + `-` + 6 of `[0-9a-z]`), even when it is a link to another run's directory. A last component that is no
  run id (a link such as `~/latest`) is followed one link at a time, at most 40, to the first name that is a run id;
  a chain that reaches none gives the directory's resolved path, and the run is then the first line's `run`.
- Every line's `run` is that run (`run-mismatch`). The line is counted in `lines`: it chained before it was refused.
- Line 0 is a `run_start` and no other line is (`run-shape`); a newer line's `kind` counts as a v1 line's does.
- No line follows a `run_end`, and no torn tail does either: a torn tail is a dying writer's, and the writer of
  `run_end` was not dying (`after-run-end`).
- A ledger with no line, or whose chain matches but holds no `run_start`, is no run to check: `cannot-check`,
  `no-run-start`.

## 7. The anchor

*(written down 2026-11-11; record-ledger.md §4, E28, E29)*

- `chain.log` holds one line per closed run, `<run id> <event id>\n`: the run id, one space, the 64-character head,
  nothing else (no other space, no `\r`). An unterminated last line is a torn append and is skipped.
- Any other line makes the whole file `anchor-malformed`, for every run, wherever it is. Two lines for the run naming
  two heads are `anchor-malformed`; the same line twice is one anchor.
- An anchor path that names no file anchors nothing. One that names a link or a non-regular file cannot be read
  (`cannot-check`, `unreadable`).
- With an anchor given, a run whose name is no run id cannot be looked up: `run-id-invalid`.
- When the anchor holds a line for the run, its head is the ledger's head (the id of its last line), whether or not the
  ledger ends in `run_end`; otherwise `anchor-mismatch`. A reader that scanned short of `run_end` rescans once before
  it reports this, since a launcher inside Close may anchor between the scan and the read. The rescan rewinds the
  original ledger descriptor; a replacement under `events.jsonl` cannot substitute a different record.
- An ended run with no anchor line is `anchor-missing`, unless its lock is held: a launcher still inside Close anchors
  last, so a reader waits up to 2 s and then answers `cannot-check`, `run-closing`. A run that has not ended owes no
  anchor line.
- With no `events.jsonl`: when the anchor holds a line for the run, `ledger-missing`; when `events.jsonl` is a link, a
  FIFO, a directory or any other non-regular file, `ledger-replaced`; with no anchor line, `cannot-check`
  (`no-ledger`, or `unreadable` for a non-regular file).
- Without an anchor, lines cut from the end of a ledger are not seen: a reader says so.

## 8. Verdicts and reason codes

| Verdict | Reason | When |
|---|---|---|
| `match` | `ok` | every check above held |
| `mismatch` | `line-malformed` | §3, §4, §5 |
| | `id-mismatch` | §4 |
| | `chain-broken` | §5 |
| | `run-mismatch`, `run-shape`, `after-run-end` | §6 |
| | `line-too-long` | §2 |
| | `run-id-invalid`, `anchor-malformed`, `anchor-mismatch`, `anchor-missing`, `ledger-missing`, `ledger-replaced` | §7 |
| `cannot-check` | `no-ledger`, `no-run-start`, `run-closing`, `unreadable`, `internal` | nothing is said about the record |

The first finding in reading order is the one reported: framing and lines in order (for one line: framing, then
after-run-end, then the JSON object/unique-key gate, a refused v1 timestamp, the digest, the remaining structure,
the chain, the run, the shape), then the tail, then the anchor. A finding
about one line names it (`line`, its number from 0). `lines` counts the lines the chain held through; `head` is the
last of their ids. A validating reader (Go's `tego events --verify`) may also report a schema finding of its own.

`tego-verify` exits 0 for `match`, 1 for `mismatch`, 125 for `cannot-check` and 2 for a usage error, and labels every
result with `scope: integrity` and `checked_by` (the checker and its version). Two implementations agree when their
verdict, reason, `line`, `lines` and `head` agree; their words and `checked_by` differ by design.
