# ADR 0146: Rust is a second, independent implementation of the pure core; Go stays the only enforcer

Status: **proposed 2026-11-11**. Phase P0 built: the pure Go chain check
(`pkg/spec/record/chaincheck`), `spec/record/v1/CHAIN.md` and its handwritten vectors, `rust/` with `tego-record`
and `tego-verify chain`, the differential (`test/rustdiff`) and `make rust-check`. The Go checker, RFC 3339 leaf and chain spec/vectors are admitted to the public engine export.
Rust, the differential and `rust-check` remain explicitly private; public Rust shipping requires the owner's later
decision (P3). No Rust release or CI integration is claimed. Adds to [ADR 0001](0001-go-for-the-engine.md) (its Rust runtime behind `spec/` stays open and is not
this decision). Builds on [ADR 0017](0017-kernel-conformance-suite.md) (expectations are handwritten), ADR 0028 (the
decision core is pure), ADR 0048 (the exec matcher), ADR 0007 (a later rule only tightens). Amends
docs/REPO-LAYOUT.md's growth path (a `rust/` workspace beside the reserved `runtime-rs/`) and the rule "no new
third-party dependency", for the `rust/` tree only and only for the crates and versions `rust/deny.toml` names.

## Context

The decision separates pure logic from code that touches the machine so an independent checker can check the
same written rules without gaining authority over a live action.

Measured on 2026-11-11 on the dev box (i7-10870H, Go 1.27.4, GOMAXPROCS=4) unless marked:

- The engine: `internal/runtime` is 102,275 lines of Go; `tego` is 27.5 MB static (10.6 MB gzip).
- Where a user waits: a run's fixed start is 51.5 ms, mostly cgroup, Landlock, seccomp and ledger setup (read:
  historical startup measurement, 2026-09-22, stale). An exec under the supervisor costs about 700 µs over bare (read: one guest
  experiment, 20 execs). The exec matcher's own decision is 0.6 to 4.5 µs on its benchmark fixtures, and its guarded
  cases allocate. These are selected fixtures against another experiment's average, not a bound for every rule.
- The read side: `record.VerifyLine` is 1.8 µs a line.
- The pure core: `internal/policy/decide` 8,112 lines, `pkg/policy/execmatch` 6,448, `pkg/policy/gate` 1,022 and small
  matchers. depguard holds four of them pure, and depguard sees direct imports only.
- The chain check was not pure: `internal/ledger`'s `Reader.Verify` opened files, probed the run lock and waited on a
  clock in the same function that decided. This release extracts it (below).
- Not separated: `pkg/spec/agent` (22,903 lines) mixes contract parsing with host work; 37 of its 78 files import os,
  syscall, net, time or x/sys. `thishost` is pure but its live input refreshes from the host on a clock.
- The v0.1.2 flaw in the exec matcher was a finality bug (`Final`, prefix extension) found by a property test
  comparing two readings of one command; whole-vector answers stayed identical across the fix.

## Decision

1. **Go is the only implementation that decides a live action.** No Rust code runs inside `tego run`, the
   supervisor, the BPF loader or any enforcement backend: there is one kernel enforcer. What can be held by the
   repository: no production Go package imports, starts or reads the output of a Rust program. A check holds it (P3):
   `tools/oss` and a test refuse an `os/exec` or `proc.Start` of `tego-verify` or any `rust/` artifact outside `test/`,
   and depguard keeps `test/rustdiff` the only Go importer of the differential's code. What the repository cannot hold:
   a CI job that deploys after `tego-verify` exits 0, or a person who reads its result as approval. So every Rust
   result is labelled with its scope and authority (`scope: integrity`, `checked_by: tego-verify <version>`), and its
   words are about the integrity of bytes, never about a run being right.

2. **The seam is a pure Go function of bytes, built first.** Each twin has a Go side that is a pure function (no file,
   no clock, no lock, no host state) with a spec section and handwritten vectors; the existing code calls it with
   behaviour unchanged, proven by its existing tests; a depguard rule holds its direct imports, and a test holds its
   resolved repository dependency closure, including `rfc3339` and `backend` (no clock or I/O call). The chain seam is
   `pkg/spec/record/chaincheck` (`Check`, `Walk`, `LineCheck`, `AnchorHeads`), which `internal/ledger` now calls,
   keeping only the opens, the lock probe and the wait.

   The integrity-only disk adapter is a `_test.go` bridge for the shared-vector runner; the unused Reader.VerifyChain
   wrapper is removed (ADR 0029). Production file verification includes schema checks. Check and Reason are
   public library APIs and are classified as such by the dead-code ratchet; the CLI uses the streaming Walk adapter.

3. **Rust is a second, independent implementation of that function**, written from `spec/` and its vectors, not by
   translating Go. Where the spec was not enough and Go had to be read, the twin says so (`rust/*/SPEC-NOTES.md`) and
   the spec is fixed in the same change. On those rules the twin repeats Go's reading and checks nothing; the vectors
   and the differential find where the two implement one written rule differently, never a rule both read the same
   wrong way.

4. **A disagreement fails, on a change to either side.** The differential (`test/rustdiff`) compares meaning: the
   verdict, the reason code, the first bad line, the number of lines and the head; never message text or
   `checked_by`. It has no skip list and no lag file: a change to the Go twin, the Rust twin, `spec/`, or either
   side's dependencies runs it, and any difference fails. A vector where Go and the spec disagree records Go's answer as
   an open `finding`, which Go's runners pin (they fail the day Go changes) and which the differential reports as a
   failure until one side changes; it is never a skip. `make rust-check` runs all of it; it joins the gate and CI in P3,
   on every change, not only on changes under `rust/` or `spec/`.

5. **The product face is `tego-verify`.** `tego-verify chain <run dir> [--anchor <chain.log>] [--json]` says whether the
   chain of a record's bytes matches (spec/record/v1/CHAIN.md): exit 0 match, 1 mismatch, 125 cannot check, 2 usage. It
   reads only the paths it is given, has no default location, writes nothing and opens no socket. Receipt checking is
   not in it: the receipt binding commits to the record's bytes, not to the receipt's reported totals, so an
   integrity-only check of a receipt could pass a receipt whose totals were edited. It waits for a design answer
   (P2), and no wording says "the receipt and the record agree" until then.

6. **The exec matcher twin (P1) starts only after a blind qualification.** The maintainer runs it: seeded faults in a
   copy of the Go matcher, withheld from whoever builds the twin, and exploit families not disclosed to them; the twin
   must detect them without spec changes, with valid-command controls, prefix-extension properties and real-tool
   witnesses where they apply, and the surviving faults are reported. Replaying v0.1.1's known forms alone does not
   qualify it. Its wire contract includes `ArgvComplete`, `Final` and every other security-relevant output of a
   decision, not only the verdict.

7. **Build rules.** `rust/` is one Cargo workspace; `rust-toolchain.toml` pins one exact stable release at least two
   weeks old (1.99.1); Cargo declares a 1.99 minimum, and qualified builds use the exact pin. No crate is published. Every crate has
   `#![forbid(unsafe_code)]`. Clippy denies unwrap, expect, panic, indexing, unchecked arithmetic and `as` casts
   outside tests, and `make rust-check` treats every warning as an error. Release builds keep overflow checks and
   unwind: a panic is caught and reported as cannot check, never a match.

8. **Dependencies.** Exact versions, default features off: `serde =1.0.229` (std), `serde_json =1.0.154` (std,
   raw_value), `sha2 =0.11.1`; their graph is serde_core, itoa, memchr, zmij, digest, block-buffer, crypto-common,
   hybrid-array, typenum, cpufeatures, cfg-if, and libc on aarch64 only. No proc-macro crate is built (no derive) and
   there is no dev-only crate (property loops use a seeded generator in test code). `rust/deny.toml` allows exactly
   these crates at these versions, crates.io only, the licences Apache-2.0, MIT, BSD-3-Clause and Unicode-3.0, the
   five build scripts it names (each read: none compiles C or fetches), and no open advisory. A bump is its own
   commit, with the changed crates' sources read. The Go module gains no dependency.

9. **Release (P3).** `tego-verify` for linux amd64 and arm64, static musl, built natively on each runner, in the
   checksums file the existing cosign step signs, with an SBOM, and rebuilt byte for byte by the reproduce job, which
   then names the Rust artifact beside the Go binaries. Pinned linker inputs, remapped paths and an empty-cache fetch
   come with it; a build that does not reproduce does not ship, and no ADR note waives that.

## First finding (2026-11-11): Go's reader took timestamps RFC 3339 does not

What differed: the vectors written from CHAIN.md §3 held a line's `ts` to RFC 3339, and Go's reader
(`record.Decode`, `time.Parse(time.RFC3339Nano)`) initially exposed two of its extra forms through `time.Parse`'s fallback layout parse: a
comma before the fraction (`09:00:00,002Z`) and a one-digit hour (`T9:00:00Z`). Rust, written from the spec, refused
them; the differential failed on vectors 077 and 078 and nowhere else.

Decision: Go is strict. `pkg/spec/rfc3339` checks the profile before
`time.ParseInLocation(time.RFC3339Nano, value, time.UTC)`. Numeric offsets never consult `time.Local`, `TZ` or
host timezone files. The repository-source purity test follows production imports and resolves aliases; this is a
source guard, not a formal proof of the standard library. Payload validation also overrides the JSON decoder's
implicit `time.Time` unmarshaler, which otherwise consults `time.Local`. The override uses the same strict profile
and UTC parser; `TestPayloadValidationTimesDoNotConsultLocal` covers all five time-bearing payload fields and
`TestPayloadValidationTimestampGrammarUnchanged` checks its accepted grammar against the prior decoder.

The newly refused classes are comma fractions, one-digit hours, offset hour 24 and offset minute 60. The full
profile requires four year digits, a real Gregorian date, two-digit hours/minutes/seconds, `T` and `Z` upper case,
seconds 00 through 59, an optional dot followed by digits, and `Z` or a signed two-digit-hour/two-digit-minute
colon offset with hour 00 through 23 and minute 00 through 59. All other listed shape/calendar refusals were
already Go refusals. Years 0000 through 9999, arbitrary fraction length and `-00:00` remain accepted. The governance
record stays standard-library only; its canonical re-encoding already refused these noncanonical timestamps.

The initial tightening weakened final-line verification: `WholeLine` treated semantic decoding failures as torn
bytes. The first correction separated closed-container framing from grammar, depth and semantic fields, but still hid a
closed final value when garbage followed it. The final framing rule is: once the first top-level JSON value
closes, the entire final chunk is a record line, including any suffix. Non-whitespace bytes after that value are
`line-malformed`; JSON whitespace after it is permitted and remains covered by the digest. Appended whitespace
with a stale id is therefore `id-mismatch`, while a correctly rehashed line can match. Only a final chunk in which
no top-level value has closed can be a torn tail. Closed containers are framed independently of their internal
grammar and depth; scalars use their JSON grammar to identify the first closed value.

JSON syntax, object shape and top-level key uniqueness are checked before the digest. A malformed suffix is
therefore `line-malformed` even with a stale id. The correction gives these object-parsing failures a distinct error
so their diagnostic precedence does not depend on timestamp parsing; this changes failure precedence only.
The version gate precedes the timestamp check; a refused v1 timestamp precedes the digest, with or without a
newline. Other common fields remain checked after the digest, and newer versions' timestamp fields are not interpreted. A malformed
suffix cannot hide a refused timestamp. Vectors 106 through 129 cover suffixes and
whitespace with no anchor, an empty anchor and a populated anchor; they include refused timestamps and stale or
recomputed whitespace digests. The released framing loophole is separate from the timestamp tightening: source
reading confirms that v0.1.0 through v0.1.2 can verify only the prefix before an altered final record when no
populated anchor exists. An intact anchor entry detects the lost head.

The hostile reread also found that Rust's raw-value parser rejected `01` as one numeric token, while Go's stream
decoder recognized the closed `0` and retained the suffix. The framing rule follows the first closed value:
`0` and `-0` close before another digit. Shared vectors 127 through 129 pin this boundary with each anchor state.

| Caller | Refused timestamp in a complete record | Test |
|---|---|---|
| `record.Decode`, `Chain.Add`, pure `chaincheck` and Rust chain | Decode error / `mismatch`, `line-malformed`; a suffix after the closed value cannot hide the line | `TestRefusedTimestampIsNeverATornTail`, vectors 087 through 102 and 106 through 129 |
| `Reader.Lines` and `Bind` | Raw complete JSON yielded; binder records error and binds no head | `TestReadersRefuseCompleteBadTimestamp` |
| `Entries`, `Iter`, `Backward`, `State` | Malformed-record error; `SkipNewerVersions` does not skip v1 errors | `TestReadersRefuseCompleteBadTimestamp` |
| Follower with lock free; Writer resume | Malformed-record error; resume leaves bytes unchanged | `TestReadersRefuseCompleteBadTimestamp` |
| `LinesFrom` live append poller | Yields terminated raw bytes; every unterminated tail waits for a newline | `TestReadersRefuseCompleteBadTimestamp` |
| `tego events --verify` | Exit 1 with malformed timestamp detail | `TestEventsVerifyRefusesCompleteBadTimestamp` |
| Receipt `Compute` / `Check` | No constructed receipt / chain step fails, head not checked | `TestReceiptRefusesCompleteBadTimestamp`, `TestReceiptCheckRefusesCompleteBadTimestamp` |
| Dashboard cache | `Bad` increments and scan continues for terminated lines; all unterminated tails wait for newline | `TestCacheCountsBadTimestampAndContinues`, `TestCacheHoldsBadTimestampUntilNewline` |

Every released Tego writer stamps UTC and serializes with `RFC3339Nano`, using `Z` and an optional dot fraction. The prior
fixture survey found all 2,271 timestamps inside the profile; it was not rerun for this correction. No writer
compatibility claim extends to hand-edited or third-party records.

## Where the twin checks nothing yet

The rules below of CHAIN.md §3 were taken from Go's behaviour. A second checker that repeats them would check
Go against itself. Each needs an answer from a source independent of both implementations:

| Rule | Today (Go's reading) | Independent source for the right answer |
|---|---|---|
| Nesting depth 10,000 | `encoding/json`'s internal limit | A design decision: the deepest a Tego writer emits (a payload field is at most 4 KiB, so about 2,048), RFC 8259 §9 allowing a parser's own limit |
| Duplicate keys refused at the top level only | `objectFields` | RFC 8259 §4 (names SHOULD be unique, behaviour otherwise unpredictable) and RFC 7493 (I-JSON) §2.3 (MUST NOT); a design decision whether nested duplicates are refused too |
| Bytes that are not UTF-8 inside a string read as U+FFFD | `encoding/json` and E18's writer-side repair | RFC 8259 §8.1 (JSON text MUST be UTF-8) and I-JSON §2.1, which say refuse; a design decision against the writer's own E18 |
| A lone surrogate escape read as U+FFFD | `encoding/json` unquoting | RFC 8259 §8.2 (unpredictable), I-JSON §2.1 (MUST NOT); a design decision |
| The common fields' types and ranges (uint64, int64) | `decodeCommon`'s Go types | A design decision written into the spec per field; I-JSON §2.2 bounds interoperable integers to 2^53 |
| `ts` | was `time.Parse`; now the RFC 3339 profile above | RFC 3339 itself: settled by the first finding, now checked independently |
| `attribution` names use Unicode simple case folding | Released Go readers have always used `encoding/json` struct decoding; the earlier spec was silent. CHAIN.md now preserves this rule precisely: U+0130/U+0131 do not match ASCII I; U+017F matches S, U+212A matches K. Top-level names remain exact. | Compatibility decision 2026-11-12; copied from Go, not independent evidence |
| `v` fits signed 64 bits; 2 through 2^63-1 are newer | Go's `int` decoder on the supported 64-bit targets | Compatibility decision 2026-11-12; CHAIN.md now states it, vectors 082 through 085 hold the boundaries |

## Rejected, and what the review reopened

- **(a) The runtime rewritten in Rust now.** Rejected: 102,275 lines to replace for no measured gain, and the tiers
  proven in KVM guests would start over. Rust could reduce allocation and scheduling variation in notification
  handling; reopen on a measured Go limit there. ADR 0001's door stays open.
- **(c) One Rust core that the Go engine calls on the hot path.** Rejected: cgo breaks the static CGO-off build;
  WebAssembly in Go needs a runtime as a new engine dependency; each makes Rust an enforcing path. Reopened in part: a
  helper process off the hot path (historical verification, migration, previews) needs neither cgo nor live authority,
  and is not ruled out.
- **(d) WebAssembly in the dashboard first.** Deferred: decision previews need the rule table's wire form first.
  Offline checks and private local editing have value of their own, and a standalone Go matcher may build for
  WebAssembly even though contract loading does not.
- **A second independent implementation in Go.** Not chosen, and the rejection is weak: the motivating flaw was in
  finality logic, not in `strings` or JSON, which a different Go algorithm with an independently specified reader could
  also catch without a second toolchain. Reconsider if the blind qualification (6) shows language diversity adds
  little.
- **A Python verifier.** Rejected for the product (no static binary); its suitability as a fuzz oracle was not
  measured.
- **Porting the whole pure core at once.** Rejected: breadth and churn overwhelm the evidence.
- **A vendor tree.** Not chosen, and weakly: `Cargo.lock` checksums establish content identity but not availability or
  convenient review; vendoring would give both at the cost of the crates' sources in the public tree.

## Consequences and residuals

- A second toolchain is private during P0. The export manifest admits the Go seam and vectors now and excludes
  `rust/`, `test/rustdiff`, the Rust script and Make target. SPDX checks `.rs` even while private. Public Rust
  admission, dependency notices, CI, release and reproduction remain P3 work after the owner's shipping decision.
- The differential transport bounds requests (5 s, 64 MiB), responses (64 KiB) and shutdown (2 s), echoes monotonic
  request identifiers and validates response fields. Shutdown closes the request side and reads responses through EOF
  within its deadline, refuses any extra reply or trailing byte (including whitespace), then checks the server's
  exit. The response reader owns its pipe until the drain ends; Wait cannot close it early. Its non-compared run
  label and diagnostic text are empty in differential replies so legitimate large inputs fit that response bound.
  Line and chain answers both carry scope and checker identity. Tests cover invalid replies, duplicates between
  requests and after the final reply, trailing bytes, request/shutdown timeouts and nonzero exits after the last
  answer. This qualifies the checked protocol in `test/rustdiff/PROTOCOL.md`, not every possible transport fault.
- Rust rescans the original open events descriptor after an anchor race, seeing appends to it but never accepting
  an inode replacement at its name. Disk-vector directories are allocated atomically per execution and owned until
  cleanup; concurrent tests cannot remove one another's fixtures.
- Every change to a twinned Go function costs a Rust change, and parser and diagnostic disagreements will cost time
  before any independent bug is found. The first one, `go-ts-lenient`, was found and closed on 2026-11-11 (above).
- `tego-verify` checks that the chain of a record's bytes matches and, with an anchor, that none was cut from its end.
  It does not prove who made the files, that the run was complete or true, or that a receipt's totals are right:
  whoever can write `events.jsonl` and `chain.log` can make a matching pair. A signature would name a signer, not make
  a host honest. These limits apply to any future verifier.
- No speed is claimed for Tego from this ADR. Any future checker speed comparison must use a standalone Go
  program over the same pure check before any number is published.
- Separating "business rules" (a rule family on an action's facts) is not decided here. If chosen, it is a pure Go
  package with its own spec and vectors that only tightens (ADR 0007), and its own ADR.
