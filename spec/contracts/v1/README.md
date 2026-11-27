# Contracts view v1

`tego rules list --json` emits `schema: "tego.contracts.v1"`. `tego rules list <name|path> --json` emits
`schema: "tego.contracts.show.v1"`. Both satisfy [contracts.schema.json](contracts.schema.json), a JSON Schema
2020-12 document. This is a read-only view. It changes no contract, compile rule, merge order or record revision.

The list always contains `contracts`, `roots`, `issues`, `incomplete`, `context` and `footer`, even when empty.
The show object contains `contract`, `rules`, `table`, `context` and `footer`. `table` is the existing compiler's
human-readable table; consumers should use `rules` for source relations. Source kinds are strings so another
source, such as a future baseline, can join a rule without changing this shape. No baseline is implemented here.

A contract entry has `name`, `path`, `found_in`, `cwd`, `state`, `ambiguous`, `last_run` and `diagnostics`.
Optional `aliases` lists additional registry spellings of the same checked file; aliases do not make its name ambiguous.
`contract_hash`, when present, is the existing SHA-256 of canonical merged contract bytes, 64 lowercase hexadecimal
digits with no prefix. `state` is `compiles`, `invalid`, `missing`, `unreadable`, `unsafe` or `incomplete`.
The check is offline. `compiles` is not a backend preparation or a launch result. Hashes remain available after a
successful load even when the later compile fails.

`last_run` is null when no run of that path was found in the selected ledger. Otherwise it names `id`, `at`, `tier`,
the recorded `contract_hash` only when it has 64 lowercase hexadecimal digits, and `same_contract`: `yes`, `no`, `unknown` or `not-enforced`.
`at` is the recorded start time in RFC 3339. `tier` is `landlock`, `cgroup`, `bpflsm`, `observe` or `unknown`.
Invalid recorded ids and run-only names use `unknown`; a loaded contract supplies its own validated name. `yes` and `no` compare merged canonical text only. An unknown or malformed
recorded hash, an unavailable current source or an unknown tier yields `unknown`. An observed run always says
`not-enforced`. This projection does not verify the record's chain or authenticate its claims.

Roots have `kind`, `path`, `state` (`present`, `absent`, `unreadable`) and an optional `problem`. Diagnostics carry
`file`, `line` (0 when unavailable), optional `column`, `code`, `message` and `severity`. Contract load/compile
messages use the compiler's vocabulary. `incomplete` discloses a failed or bounded discovery or unknown context;
a contract error by itself does not make discovery incomplete. A cancelled or timed-out check has state
`incomplete` and a `check-interrupted` diagnostic. Whole-command cancellation also adds an `interrupted` issue.

Each show rule has `key`, optional `entry`, `words` and `sources`. Each source has `kind`, optional `file`, `line`
and `key`. More than one source may contribute, such as a contract limit and its machine ceiling. Presets keep
their compiled-in pseudo-path and source line. Expanded filesystem/program details stay in `table`, exactly as the
compiler prints them. Rule sentences and group defaults reuse the existing rules view. Environment rule entries
name variables, never their values; the verbose compiler table retains its existing presentation.

`footer` always discloses discovery scope. `context` always states the offline, current-file check and the limits
of comparing a contract hash. The command reference and [user guide](../../../docs/site/testing-rules.md) define
selection, guards, resource bounds and exit codes. Tests validate real outputs with the repository's independent
JSON Schema validator and reject an unsupported schema version.

The list may carry an additive `general` observation (ADR 0153 slice 1). It gives the selected
source, canonical profile-merged digest, raw source digest, checked owner/mode/walk, scope and profile
digests. `loaded` means parsed only: general launch is not built yet. `unknown` and `invalid` never
authorize fallback or a launch. An absent general is omitted from the legacy list response; it does
not change standalone checks, hashes or exit status. A show response still describes only its selected
standalone file. The general's diagnostics are loader diagnostics, not compiled coverage.
