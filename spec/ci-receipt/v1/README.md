# Retained CI evidence, version 1

ADR 0143 defines the manifest and the independent expectations. These schemas
describe three separate byte strings:

- [manifest.schema.json](manifest.schema.json): `tego.ci-receipt/1`.
- [expect.schema.json](expect.schema.json): `tego.ci-expect/1`.
- [verify.schema.json](verify.schema.json): `tego.ci-verify/1`.

The manifest and expectation codecs require every property, reject unknown or
duplicate keys at every depth, reject null except the non-PR head, and reject
trailing values and invalid UTF-8. Each input is at most 64 KiB. Counts use exact
nonnegative integer JSON tokens, at most 9223372036854775807; fractions and exponent
notation are refused by the codec. Hashes use 64 lowercase hexadecimal digits.
Repository object IDs use 40 or 64 lowercase hexadecimal digits. Positive IDs and
attempt numbers are decimal strings with no leading zero. The PR head is required
for `pull_request` and null for other eligible triggers.

Every manifest filename is fixed. The reader freezes regular files into a private
directory, refusing symbolic links, multiple hard links and special files. Limits
are 128 MiB for the record, 64 MiB for the receipt, 4 MiB for the contract and each
bundle, 1 MiB for the retained comparison, 4 KiB for status and 1 KiB for the anchor.
The sorted inventory contains the receipt, record, anchor, contract and status,
using one ASCII `<sha256> <bytes> <path>\n` row per file. It excludes the manifest,
retained comparison and bundles.

`github` expectations come from independent configuration and exact-attempt API
metadata. Release checksums are a separate trust input authenticated by the caller;
the core does not authenticate them, check their signature or fetch metadata. Both
text and JSON state that limit. A passing checksum-file digest means only that the
given file matches the manifest. Producer, earlier checker and local checker
assets must each belong to that same release and commit. Unavailable local checker
identity is not-checked; contradictory producer or earlier signer assets fail. Their
architectures and executable hashes may differ. Text identity blocks are labelled
`Expected (not established):` unless the result is `match`. Independent CLI
expectation/checksum inputs refuse symlinked parent directories with exit 125.

`run_facts` preserves `tier`, the whole capability map, `best_effort`,
`reads_notified`, `runtime_grants` and `run_command_grant`. The compiled hash and
capabilities are compared with the receipt binding and record. Runtime grants,
image metadata and the artifact ID remain record/workflow assertions; this schema
has no independent expected value for those fields. Copied status must identify
the record's run and cgroup and report confirmed removal with no deferred cleanup.
It does not let this reader inspect the earlier machine.

Both the retained comparison and a fresh ended-only comparison must report all
mandatory checks passing, complete coverage and an ended match. Only
`binding.binary_sha256`, `tokens.est_cost_usd`, `tokens.unpriced_responses` and
`coverage.gaps[no-price-table]` are permitted in `not_compared`; prices are not
reproduced. Every result includes residual limits and the statement each check
supports. `coverage_complete:false` is visibly incomplete.

Bundles are checked by an independently pinned cosign (`cireceipt.CosignVerifier`):
`tego session show --verify-ci` and `--check --bundle` take `--trusted-root`,
`--cosign` and `--cosign-sha256`. Without them, every required bundle and
certificate field is reported as `not-checked` with `not checked: no bundle`.
Missing checks never become a pass. Full acceptance requires both authenticated
blobs, all certificate-field checks and both verified integration times within the
independent attempt window, allowing 60 seconds skew. A full ended match exits 0,
contradictory evidence exits 1, and an unavailable comparison exits 125. Bad command
usage exits 2.
