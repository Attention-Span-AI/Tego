# Baseline configuration status

ADR 0144 slices 2 to 5 compile the `baseline:` config's immutable refusal union, retaining its
source locations. A contract cannot loosen the union. Compilation preserves the contract/hash
and exposes a separate effective contract/hash, owner context and modeled coverage. JSON adds
`effective_hash` only when a nonempty baseline was applied. Empty and absent baselines keep the
existing compile JSON output.

Slice 6 adds the record and receipt format described below, with validated historical replay.
Enforcing launches with a nonempty baseline remain refused until per-mechanism guest proof.
The reviewed base35 fixes are integrated. Baseline editing commands and an editable dashboard card
remain later work. Compiler checks alone do not establish kernel enforcement.

The four keys are `baseline.fs.deny_read`, `baseline.fs.deny_write`, `baseline.exec.deny` and
`baseline.env.deny`. The ordinary contract's `deny_write` caveat still applies: blocked for ordinary commands; not race-free at the no-root tier. Race-free decision planes require root. They add across the system, passwd-home user and explicit `TEGO_CONFIG` layers.
An empty list adds nothing. Nulls, misspelled keys and unsupported keys fail the load. See the
[config spec](../../spec/config/v0/README.md#baseline-schema-adr-0144).
Use `tego rules check --merged` for the source contract and `tego rules check --effective` for owner-expanded
baseline insertion. Contradictory grants, protected host sockets and required environment delivery
refuse compilation; unsupported placement or mechanisms refuse decisions. Conflict
checks compare the final compiled grants with targets, known aliases and directory identities in
both directions. A second filesystem instance showing the same data remains outside alias recognition.
The coverage and residual limits for each mechanism are in [ADR 0144](../adr/0144-machine-baseline.md).

Launch, compile, check and rule-decision commands refuse an invalid, unreadable or unsafe config
layer. Every decision uses the trusted snapshot; a failed load never substitutes an empty baseline.
Automatic adoption guards load and compile a fresh owner snapshot for each adoption. For each actual
adoption, Tego creates its own directories before loading the strict snapshot used for compilation,
including on first use.
Preparation and final admission share a table of named admission checks. After the host-wide migration-lock
wait, final admission runs every check in the table marked rechecked, including the chain-anchor file probe
and selected-layer identity, exact-byte and baseline-digest comparison, including an empty baseline.
A failed rechecked entry refuses and cleans up before any process moves. Live plane admission
is checked before arming and again under the migration lock. Snapshot entries retain compiled contract
choices, selected mechanism/probe results/prepared descriptors, immutable boot facts, and the recording-only
target home because it admits no file boundary. The run-directory contract check uses the compiled
snapshot; the skip-counter baseline stays fixed to count skips during the lock wait. Already adopted
runs keep their snapshots. Adoption requires root.

Stop and observation commands, including status, events, receipt, doctor and dashboard read pages,
keep a degraded config when a layer fails. They say the baseline is UNKNOWN and give the cause;
UNKNOWN never means empty or no baseline. They cannot use that config to start or widen a run.
GC also reports degraded config, returns 125 and sweeps and deletes nothing when any layer is
unknown. Doctor JSON carries `baseline.known` and, when unknown, `baseline.reasons` naming
each failed layer, file and cause.

The system layer requires root-owned placement and a file readable by governed users, normally
0644. A root-owned group-writable ancestor, even a sticky one, is refused; so is a namespace where
placement ownership is not mapped to root. User/explicit layers retain their owner/mode/link checks.
A missing optional system/user file is recorded as absent; an explicitly selected missing file is
an error in decision commands and unknown in degraded loads. A missing passwd home selects no
user layer and prints no discovery warning. An empty baseline or entries without `~/` do not need
an owner home. Resolving a `~/` entry without that owner's home refuses with the layer, file, line
and uid: give the entry an absolute path, or run as a user with a passwd entry.
No config write or baseline edit command is added.

A receipt for a record carrying the new baseline evidence says whether a machine baseline was
in force. It lists each entry, its contributing files and lines, the actual tier and mechanism,
what operations held, conditions and limits, and recorded refusals under that entry's action rules.
It labels contract, effective and normalized baseline SHA-256 values separately. Consulted files
that were absent are shown as absent, with no byte digest. A present empty file has a digest.

A recording-only receipt says: “A machine baseline was configured. Recording alone held nothing;
every entry was not applied.” Removing an environment name at startup adds no syscall refusal.
Counts exclude reads the run did not record. A rule can also belong to the contract; its count
does not prove the baseline alone caused the refusal. A record without the baseline block proves nothing about a baseline, neither that one applied nor that none did.

The record retains the consulted bytes and applied contract. Historical replay uses those bytes,
even after the configuration is edited or deleted; it refuses facts that do not reproduce.
The effective copy is `effective.yaml` beside the original `contract.yaml`. These facts do not
authenticate the administrator's mount namespace. The record remains private under the run's
existing access controls and can contain the consulted machine settings. Edits affect later launches.

Record preparation uses named `baseline record evidence` and `effective contract copy` snapshot
checks. Adoption prepares both before any process moves, retains their results across the migration
wait, and separately rechecks current config bytes and identities under the lock. Recording-only
unknown-owner evidence stays unknown and cannot mint a verified replay handle. Adoption requires root.

The baseline codec checks original evidence bytes before typed use or UTF-8 repair, including
serialization and ledger writing. Receipt, replay, metadata and dashboard readers use that gate.
Unsupported record revisions are refused with their reason. The legacy writer comparison covers
launch/adoption `run_start` and `run_end` only; other emitted kinds remain unproven by that
comparison. Adoption requires root.

Dashboard downloads and line details revalidate bytes read after a snapshot was built. JSONL
reports a refused line in a `tego_export_note` row; CSV uses its existing single-cell `#` note
convention. These notes identify the run, byte offset and decoder reason and are not events.
Store refresh retains refusals for rejected complete lines of any kind. A refused run start or a
line whose kind cannot be established clears earlier baseline hashes. Classification uses the
exact `kind` member, as the primary decoder does; `Kind` cannot override it. After eviction,
window reload checks the bytes again and skips unchanged retained refusals without counting
them twice. The run view still shows their positioned reasons. Newly refused lines or changed
refused bytes report damage. Pause/resume polling decodes complete consumed lines before filtering and
reports damage with exit 125; a later valid confirmation is also shown. A damaged confirmation
is not an ordinary timeout. Incomplete tails wait for completion.
