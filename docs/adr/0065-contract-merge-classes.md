# ADR 0065: The contract merge is one table of keys and merge classes

Status: **accepted 2026-10-24** (a technical decision). Implemented 2026-10-24:
the table, the eight classes, the profile rules at `Load` and the coverage tests; D4 implemented 2026-10-24 by
the list form of `extends` (ADR 0066). The later key rows (D3) and the
between-parents rule (D4) are fixed here and land with the packages that add those keys. Refines agent-contract R5 and
SEMANTICS §1 (`extends`); supersedes nothing.

## Context

`merge(p, c)` in `pkg/spec/agent/merge.go` laid a contract over its profile with one hand-written statement per key:
78 keys across the root and eight sections, each with its own copy of the "contract wins if written" or
"concatenate, profile first" logic and its own origin bookkeeping. Later packages add contract keys
(`harness`, `reason.reads`, `fs.reads`, `fs.deny_write`, `host_sockets`, `revision`, and `extends` as a list);
each would have edited that one function, and the list form of `extends` would have rewritten it under them. Nothing failed for
a key added to `Contract` with no merge statement: the merge silently dropped the profile's value.

## Decision

**D1. One table, one loop.** `contractMergeRows` (merge.go) holds one row per key path of `Contract` and of its
sections, by YAML name, recursively through the sections: `{path, class, rule}`. A section's rows follow its own row.
`merge` is one loop over the table compiled against `Contract`'s type (`mergeclass.go`); a new key adds its row and the
loop is not edited. Field access is by reflection on the field the row names; the class is written in the row, never
read from a struct tag, so a review of the table is a review of the merge.

The table is checked against the type at package init and by tests: `TestEveryContractKeyHasAMergeClass` fails for a key
with no row, `TestMergeTableRowsNameRealKeys` for a row naming no key, a duplicate row, a row before its section's, or a
class the key's type cannot take (a `concat` row on a scalar, a `keymerge` row on anything but `map[string]string`, a
`stricter` row on anything but a string or a boolean, or one ordering fewer than two values). `TestR5ListsEveryMergeClassRow`
holds agent-contract R5's class table to the code.

**D2. The classes.** Each is unit-tested over a test-only fixture table (`mergeclass_test.go`), not over the contract's
own keys, so a class is proven before any key takes it. Every class carries each merged entry's origin (file:line).

| Class | Rule |
|---|---|
| `section` | A mapping whose keys merge by their own rows. A pointer section no file wrote stays nil (R6's tri-state). |
| `concat` | An ordered list: the profile's entries, then the contract's. Nil only when neither file wrote the key; a present empty list stays present (ADR 0048 (1)). |
| `union` | A list of what a run is denied: every file's entries, the profile's first. It combines as `concat` does; the class is what forbids the key from ever taking an override (`fs.deny_read`, R5's "never loses entries"). |
| `keymerge` | A string map merged key by key, the contract's value winning for a key both set (`env.set`). |
| `contract-wins` | The contract's value, whole, when it wrote the key, else the profile's. A list (`command`) or a mapping of this class is one value: its keys have no rows. A `yaml.Node` row says how it reads an empty node: `gate` and `ask` take a contract's empty mapping as a reset and a profile's as absent; `docker` takes an empty node as absent in either file. |
| `stricter` | A value from an ordered set, strictest first: across files the stricter written value wins, the contract's on a tie. A value the row marks loosening counts only when the top-level contract writes it, where it overrides; a profile that writes one has it ignored, with the warning `profile-cannot-loosen` at its line. A written value outside the order ranks below every listed one (fail closed; validation refuses it anyway). |
| `refused-in-profile` | The top-level contract's alone: a profile that sets the key is a `[schema]` error at its line, fix `set <key> in the top-level contract`. |
| `own` | The top file's own value and position, never inherited (`version`, `name`, `extends`). A profile still writes its own: `version` is required in every file, and a profile's `extends` names its own parent, merged beneath it first. |

The two profile rules (`stricter` loosening, `refused-in-profile`) run at `Load` on each profile file as it is parsed,
before any merge (`mergeTable.profileRules`), so a middle profile of a chain is held to them as a bottom one is, each
file is reported once at its own line, and the value is cleared before any merge could carry it. No current key is
`refused-in-profile` or marks a loosening value; `TestLoadHoldsProfilesToTheirRules` runs both through `Load` with a
substituted table.

**D3. The classes of the later keys.** Each later package adds only its row:

| Key | Class | Rule |
|---|---|---|
| `harness` | `contract-wins` | |
| `reason.reads` | `contract-wins` (in a `section` row `reason`) | |
| `fs.reads` | `stricter` | `held` > `auto` > `direct`; `direct` loosening |
| `host_sockets` | `stricter` | `false` > `true`; `true` loosening |
| `fs.deny_write` | `union` | |
| `revision` | `refused-in-profile` | |

**D4. Between two parents** (the rule the list form of `extends` implements for `extends: [a, b]`): the parents are combined in
the order the list names them before the contract is laid on top. `concat`, `union` and `keymerge` combine in that order
(a later parent's entries after an earlier one's; a later parent's value for a key both set wins, `keymerge`, as
*amended 2026-10-24* below). `stricter`
keeps the stricter of the parents' values (neither parent's loosening value counts: each is a profile). A
`contract-wins` scalar that two parents set to different values is an `extends-conflict` error at both lines unless the
contract sets it, which then decides. A `section` recurses; `own` and `refused-in-profile` are as in D2.

*Amended 2026-10-24:* the `extends-conflict` rule is every `contract-wins` key's, not a scalar's alone. A
list (`command`), a `yaml.Node` (`gate`, `ask`, `docker`) and a scalar alike: two
parents that write the key with different values are an `extends-conflict` error naming both parents' lines, unless
the contract writes the key, whose value then decides; a later parent never silently wins, since for `command` that
would run a program neither parent's author chose over the other's. Two values are different when taking either one
would change the merged contract's canonical form (R13), so the comparison is on decoded values, never on spelling or
comments: a scalar by its decoded value (`wall: 60s` and `wall: 1m` are one value); a list element by element, in
order and length (`[a, b]` and `[b, a]` differ); a mapping key by key on its decoded fields; a `yaml.Node` by its
canonical encoding, the bytes `Canonical()` writes for that key. A node the row reads as absent (D2: a profile's empty
`gate` or `ask`, an empty `docker` in any file) is absent here too, so it conflicts with nothing. Two parents that
write one value are no conflict, and the merged entry keeps the origin of the first parent the list names that wrote
it; a key one parent alone writes is that parent's.

*Implemented 2026-10-24 (the list form of `extends`, [ADR 0066](0066-extends-list-and-built-in-profiles.md) D3):* `combineParents`
runs this table's loop in a between-parents mode (`merger.parents`); two values are compared by the YAML `Canonical()`
writes for each (`sameValue`), which is the rule above for every kind of value at once, and only the file naming the
list settles a conflict (a profile whose own parents conflict is in error under any contract).

*Amended 2026-10-24 (ADR 0066 D3):* between two parents, a `keymerge` key no longer
takes the later parent's value. An `env.set` variable two parents set to different values is an `extends-conflict` at
both lines, settled only by the file naming the list, and one they set to one value keeps the first parent's origin: a
later profile's `PATH` decides what every exec name resolves to, and its proxy variables where every connect goes, so
taking it silently is the harm this decision names for `command`. A key one parent alone sets merges as before.

**D5. What changed.** Every merged value, `compile` print, `compile --json`, canonical form and `contract_hash` is as
before: the table merge ran beside the old `merge` over every test of `pkg/spec/agent` and `internal/cli` (both tag sets)
and compared the two results with `reflect.DeepEqual`, merged origins included, before the old code was deleted. Two
differences, neither visible in any output:

- `name`'s origin is the contract's only. A contract with no `name:` over a profile that writes one was refused
  `name is required` at the profile's `name:` line, a line that holds a name; it is now refused at the top file
  (`TestExtendsNameRequiredAtTheTopFile`, which fails on the old merge).
- `mcp` and `models` stay nil when neither file wrote them, as every other list does; the old merge made them empty
  non-nil slices. Both are `omitempty` and no code distinguishes the two.

The `ask`/`gate` fallback for a hand-built contract with no origins (a non-empty node taken without its key's origin) is
gone: `merge` runs only inside `Load`, where every written key has its origin.

**D6. The switches that stay `contract-wins`** (*added 2026-10-24*). D3 gives `host_sockets` the class
`stricter` with `true` loosening, so a profile's `host_sockets: true` is ignored with `profile-cannot-loosen` and only
the top-level contract can open host sockets. The existing keys of the same kind keep `contract-wins`, under which a
profile's `true` (or a profile's `net.assurance: kernel` a contract lowers to `best-effort`) is inherited by every
contract that extends it:

| Key | Class | What a profile's value does today |
|---|---|---|
| `io_uring` | `contract-wins` | `true` lets the run use io_uring at the root tiers |
| `keyring` | `contract-wins` | `true` lets the run use the kernel keyring |
| `ipc` | `contract-wins` | `true` lets the run use System V IPC |
| `setuid` | `contract-wins` | `true` lets a setuid binary gain root at the root tiers (ADR 0033) |
| `exec.anonymous` | `contract-wins` | `true` drops tiers 1 and 2's refusal of exec-capable memfds |
| `net.proxy.http2` | `contract-wins` | `true` enables HTTP/2 on declared model listeners |
| `net.assurance` | `contract-wins` | a contract's `best-effort` lowers a profile's `kernel`, where `fs.assurance` and `exec.assurance` keep it |

They stay `contract-wins` because this package changes no merged value (D5), and moving them is a behaviour change:
a contract that extends a profile writing `keyring: true` would lose the keyring it runs with today
(`TestKeyringOptIn` and `TestIPCOptIn` pin the inheritance), and each such profile would need the new warning and a migration note. What
holds meanwhile: a contract turns any of them off by writing `false` (`contract-wins` reads presence from the origins,
so an explicit `false` wins), an inherited value is written in the merged contract's canonical form, `contract_hash`
and the ledger's `contract.yaml`, and compile diagnoses `setuid` and `exec.anonymous` at the line that wrote them (a
profile's line when the profile did): a warning, or for `setuid` at tier landlock an error. `host_sockets` takes the stricter class from the start because no contract
depends on a profile opening it yet. Moving the keys above to `stricter` (`false` over `true` with `true` loosening;
`kernel` over `best-effort`) is a follow-up package with its own ADR and CHANGELOG entry, not part of this
byte-identical one. `TestContractWinsSwitchesAreRecorded` fails for a boolean key added with `contract-wins` that this
table does not list, so a new switch takes `stricter` or records here why not.

## Consequences

- A key added to `Contract` without a row fails the package's tests (and panics at init, naming the key), so no key is
  silently not inherited.
- The merge costs about 40 µs and 16.8 KB per `extends` link on the benchmark contract, against 25 µs and 16.0 KB for the
  hand-written merge (+5 % B/op): once per profile per `Load`, beside a YAML parse and schema walk that cost far more.
  No benchmark the bench gate tracks runs it (`BenchmarkLoad` loads a contract without `extends`).
- R5 lists every key's class in one table, which the profile author and the reviewer read and the code is held to.

## Rejected options

- **Each later package editing `merge()`.** One function edited for each key, each re-deriving the origin bookkeeping,
  and a missed key still failing silently.
- **the list form of `extends` first.** Rewriting the merge for list `extends` before any key package could start delays them, and its rewrite would still be a function each key edits.
- **A reflection-only merge driven by struct tags** (`merge:"concat"` on each field). Shorter, but the class sits on 78
  field declarations spread over `agent.go`, a security property (`union`, `stricter`) reviewed field by field, and a
  missing tag reads as a default class instead of failing.
- **Generated code from the table.** Same coverage, a generator and a generated file to keep in step, for a merge that
  runs once per profile.
