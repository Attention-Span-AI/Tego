# ADR 0066: extends takes a list of profiles, and names under tego/ are built-in profiles

Status: **accepted 2026-10-24**; implemented 2026-10-24: D1 to D7.
Implements ADR 0065 D4; refines agent-contract R5, R13, E5, E7, E15, SEMANTICS §1 and spec/record/v1 (record_minor
15).

## Context

`extends:` named one profile. A contract that wanted two sets of rules, a language preset and a project's own profile,
had to make one profile extend the other, so every combination was a file of its own and a preset could not be
combined with another file without editing one of them. The presets
are built into the binary and meant to be combined: `extends: [tego/no-secrets, tego/no-prod,
local]`. Two things had no answer: how two parents combine (ADR 0065 D4 fixed the classes' rule between two parents,
for this package to implement), and how a built-in profile is named so that no file can stand in for it.

## Decision

**D1. A name or a list of 1 to 8.** `extends` is one profile name or a list of 1 to `MaxExtendsList` (8) names
(`agent.ExtendsList`); `extends: []`, a ninth name, a null entry and anything but a name or a list of names are
`schema` errors, and `spec/agent/v0/agent.schema.json` says the same as a `oneOf` (`TestSchemaJSONMatchesGo` holds the
two to each other, and the real JSON Schema validator's tests hold the schema to both forms). Each parent is resolved
fully first, merged with its own parents; the parents are then combined left to right (D3) and the file naming the
list is laid on top as before. A name the list repeats warns `redundant-rule` and merges once. A profile name has one
spelling: no segment is empty, `.` or holds `..` (`agent.profileRE`, the schema's `profileName`), so the walk, which
compares names, never takes one file for two profiles.

A profile reached twice merges once, at its first position: the walk is depth first, each profile merged when first
reached, and a later reach contributes nothing to the merge (`extends: [a, b]` with both extending `base` merges `base`
under `a` only, so its entries are not doubled and its MCP server is not declared twice, E26). Whether a list
conflicts is decided on each parent's whole view instead (D3): the parent resolved in full, every ancestor counted
whichever entry reached it first, so what a profile's own list means never depends on the walk above it. E5's cycle
check runs on each
path of the walk, so a cycle through any entry at any depth is `extends-cycle`; E15's depth is the longest chain, and a
profile reached a second time still counts the chain beneath it toward the path that reached it, so a diamond cannot
hide a chain deeper than 8. `Contract.Profiles()` lists every profile merged in merge order (deepest first, a list left
to right), each once.

**D2. The reserved namespace `tego/`.** A name beginning `tego/` resolves only through built-in sources, which the
composition root registers on an `agent.ProfileChain` (`WithBuiltin`); every other name resolves through its
profiles-directory sources (`WithDir`), in order, the first that holds the name serving it, and an error other than
"not found" stopping the walk there (a profile that exists and cannot be read is never passed over for a later one's).
`Load` treats a `ProfileSource` that is no `ProfileChain` as a profiles directory, so no caller can open the namespace
by passing a plain source. The directory is never read for a `tego/` name: a directory source that implements
`agent.ProfileProber` says whether it holds the file, by a stat, and when it does the `extends` naming it is the error
`shadowed-builtin` at its line, naming the file, until the file is moved out of `tego/`. An error, not a warning: the
author of `profiles/tego/no-prod.yaml` reads it as the profile their contracts extend, and a warning beside a run that
merged something else would leave the contract meaning what its author did not write. A `tego/` name no built-in
source holds is `extends-not-found`, saying the name is one of tego's own. A built-in profile extends only built-in
profiles: a name outside `tego/` in a built-in profile's `extends` is `extends-not-found` at its line, never resolved
through a profiles directory, so no directory file supplies part of a preset under the preset's name. Before this ADR a `tego/` name was read
from `<profiles>/tego/<name>.yaml` like any other; such a profile must be renamed (CHANGELOG).

**D3. Between two parents (ADR 0065 D4, as amended).** `concat` and `union` lists take the first parent's entries,
then the next one's; a `keymerge` key (an `env.set` variable) both set to one value keeps the first parent's origin,
and one they set to different values is an `extends-conflict` like a `contract-wins` key's below (*amended
2026-10-24*, amending ADR 0065 D4: a later parent's value won); `stricter` keeps the stricter of the
parents' values, the first on a tie (neither's loosening value counts: `Load` already ignored it with
`profile-cannot-loosen`, each being a profile); `own` and `refused-in-profile` keys are the top file's alone. A
`contract-wins` key, a scalar, a list (`command`), a mapping replaced whole or a `yaml.Node` alike, that two parents
write with different values is `extends-conflict`, an error at both parents' lines, each naming both files, unless the
file naming the list writes the key, which then decides. Two values differ when their canonical encodings differ (the
YAML `Canonical()` writes for each: `wall: 60s` and `wall: 1m` are one value; `[a, b]` and `[b, a]` are two), and a
key two parents write with one value keeps the first parent's origin. Only the file naming the list settles its
conflict: a profile whose own parents conflict is in error whatever a contract above it writes, since the profile is
loaded and reviewed as a file of its own and must mean one thing.

The check compares each parent as it resolves in full (*amended 2026-10-24*): its whole view, the
parent merged with every one of its ancestors by these same classes, whether or not an earlier entry of the walk
reached one of them first, its scalar keys only (`contract-wins`, `keymerge`, `stricter`; a list counted once per
path would grow by the width of each level). So each list has one verdict under every order and every contract above
it, and a branch that overrides a value a shared ancestor set conflicts with a branch that inherits it: with `a` and
`b` both extending `base`, `a` setting `limits.pids: 1000` over `base`'s 7, `extends: [a, b]` and `extends: [b, a]`
are both `extends-conflict` at `a`'s line and `base`'s, settled by the contract. Each parent is what it resolves to,
however it came by its values; the dominance rule (an override of a shared ancestor wins over the branch that only
inherits it) is rejected below. The `stricter` warnings for a best-effort a profile beneath outvotes
(`fsAssuranceOutvoted`, `execAssuranceOutvoted`) read the same whole views.

**D4. Duplicate entries.** An entry two files of the chain both declare (`/tmp` in a preset and in the contract) merges
silently: a profile cannot know what its users declare, and the warning told the contract's author to remove an entry
the profile might drop later. One file's own repeat still warns `redundant-rule` at its line (E24). The entries are
kept, not removed, so the merged lists, the canonical form and every `contract_hash` are what they were.

**D5. The canonical form (R13).** `ExtendsList` writes one name as the scalar it always was and two or more as a list
in order, so the canonical form and `contract_hash` of every single-name contract are unchanged
(`TestSingleNameExtendsHashUnchanged` pins one, its hash taken on the code before this ADR), and a merged list's form
is pinned by `TestCanonicalOfMergedList`. `tego drift`'s sealed reload resolves every name of a list, a `tego/` one
included, to an empty profile, and the canonical form stays a fixed point. The profiles' bytes are not in the hash:
`contract_hash` says what the merged contract says, and D6 records which profiles gave it.

**D6. `run_start.profiles`** (`record_minor` 15, `MinorProfiles`). A run's `run_start`, and an adoption's, lists the profiles its
contract merged, in merge order, each `{name, source, sha256}`: the `extends` name, `builtin` or `dir`, and the sha256
of the bytes read. Absent when the contract extends nothing; at minor 15 or later its absence says so. It is beside
`contract_hash` as `contract_source` is: the hash says what the contract was, these say where it came from, so a
reader can tell which version of a built-in preset a run merged.

**D7. One constructor of profile sources.** Every load site of the CLI (`compile`, `run`, `drift`, a registry entry's
load) takes its profile source from one constructor in `internal/cli/profiles.go`, which builds the `ProfileChain`:
the machine config's profiles directory as the one directory source, and each built-in source by one call line. This
package registers no built-in source; the presets (`pkg/spec/presets`) add theirs there. The registry, which resolves contract names, is unaffected.
*Amended 2026-10-26:* the constructor moved to `internal/profilesrc` (`Chain`, with the directory source
`Dir`), which `internal/cli/profiles.go`'s `profileSources` returns and the dashboard's rule service
(`internal/control/rules`) uses too, so tego-control compiles a contract that extends a profile as tego does; a
built-in source is registered in `profilesrc.Chain`.

## Consequences

- A preset and a project profile combine without either editing the other, and a later one can never silently loosen or
  replace a value an earlier one set: a `stricter` key keeps the stricter of the parents' values, so no parent can
  loosen it, and a `contract-wins` key or an `env.set` variable two parents set to different values is a compile
  error the contract's author settles in the contract. Lists still combine, the earlier entries first.
- A file under `profiles/tego/` stops working as a profile, with an error that names it.
- A contract that extended a profile repeating one of its own entries no longer draws a warning for the repeat.

## Rejected options

- **Later-wins merging, as tsconfig's `extends` array does** (each later file overrides an earlier one's options).
  Simple and familiar, but a preset listed later would silently replace an earlier one's command, limit or approval
  policy, and the contract's author would learn of it from a run, not from `compile`.
- **A user file shadowing a built-in**, as a search path would (the directory first, the binary's profiles after).
  A file anyone who can write the profiles directory drops in would change what every contract naming the preset
  enforces, under the preset's name, and the record would name the preset. Precedent for a reserved namespace:
  ESLint's `eslint:` configurations and npm's scoped packages.
- **A warning for `shadowed-builtin`.** The run would merge a profile other than the one its author wrote (D2).
- **Removing an entry two files declare.** It would change the canonical form and hash of existing contracts and the
  positions concat lists keep in order.
- **Merging a profile each time it is reached.** A diamond would double every list entry and fail E26 on its MCP
  servers; merging once at the first position is what a reader of the list expects.
- **Letting any file above settle a conflict.** A profile would mean different things under different contracts.
- **Dominance between branches of a diamond** (C++'s virtual-base dominance, Python's C3 order: an override of a
  shared ancestor's value wins over a branch that only inherits it). It would let `a`, raising `base`'s
  `limits.pids: 64` to 4096, loosen it under `extends: [b, a]` though `b`, extending `base`, was written to carry the
  64: the later parent would replace the value the earlier one resolves to, which D3 forbids. The contract settles it in one
  line, and the error names both files.

## Implementation notes

- 2026-10-24: a profile reached a second time took no part in the conflict check of
  the list reaching it, so with `e` extending `c` and `b` extending `[c, d]`, `extends: [e, b]` loaded though `c` and
  `d` disagree on a `contract-wins` key, which `extends: [b]` refuses as D3 says. A later reach now passes the
  profile to that list's conflict check and assurance warnings and leaves it out of the merge
  (`TestExtendsConflictInAProfileWhateverComesFirst`); a note below corrects what it passes.
- 2026-10-24: a name with a `.` segment was accepted, and `base/./py` read the file
  `base/py` names, so `extends: [base/py, base/./py]` merged one file twice (its MCP server declared twice, E26) and
  `run_start.profiles` would have listed it under two names. The profile-name rule now refuses an empty, `.` or `..`
  segment, in Go and in the JSON Schema alike (`TestProfileNameHasOneSpelling`). A symlink in the profiles directory
  giving one file a second name is that directory author's choice and is recorded under each name it was reached by.
- 2026-10-24: `keymerge` took a later parent's value for an `env.set` key both set, so
  `extends: [tego/no-prod, local]` let `local` silently replace a `PATH` the preset sets, which decides what every exec name
  resolves to (compile's `effectivePATH`), or set another `HTTPS_PROXY`, though the Consequences said a later profile
  never replaces an earlier one's value. Such a key is now an `extends-conflict` at both lines, settled by the file
  naming the list (`TestExtendsEnvSetKeyConflict`); D3 and ADR 0065 D4 say so. Rejected: correcting the sentence
  instead, which would leave the harm the `command` rationale names (a program neither author chose).
- 2026-10-24: a built-in profile's own `extends` of a name outside `tego/` resolved
  through the profiles directory, so a directory file named `local` could add write entries and `net.allow`
  destinations to a preset extending `local`, under the preset's name (latent: no built-in source ships yet). The walk
  carries the kind of source that served each file, and a built-in profile naming a parent outside `tego/` is now
  `extends-not-found` without reading the directory (`TestBuiltinProfileExtendsOnlyBuiltins`). D2 says so.
- 2026-10-24: a conflict check kept, for each profile, the contract its merge produced, which
  leaves out every ancestor an earlier entry of the walk had merged, and passed that to later conflict checks; so one
  level deeper the verdict still depended on order. With `w` extending `[y, z]`, `y` extending `b`, `b` and `z`
  disagreeing on `limits.pids`, `extends: [w]` was an error and `extends: [b, w]` loaded, the contract silently
  settling `w`'s own conflict; and a plain diamond was refused under one order and accepted under the other. `load`
  now returns two contracts for each file: the merge as before (each profile once, at its first position) and the
  file's whole view (`mergeScalars`, `checkParents`), which every conflict check and assurance warning reads; the
  walk keeps both per profile. D1 and D3 say so (`TestExtendsVerdictNeverDependsOnOrder`,
  `TestExtendsAssuranceOutvotedWhateverComesFirst`, `TestWholeViewStaysTheSizeOfItsKeys`). A diamond whose one branch overrides a value
  of the shared ancestor that another branch inherits is now `extends-conflict` under both orders; no released
  contract is affected, since a diamond needs an `extends` list.
- 2026-10-25 (ADR 0068): the first built-in source is registered, `pkg/spec/presets` by one line in
  `profileSources` as D7 said. A name under `tego/` may end in a revision pin, `@` and a revision from 1
  (`tego/no-secrets@1`), in Go and in the JSON Schema alike; no other name takes one, so D1's one spelling holds for
  directory profiles. A built-in source may implement `agent.ProfileNamer`, and a `tego/` name no built-in source holds
  is `extends-not-found` with a fix listing the names those sources serve, where it said only to check the name.
- 2026-10-25 (ADR 0068): with pins, two names can serve one file (`tego/no-secrets` and
  `tego/no-secrets@1` while revision 1 is the newest), so the walk no longer compares names alone: a file one source
  served under an earlier name is that profile, merged once under the first name, and a list naming both warns
  `redundant-rule` once at the second name's line (`TestExtendsNameAndPinOfOneFileMergeOnce`).
