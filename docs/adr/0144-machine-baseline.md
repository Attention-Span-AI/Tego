# ADR 0144: A machine baseline, with each entry's coverage recorded

Status: **proposed; slices 1 to 5 and slice 6 record, receipt and validated replay implemented with host checks. The reviewed base35 fixes are integrated. Nonempty applied-baseline launches remain refused until slice 9 guest proof. Slices 7 to 9 remain open. Acceptance requires the decision-tightening property and per-tier guest checks**.
2026-11-11. The original design review read source at `35b34ceec` without running a build, test or binary.
Implementation notes below distinguish compiler host checks from guest enforcement proof. The coverage table remains a required per-mechanism contract, not a claim that guest acceptance has passed.
The design amendment checked the second reading against source at `35b34ceec`.
No build, test or Tego binary ran during that reading. Requirements below are decisions, not coverage claims.

## Scope

Build a contracts view, then four config deny lists that enforcing contracts cannot remove. Profiles are
optional and can carry grants; they are not a mandatory baseline (`pkg/spec/agent/merge.go:47-155`).
This follows ADRs 0007, 0059, 0065, 0066, 0068, 0069, 0071, 0113 and 0125.

User words: “The baseline adds refusals to enforcing runs Tego starts here. A contract cannot remove them
or request a known door out of the run. How strongly each entry holds depends on the tier and mechanism,
shown beside that entry. Only root can edit the host system file. A person can still start an agent
without Tego. Recording alone holds nothing. Adoption covers supported actions from attachment only.”

This does not cover every cooperative host server. ADR 0113's unlisted same-user servers, inherited
connections and older-kernel abstract-socket limits remain. Nor does a receipt authenticate that its
`/etc` was the host administrator's mount: a user can mask that path in another mount namespace. Record
what was consulted, including absence, rather than claim a root-authenticated machine policy.

## Contracts view

First build `tego contracts` and `tego contracts show <name|path>`. They add no rule and depend on no
baseline implementation. Discover project/user registries and contract sources from runs in the selected
ledger root. List roots, ambiguous names and unreadable sources. Never choose an ambiguous name by order.
Say: “These are the contracts Tego found in these registries and runs. Files outside them may be missing.”
Do not scan the disk or other homes. Historical paths are untrusted text; opening/editing requires today's
guards (`internal/registry/registry.go:7-22,53-63`; `internal/control/rules/contracts.go:26-50`).

The dashboard uses the same catalog, showing only project roots known from runs or explicit selection.
Add the baseline card first once available; show profiles, presets and ceilings separately. System entries
are locked. Contract editors show baseline entries with sources and coverage, without delete controls.
A refusal row offers “Add a baseline refusal for new enforcing runs”; it drafts, checks and saves through
the same service as the CLI. It must not say “Refuse this for every agent”.

## Config and materialization

The existing order is built-in, `/etc/tego/config.yaml`, passwd-home `~/.tego/config.yaml`, additive
`$TEGO_CONFIG`, then contract settings. There is no discovered project config layer
(`pkg/spec/config/load.go:38-48,81-112`). Add this schema to the three file layers:

```yaml
baseline:
  fs:
    deny_read: [~/secrets]
    deny_write: [/srv/releases]
  exec:
    deny: [git push]
  env:
    deny: [PROD_TOKEN]
```

Only these four lists are admitted. Reject unknown keys, nulls, grants, asks, network entries, limits and
wrong types at their lines. Absent keys and `[]` add nothing. The built-in baseline is empty. Types stay
in config; config must not import agent. Older binaries reject the unknown key, so upgrade launchers first
(`pkg/spec/config/parse.go:239`).

For each key, union entries in layer order, keeping the first position and every contributing source.
Deduplicate exact decoded strings within the baseline only. After profile/preset merging, prepend this
union to a working copy's corresponding lists. Keep every contract entry, including duplicates.
A nonempty read list re-enables the built-in read list even beside contract `deny_read: []`.
With no baseline entries, do no transformation: preserve canonical bytes, modes, rules, origins and
merged output for valid inputs. Ordinary machine ceilings stay separate.

**Decide exec mode from `C.ExecUnrestricted()` before insertion, never from YAML key presence.** If false
and `C.Exec.Allow` is nil, make it a nonnil empty list before adding a baseline exec deny. Assert the mode
is unchanged afterward. This covers `exec: {}`, assurance-only sections and written null `allow:` with
all entries commented out. A nil exec section becomes a deny-list; an existing deny-list stays one.
`DenyList()` tests nil slices (`agent.go:275-295,321-325`), and the loader's null guard runs before this
transformation (`load.go:452-471`). Planned test TestBaselineNullAllowPreservesRestrictedMode must refuse every
image both before and after insertion. Merely testing whether an `allow` key was written is forbidden.

Origins need three classes: contract, profile/preset, baseline. Keep the source contract immutable.
When prepending N entries, remap every old index-keyed origin i to i+N, including nested keys, and retain
its original class. Baseline membership is a separate many-source relation, never the single winning
origin. Top-file exceptions in `compile_userdenywrite.go:108`, `compile_askread.go:212` and
`compile_live.go:175` must explicitly exclude baseline members, even when duplicated by the top file.
Baseline missing targets cannot inherit a profile's warn-and-skip behavior.

Revalidate combined bounds. Truncated filesystem walks, alias inventories, command expansion, linked-file
searches or table limits refuse launch; they never discard a baseline row or permit a weaker fallback.
In particular `compile_userdenywrite.go:285-293,320-382` can leave hard-link coverage incomplete today.

### Home, placement and absence

Expand `~/` against `WithHome`, the home used to compile this agent's contract. At adoption this is the
agent owner's passwd home, including when the adopter is another user. Record owner uid and that home;
never substitute the adopter's home or `$HOME`. Leave baseline spellings unexpanded in `Machine` until
this context is known. File entries are literal absolute or `~/` paths; no globs or name patterns yet.
Preserve the kernel's walk, including symlink followed by `..`, and the declared spelling.

A missing system-layer target or home uses the built-in list's absent-row rule **only where that context
can hold it** (`compile_fs.go:857-885`): retain the nearest existing ancestor/name refusal and report
`conditional`, with the absence condition. A missing target beneath a write/exec-read grant cannot use
that Landlock rule. No resolved home means no absolute target, so no current tier qualifies: stop that
compile. A known home whose directory is absent can still produce an absolute absent row. Other layers'
missing targets, unplaceable paths, unreadability, and errors other than supported absence stop compile.
Do not create a target to make a rule compile or silently skip it. Errors name layer, line, owner and
“use an absolute existing target, or remove this baseline entry”. Check preparation identities and
the resolved absent-target walk again; a changed target or redirected still-absent spelling stops launch.
Ordinary partial parent creation under the compiled ancestor remains supported. A system file must be
readable by its governed users, normally 0644; unreadable is an error, never an empty layer
(`config/load.go:137-147`).

Checks of a system edit must display each owner/home checked. Offline checking cannot enumerate all
future users: report unchecked users, missing contexts and undiscovered contracts. A broad rule such as
`exec.deny: [sh]`, `env.deny: [PATH]` or `deny_read: [/usr/lib]` may stop many launches. Recovery is an
administrator's layer edit, read by the next launch, not a launch exception.

## Conflicts and escape grants

A baseline conflict stops compile and names both sides. Use code `baseline-conflict`, the baseline
layer/file/line/owner, grant file/line/key, resolved identities, selected tier/plane, and the repair.
Compile/check return 1 for contradictions; run/adopt return 125 before starting or moving any process.
Unknown placement/capability/config is 125; unsupported flags are usage 2. Never silently trim a grant.
Check the merged contract, presets, asks, live fences, runtime grants and the command after `--`.
Generated grants name their producer when no user line exists.

Conflict checks consume the final compiled grant table after profiles, presets, extends, implicit grants,
derived grants and live transforms. They never expand or place a grant spelling a second time.
Entries already rejected by ordinary schema or grant validation retain that earlier refusal; for
example, a read ask already beneath a compiled deny does not become a valid grant for this check.
Containment compares compiled paths with each baseline target and its known aliases in both directions,
using ancestor device/inode identities and the mount table.
Resolved string prefixes alone (`compile_fs.go:471`) are insufficient. Detect same-inode contradictory
file grants, case aliases and bind aliases where compile can establish them. Inventory completeness is
a precondition at path-dependent tiers. A known bind alias, case-folding mount or second hard link of a
read-denied file refuses compile there unless the selected mechanism proves coverage of all forms.
An unknown topology does not prove absence of aliases: refuse a path-dependent launch that cannot
establish its support conditions. A different filesystem instance showing the same data (a second
network mount, FUSE mirror or loop image) remains outside alias recognition. Deny its other path too.
Future replacement and mutation limits remain as in the coverage table.

| Baseline key | Required conflict check |
|---|---|
| `fs.deny_read` | Reject write/read-bearing grants at or inside its scope. An enclosing write requires held reads at Landlock; explicit `fs.reads: direct` conflicts. At Landlock reject overlapping exec grants, loaders and interpreters, including enclosing directories: exec grants carry READ_FILE (`compile_fs.go:1178-1215`). Check `fs.ask_read` and live read fences too. |
| `fs.deny_write` | Reject equal or nested write grants and ask/fence reopenings, although contract-only nearest-wins allows a nested grant today (`compile_userdenywrite.go:75-83`). An enclosing write requires a decision plane; refuse Landlock/fanotify. Include alias identities and linked descendants. |
| `exec.deny` | Deny remains before ask/allow (`pkg/policy/execmatch/index.go:383-418`). Reject explicit command allows whose invocation languages intersect it; e.g. `git push --dry-run` intersects `git push`. A bare image/directory grant is not a command exception. Reject a denied own/CLI/MCP command; today's MCP warning becomes an error for baseline membership. Reject `exec.anonymous: true` beside restricted images and a baseline exec deny. |
| `env.deny` | Reject explicit pass/set names and required launch injections: identity, routing, resolver, harness, credential `env` and `base_url_env`. Predict at compile; after `harnessEnv(agentEnv())`, validate the actual `ChildSpec.Env` immediately before exec. A denied name remaining there stops launch. Never print values. |

Command intersection uses `execmatch`'s parser, tool vocabulary, normalization and image identities.
For the same possible tool, compare normalized fixed prefixes, positional/option constraints and helper/
multicall interpretations. Disjoint tool identities or contradictory constraints prove disjointness;
otherwise produce an intersection witness. Unsupported interpretation or exhausted bounds means “cannot
rule out an intersection”, an error naming both entries. Do not implement string-prefix matching.
Fuzz this conservative solver against the real matcher: any invocation accepted by both must never be
classified disjoint. Loader/interpreter helpers and implicit grants enter the same analysis.

### Host sockets

When applying the baseline, any **nonempty configured baseline**, including redundant entries,
conflicts with `host_sockets: true`.
Also reject effective `net.allow` or approvable `net.ask` Unix grants for these protected endpoints,
including grants inherited through profiles/presets or introduced by a fence:

* Session bus `<runtime>/bus`, systemd manager `<runtime>/systemd/private`, and system bus
  `/run/dbus/system_bus_socket` and `/var/run/dbus/system_bus_socket`.
* The exact `IsContainerSocket` list: `/run/docker.sock`, `/var/run/docker.sock`,
  `/run/podman/podman.sock`, `/var/run/podman/podman.sock`, `/run/containerd/containerd.sock`,
  `/var/run/containerd/containerd.sock`, and `<runtime>/docker.sock` and
  `<runtime>/podman/podman.sock` for every protected runtime base.
* All remaining ADR 0113 protected Unix endpoints: `BuiltinRefusals.UnixRule(path, false)` returning
  `builtin.host_ipc` or `builtin.tego_surface`. This covers protected runtime subtrees, tmux, screen,
  editor-server and X11 directories, Tego directories and ledger ask/operator sockets. Runtime bases
  include `/run/user/<owner uid>` and the compile's additional runtime parents. IPC directories include
  `/tmp/tmux-<uid>`, `$TMUX_TMPDIR/tmux-<uid>`, `/run/screen/S-<user>`, `/var/run/screen/S-<user>`,
  `$SCREENDIR`, `~/.screen`, `/tmp/emacs<uid>`, `/tmp/nvim.<user>` and `/tmp/.X11-unix`.

Use declared names even when absent, resolved names, known socket identities and parent/name walks.
Ambiguous protected aliases refuse compile. Preserve ADR 0113's fixed SSH-agent exceptions and validated
run-owned runtime sockets; ordinary Unix grants outside this classification do not acquire a new refusal.
Abstract names remain subject to ADR 0113's scope and disclosed limits. Source of truth is
`builtin.go:48-132`, `compile_builtin.go:35-75,145-172`, and `compile_hostsock.go:27-41,182-239`,
not just the shorter warning list. Existing built-in refusals still decide first; this does not reopen them.

Example diagnostic: `baseline-conflict: agent.yaml:9 net.allow unix:/run/docker.sock conflicts with
/etc/tego/config.yaml:12 baseline.env.deny PROD_TOKEN (owner uid 1000): this socket can start processes
outside the run, where baseline rules do not apply. Remove the baseline entry or do not use this grant.`
For `host_sockets: true`, name that key and its line instead. Name every contributing baseline source,
with a bounded displayed list and full structured diagnostics. An administrator needing the grant must
remove the baseline entries that keep the union nonempty, or not use the grant. There is no
`--force-break`, including for root. Unknown use returns 2 before any write or launch.

## What each entry holds

Use this table at compile, tier selection, fallback and preparation. K = `kernel`, C = `conditional`,
B = `best-effort`, R = refuse launch. These are per-entry classifications, with operations, conditions
and residuals, not a blanket “baseline held”. C does not mean kernel unless its recorded condition passes.
For environment rules C means startup filtering, with no ongoing kernel guarantee.

| Key | Landlock | cgroup: LSM or fmod_ret plane | cgroup: fanotify fallback | bpflsm |
|---|---|---|---|---|
| `fs.deny_read` | K for isolated, alias-checked targets; C with held reads under a writable parent, including A11 limits; R for direct reads there or unproved aliases | K by pinned inode/name under supported topology; R for detached bind subtrees, incomplete link inventory or unsupported names | C for checked exact paths only; R for unproved aliases. Bind aliases need a pending fix; moved/future-name mutation checks remain B | Same plane conditions; R if they cannot hold |
| `fs.deny_write` | K for write-open/delete/rename outside grants; R for an enclosing/equal/nested write reopening; metadata is outside this K claim | K for supported mutation operations, chmod included for deny_write, with complete inode/link rows; R for contradictory grants/topology | Same outside-grant K and enclosing-write R as Landlock; no metadata guarantee | Same plane conditions |
| `exec.deny` | B for copied argv/name/identity matching | C: kernel pins only when doctor's exec-pin cell passes; otherwise B | B for argv; path-based image checks do not upgrade it | C with passing exec pins; otherwise B |
| `env.deny` | C: removed from final exec environment | C: same | C: same | C: same |

Read identity coverage includes launch-pinned hard links where the mechanism pins them. Ordinary Landlock
sibling enumeration does not cover an existing second hard link; require complete proof or refuse.
Whole-target/ancestor bind aliases differ from a file/subtree detached from inside a denied tree: an inode
ancestor walk need not cross the deny row for that detached part. Refuse that plane placement, or recheck
an explicitly supported fanotify fallback. The current fanotify tier does **not** hold `deny_read` through
bind aliases until the bind-alias fix lands and its guest checks pass. Its `PlaneHoldable`/
`ErrPlaneDetachedPart` work must also gate plane claims, not just fallback claims
(read: branch `509ee8934`, `internal/runtime/enforce/cgroup/planerun.go:117-160`).

Held reads retain A11's support conditions: pinned launch targets and observed installations hold; future
files renamed, exchanged or linked out before pinning may escape. Mount changes made and undone between
held reads may escape detection. Record these residuals for C rows. Landlock/fanotify do not hold chmod,
chown, xattrs or timestamps as a general write refusal. Plane metadata claims cover only implemented hooks.
See `docs/GAPS.md` A11 and `pkg/spec/backend/matrix.go:57-83,88-116,121-149`.

Exec rules refuse matched invocations by name/argv/identity, including known multicall and hard-link
forms. With unrestricted images, a renamed copy, memfd/deleted-image copy or an interpreter running its
code is outside this refusal at **every** tier, even with no write grant. Image restrictions improve
coverage without making `exec.deny` a code-content rule (`compile_execcommands.go:461-489`). Always show
image mode and this limit per exec row. Env rules cover delivery, not a variable the child later creates,
sources from a file or reconstructs in memory (`run_env.go:51-90`; `run_child.go:320-355`).

A tier pin, ceiling or fallback cannot inherit another tier's labels. Recompute and record the actual
mechanism; R aborts before child release. Offline compile checks modeled contexts without backend probes;
unknown capabilities needed by a nonempty baseline mean incomplete, exit 125. Empty-baseline
backend eligibility uses the existing predicates, but automatic guards now recompile and rerun
selection before every adoption, including live fmod_ret admission. The selected mode checks live
admission again before arming and in final admission after the migration-lock wait. Recording-only
adoption exposes the observed-handle predicate and installs no boundary. Adoption run_start does not emit FSReads
or ReadsNotified metadata; the predicate change adds neither field.
These ordinary paths need guest proof even with an empty baseline. The fix-round base/head matrix
has 39 positive rows in each of two LSM contexts, including a targeted repair in the default
context, covering owner context, migration/release, recording-only lifecycle, admission changing
before the agent starts and shared Landlock descriptors. Admission changing after selection remains
owed in a guest, with refusal, cleanup and no movement required. This does not accept the baseline
enforcement cells. Record-only paths have `not-applied` for every baseline entry.
Adoption with exec/env denies refuses before moving processes; file-only adoption requires a decision
plane and its topology checks. Existing descriptors/mappings remain outside attachment coverage
(`internal/cli/adopt.go:906-912,943-1013`).

## One application, layer protection and replay

**`agent.Compile` is the single materialization point**, from the immutable Machine baseline snapshot
after compile-home selection and before ordinary rule compilation/live transforms. `compileForRun`,
loaders, printers and views never prepend lists. Keep `RuleTable.Contract` and `Hash` as the original
contract; use a distinct `EffectiveContract` and `EffectiveHash` for the baseline contribution. Compilers,
enforcers and rule printers consume effective compiled state, never reconstruct policy from source lists.
Audit every `rt.Contract` consumer: `print.go:337` currently hides command rules when source `Exec` is nil.
Its replacement must print baseline-only exec rules and the preserved image mode; require
planned TestBaselineOnlyExecVisible for a source contract without an exec section.

Launch routes are run/service/deploy, boundary watch and adoption, through
`compileForRun` (`internal/cli/run.go:645-706`; `watch.go:98`; `adopt.go:694`). Non-launch consumers
must state their context:

* Current compilation/previews: `internal/cli/compile.go:210`, `internal/setup/check.go:62`,
  `internal/cli/learn.go:622` (save validation), and current-source uses of
  `internal/nextrun/nextrun.go:101,108` use today's TrustAbort snapshot exactly once.
* Recorded reconstruction: `internal/cli/drift.go`'s `contractTable`, recorded uses of nextrun, and
  **`internal/control/rulesview/rulesview.go:153,156`**, including its PATH retry, pass a non-public
  sealed replay option. It selects only the recorded snapshot, never today's baseline. The replay API
  issues an opaque verified handle; `compileForRun` rejects sealed handles. There is no CLI/config
  opt-out. A materialized effective copy is not a source contract and cannot be rematerialized.
* Learn reads baseline membership separately: it must not write baseline entries into the proposed
  contract. Save validation compiles the proposed source with today's baseline once.

Replay old runs with unknown baseline as unknown, not today's union. Planned test
TestBaselineAppliedOnceAcrossRulesViewReplay: compile, record, render Rules, exercise PATH retry,
then edit/delete config and render again. Assert one contribution, stable origins and effective hash;
it fails on a second application. Also test each launch route and repeated Compile on the same input.
Use the same effective observe predicate that feeds `ReadsWhyRecordsOnly` and runtime `recordsOnly`,
not watch/adopt flags alone (`compile_heldreads.go:95-105`; `run_ledger.go:327-331`).

Load baseline inputs with TrustAbort for launches, compile, checks and current in-force views. The
current dashboard uses TrustWarn (`internal/control/cli/serve.go:210`); it must report unknown on
failure, never empty. This intentionally tightens invalid-config standalone compile even without rules.
Valid no-baseline rules/bytes stay identical.

Require root ownership, no non-root write authority along the placement walk, and safe regular files
for the system layer, even when its baseline is empty. User/explicit layers retain generic trust/link
checks (`config/trust.go:65-96,112-158,198-206`). Mutations refuse governed cgroup membership, uncertainty
included; dashboard requests use peer checks, not supplied uid/path/env. Reuse CLI/web governed guards.

R10 must protect consulted layer paths, present or absent, plus the compile home's
`<owner home>/.tego/config.yaml` when it differs from `m.Home`. Adoption currently loads the adopter's
Machine; the owner's writable layer is missing from `m.Layers`, and blocking entries inside `.tego`
does not stop a write grant over the owner's home (`compile_fs.go:350-362,491-493`). Add that owner path
and all walked names to R10 before accepting a file-only adoption. This protection does not import that
owner's user baseline into the adopter's snapshot. Record which layers were actually read and which
extra owner path was protected. Reject ancestor, replacement, rename and link grants; verify every tier
and another-owner adoption in guests. This cannot constrain root or an ungoverned writer outside Tego.

## Hashes, record and receipt

`contract_hash` stays SHA-256 of **the contract alone**: the loaded profile/preset merge's `Canonical()`
bytes before baseline materialization, ceilings and runtime/live transformations. Canonical means the
existing Go-field-order YAML, two-space indent, LF and final newline, with existing nil/empty and
lossy-string rules (`canonical.go:21-47,92-99`). Comments/formatting are excluded. No new hash prefix,
reordering or normalization is permitted. `contract.yaml`, `compile --merged`, RuleTable.Hash, units,
previews and old receipt checks retain these bytes/meaning. Live already uses this separation
(`compile_live.go:30-31`).

Add `effective_hash`: SHA-256 of that same encoder's bytes for the working contract after the applicable
baseline is prepended exactly once, with mode preservation, **before** ceilings/live/runtime transforms.
Save these bytes as `effective.yaml`; `compile --json` exposes `effective_hash` only when a nonempty
baseline was applied. An absent or empty baseline retains the base JSON shape. An explicit effective
output option prints those bytes. Inserted baseline file strings use the compile-home-expanded kernel-walk
spelling; retain raw strings separately in rule metadata. Different owners with different expanded targets
must differ in effective_hash; add a cross-owner byte/hash fixture. No applied entries means effective
bytes/hash equal contract bytes/hash.
A record-only run has no applicable contribution, hence equality, despite a configured snapshot.
Baseline insertion keeps duplicates against contract lists, so a redundant baseline addition still
changes the effective hash. Baseline source positions/comments do not. Tier, ceilings, pins and actual
coverage are not hashed by it: compare those recorded facts too before claiming equivalent enforcement.

`baseline.sha256` separately hashes normalized configured rules for this compile home. Its canonical
bytes are a fixed-field JSON object in order `v`, `fs.deny_read`, `fs.deny_write`, `exec.deny`, `env.deny`,
with v=1, arrays always present, unique decoded strings sorted by UTF-8 bytes. Path strings have home
expansion but retain the walked spelling; unresolved entries retain their original spelling and recorded
resolution error/absence. Encode with Go `encoding/json.Encoder`, fixed struct fields, no indentation,
`SetEscapeHTML(false)`, one final LF; reject invalid UTF-8. Exclude sources, line numbers, file identities,
coverage and tier. This digest is of the configured snapshot even in record-only mode; it is not a hash
of kernel state. `effective_hash` preserves actual insertion order rather than this digest's sort order.
Each source digest hashes the exact raw bytes loaded, never a reopen. Empty-file digest differs from
absent; absent sources have null digest and explicit state.

Consumers must preserve these distinctions:

| Consumer | Decision |
|---|---|
| Units, source pinning, saved dashboard previews, `compile --merged` | Keep contract_hash. An independent future enforcement pin may require effective_hash; never silently reinterpret stored pins. |
| Dashboard in-force/Pending (`rulesview/inforce.go:417-436`) | Keep source-position matching on contract_hash; add effective_hash comparison for “rules for this run changed”, with baseline source/coverage detail. |
| `tego drift` | Keep contract grouping/hash fields; later add effective grouping for enforcement comparisons, separately labeled. |
| `tego receipt --check` | Old binding versions retain contract_hash and byte comparison. New bindings compare both hashes and recorded baseline/coverage; never recompute old receipts with today's baseline. |
| ADR 0143 CI receipt | Its `binding.contract_hash` remains contract-only. Add effective_hash/baseline facts through a coordinated additive binding revision; future enforcement comparisons must use them. Retain existing signature/binding meanings. |

Take **the next free minor at merge time**, without naming a number for baseline. Baseline has no numeric
allocation yet. Add its constant with its writer and test contiguous minors. Update `record.go`, record spec and
the reservation table together, preserving published meanings. Raising Minor also admits
reserved 32-35 payloads: test their gates and do not claim their writers exist. Other branches already
claim the candidate numbers (the reservation table).

Keep `run_start.contract_hash` and always write `run_start.effective_hash` and `run_start.baseline` at
the allocated revision, even with zero rules. All SHA-256 fields render 64 lowercase hex digits, without
a prefix; JSON/text receipts label the contract and effective values separately. Suggested shape
(field requirements are normative):

```text
baseline: {v:1, mode:applied|not-applied, sha256, owner_uid, home,
  sources:[{layer,file,state:present|absent|unselected|unknown,sha256}],
  protected_owner_layer,
  rules:[{id,key,value,expanded,state:present|absent|unresolved,
    rule:[],sources:[{layer,file,line}],
    tier,plane,held:kernel|conditional|best-effort|not-applied,
    operations:[],conditions:[],limits:[]}]}
```

Each `rule` is a list of exact compiled action `rule` identifiers this entry contributes to, not YAML
text or a new rule id. Several identifiers may implement one entry; duplicates may share identifiers.
An empty list requires a reason (absent guard, redundant outside-grant write refusal, or not-applied).
Carry baseline membership without replacing action rule ids. The rules array preserves union order;
replay reconstructs that order with the recorded home and expanded values. Each entry's actual table cell, operation
scope, alias support and limits must appear in both this block and the receipt. Conditional rows name
which conditions passed and the residual; compile diagnostics carry `refuse-launch` rows when no run exists.

At/after this revision, a missing block is invalid/unknown, never “no baseline”; earlier records mean
unknown. Record-only uses `mode:not-applied`, all entries not-applied. Validate required fields, digest
syntax, source/rule membership, duplicate keys and revision gates; retain unknown optional-field behavior.
Older readers ignore optional fields and cannot validate this meaning. Chain checks cover original bytes.

Receipt example: “Baseline evaluated: 2 held by the kernel, 1 conditional (held reads; future unpinned
rename/link limit), 1 best effort (exec argv).” Then show each rule's sources, actual tier/plane and the
same coverage fields, full baseline/contract/effective digests, and consulted layers including absence.
Never print bare “applied” as assurance. Configuration edits affect subsequent launches, not a running
snapshot. Replay displays recorded facts even after files change/disappear. Disclose namespace authority
limits. If a rule is also in the contract, show both memberships without claiming unique causation.
Count recorded refusals only; environment filtering invents no syscall refusal. Preserve best_effort,
coverage/loss notes and `reads_notified`: when false, say reads were not recorded and counts exclude them.

## Editing and compatibility

`tego baseline` shows the union, every source, coverage context and scope sentence. `add`/`remove` support
`deny-read`, `deny-write`, `deny-command`, `deny-env`; command strings use contract parsing, not shell
expansion. User edits target the invoking user's passwd-home layer; `--system` requires root in the
initial user namespace. `$TEGO_CONFIG` is input, not an implicit destination. Removal affects only the
selected layer and names other layers still contributing. Reject accidental root-owned user state.

`check [contract...]` is offline. Without arguments check all discovered contracts, preserving ambiguous/
unreadable findings; with arguments use explicit files and cwd. Discovery uses recorded cwd/owner/home
or an explicit selected project context; unknown context means incomplete. `--dry-run` shows the same
proposed union, diff, conflicts and checked owners/tiers without writing or preparing a backend.
Compare both current and proposed unions; existing failure does not veto a repair. Refuse saves when
the proposed check fails or is incomplete. Empty discovery says “No contracts were found to check”.

Use locked compare-and-swap edits with safe descriptors, link checks, fsync/rename/directory fsync.
User files use 0600 temporary files; system replacements retain safe, user-readable mode/ownership.
Recheck all input digests before saving. Stale preview/conflict is exit 1; usage 2; unreadable/unsafe or
uncertain input, permission and write failure 125; success or stated no-op 0. Show escaped text, no
variable values, preserve comments/unrelated keys. Check governed membership before preview and save.
Dashboard uses this same path and returns 403 to governed peers. No cross-file preflight replaces launch
checks. Root may edit the file outside Tego to recover from a rule blocking every discovered contract.

No baseline I/O, locks or RPC occur per action. Use ordinary compiled tables; increased table size,
argv checks and held reads still cost work. Performance is unmeasured. Asks, network baseline rules,
grants, remote distribution, signing and exceptions need later decisions.

## Build slices

Do not expose baseline
launch support until slices 2-6 and 9 close. The table defines each slice's required proof; the dated
implementation notes say which host checks have run. Guest closure remains open.

| Slice | Builds and dependencies | Files | Tests that close it |
|---|---|---|---|
| 1 | Contracts CLI/catalog, no added rule; no risky dependencies | new `internal/contracts`, `internal/cli/contracts.go`, catalog docs | Unit fixtures: ambiguity, unreadable/missing roots, hostile historical paths; view adds no rule |
| 2 | Config schema, immutable union/sources, trust, compile-home and absence policy; after 1 | `pkg/spec/config/{types,parse,merge,load,trust}.go`, config spec | Parser/union units, missing home/target across owners, absent sources, TrustAbort on all baseline paths; planned FuzzBaselineConfig |
| 3 | Single materializer, mode/origin preservation, dual hashes and replay handle; after 2 | new `pkg/spec/agent/compile_baseline.go`, `compile.go`, origin/canonical code; CLI/nextrun/rulesview/learn callers | Parent-commit no-baseline byte fixtures; null-allow test; origins after prepend and top-file checks; applied-once replay test; planned TestBaselineRefusalSuperset first pass; planned FuzzBaselineMerge on contract text |
| 4 | Grant/socket/env/command conflicts; after 3 | agent fs/exec/env/live/credential compilers, `execmatch`, `internal/runtime/run_child.go` | Units for every conflict above, empty/null sections, credential/harness final env, anonymous images and socket aliases; planned FuzzBaselineCommandIntersection using matcher oracle |
| 5 | Identity/topology validation and per-tier coverage, R10 owner layer; after 4 and the bind-alias fix | agent fs/mount/link code, backend selection/prepare, `internal/cli/adopt.go`, runtime enforcement | Symlink/bind/case/hard-link units, cut inventories fail closed, detached subtree/plane fallback checks; complete superset property matrix over all tier/plane contexts |
| 6 | Record revision, effective copy, receipt/check and replay facts; after 5 | `pkg/spec/record`, `spec/record/v1`, reservations, runtime ledger, `internal/check/receipt`, CLI receipt/drift/rulesview | Schema/byte fixtures: zero/not-applied/malformed/missing blocks, reserved minors, old checks unchanged, both hashes, config edit/deletion replay, per-rule table parity in receipts |
| 7 | Baseline show/add/remove/check/dry-run with shared edit service; after 6 | new `internal/cli/baseline.go`, shared config editor, user/spec docs | Units: repair, duplicate union, compare-and-swap, safe system modes, incomplete multi-owner checks, governed edits, unsupported flag |
| 8 | Dashboard baseline view/edit via slice 7, updated words; after 7 | `internal/control/rules`, rulesview, templates/static files | CLI/dashboard byte parity, source/coverage rendering, stale edits, governed peer 403, escaping, browser/accessibility checks |
| 9 | Guest proof and fix round; after 5-8 | owning packages above; `test/vm` suites | Per-tier checks below, receipt parity and second reading; fix failures before acceptance |

Planned test TestBaselineRefusalSuperset generates **contract text**, not just structs: absent/null/`[]`/filled keys,
sections and top files, profile chains/diamonds, every preset combination, baselines and fixed action facts.
Compile C and C+B for Landlock, cgroup LSM, cgroup fmod_ret, fanotify and bpflsm. Require
a refusal to remain refused, an ask to remain ask or become refused, and an allow to remain allow or
tighten. A changed refusal reason must be the reason of a baseline entry that refuses that action;
unrelated reason changes fail the property. Count decision comparisons, refusals retained and asks
retained or tightened separately. Require every applicable entry to refuse its covered actions, preserve
image mode, and retain no-baseline bytes. Compile failure means no launch; also compare successful
tables so a compiler that always fails cannot pass. Include argv/multicall, symlink/bind/hard-link/case
spellings, reads/writes and env names. Seed the null-allow example. Fuzz the parser, text materializer/merge
and command solver; preserve the parent fixtures instead of regenerating expectations with new code.
The kept corpus is finite: seven baseline choices, five modeled contexts and synthetic mount topology.
It does not generate arbitrary baseline combinations, successive nonempty-baseline changes,
system-only absent targets or mutations during admission. Separate regressions cover admission changes;
modeled comparisons do not establish guest enforcement.

Guest closure is mandatory at Landlock, cgroup **LSM, fmod_ret and fanotify separately**, and bpflsm:
bind of target/ancestor/detached file/subtree; existing hard links; symlink swaps; rename/exchange/link
of launch and future reads/writes; copied/memfd/interpreted denied programs with honest residual receipts;
actual final environment; session/system bus, container and protected IPC escape grants; edits/replacement
of every layer from a governed run, another-owner adoption included; tier pins/ceilings/fallbacks;
record-only runs; and receipts after config changes/deletion. Test both positive supported cases and
required refusals. Demonstrate A11 and out-of-scope exec results as limits, not passing refusal claims.
The guest runs and superset property test, not this source reading, decide acceptance.

## Slice 1 implementation amendment, 2026-11-11

The read-only CLI/catalog is implemented separately from baseline support. `internal/contracts` sits above
`registry.Places.CatalogContext`, `runstart.Load` over the existing `ledger.RunRepository`,
`rulefile.Read`, `profilesrc.Chain` and the shared compiled view. Depguard keeps runtime packages from importing it. No compiler, merge,
canonical encoder, rule application or record schema changed. The ADR's overall proposed status and future
acceptance conditions remain unchanged.

The catalog includes the explicitly selected current project, recorded project roots, the user registry and
recorded contract sources. There is no separate service/deployment registry on this base. The shipped systemd
agent template resolves its instance through the user registry, which is fully listed, including never-run files.
No arbitrary unit parsing or alternate service discovery was added. Dashboard catalog integration remains slice 8.

Historical paths with non-canonical components are displayed as unsafe without opening them. They are not cleaned
into another kernel walk. An explicit show path is placed with `agent.WalkedPath` first. Historical and explicit
sources pass the existing rules editor's bounded, no-follow, ownership and own-state guards; registry sources
retain their contained loader's safe relative-link behavior. Missing/unreadable roots and unknown owner/home
contexts are explicit. Even root does not enumerate other homes; a referenced different-owner file is shown
without claiming to compile under that owner's unselected context.

`agent.Offline` alone still attempts DNS. This view also supplies an immediate resolver that always defers it,
so no network lookup is made. It uses the caller's PATH for file inspection and today's TrustAbort machine
config. The latest recorded cwd supplies relative-path context; it does not reconstruct a historical PATH or
machine policy. Header-only ledger reads disclose malformed starts, use the existing reader's limits and follow
no link at the events file. They do not verify the chain or scan action history. A hash match compares canonical
merged contract text only; an observed run is explicitly not enforced.

Versioned list/show JSON and a shared schema live under `spec/contracts/v1`. Source relations are arrays separate
from rule identity, ready for a later baseline source. Human rules reuse the current rules view's sentences;
`show -v` and JSON `table` preserve `agent.PrintRuleTable` byte for byte. Lists retain at most 4,096 contracts and
32 MiB of registry source bytes. Registry directory-entry and ledger-view run limits also apply, with a 32 MiB metadata estimate. Checked registry
aliases of the same file are one entry, preserving the registry's existing identity comparison. A bound makes
the result incomplete with exit 125; it never silently becomes a complete answer.

The slice tests cover valid/invalid/missing/unreadable/unsafe sources, name ambiguity, absent/unreadable roots,
hostile historical paths, changed canonical text and formatting-only edits, unknown old hashes/owners, observed
runs, no DNS, unchanged compile tables and canonical bytes, source provenance, text goldens, JSON Schema and
layering. CLI execution and cross-owner/root file behavior are owed in a guest. No baseline guest proof is claimed.

The shared run-start projection lives in `internal/ledger/runstart`, used by the catalog and the dashboard read
model. The pure compiled-contract projection is shared below the live dashboard view. `cmd/tego` links no
`internal/control` package; ADR 0100's original link ban remains intact. No dashboard-only reachability allowance
or unrelated ledger-view wrapper removal is needed.

Fix round 1 added a 60-second whole-command deadline and 5 seconds for each contract check and registry scan.
The first acceptance fix moved recorded-path work into goroutines. In accept3, the command printed its result
within 5 to 10 seconds, but kernel-blocked threads prevented its process from being reaped until FUSE was aborted.
A returned catalog therefore did not establish that the command returned.

Fix round 2 replaced same-process recorded-path work with helpers. Fix round 3 extends that boundary to
all dashboard checks of recorded and user-supplied locations. Both binaries reexecute `/proc/self/exe` with
fixed private modes. A short launcher starts the worker and exits; the caller reaps the launcher before sending
paths as framed descriptor data. Neither PATH nor a replaceable executable name chooses the helper image.
The existing privilege guard runs before helper dispatch, including the control binary's root/capability refusal.

One context-owned worker serves sequential command checks and all checks for a dashboard page, including
guide bootstrap, change-feed and link-reference reads. They take the request context and session. Reuse removes the former
launcher/worker pair per source. Only abandonment or a transport refusal discards that worker. Each exchange
has a five-second deadline; the CLI retains its sixty-second whole-command deadline. Closing both caller pipes
interrupts pipe I/O, so service request goroutines do not wait for filesystem recovery. A worker-wide pipe-HUP
watcher cancels the current operation when its caller leaves; registered operations receive that context.
Guarded mutation paths check cancellation again before submitting file writes or replacement renames.
A resumed operation that observes cancellation refuses a new contract/registry/live-overlay commit or
directory creation. Cleanup can still remove empty directories it already created. Cancellation is not atomic with a write
syscall and cannot undo one already submitted. Each exchange has private
reply ownership; a late reply cannot mutate returned entries or satisfy a later worker's request. A submitted
mutation with a timed-out reply can have an uncertain outcome. The user must reload after recovery before retrying;
the helper boundary does not make a kernel-blocked write cancellable or transactional.

The spawning thread and worker remain pinned during credential capture, start and comparison. Real/effective/
saved/filesystem ids, groups, all five capability sets, securebits, NoNewPrivs and Seccomp must match before every
request. Exec and every request retain an empty environment. Fix round 4 removes environment restoration:
the caller freezes identity, passwd home/username and lookup failure, guard homes, runtime bases, IPC paths,
PATH and working-directory facts before dispatch. The service context also carries its selected machine snapshot,
home, anchor, ledger, registry and profile locations. Missing caller context refuses a request. Workers do not
select or derive these facts from their process. Compiler and profile checks consume the explicit value. Secret-environment
warnings receive names without values. Request/reply frames have a 128 MiB byte cap, raw source bytes and complete
private machine snapshots. The helper never reloads configuration. The earlier preservation claim was too
strong: dropping XDG_RUNTIME_DIR could loosen runtime-parent refusal; helper/in-process parity now covers
default, alternate runtime/config/home and framed delegate contexts. Actual sudo identity remains owed in a guest.

The caller also selects evaluation time, including its offset for rule-comment dates and guide scan freshness.
An explicit date clock remains supported. Resolver selectors (`LOCALDOMAIN`, `RES_OPTIONS`, `HOSTALIASES`,
`RESOLV_HOST_CONF`, `RESOLV_MULTI`, `RESOLV_REORDER`, `RESOLV_ADD_TRIM_DOMAINS`,
`RESOLV_OVERRIDE_TRIM_DOMAINS` and the relevant `GODEBUG` modes) cross as names only.
When these settings cannot be reproduced in the empty helper,
an added hostname gets a cannot-tell preview warning through both paths; the check neither restores their values
nor silently uses a different resolver. A supplied resolver remains an explicit test seam. The next run resolves
hosts independently. Journal/live-change PID attribution remains the actual writer/helper PID, not the service PID;
compiler/refusal parity does not claim identical mutation IDs or process attribution.

The old four-worker shared budget refused healthy concurrent commands. Fix round 3 raises it to 32 workers per
effective uid and network namespace, allowing sixteen simultaneous healthy commands plus sixteen slots of
headroom. This is a finite resource ceiling, not an availability guarantee under arbitrary concurrency. Each
worker retains an abstract Unix datagram socket reservation on fd 2 until actual process exit, even after its
caller exits. No socket data is sent or received. Predictable-name squatting can deny a slot but cannot inject a
reply. Each caller process also has 32 local worker slots; cancellation releases the local worker slot, but cannot release
the kernel reservation of a blocked worker. At most 32 short launchers can briefly coexist, for 64 helper
processes during startup. Exhaustion, inability to reserve, and a changed post-exec credential boundary refuse
checks without trusting the path. [Measured costs and refusals](../testing/contracts-helper-cost.md) give the
before/after matrix and the resource estimate. No contract, record or receipt schema changes. Rules JSON adds optional source_unavailable.

### Availability correction (2026-11-17)

A closed request's healthy worker can still retain its kernel reservation briefly until actual exit.
Immediate admission refusal made sequential checks fail when other commands had nearly filled the uid-wide
pool. Local and kernel-slot admission now share at most one second within the exchange's existing
five-second deadline for capacity, leaving the remaining time for the check itself (since 2026-11-20 the wait is
part of the start-up budget, see below). Kernel reservations
are rescanned on a 10 ms timer. The 32-worker ceiling, inherited leases,
credential checks and abandonment rules remain unchanged. A stuck worker still retains its reservation;
continuous saturation has no availability guarantee and cannot grow the pool.

The dashboard treats a bounded contract-check failure as temporary unavailability (HTTP 503), including
structured, raw and new-contract Save and the raw Save's preliminary checks. Its page says the check could
not finish and asks the person to reload the contract and its History, review again, and then try saving.
It does not claim that nothing was saved: a submitted mutation whose reply timed out may already have reached
the file. No automatic write retry is performed. This preserves the uncertain-write decision above while
replacing the generic HTTP 500 and the new builder's misleading definite “Not saved” response.

### Start-up and location budgets (2026-11-20)

One five-second deadline covered the whole exchange, and it started before the helper process existed. On a busy
machine, starting the helper, or waiting for a free slot, used the budget, and the person read "cannot tell: this
location does not answer (a disconnected or stuck mount?)" about a location nobody had asked. The exchange now has
two budgets, and each refusal says what happened.

- The **start-up budget** (`contracts.StartTimeout`, 30 s, ten times that in a race build) covers waiting for the
  session's gate and for a free helper slot (local and kernel), starting the helper, and its report that it is
  alive. The report is a ready frame (status byte 2) the worker writes after it has decoded the request and
  before it runs the operation. A miss refuses with `cannot tell: Tego's checker did not start in time (the
  machine is very busy); try again` (`contracts.StartupUnavailable`), the typed `startupError`, which still wraps
  the deadline, so every caller that refuses on a deadline refuses the same way. Nothing was sent to the location,
  so nothing was written. The one-second slot wait of the 2026-11-17 correction is part of this budget now: a pool
  held by stuck workers refuses after the start-up budget, not after one second, and the refusal still names how
  many helpers are alive.
- The **location budget** (`contracts.CheckTimeout`, stays 5 s) starts when the ready frame arrives, in the caller
  and, as a duration (`checkRequest.Within`) never as a wall-clock time, in the worker. Only a miss of this budget,
  and any other failure after the ready frame, says "this location does not answer". A write already submitted
  keeps the uncertain-outcome wording above: its reply can only time out inside this budget.

A stuck mount still costs at most the start-up budget plus five seconds for one check, never a hang. A page or
command that makes several checks shares one start-up budget and one location budget (`contracts.WithBudget`,
`pathcheck.Bound`), as the one deadline of a page was shared: after one location did not answer, the page's further
checks refuse at once. A helper that is reused (a session's second check) is ready at once. The absolute deadline
that `pathcheck.Bound` used to send across the pipe is gone: it started before the helper existed.

Callers keep the two sets of words apart by type. `contracts.CheckUnavailable` never re-words a start-up refusal,
`pathcheck.LocationError` and `pathcheck.Call` keep it, and the dashboard's tests for a refusal that changed
nothing (`checkUnavailable`, the unavailable entries, the unavailable source) ask `pathcheck.IsUnanswered` for an
error and `pathcheck.UnansweredText` for text a view carries, so both refuse the same way and show their own words.
Not covered by this section, closed by the next one: work the operation itself does inside the helper (a draft
compile), and a start failure that is not a deadline.

### A compile is not the location; what each refusal knows (2026-11-20, fix20)

fix19 left five places where Tego still said something untrue. Each says what it knows now.

1. **A compile is not the location.** The rules service runs the draft compiler (`draftcompile.Check`) inside the
   helper, so its child's start and its three seconds were spent from the location's five, and a compile that did not
   finish said "the new contract does not compile, so nothing was written: context deadline exceeded". The location
   budget is a clock that runs only while the helper touches the location. `contracts.PauseLocation` stops it: the
   worker writes a pause frame (status byte 3, then the longest the work may take, eight bytes, nanoseconds, never
   more than `contracts.PauseLimit`, the start-up allowance and the compile budget with room), the caller stops its
   own clock and bounds the pause by that time, and a resume frame (status byte 4) starts both again with the time
   that was left. The worker's context is a pausable clock (`locationClock`), so `pathcheck.Context` no longer
   re-derives a fixed deadline from it. The compile has two budgets of its own: the start-up allowance
   (`draftcompile.StartAllowance`, the helper's `StartTimeout`) covers the compiler slot, the built-in grammar's
   fingerprint, the child's start and its first byte on its standard output, which says it has read the draft and is
   about to compile; `Budget` (3 s) starts when the parent reads that byte. Both are shared by the checks of one
   request (`draftcompile.WithBudget`). A compile that runs out of either, or whose caller gives up, is refused in
   words of its own, as the typed `contracts.CompileNotFinished` (`cannot tell whether the new contract compiles: the
   check did not finish in time (the machine is very busy); nothing was written; try again`, or `...the check was
   cancelled before it finished...`); it still wraps its cause, crosses the helper pipe with `contracts.ErrCompileUnfinished`
   as its kind, and the layers that cannot import `contracts` (`check/rule`, `registry`) recognise it by its
   `NotFinishedWords` method, never by text. "does not compile" is for a real compile error only. A stuck location costs at most
   the start-up budget plus five seconds of location time plus the bounded compile; a pause that is not ended in
   the time the worker named is abandoned and refused in the compile words, because nobody asked the location.
2. **A pool full of stuck helpers.** A helper abandoned after its ready frame and the end of its location budget keeps
   its kernel slot until the mount answers. The process that abandoned it knows exactly that: it records the slot's
   name with the helper's pid and start time (the worker reports its pid in its first frame), and the record counts
   only while that process is still alive with that start time. When a caller waits for a slot and every slot it may
   take is taken, and every one is a record of this kind, nothing it can wait for would free one: it refuses at once
   in the mount's words, "N earlier checks are still stuck on a location, and each holds a filesystem helper slot".
   Where some slot's holder is not known to be stuck (another command's helper, a healthy worker not yet gone), the
   wait is fix19's, the start-up budget, and the refusal says only what is known: `cannot tell: Tego's checker could
   not start: N filesystem helpers are still alive in this uid and network namespace, and Tego cannot tell whether
   they are busy or stuck`. The local pool (this process's own live helpers, each held by a request in progress)
   keeps the busy words: those helpers are known to be in use.
3. **Start failures that are not deadlines.** A failed fork, a refused credential check, a launcher that exits
   non-zero, a worker that dies before its ready frame: `cannot tell: Tego's checker could not start: <reason>`
   (`contracts.StartFailure`, `IsStartFailure`). It is the same typed start-up refusal as the busy words
   (`IsStartupUnavailable`, `pathcheck.IsBusy` and `UnansweredText` count both), fails closed the same way, and says
   which. Nothing was sent to the location.
4. **A caller that cancelled** is neither of those: `cannot tell: the check was cancelled before it finished`
   (`contracts.CancelledCheck`, typed, wrapping `context.Canceled`) wherever the cancellation can reach a person or
   a record (a catalogue entry's diagnostic, a service reply); classification-only code (the exchange, `LocationError`)
   no longer maps it to the mount's words at all.
5. **`TestRecordedPathProcessExit`'s other stages** end when the tracer has seen their worker held and says so on the
   command's standard input, as `limit` did, instead of at a 3 s caller deadline; the transport's own bounds still end
   a call that is never answered.

6. **One request is one scope.** The dashboard's `ServeHTTP` makes each request's context a scope
   (`contracts.WithScope`), so every check of a page (the rule service's calls, the in-force view, the guide's keys,
   the path checks) shares one start-up budget and one location budget, not one pair per check. Before this only the
   Rules page (`web/rules.go`) and each service call alone made a scope, so a page of several calls whose checker
   could not start could wait the start-up budget once per call. `TestScopeSpendsTheStartupBudgetOnce` holds the
   budget (five checks of one scope against a checker that never starts take one budget), and
   `TestEveryRequestIsOneScope` that a request's checks are in a scope no other request shares. The governed-Previews
   test (`TestBuilderGovernedPreviewsCannotEvictPersonsReview`) gives each of its 200 Previews its own bound (5 s)
   and the loop one (a minute): a starved Preview counts as starved and fails at its bound, so its running time
   is not the host's, and the property it holds (a governed Preview never evicts or acknowledges the person's
   review, never offers Save) is checked on every Preview that was answered. A test whose worker a tracer steps
   system call by system call (`TestRecordedPathProcessExit`) gives the location the time such a worker needs
   (`locationTimeout`, a variable) in its stages that end on the tracer's word.

Still not proven: the real stuck-FUSE guest recipe (`docs/testing/contracts-stuck-mount.md`); work the operation
itself does after its ready frame that is neither the location nor a compile (a page's own CPU work in the helper)
still runs inside the location budget; a compile that is refused for want of a free compiler slot ("busy, try
again") is not retyped.

### A starved checker is not a stuck location (2026-11-20, fix23)

After the ready frame the five-second location budget still held the CPU the helper needed for its own cheap work. On a
busy machine (a machine running agents that compile and test: Tego's normal case) a helper is runnable but starved: fix19
measured 4.4 to 4.9 s of wall time for a `Current` that needs well under a second of CPU, and the person read "this
location does not answer (a disconnected or stuck mount?)" about a location that had answered. When the budget runs out,
Tego now looks at the helper before choosing words.

- **The evidence** is the kernel's own counters for the helper Tego started, read from its pid and nothing else:
  `/proc/<pid>/task/<tid>/stat` (the state letter) and `/proc/<pid>/task/<tid>/schedstat` (time on a CPU, time waiting on
  the run queue), for every task of the process, sampled at the ready frame and at the end of the budget
  (`contracts.Watch`; a compile pause stops the window, its resume restarts it). The process-wide files of the same names
  describe the thread-group leader only, and the helper's filesystem work runs on whichever thread its goroutine was locked
  to, so the per-task files are the ones that see it. A pid that now has another start time, or that has gone, is not read.
- **The decision** is arithmetic and nothing else. Let the window be the time counted since the last decision, the wait
  the largest run-queue wait of any one task in it, and the run the most time on a CPU of any one task in it. Checked in
  this order: *Unreadable*: a counter could not be read, at the start of the window or at its end. *Blocked*: any task in
  state D at the end of the window. *Starved*: wait at least half of the window (`wait*2 >= window`). *Running*: run at
  least half of the window (`run*2 >= window`), and not starved. *Blocked* again: anything else, that is, a process that
  was mostly asleep, with less than half of the window waiting and less than half running. Half is the plain majority
  for both: a helper that was runnable and not running for most of the window cannot be told apart from one that had
  nothing to wait for; one that was on a CPU for most of it was working, which a stuck mount never does (the thread of a
  helper blocked in a mount is in D or asleep, not on a CPU); one that was neither was waiting for something else.
  (Amended the same day, fix23 follow-up: the first version called everything that was not starved blocked, so a
  helper that was mostly running, a long operation of its own, got the mount words at 5 s, which is false.)
- **Blocked** keeps the mount words at five seconds: a stuck mount still costs five seconds, and its helper is recorded
  as stuck on its slot. **Starved** and **Running** extend the location budget by another five seconds, and again
  while the evidence of each new window still says starved or running (a helper that is then blocked gets the mount
  words at the end of that window), to a hard cap of 20 seconds of location time in all (`locationCap`, four budgets); the
  same cap is also the most a worker's own clock may run (plus a fifth of a budget, so the caller, which reads the
  counters, always decides first). **Starved to the cap** refuses typed with
  `cannot tell: Tego's checker was too slow to finish (the machine is very busy); try again` (`contracts.CheckTooSlow`,
  `IsCheckTooSlow`); **Running to the cap** refuses typed with
  `cannot tell: the check was still working when its time ran out; try again` (`contracts.CheckWorking`,
  `IsCheckWorking`), which blames neither the location nor the machine. Neither says nothing was written, because a
  write already submitted can have reached the file (the uncertain-outcome pages are unchanged), and neither records the
  helper as stuck: it is not known to be. **Unreadable** refuses with
  `cannot tell: the check did not finish in time (a stuck location, or a very busy machine)`
  (`contracts.CheckUnclear`, `IsCheckUnclear`), which claims neither cause, after the one budget, and does not record a
  stuck helper either.
- **A blocked helper's wait (2026-11-21, fix25; revised the same day, below).** A helper blocked in this computer's own disk was getting "this
  location does not answer (a disconnected or stuck mount?)": a person Save sat in `jbd2_log_wait_commit`, an
  fsync waiting for the filesystem journal on a 98 percent full disk under heavy I/O, with 38 ms of run-queue wait in a
  5 s window. When the location budget runs out and the verdict is Blocked because a thread is in state D, the exchange
  reads `/proc/<pid>/task/<tid>/wchan` of each thread in state D (only those, at the end of the window, with the other
  counters) and looks the name up in one fixed table, kept in `internal/contracts/wchan.go` and held to this one by
  `TestWchanTableIsInADR0144`. A name is matched exactly (also when followed by `.`, the compiler's suffix for a split
  function such as `.part.0`) or by the fixed prefix written with `*`:

  | wchan family | Names | Words |
  |---|---|---|
  | Local disk or journal | `jbd2_*`, `xfs_log_force*`, `btrfs_commit_transaction*`, `io_schedule*`, `folio_wait_bit*`, `wait_on_page_bit*`, `blk_mq_*`, `ext4_*` | `cannot tell: this computer's disk did not finish writing in time (the disk is very busy or nearly full); try again` (`contracts.CheckDisk`, `IsCheckDisk`) |
  | Network or user-space filesystem | `fuse_*`, `request_wait_answer`, `nfs_*`, `rpc_*`, `cifs_*`, `smb*`, `ceph_*`, `p9_*` | the mount words, as before |
  | Unreadable, empty or `0` (the kernel hides it), or a name not in the table | | the mount words, as before |

  The disk words need every thread in state D to wait in the disk family, and at least one: a helper with a thread in a
  mount, or in a name the table does not have, keeps the mount words, and so does a disk name on a thread that is not in
  state D. There is no model and no test beyond the table. **A disk wait is slow, not stuck, and is extended** (the
  revision of 2026-11-21, after `TestLearnSaveAndTheDashboardSaveTheSameFile/same` was refused "disk did not
  finish writing" at 5 s on a host whose disk stalled for up to 18.8 s): it is given steps of the location budget as a
  starved or running helper is, one more while each new window still shows every thread in D in the disk family, to the
  same 20 s cap, and a window in which a thread is in a mount, or in a name outside the table, ends with the mount words
  at the end of that window. Only the cap gives the disk words, and only then is the helper recorded as holding its slot
  until the disk answers. A wait in a mount, or in anything outside the disk family, is not extended: a stuck
  mount still costs five seconds. The request scope's bound (`WithRequestScope`) caps the extension as it caps every
  other, in whole steps. The disk words have their own type like the other refusals after the ready frame; it has its
  own type with the other refusals after the ready frame (`pathcheck.IsUnanswered`, `UnansweredText`, `LocationError`,
  `CheckUnavailable`, the remote text prefix and `pathcheck.Words` / `WordsOf`, which give the 503 page its line "the disk
  of this computer did not finish writing in time (it is very busy or nearly full)"), and like the too-slow words it does
  not say nothing was written: a write already submitted may have reached the file. The wchan read is a new reader site
  (ADR 0153's input rows of `sched.go#procScheduler`): the helper's own pid, a process Tego started, and one file per
  blocked thread. A kernel that hides wchan (`kernel.kptr_restrict`, a hardened or masked `/proc`) gives `0` or an error
  and the mount words, as before. The compile child, which has no location, keeps its words, and no extension, for a blocked child.
- **Kernels and sandboxes without schedstat.** `/proc/<pid>/task/<tid>/schedstat` exists only where the kernel was built
  with `CONFIG_SCHED_INFO` (selected by `CONFIG_SCHEDSTATS` and by `CONFIG_TASK_DELAY_ACCT`, both on in the distribution
  kernels this project has measured: Ubuntu 6.17 here; the guest kernels were not read for this change), and a process
  that mounts `/proc` with `hidepid` or a masked `/proc` (a container runtime that hides it) has no such file for the helper
  either. There the evidence is `contracts.ErrNoSchedstat`, every expiry is Unreadable, and the neutral words above apply:
  such a machine loses the starved extension, never the safety.
- **Scope.** One scope (a dashboard request, a command) shares one location budget and one cap, not one cap per check: a
  grant is made from what the scope has left (`budget.extra`), the checks of a page together can spend at most 20 s of
  location time, and after the check that crossed the cap, or any refusal, the scope's later checks refuse at once in
  the same words without starting a helper. fix20's one scope per request is unchanged.
- **The compiler gets the same treatment.** The draft compiler's 3 s budget, which starts when its child says it has read
  the draft, ends the same way: the child's counters (`draftcompile.awaitCompile`, its pid) say starved, and it is given
  another 3 s while that holds (or while it was on a CPU for at least half of its window, the same arithmetic), to 20 s of
  compile time in all for a request (`draftcompile.Cap`); starved to the cap says the compile did not finish because the
  machine is very busy; running to the cap says `cannot tell whether the new contract compiles: the compile was still
  working when its time ran out` (`contracts.CompileStillWorking`); a child that was asleep or blocked, or could not be
  read, says only `cannot tell whether the new contract compiles: the check did not finish in time; nothing was
  written; try again` (`contracts.CompileNoAnswer`). `contracts.PauseLimit` grew to the start-up allowance and 25 s,
  so the helper waits for a compile that was extended.
- **Compile infrastructure failures** (a full compiler slot, "busy, try again"; a start that failed; a child that died or
  returned no result; a grammar that could not be bound) no longer say "does not compile": `contracts.CompileBusy` (`the
  compiler is busy with other checks`) and `contracts.CompileCouldNotRun` (`Tego's compiler could not run`), typed as the
  other unfinished compiles (`contracts.CompileUnavailable`, `IsCompileUnfinished`), with the reason kept and the same
  `; nothing was written; try again`. "does not compile" is for a compile error only.
- **Old readers and callers.** The two new refusals count as refusals that changed nothing, as the mount's words do
  (`pathcheck.IsUnanswered`, `UnansweredText`, `LocationError`, `CheckUnavailable`, the remote text prefixes), and a
  wrapper never re-words them; `IsLocationUnavailable` stays the mount's alone. Every caller that maps these errors to words
  or HTTP codes keeps its refusal class and fails closed, with nothing written.
- **Input inventory.** The reads of `procScheduler` are a new reader site (ADR 0153's input rows for `sched.go`, and
  `tools/rulecheck`'s reader baseline for the changed `exchange`, `handleRequestContext`, `Check` and the new
  `awaitCompile`): they read only the pid of a process Tego started (a helper worker or a compiler child), only its own
  `stat` and `schedstat` and task directory, and no contract, record or location.

Not proven: the real stuck-FUSE guest recipe was not run. The scheduler counters count time on a CPU's run queue;
whether time spent throttled by a cgroup's `cpu.max` counts as run-queue wait was not measured, and a helper throttled
that way that is neither waiting nor running by the counters is Blocked, with the mount words.

### A page is answered before its write deadline (2026-11-21, fix27)

The stuck-FUSE guest recipe (ubuntu 6.17) passed every step but step 9: with all 32 helper reservations held, the
dashboard's first page was closed with no response at 30.1 s. The handler sat in `contracts.reserveHelperWith` waiting
out the 30 s start-up budget (`contracts.StartTimeout`) while the server's `WriteTimeout` is also 30 s (`web.writeTimeout`),
so the write deadline passed at the same moment and the connection was dropped before anything was written. A page
whose checks wait for a slot, a start or a mount can also spend the start-up budget, then the location budget, then
the starved or running extensions: 30 s and up to 20 s more.

- **A request scope has a bound of its own.** `contracts.WithRequestScope(ctx, within)` is a scope whose helper
  exchanges together end by now+within: the wait for a slot or a start (`startLeft` is cut to the time left), the
  location time (a timer for the bound ends the exchange, and `grant` gives a step only when a whole step fits before it, so a helper
  still starved or working when the page has less than a step left is refused as one starved or working to the cap), and a compile's pause (ended in the compile
  words). It is not a new deadline on the request's context, so nothing else changes, and a scope that is a scope already
  is not rebounded. A command (`WithBudget`, no request) has no such bound, so the CLI at capacity still exits 125 after
  the 30 s start-up budget.
- **The bound is derived from the server's deadline.** `web.requestBound = writeTimeout - writeMargin`, with
  `writeMargin` five seconds (times `raceScale`, as `contracts.CheckTimeout` is) and `writeTimeout` the constant
  `Serve` gives the server, so the two cannot drift: `TestRequestScopeIsBoundedByTheWriteDeadline` and
  `TestOuterDeadlinesWrapTheScaledOnes` hold the margin. `ServeHTTP` makes every request's scope a request scope
  with it, except the live stream (`/events`), which lifts the write deadline for its own connection (`live.go`) and so
  only shares the budgets. The first request's header read has reset the write clock before the handler starts; the
  margin is for rendering and writing.
- **What the person sees.** A page at capacity is refused after at most 25 s (not 30) with the capacity words (`N
  filesystem helpers are still alive in this uid and network namespace, and Tego cannot tell whether they are busy or
  stuck`, or the busy words for this process's own pool), and the page answers with its unavailable entry and disabled
  actions, as the recipe expects. A page whose checks use the whole bound has the later ones refused at once, with the
  same words.
- **Why fix20's stuck-pool rule did not refuse at once.** It refuses at once only when every slot is a record this
  process made of a helper it abandoned after its ready frame and the end of its location budget. At step 9 the 32
  reservations are held by stuck helpers of other commands (the recipe runs fresh CLI commands until the kernel bound is
  taken), so the dashboard knows none of them: the pool is "unknown holders" and keeps the wait, as ruled. The CLI
  waits the whole 30 s there too. The wait itself is now bounded by the page's time.

### A full pool of helpers older than any check can live is stuck (2026-11-21, fix29)

fix27 bounded a page at capacity by its write deadline, and still left each page, and every CLI command, waiting its
whole bound when all 32 slots are held by helpers of other processes: this process knows none of them, so it could not
tell stuck from busy, and the dashboard stayed unusable until the mount was fixed. One thing is known about every
helper without knowing anything about its process: how long a healthy one can live.

- **A helper has a maximum lifetime** (`contracts.helperMaxLifetime`): the start-up budget (`StartTimeout`), plus the location
  cap (`locationCapSteps` times `CheckTimeout`, 20 s), plus the paused compile allowance (`PauseLimit`), plus a fixed
  margin (`helperLifetimeMargin`, 10 s). 115 s in an ordinary build, ten times that under race. It is computed from those
  constants (the constants, not the variables a test swaps), so it cannot drift from them; `TestHelperMaxLifetimeIsMadeOfTheBounds`
  holds the sum. Every healthy helper is abandoned at its own bounds (its caller closes its pipes, which ends it), so none lives longer.
  One that is still alive past that age is stuck, by definition: there is no heuristic and no time-to-live, only the
  bounds the caller itself keeps. The margin covers the fork and exec before the first bound starts, the worker's own
  backstop (a fifth of a location budget) and its exit.
- **At the start of a slot wait** (`reserveHelperWith`, the first time every slot the request may take is found taken),
  the holders of the slots nothing else is known about are looked up once. If every one is identified and older than the
  maximum lifetime, the refusal comes at once, in the words of a pool of stuck checks (`ErrHelpersStuck`, the mount's
  type): "N earlier checks are still stuck on a location that does not answer, and each holds a filesystem helper slot, so
  no helper can start". A slot this process's own record says is stuck (fix20) counts as stuck without being looked up. If
  any holder is younger, or exactly as old as the maximum (older means strictly), or its age cannot be read, or it cannot be
  identified, the wait is the start-up budget's, as before, and says only how many helpers are alive. The CLI refuses at once
  the same way (its 30 s wait is unchanged when the pool is not known to be stuck), and so does a dashboard page.
- **How holders are identified.** The kernel's reservation is an abstract UNIX socket per slot in the network namespace of
  the uid; a helper holds it as its standard error (fd 2, ADR 0144's reservation text). A reader (`procHolderStarts`,
  `internal/contracts/holders.go`) reads `/proc/net/unix` for the inodes of the reservation names (the abstract name is
  listed with its leading NUL written as `@`), then names the pid that holds each socket in two ways. First `/proc/locks`:
  a worker takes a `flock` on its reservation before it says anything (`holdReservation`), the lock table names the pid
  that took it, and it needs no right over that process. Second `/proc/<pid>/fd/2` of each process for the socket it is,
  which a process that is not dumpable hides from every reader without `CAP_SYS_PTRACE`: the helpers are undumpable (ADR
  0100, amendment 2026-11-22, F6), so the second way alone found none of them, and the first was added when that was found
  (`TestProcHolderStartsFindsARealUndumpableHelper` fails without it). For a match only `/proc/<pid>/stat` of that
  pid gives the start time (the time since boot, a tick of 10 ms). The age is the time since boot now (`CLOCK_MONOTONIC`,
  which never counts suspended time, so a holder is never judged older than it is) less that start. A slot with no
  identified holder (another uid's process, another pid namespace's, a hidden `/proc`, a kernel without file locks, a
  descriptor other than 2) has no entry, which keeps the wait; when two processes hold the socket the younger decides. Only
  a socket on fd 2 is ever locked, never a terminal or a file. It reads no contract, record or location, and starts no
  process.
- **Inventories.** `holders.go` is a new reader site: ADR 0153's input rows for it (`/proc`, `/proc/`, `/fd/2`, the
  `Readlink` of a process's fd 2, `/proc/net/unix`, and since then `/proc/locks`) and the changed hashes of `budget.go` and `process.go` are listed,
  and the production graph is recertified (a new package-internal reader of `/proc`, no new process producer).
- **Tests** (injected clock and holder reader): all holders old refuses at once; one holder young, one holder's age unreadable,
  nothing identified, a failed reader or clock keep the wait; a holder exactly at the maximum keeps the wait and one nanosecond
  more refuses; a pool with one slot this process knows stuck and the rest old refuses and asks the reader only for the rest; a
  free slot reads nothing. `TestProcHolderStartsFindsTheProcessThatHoldsTheReservationAsFd2` runs the real reader against a
  child process that holds a reservation as its fd 2, and `TestProcHolderStartsFindsARealUndumpableHelper` against a real
  (undumpable) helper.
- **Not proven.** The real stuck-FUSE recipe (`docs/testing/contracts-stuck-mount.md`) was not run for this change: at step 9
  the 32 helpers are seconds old, so the pool is not yet stuck by this rule; the recipe's step 9 now also waits until they are
  past the maximum and expects the immediate answer (a command within 10 s, a page within 20 s), and accepts either words
  for the pages it makes while the pool ages. A helper session that keeps one healthy worker for longer than the maximum
  lifetime (a caller that runs sequential checks outside any scope, without a deadline) would be taken for stuck only when
  all 32 slots are held by such sessions; every session in the product is bounded by its command's or its request's scope.

### Helper slots kept for the person (2026-11-19)

After 200 governed Previews on a busy machine, the person's Save was answered 503: the governed requests'
workers, each holding its kernel reservation until it exits, filled the 32 slots, and the person's check waited
out its one-second admission. A governed program's checks now never take the last four of the 32 slots, in this
process (local worker slots) or in the uid's kernel reservations: a dashboard request whose connection comes from
inside a run, or cannot be shown to come from outside every run, and `tego contracts` run inside a run (or where
that cannot be told), are marked governed (`contracts.WithGovernedCaller`, asked once, when a check first needs a
slot). Other checks try the four kept slots first, then the shared ones. The bound on all slots, the admission
wait and every answer a governed request gets are unchanged; a governed burst alone still gets the bounded 503.
What this does not cover: a same-user process that binds the reservation names itself can still deny slots, as
above. ~~Other callers outside the dashboard and `tego contracts` are not marked.~~ Amended the same day (review
finding 1): a request whose context carries no marker is classified once per process by that process's own run
membership (`runscope.InRun`, which fails closed), so every entry point that starts helpers (tego-control's rules,
guide and setup commands, the rules service, the in-force and insight views, the path checks, the dashboard's
pages) is governed inside a run or where it cannot tell, and only a process shown to be outside every run takes the
four slots with an unmarked request. A marker adds to that membership and never removes it: a dashboard that is
itself inside a run makes every request governed. The dashboard's per-request answer is asked when a check first
needs a slot and is not cached for "cannot tell" (review finding 4): where the dashboard cannot read the cgroup view
it gives the person no reserve, which fails closed.

Compiled policy objects stay in the worker. The service receives the already-built display projection,
rendered table and diagnostics, without a partially reconstructed compiled-policy pointer. The helper redacts
`env.set` values from text and tables while the full compiled policy is still available. It carries the guide's
command-origin flag and live-block refusal words explicitly, rather than inferring either from a lossy display
object. Worker caches
live only for that request's helper; no source stat cache remains on service threads.

The dashboard preserves unavailable catalogue entries and shows
`cannot tell: this location does not answer (a disconnected or stuck mount?)`. Actions that would change or
trust that entry remain disabled. This includes a source or extended profile whose metadata answers but whose
read returns EIO/ENOTCONN or times out. The view carries source availability separately from position fallback;
the chooser keeps recorded guard refusals. Fix round 5 checks every loader diagnostic for unavailable causes,
preserving diagnostic text even when another error came first. The page first receives a copy-only projection,
then checks the source in a second exchange on the same worker within one overall deadline. If the source read
never returns, the received recorded rules, redacted YAML and recorded hits stay visible at copy positions
with an unavailable reason. No source comparison is shown; source edits and trust-dependent actions are
disabled. This requires the ledger and copy to answer. The fallback uses recorded text without compiler probes
and makes no fresh compilation or enforcement claim. The healthy path then compiles once to retain source
positions when hashes match. Its full path-dependent checks run in its own helper rather than leaving a
kernel-blocked service thread behind. A known run view is obtained before location metadata and catalogue
source reads. All share the request budget; a source check that exhausts it cannot start a replacement worker.
A canonical alias that cannot be resolved may leave the selection unidentified. Initial selected
machine-config and selected-ledger loading, plus caller
identity/current-directory capture, still require responsive locations; those are outside the recorded-path boundary.

Host process-lifecycle tests stop a helper at syscall entry. They prove bounded caller waits and actual caller
reaping with a held request, but do not reproduce the uninterruptible kernel wait from accept3. Actual CLI and
dashboard return against a normally answering FUSE server stopped with SIGSTOP, then killed, retained helper
counts/states, exhaustion across commands, recovery/disappearance after abort, and real-root/sudo/other-uid
credentials remain a **MERGE BLOCKER**, **owed in a guest**. The complete versioned
[guest recipe](../testing/contracts-stuck-mount.md) is the acceptance procedure. No guest runs in fix rounds 3 or 4. The revised recipe is run on the final commit.

Registry save still creates its final name directly on this branch. A cancelled submitted create/write may
leave partial bytes. This design relies on the builder's shared atomic writer; registry.Save.WriteContext, reached
by dashboard saveNew/CreateNew and CLI learn --save, will pick up that writer. No second writer is added here.

The compiler preserves `user.Current`'s process-cached real-uid home and first lookup error. At its first
implicit-home compile, it requires that cached uid/home agree with `config.LookupPasswd` for the process's
real uid, refusing disagreement or lookup failure rather than moving protections to another home. The agreed
result or error is then frozen for later compiles. Neither `SUDO_UID` nor the `USER`/`HOME` fallback establishes
the compiler's home. CLI callers with an owner home selected by machine-config discovery explicitly supply it.
Without a nonempty explicit `WithHome`, a lookup error or empty passwd home refuses compilation, including a contract
whose paths are home-independent. Library callers may supply a nonempty `WithHome`; home-dependent built-ins
and the default chain anchor then use that supplied home. Config discovery remains separate: no passwd home
selects no user layer and does not by itself make the loaded baseline UNKNOWN.

*Amended 2026-11-12 (integration security-release precedence):* the earlier acceptance fix allowed absent
passwd entries and empty passwd homes to compile against an absolute ledger root. That acceptance is withdrawn
to preserve the pinned v0.1.3 release's implicit-home refusal. An absolute ledger root does not establish the
compiler's home. Trusted passwd lookup and defensive empty-home path guards remain; integration
tests now require implicit-home refusal and retain explicit-home success. No baseline enforcement is added.

*Amended 2026-11-13 (implicit-home context correction):* the library default also retains the release's
real-uid context. In a real-root process, `SUDO_UID` must not silently replace root's compiler home with another
account's and thereby remove root's credential, IPC or chain-anchor protections. The earlier invoking-uid
default claim is withdrawn. Config discovery still uses the invoking uid; its CLI callers pass a selected
nonempty home explicitly through `WithHome`. Tests exercise the actual default lookup with controlled real-uid/passwd
inputs, check the protected reads and sockets, require root-anchor write refusal, and retain explicit-home
override behavior without consulting the default lookup.

*Amended 2026-11-13 (cached context correction):* a fresh trusted lookup on every compile was insufficient:
the release's `user.Current` caches its first entry or error process-wide. A later passwd-home or real-uid
change must not move protections away from the original home; an initially cached lookup error must not be
retried into acceptance. The compiler therefore consults that release cache first and freezes its trusted
validation. A pre-existing cached uid/home that disagrees with the current trusted entry refuses compilation;
the explicit nonempty `WithHome` API remains available. Tests cover repeated root-anchor refusal after both
changes, cached error preservation, pre-compile disagreement, missing passwd and explicit-home bypass.
Host tests exercise the production pure-Go lookup against a passwd fixture without the invoking uid and
check an exact anchor-file write grant outside the runs directory. Separate single-change overlays cover
lookup and anchor derivation. Actual numeric-uid compile/run checks remain owed in a guest.

Recorded hashes are emitted only when they are 64 lowercase hexadecimal digits. Unknown tiers and invalid
recorded identifiers use `unknown`; record metadata is still unauthenticated. The text comparison header says
`SAME TEXT AS LAST RUN`, while the versioned JSON key remains `same_contract`.

When invoked as root, a recorded root-owned, regular, singly-linked file with no group/other write can pass the
source guards even if it is not a contract; a YAML parse error may quote a short fragment of its contents. Only
the invoking user's selected ledger is read. No additional authority or other-home discovery is introduced.

The separate current-source offline compile path does not reconstruct a recorded tier pin or run-command grant.
Sharing its resolver/options with `nextrun.Compile` remains open. Tests now feed
ESC and newline paths through registry and run discovery, text/verbose show and JSON round trips. Root-independent
failure fixtures replace permission assumptions; real permission and cross-owner behavior are owed in a guest.

## Slice 2 implementation note (2026-11-11)

This dated note describes the config-only delivery. The slices 3 to 5 note below supersedes its
public baseline field, not-applied notice and deferred-compilation statements.

The config-only slice provides `Machine.Baseline`, defensive-copy access to union entries and their
sources, consulted layer states with exact-byte digests, and `Baseline.Resolve(BaselineOwner)`.
The latter takes an explicit uid/home and retains expanded kernel-walk spellings and system-only
absent ancestor/name candidates. It neither decides coverage nor runs during compilation yet.
Decision loads use `TrustAbort`; observation/stop loads use `TrustWarn` and retain unknown layer
states with reasons. `Machine.BaselineKnown()` distinguishes a complete union from UNKNOWN;
UNKNOWN never means empty. The system reader extends the trusted-descriptor reader with
root-owned placement metadata checks and user readability/searchability checks while preserving
I10's file-open boundary. A nonempty union emits a per-contributing-layer notice that the baseline
is read but NOT YET APPLIED to any run. Root identity is modeled in unit fixtures; privileged
ownership and governed layer changes are owed in a guest. This does not accept the ADR or expose
baseline launch support. Decision-load E13 still refuses a selected missing `$TEGO_CONFIG`; unset is
unselected. Baseline lists reject YAML aliases as wrong node types, like the existing config parser.


## Config load classes amendment (2026-11-12)

The first slice 2 implementation made every load abort. A user-owned config file can have its
mode changed by a governed agent at mechanisms that do not hold metadata changes. Aborting
`stop` because that file is unreadable lets the file disable a control that must still end the run.
The two load classes below replace that universal-abort decision. They apply with an empty
configured baseline too, because an unreadable layer cannot establish that it contains no entries.

* **(a) Rule decisions use `TrustAbort`.** Launch, compile, check, adopt, saved-rule validation and
  in-force views that state rules refuse every failed layer before deciding any rules. No partial
  Machine is returned. A current-rule consumer given a degraded Machine must refuse it too;
  checking nil alone is insufficient. `agent.Compile` is the shared guard. This includes recording
  launches: a class (b) command cannot become a launch by choosing record-only mode.
* **(b) Observation and stop use `TrustWarn`.** Stop, status, events, receipt, doctor, dashboard read
  pages and gc keep a degraded Machine. Good layers still supply ordinary settings. A failed layer
  is `unknown`, retains its reason, and makes `Machine.BaselineKnown()` false. A missing passwd
  home selects no user layer and prints no discovery warning. Every output that would state the baseline says
  **baseline UNKNOWN: it could not be read**, with the failed layer and reason. It never says empty
  or no baseline. Such a load cannot start or widen a run. GC reports the failure and sweeps and
  deletes nothing, returning 125: its ledger root or retention could be in that failed layer. A readable ledger
  remains necessary; this change does not repair a run directory an agent made unreadable.

`config.Load` defaults to (a); `LoadMode` and `LoadSources` choose explicitly. `Resolve` only names
sources; it selects no user layer when passwd provides no home. All product loaders and their shared downstream
consumers are classified here. A helper spanning classes must preserve the class at the operation
boundary, rather than silently accepting an incomplete snapshot.

| Loader or consumer in the tree | Class | Use and boundary |
|---|---|---|
| `pkg/spec/config.Load` | (a) | Public default; abort mode. |
| `pkg/spec/config.LoadMode`, `LoadSources`, private `loadSources`/`applyFile` | (a)/(b), explicit mode | One implementation of trust and parsing; mode changes failure handling only. |
| `internal/cli.loadMachine` (`config.go`) | (a)/(b), caller mode | Resolves invoking uid, secure execution and paths once; emits the selected load's diagnostics. |
| `internal/cli.runRun` (`run.go`), `watch.go` through `runRun`, service/deploy launch paths | (a) | A launch, including record-only watch. |
| `internal/cli.runAdopt` (`adopt.go`), `runAgents` with adoption/guard (`agents.go`) | (a) | Compile or attach rules before moving processes. An agents scan alone does not load config. |
| `internal/cli.guard.currentMachine` and `prepareAdoption` (`guard_config.go`) | (a), each fresh adoption and final admission | Strict reload and fresh owner compilation for every new adoption, followed by selected-layer identity/byte and baseline-digest comparison under the migration lock. Empty snapshots are compared too. Failed/UNKNOWN loads never fall back or reuse a prior boundary. Changed ledger/anchor location requires guard restart. Existing adopted runs retain their snapshot. |
| `internal/cli.runCompile` (`compile.go`) | (a) | All compile modes, including effective settings, tests and offline output. |
| `internal/cli.initCheckEnv` (`init.go`) | (a) | Preset draft/check and write validation through `setup.CheckFile`; listing presets needs no load. |
| `internal/cli.runSetup` (`setup.go`) | (a) | Stores a current machine check and checks current contracts; no readiness claim from incomplete config. |
| `internal/selftest.trustedLayer` (`contract.go`) | (a) | Checks the caller's selected explicit layer before copying it; each self-check launch also uses (a). |
| `internal/cli.cmdTest` preflight and post-failure hint (`test.go`) | (a) | Strict preflight prints notices before self-check launches; a later probe reuses that Machine. |
| `internal/cli.cmdContracts` (`contracts.go`), with `internal/contracts` catalog and show | (a) | Compiles today's sources and states their rules (slice 1); a degraded snapshot would state rules from incomplete config. The catalog's `config.Builtin()` for a nil Machine is a library default, not a degraded load. |
| `internal/cli.scanLedgerRoot` (`scan.go`, ADR 0145) | (a), at most 1 MiB per layer (`LoadSourcesBounded`) | Names the ledger root for the scan's live-record probe only. A failed load leaves that probe not read (reason `io`), so it never establishes that a matched agent runs inside or outside Tego. |
| `internal/cli.runDoctor` (`doctor.go`) | (b) | Reports bad config, its reason and mode repair advice; JSON carries baseline.known and baseline.reasons; never restores modes. |
| `internal/cli.runStatus` (`status.go`) | (b) | Recorded/live status; no current baseline assertion when unknown. |
| `internal/cli.runStop` and `runStopAgent` (`stop.go`) | (b) | Existing runs can be stopped after a config-layer failure. |
| `internal/cli.runGC` (`gc.go`) | (b) | Reports degraded config and returns 125; no sweep, retention, journal prune or build deletion on unknown config. |
| `internal/cli.machineOnce.load/get` (`drift.go`) | (a)/(b), operation guard | One snapshot and one diagnostic print per invocation; (a) consumers must reject UNKNOWN before decisions. |
| `internal/cli.events.go`: `resolveRunDir`/`runDirUnderRoot`, follow/verify; `receipt.go`: newest/verify chain | (b) | Resolves record locations and reads/verifies existing records. |
| `internal/cli.runDrift`/`contractTable`, `measure.go`, `verify.go` | (b) | Historical display or verification; unavailable compilation stays unknown, never a current rules claim. |
| `internal/cli.runLearn` read/proposal display and `learnStateDirs` | (b) | Describes a record; a degraded load does not validate a saved contract. |
| `internal/cli.runLearn --allow-host`, `saveProposal` (`learn.go`) | (a) | Configured refused addresses decide proposed grants; saving compiles against a complete snapshot. |
| `internal/cli.runRule`/`compileRule` (`rule.go`) | (a) | Rule mutation, dry-run and next-run validation. |
| `internal/cli.blockRun` (`block.go`), used by block/unblock, route, MCP tools, lift/restrict and pause/resume | (b) for block/route lists, MCP tools and pause; (a) for other mutation | Lists observe and pause only stops; rule changes, unblock and resume can decide or widen a run. |
| `internal/cli.askRoot` (`ask.go`) | (b) for ask/deny; (a) for approve/alternate | Pending-ask display and refusal observe/narrow; approval and alternate delivery can release an action. |
| `internal/cli.vaultDirOf` (`vault.go`) | (b) for list/revoke/disallow; (a) for add/allow/rotate | Display and removal do not widen delivery; adding or changing available credentials requires complete config. |
| `internal/control/cli.loadMachineReport`, `reportLedgerRoot`, `reportAnchorPath` (`serve.go`) | (b) | Dashboard startup/read facts, ledger selection and anchor lookup; errors name the actual failed layer. A failed explicit layer no longer prevents read service startup: the selected fallback ledger and UNKNOWN cause must be conspicuous. |
| `internal/control/cli.cmdRules` (`rules.go`) | (a) | In-force rules output requires a complete Machine; a degraded dashboard may still show read pages. |
| `internal/control/rulesview.loadCopy`, `InForce` and PATH retry | (a) when stating rules | Read pages can remain available, but rule compilation is refused under UNKNOWN, with its cause. Recorded source text can still be shown. |
| `internal/control/rules.Service` check/preview/new/edit/apply/undo paths | (a) | Checks through nextrun/setup must reject unknown config before a rule decision or write. |
| `internal/setup.Check`/`CheckFile`/`Draft`/`Apply`, `internal/nextrun.Compile` | (a) | Shared current-contract checks; caller supplies the complete Machine. A deliberate library nil/Builtin context is not a degraded load. |
| `internal/guide` contract checks (`contract.go`) | (a) within (b) guide display | An unknown config is an unknown contract check; dashboard guide/read facts remain displayable. |
| `internal/guide/guidetest.Fixture.Machine`, `internal/testutil/contracttest` | (b)/(a) fixture modes | Test-only explicit isolated sources, not host config discovery or product launch paths. |

`tego run`, `watch` and `test` hand off to a user scope (`internal/cli/runscope.go`) before they load config; the
handoff reads no layer, and the child it starts makes the class (a) load. The CI receipt verifier
(`internal/check/cireceipt`) reads no machine config; `tego receipt --check` is class (b) above.
`tools/fdcheck.loadConfig` reads that tool's own unrelated JSON type. It is not a machine-config
loader. VM probe uses of `config.Builtin()` are isolated fixtures, not additional file loaders.

This supersedes the dashboard's earlier startup refusal when `$TEGO_CONFIG` failed and no
`--ledger` was supplied. Read/stop service remains available; startup names the ledger it actually
serves and why config selection is degraded. An explicit `--ledger` still selects that ledger.
Current-rule views, approval/resume and every route that could widen a run require complete config.
The service may not turn a read-page fallback into permission to start or widen an agent.

`TestBaselineDecisionAndObservationLoads` holds both load classes; strict consumers are also held
by `TestCompileRefusesUnknownBaseline`. `TestStopSurvivesUnreadableAndWritableUserConfig` checks
that stop still works after mode 000 and 0666 user-layer changes. The temporary notice is removed
by slices 3 to 5; `TestDecisionCommandDoesNotPrintObsoleteBaselineNotice` and
`TestBaselineLoadRetainsSourcesWithoutEnforcementClaim` hold the current behavior. These are
unit/command checks; their execution and overlay-negative results are retained privately.

### Mode changes, per mechanism

This is source verification, not a guest proof. Landlock has no chmod right at any ABI
(`pkg/spec/backend/matrix.go`, `internal/runtime/enforce/landlock/filter.go`); notifying chmod for
recording or gate scoring does not turn it into a metadata boundary. The cgroup fanotify fallback
inherits that limit: fanotify has no chmod permission event. An owner can therefore make its
config mode 000 or 0666 at those mechanisms without a write grant for the file.

Cgroup with an LSM or fmod_ret decision plane, and bpflsm with its LSM plane, differ. The
`path_chmod` hook calls `tego_protect_hook` and refuses a nearest `TEGO_ROW_PROTECTED` deny-write
row (`bpf/decide_stepb.h`). The compiler emits built-in deny-write rows for the compile home's
`.tego` directory (`pkg/spec/agent/compile_builtin.go`), so its config is covered where that row
and the actual plane hold. This is not a universal chmod refusal. A user-owned explicit layer
outside protected trees is not protected merely by appearing in `Machine.Layers`: R10's check
in `compile_fs.go` forbids write grants over the layer, but adds no metadata row. Adoption's
another-owner layer pathname is now included in R10 checks; its privileged enforcement remains
owed in a guest. Record-only runs install no such boundary.
An owner outside Tego can always change its own mode; root or another privileged external actor
is not constrained by these protections. Governed mode changes at every tier/plane are owed in a guest.

`run` restores its invoking user's missing owner bits on `.tego`, its config and own log before
loading, and restores the remaining own state before compile (`restoreUserState`,
`RestoreOwnState`). `gc` does the first part before loading except under `--dry-run`. Run shutdown
restores its own state once its processes are gone (`restoreRunState`). These paths add only the
owner bits needed; they never clear group/other write bits or repair links. Root launchers restore
nothing. Doctor reports a layer mode problem and its repair, with UNKNOWN baseline, but remains
read-only and does not restore it. A bad run-directory mode can still block record tools until
shutdown or manual repair, independently of the config-load class.

### Slice 2 limits and proof boundary

The baseline union uses entry/source sets and has a limit of 100,000 entries per layer, including
duplicates across the four lists. A rejected layer never contributes a partial baseline. Successful
nonempty loads emit `config-baseline-not-applied` for every contributing layer, stating that its
baseline is read but NOT YET APPLIED to any run. Slice 3 removes that notice when materialization
applies the entries. A parsed config is not evidence that an action would be refused today.

System placement checks preserve I10's open boundary. The audit checks decoded pathname
accesses, including no-follow ancestor metadata and link text, with opens restricted to layer
files and their containing directories. It cannot establish complete I10 compliance: inherited
procfs checks make additional metadata accesses whose paths the tracer cannot decode.
Those inherited metadata walks remain release-line follow-up. System placement checks do not
open `/` or placement ancestors. Sticky group-writable placement and an owner unmapped from root are refused,
even for an absent optional system file. Real ownership, namespace and governed-edit checks are
owed in a guest. The fix-round report records targeted positive and overlay-negative tests; no
new acceptance of the ADR or kernel enforcement is claimed here.

### Home discovery and observation results (fix round 2, 2026-11-12)

The earlier unknown-home rule in this amendment is withdrawn. The base loader selected no user
layer when passwd supplied no home. Turning that into an unknown selected layer broke common
container uids. Keep that discovery and trust boundary: never borrow `$HOME` for a user config
path, and print no missing-home warning. No baseline, absolute baseline paths and non-path entries
need no owner home. Only resolving a baseline `~/` entry requires the explicit agent owner's
home. Failure names the entry's layer, file, line and uid, and advises an absolute path or running
as a user with a passwd entry. Loading a raw union does not resolve it; Compile still applies no
baseline entries in this slice. Another owner's home is never replaced by the invoking user's.
The base's missing-home journal retention rule also survives: automatic retention and gc leave
the journal unpruned unless `--keep` is explicit. This rule no longer depends on a printed warning.

A selected layer that fails still makes observation snapshots UNKNOWN and decisions still refuse.
GC's deliberate no-work result returns `identity.ExitError` (125), with one clear line saying
nothing was swept or deleted, including under `--dry-run` and `--json`. Doctor remains available;
every JSON report includes `baseline: {known: true}` for a complete snapshot, or `known: false`
and `reasons`, one string per failed layer naming the layer, file and cause. This outer CLI report
has no separate published JSON schema. These fields assert config completeness, not enforcement.

*Amended 2026-11-12 (integration registry reconciliation):* revision 31 is the
written `MinorLearn`, not an available principal or baseline revision. Declared
revisions 32 to 35 retain deployment, secrets/vault/redactions, shares and
stopped_by; 36 is the unwritten team principal reservation; 37 is held for the
unmerged local-roles profile; business rules are allocated unwritten revision 38.
The former instruction to add a constant for reserved 31 is superseded. Baseline
remains unallocated and takes the next free revision only when its writer lands.
This correction changed no record constant, validator, wire shape or default minor at that checkpoint. Minor 39 was subsequently allocated on 2026-11-17 and is implemented as MinorBaseline while keeping 36 through 38 unsupported.

## Slices 3 to 5 implementation note (2026-11-12)

`agent.Compile` now consumes `Machine.BaselineSnapshot()` after owner-home selection, once.
The machine union has private backing. The materializer copies the affected sections and origins,
prepends expanded entries without deduplicating against the source, preserves the semantic image mode
and rejects rematerializing an effective copy. `Contract`/`Hash` retain the source meaning;
`EffectiveContract`/`EffectiveHash` name the copy before ceilings and live transforms.
`tego rules check --merged` retains source canonical bytes; `tego rules check --effective` prints effective bytes and JSON
exposes both hashes only for a nonempty applied baseline. Empty and absent baselines omit
`effective_hash`, preserving the base compile JSON shape. Text and JSON include each entry's sources,
modeled coverage, conditions, operations and limits. These are compile predictions, not recorded
actual-mechanism claims.
With an empty union, existing table and canonical fixtures are retained.

Membership carries all baseline sources separately from contract/profile positions. Origins move
with nested index keys. `Origin` distinguishes contract, profile/preset and baseline, including a
baseline whose source pathname equals the contract's. Baseline refusals cannot use top-file
write, ask-read or live-fence exceptions. Combined exec bounds are revalidated.

Grant conflicts compare compiled write/read-bearing scopes, asks and fences with primary targets,
known aliases and ancestor identities in both directions, following the table above. Home expansion,
cwd placement, trailing separators and links belong to the grant compiler.
Filesystem write/ask/ask-read, executable and read-fence grants do not expand globs.
Pattern candidates are rejected by their ordinary compiler or schema before conflict checking.
Different filesystem instances exposing the same data remain outside this check. Conflicts also
include command-language intersection through
the real matcher, anonymous restricted images, protected Unix names/aliases/known identities,
environment pass/set and predicted launch producers. Runtime validates the final command and the
final `ChildSpec.Env` after harness additions. Diagnostics retain every source structurally and
bound only the displayed source list. Environment values never enter those diagnostics.

Topology checks use strict mount snapshots, ancestor identities, bind/detached mappings, case
support and bounded link inventories. Truncation refuses placement. Supported linked descendants
get inode rows for decision planes. `BaselineAt` recomputes each tier/plane cell; selection and
preparation validate the actual mechanism and opened identities. A plane skipped by supervisor
filesystem notifications cannot inherit a plane guarantee. An outside-grant write refusal already
held by the global write default needs no extra path-alias proof at Landlock/fanotify.
R10 includes consulted absent files and the selected owner's user layer without importing it.

Sealed `BaselineReplay` handles verify source/effective hashes and reproduce insertion bytes.
They are not CompileOptions. Launch and adoption reject their tables. Old historical routes use
an unknown handle, never today's union, including PATH retry. Slice 6 must validate recorded
revision/owner/source/coverage facts before minting a verified handle, wire it into those routes,
and write effective.yaml and both hashes without changing old receipt bindings.
Its decoder also needs an agent-package reconstruction API for the private identity, deny-write
and topology facts. Compile JSON's modeled coverage is not a serialized replay snapshot; those
facts must come from validated recorded rows, without consulting today's config or mount inventory.

`runtime.baselineLaunchRecord` is an explicit release boundary: an enforcing launch with a
nonempty applied snapshot returns 125 immediately after CLI compilation, before backend probes,
capture/relay resources or process start/movement. Runtime constructors repeat the check. There is no flag or config
exception. Slice 6 must install the record/receipt facts and slice 9 must prove each actual
mechanism before that boundary is removed. Recording-only routes retain not-applied snapshots.
The dashboard reuses one startup config snapshot for its root, anchor and rule service.
Long-running automatic adoption guards reload trusted layers and compile the current owner context
for every new boundary adoption. Preparation and final admission use one table of named admission
checks. Final admission runs every check in the table marked rechecked after the host-wide migration-lock
wait, including strict configuration reload and selected-layer identity/byte and baseline-digest comparison,
including emptiness, against the prepared snapshot. Absent layers compare the no-follow
identity of the nearest observed directory and the unresolved suffix under I10; this
cannot prove continuity between observations or inspect an absent containing directory. A changed, unreadable or unparsable layer refuses
without an empty-baseline fallback. Equal bytes are insufficient for cache reuse: a resolved layer
or containing directory identity can change without changing the layer digest. This comparison does
not pin every ancestor or intermediate link, or prove continuous absence between observations. Startup tables are preflight only;
each adoption releases its own preparation after its run, without retaining retired preparations.
Failed reloads or compiles never fall back to an earlier table. Existing adopted runs keep their
original snapshot. At guard start, record locations capture resolved directory placement and device/inode
identity. During final admission after the migration-lock wait, redirected or replaced ledger/anchor
directories refuse with the location name and a restart instruction. The chain-anchor file probe repeats
under that lock, so replacing the file with a link refuses before movement. Supported record-directory
absence pins the nearest existing directory and literal missing suffix, permits ordinary creation there,
and pins newly observed directory identities. The strict snapshot used for each actual adoption is loaded after
Tego creates its own directories, preserving first-use adoption while retaining strict parent-identity
comparison for changes after preparation.
These are checks at adoption boundaries, not continuous observation or directory custody.

Host test counts, overlay-negative proofs and the fix-round ordinary-adoption guest results are
in the base35 report. The initial implementation ran no guest. Baseline-specific root ownership,
actual bind mounts, governed edits and every baseline enforcement mechanism remain owed in a guest.
No private gate ran. This note does not accept the ADR.


## Slices 3 to 5 final admission amendment (fix round 2, 2026-11-12)

Reading a fact before preparation does not admit it across a wait. The migration path calls one
final-admission function while holding the host-wide migration lock, immediately before the first
process move. As corrected in fix round 3, preparation and final admission draw their checks from one
table of named admission checks, each marked rechecked or snapshot on purpose with its reason.
Preparation runs every entry; final admission runs every check in the table marked rechecked. These
include caller process identity, owner and namespace rules, tree-task checks, baseline target identities,
keyed paths, the chain-anchor file probe and selected plane mode's live admission. The CLI callback
reloads configuration with TrustAbort; the table's owner entry rechecks owner-home/record placement
facts. Final admission compares selected-layer identity and exact-byte SHA256 values plus the prepared
admission baseline digest with the prepared snapshot. An empty prepared baseline has no exemption: a baseline
that appears while waiting refuses the pending adoption. The current nonempty-baseline record gate
also sees that newly loaded baseline. Changed, unreadable, unparsable or no-longer-admitted facts
refuse, clean up and move no process. The prepared backend separately checks its selected mode's live
admission before arming the empty scope.

These are observations at admission boundaries. They do not give continuous custody of external
configuration, passwd, paths or kernel preemption mode. Existing adopted runs deliberately keep their
compiled snapshot. External changes after final admission retain the mechanism's documented limits.
No new record or receipt format is introduced.

The saved ordinary-adoption guest test changes preemption after guard startup but before the agent
starts, so it proves startup-cache invalidation only. Retain that startup case. The regression that
changes admission after backend selection and requires refusal, cleanup and no movement remains
owed in a guest; the [admission regression recipe](../../test/vm/baseline-admission.md) records its seams and expected
lines. Real network-mounted homes, governed layer edits and nonempty-baseline acceptance also remain
owed in a guest. Host seam tests and overlay negatives exist; they do not
replace those guest rows or accept ADR 0144.


## Slices 3 to 5 admission table and first-use amendment (fix round 3, 2026-11-13)

The final-admission guarantee is every check in the table marked rechecked. The same named check
functions admit preparation and final migration. The CLI creates the table and runtime extends that
same table as its prepared objects become available; each stage prepares every new entry. Final
admission refuses an unprepared entry and seals the table against later additions.
The guard covers direct static calls within this package; a check reached through an interface value,
a function value or another package is not covered by the guard and is covered by review.
The structural test follows calls by name within each package to a fixed point, including permitted
preparation helpers. Its reviewed call inventory is a tripwire against forgetting classification,
not a proof. The table entries and their tests hold the recheck policy. The chain-anchor file's
`ledger.ProbeAnchor` check belongs to this table as rechecked, independently of its directory's
placement and identity checks. An anchor file replaced by a link must refuse, clean up and move no process.

The table's snapshot-on-purpose entries are:

- `compiled contract`: contract/profile/preset text and compiled choices are the requested input;
  later edits apply to another preparation, and a recording-only target home admits no file boundary or baseline.
- `compiled record release gate`: the release gate checks that compiled table; the rechecked current
  configuration entry independently checks even a baseline added while waiting.
- `selected backend`: functional probes, selected mechanism and immutable boot facts are preparation
  inputs; final admission checks that mechanism's live admission without reselecting it.
- `prepared contract copy`: record bytes and anchor path come from the compiled snapshot and prepared
  configuration, which final admission compares again.
- `compiled runtime eligibility`: adjustable-rule eligibility and requested limits remain fixed with
  the compiled contract, while current baseline configuration is checked separately.
- `local approval floor`: the machine's pinned approval authority (ADR 0154) cannot be carried by an
  adoption; a set floor refuses it first, and the machine config is immutable for the process.
- `prepared enforcement handle`: prepared descriptors, maps, mechanism and row ownership are fixed by
  Prepare; the separate live-plane entry rechecks current admission.
- `run directory contract`: `mintRun` reaches `checkRunDir`, which compares the generated lexical
  run path against the compiled FS and FSAsk rules. This derives from the already-snapshotted
  compiled contract and reads no filesystem state; neither input changes during the wait.
  Allocation is performed once in this entry and is never repeated under the migration lock.
- `skip counter baseline`: this is the baseline the run's skips are counted from; reading it again
  after the wait would hide what was skipped during the wait.

Own-directory initialisation can create the absent user config layer's parent. The strict snapshot
used for each actual adoption is loaded after that initialisation, including owner-record creation for the
invoking owner. Final comparison remains strict: an external configuration or parent-identity change
during the wait still refuses. The same ordering applies to first-use `tego run`; run does not use
adoption's final snapshot comparison. This changes neither the snapshot status of adopted runs nor
the guest obligations above.

## Slice 6 record implementation amendment (2026-11-12)

`MinorBaseline` names the allocated baseline revision in `pkg/spec/record/record.go`. This build understands revisions 0 through 35 and `MinorBaseline`. Reserved revisions 36, 37 and 38 are unsupported here, just like a revision above this build’s ceiling: record decoding and validation, receipts, drift, historical replay, rulesview and metadata projection refuse them with an unsupported-revision reason. No writer for the declared revisions 32 through 35 is added.

Only a nonempty configured snapshot selects this writer revision. A future writer selecting it with zero rules still needs the complete block and effective hash.

The launch and adoption writer seams are byte-compared with pre-baseline fixtures from `2910acb2b` for `run_start` and `run_end`, with the exact host-field masks listed in `internal/runtime/testdata/prebaseline/README.md`. Other event kinds and complete running-process streams are not proven by this comparison.

New run starts retain exact consulted layer bytes and their digests, explicit absent/unselected
states, the original canonical contract, effective canonical contract, both contract hashes,
owner uid/home and whether that context is known, protected owner-layer path, ordered entry
membership and actual tier/plane coverage. Byte strings use JSON base64. `effective.yaml` is
written through the held ledger directory descriptor; failure stops recording rather than
silently losing the new copy. Embedded evidence is limited to 1 MiB before the existing 2 MiB
ledger-line cap. Evidence that cannot fit refuses recording; it is never truncated or offloaded
past validators. Exact config bytes may include ordinary private machine settings, so these
records retain the run directory's existing private access boundary.

`baseline.sha256` follows the fixed-field encoding above. An additional `evidence_sha256`
binds auxiliary facts excluded from that normalized digest, using the fixed Go evidence struct's
JSON bytes with that field empty. It checks consistency, not authorship. Chain verification still
covers original record bytes. Replay parses the retained layer bytes, reconstructs the ordered
union and source lines, checks home expansion and source/effective bytes, reproduces insertion,
and checks action membership and coverage against the retained compiler projection. It performs
no config discovery, passwd lookup or mount inventory while minting the sealed handle. That
projection is historical evidence, not permission to run it. Recompiling ordinary historical
contract paths can still fail when those paths have disappeared; no current filesystem is
claimed equivalent to the recorded filesystem.

Receipts distinguish a baseline in force from a configured recording-only snapshot, show full
source/effective/baseline digests and each entry's actual coverage, and count only recorded
refusals under its action rule ids. Shared contract membership is not unique causation; startup
environment filtering invents no syscall refusal. Binding 3 adds effective and baseline evidence
hashes. Bindings 1 and 2 keep their original comparisons and contract-only meaning. Dashboard
receipts use the same escaped words. Old records produce no baseline claim.

The release boundary is unchanged: enforcing launches with a nonempty applied baseline remain
refused before launch or adoption. Slice 9's five-mechanism proof remains required. The reviewed base35 fixes are integrated. Slice 7 supplies the edit service; slice 8 supplies the baseline card and editor.
The integrated base35 amendments retain compiled-grant conflicts, record-location identities,
ordinary adoption regression evidence and corrected property/CLI compatibility claims.

The record also carries `fact_sha256` commitments for individual owner, source and rule fields.
They identify which independent edit failed before the aggregate evidence check. The opaque replay
projection's object keys are sorted with JSON numbers retained exactly, so key order changes do not
masquerade as a changed compiler fact and inode values never pass through floating point.
Coverage reproduction uses recorded per-entry/path identity relations. A missing relation refuses
historical coverage; no current `stat`/ancestor walk substitutes for a recorded relation. The sealed
handle retains those facts for later historical coverage calls. Both commitments remain integrity
checks, not authentication of the original collection.

Slice 6 host validation (2026-11-13): the complete fresh race suite passed across 17 affected
packages, including the record and shared-vector consumers. Seventeen independent removal
overlays compiled and failed their named kept assertions. Four vet tag sets, both lint profiles,
the descriptor and reachability ratchets, skip lists, rulecheck, record-version gates and
`scripts/rust-check.sh` passed. Earlier fixture chains still verify without a baseline claim;
the no-baseline run-start golden remains byte-identical. Applied recording is tested through
the compiler/record seam, not a running enforcing process. All five actual-mechanism cells,
recording-only/adoption receipt parity and config-edit/deletion checks remain owed in a guest.
The base35 fixes are integrated; their earlier guest evidence remains scoped to that report.

## Reviewed baseline merge and slice 6 admission (2026-11-13)

The merge retains all four reviewed base35 rounds and selects `MinorBaseline` for baseline evidence.
The same admission table now owns two additional snapshot entries on adoption:
`baseline record evidence` builds and validates bounded evidence from the retained layer bytes,
compiled contract, owner known-state and prepared mechanism; `effective contract copy` writes those
bytes once through the held ledger directory descriptor. Both prepare before Attach, Arm and
migration. Final admission retains their results; `current configuration` still reloads strictly
and compares exact bytes and selected-layer identities under the migration lock. The published
run_start uses the prepared evidence. A launched run registers the same two named checks before
record publication and child release. Historical replay remains barred from launch and adoption;
the adoption refusal is owned by `compiled runtime eligibility` and repeated handle eligibility.
Unknown owner context can be recorded without minting a verified replay handle.

The structural guard recognizes the shared record registration helper's literal Check.Run bodies
and follows that helper through the existing reviewed call graph. Its static-dispatch limits remain
unchanged. This merge adds no acceptance of the five baseline enforcement mechanisms.

## Slice 6 fix round 1 (2026-11-17)

Baseline readers validate required evidence on the raw record bytes through `record.ValidateRunStartBaseline` before typed use. Omitted, null, wrong-type and duplicate required facts refuse with a reason; nullability follows `Event.ValidateAt`, including nullable source fields and opaque replay facts. A decode error is a refusal; callers discard typed destinations on every error. The same gate covers raw JSON exports and the dashboard receipt page.

A record without the baseline block proves nothing about a baseline, neither that one applied nor that none did. Existing human receipts without evidence keep their bytes. Slice 7 owes an explicit no-baseline writer state with its own revision when the launch guard is lifted. This allocation supersedes the old provisional baseline number; historical collision descriptions above remain history.


## Slice 6 raw reread amendment (fix round 2, 2026-11-17)

Cached offsets are hints, not validated bytes. Dashboard filtered and whole-run exports,
line detail and retained-window rehydration decode the bytes read again through `record.Decode`
before publishing them. Refusals retain the decoder's reason. The result-cache tail probe
also decodes its line; a refusal forces the uncached path that reports the reason. Offset-based
live-fence and pause/resume polling decode before filtering and report refused lines to the command caller.
Pause/resume damage returns 125 and preserves a later valid confirmation in the output. The normal Store
summary path retains every rejected complete line with its offset. A refused run start or an
unclassifiable line sets `StartError` and clears earlier baseline hashes. Refusal classification uses
the exact `kind` member, including when other case variants occur. Evicted windows revalidate
unchanged retained refusals and skip them without incrementing `Bad` or losing their positioned
metadata; the run page remains available with those refusals. Newly discovered or byte-changed
refusals still propagate as damage. Downloads use the existing
JSONL export-note and CSV single-cell `#` note conventions, with the run, offset and reason;
refusals never become event rows. Retained-window
newly discovered refusals cross the Store worker/publication boundary in `ReadError`; lazy exports and details
return the decoder reason instead of keeping a prior summary without that refusal.
Baseline evidence and its effective/source commitments are checked before E18 UTF-8 repair;
the repair decision for other line kinds is unchanged. `DecodePayload` clears its destination
before JSON decoding, including syntax failure. Direct `json.Unmarshal` callers must discard
the destination on every error; syntax errors may bypass `UnmarshalJSON` entirely.
The [reader inventory guard](../../tools/rulecheck/baseline_readers_test.go) parses sources under all build tags and checks the reader inventory,
site counts and mapped test names. The inventory includes evidence types and fields, named
carriers and payload decodes, plus byte-offset rereads and their shared helpers. Recognized JSON decoder selectors are sites regardless of destination type, including in the codec.
Generic and untyped declarations (methods, local `any` values and function literals included)
are conservative contexts; their calls and calls in evidence-bearing declarations are inventoried
without guessing a callee's inferred type. This deliberately includes non-readers and constructors. This syntax inventory does not prove arbitrary data flow. New sites
require an exercised route and a checked-in inventory update. Guest acceptance is still owed.
