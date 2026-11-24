# ADR 0156: edit contract drafts without changing write authority

Status: accepted for the dashboard builder, 2026-11-12.

A person needs to review a watched run's draft in sentences, while a Full view must retain every field. A view
switch must not regenerate a file from the fields a smaller form happens to know about.

The browser carries the explicit draft through server forms. Simple removes only a grant the draft already spells.
Unknown fields and comments remain in the YAML node tree; a view switch with no change preserves the exact bytes.
The Full editor edits the same draft. Names for recorded addresses are explicit host answers, retaining transport
and port; they never come from an inferred DNS association. The real compiler remains the only contract validator.
A blank draft explicitly starts with empty write, exec, destination and environment grants and retains built-in
secret refusals. No new live widening is enabled by default.

New files use PlanNew/CreateNew. Registry saves and guarded project-file creates share registry.WriteFileAt,
the descriptor-relative contract publisher. Guarded replacements use that same publisher.
Changes use Current, PlanRaw/ApplyRaw or PlanChange/ApplyChange. Browsers still name existing contracts only by
opaque references in the ledger's bounded set. No browser path extends that set. SHA-256 stale-file checks, the
preview-bound acknowledgement, compile-before-write, origin, CSRF and governed-peer checks remain mandatory.

The widening list compares immutable compiled tables family by family through `pkg/spec/agentdiff`, a pure
Layer 0 specification package beside the compiler output types. It links no evaluator or decision engine.
`TestControlLinksNoEngine` remains unchanged and applies in both build configurations. Each family's result is
unchanged, narrowed, widened with its new entries, or cannot classify. A widening may also remove entries.
Every authority-bearing compiler field has exactly one row; reflection tests reject a missing row or a new
field in a custom classifier. The comparison orders each family's grants independently. Another family can
still refuse an operation a widened family grants, so this is not a proof of final decisions or equivalence.
Changed families it cannot order say "Also review: <family> changed and Tego cannot tell whether it allows more"
and require explicit confirmation, as widened families do. Every free edit still needs its acknowledgement.
Compiled profile output, resolved paths and full CIDR ranges are compared, without action probes or I/O.
The matrix is the seed of ADR 0153's general-contract composition check. Extend its rows to prove that
customisation is within the general contract family by family; unclassified results cannot prove that relation.

A security regression test found that the configured registry root could be a symlink even though agents/ was
partly confined with os.Root, which still followed an inward agents link such as `agents -> .`. Reviewed dashboard registry saves now
create and open every directory component, including agents itself, with O_NOFOLLOW beneath the preceding
descriptor. The final descriptor remains pinned through publication. The preview
also refuses a linked root in words; the descriptor walk closes the check-to-write race. This adds a refusal for
linked registry directories; it does not loosen a rule. Existing linked registries must be configured by real path.

A second regression swaps a loaded contract's directory for a link immediately before Replace. Dashboard writes
now ask the existing rulefile writer to open the supplied real path without resolving links again. The final
component walk with O_NOFOLLOW rejects the swap; later operations remain relative to that descriptor.
Linked contract directories are read-only from the dashboard until configured by real path. CLI defaults stay
unchanged. An invalid old contract can still be repaired: the real compiler must accept the replacement, the
review explicitly says that it restores the ability to start a run and requires review of every rule, and the
confirmation binds the old bytes and new compiled table. Old compiler errors are not echoed with hidden values.

The viewer's Simple/Full preference is a one-year scoped HttpOnly SameSite cookie. Native forms and disclosures provide the
same editing/check/save path without scripts. Source errors identify the run selector or preset group;
a missing or invalid run never offers a broken detail link. A rejected new-contract builder save retains the posted redacted editor text instead of
redirecting away its edits. Live errors update their field descriptions, and native error focus follows the
shell's scroll restoration. Save does not trigger the warning for abandoning an edited draft. With scripts the preview alone updates after a Simple choice.
The Full field guide defines every contract key, including nested MCP tools and model routes; a reflection test
checks coverage against the contract types. Simple compiler errors link to their source field or the Full control.
Environment values in existing files keep their existing hidden-value restoration; new raw drafts cannot carry
new environment values through the builder.

Proof is in the builder service, HTTP and chrome-tagged tests. The chrome-tagged checks require explicit invocation.
No runtime or kernel enforcement mechanism changes in this package.

## Fix round 1: one durable contract publisher

Registry entries, dashboard project creates and dashboard replacements now use the registry leaf package's
WriteFileAt. The owning rulefile layer retains its trust checks, locks, backups and journal. No record schema
changes. The registry leaf depends only on specification packages and platform syscalls; it never imports the
rulefile or dashboard layers.

Publication steps are: open every directory component with O_DIRECTORY and O_NOFOLLOW beneath its parent;
compare the final descriptor's device and inode with the reviewed identity when supplied; create a random
exclusive temporary file beneath that descriptor; write all bytes; set the requested mode; sync and close the
file; repeat the owning guards; recheck the temporary inode and SHA-256; for replacement, recheck the old file's
device, inode and SHA-256; atomically
publish without replacement for a new file, or rename over the verified old file for a change; sync the directory.
No contract under its final name is visible with partial contents. An ordinary failure removes the temporary
name and names its failing step. A directory-sync failure after publication says that the complete file was
published. Abrupt process termination before publication can leave an unreferenced temporary dot-file.
Registry post-publication resolution can still refuse an unusable entry. Its cleanup removes the file and
syncs the directory. A failed cleanup explicitly reports that the complete file may remain or that the
removal could not be synced. Existing caller error handling preserves those statements.
The inode/digest checks and final path publication syscalls are separate operations. Another authorized
writer to that directory can race them. This is not an atomic compare-and-swap against hostile directory
mutation; the no-partial-content guarantee describes this writer's publication of its complete temporary file.

Save's registry directories are 0700 and its contracts are 0600. Project creates are 0644; replacements preserve
the previous mode. The effective user owns new inodes, with the filesystem's inherited group. Replacement is
restricted by rulefile to that file's existing owner. Linked registry roots and linked agents directories are
refused even when a link points inward. Replacing the old file with another inode holding identical bytes is
stale. A linked or concurrently replaced backup is also refused. These new refusals fail closed.

Existing callers affected are tego rules learn --save, dashboard registry saves, rulefile Create and rulefile Replace
(including the dashboard and command-line rule edits). The name-resolution, trust, compile, write-entry and
journal guards remain their callers' responsibility. Tests cover `agents -> .`, interrupted publication, syscall
step ordering, directory identity substitution and same-byte inode substitution; caller regression results are
recorded in the fix-round report. Crash durability on a real filesystem remains owed in a guest.


## Fix round 1: exhaustive compiled-family comparison

The table below assigns every `RuleTable` and merged `Contract` field, including private metadata,
with merged-contract fields prefixed `Contract.`. The coverage guard does not exempt private fields.
A classified row may still return cannot classify for incomparable changes. Widened rows name every added
family grant or increased bound. Changes to the other rows always require review.

| Family | Fields | Ordering |
| --- | --- | --- |
| filesystem | `FS`, `Contract.FS` | write grants classified, including the empty-write root sentinel; other differing FS entries or AppArmor assertion cannot classify |
| filesystem approvals | `FSAsk` | classified |
| filesystem protection | `AskDenyWrite`, `DenyWrite`, `DenyWriteLinked`, `NameDeny`, `NameExempt`, `NameLeftOut`, `Reads`, `OwnState`, `OwnReadable`, `DenyReadPatterns`, `AbsentDenyRead`, `AskReadRelaxes` | cannot classify when changed |
| programs | `Exec`, `Contract.Exec` | image, directory, basename, unrestricted and anonymous scope classified |
| program arguments | `ExecCommands` | cannot classify when changed |
| destinations | `Net`, `Contract.Net` | destination scope and TCP/UDP containment classified; changed expiry deadlines cannot classify |
| destination approvals | `NetAsk` | destination scope classified; changed expiry deadlines cannot classify |
| environment | `Env`, `Deny` | classified |
| environment assignments | `Set` | cannot classify when changed |
| run limits | `Limits` | wall classified; other differing limits cannot classify |
| network limits | `NetLimits` | classified |
| approval configuration | `AskConfig` | broker presence, timeout, pending and standing refusal classified; hold changes cannot classify |
| credentials | `Contract.Credentials` | classified |
| read recording | `ReasonReads` | on/off classified; changed auto/off choice cannot classify |
| listeners | `Listen` | cannot classify when changed |
| ingress | `Ingress` | cannot classify when changed |
| DNS | `DNS`, `DNSQueries`, `DeniedResolved` | cannot classify when changed |
| proxy | `Proxy` | cannot classify when changed |
| HTTP | `HTTP` | cannot classify when changed |
| gate | `Gate`, `Workdir` | cannot classify when changed |
| live controls | `Live`, `Contract.Live` | cannot classify when changed |
| assurance | `NetAssurance`, `FSAssurance`, `ExecAssurance` | cannot classify when changed |
| recording | `Record` | cannot classify when changed |
| protection tier | `Tier`, `Reach` | cannot classify when changed |
| capture | `Capture` | cannot classify when changed |
| harness | `Harness`, `HarnessHook` | cannot classify when changed |
| launch grants | `RunCommandGrant` | cannot classify when changed |
| built-in refusals | `Builtins` | cannot classify when changed |
| compile context | `Home`, `ContractPath`, `PATH` | cannot classify when changed |
| business rules | `businessRules` | cannot classify when changed |
| machine baseline | `EffectiveContract`, `Baseline`, `replayed`, `baselineReplayFacts`, `Contract.materialized`, `Contract.baselineCounts` | frozen baseline/replay context; a source-duplicate effective contract uses the existing families, independent effective authority cannot classify when changed |
| MCP | `Contract.MCP` | cannot classify when changed |
| models | `Contract.Models` | cannot classify when changed |
| process privileges | `Contract.IOUring`, `Contract.Keyring`, `Contract.IPC`, `Contract.Setuid`, `Contract.HostSockets`, `Contract.KeepDescendants` | classified |
| launch command | `Contract.Command` | cannot classify when changed |
| reserved declarations | `Contract.Prompt`, `Contract.Skills`, `Contract.Visibility`, `Contract.Docker`, `Contract.Containers` | cannot classify when changed |
| compiler metadata | `Hash`, `EffectiveHash`, `Profiles`, `Contract.Learn`, `Contract.Version`, `Contract.Name`, `Contract.Revision`, `Contract.Extends`, `Contract.Env`, `Contract.Limits`, `Contract.Record`, `Contract.Tier`, `Contract.Capture`, `Contract.Harness`, `Contract.Reason`, `Contract.Gate`, `Contract.Ask`, `Contract.file`, `Contract.origins`, `Contract.loaded`, `Contract.profiles` | non-authority metadata or declarations duplicated by compiled fields |

## Fix round 1: bind review and contain draft compilation

All new-contract and existing builder saves use `reviewAck` and `reviewOK`. The value binds SHA-256 of the exact
restored draft bytes; retained setup actions and displayed setup metadata; destination kind and canonical path;
final directory device/inode; the digest of each
profile and preset read; each loaded or absent machine-config layer and its digest; machine settings; and the
compiled result's digest. A failed offline lookup leaves `NetRule.ResolvedAt` zero because it supplies no
DNS evidence; successful resolution still stamps its clock. The binding retains every field, including TTL
and expiry. With `max_stale`, missing evidence keeps the compiler's already-expired sentinel. The deterministic
snapshot includes opaque DNS/HTTP/proxy/gate data and the
command index's private data. Immutable built-in grammar callbacks use stable slots rather than process addresses;
unknown grammar objects or callbacks refuse the check. Existing edits additionally bind their base SHA-256. A narrowing carries the
same value in a hidden field. Wider and unclassified changes require explicit confirmation. Save revalidates the held proposal and
refuses any binding mismatch. The new preview says that inherited rules or destination changed. Directory identity is
also checked against the descriptor the shared publisher uses. Its pre-publication callback reloads source
bytes; it does not claim to freeze every filesystem object the compiler inspected. A dependency that changes
after the final source read is a later on-disk edit and will be compiled again when a run starts.

Amended in fix round 2: registry-directory preparation (0700) requires the same governed-peer, Origin and
CSRF guards as Save. The source Preview form uses POST and prepares the destination before the final
compilation. Creating its parents changes protected-path metadata, which must be bound in its prepared state.
Read previews do not prepare destinations; when the
registry directory is missing they withhold Save and ask for Preview. The builder read invariant is stated in
DASHBOARD.md's security section. The route snapshot regression enumerates the production registration table,
including followed aliases, for both read methods, using one real service and compiler for Rules and Setup.
Every preview case must reach a valid reviewed plan before comparing home, project and ledger snapshots. Project setup directories are made only after the reviewed acknowledgement matches.
Setup's exact planned directories may compile before their parents exist. This exception skips only that
missing-parent error; the remaining contradiction, protected-state and resolved-path checks still run. Runtime
compiles never use the preview option. Setup creates the retained paths without following a link before the
contract is published. The complete compiled snapshot is recomputed once within Save; the registry hook then
checks path and bytes against it, avoiding a duplicate full compile within the same deadline.

Generated environment assignments, setup metadata and the server-derived withheld list stay in an in-memory draft with a random opaque token,
authenticated session, canonical project/destination and agent name. Source and reviewed proposals share at most 64 serialized entries, 8 MiB per entry and 32 MiB total,
with eviction preferring the inserting session's oldest entry, otherwise the global oldest; insertion order breaks clock ties. Entries expire 30 minutes after creation and are purged on store access. The review binding also covers the retained setup folders, so a different authenticated draft with
identical final YAML cannot substitute other folder creation. Learned drafts retain the registry own-write guard
on Check and Save. Restoration clones the withheld list from the retained draft, never from the form, so an
unchanged rendered Save keeps its review binding. Check and view switches restore only server-held assignment values through the existing strict
placeholder restorer. Save uses the held reviewed bytes, including those values. A literal replacement, another session or a different draft destination is refused without
echoing values. Both YAML projections are redacted. Compiler diagnostics scrub the exact merged assignment snapshot, including
expanded project paths, PATH components and quoted forms. An inherited-load failure uses a generic diagnostic
when no trustworthy merged snapshot exists. A parser failure in the submitted document preserves only its
validated numeric line location, never its message or source values. Empty posted Full text is refused rather than recomposing its
source. New environment values still require a terminal.

Draft checks run in cancellable compiler-only children through the reviewed process-start wrapper. A shared
limit of two children and a 100 ms admission wait bounds concurrency; a request shares a total 3 second compilation/admission budget across helper calls.
File publication and sync do not consume compilation time; they retain request cancellation.
The immutable built-in command grammar initializes once; a canceled waiter stops waiting immediately while
that single initializer finishes for later requests. Cancellation or deadline kills a running child and releases the caller. A slot remains occupied until the child is
reaped, including a child stalled in kernel filesystem I/O. Once both are occupied, other requests get
"busy, try again". The resolver is the existing no-lookup resolver: hostname validation is offline. Existing
lookup warnings run separately with their own bounded budget. Untrusted draft filesystem reads are confined to
the compiler child: inherited profiles/config layers, path/link and mount metadata, executable lookup/loaders,
secret-path expansion and protected-state checks. Project-path canonicalisation and preset composition also use
this pool: setup probes write-path metadata and project markers in a child, retaining its public creation metadata.
There is no profile-load fallback in the HTTP worker after failure. Destination guards and the publisher still
perform their necessary filesystem operations when preparing or writing the selected destination; the child
deadline is not a guarantee that every Save syscall is cancellable. A busy preflight retains the posted redacted
text and its authenticated draft handle for retry. The child starts no agent and writes no contract. No decision
engine is linked.

Evidence is in the retained service, HTTP, child-admission/cancellation and publisher regressions. Real governed
peer exclusion and crash durability remain owed in a guest. These are new stale-review and symlink refusals;
no refusal is relaxed and no record or receipt schema changes.

## Fix round 3: retain the proposal at review

The structured edit builder inserts a dated comment. Rebuilding at Save changed the proposal across midnight
and refused an unchanged acknowledgement. All builder saves now use the retention rule in
DASHBOARD.md, “Simple and Full contract drafts”. Preview stores the bytes, full review binding and setup or edit
metadata in authenticated memory. The acknowledgement carries the unique review identity and authenticates this retained proposal within its session. New-contract bindings also include the
composition draft identity. Raw and structured edits have distinct kinds; raw bindings also cover the
editor-input digest, and structured bindings cover the ordered edits. Every save-eligible Preview has its own random identity, including equal bytes from identical input. A later Preview cannot replace or refresh an earlier review.
Save performs the existing source, directory and exact-byte compilation checks, then publishes the held bytes.
Missing retained state refuses with one sentence asking for review again; no source, preset, run or edit builder
is used as a fallback. This adds an explicit refusal on expired or evicted reviewed state. No record schema changes.

`TestBuilderStructuredPreviewSaveAcrossMidnight` renders a dated structured review for both hostname lists and
saves its exact bytes after an injected midnight. `TestBuilderSaveNeverBuildsProposalAgain` counts proposal
construction across all six source/edit paths. Lost-draft, cloning and count/byte/expiry tests cover the memory
boundary. The real-compiler read-route table measures host fixtures only; real governed-peer exclusion and
crash durability on a real filesystem remain owed in a guest.


## Fix round 4: one review, one identity

Amended 2026-11-13 (fix round 5): the authenticated handler marks a governed or uncertain peer's Preview as read-only; it skips source and review retention entirely and the page offers no Save; a supplied retained-composition handle is refused before store access, so governed readers must preview fresh source.
Every save-eligible Preview mints a separate 192-bit identity from the system random source. Its acknowledgement
carries that identity and binds it with the reviewed bytes and compiled binding. Equal Previews never
replace each other. Reviews expire exactly 30 minutes after their own creation; reads, Save validation
and later Previews never extend that lifetime. Save atomically consumes the review after validation and
before publication, so a replay refuses; a publication failure also requires a new review. The retained
review is keyed only by its identity and checked against its authenticated session. Identity and
acknowledgement comparisons use constant time.
At capacity, insertion evicts the inserting session's oldest entry first, otherwise the global oldest,
using insertion order to break clock ties. Eviction only loses a review; an old acknowledgement can never
select a replacement.
The form carries the review identity as the 48-hex-character prefix of its acknowledgement, followed by a dot
and the MAC. The MAC binds that prefix with every existing reviewed-write field; no acknowledgement lookup
or content-derived key is retained. A random identity collision refuses instead of replacing stored state.
The shared source/review store retains the existing 64-entry, 8 MiB-entry and 32 MiB-total bounds.
No record or receipt schema changes. These are additional replay and lost-review refusals.


## Fix round 4: accept the current reviewed base

A Check after an external edit reviews the current source B, even if its editor opened at A. Its Stale flag
is a historical display warning, not a refusal of the newly reviewed B. Save first validates the submitted
base and current guarded source against retained B, then the directory and exact-byte compiled binding.
Only after those checks does it clear the historical flag, without rebuilding the proposal. An external
edit to C after Check still refuses and requires review again; publication retains its own base/identity checks.
`TestBuilderReviewAfterConcurrentEdit` measures both journeys for raw and structured forms. This corrects an
unintended refusal of a valid review; no source, directory, dependency or compilation guard is removed.


## Fix round 4: required source errors after preflight refusal

The renderer marks an empty required finished-run choice in both views even when an earlier project
preflight refuses. It retains the original refusal and offers no Save; it does not bypass preflight.
`TestBuilderMissingRunErrorWithCancelledPreflight` exercises an already-cancelled real request;
`TestBuilderMissingRunErrorsDoNotDependOnPreflight` covers refusal mapping and deduplication.
This deterministic defect does not identify the unrecorded preflight outcome behind the earlier intermittent
missing-run assertion, nor the separate generated-environment failure. Those historical causes remain unknown.


## Fix round 4: preserve native textarea blank lines

HTML consumes the first line feed immediately after a textarea opening tag. New-contract Full, Simple and
Save forms and raw Simple now share an escaped template helper that emits a protective line feed only when
their text starts with one. That preserves intentional blank lines without adding a byte to the submitted value.
The content remains template-escaped.
`TestBuilderNewLeadingNewlinesSurviveRenderedForms` parses HTML for Full-to-Simple-to-Full and Save, with
zero, one and two leading line feeds, then checks the exact published bytes. Regex form extraction alone
did not cover this browser parsing rule. `TestBuilderRawLeadingNewlinesSurviveRenderedForms` adds the raw
Full-to-Simple-to-Full-to-Simple Save journey and exact-byte check. Raw Full already has a protective formatting LF.
Review and record schemas are unchanged.

Amended 2026-11-13 (fix round 6): the live-region cache previously bypassed the handler's peer decision,
allowing a governed or uncertain reader to receive a person's new-contract preview credentials. Both builder
preview routes now render fresh through that path under ADR 0123's shared-cache rule. Ordinary-GET tests in
fix round 5 did not cover this path. Region regressions cover both request orders and uncertain readers;
ordinary person pages still reuse cached renders. Real peer classification remains owed in a guest.

## Integration with the bounded filesystem service (2026-11-17)

Rule operations retain the current own-image helper boundary and explicit caller context. The serving
process transfers its bounded review store exclusively over that trusted pipe and restores only a complete
reply. An abandoned exchange discards pending reviews, including an uncertain Save; review again before
another write. Governed and uncertain read-only previews never access or transfer that store. A helper
cannot multiply the compiler limit: two abstract socket reservations, scoped to this service, uid and network
namespace, are inherited by compiler children until actual exit. They carry no data and create no disk entry.
Machine snapshots preserve baseline source facts and UNKNOWN state; profile trust uses the selected caller.
Cancellation is checked after blocking reads and before new directory/file publications, including the
no-replace hard-link fallback. A submitted mutation can still have an uncertain outcome.

The newer standalone registry compatibility decision in `b68fbcab6` retains symlinked *ancestors* of the
configured registry. Its registry root and agents directory are still opened without following a link.
Reviewed dashboard saves retain the strict no-link walk for every component and bind the final directory
identity. The broader no-link rule for standalone ancestors remains `TODO(next9)` pending a compatibility
decision; this integration does not delete the existing parent-link regression.

The family matrix explicitly treats withheld Learn history as compiler metadata and compiled private
business rules as unclassified authority. A change to that authority requires review, and no evaluator is linked.

## The rule editor says the compiled comparison's direction (2026-11-21)

The Change rules form (`PlanChange`) and `tego rules edit` named a change's direction, narrows, widens or mixed, from
a lexical model of the file (`internal/check/rule`, direction.go): its own entries, resolved, with no profile, glob
or link in it. The compiled-family comparison above only added review items on top, so the word a person read could
still be the model's: a pure refusal read "mixed" and asked for a confirmation because a family it could not order
changed, `/usr/bin/cat` beside `cat` read as a widening though both compile to one grant, and a glob read "May read
./*.pem, May read ./*.pem".

The direction is now the comparison's alone. `PlanChange` compiles both texts and `agentdiff.Fold` gives one word:
narrows when every family is unchanged or narrowed, widens when some family widened and none narrowed or could not be
ordered, mixed otherwise. A family that cannot be ordered is mixed and never narrowing; a comparison that cannot be
computed is no proposal (the plan's `Err`). Each sentence takes the direction of the families its list is about, and
a sentence whose families compiled to the same tables says "No change: the compiled contract allows the same", which
is how an entry a profile the contract extends also grants reads. The edit core's lexical model still words the
sentences and still decides the live "Also apply now" blocks' list changes; a test compiler, which returns no table
(`Service.Compile`, `Service.Check`), leaves the lexical word in place. Only tests set those.

The refusal side of the filesystem families is now ordered (`pkg/spec/agentdiff/fsrefusals.go`), which is what made the
words above available: a `deny_read` row (a refusal, or a question when `AskRead` marks an `fs.ask_read` entry) added or
made stricter narrows, one removed or made looser widens (and is named), a question that goes beneath a folder that is
now refused loses nothing, and the `deny_write`, approval-scope protection, `deny_read` pattern and nested-read rows of
the protection family are ordered the same way, each only a refusal. A refusal beside a grant at the same path, a
question under a stricter refusal, a changed attribute of a row that stayed and every other protection field
(`DenyWriteLinked`, the name rules, own state, `AbsentDenyRead`, `AskReadRelaxes`, held-read mode, name rules and aliases)
still say cannot classify. The ordering reads the compiler's rows and evaluates nothing. It is held to the decision
engine by `TestAgentdiffNeverCallsLooserTighter` (`internal/policy/decide`) and `TestPlannedNarrowsNeverLoosensWhatTheEngineAllows`
(`internal/control/rules`): over random contracts and random edits, a pair the comparison folds to narrows is
probed with `decide.Evaluate` at tiers landlock, cgroup and bpflsm over reads, writes, programs and destinations, and none
may be answered more permissively afterwards. A mutation that calls a removal narrowing fails it.

A "never allow" a person is offered from a line (`ActOn`) is checked with the compiler before it is shown, as every
other choice that adds a refusal of a name already was for a built-in socket: a `deny_read` or `deny_write` entry for a
name that is not there yet is refused by the compiler (`path-missing`), so the choice says that, in words, and the folder
that holds the name stays offered, instead of an effect nobody could have. A "never allow" for a held write at a level
wider than its `fs.ask` scope is refused when an `fs.write` entry beneath still allows its own subtree, since the effect it
words ("refuse writes to everything under") would not be true of the next run. The asks beneath a refused folder that go
with it are said in the sentences, one each, and the compiled comparison shows nothing becomes allowed.

A diagnostic that lies in a profile the contract extends names the profile, its file and the line in it. The draft
compiler's generic withheld message for a failed inheritance (its words may quote a value) is followed by one location
line per fault, "profile <name> · <file> · line N" or "the draft · line N", from the loader's structured positions and never
its message.

"Apply now" and "Also apply now" place a live block begun-first, as an Undo's lift and a Redo's placement do: the begun line
is written to the journal before the block is placed, then the outcome. A change whose own journal line failed places
nothing, and begun lines that cannot be written place nothing. A change that cannot be applied live says what the next run
is (in force the next time the agent starts) and gives the line that starts it again.

The 503 page "The contract check could not finish" names which case happened, by the refusal's type: the machine is busy,
the check was still working, the checker could not start, the request was cancelled, earlier checks are stuck on a location
and hold every checker slot, or the location does not answer. Its status code and refusal class are unchanged. No record or
receipt schema changes.

Review fixes (2026-11-21, after an adversarial review). A sentence takes the direction of every family its list can change (an
`exec.allow` entry with words also changes the program arguments' family) and is never narrowing, and never "No change", while
any family of the change cannot be ordered, so it agrees with the overall direction. "No change" says it holds only while the
profile that also grants it stays as it is. A pattern entry's sentence says what the compiled contract gives: the files the
pattern matches when the agent starts, and that a file created later is not covered (the compiler expands a pattern over the files
there; spec/policy/SEMANTICS.md §2). "Act on this" (`ActOn`) gives the picked change the compiled comparison's direction and lists
what it newly allows; a change that cannot be compared is not proposed; its menu of choices alone keeps the action's word. The
wider-level "never allow" over an `fs.ask` scope words its effect as not covering a write entry beneath it in a profile, which
the edit core cannot see. The restart line is the run's recorded command, hidden when it holds a credential-looking value, as every
other printed command line is. The property tests tell a question from a refusal (the engine's ask rule names) and reach removed
`deny_write` rows, removed patterns, removed nested reads and profiles; the mutations that survived the first versions now fail them
or the directed `agentdiff` tests.
