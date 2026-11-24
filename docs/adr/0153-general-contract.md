# ADR 0153: one general contract and explicit exceptions for a named agent

Status: **accepted 2026-11-12; slice 1 implemented, launch and customisation not implemented**.
Decision includes the rulings of 2026-11-12: G1 through G4, R1 through R4 and R5/R6.
Slice 1 selects and displays sources only. All launch checks below are future requirements.
Implementation base: `2910acb2bb846894f70f6b497ba1a40e80786322`.
Builds on ADRs 0059, 0065, 0066, 0068, 0125 and 0144. Refines the planned Contracts view and A3 builder;
does not supersede the machine baseline, existing registry resolution or standalone contract semantics.

## Context

The owner wants one general contract in the dashboard, applied by default, with differences for one agent.
ADR 0144 provides a catalog and a machine baseline of refusals. The baseline cannot express shared grants or
provide a contract for an agent that has none. On this HEAD only its config and catalog slices exist; its
enforcement acceptance remains future work. This ADR must not claim otherwise.

Profiles provide reusable rules but are optional. A file can delete `extends`; grants concatenate and several
settings are contract-wins (`pkg/spec/agent/merge.go`, ADRs 0065/0066). A profile added by generators cannot
be the general contract's selection boundary. A physical file containing every agent would couple all edits
and require new registry/source semantics. The dashboard can give one place without one physical file.

Today `tego run <name|path>` requires a contract. Name resolution refuses ambiguous and unsafe candidates
(`internal/cli/contractref.go`, `internal/registry/registry.go`). The compiler gives the CLI command an implicit
image grant, including loaders/interpreters (`compile.go:116`, `compile_exec.go:127`). That grant is recorded
separately from contract_hash. A managed path must check it against general permissions rather than inherit
its unrestricted authority to add a program. This check must compare final compiled authority, including
`ExecCommands.Unconstrained` from `implicitGrants`, after the command is bound.

Existing contracts must continue working. Applying arbitrary new defaults to them while preserving their
permissions is impossible in general. Preserve standalone launches explicitly, show that general is not
applied to them, and migrate by choice. An agent outside a Tego run is not held by any new default.

## Decision

**D1. Three layers, one explanation.** The machine baseline is the locked refusal floor. The general contract
defines shared permissions and refusals for general/managed launches. A named agent's customisation holds
tightening differences and, where publication authority is proven, separate named exceptions. The baseline is the only layer nobody may loosen. Baseline authority and per-rule tier/plane coverage remain ADR 0144's.
Neither a general contract, a customisation nor a live control can remove a baseline refusal.

**D2. One selected general contract.** Decide scope first from the fixed `/etc/tego/general.yaml` lookup.
Present and trusted means system scope: root-owned, not writable by others, with equally trusted parents,
in the initial user namespace. Only a no-such-file result beneath trusted parents means user scope and
permits passwd-home `~/.tego/general.yaml`. An unreadable file, wrong owner, link, invalid source or other
lookup error refuses the general launch. No environment variable, flag or user file moves scope. The
selected file is a complete ordinary v0 contract, including a default command, with the existing profile/preset syntax. Its user scope is labelled Your agents
on this machine; a system general can supply the same defaults across accounts.

No project file, `$HOME`, `$TEGO_CONFIG`, profile name or delta field can replace this selection. On general routes, baseline layers union only from the policy sources permitted by the selected scope.
Standalone config layers retain their existing union. General authority is selection, not last-wins merge of complete
contracts. System sources require root-owned safe placement and user readability; user sources require
trusted owner/mode/directory checks, bounded regular-file reads and the one-name rule. Record absence,
unselected and unknown states separately. Root ownership of the top file alone does not establish its
authority: the weakest selector, config, dependency, consulted file or relied-on absence determines it.
Use the single authority check specified below for every general launch, including managed activation.

Slice 1 inspection has one request budget: 8 MiB of admitted source bytes including all profile reads,
128 profile resolution attempts, 16 MiB of conservative expanded-node/merge work and final canonical
output, and 64 diagnostics within 64 KiB. Each bounded file read may consume one extra overflow byte
to detect exhaustion. Alias resolution reads count even when merge deduplicates them. Cancellation is
checked through recursion and between regular-file read chunks; an in-progress filesystem syscall is
not interruptible by this context. Graph inspection requires regular profile files; FIFO/socket sources
are refused instead of letting a stream hold a Contracts request open. This is separate from ordinary
standalone profile loading, whose prior stream behavior is retained. Exhaustion/cancellation is UNKNOWN, without a partial name/hash or
profile list. Ordinary standalone LoadBytes keeps its previous limits and semantics. The selected
top source is trusted for observation; the existing config/profile chain is not a system launch authority
manifest. Private relative/absolute source links use the opened descriptor's resolved containing directory,
with identity binding and placement rechecks; link mode 0777 is not directory authority.

**D3. Explicit new launch paths, after release acceptance.** Add `tego run --general [-- <argv>...]` for an agent without an own contract;
without argv use the general's default command. Add `tego run --managed <name>` for a trusted named binding
and optional differences. Old name/path launches retain their current source resolution, flags and behavior.
No resolution error becomes an automatic fallback. New dashboard setup chooses managed/general when
available. Missing general on that path is an error before a child, not a permissive generated contract.
Until slices 2 through 10, including 6a/6b and every enforcement dependency, are closed and guest-proven,
production builds contain no general launch selector: no flag, config key, environment switch or hidden
subcommand. Slice 2 launch registration and callers exist only behind the repository's `tegotesthooks`
build tag, as `internal/cli/machine_testhook.go` does. A runtime switch is insufficient. Keep the
selector-specific production CLI and config-schema guards, then check the build-selected production package graph structurally and dispatch every registered
command, hidden commands included. Environment reads belong to the mechanically checked input inventory.
These checks and their limits are described below. Slice 11 alone removes the boundary after the complete evidence is accepted; hiding UI or documentation never satisfies it.

**D4. Named identity is explicit.** In system scope keep the binding/customisation/exception envelope
only at fixed `/etc/tego/managed/<uid>/<name>.yaml`, owned and published by root with trusted root-owned
placement. In user scope use passwd-home `~/.tego/managed/<name>.yaml`, with checked user/root ownership
and private trusted placement. Both contain version 1, parsed name, checked uid, absolute folder with
resolved directory identity, exact launch argv, resolved program identity and optional `changes`.
Require the one-name rule and protected directory reads. No project binding can shadow either store;
system scope never consults a user envelope, including for tightening. Root multi-owner launches
require explicit supported owner/home context, or refuse.

Reuse A4-2's command-and-folder identity comparison for views once implemented. No such package exists
on this HEAD. Scan findings cannot authorize selection. A missing/unreadable command or folder, uncertain
wrapper/script, ambiguous candidate or stale process yields Cannot tell. The explicit trusted binding
selects launch authority; inferred identity only joins observations to it. Verify resolved launch inputs
again before release. A display name or PID is not an agent's durable identity.

Program identity carries authority only when deciding whether an exception applies. Without an
exception, G or its stricter customisation bounds the program whatever its identity. Record the resolved
program path and digest as facts for every launch. A missing or unresolvable program still follows the
ordinary supported launch/refusal rules; it never gains an exception by its name.

An exception is published for exactly one of these launch forms. The launcher must be in the
initial mount and user namespace. This is a closed table:

| Form | What publication pins | How the launcher resolves and starts it |
|---|---|---|
| A. Absolute path to a native executable | Absolute path and content SHA-256. | Open without following a final link, hash that descriptor and execute that same descriptor. |
| B. Bare name of a native executable | Absolute path resolved at publication, content SHA-256 and the ordered search list recorded in the exception. | Resolve using that recorded list, never caller PATH; then start as A. |
| C. Explicit interpreter and script, such as `python3 x.py` or `node main.js` | Interpreter as A or B; script absolute path and SHA-256; exact argv prefix through the script. | Start the interpreter as A/B; open and hash the script, then hand it to the interpreter by descriptor path. Relative script operands resolve from the checked bound folder at publication. |
| D. Script with an absolute `#!` interpreter line | Script absolute path and SHA-256, including its interpreter line; interpreter path and SHA-256. | Start as C, with the launcher performing the interpreter start itself. |

The following forms cannot hold an exception in this version. Publication refuses naming the row;
nothing is stored. Where otherwise supported, the program may still run under G or a stricter customisation.

| Form | Reason publication refuses |
|---|---|
| E. `#!/usr/bin/env name` script | A search at start chooses an interpreter that the pin does not cover. |
| F. A wrapper or launcher that fetches or selects code at start: `npx`, `uvx`, `pipx run`, `go run`, `docker run`, `bash -c "..."`, or `sh script` reading a remote | The code that runs is undecided at publication. |
| G. A relative executable path | Resolve it and publish form A instead; publication offers that conversion. |
| H. A container entry point, or any launch whose launcher is outside the initial mount or user namespace | The pinned paths and owners do not name the machine's paths and owners. |

An exception launch has a closed environment. The child receives exactly three sources: literal published `env.set`
values; passed caller variables from this fixed list: `TERM`, `LANG`, `LC_*`, `TZ`, `HOME`, `USER`,
`LOGNAME`, `COLUMNS`, `LINES`, `NO_COLOR`; and the eligible engine-set names listed under R5 below.
`LC_*` means names beginning with `LC_`. PATH is set from the exception's recorded ordered search list.
Any other caller variable requested by `env.pass` refuses publication, naming that variable. An implicit pass-all environment also fails this rule. This allow
list closes caller code-loading inputs, including `NODE_OPTIONS`, `LD_PRELOAD`, `PYTHONPATH`,
`PYTHONSTARTUP` and `BASH_ENV`; enumerating forbidden names would leave other loaders open. Literal
published values carry the publisher's authority and are included in the source bytes and digest.
The complete final environment must meet this closure after identity, endpoint and harness producers.
Engine ownership alone grants no exemption: R5 fixes the names, engine-only values and forbidden
code-loading uses. Slice 4b must replace legacy caller-derived values on this route.

For C and D the pin covers the interpreter and entry script. It does not cover modules, packages or
configuration loaded later. The ADR, GAPS and publication display must say:
`This exception follows the program at <path>. Anything that can change the files this program loads can use the exception.`
This version does not check whether another agent's contract can write those files.

The four outcomes are distinct:

1. No binding matches command and folder: run under G or its customisation, without an exception.
2. A binding matches and resolved identity equals its pin: apply the exception, print it and record it.
3. A binding matches but identity differs, cannot resolve or is no longer pinnable: refuse the whole
   launch, exit 125. Show what was approved and what was found:
   `this agent's exception was approved for a different program: <what changed>; publish it again or remove it`.
   Legitimate program updates require republication. Never silently retry with or without the exception.
4. An unpinnable form at publication: refuse with its table row and store nothing.

A missing explicitly selected managed binding still refuses `--managed name`; it does not become an
unbound launch. Keep checked descriptors and pins through child release; inability to hold them refuses
that launch cell. Reuse compiled program paths (`ExecRule.Path`/`Resolved`), runtime resolution primitives,
descriptor hashing/re-stat checks in `internal/runtime/supervisor/node_build.go`, and `internal/execpin`'s
script-stage/argv facts at a permitted dependency layer. Today's kernel exec pin stores dev/inode/stages
and argv MACs, not publication SHA-256 approval. Slice 4a must implement the closed forms and resolver;
the current `internal/runtime/run_env.go:resolveCommand` precedence is not this decision.

**D5. Tightening and explicit exceptions.** The general is a default, not a ceiling for its author.
A customisation may tighten through the closed operations below. It may widen only through a separate
`exceptions` list whose entries each have a unique stable name, kind and literal scope. No silent merge,
arbitrary replacement v0 fragment, profile override, opt-out flag or omitted inheritance line grants access.
Unknown fields, duplicate names/keys, nulls and unsupported operations refuse. There is no root force flag.

Every exception source also binds the checked uid, managed name, exact argv, resolved folder and program
identity specified in D4, including the interpreter/script path and content digests required by its
supported form.
The root store is namespaced by uid. A matching file name never authorizes attaching an exception to
another binding. Command and folder first determine whether an exception binding matches. If none
matches, an otherwise valid unbound general launch runs without an exception, as D4 outcome 1 requires.
A missing or invalid explicitly selected managed binding still refuses that named launch. When a
command/folder binding matches but its program, interpreter or script differs from the approved pin,
refuse the entire launch under outcome 3; republication is required before that exception can apply.
Ambiguous sources refuse; never transfer an exception by label.
All consulted customisation sources retain separate trust facts and raw digests, even when their
resolved named operations share one canonical customisation hash. System scope consults only fixed
root-published policy; it does not read user contributions. In user scope a contribution without
exception-publication authority may only reduce the inherited candidate, including its authorized
exceptions. File ownership alone never promotes it to system authority.

An exception requires ALL five conditions:

1. Its file has the selected general's publication authority. A system general requires a root-owned
   exception under `/etc/tego/managed/<uid>/<name>.yaml`, with safe root-owned placement and system trust checks.
   A user-owned file under `~/.tego/managed` cannot publish an exception to a system general, even if its
   uid field says root or root launches it. For a user general, use that passwd owner's private managed
   directory, trusted owner/root descriptor, safe complete walk, mode and one-name checks. Root-owned
   general files placed in a user's writable directory do not establish a system publication boundary.
   A managed location alone is insufficient: its writer set must be no broader than the selected general's.
   Never infer permission from a label, submitted path, browser uid, matching file owner alone, or scan.
2. Baseline refusals and existing ADR 0144 conflict rules always win. Any overlap that the compiler cannot
   prove safe refuses with baseline and exception sources. Do not trim the grant silently. Ceilings still apply.
3. Compile prints every named exception and its resolved effect. Contracts says **Additionally allowed for
   this agent: ...**. The builder shows that list before saving, including removals of general refusals.
4. The run records general_hash, customisation_hash and a required boolean `exceptions` fact, plus the full
   named exception list and source authority. Receipts disclose **Exceptions: yes/no** and their scopes.
5. Removing the customisation document restores current general rules. Removing the managed binding file
   refuses `--managed name`. Binding and optional customisation are distinct concepts even if stored in one
   envelope: deleting `changes` and `exceptions` restores G; deleting the envelope removes the binding.

In user scope, a consulted customisation outside exception-publication authority may only tighten.
An explicit exception in such a consulted source refuses even when redundant or empty; it is never
reclassified. System scope ignores user policy selectors with the required line and does not parse
their files as contributions. Resolve today's general first: a switch from user to system authority
invalidates user exceptions before launch. Revalidate exceptions against today's G and
baseline at preview, save and launch. No old preview, receipt or hash alone authorizes an exception.
For a fresh launch, deleting the general's selected file either selects a safely verified fallback, with
its own authority, or leaves no general and refuses. A change between the two authority checks always
refuses that pending launch instead of reselecting. Deleting the managed file never becomes a standalone launch.

| Tightening operation | Semantics |
|---|---|
| Add read/write/exec/env denial | Accumulate strict supported denials. Never remove baseline membership. |
| Keep fs.write/net.allow/exec.allow/env.pass entries | Exact decoded subset, original order/multiplicity and section modes; empty keeps none; stale references refuse. |
| memory/pids/wall cap | Positive typed value no higher than a finite general cap. An absent general cap supplies no additional bound; retain machine ceilings. |
| Omission or empty customisation | Inherit general; unreadable or malformed is a failure, never inheritance. |

The exception language is also closed. Its first implementation supports named literal fs.write, net.allow,
exec.allow and env.pass additions, named removal of exact general deny entries within SUPPORTED families,
and named higher finite memory/pids/wall caps, with explicit source membership. The exhaustive family
matrix below limits these operations; it does not authorize an exception for a FROZEN family or turn
an inherited ask into an allow. Decode cap units to positive integers and check
machine ceilings through the existing compiler; print the requested and effective cap. Other general
switches or unbounded cap removal require a separately reviewed operation, not a generic YAML patch.
An exception names each inherited denial it relaxes. Removing a general membership never removes a duplicate
baseline membership. A conflicting customisation denial refuses; the writer must repair it explicitly.
Keep plus exception on the same key refuses until an unambiguous operation is supported. No order-based win.

Ordinary profile merge and text diff are not the security boundary. Apply typed changes to immutable G.
For tightening-only successful candidates, compiled authority must be a subset of G in the same trusted
run context, retaining G's original command authority as D6 specifies. Candidates with exceptions must
stay within G plus exactly those named scopes, intersected with baseline refusals and machine ceilings. Implicit MCP/model/helper/credential/env
producers, asks and runtime grants cannot introduce an unnamed widening or restore an attempted reduction.
Unknown comparison or unsupported topology refuses, with both sources and the producer. Record resolved
helpers and dependency effects under the exception that authorizes them; do not hide them in a CLI grant.

Preserve restricted exec empty lists, nonnil env pass lists and net section presence through save/reload.
Do not switch off built-in read refusals through an empty list. Extend origin membership checks so duplicate
top-file denials cannot reopen mandatory general/customisation refusals without an authorized named exception.
An exception never overrides source protection. Validate G's strict denial coverage even with no changes;
ordinary v0 Load success alone does not establish a supported managed guarantee.

**D6. One composition and one baseline materialisation.** A Layer 2 source reader snapshots trusted bytes
and selection facts through `contractsrc.CheckGeneralAuthority`, defined below. A pure agent composition
entry applies typed operations to an immutable fully loaded G and binds the concrete name/command into C.
An invocation precheck may give an early diagnostic, but cannot approve composition. Compile G in its
original command context and C in its selected command context against the same captured policy and
fixed owner, folder, environment, machine and baseline inputs. Each comparison uses the same target
observations and compilation tier/plane for G and C. Initial compilation produces the runtime floor;
actual preparation facts are checked later under the lifecycle below. Binding C must not add
implicit authority to the G reference. After all producers, compare final authority family by family:
`authority(C) <= authority(G) + exactly the named exceptions`, with baseline refusals and machine ceilings
retained. A comparison failure refuses compilation with the family, grant, producer and source. Unknown
comparison refuses too. Default/selected commands, loaders and interpreters have no implicit exemption.

The first regression is G with `command: [true]` and `exec.allow: ["git status"]`, C selecting `[git, status]`.
The ordinary compiler's `implicitGrants` gives C unconstrained git through its command. Even though the
invocation passes G's matcher, the final command family comparison must refuse that unconstrained grant,
including `git push`. A future exact-launch pin may support it only if final C still has G's git constraint;
the first version may refuse. Never silently weaken an argv rule to make the launch work.

Compile each candidate through `agent.Compile`, ADR 0144's single baseline insertion point; each
compilation inserts the baseline once. Fallback may recompile from the same captured source bytes.
C is the validated complete derived v0 source; E is its compiled effective result. No CLI/view/profile loader
inserts baseline rows. Compare both final prepared G and C tables at every reachable actual mechanism,
including runtime helper, MCP, model, credential, harness, final environment and CLI grants. Later producers
must use the same bounded authority assertion before adding a grant; a producer without an inventory entry
refuses. If existing tier/plane fallback recompiles, use only the same captured source bytes, recompute
the G/C composition verdict in the actual context and refuse an unsupported cell or unmet mechanism
floor. Runtime uses only accepted E after final-env and coverage checks,
then reruns the one source authority check immediately before releasing the child. Replay cannot compose
a materialised output twice. Reuse enforcement tables and the baseline solver; no new kernel engine.
Every decision is deterministic; no language model participates.

### Exhaustive rule-family matrix for the first version

This matrix covers `Contract`, nested sections and compiled/runtime producers. A new language field or
producer has no default order: it is FROZEN until this matrix and its comparator are amended. A schema
inventory test must map every field and derived producer to one row. SUPPORTED means only the closed
operations and comparison below. FROZEN means any explicit customisation or exception touching the row
refuses with `this part of the general contract cannot be customised yet`; unchanged inherited content
must still compile identically in G and C or compilation refuses. Equality here includes resolved identities,
section/list modes, producer effects, coverage and sources that carry mandatory membership.

For each operation and mechanism the authority order is DENY <= ASK <= ALLOW. An ask may become a deny,
never an allow in this version, including through an exception. Approval may release only G's original
compiled ask scope; it cannot create a persistent ordinary grant. C silence always inherits the exact G
value and presence mode, never the v0 default. Malformed/null/unknown C input refuses. G silence means
its real v0 compiled default as listed below; it is not presumed to be either an empty set or unrestricted.
Named exceptions enlarge only their literal family scope and never baseline membership, source protection,
ask authority or enforcement mechanism. No sampled property substitutes for the matrix/comparator proof.

| Rule family and fields/producers | Meaning of within on final compiled authority | Silence in G; silence in C | First version |
|---|---|---|---|
| File read: `fs.deny_read`, built-in and source read refusals | Retain each mandatory denial membership and built-in mode. Additional supported strict literal denials may only reduce effective readable objects at every mechanism; use the shared baseline coverage/alias/topology solver. A named exception may remove only its exact G denial membership, never an ask/baseline/source refusal. Unknown scope or coverage refuses. | G absent/nil keeps built-in read refusals; explicit `[]` is a distinct disabled mode and cannot be manufactured by C. C omission inherits both mode and entries. | SUPPORTED for additive strict literal denials and named exact G-membership removal; all read-mode/assurance changes are FROZEN. |
| File write: `fs.write`, `fs.deny_write`, built-in writes, source guards | Retained compiled literal grants are exact resolved tuples with their masks/modes; no broader path, alias, nested override or implicit producer may appear. Denial additions use the strict coverage solver. Named additions/removals name exact grant or G-denial memberships; union only those scopes. No arbitrary glob/subtree inclusion inference. | G no write entries grants only unchanged implicit compiler/runtime writes; C omission preserves them and mandatory refusals. Empty keep removes all explicit grants without dropping the section. | SUPPORTED for exact keep, literal named additions and strict denial additions/removals; uncertain topology refuses. |
| Exec programs: `exec.allow` image entries, command/MCP/interpreter/loader/helper/runtime images | Every final C image tuple (absolute/resolved identity, ByName, IsDir, verdict, loader and helper closure) must be retained unchanged from G or accounted for by one named image exception. ByName/directory scope cannot replace an exact-file grant. All mandatory exec refusals remain. | G nil/no keys and `allow: []` retain their distinct image modes; deny/ask-only mode remains distinct and may allow unrestricted images. C omission inherits the exact mode. | SUPPORTED for exact keep/literal named image additions and supported additive denials. Mode changes and arbitrary directory inclusion are FROZEN. |
| Exec command rules: parsed `exec.allow/deny/ask`, `ExecCommands.Unconstrained`, interpreter/loader argv and candidate closures | Retain G's exact parsed constrained patterns and identities, or remove allow entries/add supported denials. Named removal of a G-denial membership relaxes only that exact parsed pattern scope. Every new allow needs an exact named pattern and unchanged resolver closure. No C unconstrained tool unless G already has that same unconstrained authority or an explicit named unconstrained-program exception authorizes it. Pattern containment beyond exact canonical equality is unsupported and refuses. Asks remain asks or become deny. | G no command pattern means the real compiled image-only/default argv behavior, including implicit unconstrained commands. C omission preserves it; empty keeps never change list mode. | SUPPORTED for exact keep, additive deny, named exact G-denial removal and literal named patterns; generic pattern inclusion/rewriting is FROZEN. |
| Network hosts and ports: `net.allow`, derived destinations | Retain exact normalized endpoint tuples (protocol, host/address, port, UNIX identity and resolved address restrictions); remove entries or add exactly named literal endpoints. G/C use the same DNS snapshot and rejected-address classes. No host wildcard, port range, transport or producer widens a tuple. | G absent net section has its actual unrestricted/default behavior; present empty is distinct. C omission preserves that mode; an empty keep cannot remove the section. | SUPPORTED for exact allow keep/literal named additions. Unknown DNS/alias comparison refuses. |
| Network extensions: `net.http/listen/ingress/limits/dns/proxy` | Require equal normalized request, listener, ingress, proxy, DNS and network-budget tables, mechanisms and derived grants. No partial ordering is claimed. | G omission uses each compiler default; C omission inherits the resolved value and section mode. | FROZEN. |
| MCP servers and tools: `mcp`, `tools.allow/deny/ask`, relay | Require equal server identities, transport, tool policy, asks and all implicit image/network grants. No tool-name subset is claimed to bound server/relay authority. | G no MCP gives no declared server; per-server omitted tool policy keeps its real default. C omission inherits exactly. | FROZEN. |
| Secrets: `credentials`, vault and credential injection | Require equal credential identities, destination scopes, stand-in/base-URL variables, injection and vault capability. Never compare or print secret contents as policy grants. | G omission has no declared injection; C omission inherits all approved capability and derived effects. | FROZEN. |
| Environment: `env.pass/deny/set/mask`, final reserved/runtime variables | An exception launch must first satisfy D4's closed environment; an env.pass exception cannot bypass it. Final passed-name authority may be an exact retained subset plus exact named env.pass exceptions; denied-name memberships accumulate or are explicitly named for removal. Existing `env.set` values and runtime-reserved variables remain equal; a producer cannot restore a removed name/value. | G nil pass inherits caller environment subject to deny/reserved rules; written empty passes none. C omission preserves mode; written empty keep remains nonnil. | SUPPORTED for exact pass keep, additive deny and literal named pass/G-deny operations; set/mask changes are FROZEN. |
| Caps and budgets: `limits` and effective machine clamps | For memory/pids/wall, compare positive normalized bytes/count/nanoseconds and bounded bits after clamps: C finite <= G finite, or finite <= G unbounded; a named finite exception supplies only its approved new bound, always clamped. All other dimensions must be equal; no order for CPU weight, stall/repeat control, cost/tokens or pressure thresholds is assumed. | G nil inherits machine ceiling; absent final bound is unbounded, not zero. C omission inherits exact value/bounded bit. | SUPPORTED only for memory/pids/wall reductions/named higher finite bounds. CPU/cpu_weight/memory_high/tokens/cost_usd/stall_after/repeats and network budgets are FROZEN. |
| Ask rules: `fs.ask/ask_read`, `net.ask`, `exec.ask`, top-level `ask`, completion/timeout/pending limits | Explicit ask fields/config remain equal. A supported added denial may turn an effective ASK into DENY; no keep, exception, helper or approval may turn ASK into ordinary ALLOW. Preserve the original mechanism and completion scope, including asks currently refused everywhere. | G absent means no declared ask except unchanged gate/producer effects; omitted ask config has compiler defaults. C omission inherits scopes/config/completion. | FROZEN for direct ask edits and exceptions; the verdict reduction caused by a supported denial is checked. |
| Required tier and mechanisms: `tier`, assurances, `fs.reads`, AppArmor assumption, `capture`, `io_uring`, `keyring`, `ipc`, `setuid`, `exec.anonymous` | Require equal requested/effective mechanism facts and at least G's coverage in every reachable actual tier/plane. A number ordering of tiers is insufficient. Fallback recompares both final tables or refuses. Baseline mechanism requirements remain mandatory. | G silence resolves compiler/machine defaults and probes; C omission inherits requests and required resolved coverage. | FROZEN; unsupported or weaker mechanism refuses even with empty C. |
| Gates: `gate` predicates, thresholds, completion and generated asks | Require equal compiled gate program, facts, thresholds and completion, plus equal ask authority. No score/threshold ordering is asserted. Added strict denial may dominate a gate result; the gate cannot reopen it. | G absent/empty compiles no gate; C omission inherits the same program. | FROZEN. |
| Business rules | No business-rule language/package is present on this HEAD (`spec/policy/bizrule` is absent). Any proposed field or producer has no defined authority order. | G unsupported field already refuses; C omission introduces nothing. | FROZEN; unknown fields refuse, never silently ignored. |
| Models and routes: `models`, endpoint/router/forwarder producers | Require equal endpoint/route identity, request authority and all derived network, helper and env facts. A supported reduction that a producer restores refuses. | G absent gives no declared model route; C omission inherits exact default/effects. | FROZEN. |
| Runtime controls/lifecycle: `live`, `host_sockets`, `harness`, `reason`, `keep_descendants`, runtime grants | General launches require Locked. Preserve all remaining compiled controls, socket/descriptor scope, harness/reason and producer closure exactly; transient blocks can narrow only. Stop/Pause/Deny remain available. | G omitted live is Locked; other omissions use compiler defaults. C omission inherits them; an incompatible G refuses launch. | FROZEN. |
| Recording, source and non-authority metadata: `record`, `version/name/revision/learn/extends`, folder/command binding | Keep record mode and complete sealed source membership. Only the explicit trusted name/command/folder binding may differ, and its final effects must pass every other row; presentation metadata adds no permission. C cannot select another profile or record mode. | G required/default fields follow v0 validation; C omission inherits the resolved source and record mode. | FROZEN except the explicit checked invocation binding. |
| Observational file watches: `fs.watch` | Require equal resolved watch scope and any monitoring/read effects; no authority order is claimed. | G omission adds no declared watch; C omission inherits exact scope/effects. | FROZEN. |
| Reserved/schema-only fields: `exec.privileged`, `env.mask`, `prompt/skills/visibility/docker/containers` and future fields | Preserve current schema refusal; no customisation bypass or authority order is defined. | G retains existing supported-empty/default checks; C omission inherits them. | FROZEN. |

Introduce a typed derived-source context so compiling a general stored inside `.tego` does not lift the
own-state read denial through the ordinary top-contract directory exception (`compile_fs.go:172`). Retain
real source positions, cwd and protected walks. A fabricated project source path is not a solution.

**D7. Hashes preserve their meanings.** At a new coordinated record minor:

* `general_hash` hashes G's existing canonical profile-merged v0 bytes before binding/differences/baseline.
* `customisation_hash` hashes canonical v1 differences JSON. Fixed field order is v, deny, keep, limits, exceptions;
  subfield order is the operation table order; absent differs from written empty; list order is retained;
  limits decode to bytes/count/nanoseconds. Exception entries retain written order with fixed name/kind/scope fields; include exact denial membership references where applicable. Use UTF-8, no indent, HTML escaping off and one final LF.
* Exact source-byte SHA-256 values identify the selected general, managed envelope and profile inputs.
  Binding metadata records checked uid, literal argv, declared/resolved command/folder, absolute program,
  interpreter/script SHA-256 identities, trusted resolution inputs, identity version and raw digest.
* `contract_hash` remains SHA-256 of C.Canonical(). Standalone contract hashes are unchanged.
* `effective_hash`, effective.yaml and the baseline digest/sources/coverage remain exactly ADR 0144's.
* Seal the immutable source-manifest digest, general/customisation hashes, each exception with its yes/no
  outcome and the tier reached.
* Actual tier, plane, ceilings, runtime/CLI grants, capabilities, read coverage and residuals remain
  separately recorded. Contract hashes do not hash kernel state or prove equivalent enforcement.

Store canonical general.yaml, customisation.json (including the empty document for every general/managed run), binding.json when bound, contract.yaml and
effective.yaml in the run record. Add `contract_layers` with v=1, mode general/customised/standalone/not-applied,
selected inputs, hashes, the named `exception_list` array and required `exceptions: true|false`. The customisation document uses `exceptions` for its operation list; the record boolean lives in contract_layers and is a different field. True means a nonempty authorized exception list, including a currently redundant grant; it is not inferred from G/C hash inequality. Empty customisation has a defined canonical digest. Managed source facts live there; do not present a derived copy as an editable
contract_source file. For every general/managed run, require general_hash, customisation_hash and the exceptions boolean.
Mode general has no operation keys: its customisation snapshot is exactly `{"v":1}` followed by LF, with that digest, exceptions false and the G snapshot; a binding is present when named.
Mode customised records any declared operation keys, including a written empty list, with their canonical
snapshot and the binding. Empty lists retain their hash distinction; they do not make exceptions true. True exactly matches a nonempty authorized named exception list.
Standalone and not-applied do not claim general inputs. At the new minor validate required mode/hash/snapshot combinations. Earlier missing
metadata is unknown. No new minor number is promised until integration checks reservations.

Historical views and receipt verification use verified recorded snapshots and sealed inputs, never current
general/config. Old receipt/CI binding versions keep their contract_hash semantics. A future binding version
explicitly adds effective_hash and layer facts. Count recorded refusals only and disclose unrecorded reads.
Per-rule source membership does not establish unique cause. Namespace/authority limits stay visible.

**D8. Edits affect the next launch.** Only root edits system general and system managed envelopes,
including tightening changes, bindings and exceptions. User/root edits user-scope general and managed
envelopes outside governed runs. A non-root dashboard never becomes a system writer. Use the
same shared preview/save service for CLI and web, guarded reads, scoped impact checks, raw-input CAS,
locks, safe temporary files, fsync/rename/directory fsync and actor/change journaling. Reload a complete
TrustAbort machine/source snapshot for each current-policy operation, not the dashboard's cached startup
Machine. Recheck every input, including selection-sensitive absence and profiles. Refuse incomplete or
stale previews. Each save changes one file: a general edit requiring simultaneous delta repair refuses
until individually valid repairs land first. No new cross-file transaction system. External root edits
remain a recovery path.

R10, alternate and ask guards cover all consulted source walks, including missing selection targets,
replacement parents and link names. Preserve `.tego` read/content protections. Governed mutations and
uncertain membership refuse; web uses authenticated peer checks plus CSRF/Origin, not submitted uid/path.
An owner outside Tego can edit owner files; root and namespace manipulation remain disclosed limits.
Landlock/fanotify do not acquire metadata guarantees from this ADR. Making an input unreadable causes
UNKNOWN/refusal for new decisions, not silent inheritance loss. Stop/read recovery remains available.

Running agents keep immutable G/delta/baseline snapshots. Show current-vs-recorded drift and require a new
run to use disk changes. Managed runs are Locked in this release; reject an Adjustable general, observe
mode and differing record overrides on these selectors. Existing scoped asks and narrowing stop/pause/deny/
blocks remain. Other mutation paths must prove they remain within C plus baseline or refuse. Standalone
live/flag semantics do not change. Removing an extra tightening delta is an explicit next-run edit that can
return to general. Removing all customisation including exceptions restores general; removing a tightening restriction while retaining an exception requires the full exception preview again.

**D9. Contracts is the home.** General contract first, locked baseline alongside/below, then one row per
identified agent: Same as general, tightening differences, or **Additionally allowed for this agent: ...**, and Customise for this agent. Never label an exception-bearing agent Same as general, even if its current exception is redundant. Keep own-contract and
unassociated files visible, clearly labelled general not applied. Unknown identity or source is unknown.
Use the shared catalog rather than run history alone. Simple/Full, source sentences, preview, line errors,
terminal twins, protected writer and approved desktop/phone components remain common with A3/B2-8.
At phone widths rows stack into labelled facts with no hidden decisive value. Scripts-off, CSP, keyboard,
320/390/1280 widths, both themes and zoom/accessibility checks close the UI slice.

**D10. Scope and migration.** Saving a general contract does not govern programs the scan found outside
Tego, attach rules, rewrite agent settings, restart services or replace a startup environment. Offer an
explicit next-launch line. Do not offer full general adoption in this revision. Existing adoption retains
ADR 0144's supported scope and refusal of unsupported contributions.

Existing contracts, registry names, commands, profile order, canonical bytes and contract_hash stay unchanged
on the standalone route, apart from the independently accepted baseline's documented effect. No auto file
rewrite or extends insertion. New metadata labels compatibility mode. Migration preserves the old source,
previews old and proposed effective tables in one context, and writes a separate binding only on choice.
If preserving access needs a grant not in G, show it and require an explicit named exception from an authorized publisher, or keep standalone. Migration never invents or silently approves an exception. The UI never says the compatibility population is covered by G. A later mandatory migration is
a separate behavior decision.

## Consequences

The user gets shared defaults and small per-agent differences without replacing the refusal floor or
registry. Deleting an inherited general refusal requires an authorized named exception; deleting all customisation returns to G; deleting a managed
file refuses its named launch. No optional inheritance line is the boundary. A person can still deliberately
choose standalone compatibility or start an agent outside Tego; this ADR does not claim host-wide control.

New sources, provenance, derived-source handling and both closed operation languages need security review
and guest proof. A record alone does not make a grant safe. Same-owner unheld processes can publish user
exceptions; file ownership is the authority until roles exist. Root and namespace limits remain as in ADR 0144.
A system G with a user-writable profile or a user-selected search root has weaker authority than its top
file. Slice 1 displays dependency digests but authorizes no launch. The following operational gate is
required before the test-only slice 2 launch path can run and is retained after production release.

### One authority check, fixed scope and a closed system source universe

Implement `contractsrc.CheckGeneralAuthority(ctx, request, previous)` for every general/managed caller,
before compilation and immediately before child release. A display snapshot from `ReadGeneral` is
observational and cannot authorize a launch. Reads remain bounded and context-aware; exhaustion or
cancellation is UNKNOWN and refuses. Scope comes first from D2's one fixed system-general lookup.

System scope reads policy only from fixed root-owned safe locations: `/etc/tego/general.yaml`,
`/etc/tego/config.yaml`, `/etc/tego/profiles`, installed built-in presets under reserved `tego/`, and
system binding/exception stores under `/etc/tego/managed/<uid>`, and the R6 price source
`/etc/tego/prices.yaml` or the binary's built-in table when a cost limit is in force. A safely verified
absent system config uses compiled defaults, including `/etc/tego/profiles` for this scope. A checked system config may
select a safe root-owned subdirectory of `/etc/tego/profiles`; relative, home-expanded and outside roots
are invalid system policy. Complete trusted placement is required for every policy source, consulted
search position and absence. A root-owned target beneath a user-selected or replaceable directory
cannot establish this boundary. Built-in preset bytes and their revision are captured as policy.

The user config layer, `TEGO_CONFIG`, `HOME`, XDG variables, `~/.tego/profiles` and policy-file flags do
not supply system policy. If such an input is set to something that would change policy in user scope,
print one line saying it is ignored; its presence is not a launch error. Do not read that alternate
policy to determine authority. These values may still be observations or execution inputs where the
inventory says so. In particular, caller PATH can resolve a command without an exception; it cannot
resolve system profiles or exceptions.

User scope uses today's user config layer and source resolution, with user authority. General selection
still uses the passwd home, never HOME or XDG. Its compiled profile default is the user's
`~/.tego/profiles`; record source digests so changes are visible afterwards. An ungoverned process of
the same user can write these user sources. At tier landlock a governed process with a whole-home write
grant can also write them. Future source protection has its mechanism limits; this ADR does not remove
them. Label every user-scope exception `user-level` wherever displayed, including publication, compile,
Contracts, run output and receipts. Root-owned individual files do not promote user scope to system.

Obtain the real uid first. Under sudo use the existing validated invoking-user/delegate rule from
`SUDO_UID`/`SUDO_GID`, including its initial-user-namespace condition. Root reads policy only from fixed
system sources; reads of delegate-owned sources use that user's credentials. `AT_SECURE` refuses every
general launch. Neither browser uid nor YAML uid establishes the owner. Unsupported multi-owner context
refuses. A direct root invocation without a valid non-root delegate remains unsupported, as
`internal/runtime/run_child.go:privilegedTarget` already requires. Even if fixed system absence selects
user scope, this does not authorize reading `/root/.tego` as launch policy or bypass the existing
root-launch refusal. Record real/delegate uid/gid, passwd home, namespace identities and secure-exec fact.

A policy source decides authority and must remain trusted and unchanged. An observation describes a
place named by a rule: whether a project folder exists, or which `.env` files are there. It carries no
authority. Re-take observations where the product already does so; an observation change alone is not
a source-manifest refusal. Classify producer inputs by that distinction rather than pinning every
filesystem fact the compiler or preparation happens to inspect. The bound folder's identity remains a
binding constraint; unrelated contents of that folder do not become policy sources.

Without an exception, resolve the command using G's own literal PATH when set, otherwise caller PATH.
Record the resolved path and digest as facts; no publisher search list exists on an unbound launch.
With an exception, use D4's recorded search list and descriptor execution. Caller PATH neither chooses
the exception program nor acts as an additional mismatch detector.

### Three-stage manifest lifecycle

1. **Immutable source manifest, before compilation.** Capture requested selector and scope; real and
   delegate owner/passwd/namespace/secure-exec context; every policy source's declared and resolved path,
   descriptor identity, full trusted placement and raw SHA-256; each verified absence and its proving
   directory identity; consulted binding/exception records; resolver inputs and program identity from
   D4. Include baseline policy inputs required by ADR 0144 and cost-limit price sources under R6,
   including the built-in table digest and any relied-on system-price absence. Compilation reads
   policy only from these captured bytes. Hash canonical non-file inputs and absence facts without fabricating file hashes.
2. **Compiled constraints.** Compile the captured bytes into authority(G), authority(C), the verdict that
   C is within G plus exactly named exceptions, and the required runtime floor: tier and mechanisms.
   Record required coverage as mechanisms, not merely an ordering of tier numbers. Baseline refusals
   and machine ceilings remain mandatory.
3. **Preparation facts.** Actual tier, runtime endpoints, cgroup and harness objects arise during
   preparation. They are checked against the compiled constraints, never compared for equality with
   the source manifest. They may not lower the floor or add authority. If the product's existing
   fallback recompiles for a lower tier, it uses the same captured bytes without another policy read,
   and recomputes the composition verdict there. An unmet floor or failed comparison refuses.

File identity comparisons use device, inode, file type, uid, gid, permission bits, link count, size,
mtime and ctime at nanosecond resolution, plus the descriptor-read content SHA-256. Atime is excluded.
Placement comparisons retain the declared/resolved path and the ordered walk: component name, device,
inode, file type, uid, gid, permission bits, and any permitted link's literal target and resolved target
identity. Directory identity is device/inode/type/uid/gid/permission bits; unrelated directory entry
timestamps are excluded. A verified absence retains that trusted nearest existing directory walk and
identity plus every missing suffix component; only a no-such-file lookup proves it. The fixed system
general selector cannot be a link. Program descriptors are compared to the published identity where
an exception applies and to the captured program identity for the pending launch.

Immediately before releasing the child, re-verify every policy source identity/digest/placement, every
absence and the program on the descriptor that will be executed against the immutable manifest.
Any difference or uncertainty refuses the whole launch, exit 125, naming the source and repair; the
person starts a fresh launch. There is no in-launch retry, policy reread for recompilation or silent
reselection. Keep the descriptors/pins and blocked-child handoff needed to hold those facts through
release; an unsupported handoff refuses that cell. Root and namespace manipulation remain disclosed
host authority limits. Seal the manifest digest, both policy hashes, every exception's yes/no outcome
and actual reached tier in the record, as D7 requires.

### Worked examples from the design review

* **Pinned node entry script and NODE_OPTIONS.** Publish form C for `node /opt/agent/main.js`, pinning the
  interpreter, entry script and exact argv prefix. With caller
  `NODE_OPTIONS=--require=/work/inject.cjs`, that variable is absent from the closed child environment.
  Equal pins satisfy the program-identity check; the caller cannot add this startup load. Exception
  acceptance also requires the complete final environment to meet the R1/R5 closure. A contract that asks for
  `env.pass: [NODE_OPTIONS]` refuses publication, naming the variable. Literal published `env.set`
  values carry the publisher's authority. The entry script's later modules/configuration remain the
  stated interpreted-program limit, even though this caller injection is closed. R5 permits
  engine-generated TEGO_RUN_ID and its listed siblings, with forged caller values discarded. That design removes the identity conflict; implementation and positive launch proof
  remain slice 4b work.
* **Unbound bare command with no system config.** A trusted `/etc/tego/general.yaml` has
  `command: [true]` and no literal PATH; `/etc/tego/config.yaml` is safely verified absent. Scope is
  system, its profile default is `/etc/tego/profiles`, and built-ins remain reserved under `tego/`.
  There is no exception binding. Resolve `true` from the captured caller PATH, record its actual path
  and digest, and run under G if compilation and ordinary launch checks succeed. It receives no
  exception. There is no invented publisher search list or user-profile default. A changed program
  descriptor or source before release refuses this pending launch.
* **Backend reaches a lower tier after compile.** Capture source bytes once and compile constraints.
  Preparation then reaches a lower tier and allocates endpoints/harness objects. Those new objects
  are preparation facts, not changed source fields. The existing fallback may recompile G and C for
  that actual tier from the same captured bytes and recompute composition. If both the required floor
  and composition hold, verify the original source manifest and release. If either fails, or any
  source/absence/program changed, refuse exit 125. Start again explicitly after repair; no retry loop.

### What slice 2 must change

The inventory below describes current code, not accepted general-launch behavior. These contradictions
remain deliberate work for later slices; this round changes no launch, editor or record code:

* `pkg/spec/config/builtin.go` defines one `DefaultProfiles = "~/.tego/profiles"` for all contexts.
  Make that default scope-dependent for the new route: `/etc/tego/profiles` in system scope, today's
  user default in user scope. Preserve standalone behavior.
* `ReadGeneral` consumes an already layered Machine and `profilesrc.Chain(m)`; `config.Resolve` and
  `LoadSources` consult the existing user and TEGO_CONFIG layers. General launches must decide scope
  before this policy discovery, ignore alternate user policy in system scope with the required line,
  and keep delegate reads under delegate credentials. Slice 1 remains observation only.
* `internal/runtime/run_env.go:resolveCommand` prefers compiled Exec entries before effective PATH;
  general launches without an exception must use G's literal PATH or caller PATH as decided above.
  Exception resolution uses only D4's recorded list. Keep standalone resolution unchanged.
* `config.DefaultPrices` is `"~/.tego/prices.yaml"`; `cli.runPrices` loads it after compile. A price
  rewrite can turn cost budgets off (`internal/pricetable/pricetable.go:FromMachine`). This is policy,
  not an ordinary preparation observation. System G cannot consume this user default. Capture
  authorized price bytes before compile under R6: fixed `/etc/tego/prices.yaml` or the built-in table in system scope, current user sources in user scope. Refuse a finite system cost
  limit without a trusted price for the model; never consult the user table. Preserve standalone handling.
* Current config loading ignores TEGO_CONFIG under secure execution but can still load config;
  general launches must instead refuse when AT_SECURE is set. The existing reader can observe safe
  source links; the scope-deciding fixed system-general path must reject a link for launch authority.
* Existing ordinary environment/runtime producers, compilation and preparation do not implement the
  closed exception environment, source manifest, compiled constraints or final shared verification.
  Slice 2 supplies the resolver/manifest seams, slices 4a/4b complete exception forms/environment, and
  slice 5a closes producer/composition checks before those launches can be accepted.

### R5: engine-set variables are the third and last environment source

Engine-set variables supplement R1's published literals and fixed pass-through list. Values come
only from the engine. Discard every caller entry of the same name, including duplicates, before any
producer runs; published literals cannot override an engine-owned name either. An inactive producer
leaves its reserved name absent, never inherited. Publication lists names, not per-run values. A new
name requires review and an amendment to this list. No engine-set variable may carry a path or option
that an interpreter loads code from. Final validation refuses any unlisted name or forbidden use.
PATH remains the recorded exception search list, not a fourth source.

The following list is taken from `identity.Env.overrides`/`ProviderBaseURLVars`, `runner.agentEnv`,
`forwarderVars`, `dnsBrokerEnv`, `guardedResolverEnv`, `configureClaudeSockets`, `harnessEnv`,
`mcprelay.Service.Vars` and the Claude provisioner. It distinguishes eligible future exception names
from legacy producers requiring refusal. This list does not claim current standalone behavior meets R5.
The `engine:` prefix marks an inventory key; it is not part of the environment variable name.

| Engine-set name | Producer and required exception behavior |
| --- | --- |
| `engine:TEGO_RUN_ID` | identity.Env; fresh engine run id |
| `engine:TEGO_AGENT` | identity.Env; checked agent id |
| `engine:TEGO_PARENT_RUN` | identity.Env; validated engine lineage, empty for no validated parent; never trust caller TEGO_PARENT_RUN as lineage authority |
| `engine:TEGO_LEDGER` | identity.Env; engine record directory, not a code-loading directory |
| `engine:TEGO_REASON` | identity.Env; engine refusal-data file |
| `engine:TEGO_TIER` | identity.Env; actual reached tier |
| `engine:OTEL_RESOURCE_ATTRIBUTES` | identity.Env; engine run/agent attributes only; discard legacy caller attributes rather than append |
| `engine:PGAPPNAME` | identity.Env; engine tego:<run id>, replacing legacy caller value |
| `engine:NO_PROXY` | identity.Env; engine loopback bypass list only, never append caller members |
| `engine:no_proxy` | identity.Env; same rule as NO_PROXY |
| `engine:ANTHROPIC_BASE_URL` | forwarder provider; engine listener URL |
| `engine:OPENAI_BASE_URL` | forwarder provider; engine listener URL |
| `engine:OPENAI_API_BASE` | forwarder provider; engine listener URL |
| `engine:GOOGLE_GEMINI_BASE_URL` | forwarder provider; engine listener URL |
| `engine:GOOGLE_VERTEX_BASE_URL` | forwarder provider; engine listener URL |
| `engine:CODE_ASSIST_ENDPOINT` | forwarder provider; engine listener URL |
| `engine:TEGO_DNS_BROKER_DIR` | dnsBrokerEnv; validated engine broker directory, data/socket use only |
| `engine:TEGO_DNS_BROKER_PID` | dnsBrokerEnv; engine broker process id |
| `engine:RES_OPTIONS` | guardedResolverEnv; engine fixed single-request, discard legacy caller options |
| `engine:TEGO_MCP_RELAY` | mcprelay; engine control listener |
| `engine:DOCKER_HOST` | identity optional adapter; engine socket only if otherwise supported; D4 container entry points remain ineligible |
| `engine:RAY_ENABLE_UV_RUN_RUNTIME_ENV` | identity optional adapter; fixed 0 only if otherwise supported |
| `engine:XDG_RUNTIME_DIR` | configureClaudeSockets; generated private socket state only, no caller selection on exception route |
| `engine:CODEX_HOME` | legacy forwarder config directory may load startup configuration/code; forbidden as engine-set exception input in this version; refuse a combination requiring it |
| `engine:TEGO_CLAUDE_SETTINGS` | legacy provisioner settings may contain executable hooks; forbidden as engine-set exception input; refuse a combination requiring it |
| `engine:TEGO_MCP_CONFIG` | legacy MCP config can select executable servers; forbidden as engine-set exception input; refuse a combination requiring it |
| `engine:CONTAINERS_CONF_OVERRIDE` | legacy adapter config can select helpers/hooks; forbidden as engine-set exception input; refuse a combination requiring it |
| `engine:RAY_RUNTIME_ENV_HOOK` | legacy adapter code-loading hook; forbidden as engine-set exception input; refuse a combination requiring it |

`DOCKER_CONTEXT` is removed by the legacy Docker producer, which supplies no value for that name.
`WSL_INTEROP` is removed from every enforcing agent environment; the filter supplies no value for it either.
Record-only runs retain the caller's value. Neither removal grants engine injection authority. `HOME`, `USER` and `LOGNAME`
are R1 pass-through/account normalization names, not additional engine injection authority. Credential
`Env`/`BaseURLEnv` keys and generic provision `Env` entries are dynamically selected today. They do not
extend this list: an exception requiring an unlisted dynamic injection refuses; a published literal may
still supply a non-reserved name through source (1), without a runtime producer replacing it. The
literal authority does not authorize a code-loading engine output. Do not silently drop a required
producer and launch a broken agent; refuse with the name and suggest an eligible form or standalone.

the complete-source engine-name inventory (retained separately) compares the named source literals to this list and retains the whole
input-surface ratchet for dynamic producers and unknown APIs. An injection of an unlisted literal
fails without changing production code. This is a list-keeping check, not child-environment proof.
Slice 4b must test replacement of forged/duplicate caller values, optional-producer absence, engine-only
telemetry/resolver values and final closure. Unsupported code-loading combinations refuse explicitly.

### R6: prices are policy wherever a cost limit is in force

Rewriting prices can disable a cost limit. Capture price policy before compilation, not in ordinary
post-compile preparation. In system scope consult only fixed `/etc/tego/prices.yaml` under the same
root-owned descriptor, safe-placement and bounded-read checks as other policy, or the table built into
the binary. Never consult `~/.tego/prices.yaml`, a user config price selector or a caller override.
A present unsafe, unreadable or malformed fixed system table refuses; only verified absence permits
absence fallback. A valid fixed table supplies its complete exact model entry first; a missing or
incomplete entry may use a complete exact entry in the built-in table. No heuristic model aliasing.

The source manifest records the file path, identity, placement and raw digest, or `built-in` plus the
binary's table digest; when both are consulted record both and every relied-on absence. Recheck file
sources and absences immediately before release; built-in bytes stay bound to this binary. User scope
reads prices as today, under user authority, with the consulted sources in the manifest too. Without
a cost limit ordinary optional estimate warnings remain unchanged; they do not authorize enforcement.

A system general with a finite `limits.cost_usd` and no trusted price for the model in use REFUSES
before child release, exit 125. The diagnostic names the limit, exact model and both allowed places:
`limits.cost_usd=<limit>: no trusted price for <model>; install /etc/tego/prices.yaml as root or use a model priced by the built-in table`.
Preflight every selected/declared model; an unknown model selection refuses as `<unknown>` and asks
for an explicit priced model. It never falls back to the user's table or runs silently unenforced.
Existing fail-closed metering of unexpected runtime models/usage remains required; the launch check
does not claim to predict a response's usage. This narrows the legacy PricesAnyModel check for this route.

Current source audit finds zero shipped built-in price entries and zero installer writes to the new
fixed system path. A table allocated in a test is not a shipped table. Slice 2a must add an explicit
built-in table (an empty table is allowed but prices no model), its digest and source-selection capture.
Do not invent rates. Installer and dashboard must preflight the proposed system general and all its
models against these exact sources before activation/save, show each missing model and limit, and
block activation/save until root installs valid prices or the operator explicitly chooses a priced
model or removes the cost limit. Keep Stop/Pause/Deny available. Never copy the user's table silently.
The dashboard cannot write a system table as non-root. CLI launch repeats preflight for external edits.

Ordinary setup matrix: eight cases, six finite-limit S cases. Cases 1, 2, 4 and 5 refuse;
case 6 also refuses on this head because its future built-in entry does not ship. Thus five of six
finite-limit S setups lack an authorized usable price on this head; case 6 becomes a positive control
only when that reviewed built-in entry ships. These counts describe fixtures, not deployed machines.
The availability facts are measured offline with price parser/Cost fixtures; the launch outcomes below
are required R6 behavior, not measured launches. No fleet frequency is inferred from eight fixtures.
Built-in availability is zero on this head. Trust failures use the existing source trust rule, not a
parser-success inference. Later system-source and activation checks are slice 2a/8 work.

| Case | Ordinary setup | Measured price availability | Required launch/activation result |
| --- | --- | --- | --- |
| 1 | S finite cost, fresh install, no system table | Missing file, zero built-in entries | Refuse; installer/dashboard name model and limit, request root table |
| 2 | S finite cost, only a valid user table | User table can price model but is unselected; zero built-in entries | Refuse; explain user table cannot supply S policy |
| 3 | S finite cost, valid root system table with exact model | Complete fixture entry prices model | Pass pricing preflight; other launch checks still apply |
| 4 | S finite cost, valid root table for another model | Requested model is unpriced | Refuse; show missing exact model |
| 5 | S finite cost, partial entry missing input or output rate | Requested model is unpriced | Refuse; repair entry, never treat omission as zero |
| 6 | S finite cost, absent file, future built-in complete model entry | Complete in-memory fixture prices model; no such shipped entry today | Pass pricing preflight when that reviewed table ships |
| 7 | S without cost limit, no table | Missing file, zero built-in entries | No R6 cost refusal; optional estimate warning |
| 8 | U finite cost, valid user table | Complete fixture entry prices model | Current user price authority, captured in manifest |

An unsafe/unreadable/malformed system table refuses independently of model availability; the matrix
counts pricing-availability cases, not an exemption for broken trust. Guest ownership, actual launch
refusals and installer/dashboard behavior are owed in a guest. the complete-source price inventory (retained separately) keeps
price defaults/read sites in the mechanical inventory and checks these system/user/built-in decisions.

### Production build boundary and its proof limits

Keep `TestProductionRunHasNoGeneralSelector` and `TestProductionConfigHasNoGeneralSelector` as guards
for their enumerated parser spellings. They do not establish the absence of an environment branch,
hidden command or alternate launch caller. R4 additionally requires structural coverage of the
build-selected production package graph and dispatch coverage over every registered command, hidden
ones included. Launch-capable general entry points may exist only in `tegotesthooks` source files
until slice 11 accepts the release evidence. The source-input inventory covers environment reads.

the complete-source build-boundary check (retained separately) pins the reviewed no-general-launch source graph for both active
binary roots (`cmd/tego`, `cmd/tego-control`), using Go's `go/build.ImportDir` file selection
and hashes of selected module source files, including the module's root package. The certificate is generated independently with `go list
-deps -json` for Linux amd64/arm64, CGO disabled, each plain and `tegobpf`, at the default architecture
levels. Tool tags are captured from Go's build context. the complete-source engine dispatch check (retained separately) exercises the
registered engine commands, hidden ones included; `TestProductionGeneralControlDispatch` checks the
complete control registry and the separately retained archived-Maze check covers the former registry.
Control forwards verbatim arguments and parses inside command bodies, so its callbacks prove routing
only. The archived Maze proof uses parser/help routes that stop before command bodies. The private-source fingerprints are excluded from
the rewritten public cut; that tree needs its own build verification.
A graph or source change then fails pending review and recertification. This pins the reviewed build;
it is not a semantic proof for a deliberately changed certificate, external dependency or toolchain. Command dispatch tests
must enumerate `commands()` rather than a fixed command list; callback substitution verifies routing
and parser behavior without running product commands. It does not execute their launch bodies. Record
the actual structural/dispatch test names and measured results outside this ADR, not as future
implementation acceptance here. No general launch behavior is implemented by these tests.

Exceptions also persist across general revisions until explicitly removed. Every fresh preview/launch rechecks
their scopes against current G, baseline and sources; receipts retain the original snapshots. The UI shows
revision drift and the whole exception list, including redundant entries. There is no implicit expiry or role
system in this decision.

Only source selection and read-only Contracts display are implemented here. No general/managed launch,
customisation parser, editor or record revision is enabled by slice 1. Kernel refusal and real root placement
are owed in a guest; unit-modeled ownership does not discharge them. Nov 15 remains a target, not proof.

## Hard cases under the exception rule

| Case | Required answer |
|---|---|
| Delete extends, changes, or exceptions | Launch selects G out of band. Removing all customisation restores G. An omitted line cannot widen a tightening-only file. |
| Delete binding or no general remains | Refuse named/general launch before child; no standalone or permissive fallback. |
| Broken/unreadable system G, writable ancestor, dangling link | Unknown/failure; never user fallback. Only safe absence selects user. |
| User exception to system G; forged uid; matching owner but writable placement | Refuse exception. Trust is a complete publication boundary, not one stat or claimed role. |
| User G becomes system G | System scope stops consulting user envelopes; no old user exception or tightening policy carries over. An otherwise valid unbound launch uses system G without an exception; a named launch requires its system binding. |
| Exception overlaps baseline or duplicates its denial | Baseline membership wins; refuse conflict with both sources. Root cannot force it. |
| General denial plus nested write, ask, live fence, duplicate top denial | Only a named authorized exception may remove G membership; no path/merge side effect can do it. Baseline remains. |
| G command true and exec.allow git status; C command git status | Compare final compiled command authority. C's ordinary unconstrained git grant refuses; matching the one launch argv does not admit git push later. |
| MCP/model/credential/environment injection restores a removed grant | Refuse any FROZEN family edit. An inherited producer may add only the exact SUPPORTED-family scope covered by a named exception; a hidden producer is never authority. |
| Last exec/net/env grant removed; empty vs absent vs null | Keep restricted mode through canonical reload. Null/malformed refuses. Empty customisation inherits, empty keep removes all. |
| Higher memory/pids/wall cap | Require an authorized named positive finite cap exception and retain machine ceilings. No silent scalar override. |
| Privilege/record/live switch, unbounded cap removal, generic replacement fragment | Refuse unsupported operation, even from trusted publisher; add a reviewed typed operation before accepting it. |
| Exception name reused by another uid/argv/folder/program, or same argv after script replacement | A label never transfers approval. No command/folder binding match means no exception on an otherwise valid unbound general launch. A matching binding with a changed program pin refuses exit 125 and requires republication; an invalid explicitly selected managed binding still refuses its named launch. |
| Same label, different folder; two bindings; unknown wrapper/argv | Explicit trusted managed name authorizes. Display Cannot tell when observation cannot join uniquely; never choose least restrictive. |
| Root acts for another owner | Explicit supported uid/home context or refuse. Dashboard service uid is not the owner. |
| System G with user config/profile override | Slice 1 only observes. Future launch decides scope first, ignores the user policy selector with one line and reads only fixed system policy. An unsafe dependency actually selected by system policy refuses. |
| Source swaps, stale preview, stale keep/exception reference | Immutable source manifest before compile and verification before child release, plus editor CAS. Changed policy/resolver/program facts refuse exit 125 with source and repair; ordinary observations and constrained preparation facts follow the lifecycle above. No retry or partial batch. |
| A slice 2 selector in an ordinary production build | It must not exist until slice 11 accepts every slice 2-to-10 dependency and guest proof; only tegotesthooks builds may exercise the incomplete launch path. |
| A customisation touches a family with no defined order | FROZEN refusal, including an exception; never infer safety from fewer source entries or a sampled property. |
| Delete customisation while run is active | Future run returns to G; active run retains recorded C/E and exceptions. Display revision drift. |
| Unreadable source after start | Stop/Pause/Deny and recorded display remain; new policy decisions refuse. No silent reload. |
| Standalone typo, old flags/hashes, service/boundary route | Preserve existing semantics; never reinterpret a failed name as general. Compatibility population remains visible. |
| Migration needs more than G | Authorized publisher must explicitly name and preview exceptions; otherwise retain own contract. No automatic exception. |
| Scanned program outside Tego, adoption, changed startup env | Show outside/unknown and next-launch line; saving does not govern it. No full managed adoption in this release. |
| Copied/interpreted exec, old descriptors, chmod, hostile root/namespace | Disclose mechanism limits; neither named exceptions nor layer hashes create stronger kernel guarantees. |
| Replay after edits/deletion; old receipt lacks fields | Use sealed verified recorded inputs. Old missing metadata is unknown; new minor requires list/boolean/hash parity. |

## Rejected options

* **A default profile alone:** familiar and inexpensive, but removable and permissive under current merge classes.
* **Rename the baseline:** retains a real floor but supplies neither shared grants nor no-own-contract launches.
* **One physical file for every agent:** easy to inspect for a small installation, but couples edits and replaces
  registry/source rules for a benefit the central view can provide.
* **Adjustable general grants:** useful for different agents' needs, but requires another reviewed authority and
  conflict language. It is a later candidate, not secretly implemented by command overrides.
* **Silent loosening merges:** rejected. Named recorded exceptions are accepted only with publication trust, bounded operations, baseline conflict checks and visible preview; recording alone never authorizes them.
* **Arbitrary full-contract intersection:** no complete comparator exists for arbitrary defaults, precedence
  and pattern inclusion. The exhaustive matrix permits only defined compiled comparisons; the rest is FROZEN.
* **Replace all old contracts immediately:** makes a stronger universal claim but breaks the compatibility requirement.
* **Fallback after any registry failure or automatic scan adoption:** convenient but can lose intended policy or
  claim rules were installed when only a program was observed.

## Acceptance and open coordination

The maintainer allocates the next record minor and sequences shared baseline/identity/builder files.
Slice 1 never compiles the selected general through the ordinary top-contract directory exception, never
changes launch tables, and makes source problems observational rather than new standalone refusals.
General sources are absent from legacy list output when neither source is selected. Existing list/show
and compile golden fixtures must pass unchanged; pin pre/post canonical and compiled fixture digests.

### Input inventory: the current code and the required authority

This table records resolver inputs from the current private source tree. The public export keeps the primary decisions and omits the private ledger and fingerprint tests; its rewritten sources need separate verification. U and S mean the required user and system scopes in R2. General launch is not implemented today. Current read-only discovery and legacy launch behavior do not establish these future checks. The source expression in each mechanically checked private-ledger row gives the exact current value, flag default, call arguments, and source site. The treatment cells refer to the following closed definitions. A literal or named constant row inventories the value used by the surrounding algorithm; it does not assert that the value is independently read from the caller.

The following primary rows explain the actual source precedence, implicit library inputs, absence branches and required changes. The mechanical rows in the private ledger enumerate individual syntax sites, rather than replacing these decisions with categories.

| Input and current source sites | Scope where consulted | Authority | Absence rule | First check to release comparison |
| --- | --- | --- | --- | --- |
| Fixed `/etc/tego/general.yaml`, `contractsrc.SystemPath`, `readGeneral` | S/U, before any policy selection in slice 2; today a complete machine snapshot is required first | Root-owned fixed file and trusted parents, initial user namespace; no link allowed for scope selection | Trusted ENOENT selects U; any other failure refuses; today the read-only source reader permits trusted links | Pin selector, checked parent identities, source identity/digest or proved absence; any change refuses |
| `<passwd home>/.tego/general.yaml`, `contractsrc.readGeneral` | U only; S skips it | Delegate user; user-level authority, no machine authority | No passwd home leaves user source unselected; missing file means no user general source; unreadable/untrusted is unknown | If selected, pin source bytes, identity and containing directory; pin verified absence when consulted |
| `/etc/tego/config.yaml`, `config.EtcPath`, `Resolve`, `loadSources` | U and S | Fixed root-owned system source | Optional only on verified absence; trust/read/parse errors refuse decision loads | Source identity/digest, placement and absence proof; no reload at compile |
| `<passwd home>/.tego/config.yaml`, `config.UserRelPath`, `Resolve` | U only in slice 2; read by today's normal merged config before `ReadGeneral` | Delegate user | No passwd home selects no layer; verified missing optional layer; errors refuse a decision load | Pin selected source; no consultation in S; ignore a policy-changing user layer with one line |
| `TEGO_CONFIG`, `config.EnvConfigVar`, `Resolve`, `loadSources` | U only when not secure; ignored for S policy | Delegate user's explicit policy selector | Unset is unselected; selected missing file refuses; relative/proc paths refuse today | Pin selector and selected source or absence; S reports policy-changing setting ignored |
| `SUDO_UID`, `config.InvokingUID` | Identity setup in U/S, never scope selection | Existing delegation rule: real uid 0 in initial user namespace, parsed unsigned uid except 0xffffffff; otherwise real uid | Empty, invalid or noninitial namespace is treated as unset today | Capture real/delegate identity; it stays fixed for the launch; user-file reads use delegate credentials |
| `SUDO_GID`, `cli.sudoGID`, runtime `dropTarget`/`privilegedTarget` | Identity/credential setup in U/S | Existing product validation; primary passwd gid is the fallback where supported, not arbitrary machine authority | Empty/invalid falls back to validated passwd gid; invalid target credentials refuse | Capture validated credential target; apply the same target when reading delegate policy and releasing child |
| Initial user namespace, `config.CurrentUserNamespace`, `/proc/self/uid_map` | U/S identity and trusted system scope | Kernel observation; identity mapping `0 0 4294967295` means initial; other map means child | Unreadable is unknown, never initial-root authority | Immutable per process; capture and enforce namespace requirement; also require initial mount namespace for an exception |
| `AT_SECURE`, `config.DetectSecureExec`: runtime `unix.Auxv()` then `/proc/self/auxv` | Before general U/S launch | Kernel execution fact | Probe error refuses; nonzero refuses general launch; today's ordinary config only suppresses environment policy selectors | Capture once; no environment substitution; a secure general launch never reaches release |
| Passwd home/name/gid, `config.LookupPasswd`, libc and pure-Go build variants | U paths and delegate identity; S never uses home to choose a policy source | Existing account database for the real/delegate uid | Missing home omits user config/profile defaults; a required `~` expansion can refuse | Capture resolved identity/home used by selectors; source paths in manifest cannot move; libc/NSS internals are outside the syntax recognizer |
| `HOME`, `os.UserHomeDir` aliases in CLI logging and runtime anchor/ledger root | Existing output/runtime placement; not general policy selection in S | Caller account placement observation outside policy authority | Today's fallback is allowed only where existing secure/root rules allow it; otherwise refusal or configured absolute root | Record/validate runtime placement as today; do not let it select S policy; no source-equality refusal for an ordinary placement observation |
| `XDG_RUNTIME_DIR`, `config.RuntimeDirBases`, runtime directory creation and supervisor host bases | U/S preparation and protected target observations, not S policy source | Caller-selected runtime location subject to existing ownership/permission/absolute-path checks | Base list always begins `/run/user/<invoking uid>`; distinct absolute XDG value adds a base; creating a required runtime object can refuse when unusable | Existing places are checked where the product rechecks them; preparation must meet compiled floor; no policy-source digest comparison |
| `/run/user`, `config.LogindRuntimeRoot` | U/S runtime bases | Built-in protective default plus kernel/account uid | Does not disappear from the protected base list when XDG is absent | Same observation/preparation rule as runtime bases |
| `XDG_CONFIG_HOME`, control CLI `severityFile` via `os.UserConfigDir()` | Dashboard severity-display configuration only; not general policy selection | Caller display preference; no S policy or exception authority | On Linux, nonempty XDG_CONFIG_HOME is the directory; otherwise `$HOME/.config`; API error gives no Severity page | The chosen `<config dir>/tego/severity.json` is a display observation; existing display validation applies, not source-manifest equality |
| `XDG_CACHE_HOME`, selftest `treeParent` via `os.UserCacheDir()` | Selftest scratch-root fallback only; not general policy selection | Caller scratch placement; no S policy or exception authority | On Linux, nonempty XDG_CACHE_HOME is the directory; otherwise `$HOME/.cache`; API error contributes no cache candidate | Candidate location is a preparation observation; existing directory validation applies, not policy-source equality |
| `TMPDIR`, doctor `makeFixtureDir` via `os.TempDir()` and `os.MkdirTemp(base, ...)` when `/run/tego` cannot be created | U/S capability-probe fixture placement only | Caller temporary placement observation; no policy source authority | Fixed `/run/tego` is attempted first; failed creation makes base empty; standard library uses nonempty TMPDIR else `/tmp` | Preparation capability result must meet compiled floor; temporary target changes are not source-policy differences |
| `TMPDIR`, `cli.watch` via `os.MkdirTemp("", "tego-watch-")` | Existing watch generated-contract preparation | Caller temporary placement; generated contract bytes still define that legacy watch run | Nonempty TMPDIR else `/tmp`; temporary-directory creation failure refuses watch setup | A future general customisation must capture generated policy bytes before compile; directory creation is preparation, not scope authority |
| `TMPDIR`, `cli.adopt` via `os.MkdirTemp("", "tego-adopt-")` | Existing adoption generated-contract preparation | Caller temporary placement; no general scope/exception authority | Nonempty TMPDIR else `/tmp`; creation failure refuses adoption setup | Future general customisation captures generated bytes before compile; preparation stays subject to compiled floor |
| `TMPDIR`, `cli.receipt` via `os.MkdirTemp("", "tego-ci-check-")` | Receipt verification scratch only, not launch policy | Caller temporary output location | Nonempty TMPDIR else `/tmp`; creation failure refuses that verification step | Existing verification checks; no source-manifest field for temporary output |
| CLI `init` via `os.CreateTemp(filepath.Dir(path), ".agent.yaml.*")` | Contract creation only | Explicit destination directory, not TMPDIR or XDG selection | Creation failure refuses write; no implicit temp-root fallback | Future launch captures the resulting selected policy file, not this earlier temporary output |
| `config.DefaultProfiles = "~/.tego/profiles"`, `Builtin`, `expandHome`, `profilesrc.Chain` | U today; slice 2 must make default S=`/etc/tego/profiles`, U=current user default | S root-owned fixed directory; U delegate user | No passwd home drops built-in U profile directory; required missing profile refuses; S cannot fall back to U | Pin consumed profile bytes/identity and checked directories or consulted absences; current compiled-in default is not scope dependent |
| `profilesrc.Chain`: built-in registration then directory registration; `ProfileChain.resolveBounded` | U/S with scope-selected directory | Reserved `tego/` names use built-in sources only; other names use directory sources only | Missing source tries next source in that class, then extends-not-found; a directory shadow of a reserved built-in is reported, not substituted | Source class, ordered source list, each consumed file and consulted absence in source manifest |
| `<profiles root>/<name>.yaml`, `profilesrc.Dir.Location`/`resolve` | U or fixed S profile directory | Same scope authority as owning profile directory; beneath-root `os.Root` resolution and existing trust checks | Empty root/name, nonlocal name, missing/unreadable/nonregular file cannot supply required profile | Pin exact descriptor bytes plus checked resolved parent; source change refuses; script-loaded files are separately subject to R1's limit |
| `presets.Source`, embedded built-in YAML, name without revision versus `@revision` | U/S | Published binary data; names without revision select newest embedded revision, pinned name selects that revision | Missing built-in name/revision refuses required profile resolution | Source manifest includes selected revision and bytes/digest; frozen revision tests guard release data |
| Registry position 1: `<cwd>/agent.yaml` if its `name:` matches; position 2: `<cwd>/.tego/agents/<name>.yaml`; position 3: `<machine.registry>/agents/<name>.yaml`, `registry.Places.Resolve` | Today's normal contract-name lookup; U policy path in future; never a source of S general authority | Delegate user/root trust today; neither project nor user source gains S authority | Missing positions continue; duplicate different files, project duplicate, or a same-name ordinary file cause ambiguity refusal; no match refuses named legacy contract | Pin each source and each absence relied upon for selection, including ambiguity observations that decide selected policy; no silent precedence replacement |
| `config.DefaultRegistry = "~/.config/tego"` | U registry policy; never S general authority | Built-in user registry selector expanded using passwd home, user mutable contract files | No passwd home clears built-in registry | Pin selected registry source bytes/identity and all selection absences |
| `config.DefaultLedgerRoot = "~/.tego/runs"` | U/S record-output placement under existing account rules | Configured destination and validated account placement; no source policy authority from output files | Unexpanded `~` follows current secure fallback/refusal rules | Existing output placement checks; generated ledger records are not source policy |
| `config.DefaultPrices = "~/.tego/prices.yaml"`, `limits.FromMachine`, CLI `runPrices`; future fixed `/etc/tego/prices.yaml` and `built-in` | Cost-limit policy in U/S under R6; current default U only | S fixed root-owned system table or binary table, never user prices; U current user authority | Verified S file absence permits built-in; unsafe/read/parse errors refuse; finite S limit without trusted exact model price refuses | Capture file path/identity/digest or built-in table digest before compile; pin consulted absences and verify before release |
| Run flags `--tier`, `--record`, `--observe`, `--offline`, `--status-file`, `--v`/`--verbose`, `--service`, `--no-summary`, `cmdRun` | Today's run; future general U/S only under composition and runtime floor rules | Caller option does not confer exception or machine policy authority | Defaults are empty strings or false exactly as the registered flag row states; invalid values refuse as current parser/checks require | Freeze selected launch options; any policy-affecting option is compiled into C and checked within G; status/output options remain observations |
| Contract/name positional argument and post-contract command argv, `cmdRun`, `commandFor`, compiler `WithRunCommand` | Today's legacy run; future G/customisation binding | Caller can choose a command under G; user policy file cannot replace S policy | Empty contract or empty explicit command is usage refusal; no explicit command uses contract command | Capture selector/argv; exception match uses R1; no-exception resolved program is recorded without program identity granting authority |
| `PATH`, CLI `WithPATH(os.Getenv("PATH"))`, compiler `effectivePATH`, runtime `resolveCommand`/`lookPath` | No exception: G's literal PATH if set, else caller PATH; exception: recorded search list only | Caller PATH is a resolution observation without exception; recorded exception list has publication authority | Empty or unusable list resolves no bare name; record resolution failure honestly; an existing exception mismatch/unresolvable target refuses 125 | Capture ordered resolver inputs and resolved program fact; R3 verifies the captured program descriptor/identity/digest before release even without exception; exception additionally equals publication pin |
| Existing command resolution: matching compiled `Exec` basename first, then `rt.PATH`; path containing `/` passed through; empty PATH components skipped; first candidate that is not a directory and has any execute bit wins | Legacy launch only as implemented; slice 2 must reconcile general resolver with R1/R2 | Existing compiled rule plus caller/contract path, not exception authority | Legacy unresolved name passes through for kernel exec failure, usually 127 | General exception mismatch is never this legacy fallback; source/program verification uses captured bytes and executable descriptor |
| Compiler loader directory search, `loaderDirs` | U/S compile observation | Built-in search list: `/lib`, `/lib64`, `/lib32`, `/libx32`, `/usr/lib`, `/usr/lib64`, `/usr/lib32`, `/usr/libx32`, then glob results `/lib/*-linux-*`, `/usr/lib/*-linux-*` | Missing/unreadable directories contribute no loader identity | Compiler target observation, not source policy; recompile the same source bytes at actual tier; backend/mechanisms meet floor |
| Compiler tool helper search, `helperDir` | U/S compile observation | Relative to resolved executable prefix, first `<prefix>/lib/<tool>-core`, then `<prefix>/libexec/<tool>-core`; no unrelated installation fallback | No regular `<dir>/<tool>` gives no helper directory | Target observation; R1 exception pins entry program rather than all script/module/helper loads |
| Doctor libssl producer search, `doctor.libsslDirs`/`systemLibSSL` | U/S preparation capability observation | `/usr/lib64`, optional `/usr/lib/<triplet>`, `/usr/lib`, `/lib64`, optional `/lib/<triplet>`, `/lib`, `/usr/local/lib64`, `/usr/local/lib`; first directory with highest-sorting regular matching library | Missing candidate continues; no usable probe target affects supported capability/floor | Actual capability result checked against compiled floor; not source-manifest equality |
| Uprobe producer search, `uprobe.systemLibraries`/`libDirs` | U/S preparation | `/etc/ld.so.cache` entries first; optional `/lib/<triplet>`, `/usr/lib/<triplet>` first in directory fallback, then `/lib64`, `/usr/lib64`, `/lib`, `/usr/lib`, `/usr/local/lib64`, `/usr/local/lib`; libssl matches deduplicated by identity and build id, native architecture only | Missing/cache failure continues to directory fallback; unavailable mechanism must meet compiled-floor rule or refuse | Preparation fact checked against compiled mechanisms; generated attach objects are not source-manifest fields |
| `TMUX_TMPDIR`, `SCREENDIR`, compiler `builtinRefusals` helper `envPath` | U/S protective target observations | Caller values add immutable refusal locations; cannot publish an exception or select S policy | Empty adds no extra target; unplaceable nonempty value produces compile diagnostic | Retake protected target observations at existing product checks; no source-change refusal merely because target changed |
| Inherited environment and `env.pass`/`deny`/`set`, `run_env.buildEnv`, runtime `environ`, compiler `WithEnviron` | Current child environment; future exception child must use closed R1/R5 environment | R5 engine-set names take engine-only values, caller names discarded, code-loading engine outputs forbidden; literal published `env.set` has contract authority; short allowed pass list carries no code-loading authority; arbitrary inherited variables cannot accompany exception | Today nil pass inherits everything; explicit pass drops unnamed variables; slice 4b must change exception preparation and reject disallowed requested pass variables at publication | Capture literal sets/pass selection/resolver inputs; construct once from authorized values; no caller `NODE_OPTIONS` reaches exception child |
| Harness `CODEX_HOME`, Claude settings/config flags, runtime `codexConfigPath`, adapter argv and discovery paths | Existing preparation and script/module/config loading; not S general policy authority | Existing contract/harness choices and current user files; entry-script pin does not assert downstream config immutability | R5 refuses exception combinations requiring code-loading engine variables; existing standalone checks remain | Generated objects checked against compiled constraints; downstream modules/config remain R1 C/D stated limit, not silently added to source-manifest equality |
| `TEGO_PARENT_RUN`, `TEGO_DNS_BROKER_PID`, `TEGO_DNS_BROKER_DIR`, UI `TEGO_HINTS`, desktop `DISPLAY`/`WAYLAND_DISPLAY`/`DBUS_SESSION_BUS_ADDRESS` | Existing record lineage, broker client or display/UI paths | Incoming lineage/UI are observations, never selectors; outgoing broker/lineage values must be engine-only under R5 | Missing optional metadata/UI uses existing no-parent/no-display behavior; DNS command validates required broker target | Existing observation validation; never select policy or grant an exception |
| `TEGO_TEST_*` and tagged phase/backend hooks | Test builds only | Test isolation/instrumentation, no production general authority; existing secure-process suppression remains | Unset retains normal behavior for that hook | Production build excludes these files; structural boundary test covers executable linkage separately |
| Control CLI `loadMachineReport`, `config.Resolve` then `LoadSources`; fixed system, passwd user, TEGO_CONFIG layers | Existing control read side; required general authority still scope-first | Same layer provenance as engine; read-side TrustWarn may keep UNKNOWN, never authorize a launch from it | Existing optional/explicit-layer absence rules; failed layer remains UNKNOWN in degraded read mode | Future general launch requires strict source capture independent of this display snapshot |
| Setup `Draft`/`ecosystem`, project `package.json`, `Cargo.toml`, `pyproject.toml`, `requirements*.txt`, `go.mod`, options and home | Current init/generation workflow; no S general authority | User choices and project-marker observations generate suggested user policy, not embedded preset authority | Missing markers add no ecosystem grants; invalid requested generation/preset input keeps existing errors | Capture resulting authorized policy before any future general compile; marker observations used while drafting do not become immutable launch sources |
| Selftest scratch-root candidate order, `treeParent` | Existing `tego test` run driver preparation | Explicit temp root or standard-library temp root, then supplied environment XDG_RUNTIME_DIR, then user cache dir | Empty/nonabsolute/unresolvable/non-directory candidate or one inside the engine binary directory is skipped; exhausting all refuses | Preparation observation checked by existing placement rules; generated selftest policy bytes are captured if a future general launch consumes them |
| Selftest caller TEGO_CONFIG overlay, `writeConfig` | Existing selftest run driver | Caller's current machine layer copied into private selftest config, then selftest-specific fields written; not system general authority | Explicit caller layer read/parse failure refuses selftest setup | Future general path cannot use this to replace S policy; source manifest must capture authorized policy bytes before compile |
| Maze workspace and personal rules, `scope.LoadWorkspace`/`LoadPersonal`; `.maze/workspace.yaml`, `<HOME>/.maze/personal.yaml`; generated `<HOME>/.maze/projects/<project id>/` contract/verdict files | Current Maze user workflow and engine compile wrapper, not S policy | User-level policy; process HOME selects personal/project storage and rule normalization | Missing workspace/personal file means not configured; existing parse/permission errors remain errors | Future general customisation must capture selected user policy bytes and compare within G; no Maze approval can confer S exception authority |
| Maze tool/engine resolution, `scan.Env.LookPath`, `verifyEngine` | Existing user workflow | Caller PATH absolute directories only, empty components skipped; regular executable required; engine located inside project is refused for verification | No engine or non-Linux means no verification with explicit disclosure; engine start/compile failure does not count as checked rules | Program identity facts and existing project exclusion; no general exception authority |
| Rule-file locator, `rulefile.FindAtIn`, `Read`/`pin`; HOME/passwd home refusal roots, `/etc/group` and `/etc/passwd` private-group trust data | Existing CLI/dashboard rule reads and edits | Selected contract is user policy; trust/account data decides whether source may be read for a change, not S scope | Missing/stale/untrusted source refuses relevant edit; private-group lookup failure fails that trust allowance closed | Pin selected source bytes/identity and parent for edit; future launch source capture separately follows R3; HOME can add refusal roots only |
| Control handoff, `handoff.Open`/`Exec`/`Spawn` | Current engine-to-control dispatch | Sibling control binary, caller/root ownership and write-mode checks plus compiled SHA-256; sealed memfd is executed; never caller PATH | Missing/unpinned/untrusted control image or unsupported required sealed execution refuses handoff | Existing sealed image/digest check; future general entry program descriptor must also satisfy R3 and exception pin if present |
| `realtego` and `guide/guidetest` helper package inputs | Tests and tagged isolation protections only | No production policy or launch authority | Helper isolation/fixture checks; absence cannot grant production authority | Helper observations checked as defined by those tests; these packages are not falsely described as wholly build-tagged source files |
| System/user binding and exception stores | No current code input or source path exists in this slice | Future S fixed root-owned stores; future U delegate-user stores labelled user-level | Future no binding means G, existing mismatched binding refuses, unpinnable publication stores nothing | Future records and consulted absence are source-manifest fields; do not invent present code inventory sites for these stores |

#### Treatment codes for individual source sites

Each `.scope`, `.authority`, `.absence` and `.compare` cell below expands to the matching column here. These are required handling rules for the algorithm containing the site. A path literal, default declaration, selector alias or absence sentinel is part of that algorithm's input surface; its row does not claim an additional I/O operation. The primary rows above resolve special cases and describe present differences. No treatment code claims these future launch checks already exist.

| Code | scope | authority | absence | compare |
| --- | --- | --- | --- | --- |
| GENERAL-SOURCE | Fixed system selector first; user G in U only | Root S source, delegate U source | Trusted fixed-system ENOENT selects U; selected source errors refuse | Source identity, content digest, parent proof and consulted absence unchanged |
| CONFIG-ENV | U only, never S policy | Delegate explicit config selector; ignore in S | Unset unselected; selected missing or invalid path refuses | Selector and source identity/digest/absence pinned |
| CONFIG-SOURCE | Fixed system config U/S; user config U only | Source provenance decides root or delegate authority; parser constants carry none | Optional system/user verified absence; selected explicit path errors refuse | Consumed policy identity/digest/placement and absence pinned; parser constants fixed by build |
| CONFIG-DEFAULT | Binary defaults in U/S; profiles default scope dependent in slice 2 | Built-in literal setting; no caller authority | Missing override retains literal default; missing home follows primary row | Build/default choice fixed; consumed mutable policy source separately pinned |
| IDENTITY | U/S identity setup; does not select scope through caller variables | Kernel ids/namespace/secure fact; validated existing sudo delegation/account database | Unknown never becomes initial-root authority; secure general launch refuses; invalid sudo value uses existing fallback | Fixed validated identity/namespace/credential target; policy selector paths captured from it |
| PROFILE | U directory or fixed S directory; reserved names built-in only | Root S profile, delegate U profile, or binary preset according to actual selected source | Missing source tries next same-class source; required final miss/error refuses | Ordered source class, consumed bytes/identity/parent and relied absences pinned |
| SETUP-GENERATOR | Current user init workflow, not S general authority | User choices and observed project markers construct proposed user policy; embedded presets retain their own binary authority | Missing markers add no suggested grants; existing generator validation and required preset errors still apply | Before a future general launch, capture authorized generated policy bytes and compare within G; marker observations during generation are not pinned policy sources |
| PRESET | U/S embedded built-in source | Frozen binary revision bytes | Unknown name/revision cannot satisfy required profile | Selected revision/digest/build fixed |
| CONTRACT-SOURCE | U user/project policy; S only its fixed root sources | Delegate policy cannot acquire machine authority; source byte consumer determines whether general customisation is allowed | Search uses documented positions and ambiguity rules; required miss/error refuses | Every selected policy identity/digest and absence deciding selection pinned |
| REFUSAL-ENV | U/S compiler protected-target extension only | Caller values add refusal targets, never authority | Empty adds no target; invalid nonempty target diagnoses/refuses compilation where current code requires | Observation retaken at existing checks; compiled protections/floor must hold |
| RUNTIME-BASE | U/S preparation/protected target | Caller/runtime/account location with existing placement trust checks, no policy-source authority | Built-in logind base remains; unavailable required runtime directory refuses | Existing target checks; preparation meets compiled floor; no source equality rule |
| RESOLVER | U/S; exception uses recorded list exclusively | No exception: G literal PATH then caller PATH; exception: publication search list | No usable candidate records failure; an existing exception resolution failure refuses | Ordered resolver inputs captured; R3 rechecks captured program descriptor/identity/digest before release even without exception; exception additionally equals publication pin |
| CHILD-ENV | U/S child preparation | Published literal sets; exception pass-through restricted to R1 list plus R5 engine-only named outputs | Current nil pass inherits; slice 4b closes exception environment and refuses forbidden publication pass entries | Caller engine-name values discarded; no code-loading engine output; authorized environment/resolver inputs captured and constructed before release |
| RESOLVER-ENV | U/S child resolution/environment algorithms | Primary PATH/closed-environment rows determine authority; literal normalization data grants none | Empty candidate/env follows documented current algorithm; exception mismatch refuses | Source resolver inputs and captured program descriptor/identity/digest verified under R3; exception additionally equals publication pin; ordinary rule targets remain observations |
| LAUNCH-OPTION | Current launch commands; future U/S general only under composition | Caller options can tighten/select work, never confer exception/system authority | Exact registered default or parser/usage error as source expression shows | Capture options; compile policy-affecting choices in C and check within G/floor; output-only options remain observations |
| OTHER-CLI | Owning non-general CLI command only; no present general launch selector | Caller option/output/inspection input; source-producing command cannot itself confer general launch authority | Exact registration/default or owning command's current error branch | Existing command checks; reuse in general path requires reclassification and source capture where applicable |
| PRICE-SOURCE | Cost-limit policy U/S; S fixed /etc/tego/prices.yaml or built-in only | Root/binary authority S, current user authority U; never user prices in S | Verified file absence permits built-in; bad system source refuses; finite S cost without exact trusted model price refuses | Capture file path/identity/digest or built-in digest before compile plus absences; verify before release |
| PREPARATION | U/S backend, producer and lifecycle preparation | Kernel/runtime capability/target/object observation; no policy-source authority | Current fallback/unsupported-mechanism handling; never use absence to lower compiled floor | Actual tier/mechanisms/objects checked against compiled constraints; source bytes never reloaded |
| EXEC-OBSERVATION | U/S compile/resolution targets | Contract-authorized rule plus observed executable/loader/helper target; identity grants authority only through exception | Current missing-target diagnostics/search continuation; exception target mismatch refuses whole launch | Existing target rechecks and actual compiled floor; R1 executable/script pins verified on descriptors; modules remain stated limit |
| TARGET-OBSERVATION | U/S compiler rule targets and compiler literal metadata | Contract bytes decide authority; observed filesystem/DNS/topology supplies facts, not authority | Existing per-rule missing-target diagnostic/refusal or observation semantics | Retaken where current product retakes; source-change refusal does not apply to target changes alone |
| HARNESS | U/S harness preparation and loaded user-program config | Compiled contract/harness choice; generated runtime objects and loaded user config do not select S policy | Existing required harness/config/runtime checks; no fabricated exception on miss | Generated objects meet constraints; entry pin does not cover downstream modules/config; R1 environment remains closed |
| RECORD-LOCATION | U/S ledger/anchor/runtime placement | Existing configured record destination and validated account placement, no new policy authority | Existing secure/root HOME fallback rules or output/refusal | Existing placement checks and compiled record requirements; generated records are not source manifest policy |
| RECORD-FACT | U/S identity/record metadata | Observed process fact or fixed record field/variable name, never exception authority | Missing optional metadata remains absent under existing rules | Record facts honestly; do not compare observation to source policy bytes |
| PLATFORM | U/S platform/proc implementation and literal protocol data | Existing syscall/descriptor/credential protocol; literals grant no policy authority | Existing operation's error/refusal; unknown facts do not imply trust | Existing descriptor/credential checks; any prepared mechanism meets compiled floor |
| TEST-HELPER | Test helper package only, imported by tests or tagged protection code | Test fixture/protection input; no production policy or launch authority | Missing input cannot grant production authority; helper-specific isolation/error rules apply | No production caller; fixture/protection observations use their existing checks |
| TEST | Tagged test variant only | Test control/isolation, never production authority | Hook-specific unset/default and secure-exec suppression | Production exclusion; no general production selector |

#### How the inventory test finds changes

The private-source `TestGeneralInputInventory` parses every non-test Go source file, including currently inactive build variants, recursively below `cmd/{tego,tego-control,maze}`, `internal/{cli,control,contractsrc,contracts,profilesrc,registry,runtime,adapters,platform,doctor,nextrun,setup,selftest,guide,handoff,maze,realtego,rulefile}`, `pkg/policy/execmatch`, and `pkg/spec/{agent,config,presets,identity}`. It does not use a list of current filenames. It enumerates full environment-read expressions, selector aliases, recognizable environment-name literals, literal flag registrations and their defaults, positional argument accesses, named defaults/locations, path literals, path construction/search and identity APIs, and explicit absence sentinels. The row key contains the relative source file, function or method, kind and formatted expression; repeated identical expressions within one function have separate rows with an occurrence suffix. Each row must have all treatment columns and match its reviewed treatment code. Removed sites leave stale rows and fail too.

The test also checks one normalized source/AST SHA-256 per non-test file, including comments and build constraints. This is deliberately conservative: any change through an unknown API, new function, new file, new nested package, changed search ordering, changed trust branch or renamed environment helper invalidates its reviewed surface even when no recognizer identifies a new row. The digest is a demand to review every input in that file, not a claim that the test understands its semantics. `TestGeneralInputInventoryDetectsAddedInputs` checks distinct environment reads, new flags/default paths, explicit absence, inactive variants, nested packages, excluded tests, and an unknown API that changes the surface digest.

The recognizers are syntactic. They do not determine runtime reachability, ownership, credential transitions, data flow, semantic authority or implicit reads performed by the Go runtime, libc/NSS, the dynamic loader, the kernel, embedded YAML programs, shell code, generated binaries, or external modules. Standard-library implicit HOME/XDG/TMPDIR behavior, their concrete display/scratch roles, and libc/NSS are called out in the primary table. Non-Go source and third-party dependency changes need separate review. A new package outside these namespaces is not traversed merely because it exists; a changed importing file inside the namespaces invalidates its surface and requires expanding scope if the new dependency locates policy or starts a run. An already imported out-of-scope dependency can change without this test detecting it. The inventory therefore guards the listed package surfaces; it is not a proof of all possible transitive external input. R2 ownership and end-to-end launch tests remain slice-2 work.

*Amended 2026-11-17 (integration pass 9):* The public command/layout decision archives Maze;
only `cmd/tego` and `cmd/tego-control` are active production roots. Its new selector
assertions are preserved in the archived Maze tree. The source inventory below and the
four production architecture/tag certificates are recertified for the combined tree,
including grouped commands, bounded filesystem helpers and the current owner checks.
The inventory still checks every non-test source, including inactive variants, in
its active namespaces; missing active roots and any unreviewed input still fail.
The earlier claim that a whole-home governed writer can change Tego's own user policy
is withdrawn for ordinary content writes: the built-in write floor refuses them,
as corrected by the ADR 0145 guest disclosure. Same-user programs outside a run and
metadata, alias, inherited-descriptor and external-service limits remain separate.
Fixed general-source placement reads are synchronous; graph cancellation does not
interrupt an already blocked filesystem syscall. Existing recorded-contract checks
retain their bounded helper transport. No general launch is enabled.

### Input review, 2026-11-18: scope rehearsal and WSL refusals

The scope environment inputs moved to the common entry helper without becoming authority to move. The new
`--no-scope` flags suppress a diagnostic helper only. Fixed `/proc/1/cgroup` content is a fail-closed entry
precondition; fixed `/proc/self/ns/pid` is a fail-closed root-tier availability precondition. Neither comes from
contract text or environment. Delegated-tree inputs moved to the shared D3 check; rehearsal does not skip them.
The four WSL server names extend the immutable refusal inventory through its existing target observation and
identity machinery. `WSL_INTEROP` is removed from the final enforcing environment; its absence grants no authority.
All pre-existing input rows in the changed surfaces retain their treatment. The general-contract comparison and
price inventories gain no new resolution source or commercial authority from these engine changes.

### Input review, 2026-11-18: WSL readiness warnings

The existing D1 kernel-release value chooses WSL diagnostic wording only. It grants no admission or peer authority.
The four pending containment rows prevent a readiness verdict and a green stored setup check, while the measured
kernel capability tier remains available for diagnosis. No new environment, file, contract or resolution input is added.

Input review, 2026-11-18: the PID-namespace pin diagnostic captures the existing `AutoTiers` result once per
compile route and rewrites only its misleading missing-build warning. Every pre-existing input row in
`internal/cli/compile.go` and `internal/cli/run.go` retains its source and treatment. No input or probe was added.
