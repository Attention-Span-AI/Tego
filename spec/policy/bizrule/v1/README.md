<!-- SPDX-License-Identifier: Apache-2.0 -->

# Business rule specification v1

Frozen 2026-11-12 by [ADR 0151](../../../../docs/adr/0151-business-rules.md).
This is a specification, not an implemented feature. README, WIRE, ADAPTER and
`schema.json` define v1. Numbered sentences are requirements and coverage units.
Each cites an authority or an explicit design decision. Fixture expectations
were authored from these sentences, not obtained from an evaluator.

## Scope and composition

**B001.** Evaluation MUST be a deterministic function of immutable bundle,
request bytes and supplied state, with no clock, environment, file, network,
randomness, callbacks or language model. Source: ADR 0151 decision 1.

**B002.** A business answer MUST be allow, ask, deny or none; none MUST mean no
applicable action selector and MUST NOT mean permission. Source: ADR 0151 decisions 1, 3.

**B003.** Final composition MUST use deny stricter than ask stricter than allow;
none contributes no restriction, and unknown contract verdict MUST act as deny.
The 32-cell table in ADR 0151 is normative. Source: ADR 0007; ADR 0151 decision 3.

**B004.** Contract verdict MUST include installed restrictions and the effective
MCP rule, using authorized live precedence from mcptool, not an intersection with
the original MCP lists. A live allow MUST NOT remove a business restriction.
Source: mcptool.Decide; ADR 0126; ADR 0151 decision 3.

**B005.** For equal restrictive verdicts the final source MUST be contract; for
business none it MUST be contract; otherwise the stricter layer MUST be named.
Allow/allow MUST name business. Source: decision for stable diagnostics, ADR 0151 decision 3.

**B006.** A missing required evaluator MUST refuse launch with 125. Runtime
missing, crashed, timed_out or nonsense MUST produce business deny with
`evaluator.<status>`, rule `$evaluator`, before interpreting call facts.
Source: ADR 0151 decision 3; explicit error precedence decision.

**B007.** A required layer's queue_full, late_reply, wrong_binding, extra_reply,
restarted or record_failed status MUST also deny as `evaluator.<status>`.
These statuses are wrapper fault inputs to the fixture seam, not observations
made by a pure evaluator. Source: ADR 0151 decisions 3, 4.

**B008.** An unproven topology MUST yield deny, `$topology`, `topology.unproven`,
without usable facts; unsupported rule configuration MUST refuse launch.
Source: ADR 0151 decision 2; ADAPTER topology requirements.

## Bundles

**B009.** A contract requiring v1 MUST carry the canonical bundle bytes or an
immutable content-addressed object plus its SHA-256 digest, and MUST bind the
digest in its own contract hash. Missing bytes MUST refuse launch, never use a
latest bundle. Source: ADR 0151 decisions 1, 3; W003.

**B010.** A bundle MUST have version 1, adapter `square.refund.v1`, exact server
label and an ordered rules array. Its complete shape MUST satisfy schema.json.
Unknown version, fields, kinds, duplicate IDs or noncanonical bytes MUST deny
as `$bundle`, `bundle.invalid`. Source: explicit closed vocabulary decision.

**B011.** Rule IDs MUST be unique ASCII labels and rules MUST sort strictly by
ID byte order. Currency arrays MUST be nonempty, unique and byte-sorted. Bundle
semantics MUST NOT depend on map order. Source: explicit canonical ordering decision.

**B012.** Hashing MUST cover the canonical bytes, not YAML, parsed equivalence,
filename, tool discovery response or a mutable reference. A valid but substituted
bundle MUST deny as `$bundle`, `bundle.digest`. Source: ADR 0151; W003.

**B013.** One bundle MUST remain pinned for the run; editing, weakening, removing
or changing its adapter MUST require a new run. Unknown or omitted required
bundle support MUST refuse compilation/launch. Source: ADR 0151 decision 3.

## Supplied action and money

**B014.** The request MUST carry exact untrusted MCP message bytes as lowercase
hex; the adapter MUST derive facts only from the declared exact paths and MUST
bind the bytes and server identity to the result. Source: ADR 0151 decisions 1, 2; A004.

**B015.** Before extracting facts, a parser MUST reject malformed JSON, non-UTF-8,
BOM, lone surrogate escapes, trailing values or bytes, duplicate keys at every
depth (including equal decoded escaped names), and nesting deeper than 16.
It MUST NOT use last-key-wins or Unicode replacement. Source: RFC 8259 sections 4,
8, 9; explicit strict profile decision, ADR 0151 decision 5.

**B016.** JSON number tokens MUST use `0` or optional minus then a nonzero digit
followed by digits; negative zero, fraction, plus, leading zero and exponent
notation MUST refuse, even if mathematically integral. Source: explicit canonical
integer decision; JSON grammar is further restricted by v1.

**B017.** All object keys MUST be literal, unescaped lowercase ASCII, matching
`[a-z][a-z0-9_]*`, with the exact names defined by the profile.
Unknown fields MUST refuse at their A019/A020/A005 boundary; case aliases and
escaped keys MUST refuse globally. Repeated amount
fields anywhere and amount-like fields outside the declared path MUST NOT be
searched, ignored or merged. Source: ADR 0151 decision 5; A005.

**B018.** A missing, null, string, boolean, array, nested object or wrongly typed
amount/currency MUST refuse, never use a default or coerce. Source: ADR 0151 decision 5.

**B019.** Internal money MUST be canonical nonnegative signed-64 decimal text in
minor units, range 0 through 9223372036854775807, never a float. Arithmetic MUST
check before addition. The narrower adapter range in A006 precedes predicates.
Source: explicit exact integer and overflow decision.

**B020.** Currency MUST be an exact code in this closed table; exponents MUST be
the table's own values and MUST NOT come from the caller, locale or a live lookup.
No conversion or netting across currencies is permitted. Source: explicit v1
subset decision; ISO 4217 denominations, Square monetary-amount documentation.

| Code | Exponent | Meaning of 1000 minor units |
|---|---|---|
| CAD | 2 | CAD 10.00 |
| JPY | 0 | JPY 1000 |
| KWD | 3 | KWD 1.000 |
| USD | 2 | USD 10.00 |

This table specifies representation, not that Square supports refunds for every
seller in these currencies. Remote eligibility remains the server's decision.
[Square money](https://developer.squareup.com/docs/build-basics/working-with-monetary-amounts), read 2026-11-12.

**B021.** Safe facts MUST consist only of amount_minor, currency, exponent and
source `submitted-call`. They MUST describe the submitted request, not payment
eligibility, account currency, a customer identity or a successful effect.
Source: ADR 0151 decisions 1, 4; W013.

**B022.** After bundle/status/topology/adapter checks, a different trusted request
server MUST return none without inspecting its call bytes. On the selected server,
a valid canonical non-batch A019 envelope naming a different tool MUST return
none, without applying dispatch or refund payload shapes. Malformed selected-server
calls MUST refuse before tool selection. None MUST
have rule ID empty, condition `not_applicable`, no facts or reservation; C alone
then decides. An equivalent tool MUST NOT inherit this rule by guessed business
meaning. Source: ADR 0151 decision 5; explicit scope-gate precedence decision.

**B023.** On the selected server's generic `make_api_request`, any dispatch other
than exact refunds/payment MUST refuse as `adapter.dispatch`, not none, because
aliases and other operations can spend money. Source: explicit narrow adapter decision, A003.

**B024.** Any top-level batch on the rule-bearing server MUST deny as
`adapter.batch` without evaluating or delivering any member, including mixed or
apparently harmless batches. Source: ADR 0151 decision 5.

## Rule kinds and ordering

**B025.** A per_call rule MUST pass for amount <= limit and deny above it as
`per_call.exceeded`, applying only to its exact currency. Limits MUST be within
B019's range. Source: explicit inclusive cap decision; owner's refund example.

**B026.** A currencies rule MUST pass only for a code in its list and otherwise
deny as `currencies.not_listed`. Unknown currency codes MUST already have failed
adapter validation. Source: explicit closed currency allow-list decision.

**B027.** A threshold rule MUST pass for amount <= ask_above, ask for
ask_above < amount <= deny_above as `threshold.ask`, and deny above deny_above
as `threshold.deny`; configuration MUST require ask_above < deny_above.
Source: owner's approval example; explicit inclusive boundaries decision.

**B028.** A per_run rule MUST compare the current total plus this submitted amount
to its inclusive limit in the same currency, denying above it as
`per_run.exceeded` and arithmetic overflow as `per_run.overflow`.
Source: explicit split-call answer, ADR 0151 decision 4.

**B029.** All matching rules MUST contribute restrictions, with deny dominating
ask; among equal business restrictions choose the first ID in bundle order.
When all pass choose the first matching rule and condition `satisfied`. If
no rule applies to the currency, choose allow, empty ID, `satisfied`.
Source: explicit deterministic attribution decision; ADR 0007.

**B030.** A rule with a different currency MUST contribute no restriction or
conversion; authors requiring complete caps MUST list caps for every admitted
currency. Empty rules MUST be invalid; missing currency caps MUST be visible
in the compiled preview. Source: explicit v1 scope decision.

**B031.** Failure before predicates MUST return business deny with no partial
safe facts or reservation. Once fact validation succeeds, predicate failures
MUST retain the complete safe facts. Source: explicit privacy and diagnostic decision.

## State, retries and concurrency

**B032.** The host relay's durable run owner, outside the agent and evaluator,
MUST own one serialized state across all connections for (run, bundle digest,
server, epoch). Pure evaluation MUST only propose a reservation. Source: ADR 0151 decision 4.

**B033.** Every covered request MUST supply a ready, correctly scoped state
snapshot, even without a per_run rule, to check local idempotency reuse. A missing,
lost, unavailable or differently scoped snapshot MUST deny as `state.unavailable`
or `state.binding`; no implicit zero or fresh epoch is allowed mid-run.
Source: explicit replay/state decision; ADR 0151 decision 4.

**B034.** A fresh run MUST create a new epoch and explicit zero totals before
admission; missing currency in a ready totals list MUST mean zero. Totals MUST
sort by currency and contain no duplicate, negative or overflowing values.
Invalid state MUST deny as `state.invalid`. Source: explicit state representation decision.

**B035.** The SHA-256 of the admitted idempotency_key bytes MUST be checked
against the state's sorted unique seen_keys. Reuse MUST deny as `state.replay`,
even if the call digest or amount differs. Raw keys MUST NOT be recorded.
Source: explicit conservative local retry decision; ADR 0151 decision 4.

**B036.** A reservation MUST be proposed only for final allow with at least one
matching per_run rule, once per currency rather than once per rule. It MUST
include before, amount, after, state revision, currency and key digest.
Source: explicit pure-result/state-commit separation decision.

**B037.** Before delivery the owner MUST atomically recheck state revision and
all restrictions, persist decision intent, seen key and any reservation durably,
then advance the revision. Conflict MUST require reevaluation on current state,
never send with the stale proposal. Persistence uncertainty MUST deny and block
this route for the run. Source: ADR 0151 decision 4; explicit serialization decision.

**B038.** Denied and pending calls MUST spend no budget. Approval MUST reevaluate
against current state and compose all current restrictions before reserving.
Approval of one split call MUST NOT reserve room for another. Source: ADR 0151 decisions 3, 4.

**B039.** Once durable intent exists, a reservation MUST NOT be released on local
send failure, missing reply or remote error; counts describe admitted submissions.
No automatic resend is permitted. Source: conservative accounting decision, ADR 0151 decision 4.

**B040.** Restarting an evaluator MUST NOT reset totals, replay state or requests.
Uncertain state recovery MUST block further affected calls until a new run.
Run IDs/epochs MUST NOT be reused to present a reset as continuity.
Source: ADR 0151 decisions 3, 4.

**B041.** A request ID MUST never be reused on a session; a duplicate, late,
wrong-run, wrong-call or wrong-bundle result MUST refuse and poison that session.
The remote API's idempotency behavior MUST NOT be advertised as Tego exactly-once
delivery. Source: ADR 0151 decisions 3, 4; W018.

**B062.** Before constructing any request, the durable owner MUST authenticate
state provenance and compare its epoch with the independently retained expected
epoch for the admitted run/bundle/server. A mismatch or unprovable continuity
MUST block the route without invoking evaluation. The evaluator MUST validate
the epoch's syntax only; its request contains no independent expected epoch,
so it MUST NOT claim to establish epoch continuity or detect a well-formed reset.
Source: explicit trust-boundary clarification of B032/B040; freeze review 3.

**B064.** State validation MUST use this order: null state yields
`state.unavailable`; otherwise any well-formed run_id/server/bundle_digest
binding unequal to the request yields `state.binding`; then a literal status
lost or unavailable yields `state.unavailable`; then every remaining W007 shape,
type, enum, label, range, ordering or uniqueness defect yields `state.invalid`;
then key reuse yields `state.replay`; then revision/key-count exhaustion yields
`state.capacity`. A missing/malformed binding field within a state object MUST
be a shape defect, never compared by coercion; a scalar/array state MUST have
already failed the outer W007 type check. All these failures MUST discard
facts. No epoch equality check is possible inside evaluation (B062).
Source: explicit deterministic state-error clarification; freeze review 5.

## Approval, evidence and limits

**B042.** Ask MUST block delivery until an authenticated person's single-use
answer matches the exact immutable call and all bindings listed in ADR 0151.
No broker, timeout, denial, disconnect, stale authority or replay MUST mean yes.
Source: ADR 0151 decision 3.

**B043.** A person MUST satisfy only the pending ask, never a denial or new
kernel grant. Current state and the complete effective restrictions MUST be
recomposed after a hold; changed call/policy/authority bindings MUST invalidate
the answer. Source: ADR 0007; ADR 0151 decision 3.

**B044.** A business record MUST retain the exact result bindings, deciding
rule/condition, safe facts, effective-rule revision/source, topology, state
epoch/revision, reservation and any approval principal/bindings; raw arguments,
payment IDs, keys and secrets MUST NOT be copied. Source: ADR 0151 decision 4.

**B045.** A new record minor and shape validation MUST precede emitting new
business fields. An asynchronous best-effort emit MUST NOT substitute for
acknowledged durable business admission intent. Source: ADR 0151 decision 4.

**B046.** Intent write failure MUST refuse before delivery. An outcome write
failure after delivery MUST block more affected calls and retain unknown remote
outcome/coverage; inability to record a denial MUST mark coverage unknown.
Source: explicit fail-closed recording decision, ADR 0151 decision 4.

**B047.** Evidence MUST distinguish evaluated, reserved, attempted, locally
accepted write, failed/uncertain delivery and server-reported success/error.
Neither allow nor a local write MUST be called successful refund execution.
Source: ADR 0151 decision 4; stdio.go's existing event-before-write behavior.

**B048.** Receipt and dashboard MUST share one projection of recorded facts,
include scope/revisions/conditions/reservations/uncertainty, and MUST NOT invent
a count of unobserved calls or interpret no record as no action. Source: ADR 0151 decision 4.

**B049.** Bounds in WIRE MUST be inclusive where stated; above-bound requests,
fields, depth, counters or queues MUST refuse without truncation or fallback.
Source: explicit bounded resource decision, W016 through W019.

**B050.** A schema identifier or matching tools/list schema MUST NOT alone attest
server behavior; implementation, dependencies, configuration and schema MUST be
pinned and updates require a reviewed adapter/new run. Source: ADR 0151 decision 5.

**B051.** The pure result's record projection MUST say stage evaluated, delivery
not_attempted and remote_outcome unknown; later delivery observations belong to
separate append-only records, never retrospective mutation of the answer.
Source: explicit seam design decision; ADR 0151 decision 4.

**B052.** Coverage MUST be `mediated` for a selected, validated fact result,
`none` for none, and `unknown` for failures before facts. It MUST describe this
observation only, not certify topology or completeness of a whole run.
Source: explicit coverage vocabulary decision, ADR 0151 decision 4.

**B053.** Fault/error precedence MUST be: envelope grammar/limits, bundle
grammar/limits, bundle digest, evaluator status, topology, request adapter match,
trusted server scope gate, call byte limits/JSON grammar, batch, A019
envelope/selector, A020 dispatch shape, dispatch values, A005 payload
shape/ranges, B064 state validation, predicates,
composition. Within call parsing, byte bound precedes complete JSON/UTF-8/
surrogate grammar, then depth/member limits, then all decoded-key duplicates,
then canonical spelling. An escaped duplicate key MUST be input.duplicate,
even though its escape also violates canonical spelling. Malformed full JSON
MUST precede a duplicate earlier in its prefix. Within each dispatch-shape or
payload stage use
missing before unknown before type before leaf-byte bounds before range; ties
use byte-sorted field paths. Source: explicit deterministic error decision.

**B054.** Grammar errors MUST be `input.json`, noncanonical token/key/string
errors `input.canonical`, duplicate decoded keys `input.duplicate`, limit errors
`input.limit`, envelope errors `adapter.envelope`, selected-field missing/unknown/
type/range errors `adapter.missing`, `adapter.unknown`, `adapter.type`,
`adapter.range`. Adapter failures MUST name `$adapter`. Source: explicit diagnostic enum decision.

**B055.** Invalid request envelopes MUST produce a local refusal with no evaluator
answer; no malformed answer may be treated as allow. The fixture wrapper's
expected local refusal MUST use business deny `$wire`, `wire.invalid` and final
deny source wire, with no facts/reservation. Source: explicit local-error fixture decision.

**B056.** A request adapter different from the bundle MUST deny as `$adapter`,
`adapter.revision`; a selected call on a different server MUST be none, not
reinterpretation under the named server. Source: explicit binding/scope decision.

**B057.** With 4096 admitted keys already present or an exhausted uint64 state
revision, an affected call MUST deny as `state.capacity`; no eviction or wrap
is permitted.
Source: explicit bounded replay accounting decision.

**B058.** Denial MUST remain possible when a helper fails; shutdown/cancellation
MUST cancel held calls, close channels and retain durable state. No already-sent
action can be undone by shutdown. Source: ADR 0151 decisions 3, 4; W018.

**B059.** Changing meaning, default, field, limit, currency exponent or canonical
form MUST allocate a new spec version; editorial corrections MUST retain IDs
and be logged in CHANGES.md. Source: explicit freeze/versioning decision.

**B060.** Fixture checking MUST validate every complete fixture against schema.json
plus coverage inventory and W002 string byte examples, without calculating
predicates, reservations or composition answers. Semantic
qualification MUST separately run an implementation against the handwritten
expectations and independent server/kernel witnesses. Source: ADR 0151 acceptance;
explicit distinction between form and behavior.

**B061.** On business ask the result MUST list every matching business ask in
bundle order as `{condition,rule_id}`, not only the deciding rule; other business
verdicts MUST have an empty asks array. Approval MUST bind that complete set and
the effective contract ask identity. The external completion wrapper MUST retain
the original held call/request/approval context, obtain fresh evaluation with a
new request ID and current state, refuse any denial/error or changed binding/ask
set, then discharge only the complete approved ask set before final recomposition
and atomic reservation. The pure evaluator MUST continue returning ask and MUST
NOT consume a human answer. Current state/revision and the fresh evaluation ID
may differ from the original approval context; call, bundle, adapter, effective
restriction revision and approving authority may not. After discharge and final
allow, the durable owner MUST build/commit a B036-shaped reservation from fresh
validated facts/state if a per_run rule applies; every such predicate must have
passed in the fresh evaluation. This checked bookkeeping MUST NOT reinterpret
or override any predicate. Source: explicit complete
ask-set/completion decision, ADR 0151 decision 3; independent specification review.

## Implementation agreement

**B063.** The Go live evaluator MUST execute inside the relay process with no
second process on the request path. An independent Rust evaluator MUST also
serve the browser preview for the contract builder's business switches and a
standalone checker. Both MUST pass every vector; disagreement on any input MUST
fail the build. Preview MUST confer no delivery authority. Source: ADR 0151
decision 6, implementation language decision taken in fix round 1.
