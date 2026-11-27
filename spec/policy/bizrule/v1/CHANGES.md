<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changes

2026-11-12: initial v1 freeze under ADR 0151 had 104 requirements and 160
handwritten vectors. No evaluator or runtime integration exists.

## Fix round 1, 2026-11-12

This is the pre-implementation review correction to v1, before either evaluator
is written. IDs are stable. New IDs are B062 through B064, W026 through W028,
and A019/A020 at the end of their interface section. There are now 112
requirements and 218 vectors. Existing 160 vectors and schema are unchanged.

Finding 1 closes envelope, dispatch-shape, dispatch-value and payload boundaries.
Finding 2's escaping allegation is disputed: W002 already had the correct literal
escapes at 4eb963fe6; exact hex examples and string vectors are added.
Finding 3 names owner-authenticated expected epochs and the evaluator's limit.
Finding 4 defers approval digest bytes explicitly outside the frozen contract.
Finding 5 adds interaction/real-dispatch/outer-wire diagnostic cases.
The implementer pass also clarifies ASCII/number spelling, nested state errors,
LF framing, syntactic member counts, replay capacity and queue transitions;
A005's four leaves plus required container corrects its earlier five-leaf wording.
The language decision is now Go live in process and independent Rust for browser
preview and standalone checking; both must pass all vectors and any disagreement
on any input must fail the build. These implementations remain unbuilt.

The replacement paragraphs below list verbatim every added or changed sentence
in the specification documents, including inventory prose and acceptance cases.
Unchanged sentences in a replaced paragraph are repeated for context. Link targets
are rebased to this directory; sentence text is unchanged. Changed
inventory table rows are listed separately. The ADR replacements are also listed below. GAPS, debt and Unreleased
sentences are recorded in the following status-documentation commit.

### README.md

**B017.** All object keys MUST be literal, unescaped lowercase ASCII, matching
`[a-z][a-z0-9_]*`, with the exact names defined by the profile.
Unknown fields MUST refuse at their A019/A020/A005 boundary; case aliases and
escaped keys MUST refuse globally. Repeated amount
fields anywhere and amount-like fields outside the declared path MUST NOT be
searched, ignored or merged. Source: ADR 0151 decision 5; A005.

**B022.** After bundle/status/topology/adapter checks, a different trusted request
server MUST return none without inspecting its call bytes. On the selected server,
a valid canonical non-batch A019 envelope naming a different tool MUST return
none, without applying dispatch or refund payload shapes. Malformed selected-server
calls MUST refuse before tool selection. None MUST
have rule ID empty, condition `not_applicable`, no facts or reservation; C alone
then decides. An equivalent tool MUST NOT inherit this rule by guessed business
meaning. Source: ADR 0151 decision 5; explicit scope-gate precedence decision.

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

**B057.** With 4096 admitted keys already present or an exhausted uint64 state
revision, an affected call MUST deny as `state.capacity`; no eviction or wrap
is permitted.
Source: explicit bounded replay accounting decision.

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


### WIRE.md

**W002.** Canonical strings MUST decode only to ASCII U+0020 through U+007E,
contain those characters literally, escape quote and backslash only as `\"` and `\\`,
and MUST NOT use alternate escapes. Bundle,
wire labels and the admitted call profile contain only bounded ASCII. Arbitrary
byte fields MUST be lowercase even-length hex, with empty bytes `""`. A malformed
UTF-8 call MUST remain representable without replacement through call_hex.
The following complete JSON string bytes MUST decode to the indicated value
bytes; hex has no framing LF:

| Value | JSON hex | Decoded value hex |
|---|---|---|
| quote | 225c2222 | 22 |
| backslash | 225c5c22 | 5c |

**W003.** Bundle digest MUST be lowercase SHA-256 of W001 canonical bundle bytes,
without a domain prefix or LF. Call digest MUST be lowercase SHA-256 of decoded
call_hex bytes, including invalid bytes for a refusal. The future request digest
for human approval MUST bind the entire canonical request and all external approval
bindings; its preimage/framing is outside this frozen byte contract (W026).
It MUST NOT be substituted for the call or bundle digest.
The stdio transport's single framing LF MUST be outside the call digest; the
same canonical content bytes MUST be sent with that framing after admission.

**W007.** At the outer request stage state MUST be present and null or an object;
other types MUST be wire.invalid. A state object MUST have bundle_digest, epoch,
revision, run_id, seen_keys, server, status, totals. Status MUST be ready/lost/unavailable;
revision MUST be canonical uint64 decimal text including zero. Totals MUST be
objects `{currency,minor}` in code order; minor MUST meet B019. Seen keys MUST
be sorted unique lowercase SHA-256 digests. Bindings MUST equal the request's.
Canonically spelled nested state shape/type/range/unknown-field failures MUST
be deferred to B064 and yield state.invalid only if its shape-validation step
is reached. Only outer
request field/type/enum/version errors are wire.invalid. B016 integer-token
spelling and W001/W002 canonical spelling MUST apply throughout bundle and
request JSON, even to otherwise invalid nested fields. Full-request lexical,
canonical, grammar, request-frame byte bounds, syntactic member/depth bounds
and framing errors at any nesting, including state, MUST be wire.invalid before
evaluator status. Canonically spelled nested state shape/type/enum/range and
state-specific label/array/numeric bounds MUST remain deferred to B064.

**W016.** Bundle bytes MUST be <=32768, call bytes <=65536, canonical request
frame including LF <=524288 and response frame including LF <=8192; a request
above its frame bound MUST be a local wire refusal. Each object MUST have <=64
syntactic key/value pairs counted before duplicate folding, rules <=32,
currencies <=4, labels <=64 bytes, idempotency_key <=45 bytes, payment_id <=192
bytes and nesting <=16 containers (root depth 1).
Bounds MUST be checked before unbounded allocation. Above bounds MUST deny
as input.limit or bundle.invalid at the appropriate precedence stage.

**W017.** The host relay MUST have <=1 outstanding evaluation
per run, <=16 waiting calls per run, <=16 active runs and <=64 total queued calls
per host. Saturation MUST refuse queue_full. The host scheduler MUST arbitrate
these limits atomically; extra connections or workers MUST NOT evade aggregate
limits. The live evaluator MUST remain in process under B063.

**W018.** The host wrapper MUST bound evaluation to 1000 ms using a host
monotonic clock outside the pure evaluator. A standalone process wrapper MUST
include request write and reply read in that 1000 ms bound and limit shutdown
plus EOF drain to 2000 ms; it MUST NOT be placed on the live request path.
No extra stdout byte, duplicate reply, wrong binding,
late reply, nonzero exit or restart on an existing session is allowed. A poisoned
session MUST refuse pending work and require a newly admitted session with
unchanged durable run state, not automatically retry an old request.

**W021.** Null bundle_wire_hex MUST mean canonical bundle bytes without LF; null
request_wire_hex MUST mean canonical request bytes followed by exactly one LF.
Non-null bundle_wire_hex or request_wire_hex MUST replace those respective bytes
exactly, to represent malformed inputs without making the fixture itself invalid
JSON. Malformed call bytes MUST use request.call_hex, including duplicate keys,
invalid UTF-8, batches and trailing bytes. Expected MUST always be a full result.

**W025.** Asks MUST be an ordered array of `{condition:"threshold.ask",rule_id}`
for every matching business ask when the business verdict is ask, and [] otherwise.
The original request digest in W003 MUST bind the original held approval context;
completion MUST retain it separately from the new evaluation request's digest.
The result describes initial evaluation, not approval completion. A later approval
wire protocol MUST implement B061 without using a fresh-state digest mismatch to
invalidate an otherwise unchanged original context, or using that exception to
permit changed call, policy, authority or ask-set bindings.

**W026.** The approval request digest's object, field types, preimage ordering,
domain separation and framing MUST be specified by a later approval protocol
with known digests before approval is enabled. No v1 consumer MUST infer a
byte-compatible approval digest from W003 or add it to the closed W005 request.
This deferral MUST NOT weaken B042/B061 binding and single-use requirements.
Source: explicit frozen-contract boundary; freeze review 4.

**W027.** A request_wire_hex override MUST contain exactly one canonical request
object followed by exactly one LF byte (0a); missing LF, CRLF, doubled LF or
trailing bytes MUST be wire.invalid. Bundle and call bytes MUST contain no
framing LF. The Go in-process seam MUST apply the same wire validation to fixture
requests without starting a helper; standalone transports MUST use these bytes.
Source: explicit fixture-framing clarification of W001/W021.

**W028.** Queue counters MUST count each call once: waiting calls include
human-held and queued-for-evaluation calls but exclude the one outstanding
evaluation; total queued is the sum of waiting calls across runs. Active runs
MUST count runs with any waiting or outstanding call, not idle admitted runs.
W017 bounds MUST be checked atomically before accepting work; a hold MUST retain
its waiting slot. Transition from outstanding evaluation to a human hold MUST
atomically acquire a waiting slot or refuse queue_full without retaining a hold.
Source: explicit wrapper-counter clarification of W017/W019.


### ADAPTER.md

**A004.** The admitted MCP envelope MUST satisfy A019 before selecting a tool.
For `make_api_request`, dispatch arguments MUST satisfy A020 before selecting
the refund payload in A005. The amount path MUST be
`/params/arguments/request/amount_money/amount`, currency path
`/params/arguments/request/amount_money/currency`. Source: explicit staged
adapter decision; pinned registration and handler.

**A005.** The admitted request object MUST be exactly `{amount_money,
idempotency_key,payment_id}` and amount_money exactly `{amount,currency}`.
All four leaves and the amount_money object MUST be present.
Unknown/nested/repeated/alternative money fields MUST refuse. Omitting payment_id MUST NOT enable an unlinked refund.
Source: explicit linked-refund-only decision, ADR 0151 decision 5.

**A019.** The envelope stage MUST accept exactly a root object with fields
`{id,jsonrpc,method,params}`, jsonrpc string `"2.0"`, id a positive integer token
<=9007199254740991, method string `"tools/call"`, and params an object with
exactly `{arguments,name}`. Name MUST be a W005 label string; arguments MUST be
an object. Missing, unknown, wrongly typed or out-of-range fields in this stage
MUST yield `adapter.envelope`. This stage MUST NOT validate the fields inside
arguments. After global call grammar, limits and canonical checks and this
stage, any name other than `make_api_request` MUST yield none, regardless of
its arguments' shape beyond being an object. Source: explicit validation-boundary
decision resolving freeze review 1.

**A020.** On `make_api_request`, the dispatch-shape stage MUST require exactly
`{method,request,service}` inside arguments, with method and service strings and
request an object. Missing, unknown or wrongly typed fields at this boundary
MUST yield `adapter.missing`, `adapter.unknown` or `adapter.type` respectively.
Only after this shape passes MUST service/method values be compared with A003;
any other value MUST yield `adapter.dispatch` before inspecting the request's
contents. The payload stage MUST then validate only request and its descendants
against A005 through A007, with B053/B054 diagnostics. Missing parents MUST be
reported at the parent path; descendants of a missing or wrongly typed parent
MUST NOT create additional missing-field errors. Source: explicit validation-boundary
decision resolving freeze review 1.

### COVERAGE.md

The initial freeze had 104 requirements and 160 authored JSON cases. Fix round 1
has 112 requirements and 218 cases. The form checker validates schema shape,
unique IDs, requirement citations, this coverage inventory and the two W002 JSON
string byte examples. It does not compute predicates, compose verdicts, extract
money or execute state transitions. Behavioral answers remain handwritten and
unexecuted by any evaluator. Serialization/digest calculation is not an evaluator
oracle; negative inputs remain exact hex bytes.

The earlier freeze review and the later independent review are distinct. The
later review sampled 40 cases and found missing diagnostic boundaries and coverage.
Fix round 1 closes those written boundaries and adds cases. Neither review proves
runtime behavior. Pinned-source inspection is not server execution, schema
discovery, dependency attestation, kernel qualification or payment testing.

| Group | Cases |
|---|---:|
| bundle | 22 |
| composition | 32 |
| cumulative | 28 |
| limits | 22 |
| money | 26 |
| parser | 65 |
| scope | 23 |

The composition group retains all 32 cells in ADR 0151. New parser cases pin
root/params/dispatch/payload/money boundaries and canonical strings. Cumulative
cases pin shared-currency rules, replay without per_run, competing state errors
and the external epoch trust boundary. Scope adds real payments.create,
disputes.accept and orders.batchGet dispatch controls from the pinned source,
plus registered metadata tools. The earlier hypothetical equivalent-tool control
remains a scope example, not a claim of upstream registration. Bundle cases add
outer-field, state lexical/type and framing distinctions. Limits include member
counting before duplicate folding.

[ACCEPTANCE.md](ACCEPTANCE.md) records future integration acceptance cases,
including epoch provenance, deferred approval digest framing, queue accounting,
Go/Rust/browser agreement and guest qualification. These cases have not run.

The table is an exact citation inventory, not a claim of behavior tested. Blank
case coverage means implementation/operational acceptance is still required.
Every populated row also needs evaluator tests and relevant independent witnesses.

| Requirement | Source document | Fixture IDs |
|---|---|---|
| B003 | [README.md](README.md) | c13-contract-denial-no-reservation, s01-equivalent-tool-allowed, x01-allow-allow, x02-allow-none, x03-allow-ask, x04-allow-deny, x05-allow-missing, x06-allow-crashed, x07-allow-timed_out, x08-allow-nonsense, x09-ask-allow, x10-ask-none, x11-ask-ask, x12-ask-deny, x13-ask-missing, x14-ask-crashed, x15-ask-timed_out, x16-ask-nonsense, x17-deny-allow, x18-deny-none, x19-deny-ask, x20-deny-deny, x21-deny-missing, x22-deny-crashed, x23-deny-timed_out, x24-deny-nonsense, x25-unknown-allow, x26-unknown-none, x27-unknown-ask, x28-unknown-deny, x29-unknown-missing, x30-unknown-crashed, x31-unknown-timed_out, x32-unknown-nonsense |
| B022 | [README.md](README.md) | s01-equivalent-tool-allowed, s02-other-server-allowed, s03-other-server-malformed, s12-other-server-batch, s21-other-tool-empty-arguments, s22-other-tool-malformed-envelope, s23-other-server-over-call-bound |
| B023 | [README.md](README.md) | s07-service-alias, s08-other-method, s18-payments-create, s19-disputes-accept, s20-orders-batchget |
| B028 | [README.md](README.md) | c01-first-sixty, c02-second-sixty-refused, c03-remainder-equal, c04-full-plus-one, c11-add-overflow, c12-overflow-boundary-equal, c16-other-currency-independent, c25-two-run-rules-one-reservation, c26-second-run-rule-denies |
| B029 | [README.md](README.md) | c25-two-run-rules-one-reservation, c26-second-run-rule-denies, m23-deny-beats-ask, m24-two-denials-first-id, m25-two-asks-first-id |
| B033 | [README.md](README.md) | c06-state-lost, c07-state-unavailable, c08-missing-state, c09-other-run-state, c10-other-bundle-state, c27-replay-without-run-rule |
| B035 | [README.md](README.md) | c05-key-replay, c27-replay-without-run-rule |
| B036 | [README.md](README.md) | c01-first-sixty, c13-contract-denial-no-reservation, c25-two-run-rules-one-reservation, c26-second-run-rule-denies |
| B040 | [README.md](README.md) | c06-state-lost, c18-new-run-new-epoch, c28-epoch-continuity-external |
| B062 | [README.md](README.md) | b22-state-epoch-over-limit, c28-epoch-continuity-external |
| B064 | [README.md](README.md) | b22-state-epoch-over-limit, c19-binding-before-unavailable, c20-unavailable-before-shape, c21-shape-before-replay, c22-replay-before-capacity, c23-missing-binding, c24-wrong-binding-type, c25-two-run-rules-one-reservation, c26-second-run-rule-denies, c27-replay-without-run-rule |
| B053 | [README.md](README.md) | l22-member-bound-before-duplicate, p37-root-missing, p38-root-unknown, p39-root-type, p40-params-missing, p41-params-unknown, p42-params-type, p43-dispatch-missing, p44-dispatch-unknown, p45-dispatch-type, p46-payload-missing, p47-payload-unknown, p48-payload-type, p49-money-missing, p50-money-unknown, p51-money-type, p52-missing-service, p53-method-type, p54-dispatch-before-payload, p55-unknown-before-type, p56-type-parent-before-child, p57-missing-before-unknown, p58-null-root, p59-scalar-root, p62-alternate-quote, p63-non-ascii, p64-control-escape, p65-canonical-quote-range, s03-other-server-malformed, s12-other-server-batch, s23-other-server-over-call-bound |
| B054 | [README.md](README.md) | p37-root-missing, p38-root-unknown, p39-root-type, p40-params-missing, p41-params-unknown, p42-params-type, p43-dispatch-missing, p44-dispatch-unknown, p45-dispatch-type, p46-payload-missing, p47-payload-unknown, p48-payload-type, p49-money-missing, p50-money-unknown, p51-money-type |
| B055 | [README.md](README.md) | b11-unknown-request-field, b12-duplicate-request-field, b13-approval-digest-outside-v1, b14-state-scalar-outer-type, b15-missing-state-outer-field, b16-state-key-order-before-status, b17-state-number-spelling-before-status, b18-request-lf-present, b19-request-lf-missing, b20-request-double-lf, b21-state-integer-type-deferred, l16-wire-invalid, l17-wire-over-byte-limit |
| B063 | [README.md](README.md) | Implementation acceptance required |
| W002 | [WIRE.md](WIRE.md) | p60-canonical-quote, p61-canonical-backslash, p62-alternate-quote, p63-non-ascii, p64-control-escape, p65-canonical-quote-range |
| W007 | [WIRE.md](WIRE.md) | b11-unknown-request-field, b12-duplicate-request-field, b13-approval-digest-outside-v1, b14-state-scalar-outer-type, b15-missing-state-outer-field, b16-state-key-order-before-status, b17-state-number-spelling-before-status, b18-request-lf-present, b19-request-lf-missing, b20-request-double-lf, b21-state-integer-type-deferred, b22-state-epoch-over-limit, c19-binding-before-unavailable, c20-unavailable-before-shape, c21-shape-before-replay, c22-replay-before-capacity, c23-missing-binding, c24-wrong-binding-type |
| W016 | [WIRE.md](WIRE.md) | l07-call-at-byte-limit, l08-call-over-byte-limit, l09-payment-id-at-limit, l10-payment-id-over-limit, l11-key-at-limit, l12-key-over-limit, l15-bundle-over-byte-limit, l17-wire-over-byte-limit, l18-depth-at-limit, l19-depth-over-limit, l20-members-at-limit, l21-members-over-limit, l22-member-bound-before-duplicate |
| W026 | [WIRE.md](WIRE.md) | b11-unknown-request-field, b12-duplicate-request-field, b13-approval-digest-outside-v1, b14-state-scalar-outer-type, b15-missing-state-outer-field, b16-state-key-order-before-status, b17-state-number-spelling-before-status, b18-request-lf-present, b19-request-lf-missing, b20-request-double-lf, b21-state-integer-type-deferred |
| W027 | [WIRE.md](WIRE.md) | b11-unknown-request-field, b12-duplicate-request-field, b13-approval-digest-outside-v1, b14-state-scalar-outer-type, b15-missing-state-outer-field, b16-state-key-order-before-status, b17-state-number-spelling-before-status, b18-request-lf-present, b19-request-lf-missing, b20-request-double-lf, b21-state-integer-type-deferred |
| W028 | [WIRE.md](WIRE.md) | Implementation acceptance required |
| A003 | [ADAPTER.md](ADAPTER.md) | s07-service-alias, s18-payments-create, s19-disputes-accept, s20-orders-batchget |
| A007 | [ADAPTER.md](ADAPTER.md) | l09-payment-id-at-limit, l10-payment-id-over-limit, l11-key-at-limit, l12-key-over-limit, p62-alternate-quote, p63-non-ascii, p64-control-escape, p65-canonical-quote-range |
| A019 | [ADAPTER.md](ADAPTER.md) | p37-root-missing, p38-root-unknown, p39-root-type, p40-params-missing, p41-params-unknown, p42-params-type, p43-dispatch-missing, p44-dispatch-unknown, p45-dispatch-type, p46-payload-missing, p47-payload-unknown, p48-payload-type, p49-money-missing, p50-money-unknown, p51-money-type, p52-missing-service, p53-method-type, p54-dispatch-before-payload, p55-unknown-before-type, p56-type-parent-before-child, p57-missing-before-unknown, p58-null-root, p59-scalar-root, p60-canonical-quote, p61-canonical-backslash, s21-other-tool-empty-arguments, s22-other-tool-malformed-envelope |
| A020 | [ADAPTER.md](ADAPTER.md) | p37-root-missing, p38-root-unknown, p39-root-type, p40-params-missing, p41-params-unknown, p42-params-type, p43-dispatch-missing, p44-dispatch-unknown, p45-dispatch-type, p46-payload-missing, p47-payload-unknown, p48-payload-type, p49-money-missing, p50-money-unknown, p51-money-type, p52-missing-service, p53-method-type, p54-dispatch-before-payload, p55-unknown-before-type, p56-type-parent-before-child, p57-missing-before-unknown, p58-null-root, p59-scalar-root, s18-payments-create, s19-disputes-accept, s20-orders-batchget |

### ACCEPTANCE.md

These cases describe future integration tests. They have not run. The pure
vectors cannot establish authenticated provenance, durable continuity, queue
atomicity, human authority, kernel isolation or build integration.

| Case | Given | Required observation |
|---|---|---|
| E01 epoch substitution | The owner retains expected epoch e1 for run1 and receives the zero-total e2 snapshot in c28-epoch-continuity-external. | B062: reject before constructing a request. No evaluator call or delivery. The pure c28 answer alone is allow because it has no independent epoch witness. |
| E02 epoch recovery | Restore the authenticated e1 snapshot with current revision, totals and seen keys for the admitted run1/bundle/server. | B032/B040/B062: verify provenance and expected epoch before constructing the request; preserve totals/replay state across connections and evaluator restarts. An uncertain restore blocks the route. |
| E03 new run | Explicitly admit a new run2 with a newly authenticated e2 and zero totals. | B034/B062: permit construction of the new-run request; never label it continuity of run1. See c18-new-run-new-epoch for pure supplied state. |
| E04 approval digest | Two clients choose request-bytes concatenation and a canonical object wrapper for approval bindings. | W026: neither format is certified by v1. Approval remains disabled until a later protocol specifies exact bytes and known digests. The bundle and call digest formats in W003 remain fixed. |
| E05 waiting bound | One run has one outstanding evaluation and 15 waiting calls, including 3 human-held calls. | W017/W028: one more waiting call is admitted; the next refuses queue_full. Outstanding evaluation consumes no waiting slot. A held call keeps its waiting slot. |
| E06 host bound | Across runs there are 64 waiting calls, including holds, plus outstanding evaluations. | W017/W028: another waiting call refuses queue_full. Extra helpers cannot evade the shared count. |
| E07 active run bound | Sixteen runs have waiting/outstanding work; another admitted run is idle. | W017/W028: work for the idle run refuses queue_full until one active run has no waiting or outstanding work. Idle admission alone consumes no active-run slot. |
| E08 implementation agreement | Go live library, Rust standalone and Rust browser builds receive every vector and the same additional input corpus. | B063: compare complete results, including diagnostic choice, facts, asks, bindings, record projection and reservation. Any disagreement on any input fails the build. Go and Rust must each match every authored expected answer; agreement on a wrong answer is insufficient. The browser preview has no forwarding authority. |
| E10 hold transition | One outstanding evaluation returns ask while its run already has 16 waiting calls. | W028: refuse queue_full instead of creating a seventeenth waiting hold; no delivery or budget reservation. |
| E09 topology | Qualify the pinned worker/channel/credential boundary and every A013/A014 conjunct with harmless offline witnesses. | A018: owed in a guest. Current-base admission must refuse. No outbound payment call is required. |

For E05 through E07, counter inspection and admission happen atomically. These
are integration acceptance obligations, not timing or availability claims.


### 0151-business-rules.md

Status: accepted 2026-11-12 for specification v1. Implementation and deployment are not built by this decision.
Amends ADR 0126's design with a separate argument-rule family; preserves ADR 0007's tightening principle.
ADR 0146's live-language restriction remains in force: the live evaluator is Go in the relay process.

The review of PLAN-2 and its two draft records rejected a production language choice without a named user
requirement, an imaginary refund schema, an unpriced mediation prerequisite and optimistic delivery claims.
This ADR settles the specification and implementation languages independently of release work. It selects Go for
the live evaluator and Rust for an independent evaluator; neither implementation is built by this decision.

Select Square's public self-hosted `square-mcp-server`, revision
`b276734fe2f1e6d4990fd99c2189c5d8d280a8b8`, read 2026-11-12. The tool is `make_api_request`, with
`service: "refunds"`, `method: "payment"`. The amount is `request.amount_money.amount`, a JSON integer
in minor units, and currency is `request.amount_money.currency`. This is a real generic dispatch tool,
not an invented `issue_refund` tool. The [adapter](ADAPTER.md) lists the exact
upstream schema, every request field and the narrower admitted profile. Closed MCP-envelope, dispatch-argument
and refund-payload stages have distinct validation boundaries and diagnostics. Sources:
[registration](https://github.com/square/square-mcp-server/blob/b276734fe2f1e6d4990fd99c2189c5d8d280a8b8/server.ts),
[refund dispatch](https://github.com/square/square-mcp-server/blob/b276734fe2f1e6d4990fd99c2189c5d8d280a8b8/services/refunds.ts),
[request type inventory](https://github.com/square/square-mcp-server/blob/b276734fe2f1e6d4990fd99c2189c5d8d280a8b8/utils/type-map.ts).

The pure answer includes every matching business ask in addition to the deciding rule. One approval covers
that exact complete set plus the effective contract ask identity; no partial discharge is allowed in v1.
Completion keeps the original held approval context, evaluates again with a new evaluation ID and current
state, refuses any denial/error or changed call, policy, authority or ask set, and only then discharges the
approved ask barriers and recomposes remaining restrictions. The original request digest remains bound to
the held context; fresh state and evaluation ID are intentionally separate. The approval request digest format
is outside the frozen v1 byte contract until the separate approval protocol defines its preimage and framing.
The pure answer is never edited into an allow, and any other outstanding kernel/completion restriction remains
effective.

Cumulative means the sum of admitted submitted amounts in one currency on the named route in one run.
It is not actual refunded money, an order's remaining refundable balance or a cross-run quota. A host-side
durable run owner serializes reservations across all connections, outside the evaluator and the agent.
It authenticates the expected epoch before constructing evaluator input and binds state to run, bundle, server
and that epoch. The pure evaluator checks supplied state but cannot establish epoch continuity or detect a
well-formed substituted epoch with reset totals. The owner writes the reservation and safe decision intent durably
before attempting delivery and retains reservations even after write/remote failure. Loss or uncertain
recovery blocks this rule-bearing route for the rest of the run. A new helper does not create new state.
A new run is an explicit new budget, not continuity. See the specification for overflow, conflicts and replay.

### 6. Language decision taken

The live pure evaluator will be a Go library inside the existing relay process. No second process is on
that request path. This keeps authenticated call bytes and final composition in the relay, avoids a new live
process-admission boundary and pipe failures, and preserves ADR 0146's live-language restriction.

Rust is selected for an independent second pure evaluator, the browser preview for the contract builder's
business switches, and a standalone checker. The browser consumer and independent checker justify maintaining the
second implementation; the preview has no authority to permit or forward a call. Neither evaluator, the preview
nor the standalone checker is implemented here. No cgo, shared ABI, automatic cross-language fallback or second
live policy authority is selected.

Both evaluators must pass every frozen vector. A disagreement between them on any input fails the build.
Separate implementations must follow the specification alone, including validation stages, diagnostic precedence,
canonical bytes, checked integer arithmetic and externally authenticated state ownership. Sharing evaluator
logic would defeat the independent cross-check. Build integration must compare both evaluators before shipment;
this document does not claim that such a gate exists today.

Measure live artifact size and end-to-end request cost with the same fixtures, topology, build mode and limits.
Include dependency audit, maintainer review, release proof and operational upkeep. No measured latency or memory
claim follows from the language choice. Unbuilt central services remain subject to their own measured delivery
choices.

Independent specification, fixture review and pure evaluator work can proceed away from the security release.
Relay, durable record, topology admission, dashboard, approval, CI and export changes need later coordinated jobs.
There is no shipping schedule or performance claim here. Estimate integration after the exact supported tier
and credential isolation design are selected; price missing mediation protection separately from a comparison.
Qualification must include parser witnesses with the pinned server, concurrent reservations, bypass attempts,
state loss, recording failure, all composition cells, replay and every supported kernel/tier. Schema-valid
fixtures are not evidence of any of those runtime properties.

## Status document sentence replacements

These sentences correct the related existing status rows and Unreleased overlay.

### docs/GAPS.md

```text
| C50 | *Added 2026-11-01; code reconciliation 2026-11-12.* The MCP relay, which ships behind `--preview`, is not a security boundary against a run that may attach to its own processes. Where the tier does not refuse attach and Yama `ptrace_scope` is 0 or 1, an agent can ptrace the shim it started and write to the server without a decided or recorded `mcp` line. Agent `pidfd_getfd` imports already fail closed at enforcing tiers (`internal/runtime/supervisor/pty.go:handlePidfdGetfd`); the older general socket-copy claim was stale. The server's stdio being sockets closes `/proc` reopening, and the gate's second look closes a fake relay and a reissued pid, but neither establishes a general lifetime attach ban. The gate recognises the declared command line exactly; another spelling of the same server is not the server, and a server that opens `/dev/stdin` by name fails, since its stdin is a socket. | Set `ptrace_scope` to 2 or higher where the relay must hold against the agent, and close other spellings with `exec.deny`; these are not a qualified exclusive-route proof. ADR 0126 residuals, `docs/site/mcp-tools.md`. **→ Open, stated.** SEC06 binds each pending start to the exact child pinned before exec; same-run attach protection is still unqualified. ADR 0151 and `spec/policy/bizrule/v1/` specify closed validation stages and externally authenticated epoch continuity, with Go in the live relay and an independent Rust evaluator/preview/checker; implementation and tier qualification remain unbuilt. The code was read, not exercised; kernel/tier acceptance is **owed in a guest**. |
| C51 | ~~*Added 2026-11-01.* A child forked before its parent execs the MCP shim could consume the shim’s pending server start, running the declared server on channels the agent holds without ptrace or an `mcp` decision.~~ | Closed by SEC06, 2026-11-03: the shim starts a waiting child stage, registers its PID before release to exec, and waits for acknowledgement. The relay pins that child with a pidfd and only its matching PID with a live pidfd can consume the one start. A sibling cannot consume it; a dead child or unavailable identity fails closed. Regression tests cover an unregistered child, a preexisting child with the real admission, sibling theft, consumption and lost identity. The compatibility follow-up preserves `mcp relay *` grants with an exact-child runtime stage allowance, without a general stage pattern. C50’s attach residual remains open; enforcing-tier `pidfd_getfd` imports already refuse; see the proposed ADR 0126 amendment. |
```

### Additional status notes

```text
- GAPS C50 stays open: same-run ptrace authority over the shim/server can bypass tool decisions where attach is
  permitted. Agent `pidfd_getfd` imports already fail closed at enforcing tiers
  (`internal/runtime/supervisor/pty.go:handlePidfdGetfd`); the older general socket-copy claim was stale.
  `bpf/decide_control.h:tego_ptrace_peer` admits same-run peers, subject to the guarded-exec check, and does not
  establish a general shim/server lifetime attach ban. This is code inspection, not tier qualification; acceptance
  is **owed in a guest**. ADR 0151 and `spec/policy/bizrule/v1/` now specify closed validation stages and owner-authenticated
  epoch continuity, with Go in the live relay and an independent Rust evaluator, browser preview and standalone
  checker. Both must pass every vector and any disagreement fails the build; these implementations and their
  build gate remain unbuilt. The proposed ADR 0126 amendment retains the preview alternative and its disclosure.
```

### tools/oss/testdata/overlay/docs/CHANGELOG.md

```text
- Specify business restrictions for one pinned Square refund adapter, including closed validation stages,
  canonical bytes, owner-authenticated state epochs and handwritten expectations. ADR 0151 selects Go inside
  the live relay and an independent Rust evaluator, browser preview and standalone checker; both must pass every
  vector and disagreements must fail the build. These are specification and language decisions. No evaluator,
  preview, checker, approval protocol, build gate or qualified enforcement topology is implemented here.
```
