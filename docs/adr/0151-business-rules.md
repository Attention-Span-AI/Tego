<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR 0151: deterministic business restrictions on mediated action facts

Status: accepted 2026-11-12 for specification v1. Implementation and deployment are not built by this decision.
Amends ADR 0126's design with a separate argument-rule family; preserves ADR 0007's tightening principle.
ADR 0146's live-language restriction remains in force: the live evaluator is Go in the relay process.

## Context

An owner wants a refund above an amount to need a person. A tool-name allow list cannot express that condition.
Tego holds AI agents of every kind to rules the Linux kernel enforces and records each run. Business conditions
add a deterministic user-space restriction where the MCP relay can see a complete submitted tool call.
No language model collects, interprets, approves or decides any of these facts or conditions.

The inspected base is `2910acb2bb846894f70f6b497ba1a40e80786322`. The relay has admitted shim identity, run and
configured server, message bytes and tool names. It does not have trustworthy refund amounts today.
`internal/runtime/mcprelay/stdio.go` reads `arguments` as an object through `derive/mcp`; `keys.go` checks
duplicates only in the message and params. `keys_test.go` explicitly permits argument duplicates.
`wire.go` makes one compact forwardable message; compaction alone does not resolve parser disagreements.
The allow event precedes the write and its write error is ignored. Existing events therefore cannot prove
delivery. Existing asks recheck only tool denial at completion, not all conditions on exact call bytes.

The review of PLAN-2 and its two draft records rejected a production language choice without a named user
requirement, an imaginary refund schema, an unpriced mediation prerequisite and optimistic delivery claims.
This ADR settles the specification and implementation languages independently of release work. It selects Go for
the live evaluator and Rust for an independent evaluator; neither implementation is built by this decision.

## Decision

### 1. Meaning and responsibility

A business rule is an immutable, versioned, closed predicate on supplied facts about a submitted action. It returns
business `allow`, `deny` or `ask`, with the rule and failed condition. A selector outside its coverage returns
`none`, not permission. Business allow means that its restriction is satisfied. One final decision after
composition owns forwarding. Business rules neither grant kernel authority nor establish business truth.

The first family covers an amount per call, cumulative submitted amounts per run, an allowed currency list,
and ask above X with hard refusal above Y. The frozen byte contract is
[bizrule v1](../../spec/policy/bizrule/v1/README.md). Its [wire definition](../../spec/policy/bizrule/v1/WIRE.md),
schema and handwritten vectors are authoritative for either language. There is no arbitrary expression text,
callback, general rules language, clock read, I/O, dynamic schema inference or model in evaluation.
Roles govern who may change rules or answer an ask; they are a separate feature and are not implemented here.

The relay owns authenticated collection, schema validation, immutable call bytes, composition, holds,
durable reservations, forwarding and records. A pure evaluator consumes immutable inputs and proposes an
answer and reservation. A preview has no authority. An approval service authenticates a person and answers
an exact, single-use request. An untrusted agent's amount is a submitted fact, never an attested account balance.

### 2. One named adapter and admission boundary

Select Square's public self-hosted `square-mcp-server`, revision
`b276734fe2f1e6d4990fd99c2189c5d8d280a8b8`, read 2026-11-12. The tool is `make_api_request`, with
`service: "refunds"`, `method: "payment"`. The amount is `request.amount_money.amount`, a JSON integer
in minor units, and currency is `request.amount_money.currency`. This is a real generic dispatch tool,
not an invented `issue_refund` tool. The [adapter](../../spec/policy/bizrule/v1/ADAPTER.md) lists the exact
upstream schema, every request field and the narrower admitted profile. Closed MCP-envelope, dispatch-argument
and refund-payload stages have distinct validation boundaries and diagnostics. Sources:
[registration](https://github.com/square/square-mcp-server/blob/b276734fe2f1e6d4990fd99c2189c5d8d280a8b8/server.ts),
[refund dispatch](https://github.com/square/square-mcp-server/blob/b276734fe2f1e6d4990fd99c2189c5d8d280a8b8/services/refunds.ts),
[request type inventory](https://github.com/square/square-mcp-server/blob/b276734fe2f1e6d4990fd99c2189c5d8d280a8b8/utils/type-map.ts).

The supported target is exclusive local stdio mediation of this pinned server, with a run-wide kernel-held
process, file, socket and network boundary. Admission must prove all adapter topology requirements before
launch and keep them true for the run. No offered tier is certified by this document. **On the inspected base
this profile must refuse activation**: general protection of shim/server memory and credentials from same-run
attack, schema pinning, strict arguments and durable accounting are not established. An implementation cannot
turn this admission failure into a warning or call the current preview relay a business enforcement boundary.

This is the differentiator: the contract must make bypass authority unreachable to the agent using Linux
enforcement, rather than trusting the agent to honor a client hook or configuration file. It does not put the
integer comparison in the kernel. Exact command-start gating and a client pointing at a relay alone are
insufficient. A host permitting another spelling of the server, direct payment API access, a proxy, writable
server code, inherited channels, or attach authority has no exclusive-route claim. No direct remote HTTP,
adopted process, record-only run, mutable server or generic network-content coverage is supported by v1.

Current-code reconciliation matters: `internal/runtime/supervisor/pty.go:handlePidfdGetfd` already refuses all
agent descriptor imports at enforcing tiers. The older C50 prose that describes those imports as generally
permitted is stale for this base. `bpf/decide_control.h:tego_ptrace_peer` still admits same-run peers, subject to
the guarded-exec check. Do not infer a general shim/server lifetime attach ban from it. Yama alone is not a
portable per-run enforcement proof. This work reads that code; it does not run or qualify it.

### 3. Composition, failures and live rules

Let C be the stricter of the installed kernel/base restrictions and the **effective** MCP-tool decision.
The effective tool decision is `mcptool.Decide`: authorized live overlay first, then the contract lists.
Locked and Adjustable behavior remains ADRs 0125/0126's. This decision does not silently replace the effective
rule with the original lists, nor let a live tool allow bypass a business denial. Business bundles are pinned
for a run; editing or removing them takes effect only in a new run in v1.

The whole composition table has **32 cells: 4 contract states by 8 business states**. `hold` means ask with
no forwarding, and `refuse` means deny. An unknown or unreadable C is deny. `none` has rank allow solely for
composition; it makes no statement about the capability in that call.

| C | business allow | business none | business ask | business deny | evaluator missing | crashed | timed out | nonsense |
|---|---|---|---|---|---|---|---|---|
| allow | allow | allow | hold | refuse | refuse | refuse | refuse | refuse |
| ask | hold | hold | hold | refuse | refuse | refuse | refuse | refuse |
| deny | refuse | refuse | refuse | refuse | refuse | refuse | refuse | refuse |
| unknown | refuse | refuse | refuse | refuse | refuse | refuse | refuse | refuse |

Missing required evaluation refuses launch (launcher failure 125), as does unsupported configuration. The
missing cell is also mandatory defense if a running path encounters it. Crash, timeout, invalid enum, wrong
binding, duplicate/late/trailing output, resource exhaustion or lost required state are denial, never fallback
allow. Failure remains a business refusal even if another layer already denied. No automatic retry or helper
restart can reset a run's state or resurrect an outstanding request. Kernel restrictions remain installed.

Pending asks block delivery. A person can satisfy only the exact ask, never override deny. Approval binds
host/run, person authority, request ID, nonce, call digest, adapter/server identity, bundle digest, effective
restriction revision and expiry. At completion recollect current restrictions and state, invalidate changed
bindings, evaluate again and compose all floors. A new cumulative reservation is atomic at this point.
Denial, timeout, disconnect, missing person, stale answer and replay refuse. The current tool-name ask path
cannot be reused unchanged. V1 freezes ask semantics; it does not ship approval or distinct-person governance.

The pure answer includes every matching business ask in addition to the deciding rule. One approval covers
that exact complete set plus the effective contract ask identity; no partial discharge is allowed in v1.
Completion keeps the original held approval context, evaluates again with a new evaluation ID and current
state, refuses any denial/error or changed call, policy, authority or ask set, and only then discharges the
approved ask barriers and recomposes remaining restrictions. The original request digest remains bound to
the held context; fresh state and evaluation ID are intentionally separate. The approval request digest format
is outside the frozen v1 byte contract until the separate approval protocol defines its preimage and framing.
The pure answer is never edited into an allow, and any other outstanding kernel/completion restriction remains
effective.

### 4. Accounting, delivery and evidence

Cumulative means the sum of admitted submitted amounts in one currency on the named route in one run.
It is not actual refunded money, an order's remaining refundable balance or a cross-run quota. A host-side
durable run owner serializes reservations across all connections, outside the evaluator and the agent.
It authenticates the expected epoch before constructing evaluator input and binds state to run, bundle, server
and that epoch. The pure evaluator checks supplied state but cannot establish epoch continuity or detect a
well-formed substituted epoch with reset totals. The owner writes the reservation and safe decision intent durably
before attempting delivery and retains reservations even after write/remote failure. Loss or uncertain
recovery blocks this rule-bearing route for the rest of the run. A new helper does not create new state.
A new run is an explicit new budget, not continuity. See the specification for overflow, conflicts and replay.

Record only approved facts: minor-unit integer and currency/exponent, submitted-call provenance, rule IDs
and conditions, version and bundle/adapter/call digests, run/request IDs, effective tool-rule source/revision,
topology/coverage, counter epoch/revision/reservation, approval binding and authenticated principal if any.
Payment IDs, idempotency keys, arbitrary arguments, response bodies and secrets are not copied to the ledger.
Hashes can still reveal guesses of low-entropy input; access and retention apply to them too.
Allocate a record minor and validated shapes in a later integration change before writing any new fields.

Use distinct stages: evaluated; durable intent/reserved; delivery attempted; write accepted by the local
transport; delivery failed or uncertain; remote response reported success/error; remote outcome unknown.
An evaluated allow is not "forwarded". A successful socket write proves only local delivery acceptance.
A server-reported success is labelled as reported, not verified settlement. No refund is undone on failure.
Do not automatically resend. A retry is a new decision and reservation; local idempotency-key reuse is refused.
Remote deduplication is the server's behavior, not a Tego exactly-once guarantee.

The existing asynchronous emitter may drop events. Business admission therefore needs an acknowledged durable
intent/reservation path; inability to write it refuses before sending. Failure recording an outcome after a
send blocks further affected calls and leaves that outcome unknown. It cannot undo the send. Ordinary source
queue counters do not meet this prerequisite. A lost denial record also marks coverage unknown. No count of
unobserved calls is invented, and no absent line is proof that a bypass did not happen.

Receipt and dashboard use one future shared read projection. Show configured scope, actual bundle/adapter
revision and topology, evaluated counts, refusal/ask conditions, reservations by currency, delivery stages,
remote reports and recording/coverage uncertainty. Their totals describe recorded observations only.
The display must distinguish not configured, not applicable, refused before evaluation and unavailable.
Rule switches state minor units, currency, per-call or per-run scope, and next-run activation. They remain
unavailable until the implementation and topology qualify. Neither a receipt nor a signature proves a truthful
host, full observation or compliance. No UI, receipt, runtime or record code changes in this job.

### 5. Required limit sentences

Each row supplies both behavior and the documentation sentence that must accompany the feature.

| Gap | What this rule does | What it does not do | Required sentence |
|---|---|---|---|
| Call shaping: one amount seen, another acted on | Refuse duplicate/escaped/case-alias keys, unknown money fields, unsupported dispatch, unsafe JavaScript integers and noncanonical numbers; evaluate and send the same validated canonical object | Prove a malicious server interprets honestly or a remote account matches the caller's business story | "This rule limits the submitted amount in the pinned adapter profile; it does not verify the server's money effects." |
| Two calls for half | Each passes a per-call cap; a configured per-run cap atomically counts both before delivery | Infer an order, customer, cross-tool or cross-run total, or recover a lost budget by guessing zero | "A per-call cap permits split calls; the optional per-run cap counts admitted submissions on this route, not settled refunds." |
| Equivalent tool or method | Return none outside the selector; apply C to decide, deny unknown dispatch on this adapter's generic tool | Recognize business equivalence or claim universal refund coverage | "Another permitted tool can perform the same business action unless its own rules or the kernel-held contract refuse that route." |
| Batch | Refuse the entire client batch on the rule-bearing server, including otherwise harmless members | Split, reorder or partially deliver a batch, or promise cross-server atomicity | "This adapter refuses batches; no member of a refused batch is delivered." |
| Server schema changes | Pin implementation/configuration and discovered schema; mismatch refuses launch or blocks further calls | Trust an unchanged tool name or schema hash as proof of unchanged server behavior | "A server or schema update requires a reviewed adapter revision and a newly admitted run." |
| Failure after allow | Retain reservation, record attempted/failed/uncertain delivery and any reported outcome; refuse automatic retry | Prove settlement, restore spent budget on a missing reply or ensure exactly-once payment effects | "Allowed means admitted for submission; a failed or missing response leaves the remote outcome unknown." |

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

## Options weighed

**OPA/Rego.** A refund amount, currency and trusted approval context fit structured input; policy tests,
authoring tools, data policies, management APIs and compiled Wasm could save substantial work for customer-owned
policies. Here they add a language, dependency/builtin graph and result/error wrapper for four closed kinds.
Undefined, conflicting or malformed answers must deny. Network/clock builtins must be disabled; Wasm needs
host support for some builtins. OPA would still not establish facts, hold the call, reserve a durable total or
authenticate exact-call approval. Reconsider when a real policy pack exceeds this vocabulary. That comparison
must price maintaining our validator, evaluator and schema too, rather than treating them as free.
[OPA policy language](https://www.openpolicyagent.org/docs/policy-language),
[Wasm and host builtins](https://www.openpolicyagent.org/docs/wasm), read 2026-11-12.

**Cedar.** It can express this refund condition now using amount and currency context; trusted approval context
can participate. Schema validation, roles/entities, default denial, forbid precedence and determining-policy
diagnostics are useful, especially if role policy grows. It supplies neither trustworthy context nor an
approval hold, replay protection or durable counters. Cedar skips policies with evaluation errors and reports
diagnostics; our wrapper would refuse any relevant error. For four kinds, dependency and policy-language
review exceed the expected authoring benefit, conditionally. Reconsider together with ABAC requirements and
the real cost of maintaining our own semantics, not only for future roles.
[Cedar authorization](https://docs.cedarpolicy.com/auth/authorization.html), read 2026-11-12.

**A general Tego language.** It would offer arbitrary customer conditions without an external engine, at the
cost of a parser, type system, termination/cost model, diagnostics and versioned semantics. There is no buyer
requirement to justify those costs. Closed kinds still require maintained schemas and tests; they are not a
claim that custom policy machinery is costless.

**Inside mcptool.** That package already supplies exact-name allow/ask/deny, live precedence and list filtering
with no I/O. Adding money and counters there would entangle tool visibility, Adjustable behavior and submitted
facts, and risk treating tool allow as permission. Keep it as one input to final composition. A separate pure
package is useful in either language. Shared names for verdicts do not imply shared authority.

## Consequences and acceptance

Independent specification, fixture review and pure evaluator work can proceed away from the security release.
Relay, durable record, topology admission, dashboard, approval, CI and export changes need later coordinated jobs.
There is no shipping schedule or performance claim here. Estimate integration after the exact supported tier
and credential isolation design are selected; price missing mediation protection separately from a comparison.
Qualification must include parser witnesses with the pinned server, concurrent reservations, bypass attempts,
state loss, recording failure, all composition cells, replay and every supported kernel/tier. Schema-valid
fixtures are not evidence of any of those runtime properties.

Three sentences sales must never say: "The kernel enforces your refund amounts." "This prevents refund loss
through every tool and API." "An approved or verified receipt proves the refund succeeded and the run complied."

## Implementation note, 2026-11-12: pure Go evaluator

`pkg/spec/bizrule` implements the frozen v1 byte contract and pure evaluation,
including deferred state validation, complete ask sets, checked reservation
proposals and composition. The private `tools/bizeval` is a test-only stdin/stdout transport;
its alternating bundle/request convention is documented in its package comment.
It is not the live path. No product code imports or starts this tool.

The library passes all 218 handwritten vectors. This proves those pure answers,
not topology, authenticated epoch continuity, durable admission, delivery or human
approval. No v1 semantics or frozen vectors change. The live relay, cumulative
state owner, approval protocol, shared record/dashboard projection, independent
implementation disagreement build integration and guest qualification remain
later work. The current admission refusal in decision 2 remains required.

## Rust implementation note, 2026-11-12

The independent `rust/tego-bizrule` crate implements the frozen v1 pure seam,
including staged lexical/adapter/state validation, all four predicates, exact
composition and uncommitted reservations. All 218 handwritten complete results
pass in the Rust vector harness. The library also compiles for
`wasm32-unknown-unknown`; browser bindings and the contract-builder preview are
not implemented. No language-model interpretation or delivery authority is added.

The standalone checker uses a documented local two-hex-field driver envelope
because W005 contains no bundle transport. It does not extend or change v1 bytes.
Malformed production request frames receive no evaluator answer. W022 local
refusals remain fixture-wrapper diagnostics. Differential integration must align
the outer driver, compare every field and fail on any disagreement; that build
integration is still owed. The evaluator cannot authenticate epoch continuity
or commit state. Current-topology admission remains refusal, and kernel/tier
acceptance remains owed in a guest. This proof does not qualify public packaging.


## Differential qualification note, 2026-11-12

The independent implementations are merged without changing either evaluator or
any frozen v1 byte, requirement or vector. The private kept `test/bizdiff`
compares complete canonical Go results with the Rust checker's exact frames.
Malformed production requests require no answer on both sides; local diagnostic
APIs remain fixture-only. The harness preserves exact request bytes and adapts
only the non-normative bundle transport permitted by W024.

The specification-derived indexed generators, explicit Cartesian boundary suite,
carried-state sequences, malformed outer forms and transport negative controls
are documented privately, with the measured qualification and report-gap
comparison. This supplies a private disagreement
check, not activation in the default build or CI. No policy meaning or topology
admission decision changes. Durable ownership, approval bytes, browser preview,
record integration and guest qualification remain separate work.


## Integration decision, 2026-11-12

[ADR 0152](0152-business-rules-at-the-relay.md) specifies the relay integration;
this record retains sole authority for business semantics. Record minor 38 is
allocated for business lines. Slice 1 is an offline fixture profile with one USD
per-call cap and mandatory replay/durable admission. It refuses cumulative caps,
human approval, installed servers, HTTP and legacy protocol 3. Cap/condition
disclosure in refusal reasons is intentional and permits limit probing.

*Amended 2026-11-12 (integration registry reconciliation):* the incoming unwritten
business allocation of 32 collided with `MinorDeployment=32`. Business lines now
hold 38, preserving declared revisions 32 to 35, principal reservation 36 and the
unmerged local-roles branch's opt-in allocation 37. No business record constant,
shape or writer is implemented by this preflight. The default remains 31; frozen
business v1 semantics, canonical bytes and vectors are unchanged.

Policy writers and dispatch share a linearization lock from slice 1. Initial
schema verification precedes readiness; list changes or unexpected server
requests withdraw it. Pending response capacity precedes intent commit. Writes
have a finite monotonic bound with independently available cancellation. Reaper
and sweeps preserve uncertain journals and never repair them to a permissive
state. Every isolation prerequisite is a product check at doctor and run start.
The no-root tier refuses even per-call contracts because the chosen profile
requires a root-owned owner and separate worker identity. Missing capability
means launch refusal 125, not partial protection. Implementation and guest
qualification must be reported separately; this decision certifies neither.


## Product preflight checkpoint, 2026-11-12

The contract compiler now uses DecodeBundle to validate and pin the declared
bundle. Both runtime admission constructors (launch and adoption) and legacy
relay entry points refuse business-bearing tables. This does not wire live
refund evaluation, durable ownership, records or receipts. ADR 0152 records
the remaining requirements. The compiler's decoder import makes 27 other
frozen library/tool functions visible to production reachability analysis;
they retain exact public-api, test-api or tool-only classifications. They are
not claimed as live relay calls. Pure evaluator source and v1 bytes stay fixed.
