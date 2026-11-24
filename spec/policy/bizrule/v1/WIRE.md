<!-- SPDX-License-Identifier: Apache-2.0 -->

# Business rule v1 bytes and fixture schema

All W requirements are explicit design decisions under ADR 0151. The JSON Schema
2020-12 file `schema.json` checks fixture shape, including complete expected
answers. The requirements additionally define lexical/canonical, numeric-range,
binding and semantic checks which JSON Schema alone does not establish.
Fixture containers are human-readable JSON data, not literal transport frames;
W021 specifies which embedded objects are serialized into canonical bytes.

**W001.** Canonical objects MUST sort keys by ASCII byte order, use compact JSON,
no BOM, no whitespace or final newline, exact case, and include every specified
field. Arrays MUST preserve specified order; absent optional values MUST be null,
not omitted. Protocol frames alone add one LF after canonical object bytes.

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

**W004.** Bundle fields MUST be adapter, rules, server, version. Rules MUST be
one of `{currency,id,kind:"per_call",limit}`, `{codes,id,kind:"currencies"}`,
`{currency,id,kind:"per_run",limit}`, or
`{ask_above,currency,deny_above,id,kind:"threshold"}` with exact field sets.
Money thresholds MUST be B019 decimal strings, not JSON numbers.

**W005.** Request fields MUST be adapter, call_hex, contract_bundle_digest,
contract_verdict, evaluator_status, request_id, run_id, server, state,
tool_source, topology, version. Version MUST be integer token 1; IDs MUST be
canonical decimal strings 1..18446744073709551615. Run/server/epoch/rule labels
MUST match `[A-Za-z0-9._/-]{1,64}`. Request IDs MUST increase within a session.

**W006.** Contract verdict MUST be allow/ask/deny/unknown; tool_source MUST be
contract/live; topology MUST be exclusive/unproven. The fault seam's
evaluator_status MUST be ready/missing/crashed/timed_out/nonsense/queue_full/
late_reply/wrong_binding/extra_reply/restarted/record_failed. Production callers
MUST derive these values outside agent control. A wire unknown enum MUST refuse.

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

**W008.** Result fields MUST be adapter, asks, bundle_digest, business, call_digest,
facts, final, record, request_id, reservation, run_id, server, version. Bindings
MUST echo the request; bundle_digest MUST echo contract_bundle_digest, including
on substitution errors, never the substituted bundle's digest.

**W009.** Business MUST be `{condition,rule_id,verdict}` with verdict
allow/ask/deny/none. Rule_id MUST be the deciding rule ID, empty for none or an
unconstrained currency, or `$bundle`, `$evaluator`, `$adapter`, `$state`,
`$topology`, `$wire` on corresponding failures. Successful condition MUST be
satisfied; none MUST use not_applicable. Other conditions MUST be the exact
codes in README. No diagnostic free text is authoritative.

**W010.** Final MUST be `{condition,source,verdict}`, with verdict allow/ask/deny,
source business/contract/wire. When business wins condition MUST equal its
condition. Contract wins MUST use contract.allow/contract.ask/contract.deny or
contract.unknown according to the original C value, even when unknown denies.

**W011.** Facts MUST be null on pre-fact failure or none; otherwise exactly
`{amount_minor,currency,exponent,source:"submitted-call"}`. Amount_minor MUST be
decimal text, exponent MUST be a small integer matching B020. No target or key
is a safe fact. Money MUST never round-trip through a floating-point type.

**W012.** Reservation MUST be null unless B036 applies; otherwise exactly
`{after_minor,amount_minor,before_minor,currency,key_digest,state_revision}`.
It MUST propose one addition for all matching per_run rules in that currency.
This object MUST NOT assert that durable commit has occurred.

**W013.** Record MUST be exactly `{coverage,delivery:"not_attempted",
remote_outcome:"unknown",required:true,stage:"evaluated"}` for ordinary seam
results. Coverage MUST follow B052. A local wire refusal MUST use stage
`not_evaluated` and coverage unknown. Safe record contents are the rest of this
result plus B044's integration bindings, not raw request bytes.

**W014.** Valid call input MUST already be W001/W002 canonical bytes. The future
relay intake MAY strip insignificant whitespace and sort objects only after
strict recursive validation of unique exact keys and integer/string tokens;
it MUST refuse noncanonical token/key/string spellings rather than repair them.
It MUST then evaluate and forward the very same frozen bytes. The fixture seam
starts after this intake step and rejects any noncanonical candidate bytes.

**W015.** Error-result facts and reservations MUST be null for envelope, bundle,
evaluator, topology, call, adapter and state-validation failures. Rule predicate
denials MUST retain facts. A valid but exhausted state MUST retain no partial
facts under B031, because its validation precedes predicates.

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

**W019.** A host MUST cap durable replay entries at 4096 per run/server/bundle;
the 4097th admission MUST refuse. Holding a person MUST have a host-selected
deadline <=300000 ms and consume queue capacity; expiration MUST deny. These
are refusal limits, not latency or availability promises.

**W020.** A fixture MUST have id, group, pins, why, bundle, bundle_wire_hex,
request, request_wire_hex and expected. IDs MUST be unique. Pins MUST name
existing numbered requirements and why MUST explicitly name at least one pin.
Group MUST be money/parser/cumulative/composition/scope/bundle/limits.

**W021.** Null bundle_wire_hex MUST mean canonical bundle bytes without LF; null
request_wire_hex MUST mean canonical request bytes followed by exactly one LF.
Non-null bundle_wire_hex or request_wire_hex MUST replace those respective bytes
exactly, to represent malformed inputs without making the fixture itself invalid
JSON. Malformed call bytes MUST use request.call_hex, including duplicate keys,
invalid UTF-8, batches and trailing bytes. Expected MUST always be a full result.

**W022.** In a local wire refusal fixture, result IDs/adapter/run/server/digests
MUST use the valid outer request as the diagnostic context, not untrusted fields
from the malformed wire override. These are fixture-wrapper diagnostics only;
production MUST NOT emit a valid evaluator response to a malformed envelope.

**W023.** Sequential cumulative fixtures MUST identify their predecessor in why
and explicitly supply the resulting trusted state snapshot for the next call.
They MUST NOT depend on filesystem enumeration order or execute state changes in
the form checker. Concurrent calls MUST serialize in the owner, not in JSON.

**W024.** This seam MUST NOT freeze a Rust ABI, Go struct layout, YAML parser,
process-start mechanism or UI authority. Implementations MUST share v1 meaning,
not internal representation. Version changes MUST follow B059.

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
