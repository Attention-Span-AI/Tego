<!-- SPDX-License-Identifier: Apache-2.0 -->

# Fixture inventory and proof limits

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
| B001 | [README.md](README.md) | Implementation acceptance required |
| B002 | [README.md](README.md) | Implementation acceptance required |
| B003 | [README.md](README.md) | c13-contract-denial-no-reservation, s01-equivalent-tool-allowed, x01-allow-allow, x02-allow-none, x03-allow-ask, x04-allow-deny, x05-allow-missing, x06-allow-crashed, x07-allow-timed_out, x08-allow-nonsense, x09-ask-allow, x10-ask-none, x11-ask-ask, x12-ask-deny, x13-ask-missing, x14-ask-crashed, x15-ask-timed_out, x16-ask-nonsense, x17-deny-allow, x18-deny-none, x19-deny-ask, x20-deny-deny, x21-deny-missing, x22-deny-crashed, x23-deny-timed_out, x24-deny-nonsense, x25-unknown-allow, x26-unknown-none, x27-unknown-ask, x28-unknown-deny, x29-unknown-missing, x30-unknown-crashed, x31-unknown-timed_out, x32-unknown-nonsense |
| B004 | [README.md](README.md) | s11-live-allow-still-capped |
| B005 | [README.md](README.md) | x01-allow-allow, x02-allow-none, x03-allow-ask, x04-allow-deny, x05-allow-missing, x06-allow-crashed, x07-allow-timed_out, x08-allow-nonsense, x09-ask-allow, x10-ask-none, x11-ask-ask, x12-ask-deny, x13-ask-missing, x14-ask-crashed, x15-ask-timed_out, x16-ask-nonsense, x17-deny-allow, x18-deny-none, x19-deny-ask, x20-deny-deny, x21-deny-missing, x22-deny-crashed, x23-deny-timed_out, x24-deny-nonsense, x25-unknown-allow, x26-unknown-none, x27-unknown-ask, x28-unknown-deny, x29-unknown-missing, x30-unknown-crashed, x31-unknown-timed_out, x32-unknown-nonsense |
| B006 | [README.md](README.md) | x01-allow-allow, x02-allow-none, x03-allow-ask, x04-allow-deny, x05-allow-missing, x06-allow-crashed, x07-allow-timed_out, x08-allow-nonsense, x09-ask-allow, x10-ask-none, x11-ask-ask, x12-ask-deny, x13-ask-missing, x14-ask-crashed, x15-ask-timed_out, x16-ask-nonsense, x17-deny-allow, x18-deny-none, x19-deny-ask, x20-deny-deny, x21-deny-missing, x22-deny-crashed, x23-deny-timed_out, x24-deny-nonsense, x25-unknown-allow, x26-unknown-none, x27-unknown-ask, x28-unknown-deny, x29-unknown-missing, x30-unknown-crashed, x31-unknown-timed_out, x32-unknown-nonsense |
| B007 | [README.md](README.md) | l01-queue_full, l02-late_reply, l03-wrong_binding, l04-extra_reply, l05-restarted, l06-record_failed |
| B008 | [README.md](README.md) | s10-topology-unproven |
| B009 | [README.md](README.md) | Implementation acceptance required |
| B010 | [README.md](README.md) | b03-unknown-version, b04-unknown-bundle-field, b05-unknown-kind, b09-noncanonical-bundle, l15-bundle-over-byte-limit |
| B011 | [README.md](README.md) | b06-duplicate-rule-id, b10-unsorted-rules |
| B012 | [README.md](README.md) | b01-digest-substitution, b02-changed-cap-stale-digest |
| B013 | [README.md](README.md) | Implementation acceptance required |
| B014 | [README.md](README.md) | Implementation acceptance required |
| B015 | [README.md](README.md) | l18-depth-at-limit, l19-depth-over-limit, p05-duplicate-amount, p06-escaped-duplicate, p22-duplicate-currency, p23-duplicate-params, p24-duplicate-jsonrpc, p25-leading-zero, p26-plus-sign, p27-trailing-value, p28-invalid-utf8, p29-lone-surrogate, p30-bom |
| B016 | [README.md](README.md) | m06-negative-zero, p02-float, p03-exponent, p04-uppercase-exponent, p25-leading-zero, p26-plus-sign |
| B017 | [README.md](README.md) | p06-escaped-duplicate, p07-escaped-key, p08-amount-case-alias, p10-alternative-amount-field, p11-nested-money-override, p12-unknown-field |
| B018 | [README.md](README.md) | p01-string, p09-nested-amount, p14-missing-currency, p15-missing-amount, p16-null-amount, p17-bool-amount, p18-array-amount, p19-null-money, p33-currency-number |
| B019 | [README.md](README.md) | b08-limit-over-i64, c11-add-overflow, c12-overflow-boundary-equal, m04-zero, m05-negative, m07-largest-i64, m08-i64-overflow |
| B020 | [README.md](README.md) | c16-other-currency-independent, m11-yen-equal, m12-yen-over, m13-cad-equal, m14-kwd-equal, m15-kwd-over, p13-lowercase-currency, p34-unknown-currency |
| B021 | [README.md](README.md) | Implementation acceptance required |
| B022 | [README.md](README.md) | s01-equivalent-tool-allowed, s02-other-server-allowed, s03-other-server-malformed, s12-other-server-batch, s21-other-tool-empty-arguments, s22-other-tool-malformed-envelope, s23-other-server-over-call-bound |
| B023 | [README.md](README.md) | s07-service-alias, s08-other-method, s18-payments-create, s19-disputes-accept, s20-orders-batchget |
| B024 | [README.md](README.md) | s04-batch-refunds, s05-mixed-batch, s06-batch-other-tools |
| B025 | [README.md](README.md) | m01-cap-below, m02-cap-equal, m03-cap-plus-one, m09-js-safe-largest, m11-yen-equal, m12-yen-over, m13-cad-equal, m14-kwd-equal, m15-kwd-over, m26-smallest-refund |
| B026 | [README.md](README.md) | m21-currency-not-listed |
| B027 | [README.md](README.md) | b07-equal-thresholds, m16-threshold-below, m17-threshold-at-x, m18-threshold-x-plus-one, m19-threshold-at-y, m20-threshold-y-plus-one |
| B028 | [README.md](README.md) | c01-first-sixty, c02-second-sixty-refused, c03-remainder-equal, c04-full-plus-one, c11-add-overflow, c12-overflow-boundary-equal, c16-other-currency-independent, c25-two-run-rules-one-reservation, c26-second-run-rule-denies |
| B029 | [README.md](README.md) | c25-two-run-rules-one-reservation, c26-second-run-rule-denies, m23-deny-beats-ask, m24-two-denials-first-id, m25-two-asks-first-id |
| B030 | [README.md](README.md) | m21-currency-not-listed, m22-currency-no-cap |
| B031 | [README.md](README.md) | Implementation acceptance required |
| B032 | [README.md](README.md) | c09-other-run-state, c10-other-bundle-state |
| B033 | [README.md](README.md) | c06-state-lost, c07-state-unavailable, c08-missing-state, c09-other-run-state, c10-other-bundle-state, c27-replay-without-run-rule |
| B034 | [README.md](README.md) | c15-duplicate-totals |
| B035 | [README.md](README.md) | c05-key-replay, c27-replay-without-run-rule |
| B036 | [README.md](README.md) | c01-first-sixty, c13-contract-denial-no-reservation, c25-two-run-rules-one-reservation, c26-second-run-rule-denies |
| B037 | [README.md](README.md) | Implementation acceptance required |
| B038 | [README.md](README.md) | c14-ask-no-reservation |
| B039 | [README.md](README.md) | c17-post-failure-conservative |
| B040 | [README.md](README.md) | c06-state-lost, c18-new-run-new-epoch, c28-epoch-continuity-external |
| B041 | [README.md](README.md) | Implementation acceptance required |
| B062 | [README.md](README.md) | b22-state-epoch-over-limit, c28-epoch-continuity-external |
| B064 | [README.md](README.md) | b22-state-epoch-over-limit, c19-binding-before-unavailable, c20-unavailable-before-shape, c21-shape-before-replay, c22-replay-before-capacity, c23-missing-binding, c24-wrong-binding-type, c25-two-run-rules-one-reservation, c26-second-run-rule-denies, c27-replay-without-run-rule |
| B042 | [README.md](README.md) | c14-ask-no-reservation, m18-threshold-x-plus-one |
| B043 | [README.md](README.md) | Implementation acceptance required |
| B044 | [README.md](README.md) | p12-unknown-field |
| B045 | [README.md](README.md) | Implementation acceptance required |
| B046 | [README.md](README.md) | Implementation acceptance required |
| B047 | [README.md](README.md) | Implementation acceptance required |
| B048 | [README.md](README.md) | Implementation acceptance required |
| B049 | [README.md](README.md) | l07-call-at-byte-limit, l08-call-over-byte-limit, l20-members-at-limit, l21-members-over-limit |
| B050 | [README.md](README.md) | s09-adapter-revision, s13-fee-override, s14-unlinked, s15-redirect, s16-cash, s17-schema-new-field |
| B051 | [README.md](README.md) | Implementation acceptance required |
| B052 | [README.md](README.md) | Implementation acceptance required |
| B053 | [README.md](README.md) | l22-member-bound-before-duplicate, p37-root-missing, p38-root-unknown, p39-root-type, p40-params-missing, p41-params-unknown, p42-params-type, p43-dispatch-missing, p44-dispatch-unknown, p45-dispatch-type, p46-payload-missing, p47-payload-unknown, p48-payload-type, p49-money-missing, p50-money-unknown, p51-money-type, p52-missing-service, p53-method-type, p54-dispatch-before-payload, p55-unknown-before-type, p56-type-parent-before-child, p57-missing-before-unknown, p58-null-root, p59-scalar-root, p62-alternate-quote, p63-non-ascii, p64-control-escape, p65-canonical-quote-range, s03-other-server-malformed, s12-other-server-batch, s23-other-server-over-call-bound |
| B054 | [README.md](README.md) | p37-root-missing, p38-root-unknown, p39-root-type, p40-params-missing, p41-params-unknown, p42-params-type, p43-dispatch-missing, p44-dispatch-unknown, p45-dispatch-type, p46-payload-missing, p47-payload-unknown, p48-payload-type, p49-money-missing, p50-money-unknown, p51-money-type |
| B055 | [README.md](README.md) | b11-unknown-request-field, b12-duplicate-request-field, b13-approval-digest-outside-v1, b14-state-scalar-outer-type, b15-missing-state-outer-field, b16-state-key-order-before-status, b17-state-number-spelling-before-status, b18-request-lf-present, b19-request-lf-missing, b20-request-double-lf, b21-state-integer-type-deferred, l16-wire-invalid, l17-wire-over-byte-limit |
| B056 | [README.md](README.md) | s02-other-server-allowed, s09-adapter-revision |
| B057 | [README.md](README.md) | l13-revision-exhausted, l14-replay-capacity-full |
| B058 | [README.md](README.md) | Implementation acceptance required |
| B059 | [README.md](README.md) | Implementation acceptance required |
| B060 | [README.md](README.md) | Implementation acceptance required |
| B061 | [README.md](README.md) | Implementation acceptance required |
| B063 | [README.md](README.md) | Implementation acceptance required |
| W001 | [WIRE.md](WIRE.md) | b09-noncanonical-bundle, p32-key-order |
| W002 | [WIRE.md](WIRE.md) | p60-canonical-quote, p61-canonical-backslash, p62-alternate-quote, p63-non-ascii, p64-control-escape, p65-canonical-quote-range |
| W003 | [WIRE.md](WIRE.md) | Implementation acceptance required |
| W004 | [WIRE.md](WIRE.md) | Implementation acceptance required |
| W005 | [WIRE.md](WIRE.md) | Implementation acceptance required |
| W006 | [WIRE.md](WIRE.md) | Implementation acceptance required |
| W007 | [WIRE.md](WIRE.md) | b11-unknown-request-field, b12-duplicate-request-field, b13-approval-digest-outside-v1, b14-state-scalar-outer-type, b15-missing-state-outer-field, b16-state-key-order-before-status, b17-state-number-spelling-before-status, b18-request-lf-present, b19-request-lf-missing, b20-request-double-lf, b21-state-integer-type-deferred, b22-state-epoch-over-limit, c19-binding-before-unavailable, c20-unavailable-before-shape, c21-shape-before-replay, c22-replay-before-capacity, c23-missing-binding, c24-wrong-binding-type |
| W008 | [WIRE.md](WIRE.md) | Implementation acceptance required |
| W009 | [WIRE.md](WIRE.md) | Implementation acceptance required |
| W010 | [WIRE.md](WIRE.md) | Implementation acceptance required |
| W011 | [WIRE.md](WIRE.md) | Implementation acceptance required |
| W012 | [WIRE.md](WIRE.md) | Implementation acceptance required |
| W013 | [WIRE.md](WIRE.md) | Implementation acceptance required |
| W014 | [WIRE.md](WIRE.md) | p31-whitespace-at-seam, p32-key-order |
| W015 | [WIRE.md](WIRE.md) | Implementation acceptance required |
| W016 | [WIRE.md](WIRE.md) | l07-call-at-byte-limit, l08-call-over-byte-limit, l09-payment-id-at-limit, l10-payment-id-over-limit, l11-key-at-limit, l12-key-over-limit, l15-bundle-over-byte-limit, l17-wire-over-byte-limit, l18-depth-at-limit, l19-depth-over-limit, l20-members-at-limit, l21-members-over-limit, l22-member-bound-before-duplicate |
| W017 | [WIRE.md](WIRE.md) | l01-queue_full, l02-late_reply, l03-wrong_binding, l04-extra_reply, l05-restarted, l06-record_failed |
| W018 | [WIRE.md](WIRE.md) | l01-queue_full, l02-late_reply, l03-wrong_binding, l04-extra_reply, l05-restarted, l06-record_failed |
| W019 | [WIRE.md](WIRE.md) | l14-replay-capacity-full |
| W020 | [WIRE.md](WIRE.md) | Implementation acceptance required |
| W021 | [WIRE.md](WIRE.md) | l16-wire-invalid |
| W022 | [WIRE.md](WIRE.md) | l16-wire-invalid |
| W023 | [WIRE.md](WIRE.md) | c02-second-sixty-refused, c03-remainder-equal, c04-full-plus-one, c05-key-replay, c17-post-failure-conservative |
| W024 | [WIRE.md](WIRE.md) | Implementation acceptance required |
| W025 | [WIRE.md](WIRE.md) | Implementation acceptance required |
| W026 | [WIRE.md](WIRE.md) | b11-unknown-request-field, b12-duplicate-request-field, b13-approval-digest-outside-v1, b14-state-scalar-outer-type, b15-missing-state-outer-field, b16-state-key-order-before-status, b17-state-number-spelling-before-status, b18-request-lf-present, b19-request-lf-missing, b20-request-double-lf, b21-state-integer-type-deferred |
| W027 | [WIRE.md](WIRE.md) | b11-unknown-request-field, b12-duplicate-request-field, b13-approval-digest-outside-v1, b14-state-scalar-outer-type, b15-missing-state-outer-field, b16-state-key-order-before-status, b17-state-number-spelling-before-status, b18-request-lf-present, b19-request-lf-missing, b20-request-double-lf, b21-state-integer-type-deferred |
| W028 | [WIRE.md](WIRE.md) | Implementation acceptance required |
| A001 | [ADAPTER.md](ADAPTER.md) | Implementation acceptance required |
| A002 | [ADAPTER.md](ADAPTER.md) | Implementation acceptance required |
| A003 | [ADAPTER.md](ADAPTER.md) | s07-service-alias, s18-payments-create, s19-disputes-accept, s20-orders-batchget |
| A004 | [ADAPTER.md](ADAPTER.md) | p35-string-rpc-id, p36-not-call-method |
| A005 | [ADAPTER.md](ADAPTER.md) | p10-alternative-amount-field, p11-nested-money-override, p20-missing-payment, p21-missing-key |
| A006 | [ADAPTER.md](ADAPTER.md) | m04-zero, m05-negative, m07-largest-i64, m08-i64-overflow, m09-js-safe-largest, m10-js-unsafe-next, m26-smallest-refund, p13-lowercase-currency |
| A007 | [ADAPTER.md](ADAPTER.md) | l09-payment-id-at-limit, l10-payment-id-over-limit, l11-key-at-limit, l12-key-over-limit, p62-alternate-quote, p63-non-ascii, p64-control-escape, p65-canonical-quote-range |
| A008 | [ADAPTER.md](ADAPTER.md) | s13-fee-override, s14-unlinked, s15-redirect, s16-cash, s17-schema-new-field |
| A009 | [ADAPTER.md](ADAPTER.md) | s13-fee-override, s14-unlinked, s15-redirect, s16-cash, s17-schema-new-field |
| A010 | [ADAPTER.md](ADAPTER.md) | Implementation acceptance required |
| A011 | [ADAPTER.md](ADAPTER.md) | Implementation acceptance required |
| A019 | [ADAPTER.md](ADAPTER.md) | p37-root-missing, p38-root-unknown, p39-root-type, p40-params-missing, p41-params-unknown, p42-params-type, p43-dispatch-missing, p44-dispatch-unknown, p45-dispatch-type, p46-payload-missing, p47-payload-unknown, p48-payload-type, p49-money-missing, p50-money-unknown, p51-money-type, p52-missing-service, p53-method-type, p54-dispatch-before-payload, p55-unknown-before-type, p56-type-parent-before-child, p57-missing-before-unknown, p58-null-root, p59-scalar-root, p60-canonical-quote, p61-canonical-backslash, s21-other-tool-empty-arguments, s22-other-tool-malformed-envelope |
| A020 | [ADAPTER.md](ADAPTER.md) | p37-root-missing, p38-root-unknown, p39-root-type, p40-params-missing, p41-params-unknown, p42-params-type, p43-dispatch-missing, p44-dispatch-unknown, p45-dispatch-type, p46-payload-missing, p47-payload-unknown, p48-payload-type, p49-money-missing, p50-money-unknown, p51-money-type, p52-missing-service, p53-method-type, p54-dispatch-before-payload, p55-unknown-before-type, p56-type-parent-before-child, p57-missing-before-unknown, p58-null-root, p59-scalar-root, s18-payments-create, s19-disputes-accept, s20-orders-batchget |
| A012 | [ADAPTER.md](ADAPTER.md) | Implementation acceptance required |
| A013 | [ADAPTER.md](ADAPTER.md) | Implementation acceptance required |
| A014 | [ADAPTER.md](ADAPTER.md) | Implementation acceptance required |
| A015 | [ADAPTER.md](ADAPTER.md) | Implementation acceptance required |
| A016 | [ADAPTER.md](ADAPTER.md) | Implementation acceptance required |
| A017 | [ADAPTER.md](ADAPTER.md) | s10-topology-unproven |
| A018 | [ADAPTER.md](ADAPTER.md) | Implementation acceptance required |
