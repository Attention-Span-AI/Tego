// SPDX-License-Identifier: Apache-2.0

package bizrule

func stringValue(s string) *value    { return &value{kind: 's', text: s} }
func pair(key, s string) member      { return member{key, stringValue(s)} }
func object(fields ...member) *value { return &value{kind: '{', object: fields} }
func number(n uint64) *value         { return &value{kind: 'i', text: decimal(n)} }
func null() *value                   { return &value{kind: 'n', text: "null"} }

// EncodeResult returns W001 canonical answer bytes without a framing LF.
// It refuses malformed caller-constructed results rather than repairing them.
func EncodeResult(r Result) ([]byte, error) {
	if r.Version != 1 || !label(r.Adapter) || !hashText(r.BundleDigest) || !hashText(r.CallDigest) || !label(r.RunID) || !label(r.Server) || !oneOf(r.Business.Verdict, "allow", "ask", "deny", "none") || !oneOf(r.Final.Verdict, "allow", "ask", "deny") || !oneOf(r.Final.Source, "business", "contract", "wire") || !oneOf(r.Record.Coverage, "unknown", "none", "mediated") || r.Record.Delivery != "not_attempted" || r.Record.RemoteOutcome != "unknown" || !r.Record.Required || !oneOf(r.Record.Stage, "evaluated", "not_evaluated") || len(r.Asks) > 32 {
		return nil, ErrResult
	}
	if _, ok := unsigned(r.RequestID, maxID, false); !ok {
		return nil, ErrResult
	}
	if !validBusiness(r.Business) || !condition(r.Business.Condition) || !(condition(r.Final.Condition) || oneOf(r.Final.Condition, "contract.allow", "contract.ask", "contract.deny", "contract.unknown")) {
		return nil, ErrResult
	}
	asks := &value{kind: '['}
	if r.Business.Verdict != "ask" && len(r.Asks) != 0 {
		return nil, ErrResult
	}
	previous := ""
	for _, a := range r.Asks {
		if !label(a.RuleID) || a.RuleID <= previous || a.Condition != "threshold.ask" {
			return nil, ErrResult
		}
		previous = a.RuleID
		asks.array = append(asks.array, object(pair("condition", a.Condition), pair("rule_id", a.RuleID)))
	}
	facts := null()
	if f := r.Facts; f != nil {
		exp, ok := exponent(f.Currency)
		if _, moneyOK := unsigned(f.AmountMinor, maxJS, false); !moneyOK || !ok || exp != f.Exponent || f.Source != "submitted-call" {
			return nil, ErrResult
		}
		facts = object(pair("amount_minor", f.AmountMinor), pair("currency", f.Currency), member{"exponent", number(uint64(f.Exponent))}, pair("source", f.Source))
	}
	reservation := null()
	if p := r.Reservation; p != nil {
		before, ok := unsigned(p.BeforeMinor, maxMoney, true)
		amount, ok2 := unsigned(p.AmountMinor, maxJS, false)
		after, ok3 := unsigned(p.AfterMinor, maxMoney, true)
		_, ok4 := unsigned(p.StateRevision, maxID, true)
		if !ok || !ok2 || !ok3 || !ok4 || amount > maxMoney-before || before+amount != after || !hashText(p.KeyDigest) || r.Final.Verdict != "allow" || r.Facts == nil || p.Currency != r.Facts.Currency || p.AmountMinor != r.Facts.AmountMinor {
			return nil, ErrResult
		}
		reservation = object(pair("after_minor", p.AfterMinor), pair("amount_minor", p.AmountMinor), pair("before_minor", p.BeforeMinor), pair("currency", p.Currency), pair("key_digest", p.KeyDigest), pair("state_revision", p.StateRevision))
	}
	v := object(pair("adapter", r.Adapter), member{"asks", asks}, pair("bundle_digest", r.BundleDigest), member{"business", object(pair("condition", r.Business.Condition), pair("rule_id", r.Business.RuleID), pair("verdict", r.Business.Verdict))}, pair("call_digest", r.CallDigest), member{"facts", facts}, member{"final", object(pair("condition", r.Final.Condition), pair("source", r.Final.Source), pair("verdict", r.Final.Verdict))}, member{"record", object(pair("coverage", r.Record.Coverage), pair("delivery", r.Record.Delivery), pair("remote_outcome", r.Record.RemoteOutcome), member{"required", &value{kind: 't', text: "true"}}, pair("stage", r.Record.Stage))}, pair("request_id", r.RequestID), member{"reservation", reservation}, pair("run_id", r.RunID), pair("server", r.Server), member{"version", number(1)})
	out := appendValue(nil, v)
	if _, cond := parse(out, MaxResultFrameBytes-1); cond != "" {
		return nil, ErrResult
	}
	return out, nil
}
func condition(c string) bool {
	return oneOf(c, "satisfied", "not_applicable", "wire.invalid", "bundle.invalid", "bundle.digest", "topology.unproven", "input.json", "input.canonical", "input.duplicate", "input.limit", "adapter.envelope", "adapter.dispatch", "adapter.batch", "adapter.missing", "adapter.unknown", "adapter.type", "adapter.range", "adapter.revision", "state.unavailable", "state.binding", "state.invalid", "state.replay", "state.capacity", "per_call.exceeded", "currencies.not_listed", "threshold.ask", "threshold.deny", "per_run.exceeded", "per_run.overflow", "evaluator.missing", "evaluator.crashed", "evaluator.timed_out", "evaluator.nonsense", "evaluator.queue_full", "evaluator.late_reply", "evaluator.wrong_binding", "evaluator.extra_reply", "evaluator.restarted", "evaluator.record_failed")
}
