// SPDX-License-Identifier: Apache-2.0

package bizrule

import "encoding/hex"

func rank(verdict string) int {
	switch verdict {
	case "allow", "none":
		return 0
	case "ask":
		return 1
	default:
		return 2
	}
}

// Compose returns the stricter restriction with B005 attribution. An unknown
// contract or business verdict refuses. None contributes no permission.
func Compose(contract string, business Business) Final {
	if !oneOf(contract, "allow", "ask", "deny", "unknown") {
		contract = "unknown"
	}
	if !validBusiness(business) {
		business = Business{"evaluator.nonsense", "$evaluator", "deny"}
	}
	if business.Verdict == "none" || rank(contract) > rank(business.Verdict) || rank(contract) == rank(business.Verdict) && rank(contract) > 0 {
		verdict := contract
		if verdict == "unknown" {
			verdict = "deny"
		}
		return Final{"contract." + contract, "contract", verdict}
	}
	return Final{business.Condition, "business", business.Verdict}
}

// Evaluate validates bundle bytes and evaluates an outer-validated request.
// Invalid requests (including the zero value) return ErrWire and no answer.
// Bundle failures are ordinary bound refusals and precede evaluator status.
func Evaluate(bundleBytes []byte, request Request) (Result, error) {
	if !request.valid {
		return Result{}, ErrWire
	}
	b, err := DecodeBundle(bundleBytes)
	if err != nil {
		return failure(request, "$bundle", "bundle.invalid"), nil
	}
	return EvaluateBundle(b, request)
}

// EvaluateBundle evaluates an immutable bundle against a supplied request/state.
// It neither commits the returned reservation nor authenticates the inputs.
func EvaluateBundle(b Bundle, r Request) (Result, error) {
	if !r.valid {
		return Result{}, ErrWire
	}
	if b.raw == "" {
		return failure(r, "$bundle", "bundle.invalid"), nil
	}
	if b.digest != r.bundleDigest {
		return failure(r, "$bundle", "bundle.digest"), nil
	}
	if r.status != "ready" {
		return failure(r, "$evaluator", "evaluator."+r.status), nil
	}
	if r.topology != "exclusive" {
		return failure(r, "$topology", "topology.unproven"), nil
	}
	if r.adapter != adapter {
		return failure(r, "$adapter", "adapter.revision"), nil
	}
	if r.server != b.server {
		return answer(r, Business{"not_applicable", "", "none"}, nil, nil, nil), nil
	}
	// The digest always covers the original bytes, even on a byte-limit refusal.
	if len(r.callHex) > MaxCallBytes*2 {
		return failure(r, "$adapter", "input.limit"), nil
	}
	call, err := hex.DecodeString(r.callHex)
	if err != nil {
		return Result{}, ErrWire
	}
	v, cond := parse(call, MaxCallBytes)
	if cond != "" {
		return failure(r, "$adapter", cond), nil
	}
	if v.is('[') {
		return failure(r, "$adapter", "adapter.batch"), nil
	}
	if !envelope(v) {
		return failure(r, "$adapter", "adapter.envelope"), nil
	}
	params := v.get("params")
	if params.get("name").text != "make_api_request" {
		return answer(r, Business{"not_applicable", "", "none"}, nil, nil, nil), nil
	}
	args := params.get("arguments")
	cond = shape(args, []field{{"method", 's'}, {"request", '{'}, {"service", 's'}})
	if cond != "" {
		return failure(r, "$adapter", cond), nil
	}
	if args.get("service").text != "refunds" || args.get("method").text != "payment" {
		return failure(r, "$adapter", "adapter.dispatch"), nil
	}
	payload := args.get("request")
	cond = payloadShape(payload)
	if cond != "" {
		return failure(r, "$adapter", cond), nil
	}
	money := payload.get("amount_money")
	amount, ok := unsigned(money.get("amount").text, maxJS, false)
	currency := money.get("currency").text
	key, payment := payload.get("idempotency_key").text, payload.get("payment_id").text
	if len(key) > 45 || len(payment) > 192 {
		return failure(r, "$adapter", "input.limit"), nil
	}
	exp, currencyOK := exponent(currency)
	if !ok || !currencyOK || !identifier(key, 45) || !identifier(payment, 192) {
		return failure(r, "$adapter", "adapter.range"), nil
	}
	keyDigest := digest([]byte(key))
	before, revision, cond := checkState(r, keyDigest, currency)
	if cond != "" {
		return failure(r, "$state", cond), nil
	}
	facts := &Facts{decimal(amount), currency, exp, "submitted-call"}
	business := Business{"satisfied", "", "allow"}
	asks := []Ask{}
	matched := false
	perRun := false
	for _, rule := range b.rules {
		if rule.kind != "currencies" && rule.currency != currency {
			continue
		}
		candidate := Business{"satisfied", rule.id, "allow"}
		switch rule.kind {
		case "currencies":
			if !oneOf(currency, rule.codes...) {
				candidate.Condition = "currencies.not_listed"
				candidate.Verdict = "deny"
			}
		case "per_call":
			if amount > rule.limit {
				candidate.Condition = "per_call.exceeded"
				candidate.Verdict = "deny"
			}
		case "threshold":
			if amount > rule.deny {
				candidate.Condition = "threshold.deny"
				candidate.Verdict = "deny"
			} else if amount > rule.ask {
				candidate.Condition = "threshold.ask"
				candidate.Verdict = "ask"
				asks = append(asks, Ask{candidate.Condition, rule.id})
			}
		case "per_run":
			perRun = true
			if amount > maxMoney-before {
				candidate.Condition = "per_run.overflow"
				candidate.Verdict = "deny"
			} else if before+amount > rule.limit {
				candidate.Condition = "per_run.exceeded"
				candidate.Verdict = "deny"
			}
		}
		if !matched || rank(candidate.Verdict) > rank(business.Verdict) {
			business = candidate
		}
		matched = true
	}
	if business.Verdict != "ask" {
		asks = []Ask{}
	}
	result := answer(r, business, facts, nil, asks)
	if result.Final.Verdict == "allow" && perRun {
		result.Reservation = &Reservation{decimal(before + amount), decimal(amount), decimal(before), currency, keyDigest, revision}
	}
	return result, nil
}

func envelope(v *value) bool {
	if !v.fields("id", "jsonrpc", "method", "params") || v.get("jsonrpc").string() != "2.0" || v.get("method").string() != "tools/call" || !v.get("id").is('i') {
		return false
	}
	if _, ok := unsigned(v.get("id").text, maxJS, false); !ok {
		return false
	}
	p := v.get("params")
	return p.fields("arguments", "name") && p.get("arguments").is('{') && label(p.get("name").string())
}

type field struct {
	name string
	kind byte
}

func shape(v *value, fields []field) string {
	if !v.is('{') {
		return "adapter.type"
	}
	for _, f := range fields {
		if v.get(f.name) == nil {
			return "adapter.missing"
		}
	}
	for _, m := range v.object {
		found := false
		for _, f := range fields {
			found = found || f.name == m.key
		}
		if !found {
			return "adapter.unknown"
		}
	}
	for _, f := range fields {
		if !v.get(f.name).is(f.kind) {
			return "adapter.type"
		}
	}
	return ""
}
func payloadShape(v *value) string {
	parent := shape(v, []field{{"amount_money", '{'}, {"idempotency_key", 's'}, {"payment_id", 's'}})
	child := ""
	if m := v.get("amount_money"); m.is('{') {
		child = shape(m, []field{{"amount", 'i'}, {"currency", 's'}})
	}
	for _, cond := range []string{"adapter.missing", "adapter.unknown", "adapter.type"} {
		if parent == cond || child == cond {
			return cond
		}
	}
	return ""
}

func checkState(r Request, key, currency string) (uint64, string, string) {
	s := r.state
	if s.is('n') {
		return 0, "", "state.unavailable"
	}
	for _, binding := range []struct {
		name, want string
		hash       bool
	}{{"bundle_digest", r.bundleDigest, true}, {"run_id", r.run, false}, {"server", r.server, false}} {
		v := s.get(binding.name)
		valid := v.is('s') && (binding.hash && hashText(v.text) || !binding.hash && label(v.text))
		if valid && v.text != binding.want {
			return 0, "", "state.binding"
		}
	}
	if oneOf(s.get("status").string(), "lost", "unavailable") {
		return 0, "", "state.unavailable"
	}
	if !s.fields("bundle_digest", "epoch", "revision", "run_id", "seen_keys", "server", "status", "totals") || !hashText(s.get("bundle_digest").string()) || !label(s.get("epoch").string()) || !label(s.get("run_id").string()) || !label(s.get("server").string()) || s.get("status").string() != "ready" {
		return 0, "", "state.invalid"
	}
	revision, ok := unsigned(s.get("revision").string(), maxID, true)
	if !ok {
		return 0, "", "state.invalid"
	}
	keys, totals := s.get("seen_keys"), s.get("totals")
	if !keys.is('[') || len(keys.array) > 4096 || !totals.is('[') || len(totals.array) > 4 {
		return 0, "", "state.invalid"
	}
	previous := ""
	replay := false
	for _, k := range keys.array {
		text := k.string()
		if !hashText(text) || text <= previous {
			return 0, "", "state.invalid"
		}
		previous = text
		replay = replay || text == key
	}
	previous = ""
	before := uint64(0)
	for _, total := range totals.array {
		if !total.fields("currency", "minor") {
			return 0, "", "state.invalid"
		}
		code := total.get("currency").string()
		if _, ok := exponent(code); !ok || code <= previous {
			return 0, "", "state.invalid"
		}
		previous = code
		n, ok := money(total.get("minor"))
		if !ok {
			return 0, "", "state.invalid"
		}
		if code == currency {
			before = n
		}
	}
	if replay {
		return 0, "", "state.replay"
	}
	if revision == maxID || len(keys.array) == 4096 {
		return 0, "", "state.capacity"
	}
	return before, decimal(revision), ""
}
func failure(r Request, rule, cond string) Result {
	return answer(r, Business{cond, rule, "deny"}, nil, nil, nil)
}
func answer(r Request, b Business, f *Facts, reservation *Reservation, asks []Ask) Result {
	call, _ := hex.DecodeString(r.callHex) // DecodeRequest already checked lowercase even-length hex.
	coverage := "unknown"
	if b.Verdict == "none" {
		coverage = "none"
	} else if f != nil {
		coverage = "mediated"
	}
	if asks == nil {
		asks = []Ask{}
	}
	return Result{Adapter: r.adapter, Asks: asks, BundleDigest: r.bundleDigest, Business: b, CallDigest: digest(call), Facts: f, Final: Compose(r.contract, b), Record: Record{coverage, "not_attempted", "unknown", true, "evaluated"}, RequestID: r.id, Reservation: reservation, RunID: r.run, Server: r.server, Version: 1}
}

// LocalRefusal is the W022 fixture-only diagnostic projection. Production must
// return ErrWire without an evaluator answer for a malformed outer frame.
// Context must itself be decoded from the fixture's valid diagnostic request.
func LocalRefusal(context Request) (Result, error) {
	if !context.valid {
		return Result{}, ErrWire
	}
	r := failure(context, "$wire", "wire.invalid")
	r.Final = Final{"wire.invalid", "wire", "deny"}
	r.Record.Stage = "not_evaluated"
	return r, nil
}

// validBusiness keeps a malformed caller-created value from manufacturing an
// allow/none barrier. Decoder/status failures use the same closed diagnostics.
func validBusiness(b Business) bool {
	switch b.Verdict {
	case "allow":
		return b.Condition == "satisfied" && (b.RuleID == "" || label(b.RuleID))
	case "none":
		return b.Condition == "not_applicable" && b.RuleID == ""
	case "ask":
		return b.Condition == "threshold.ask" && label(b.RuleID)
	case "deny":
		if label(b.RuleID) {
			return oneOf(b.Condition, "per_call.exceeded", "currencies.not_listed", "threshold.deny", "per_run.exceeded", "per_run.overflow")
		}
		switch b.RuleID {
		case "$bundle":
			return oneOf(b.Condition, "bundle.invalid", "bundle.digest")
		case "$evaluator":
			return len(b.Condition) > 10 && b.Condition[:10] == "evaluator." && condition(b.Condition)
		case "$topology":
			return b.Condition == "topology.unproven"
		case "$adapter":
			return oneOf(b.Condition, "input.json", "input.canonical", "input.duplicate", "input.limit", "adapter.envelope", "adapter.dispatch", "adapter.batch", "adapter.missing", "adapter.unknown", "adapter.type", "adapter.range", "adapter.revision")
		case "$state":
			return oneOf(b.Condition, "state.unavailable", "state.binding", "state.invalid", "state.replay", "state.capacity")
		case "$wire":
			return b.Condition == "wire.invalid"
		}
	}
	return false
}
