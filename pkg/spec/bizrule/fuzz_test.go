// SPDX-License-Identifier: Apache-2.0

package bizrule

import (
	"bytes"
	"testing"
)

// FuzzDecoders keeps bundle and request inputs independent. Every accepted
// input must round-trip byte-for-byte; malformed frames never become answers.
func FuzzDecoders(f *testing.F) {
	for _, v := range fixtures(f) {
		b, r := fixtureWires(f, v)
		f.Add(b, r)
	}
	f.Fuzz(func(t *testing.T, b, r []byte) {
		if bundle, err := DecodeBundle(b); err == nil {
			if !bytes.Equal(bundle.Canonical(), b) || bundle.Digest() != digest(b) {
				t.Fatal("bundle identity")
			}
			again, err := DecodeBundle(bundle.Canonical())
			if err != nil || again.Digest() != bundle.Digest() {
				t.Fatal("bundle round trip")
			}
		}
		if request, err := DecodeRequest(r); err == nil {
			if !bytes.Equal(request.Canonical(), r) {
				t.Fatal("request identity")
			}
			if _, err := DecodeRequest(request.Canonical()); err != nil {
				t.Fatal("request round trip")
			}
		}
	})
}

func FuzzEvaluation(f *testing.F) {
	for _, v := range fixtures(f) {
		b, r := fixtureWires(f, v)
		f.Add(b, r, []byte{0})
		// Derive b02 with state pinned to its contract, then change only bundle
		// bytes between evaluations. A bundle error is not a request refusal.
		if v.ID == "b02-changed-cap-stale-digest" {
			index := bytes.Index(b, []byte("20000"))
			if index < 0 || index > 255 {
				f.Fatal("missing stale cap")
			}
			request, cond := parse(r[:len(r)-1], MaxRequestFrameBytes-1)
			if cond != "" {
				f.Fatal(cond)
			}
			request.get("state").get("bundle_digest").text = request.get("contract_bundle_digest").text
			f.Add(b, append(appendValue(nil, request), '\n'), []byte{byte(index), 0})
		}
	}
	f.Fuzz(func(t *testing.T, b, wire, mutation []byte) {
		r, err := DecodeRequest(wire)
		if err != nil {
			if _, err := Evaluate(b, r); err != ErrWire {
				t.Fatal("invalid request got an answer")
			}
			return
		}
		result, err := Evaluate(b, r)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := EncodeResult(result)
		if err != nil {
			t.Fatal(err)
		}
		again, err := Evaluate(b, r)
		if err != nil {
			t.Fatal(err)
		}
		againBytes, err := EncodeResult(again)
		if err != nil || !bytes.Equal(encoded, againBytes) {
			t.Fatal("nondeterministic evaluation")
		}
		if rank(result.Final.Verdict) < rank(r.contract) || rank(result.Final.Verdict) < rank(result.Business.Verdict) {
			t.Fatal("composition loosened a floor")
		}
		for _, contract := range []string{"allow", "ask", "deny", "unknown", "invalid"} {
			final := Compose(contract, result.Business)
			if rank(final.Verdict) < rank(contract) || rank(final.Verdict) < rank(result.Business.Verdict) {
				t.Fatal("composition monotonicity")
			}
		}
		if len(mutation) == 0 {
			return
		}
		bundle, bundleErr := DecodeBundle(b)
		// Starting with the valid pinned bundle, any replacement either has
		// the pinned bytes or refuses digest validation. A bundle error itself
		// can legitimately be corrected by supplying the right pinned bytes.
		candidate := b
		if len(b) > 0 {
			candidate = append([]byte{}, b...)
			i := int(mutation[0]) % len(candidate)
			candidate[i] ^= byte(1 + len(mutation)%255)
		}
		replaced, err := Evaluate(candidate, r)
		if err != nil {
			t.Fatal(err)
		}
		if bundleErr == nil && bundle.Digest() == r.bundleDigest && result.Final.Verdict == "deny" && replaced.Final.Verdict != "deny" {
			t.Fatal("replacement cured a refusal")
		}
		if bundleErr != nil || bundle.Digest() != r.bundleDigest || result.Facts == nil {
			return
		}
		// A validated request's selector and trusted state bindings stay fixed.
		// Do not cure any malformed state by changing its bundle binding. Extend
		// every valid rule kind, repin both request and state to the new canonical
		// bundle, then evaluate. This avoids vacuous digest-error monotonicity.
		if len(bundle.rules) == 32 {
			return
		}
		for _, kind := range []string{"per_call", "per_run", "currencies", "threshold"} {
			extended, updated, ok := addRule(bundle, r, kind, mutation)
			if !ok {
				continue
			}
			after, err := EvaluateBundle(extended, updated)
			if err != nil {
				t.Fatal(err)
			}
			if rank(after.Business.Verdict) < rank(result.Business.Verdict) || rank(after.Final.Verdict) < rank(result.Final.Verdict) {
				t.Fatalf("adding %s loosened %s to %s", kind, result.Business.Verdict, after.Business.Verdict)
			}
		}
	})
}

// addRule edits wire values only, then re-enters both public decoders. It never
// shares production predicate logic. A leading/new label is found even for a
// maximal existing rule ID; sorting is performed by insertion.
func addRule(b Bundle, r Request, kind string, mutation []byte) (Bundle, Request, bool) {
	v, cond := parse(b.Canonical(), MaxBundleBytes)
	if cond != "" {
		return Bundle{}, Request{}, false
	}
	rules := v.get("rules")
	id := "0"
	for {
		exists := false
		for _, rule := range rules.array {
			exists = exists || rule.get("id").string() == id
		}
		if !exists {
			break
		}
		id += "0"
		if len(id) > 64 {
			return Bundle{}, Request{}, false
		}
	}
	currencies := []string{"CAD", "JPY", "KWD", "USD"}
	currency := currencies[int(mutation[0])%4]
	limit := uint64(mutation[0])
	if len(mutation) > 1 {
		limit = limit*256 + uint64(mutation[1])
	}
	var row *value
	switch kind {
	case "currencies":
		row = object(member{"codes", &value{kind: '[', array: []*value{stringValue(currency)}}}, pair("id", id), pair("kind", kind))
	case "threshold":
		row = object(pair("ask_above", decimal(limit)), pair("currency", currency), pair("deny_above", decimal(limit+1)), pair("id", id), pair("kind", kind))
	default:
		row = object(pair("currency", currency), pair("id", id), pair("kind", kind), pair("limit", decimal(limit)))
	}
	index := 0
	for index < len(rules.array) && rules.array[index].get("id").string() < id {
		index++
	}
	rules.array = append(rules.array, nil)
	copy(rules.array[index+1:], rules.array[index:])
	rules.array[index] = row
	extended, err := DecodeBundle(appendValue(nil, v))
	if err != nil {
		return Bundle{}, Request{}, false
	}
	req, cond := parse([]byte(r.raw[:len(r.raw)-1]), MaxRequestFrameBytes-1)
	if cond != "" {
		return Bundle{}, Request{}, false
	}
	req.get("contract_bundle_digest").text = extended.Digest()
	// Preserve an existing invalid/mismatched binding's refusal. Only the exact
	// old digest is rebased, including all valid snapshots used by the vectors.
	if state := req.get("state"); state.is('{') {
		if d := state.get("bundle_digest"); d.is('s') && d.text == b.Digest() {
			d.text = extended.Digest()
		}
	}
	updated, err := DecodeRequest(append(appendValue(nil, req), '\n'))
	return extended, updated, err == nil
}
