// SPDX-License-Identifier: Apache-2.0

package bizrule

import (
	"bytes"
	"strings"
	"testing"
)

func TestGrammarPrecedenceAndBounds(t *testing.T) {
	for _, test := range []struct{ name, input, want string }{
		{"complete grammar before duplicate", `{"a":0,"a":1}x`, "input.json"},
		{"surrogate grammar before duplicate", `{"a":0,"a":"\ud800"}`, "input.json"},
		{"duplicate before spelling", `{"a":0,"\u0061":1.0}`, "input.duplicate"},
		{"canonical before shape", `{"amount":-0}`, "input.canonical"},
		{"all depths checked", strings.Repeat("[", 30000) + "0" + strings.Repeat("]", 30000), "input.limit"},
		{"deep malformed grammar wins", strings.Repeat("[", 30000) + "0" + strings.Repeat("]", 29999), "input.json"},
		{"depth sixteen", strings.Repeat("[", 16) + "null" + strings.Repeat("]", 16), ""},
		{"depth seventeen", strings.Repeat("[", 17) + "null" + strings.Repeat("]", 17), "input.limit"},
		{"valid surrogate pair noncanonical", `"\ud83d\ude00"`, "input.canonical"},
		{"low surrogate", `"\udc00"`, "input.json"},
		{"number token", `1e0`, "input.canonical"},
		{"number grammar", `01`, "input.json"},
		{"trailing comma object", `{"a":0,}`, "input.json"},
		{"trailing comma array", `[0,]`, "input.json"},
		{"raw newline string", "\"a\nb\"", "input.json"},
		{"escaped solidus", `"\/"`, "input.canonical"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, got := parse([]byte(test.input), MaxCallBytes)
			if got != test.want {
				t.Fatalf("got %s want %s", got, test.want)
			}
		})
	}
	if _, got := parse(bytes.Repeat([]byte{'x'}, MaxCallBytes+1), MaxCallBytes); got != "input.limit" {
		t.Fatal(got)
	}
}

func TestZeroValuesRefuse(t *testing.T) {
	if _, err := Evaluate(nil, Request{}); err != ErrWire {
		t.Fatal(err)
	}
	if _, err := EvaluateBundle(Bundle{}, Request{}); err != ErrWire {
		t.Fatal(err)
	}
	if _, err := LocalRefusal(Request{}); err != ErrWire {
		t.Fatal(err)
	}
	if _, err := EncodeResult(Result{}); err != ErrResult {
		t.Fatal(err)
	}
}

func TestCompositionAllInputs(t *testing.T) {
	for _, contract := range []string{"allow", "ask", "deny", "unknown", "garbage", ""} {
		for _, business := range []string{"allow", "none", "ask", "deny", "garbage", ""} {
			b := Business{"satisfied", "cap", business}
			if business == "none" {
				b = Business{"not_applicable", "", "none"}
			}
			if business == "ask" {
				b.Condition = "threshold.ask"
			}
			if business == "deny" {
				b.Condition = "per_call.exceeded"
			}
			got := Compose(contract, b)
			if !oneOf(got.Verdict, "allow", "ask", "deny") || rank(got.Verdict) < rank(contract) || rank(got.Verdict) < rank(business) {
				t.Fatalf("%s/%s => %+v", contract, business, got)
			}
		}
	}
}

func TestImmutableInputsAndCompleteAskSet(t *testing.T) {
	var found bool
	for _, f := range fixtures(t) {
		if f.ID != "m25-two-asks-first-id" {
			continue
		}
		found = true
		raw, wire := fixtureWires(t, f)
		b, err := DecodeBundle(raw)
		if err != nil {
			t.Fatal(err)
		}
		r, err := DecodeRequest(wire)
		if err != nil {
			t.Fatal(err)
		}
		before, err := EvaluateBundle(b, r)
		if err != nil {
			t.Fatal(err)
		}
		if len(before.Asks) != 2 {
			t.Fatal(before.Asks)
		}
		for i := range raw {
			raw[i] = 0
		}
		for i := range wire {
			wire[i] = 0
		}
		copyBundle, copyRequest := b.Canonical(), r.Canonical()
		for i := range copyBundle {
			copyBundle[i] = 0
		}
		for i := range copyRequest {
			copyRequest[i] = 0
		}
		after, err := EvaluateBundle(b, r)
		if err != nil {
			t.Fatal(err)
		}
		a, err := EncodeResult(before)
		if err != nil {
			t.Fatal(err)
		}
		z, err := EncodeResult(after)
		if err != nil || !bytes.Equal(a, z) {
			t.Fatal("caller mutation changed pinned meaning")
		}
	}
	if !found {
		t.Fatal("missing complete ask fixture")
	}
}

func TestMalformedBusinessCompositionRefuses(t *testing.T) {
	for _, b := range []Business{
		{"garbage", "cap", "allow"},
		{"threshold.deny", "cap", "none"},
		{"threshold.ask", "", "ask"},
		{"satisfied", "$bundle", "allow"},
	} {
		if got := Compose("allow", b); got.Verdict != "deny" {
			t.Fatalf("malformed business %+v composed to %+v", b, got)
		}
	}
}
