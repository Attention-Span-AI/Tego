// SPDX-License-Identifier: Apache-2.0

package cireceipt

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/testutil"
)

func TestBaselineRawCIVerifierRefuses(t *testing.T) {
	data, err := os.ReadFile("../../../spec/record/v1/fixtures/baseline/applied.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	cases, err := testutil.BaselineCases(bytes.Split(data, []byte{'\n'})[0])
	if err != nil {
		t.Fatal(err)
	}
	rc := receipt.Receipt{V: receipt.Version, Binding: &receipt.Binding{V: receipt.BaselineBindingVersion, Chain: &receipt.BoundChain{}}}
	encoded, err := json.Marshal(rc)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			v := verifier{res: &Result{}, f: &frozen{files: map[string][]byte{"receipt.json": encoded, "run/events.jsonl": append(tc.Line, '\n')}}}
			v.record()
			for _, c := range v.res.Checks {
				if c.Name == "run-start" && c.Result == receipt.StepFail && strings.Contains(c.Why, tc.Fact[strings.LastIndex(tc.Fact, ".")+1:]) {
					return
				}
			}
			t.Fatalf("CI reader lost refusal reason: %+v", v.res.Checks)
		})
	}
}
