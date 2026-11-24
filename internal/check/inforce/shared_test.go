// SPDX-License-Identifier: Apache-2.0

package inforce

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/compiledview"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The overlay verification runs this against the original implementation too,
// checking every serialized field rather than only the command's sentence subset.
func TestCompiledProjectionPreservesView(t *testing.T) {
	f := newFixture(t)
	for _, text := range []string{f.supplyChain(t), commandRules} {
		rt := f.compile(t, text, nil)
		for _, tier := range backend.Tiers() {
			for _, plane := range []string{"", record.DecisionPlaneLSM, record.DecisionPlaneFmodRet} {
				shared, err := json.Marshal(compiledview.Of(rt, tier, plane))
				if err != nil {
					t.Fatal(err)
				}
				facade, err := json.Marshal(Of(rt, tier, plane))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(shared, facade) {
					t.Errorf("tier %s plane %q: shared projection differs\nshared: %s\noriginal: %s", tier, plane, shared, facade)
				}
			}
		}
	}
}
