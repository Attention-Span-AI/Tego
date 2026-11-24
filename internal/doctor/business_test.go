// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func TestBusinessRulesDoctorNeverInfersReadinessFromTier(t *testing.T) {
	for _, root := range []bool{false, true} {
		rep := state(func(st *probeState) { st.root = root }).report(nil, "")
		if rep.BusinessRules.Ready || rep.BusinessRules.Profile != "trusted-stdio-worker-v1" || rep.BusinessRules.Reason != agent.BusinessRulesUnavailable {
			t.Fatalf("false readiness: %+v", rep.BusinessRules)
		}
		var out bytes.Buffer
		if err := rep.WriteText(&out); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "business rules: "+agent.BusinessRulesUnavailable) {
			t.Fatal(out.String())
		}
		b, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		var back Report
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if back.BusinessRules != rep.BusinessRules {
			t.Fatalf("doctor JSON lost business capability: %s", b)
		}
	}
}
