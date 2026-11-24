// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestAdoptionChecksEffectiveBaselineEnvironment(t *testing.T) {
	rt := compileAdoptTable(t, "")
	cp := *rt.Contract
	cp.Env.Deny = []string{"PROD_TOKEN"}
	rt.EffectiveContract = &cp
	if got := strings.Join(unenforceableForAdoption(rt), "\n"); !strings.Contains(got, "environment cannot be changed") {
		t.Fatalf("effective environment baseline ignored: %s", got)
	}
}

func TestAdoptionRefusesAbsentBaselineReadGuard(t *testing.T) {
	rt := compileAdoptTable(t, "")
	rt.Baseline = &agent.BaselineTable{Applied: true, Entries: []agent.BaselineRule{{ResolvedBaselineEntry: config.ResolvedBaselineEntry{
		BaselineEntry: config.BaselineEntry{Key: config.BaselineDenyRead, Value: "/missing-system-secret"}, State: config.LayerAbsent,
	}}}}
	if got := strings.Join(unenforceableForAdoption(rt), "\n"); !strings.Contains(got, "ancestor/name guard") {
		t.Fatalf("absent system baseline read accepted for attachment: %s", got)
	}
}
