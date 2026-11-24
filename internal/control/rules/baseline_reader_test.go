// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBaselineBuilderAndStartRefuse(t *testing.T) {
	data, err := os.ReadFile("../../../spec/record/v1/fixtures/baseline/applied.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	good := bytes.Split(data, []byte{'\n'})[0]
	event, err := record.Decode(good)
	if err != nil {
		t.Fatal(err)
	}
	cases, err := testutil.BaselineCases(good)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	dir := filepath.Join(root, event.Run)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	subset := 0
	if raceEnabled {
		subset = testutil.ShuffleOffset(t, 4) // which fourth: the -shuffle seed's, so a few runs cover all of them
	}
	for i, tc := range cases {
		if raceEnabled && i%4 != subset { // 333 cases at about 1.1 s each in a race build (a race-instrumented helper per call): every fourth there, all in the others
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), append(tc.Line, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			fact := tc.Fact[strings.LastIndex(tc.Fact, ".")+1:]
			if _, err := readStartAt(dir, false); err == nil || !strings.Contains(err.Error(), fact) {
				t.Fatalf("start reader lost refusal %s: %v", fact, err)
			}
			service := Service{Ledger: root}
			plan := NewPlan{FromRun: event.Run, Name: "refused"}
			if res := service.fromRun(t.Context(), &plan, nil); res != nil || !strings.Contains(strings.Join(plan.Problems, "; "), fact) {
				t.Fatalf("builder lost refusal %s: result=%+v problems=%v", fact, res, plan.Problems)
			}
		})
	}
}
