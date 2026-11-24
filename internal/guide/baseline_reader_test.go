// SPDX-License-Identifier: Apache-2.0

package guide

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

func TestBaselineGuideRefuses(t *testing.T) {
	data, err := os.ReadFile("../../spec/record/v1/fixtures/baseline/applied.jsonl")
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
	dir := t.TempDir()
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), append(tc.Line, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			fact := tc.Fact[strings.LastIndex(tc.Fact, ".")+1:]
			got, err := readRun(dir, event.Run)
			if err == nil || got != nil || !strings.Contains(err.Error(), fact) {
				t.Fatalf("guide accepted evidence or lost refusal %s: %+v %v", fact, got, err)
			}
		})
	}
}
