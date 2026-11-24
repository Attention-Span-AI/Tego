// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/testutil"
)

func TestBaselineRawOriginRefuses(t *testing.T) {
	data, err := os.ReadFile("../../spec/record/v1/fixtures/baseline/applied.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	cases, err := testutil.BaselineCases(bytes.Split(data, []byte{'\n'})[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), append(tc.Line, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			r, err := ledger.OpenReader(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			// CLI drift's historical/sealed compiler consumes this origin.
			origin, err := readRunOrigin(r)
			if err == nil || !strings.Contains(err.Error(), tc.Fact[strings.LastIndex(tc.Fact, ".")+1:]) || origin.start != nil {
				t.Fatalf("origin accepted invalid evidence or lost its reason: %+v, %v", origin, err)
			}
		})
	}
}

func TestBaselineScanAndSessionRefuse(t *testing.T) {
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
	root := t.TempDir()
	dir := filepath.Join(root, event.Run)
	w, err := ledger.Open(dir, record.RunRef{ID: event.Run, Agent: event.Agent})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Abandon() }()
	path := filepath.Join(dir, ledger.EventsFile)
	if err := os.WriteFile(path, append(good, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if sessionAgent(dir, event.Run) != event.Agent {
		t.Fatal("valid session identity refused")
	}
	if ok, reason := scanRecordProbe(t.Context(), root, event.Run, time.Now()); !ok {
		t.Fatalf("valid scan refused: %s", reason)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			if err := os.WriteFile(path, append(tc.Line, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			if got := sessionAgent(dir, event.Run); got != "" {
				t.Fatalf("refused evidence supplied session identity %q", got)
			}
			if ok, reason := scanRecordProbe(t.Context(), root, event.Run, time.Now()); ok || reason != "syntax" {
				t.Fatalf("refused evidence promoted by scan: %t %s", ok, reason)
			}
		})
	}
}
