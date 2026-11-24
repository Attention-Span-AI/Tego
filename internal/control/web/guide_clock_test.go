// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/pathcheck"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
	"github.com/attention-span-ai/tego/internal/scan/result"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestGuideCallerEvaluationTimePreservesScanFreshness(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	f.PutScan(t, "a")
	// Keep the saved scan fresh at the selected caller time and stale at any
	// worker wall clock during this test, without depending on the calendar.
	path := filepath.Join(f.Home, ".tego", "scan", "last.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot result.Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	saved := time.Now().Add(-time.Hour).Truncate(time.Second)
	snapshot.Started, snapshot.Finished = saved, saved
	data, err = result.Encode(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	caller := config.CaptureCaller()
	caller.CheckedAt = saved.Add(time.Minute)
	ctx := contracts.ContextWithCaller(context.Background(), caller)
	for _, explicit := range []bool{false, true} {
		name := "caller-default"
		if explicit {
			name = "explicit-override"
		}
		t.Run(name, func(t *testing.T) {
			in := f.Inputs(t)
			in.Caller = &caller
			in.Now = time.Time{}
			evaluation := caller.CheckedAt
			if explicit {
				evaluation = saved.Add(10 * time.Minute)
				in.Now = evaluation
			}
			expectedInputs := in
			expectedInputs.Now = evaluation
			expected := guide.Compute(ctx, expectedInputs)
			found := false
			for _, step := range expected.Steps {
				if step.ID == guide.StepFind && step.State == guide.Done {
					found = true
				}
			}
			if found == explicit {
				t.Fatalf("freshness control is wrong: explicit=%t found=%t", explicit, found)
			}
			want, err := json.Marshal(expected)
			if err != nil {
				t.Fatal(err)
			}
			direct, err := json.Marshal(guide.Compute(ctx, in))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(direct, want) {
				t.Error("in-process guide ignored the selected caller evaluation time")
			}
			actual, built, err := checkedGuide(ctx, in)
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.Marshal(actual)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) || built != expected.Next.Built() {
				t.Error("helper guide ignored the selected caller evaluation time")
			}
			keys, err := checkedGuideKeys(ctx, in)
			if err != nil {
				t.Fatal(err)
			}
			wantKey := guide.ReadScan(in.Home, in.UID, in.Host.BootID, evaluation).Key()
			if keys.Scan != wantKey {
				t.Errorf("helper freshness key=%q want=%q", keys.Scan, wantKey)
			}
		})
	}
}

func TestGuideHelpersRequireEvaluationTime(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	caller := config.CaptureCaller()
	ctx := contracts.ContextWithCaller(context.Background(), caller)
	in := f.Inputs(t)
	in.Caller, in.Machine, in.Now = &caller, nil, time.Time{}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"control.guide", "control.guide-key"} {
		t.Run(operation, func(t *testing.T) {
			var reply any = new([]byte)
			var request any = guideRequest{Inputs: data}
			if operation == "control.guide-key" {
				request = guideFileRequest{Home: f.Home, UID: in.UID, Boot: in.Host.BootID}
				reply = new(guideFileKeys)
			}
			err := pathcheck.Call(ctx, operation, request, reply)
			if err == nil || !strings.Contains(err.Error(), "missing guide evaluation time") {
				t.Fatalf("helper accepted a missing evaluation time: %v", err)
			}
		})
	}
}
