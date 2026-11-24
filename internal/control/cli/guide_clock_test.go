// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestGuideInputsUseCallerEvaluationTime(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	caller := config.CaptureCaller()
	caller.CheckedAt = time.Now().Add(-time.Hour)
	caller.PATH = filepath.Join(f.Root, "absent-bin")
	original := selfExecutable
	selfExecutable = func() (string, error) { return filepath.Join(f.Root, "absent-self"), nil }
	defer func() { selfExecutable = original }()
	ctx := contracts.ContextWithCaller(context.Background(), caller)
	in := guideInputs(f.Machine(t), f.Ledger, f.Anchor)(ctx)
	if !in.Now.Equal(caller.CheckedAt) {
		t.Fatalf("guide evaluation time=%s want caller %s", in.Now, caller.CheckedAt)
	}
}
