// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestComputeCtxStopsOnCancel is R29 for drift: a cancelled context ends the scan with its error, not a report.
func TestComputeCtxStopsOnCancel(t *testing.T) {
	var b strings.Builder
	for i := 1; i <= 3*ctxEvery; i++ {
		b.WriteString(execLine(i, "exec[python3.12]", "allow", "/usr/bin/python3.12", false))
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if rep, err := ComputeCtx(ctx, r, &agent.RuleTable{}); !errors.Is(err, context.Canceled) || rep != nil {
		t.Errorf("ComputeCtx = %v, %v; want nil and context.Canceled", rep, err)
	}
}
