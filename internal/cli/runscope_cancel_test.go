// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

func TestScopeProcessCancellationNeverCommits(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	old := scopeCommandFor
	t.Cleanup(func() { scopeCommandFor = old })
	scopeCommandFor = func(string, ...string) *proc.Cmd {
		cancel()
		return proc.Command(os.Args[0])
	}
	var out bytes.Buffer
	_, err := executeUserScope(ctx, scopePlan{Env: append(os.Environ(), "TEGO_SCOPE_TEST_HELPER=success")}, &out)
	if !errors.Is(err, context.Canceled) || out.Len() != 0 {
		t.Fatalf("canceled handshake committed: %v %q", err, out.String())
	}
}
