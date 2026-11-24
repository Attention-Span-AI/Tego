// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/handoff"
	"strings"
	"testing"
)

func TestPrivateFilesystemHelperKeepsControlPrivilegeGuard(t *testing.T) {
	for _, p := range []privilege{{euid: 0}, {euid: 1000, effective: 1}, {euid: 1000, permitted: 1}} {
		var stdout, stderr bytes.Buffer
		code := mainWith(context.Background(), []string{handoff.Name, contracts.HelperCommand, "invalid-test-mode"}, &stdout, &stderr, p)
		if code != handoff.Exit(handoff.CodeAsRoot) || !strings.Contains(stderr.String(), handoff.CodeAsRoot) {
			t.Fatalf("privilege %+v: code=%d stderr=%q", p, code, stderr.String())
		}
	}
}
