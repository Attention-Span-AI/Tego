// SPDX-License-Identifier: Apache-2.0

package web

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/askproto"
)

func TestLocalRolesDashboardPolicyChangedRefusal(t *testing.T) {
	_, err := askproto.DecodeResponse([]byte(`{"error":"policy changed","code":"approval-policy-changed"}`))
	got := answerErr(err)
	for _, want := range []string{"the approval policy file changed since this run started", "tego stop <run>", "relaunch with the same ledger configuration"} {
		if !strings.Contains(got, want) {
			t.Errorf("dashboard policy drift refusal %q lacks %q", got, want)
		}
	}
	if strings.Contains(got, "only root may answer") {
		t.Fatalf("root received the identity remedy for policy drift: %q", got)
	}
	// The same cause can overtake an appended answer, when the ask is terminal.
	// Only requests that remain unanswered can still be pending.
	if !strings.Contains(got, "Any unanswered request remains pending") || strings.Contains(got, "The request remains pending") {
		t.Fatalf("policy drift refusal unconditionally claims the ask is pending: %q", got)
	}
}
