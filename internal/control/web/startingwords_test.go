// SPDX-License-Identifier: Apache-2.0

package web

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/mcpact"
	"github.com/attention-span-ai/tego/internal/control/routeact"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/liveblock"
)

// TestAChangeWhileARunStartsIsNeverSaidLocked: the dashboard's lift, restore, MCP switch and model route say a refusal
// for a run whose run_start cannot be read yet (runact.ErrStarting) in their own words, never the Locked words, as
// tego lift, tego mcp and tego route set do (acceptance 2B, 2026-11-11). The Block now panel's flash reads the same
// sentinel (actions.go).
func TestAChangeWhileARunStartsIsNeverSaidLocked(t *testing.T) {
	err := liveblock.CheckLoosening(liveblock.Target{Run: "r-x", Running: true, Starting: true})
	for name, got := range map[string]string{
		"lift":  liftErr(err),
		"mcp":   mcpErrWords(err),
		"route": routesErrWords(err),
	} {
		if got != startingWords || got == lockedWords {
			t.Errorf("%s: %q, want %q", name, got, startingWords)
		}
	}
	if mcpact.ErrStarting != runact.ErrStarting || routeact.ErrStarting != runact.ErrStarting {
		t.Error("the services' ErrStarting is not runact's")
	}

	// A first line that is there and cannot be read: its own words, which never say to try again (the review's S1).
	err = liveblock.CheckLoosening(liveblock.Target{Run: "r-x", Running: true, Starting: true, StartUnreadable: true})
	for name, got := range map[string]string{
		"lift":  liftErr(err),
		"mcp":   mcpErrWords(err),
		"route": routesErrWords(err),
	} {
		if got != unreadableStartWords || strings.Contains(got, "try again") {
			t.Errorf("%s: %q, want %q", name, got, unreadableStartWords)
		}
	}
	if mcpact.ErrStartUnreadable != runact.ErrStartUnreadable || routeact.ErrStartUnreadable != runact.ErrStartUnreadable {
		t.Error("the services' ErrStartUnreadable is not runact's")
	}
}
