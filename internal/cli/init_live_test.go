// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestInitLiveModeLockedIsToday: --live-mode locked writes the agent.yaml init always wrote, byte for byte, with and
// without --preset (ADR 0125 R1).
func TestInitLiveModeLockedIsToday(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	fixedEnviron(t)
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup)
	for _, preset := range []string{"", "no-secrets"} {
		t.Run("preset="+preset, func(t *testing.T) {
			read := func(args ...string) string {
				dir := presetProject(t)
				all := append([]string{"init"}, args...)
				if preset != "" {
					all = append(all, "--preset", preset, "--write", "src", "--allow-host", "127.0.0.1:8080")
				}
				code, out, errs := run(t, append(all, dir)...)
				if code != identity.ExitOK || errs != "" {
					t.Fatalf("init %v: exit %d\n%s\n%s", args, code, out, errs)
				}
				b, err := os.ReadFile(filepath.Join(dir, "agent.yaml"))
				if err != nil {
					t.Fatal(err)
				}
				// The whole path first: t.TempDir's numbered base (001) can also occur in its parent's random digits.
				return strings.ReplaceAll(strings.ReplaceAll(string(b), dir, "<dir>"), filepath.Base(dir), "<dir>")
			}
			if today, locked := read("--name", "same"), read("--name", "same", "--live-mode", "locked"); today != locked {
				t.Errorf("--live-mode locked changed the contract:\n%s\nvs\n%s", today, locked)
			}
		})
	}
}

// TestInitLiveModeAdjustableCompiles: --live-mode adjustable appends the live: block, the result compiles as an
// Adjustable contract (with --preset too), and a re-run says the flag was not applied.
func TestInitLiveModeAdjustableCompiles(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	fixedEnviron(t)
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup)
	for _, preset := range []string{"", "no-secrets,repo-only-writes"} {
		t.Run("preset="+preset, func(t *testing.T) {
			dir := presetProject(t)
			args := []string{"init", "--live-mode", "adjustable"}
			if preset != "" {
				args = append(args, "--preset", preset, "--write", "src", "--allow-host", "127.0.0.1:8080")
			}
			code, out, errs := run(t, append(args, dir)...)
			if code != identity.ExitOK || errs != "" {
				t.Fatalf("init: exit %d\n%s\n%s", code, out, errs)
			}
			if !strings.Contains(out, "live mode: adjustable (live both ways)") || !strings.Contains(out, "need root") {
				t.Errorf("init printed:\n%s", out)
			}
			b, err := os.ReadFile(filepath.Join(dir, "agent.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(string(b), liveAdjustableBlock) || !strings.Contains(string(b), "docs/user/live-modes.md") {
				t.Errorf("agent.yaml lacks the live block:\n%s", b)
			}
			// tier: auto compiles: a run that lands at tier landlock is the launcher's to refuse (LiveTierCheck).
			code, out, errs = run(t, "compile", "agent.yaml", "--offline")
			if code != identity.ExitOK || strings.Contains(errs, "error") || !strings.Contains(errs, "live.mode: adjustable") ||
				!strings.Contains(out, "live      adjustable (live both ways)") || !strings.Contains(out, "fence     0 entries") {
				t.Fatalf("compile: exit %d\n%s\n%s", code, out, errs)
			}
			code, out, _ = run(t, append(args, dir)...)
			if code != identity.ExitOK || !strings.Contains(out, "--live-mode adjustable was not applied") {
				t.Errorf("second init: exit %d\n%s", code, out)
			}
		})
	}
}

// TestInitLiveModeRefusesOtherValues: --live-mode takes locked or adjustable only.
func TestInitLiveModeRefusesOtherValues(t *testing.T) {
	dir := presetProject(t)
	code, _, errs := run(t, "init", "--live-mode", "both", dir)
	if code != identity.ExitUsage || !strings.Contains(errs, "not locked or adjustable") {
		t.Errorf("exit %d\n%s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(dir, "agent.yaml")); !os.IsNotExist(err) {
		t.Errorf("agent.yaml written: %v", err)
	}
}

// TestWithLiveModePinsARootTier: a template that pins tier: landlock, where Adjustable is refused, gets tier: cgroup
// under Adjustable and keeps its line under Locked.
func TestWithLiveModePinsARootTier(t *testing.T) {
	in := []byte("version: 0\ntier: landlock   # pinned\nrecord: full")
	if out, pinned := withLiveMode(in, agent.LiveLocked); string(out) != string(in) || pinned {
		t.Errorf("locked: %q %v", out, pinned)
	}
	out, pinned := withLiveMode(in, agent.LiveAdjustable)
	if !pinned || !strings.Contains(string(out), "tier: cgroup   # pinned\n") || strings.Contains(string(out), "tier: landlock") ||
		!strings.HasSuffix(string(out), liveAdjustableBlock) {
		t.Errorf("adjustable: %q %v", out, pinned)
	}
	if _, pinned := withLiveMode([]byte("tier: landlockx\n"), agent.LiveAdjustable); pinned {
		t.Error("rewrote a line that only starts like tier: landlock")
	}
}
