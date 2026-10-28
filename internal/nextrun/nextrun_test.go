// SPDX-License-Identifier: Apache-2.0

package nextrun

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestRunTier: an auto contract, or one pinning the run's tier, compiles at the run's tier; a text pinning another
// tier (a free edit) compiles as tego would, not as if the machine built only the run's tier.
func TestRunTier(t *testing.T) {
	cases := []struct {
		run  string
		pin  agent.TierPin
		want backend.Tier
	}{
		{"landlock", "", backend.TierLandlock},
		{"landlock", "auto", backend.TierLandlock},
		{"landlock", "landlock", backend.TierLandlock},
		{"landlock", "cgroup", ""},
		{"", "", ""},
		{"quantum", "", ""},
	}
	for _, c := range cases {
		if got := runTier(c.run, c.pin); got != c.want {
			t.Errorf("runTier(%q, %q) = %q, want %q", c.run, c.pin, got, c.want)
		}
	}
}

// TestCompileOffline: a host name is not resolved at the check (E18), so a name only DNS could refuse compiles, and an
// error carries the compiler's diagnostics.
func TestCompileOffline(t *testing.T) {
	dir := t.TempDir()
	cc := Context{Contract: filepath.Join(dir, "agent.yaml"), Tier: "landlock", PATH: "/usr/bin:/bin"}
	head := "version: 0\nname: n\ncommand: [\"sh\"]\n"
	if _, err := Compile(context.Background(), config.Builtin(), cc, []byte(head+"exec:\n  allow: [sh]\nnet:\n  allow: [\"no-such-host.invalid:443\"]\n")); err != nil {
		t.Errorf("an unresolvable host: %v", err)
	}
	_, err := Compile(context.Background(), config.Builtin(), cc, []byte(head+"exec:\n  allow: [sh, no-such-program-nextrun]\n"))
	if err == nil || !strings.Contains(err.Error(), "no-such-program-nextrun") {
		t.Errorf("a broken entry: %v", err)
	}
	if _, err := Compile(context.Background(), nil, cc, []byte(head)); err == nil {
		t.Error("compiled with no machine config")
	}
}
