// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/harness"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// R12: budget the complete byte path, including the maximum Linux PID, against
// Claude's fallback threshold rather than just the kernel's sun_path size.
func TestClaudeSocketBudget(t *testing.T) {
	for _, tc := range []struct {
		name, dir string
		ok        bool
	}{
		{"short run", "/run/user/1000/tego/r-00000000-000000000000a-aaaaaa/hook-state", true},
		{"103 bytes", "/" + strings.Repeat("a", 80), true},
		{"104 bytes", "/" + strings.Repeat("a", 81), false},
		{"byte count", "/" + strings.Repeat("é", 41), false},
		{"relative", "short", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkClaudeSocketPath(tc.dir)
			if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrClaudeSocketDir)) {
				t.Fatalf("%q: %v", tc.dir, err)
			}
		})
	}
}

func TestClaudePrivateRuntimeRequest(t *testing.T) {
	for _, tc := range []struct {
		name, value, state string
		h                  harness.Name
		provisioned, ok    bool
	}{
		{"private", "%R", "/run/user/1000/tego/run/hook-state", harness.ClaudeCode, true, true},
		{"explicit short", "/private", "", harness.ClaudeCode, false, true},
		{"legacy long", "/" + strings.Repeat("a", 100), "", harness.ClaudeCode, false, false},
		{"long run base", "%R", "/" + strings.Repeat("a", 100), harness.ClaudeCode, true, false},
		{"no runtime", "%R", "", harness.ClaudeCode, false, false},
		{"dropped provision", "%R", "/state", harness.ClaudeCode, false, false},
		{"other harness", "%R", "/state", harness.Generic, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &agent.RuleTable{Harness: tc.h, Set: map[string]string{"XDG_RUNTIME_DIR": tc.value}}
			r := &runner{rt: rt, cmd: []string{"/bin/claude"}, harness: harnessState{
				stateDir: tc.state, start: &record.HarnessStart{Provisioned: tc.provisioned},
			}}
			err := r.configureClaudeSockets()
			if (err == nil) != tc.ok {
				t.Fatalf("configure: %v", err)
			}
			if rt.Set["XDG_RUNTIME_DIR"] != tc.value {
				t.Fatal("mutated compiled table")
			}
			if tc.ok {
				want := tc.value
				if want == "%R" {
					want = tc.state
				}
				if r.rt.Set["XDG_RUNTIME_DIR"] != filepath.Clean(want) {
					t.Fatalf("resolved to %q", r.rt.Set["XDG_RUNTIME_DIR"])
				}
			}
		})
	}
}
