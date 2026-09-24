// SPDX-License-Identifier: Apache-2.0

package status

import (
	"fmt"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestDeriveReadsTheCapabilityLine is R-cap's read half: the snapshot carries run_start's tier and capability
// line exactly as recorded, so a view never recomputes what a tier could do from the machine it runs on.
// (limits-check-doctor-cli.md R-cap.)
func TestDeriveReadsTheCapabilityLine(t *testing.T) {
	line := map[string]bool{}
	for _, c := range backend.AllCapabilities() {
		line[string(c)] = true
	}
	line[string(backend.CapReadDeny)] = false
	dir := write(t, false, func(w *ledger.Writer) {
		if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "landlock",
			Capabilities: line}); err != nil {
			t.Fatal(err)
		}
	}, &record.RunEndPayload{Reason: record.RunEndExit})
	s := derive(t, dir, false, base, 0)
	if s.Tier != "landlock" || len(s.Capabilities) != len(line) || s.Capabilities[string(backend.CapReadDeny)] {
		t.Fatalf("snapshot tier %q capabilities %v, want run_start's own", s.Tier, s.Capabilities)
	}
	if got, want := CapabilityLine(s.Tier, s.Capabilities), fmt.Sprintf("landlock %d/%d; absent: fs.deny_read", len(line)-1, len(line)); got != want {
		t.Fatalf("line %q, want %q", got, want)
	}

	old := write(t, false, runStart(""), &record.RunEndPayload{Reason: record.RunEndExit})
	if s := derive(t, old, false, base, 0); s.Capabilities != nil {
		t.Fatalf("a run_start with no line gave capabilities %v", s.Capabilities)
	}
}

// TestCapabilityLine is the rendering: absent rows by name in CAPABILITIES.md order, a newer writer's rows
// kept rather than dropped, and an older writer's missing line never shown as a run that could do nothing.
// (limits-check-doctor-cli.md R-cap.)
func TestCapabilityLine(t *testing.T) {
	cases := []struct {
		name string
		tier string
		caps map[string]bool
		want string
	}{
		{"not recorded", "landlock", nil, "not recorded"},
		{"everything", "cgroup", map[string]bool{"fs.deny_write": true, "exec.deny": true}, "cgroup 2/2"},
		{"matrix order, not map order", "landlock",
			map[string]bool{"capture.model_traffic": false, "fs.deny_read": false, "exec.deny": true},
			"landlock 1/3; absent: fs.deny_read, capture.model_traffic"},
		{"a row this binary does not know is kept", "landlock",
			map[string]bool{"fs.deny_write": true, "zz.future": false, "aa.future": false},
			"landlock 1/3; absent: aa.future, zz.future"},
		{"an empty line is a run that could do nothing", "observe", map[string]bool{}, "observe 0/0"},
		{"no tier", "", map[string]bool{"ask": false}, "0/1; absent: ask"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CapabilityLine(tc.tier, tc.caps); got != tc.want {
				t.Fatalf("CapabilityLine = %q, want %q", got, tc.want)
			}
		})
	}
}
