// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// The administrator's opt-in must survive canonicalization (and therefore the
// contract hash) and be disclosed even for legacy ask completions without a deputy.
func TestAppArmorNamespaceOptIn(t *testing.T) {
	f := newFixture(t)
	for _, enabled := range []bool{false, true} {
		src := "version: 0\nname: t\ncommand: [python]\nfs:\n  apparmor_assume_root_namespace: false\n"
		if enabled {
			src = strings.Replace(src, ": false", ": true", 1)
		}
		c := f.load(src)
		rt, ds := f.compile(c)
		if got := slices.Contains(rt.BestEffortCellsRun(backend.TierLandlock, "", false, false), "apparmor/assumed-root-namespace"); got != enabled {
			t.Errorf("enabled=%t: run record disclosure=%t", enabled, got)
		}
		b, err := c.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if enabled && !bytes.Contains(b, []byte("apparmor_assume_root_namespace: true")) {
			t.Fatal("opt-in missing from hashed canonical contract")
		}
		warned := false
		for _, d := range ds {
			warned = warned || strings.Contains(d.Message, "apparmor/assumed-root-namespace")
		}
		if warned != enabled {
			t.Errorf("enabled=%t: compile disclosure=%t", enabled, warned)
		}
	}
	_, ds, err := LoadBytes("child.yaml", []byte("version: 0\nname: a\nextends: p\ncommand: [x]\n"),
		mapSource{"p": "version: 0\nfs:\n  apparmor_assume_root_namespace: true\n"})
	if err == nil || !strings.Contains(render(ds), "set fs.apparmor_assume_root_namespace in the top-level contract") {
		t.Fatalf("profile silently enabled the assertion: %v\n%s", err, render(ds))
	}
}
