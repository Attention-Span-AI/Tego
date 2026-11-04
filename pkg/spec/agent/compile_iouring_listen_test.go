// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestIOUringWithNoListenListWarnsAtTheRootTiers is GAPS C44's io_uring half, network-controls.md R2's exception.
// Under a net: section with no net.listen list a TCP listen is the supervisor's to refuse (enforce-landlock R11c), a
// ring's IORING_OP_LISTEN passes no seccomp notification, and the plane decides a listen only against a list
// (enforce-plane §2.20). Compile said nothing, so such a contract ran at a root tier with a ring free to autobind a
// listener on every address. It now warns io-uring at the io_uring: line wherever the run may land at a root tier,
// marked as theirs alone, with the fix; a list (net.listen: [] included), io_uring off, no net: section, and a run that
// lands only at tier landlock, where io_uring stays ENOSYS, are not warned.
func TestIOUringWithNoListenListWarnsAtTheRootTiers(t *testing.T) {
	landlock, cgroup, bpflsm := backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM
	every := []backend.Tier{landlock, cgroup, bpflsm}
	for _, tc := range []struct {
		name  string
		body  string
		built []backend.Tier // the build's tiers (WithTiers); nil leaves the option out
		want  []backend.Tier // the warning's tiers; nil for no warning
	}{
		{"pinned to bpflsm, a net.allow list", "tier: bpflsm\nio_uring: true\nnet: {allow: [\"10.0.0.0/8:443\"]}\n", nil, []backend.Tier{bpflsm}},
		{"pinned to cgroup, net: {}", "tier: cgroup\nio_uring: true\nnet: {}\n", nil, []backend.Tier{cgroup}},
		{"auto on a build of every tier", "io_uring: true\nnet: {}\n", every, []backend.Tier{cgroup, bpflsm}},
		{"auto on the released build", "io_uring: true\nnet: {}\n", []backend.Tier{landlock, cgroup}, []backend.Tier{cgroup}},
		{"auto with no build given, at the ceiling", "io_uring: true\nnet: {}\n", nil, []backend.Tier{bpflsm}},
		{"net.listen: [] declares none", "tier: bpflsm\nio_uring: true\nnet: {listen: []}\n", nil, nil},
		{"a net.listen list", "tier: cgroup\nio_uring: true\nnet: {listen: [\"tcp://127.0.0.1:0\"]}\n", nil, nil},
		{"no io_uring: key", "tier: bpflsm\nnet: {}\n", nil, nil},
		{"io_uring: false", "tier: bpflsm\nio_uring: false\nnet: {}\n", nil, nil},
		{"no net: section", "tier: bpflsm\nio_uring: true\n", nil, nil},
		{"pinned to landlock", "tier: landlock\nio_uring: true\nnet: {}\n", every, nil},
		{"auto on a tier-1 build", "io_uring: true\nnet: {}\n", []backend.Tier{landlock}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			yaml := "version: 0\nname: ring\ncommand: [\"python\", \"agent.py\"]\n" + tc.body
			c := f.load(yaml)
			var opts []CompileOption
			if tc.built != nil {
				opts = append(opts, WithTiers(tc.built...))
			}
			_, ds, err := Compile(c, f.machine, f.opts(opts...)...)
			rootReach := !strings.Contains(tc.body, "tier: landlock") && (tc.built == nil || slices.Contains(tc.built, cgroup) || slices.Contains(tc.built, bpflsm))
			if (err != nil) != (c.IOUring && rootReach) {
				t.Fatalf("immutable ring boundary: %v\n%s", err, render(ds))
			}
			var found []Diagnostic
			for _, d := range ds {
				if d.Code == CodeIOUring && strings.Contains(d.Message, "IORING_OP_LISTEN") {
					found = append(found, d)
				}
			}
			if tc.want == nil {
				if len(found) > 0 {
					t.Fatalf("warned where nothing is undecided:\n%s", render(ds))
				}
				return
			}
			if len(found) != 1 {
				t.Fatalf("%d io_uring listen warnings, want 1:\n%s", len(found), render(ds))
			}
			d := found[0]
			if d.IsError() || !slices.Equal(d.Tiers(), tc.want) {
				t.Errorf("severity %s tiers %v, want a warning for %v alone: %v", d.Severity, d.Tiers(), tc.want, d)
			}
			if line := 1 + strings.Count(yaml[:strings.Index(yaml, "io_uring:")], "\n"); d.Line != line {
				t.Errorf("at line %d, want the io_uring: line %d: %v", d.Line, line, d)
			}
			for _, want := range []string{"no net.listen", "autobind", "nothing refuses it"} {
				if !strings.Contains(d.Message, want) {
					t.Errorf("message lacks %q: %s", want, d.Message)
				}
			}
			if !strings.Contains(d.Fix, "net.listen: []") || !strings.Contains(d.Fix, "drop io_uring:") {
				t.Errorf("fix %q names neither a net.listen list nor dropping io_uring:", d.Fix)
			}
			// tego run prints it only to a run at a root tier: never at landlock, where io_uring stays ENOSYS, nor
			// under --observe, which refuses nothing.
			for _, other := range []backend.Tier{landlock, backend.TierObserve} {
				if slices.ContainsFunc(ForTier(ds, other), func(x Diagnostic) bool { return x.Message == d.Message }) {
					t.Errorf("ForTier(%s) kept the root tiers' warning", other)
				}
			}
			for _, root := range tc.want {
				if !slices.ContainsFunc(ForTier(ds, root), func(x Diagnostic) bool { return x.Message == d.Message }) {
					t.Errorf("ForTier(%s) dropped the warning", root)
				}
			}
		})
	}
}
