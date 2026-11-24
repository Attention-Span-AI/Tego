// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestIOUringWithNoListenListWarnsNothingAboutTheRing is GAPS C44's io_uring half after D28 (ADR 0024, amended
// 2026-11-23). Compile used to warn io-uring where a ring's IORING_OP_LISTEN under a net: section with no net.listen
// list had nothing to refuse its autobind. The decision plane's socket_listen now refuses that listen, as the
// supervisor refuses the syscall, so the warning's claim ("nothing refuses it") is false and the warning is gone, with
// every contract the old test warned for: none says so now. What stays is the immutable ring boundary (ADR 0113): an
// enforcing contract with io_uring: true that may land at a root tier is a compile error, whatever its net: section.
func TestIOUringWithNoListenListWarnsNothingAboutTheRing(t *testing.T) {
	landlock, cgroup, bpflsm := backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM
	every := []backend.Tier{landlock, cgroup, bpflsm}
	for _, tc := range []struct {
		name  string
		body  string
		built []backend.Tier // the build's tiers (WithTiers); nil leaves the option out
	}{
		{"pinned to bpflsm, a net.allow list", "tier: bpflsm\nio_uring: true\nnet: {allow: [\"10.0.0.0/8:443\"]}\n", nil},
		{"pinned to cgroup, net: {}", "tier: cgroup\nio_uring: true\nnet: {}\n", nil},
		{"auto on a build of every tier", "io_uring: true\nnet: {}\n", every},
		{"auto on the released build", "io_uring: true\nnet: {}\n", []backend.Tier{landlock, cgroup}},
		{"auto with no build given, at the ceiling", "io_uring: true\nnet: {}\n", nil},
		{"net.listen: [] declares none", "tier: bpflsm\nio_uring: true\nnet: {listen: []}\n", nil},
		{"a net.listen list", "tier: cgroup\nio_uring: true\nnet: {listen: [\"tcp://127.0.0.1:0\"]}\n", nil},
		{"no io_uring: key", "tier: bpflsm\nnet: {}\n", nil},
		{"no net: section", "tier: bpflsm\nio_uring: true\n", nil},
		{"pinned to landlock", "tier: landlock\nio_uring: true\nnet: {}\n", every},
		{"auto on a tier-1 build", "io_uring: true\nnet: {}\n", []backend.Tier{landlock}},
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
			for _, d := range ds {
				if d.Code == CodeIOUring && (strings.Contains(d.Message, "IORING_OP_LISTEN") || strings.Contains(d.Message, "nothing refuses it")) {
					t.Errorf("a warning that a ring's listen is undecided, which the plane now refuses:\n%s", render(ds))
				}
			}
		})
	}
}
