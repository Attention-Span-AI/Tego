// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestAutoTiersAreThisUsersOnThisKernel is the demo's bug: a tegobpf build compiled and ran an auto contract
// as a normal user, on a kernel without bpf in the LSM list, at tier bpflsm, and refused its fs.ask_read for a
// tier the run could never get. The tiers tier: auto resolves among are those this build constructs and this
// process could be given here: tier cgroup and above only as root, tier bpflsm only with bpf in the LSM list.
// An untagged build answers landlock alone whoever runs it; under -tags tegobpf this reads the real process.
func TestAutoTiersAreThisUsersOnThisKernel(t *testing.T) {
	got := builtTiers()
	if !slices.Contains(got, backend.TierLandlock) {
		t.Fatalf("builtTiers() = %v, want tier landlock among them", got)
	}
	if !config.InitNSRoot() {
		for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
			if slices.Contains(got, tier) {
				t.Errorf("builtTiers() = %v as a user who is not root: tier %s needs root, so no run of this user gets it", got, tier)
			}
		}
	}
	if st, err := doctor.ReadLSMState(); (err != nil || !st.BPFActive) && slices.Contains(got, backend.TierBPFLSM) {
		t.Errorf("builtTiers() = %v on a kernel whose LSM list %v has no bpf: tier bpflsm cannot run here", got, st.Modules)
	}
}

// TestCompileTestHeaderNamesTheBuiltTiersAutoLeftOut: compile --test's header said "tier auto: every tier this tego
// builds" whatever the set was, so a normal user of a tegobpf build (make build's) read "tiers landlock (tier auto:
// every tier this tego builds)", a landlock-only build, while the build constructs tiers cgroup and bpflsm and a run
// as root gets them. Each tier this build constructs (enforce.Buildable) that the set leaves out is named in the
// header; with none left out it still says every tier this tego builds. An untagged build constructs landlock alone;
// under -tags tegobpf this reads the real process, as TestAutoTiersAreThisUsersOnThisKernel does.
func TestCompileTestHeaderNamesTheBuiltTiersAutoLeftOut(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("the example contract names sh, not on PATH")
	}
	copyExampleTests(t, rootTierOnlyRow)
	code, out, errs := run(t, "compile", "agent.yaml", "--test", "verdicts.yaml")
	if code != identity.ExitOK && code != identity.ExitFinding {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	header, _, _ := strings.Cut(out, "\n")
	set := builtTiers()
	var left []string
	for _, tier := range backend.Tiers() {
		if tier.AtOrBelow(backend.TierBPFLSM) && enforce.Buildable(tier) == nil && !slices.Contains(set, tier) {
			left = append(left, string(tier))
		}
	}
	if len(left) == 0 {
		if !strings.HasSuffix(header, "(tier auto: every tier this tego builds)") {
			t.Errorf("header %q: the set %v is every tier this build constructs, and the header does not say so", header, set)
		}
		return
	}
	if !strings.Contains(header, "(tier auto: every tier this tego builds but ") {
		t.Errorf("header %q claims every built tier while the set %v leaves out %v, which this build constructs", header, set, left)
	}
	for _, tier := range left {
		if !strings.Contains(header, tier) {
			t.Errorf("header %q does not name tier %s, which this build constructs and the set %v leaves out", header, tier, set)
		}
	}
}
