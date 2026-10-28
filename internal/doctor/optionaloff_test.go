// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bytes"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestOptionalTierProbeSaysOff: a probe that stands in the way only of a tier above the one this machine
// reaches prints "off", not FAIL, while doctor exits 0; with --require naming that tier, or with no tier at all, it
// is FAIL again. The exit code never changes with the word.
func TestOptionalTierProbeSaysOff(t *testing.T) {
	noLSM := func(st *probeState) {
		st.lsm = LSMState{Modules: []string{"capability", "apparmor"}, Source: LSMSourceSyscall}
		fail(st, CheckLSM, "bpf is not active: tier 3 (bpflsm) is unavailable, tiers 1 and 2 are not affected", "add lsm=...,bpf")
	}
	noBTF := func(st *probeState) { st.root = false; fail(st, CheckBTF, "ENOENT", "CONFIG_DEBUG_INFO_BTF=y") }
	noLandlock := func(st *probeState) {
		noBTF(st)
		st.landlockABI = 0
		fail(st, CheckLandlock, "ENOSYS", "boot a kernel with landlock")
	}
	for _, tc := range []struct {
		name    string
		edit    func(*probeState)
		require backend.Tier
		want    []string // line prefixes
		exit    int
	}{
		{"tier cgroup, no BPF LSM", noLSM, "", []string{"off  lsm: bpf is not active"}, identity.ExitOK},
		{"tier cgroup, --require landlock", noLSM, backend.TierLandlock, []string{"off  lsm:"}, identity.ExitOK},
		{"--require bpflsm", noLSM, backend.TierBPFLSM, []string{"FAIL lsm:"}, identity.ExitRequire},
		{"tier landlock, no BTF", noBTF, "", []string{"off  btf: ENOENT; fix: CONFIG_DEBUG_INFO_BTF=y"}, identity.ExitOK},
		{"--require cgroup without BTF", noBTF, backend.TierCgroup, []string{"FAIL btf:"}, identity.ExitRequire},
		// A tier-1 probe is never "off", and with no tier at all nothing is.
		{"no tier", noLandlock, "", []string{"FAIL landlock:", "FAIL btf:"}, identity.ExitFinding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := state(tc.edit).report(config.Builtin(), tc.require)
			var buf bytes.Buffer
			if err := rep.WriteText(&buf); err != nil {
				t.Fatal(err)
			}
			for _, w := range tc.want {
				if !strings.Contains(buf.String(), "\n"+w) && !strings.HasPrefix(buf.String(), w) {
					t.Errorf("no line %q:\n%s", w, buf.String())
				}
			}
			if rep.ExitCode() != tc.exit {
				t.Errorf("exit %d, want %d", rep.ExitCode(), tc.exit)
			}
		})
	}
	// WriteResults alone, with no report to judge by, keeps FAIL.
	var buf bytes.Buffer
	if err := WriteResults(&buf, []Result{{ID: CheckLSM, Detail: "x"}}); err != nil || buf.String() != "FAIL lsm: x\n" {
		t.Errorf("WriteResults %q %v", buf.String(), err)
	}
}
