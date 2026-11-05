// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"strings"
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/cilium/ebpf"
)

func TestSyscallResultContextRefusalWithholdsTierBeforeLoad(t *testing.T) {
	savedCheck, savedAvailable := validateSyscallResultContext, execResultTracepointAvailable
	t.Cleanup(func() {
		validateSyscallResultContext, execResultTracepointAvailable = savedCheck, savedAvailable
	})
	execResultTracepointAvailable = func(string) bool { return true }
	for _, reason := range []string{
		"ret offset 24 size 8; BPF syscall exit wrapper requires offset 16 size 8",
		"missing or malformed ret field; BPF syscall exit wrapper requires offset 16 size 8",
	} {
		t.Run(reason, func(t *testing.T) {
			for i, h := range hooks {
				if h.kind != hookTracepoint {
					continue
				}
				refusal := errors.New("syscall result context " + h.attachTo + ": " + reason)
				validateSyscallResultContext = func(string) error { return refusal }
				loads := 0
				load := func(bpfobj.Object) (*ebpf.CollectionSpec, error) {
					loads++
					return nil, bpfobj.ErrNotGenerated
				}
				row := testHookWith(h, nil, nil, nil, Version{7, 0, 0}, load)
				if row.Absent || row.Loaded || row.StandIn || row.Attached || row.CapabilityOnly || !strings.Contains(row.Detail, refusal.Error()) {
					t.Fatalf("layout rejection became optional or loaded a stand-in: %+v", row)
				}
				if loads != 0 {
					t.Fatalf("unsafe context reached %d object loads", loads)
				}
				// One unsafe event suffices, including either listener capability
				// row with otherwise healthy exec events and all other hooks.
				st := state(nil)
				st.hooks[i] = row
				st.byID[CheckPrograms] = programsVerdict(st.hooks)
				if st.byID[CheckPrograms].OK || st.probe()[backend.TierCgroup] || st.probe()[backend.TierBPFLSM] {
					t.Fatalf("unsafe %s context left a root tier available", h.Name)
				}
				if missing := strings.Join(st.missingHooks(backend.TierCgroup), "; "); !strings.Contains(missing, reason) {
					t.Fatalf("tier refusal lost the plain reason: %s", missing)
				}
			}
		})
	}
}
