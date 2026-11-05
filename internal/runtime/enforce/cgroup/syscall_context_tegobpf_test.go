// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf

package cgroup

import (
	"errors"
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
)

func TestSyscallResultContextRefusalPrecedesLoadAndAdoption(t *testing.T) {
	saved := validateSyscallResultContext
	t.Cleanup(func() { validateSyscallResultContext = saved })
	for _, reason := range []string{"ret offset 24 size 8", "missing or malformed ret field"} {
		refusal := errors.New("syscall result context sys_exit_bind: " + reason)
		validateSyscallResultContext = func(name string) error {
			if name == bpfobj.ProgBindResult {
				return refusal
			}
			return nil
		}
		for _, adoption := range []bool{false, true} {
			control := &NetworkControlMaps{Config: bpfobj.NetControl{Flags: bpfobj.NetControlListen}}
			spec, _, err := loadKernelSpec(bpfobj.ObjectTraceProc, adoption, control)
			if spec != nil || !errors.Is(err, refusal) {
				t.Fatalf("adoption=%t: unsafe context returned a loadable spec: %v, %v", adoption, spec, err)
			}
			// An unselected listener program must not make an outbound-only
			// run depend on the bind event format.
			spec, _, err = loadKernelSpec(bpfobj.ObjectTraceProc, adoption, nil)
			if err != nil || spec.Programs[bpfobj.ProgBindResult] != nil {
				t.Fatalf("adoption=%t: unselected listener: %v", adoption, err)
			}
		}
	}
}
