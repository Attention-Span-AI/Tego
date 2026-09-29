// SPDX-License-Identifier: Apache-2.0

package bpflsm

import (
	"fmt"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// New returns tier bpflsm's backend: the tier-2 backend built from opts, as tier 3 (cgroup.Options.Tier). opts.Plane
// must be the plane in LSM mode, doctor's answer for tier bpflsm (Report.PlaneFor); any other mode, the fanotify
// fallback included, is refused with cgroup.ErrNeedsLSMMode, since tier 3 is that plane and nothing else (R19). The
// backend's Prepare refuses a table the plane cannot hold rather than run it on a listener (cgroup.ErrPlaneCannotHold).
func New(opts cgroupenforce.Options) (*cgroupenforce.Backend, error) {
	if opts.Plane.Mode != ebpfbindings.PlaneLSM {
		got := string(opts.Plane.Mode)
		if got == "" {
			got = "none"
		}
		return nil, fmt.Errorf("%w: the plane selected is %s", cgroupenforce.ErrNeedsLSMMode, got)
	}
	opts.Tier = backend.TierBPFLSM
	return cgroupenforce.New(opts), nil
}
