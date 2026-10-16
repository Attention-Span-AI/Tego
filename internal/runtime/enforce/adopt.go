// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"fmt"

	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// AdoptionRecorder is the tier-2 backend of a record-only adoption (ADR 0055): the build's programs,
// a slot, its rings and the run-set row the arm inserts, and nothing that decides. No tier-1 state is composed (a
// running process takes no Landlock ruleset or seccomp filter), and no decision plane is filled: the plane would hold
// a contract's default write refusal, which a record-only adoption must not apply. Its table asks for no listener
// (no deny_read or exec entry) and no network program (no net: section), so nothing of it refuses anything.
func AdoptionRecorder(m *config.Machine) (Backend, error) {
	if err := Buildable(backend.TierCgroup); err != nil {
		return nil, fmt.Errorf("%w: %w", backend.ErrTierUnavailable, err)
	}
	opts := cgroupenforce.Options{Machine: m}
	return cgroupBackend{b: cgroupenforce.New(opts), opts: opts}, nil
}
