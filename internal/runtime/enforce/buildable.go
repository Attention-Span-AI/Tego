// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"errors"
	"fmt"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// ErrNotBuilt is what every NotBuiltError matches with errors.Is.
var ErrNotBuilt = errors.New("enforce: tier not built into this binary")

// NotBuiltError is Buildable's answer for a tier this binary cannot construct on any machine.
type NotBuiltError struct {
	Tier backend.Tier
	// Why names what the binary lacks.
	Why string
	// Fix is the one action that gives the tier a binary that carries it, "" when no build of this
	// version does: a tier with no implementation has nothing to be rebuilt with.
	Fix string
}

// Error renders the sentence doctor lists under the tier and Select prints as a warning.
func (e *NotBuiltError) Error() string {
	return fmt.Sprintf("tier %s is not built into this binary: %s", e.Tier, e.Why)
}

// Unwrap makes errors.Is(err, ErrNotBuilt) hold.
func (e *NotBuiltError) Unwrap() error { return ErrNotBuilt }

// objectsAvailable reports whether this binary embeds the compiled BPF objects tier 2 loads. It is a
// variable so this package's tests can describe either build from one test binary; production never
// reassigns it.
var objectsAvailable = ebpfbindings.Available

// Buildable reports whether this binary can construct tier t, nil when it can. It is the build's half of
// the tier derivation, the half no machine probe can see: internal/doctor ANDs it into every tier it
// reports (Report.Tiers), and Select filters its probe through it, so the two read one answer and a tier
// `tego doctor` reports is always one `tego run` can construct (docs/p0/limits-check-doctor-cli.md R27 Output).
//
// Tier cgroup needs the objects an untagged build does not embed: without this, a root machine reported
// the tier and every run of it failed at Prepare with ErrNotGenerated after its ledger and cgroup existed.
// How the binary is linked no longer matters: the tier's marks are placed after the child stage's execve
// (ADR 0021 (2), (4)), so neither the stage's binary nor its loader is ever asked about, and a dynamically
// linked or PIE tegobpf build runs tier cgroup like a static one. Tier bpflsm is the decision plane in LSM mode over
// the tier-2 backend (internal/runtime/enforce/bpflsm, TIER3-PLAN T7), whose objects are embedded with tier 2's, so
// it is built exactly when tier cgroup is; the machine's half (bpf in the LSM list, LSM mode's probe) is doctor's.
func Buildable(t backend.Tier) error {
	switch t {
	case backend.TierLandlock:
		return nil
	case backend.TierCgroup, backend.TierBPFLSM:
		if !objectsAvailable() {
			return &NotBuiltError{Tier: t,
				Why: "it loads the embedded BPF objects, and this build has none (built without -tags tegobpf)",
				Fix: cgroupenforce.BuildFix}
		}
		return nil
	// Handled after the switch, as any other value.
	case backend.TierObserve, backend.TierAuto:
	}
	return &NotBuiltError{Tier: t, Why: "it is not an enforcement tier"}
}
