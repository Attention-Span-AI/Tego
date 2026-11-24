// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func validateLocalRoles(rt *agent.RuleTable, deps Deps) (config.LocalAuthority, error) {
	a, err := deps.Config.ApprovalAuthority()
	if err != nil || !a.OwnerOnly() {
		return a, err
	}
	if err := a.Check(); err != nil {
		return a, err
	}
	euid, ns, err := localLauncher()
	if err != nil {
		return a, err
	}
	if err := localLaunch(euid, ns, rt.Record, deps.Enforce.Tier(), rt.Contract.Setuid); err != nil {
		return a, err
	}
	return a, nil
}

// preflightLocalRoles is the part of the root-only floor that needs no backend: the launcher's user, the contract's
// recording and setuid. It decides from the configuration and the caller alone, so Preflight can refuse before the
// CLI probes the kernel, where a cold bpf teardown has held a refusal back for 20 to 38 seconds. Whether the tier
// the run is given enforces stays with validateLocalRoles, which repeats this check at the runtime's own entry.
func preflightLocalRoles(rt *agent.RuleTable, deps Deps) error {
	a, err := deps.Config.ApprovalAuthority()
	if err != nil || !a.OwnerOnly() {
		return err
	}
	euid, ns, err := localLauncher()
	if err != nil {
		return err
	}
	return localFloor(euid, ns, rt.Record, rt.Contract.Setuid)
}

// localLauncher reads who launches: the effective UID and the user namespace's inode. A variable so a unit test can
// stand in for an initial-namespace root launcher.
var localLauncher = func() (int, uint64, error) {
	var ns unix.Stat_t
	if err := unix.Stat("/proc/self/ns/user", &ns); err != nil {
		return 0, 0, fmt.Errorf("runtime: root-only approval requires user namespace diagnostics: %w", err)
	}
	return os.Geteuid(), ns.Ino, nil
}

// errLocalFloor is the floor's refusal, in the words the guest rows and the user page match.
func errLocalFloor() error {
	return fmt.Errorf("runtime: local root-only approvals require initial-namespace root, a non-root child, enforcement, recording and setuid disabled")
}

// localFloor holds what the floor requires of the launcher and the contract, whatever tier is selected.
func localFloor(euid int, ns uint64, mode agent.RecordMode, setuid bool) error {
	if euid != 0 || ns != record.InitialUserNamespace || (mode != agent.RecordFull && mode != agent.RecordSummary) || setuid {
		return errLocalFloor()
	}
	return nil
}

// localLaunch is localFloor plus the selected tier, which must enforce.
func localLaunch(euid int, ns uint64, mode agent.RecordMode, tier backend.Tier, setuid bool) error {
	if err := localFloor(euid, ns, mode, setuid); err != nil {
		return err
	}
	if tier != backend.TierLandlock && tier != backend.TierCgroup && tier != backend.TierBPFLSM {
		return errLocalFloor()
	}
	return nil
}

func localDrop(privileged bool, uid int, setuid bool) error {
	if !privileged || uid <= 0 || uint64(uid) >= uint64(^uint32(0)) || setuid {
		return fmt.Errorf("runtime: local root-only approvals require a verified non-root child credential drop")
	}
	return nil
}

func localEnforcing(recordsOnly bool) error {
	if recordsOnly {
		return fmt.Errorf("runtime: local root-only approvals require an enforcing handle")
	}
	return nil
}

// localRolesMinor is the revision a run writing the local approval payload carries: the revision the launch already
// writes when that is at or above MinorLocalRoles (a baseline record's, or a later revision that declares a superset of
// every earlier one), and MinorLocalRoles itself otherwise. The payload is valid from revision 37 on, so a launch never
// drops to 37 to write it.
func localRolesMinor(launch int) int { return max(launch, record.MinorLocalRoles) }
