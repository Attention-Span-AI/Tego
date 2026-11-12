// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// writeRunStart is an adoption's run_start: the run's first line, as `tego run` writes it, with what an adoption
// is: launcher_pid the adopter, command and cwd the adopted agent's own (as /proc read them), no limits block (it
// carries budgets, which nothing meters on an adoption; the cpu, cpu_weight and pids a boundary writes into its scope
// have no key there, for a launched run either), capture off (the agent's environment cannot be changed, so no forwarder reaches it), and a
// capability line that says what an adopted process can be given and nothing more (adoptionCapabilities).
func (a *adoption) writeRunStart() error {
	r := a.r
	cwd, _ := a.env.Proc.Cwd(a.spec.Root.PID)
	command := a.spec.Root.Argv
	if len(command) == 0 {
		command = []string{a.spec.Root.Exe}
	}
	plane := ""
	if a.spec.Boundary {
		plane = a.planeMode
	}
	tier := r.deps.Enforce.Tier()
	start := record.RunStartPayload{
		LauncherPID: os.Getpid(), LauncherStartNS: r.launcherStart,
		TegoVersion: r.deps.Build.Version, Commit: r.deps.Build.Commit, BPFHash: r.deps.Build.BPFHash,
		Tier: string(tier), Capture: string(agent.CaptureOff), Kernel: r.deps.Build.Kernel,
		ContractHash: hex.EncodeToString(r.rt.Hash[:]), Parsers: r.runParsers(string(agent.CaptureOff)),
		StopGrace: r.stopGrace.String(), Command: command, Cwd: cwd,
		Capabilities: a.capabilityLine(), RecordMinor: record.Minor, DecisionPlane: plane,
		ContractSource: r.deps.ContractSource, Profiles: runProfiles(r.rt.Profiles),
	}
	if a.spec.Boundary {
		start.BestEffort = r.rt.BestEffortCellsAt(tier, plane)
	}
	// Who adopted the process, on which host (ADR 0073); an adoption calls no Started hook.
	r.fillRunIdentity(&start)
	if err := r.writer.WriteRunStartIn(start, r.cg.ID); err != nil {
		return fmt.Errorf("runtime: write run_start: %w", err)
	}
	r.anchored.Store(true)
	return nil
}

// adoptionNever are the capability rows no adoption has, whatever its contract: they are tier 1's Landlock and
// seccomp filter, the supervisor (asks, gates, the gate's relay), the forwarder, and the network rows: a socket keeps the cgroup it was
// made in, so the run's cgroup programs never govern one the agent made before it was adopted, and the record cannot
// tell such a socket's connect from a governed one's (ADR 0055). A boundary with a net: section is
// refused beforehand, and no adoption installs the seccomp socket arm the socket-family row needs (ADR 0018).
var adoptionNever = []backend.Capability{
	backend.CapAsk, backend.CapCaptureModel, backend.CapNetHTTPRules, backend.CapNetHostDeny, backend.CapUDPByDestination,
	backend.CapUDPPortInKernel, backend.CapUnixSockets, backend.CapUnixAbstractScope, backend.CapTCPDestinationKernel,
	backend.CapUnixDestinationKernel, backend.CapNamespaceSandbox, backend.CapAdoptedContainers, backend.CapChmodDeny,
	backend.CapGateNetCompletion,
	backend.CapSocketFamilies, backend.CapHostSocketsRefused,
}

// adoptionPlaneRows are the rows a boundary adoption has only while a plane mode decides it: the plane's file_open,
// path and bprm_check hooks decide them for every task in the cgroup, with or without Landlock. The name entries' row
// (ADR 0043) is the handle's: true only where the slot's name check decides.
var adoptionPlaneRows = []backend.Capability{
	backend.CapFileWriteDeny, backend.CapFileDeleteRename, backend.CapReadDeny, backend.CapExecDeny,
	backend.CapReadDenyCreatedLater,
}

// capabilityLine is the adoption's run_start capability line: every row, false unless the adoption provides it. A
// record-only adoption enforces nothing; a boundary one has the plane's rows and fs.protected_write_targets; both have
// the record rows their record mode gives.
func (a *adoption) capabilityLine() map[string]bool {
	set := backend.Set{}
	if a.spec.Boundary && a.planeMode != "" {
		if rep, ok := a.r.handle.(enforce.Reporter); ok {
			full := rep.Capabilities()
			for _, c := range adoptionPlaneRows {
				set[c] = full.Has(c)
			}
		}
		// The plane's rows hold the built-in deny_write targets for every task in the cgroup, as they hold
		// fs.deny_write, so the row reads decision_plane exactly as run_start.best_effort's deny_write/default does
		// (BestEffortCellsAt): the two never disagree (CAPABILITIES R23). A target the agent held open before the
		// adoption is the adoption-open-descriptors gap, as for fs.deny_write.
		set[backend.CapProtectedWriteTargets] = a.planeMode == record.DecisionPlaneLSM || a.planeMode == record.DecisionPlaneFmodRet
	}
	for _, c := range adoptionNever {
		set[c] = false
	}
	rec := a.r.rt.Record
	set[backend.CapRecordExecOpenNet] = rec != agent.RecordOff
	set[backend.CapRecordReads] = rec == agent.RecordFull
	set[backend.CapLogAllowed] = rec != agent.RecordOff
	out := map[string]bool{}
	for _, c := range backend.AllCapabilities() {
		out[string(c)] = set.Has(c)
	}
	return out
}
