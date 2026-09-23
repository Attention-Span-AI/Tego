// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"fmt"
	"strings"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// The Landlock ABI numbers the capability rows of spec/backend/CAPABILITIES.md are gated on
// (docs/ARCHITECTURE.md §14's mechanism list).
const (
	// abiTCPPorts is ABI 4: without it tier 1 grants no network rule at all and the whole
	// host:port decision falls to the supervisor (AL2023's 6.1 with ABI 2 is the stated case).
	abiTCPPorts = 4
	// abiScopes is ABI 6: the abstract-socket scope (enforce-landlock R7), which refuses an abstract
	// unix name bound outside the run whatever the contract says.
	abiScopes = 6
	// abiPathnameUnix is ABI 9: LANDLOCK_ACCESS_NET_RESOLVE_UNIX, a resolved unix socket path.
	abiPathnameUnix = 9
	// abiUDPPorts is ABI 10: UDP destination ports decided in the kernel.
	abiUDPPorts = 10
)

// machineMatrix is CAPABILITIES.md's column for one tier with this machine's own values in it
// (R27's "the table with this machine's values substituted"). The static table is written for the
// mechanism at its best; a row that this kernel's Landlock ABI or this build's attach points cannot
// actually deliver is turned off here, with a note saying which measured value decided it.
//
// It turns rows off when the measured mechanism is absent. Conditional rows can turn on only with
// their own evidence: the Landlock ABI for abstract-socket scope, successfully probed cgroup or
// selected-plane hooks for Unix destination admission, and a selected plane mode for the protected write targets
// and, in a build that enforces them, the name entries.
func (st probeState) machineMatrix(tier backend.Tier) (backend.Set, map[backend.Capability]string) {
	set := backend.Matrix(tier)
	if set == nil {
		set = backend.Set{} // an unknown or empty tier has no column; nothing to turn off
	}
	notes := map[backend.Capability]string{}
	off := func(c backend.Capability, note string) {
		if set.Has(c) {
			set[c] = false
		}
		notes[c] = note
	}
	defer func() {
		// Every tier: R11a's implicit admit of a socket under a write entry asks sock_diag which socket the run
		// bound, and refuses every such socket where the kernel cannot answer.
		if st.unixDiag == nil || *st.unixDiag {
			return
		}
		note := "no sock_diag for AF_UNIX (CONFIG_UNIX_DIAG, the unix_diag module): a socket under an fs.write " +
			"path is refused unix-origin-unread unless a unix: entry names it"
		if prev := notes[backend.CapUnixSockets]; prev != "" {
			note = prev + "; " + note
		}
		notes[backend.CapUnixSockets] = note
	}()
	switch tier {
	case backend.TierLandlock:
		abi := st.landlockABI
		if abi < abiTCPPorts {
			off(backend.CapNetHostDeny, fmt.Sprintf("Landlock ABI %d has no network rules (ABI %d adds TCP ports); every connect is decided by the supervisor", abi, abiTCPPorts))
			off(backend.CapUDPByDestination, fmt.Sprintf("Landlock ABI %d has no network rules", abi))
		}
		if abi < abiUDPPorts {
			notes[backend.CapUDPPortInKernel] = fmt.Sprintf("Landlock ABI %d; UDP ports need ABI %d", abi, abiUDPPorts)
		}
		if abi < abiPathnameUnix {
			notes[backend.CapUnixSockets] = fmt.Sprintf("Landlock ABI %d; RESOLVE_UNIX needs ABI %d, so unix connects are decided by the seccomp supervisor", abi, abiPathnameUnix)
		} else {
			notes[backend.CapUnixSockets] = fmt.Sprintf("Landlock ABI %d: RESOLVE_UNIX available", abi)
		}
	case backend.TierCgroup:
		if !st.networkHookOK("cgroup/connect_unix") || !st.networkHookOK("cgroup/sendmsg_unix") {
			if mode := st.unixAdmissionPlane(tier); mode != "" {
				// enforce-plane §2.11: below 6.7 the plane's socket_connect and socket_sendmsg hooks decide unix names.
				notes[backend.CapUnixSockets] = "cgroup/connect_unix and cgroup/sendmsg_unix are unavailable here " +
					"(6.7+); the decision plane's socket_connect and socket_sendmsg hooks in " + mode + " mode decide " +
					"unix names in the kernel instead, and a refusal reaches the agent as EACCES"
			} else {
				notes[backend.CapUnixSockets] = "cgroup/connect_unix and cgroup/sendmsg_unix are unavailable here " +
					"(6.7+); unix connects and datagrams fall back to the seccomp supervisor, which records an " +
					"addressed datagram and does not refuse it"
			}
		}
		// Which errno a refusal carries is this machine's answer, not the static column's: where the plane
		// probe selected a mode, the plane decides files and exec and a run makes no fanotify group
		// (enforce-plane R2, R22), so its refusals read EACCES; else D8 measures whether the kernel takes an
		// errno from the listener's group (none so far does).
		// The built-in deny_write targets are refused race-free only by a plane mode (ADR 0041 D7): the static
		// column is conditional, and this machine's probe answers it.
		if mode := st.planeMode(); mode != "" {
			set[backend.CapProtectedWriteTargets] = true
			notes[backend.CapProtectedWriteTargets] = "the decision plane in " + mode + " mode decides them by inode, " +
				"chmod included"
		} else {
			notes[backend.CapProtectedWriteTargets] = "no decision plane mode passed here: the fanotify listener leaves " +
				"them to the supervisor's copied pathnames, best effort, and fs.assurance: kernel refuses the run"
		}
		// ADR 0043's name entries are decided by a plane mode's name check, whose known answers the mode passed.
		switch mode := st.planeMode(); {
		case mode != "":
			set[backend.CapReadDenyCreatedLater] = true
			notes[backend.CapReadDenyCreatedLater] = "the decision plane in " + mode + " mode refuses a file created " +
				"later at a covered name by its name, beneath each scope"
		default:
			notes[backend.CapReadDenyCreatedLater] = "no decision plane mode passed here: the fanotify listener refuses " +
				"an open of a covered name and the supervisor a creation, link or rename onto one on its copied " +
				"pathnames, best effort"
		}
		if mode := st.planeMode(); mode != "" {
			note := "decided by the decision plane in " + mode + " mode, not fanotify: a refusal reaches the " +
				"agent as EACCES, with the reason in the record"
			for _, c := range []backend.Capability{backend.CapFileWriteDeny, backend.CapReadDeny, backend.CapExecDeny} {
				notes[c] = note
			}
		} else if !st.fanotify.DenyErrno {
			notes[backend.CapFileWriteDeny] = "no errno reply here: a fanotify refusal reaches the agent as EPERM " +
				"(no kernel takes EACCES in a FAN_DENY from the listener's FAN_CLASS_CONTENT group), with the " +
				"exact code in the reason record"
		} else {
			notes[backend.CapFileWriteDeny] = "this kernel takes EACCES in a FAN_DENY reply, but the listener " +
				"sends the bare FAN_DENY, so a fanotify refusal still reaches the agent as EPERM, with the exact " +
				"code in the reason record"
		}
	case backend.TierBPFLSM:
		if st.lsm.Functional != "" && !strings.HasPrefix(st.lsm.Functional, "confirmed") {
			notes[backend.CapRecordExecOpenNet] = "the BPF LSM functional probe did not confirm the hooks run: " + st.lsm.Functional
		}
	// No per-machine notes for these.
	case backend.TierObserve, backend.TierAuto:
	}
	// The abstract-scope row is ABI-gated in every column, so the static matrix never claims it and a run
	// records it from its own ruleset (agent-contract R19). What this kernel's ABI gives a run of any tier
	// that applies a Landlock ruleset is said here, so the exposure below ABI 6 is visible before any run.
	if tier == backend.TierLandlock || tier == backend.TierCgroup || tier == backend.TierBPFLSM {
		if abi := st.landlockABI; abi >= abiScopes {
			set[backend.CapUnixAbstractScope] = true
			notes[backend.CapUnixAbstractScope] = fmt.Sprintf("Landlock ABI %d: each run's ruleset refuses an "+
				"abstract unix name bound outside it, and the run records the row", abi)
		} else {
			notes[backend.CapUnixAbstractScope] = fmt.Sprintf("Landlock ABI %d; the abstract-socket scope needs "+
				"ABI %d (Linux 6.12), so nothing refuses an abstract unix name bound outside a run: a contract "+
				"with no net: section reaches every abstract socket its uid can", abi, abiScopes)
		}
	}
	// Tiers 2 and 3 capture with uprobes and the forwarder (CAPABILITIES.md); D7's capture rows say
	// whether the uprobe half works here. The row stays on, because under capture: auto the forwarder half
	// still captures. A contract that pins capture: uprobe runs no forwarder at these tiers, so on a machine
	// whose uprobes fail its run captures nothing and records gap why=mechanism-unavailable binary=uprobe
	// (capture-derive.md §4); the note says so, since the row is the machine's and not the contract's.
	if tier == backend.TierCgroup || tier == backend.TierBPFLSM {
		tcp := st.networkHookOK("cgroup/connect4") && st.networkHookOK("cgroup/connect6")
		if !tcp {
			off(backend.CapTCPDestinationKernel, "D7 did not confirm both cgroup/connect4 and connect6 loaded and attached")
		}
		if !tcp || !st.networkHookOK("cgroup/sendmsg4") || !st.networkHookOK("cgroup/sendmsg6") {
			off(backend.CapUDPByDestination, "D7 did not confirm both IP connect hooks and both addressed UDP send hooks loaded and attached")
			off(backend.CapUDPPortInKernel, notes[backend.CapUDPByDestination])
		}
		// ADR 0018 PR 2 and (7): an inet socket that reaches inet_create past the filter is refused by
		// cgroup/sock_create, and a TCP_ULP set past it (io_uring's setsockopt) by cgroup/setsockopt, and D7 is what
		// loaded and attached those programs here. A run with a net: section records the row from its own attachments
		// (NetworkGuarantees.SocketFamilies); a run with none has it false.
		for _, row := range []string{"cgroup/sock_create", "cgroup/setsockopt"} {
			if !st.networkHookOK(row) {
				off(backend.CapSocketFamilies, "D7 did not confirm "+row+" loaded and attached")
				break
			}
		}
		switch {
		case st.networkHookOK("cgroup/connect_unix") && st.networkHookOK("cgroup/sendmsg_unix"):
			set[backend.CapUnixDestinationKernel] = true
			notes[backend.CapUnixDestinationKernel] = "D7 confirmed cgroup/connect_unix and sendmsg_unix loaded and attached"
		case st.unixAdmissionPlane(tier) != "":
			set[backend.CapUnixDestinationKernel] = true
			notes[backend.CapUnixDestinationKernel] = "D9 confirmed both selected decision-plane Unix hooks loaded, attached and decided their known answers"
		default:
			notes[backend.CapUnixDestinationKernel] = "neither both cgroup Unix hooks nor the active decision-plane Unix fallback were confirmed"
		}
		if note := st.captureNote(); note != "" {
			notes[backend.CapCaptureModel] = note
		}
	}
	if len(notes) == 0 {
		return set, nil
	}
	return set, notes
}

// unixAdmissionPlane reports the mode a run would actually use for Unix admission.
// The backend omits the plane's Unix hooks whenever cgroup/connect_unix loaded,
// even if an optional attach subsequently failed. A successful probe of an
// unused plane must therefore never fill that gap in the reported guarantee.
func (st probeState) unixAdmissionPlane(tier backend.Tier) string {
	for _, h := range st.hooks {
		if h.Hook == "cgroup/connect_unix" && h.Loaded {
			return ""
		}
	}
	choice, err := (&Report{Plane: st.plane, LSM: st.lsm}).PlaneFor(tier)
	if err != nil || choice.Mode == "" {
		return ""
	}
	mode, ok := st.plane.mode(choice.Mode)
	if !ok || !mode.OK {
		return ""
	}
	connect, send := false, false
	for _, h := range st.hooks {
		if h.Plane != choice.Mode || h.Absent || h.StandIn || !h.OK() {
			continue
		}
		connect = connect || h.Hook == (bpfobj.PlaneHook{LSM: "socket_connect", Security: "security_socket_connect"}).Section(choice.Mode)
		send = send || h.Hook == (bpfobj.PlaneHook{LSM: "socket_sendmsg", Security: "security_socket_sendmsg"}).Section(choice.Mode)
	}
	if connect && send {
		return string(choice.Mode)
	}
	return ""
}

// networkHookOK requires the embedded production program, not the minimal
// hook-type stand-in D7 can load for a binary that lacks the BPF objects.
func (st probeState) networkHookOK(name string) bool {
	for _, h := range st.hooks {
		if h.Hook == name {
			return !h.Absent && !h.StandIn && h.OK()
		}
	}
	return false
}

// planeMode is the plane mode tier cgroup runs in on this machine (PlaneState.Selected), "" when the probe did
// not run or selected the fanotify fallback.
func (st probeState) planeMode() string {
	if st.plane == nil || st.plane.Skipped || st.plane.Selected == PlaneFanotify {
		return ""
	}
	return st.plane.Selected
}

// captureNote is capture.model_traffic's note from D7's capture rows (R27 D7), "" when they all
// loaded and attached or were never run. Capture loads uprobe_ssl as one collection, so one program
// the verifier refuses leaves it no uprobes at all, and a binary whose probes do not all attach stays
// uncaptured (capture-derive.md's attach-failure row); either way the forwarder is what is left, and a
// contract that pins capture: uprobe runs none.
func (st probeState) captureNote() string {
	var failed []string
	standIn, untested := false, false
	for _, h := range st.hooks {
		if !h.Capture {
			continue
		}
		standIn = standIn || h.StandIn
		switch {
		case captureFailed(h):
			failed = append(failed, h.Hook+": "+h.Detail)
		case h.LoadOnly && h.Target == "":
			untested = true
		}
	}
	switch {
	case standIn:
		return "this binary carries no uprobe_ssl object, so capture has no uprobes here; the forwarder still " +
			"captures, except for a contract that pins capture: uprobe, which runs no forwarder"
	case len(failed) > 0:
		return "D7's uprobe_ssl rows failed (" + strings.Join(failed, "; ") + "), so capture's uprobes cannot " +
			"be relied on here; the forwarder still captures, except for a contract that pins capture: uprobe, " +
			"which runs no forwarder"
	case untested:
		return "D7 found no system libssl, so capture's uprobes were tested for their load only"
	}
	return ""
}
