// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"fmt"
	"io"
	"strings"
)

// Capability names one row of spec/backend/CAPABILITIES.md. The twenty-seven constants below are the
// closed set, in the table's row order.
type Capability string

// The capability rows, in CAPABILITIES.md order.
const (
	CapFileWriteDeny Capability = "fs.deny_write"
	// CapFileDeleteRename's name predates the chmod row and is kept, since ledgers carry it: the row is delete,
	// rename, mkdir and mknod, which Landlock denies; chmod is CapChmodDeny (agent-contract E35).
	CapFileDeleteRename  Capability = "fs.deny_delete_rename_mkdir_chmod_mknod"
	CapReadDeny          Capability = "fs.deny_read"
	CapExecDeny          Capability = "exec.deny"
	CapNetHostDeny       Capability = "net.deny_host_port"
	CapUDPByDestination  Capability = "net.udp_by_destination"
	CapUDPPortInKernel   Capability = "net.udp_by_port_kernel"
	CapUnixSockets       Capability = "net.unix"
	CapAsk               Capability = "ask" // runtime narrows this to an actually started approval broker
	CapRecordExecOpenNet Capability = "record.exec_open_connect"
	CapRecordReads       Capability = "record.reads_mmap_chmod"
	CapCaptureModel      Capability = "capture.model_traffic"
	CapLogAllowed        Capability = "log.allowed_with_rule"
	CapAdoptedContainers Capability = "containers.adopted"
	CapNetHTTPRules      Capability = "net.http_rules"
	CapNamespaceSandbox  Capability = "containers.namespace_sandbox"
	// CapUnixAbstractScope is Landlock's abstract-socket scope (ABI 6, Linux 6.12; enforce-landlock R7): an
	// abstract unix name bound outside the run's domain is refused to the agent whatever its contract says.
	// It is the last row, not beside net.unix, so that no earlier row's index moves (R23): below ABI 6 a
	// contract with no net: section reaches every abstract socket on the host (agent-contract R19), and this
	// row is how the run's record says so.
	CapUnixAbstractScope Capability = "net.unix_abstract_scope"
	// CapChmodDeny is a chmod refused under the contract's write rules. Only tier 3's path_chmod hook can: no
	// Landlock ABI has a chmod right, tier 1's filter does not notify chmod and fanotify has no permission
	// event for it (agent-contract E35). Last, so no earlier row's index moves (R23).
	CapChmodDeny Capability = "fs.deny_chmod"
	// Appended destination admission rows preserve earlier ledger indices.
	CapTCPDestinationKernel  Capability = "net.tcp_destination_kernel"
	CapUnixDestinationKernel Capability = "net.unix_destination_kernel"
	// CapExecCommandArgv is an exec command rule's allow held to the argv it was decided on (ADR 0048 (9)): a
	// refusal is exact at every tier, an allow is the supervisor's copied fact until P2's exec pins hold it in the
	// kernel at a plane tier. Appended last, so no earlier row's index moves (R23).
	CapExecCommandArgv Capability = "exec.command_argv"
	// The five rows of ADR 0041 D7, appended last so that no earlier row's index moves (R23). Each says whether a
	// tier completes a kind of supervisor decision race-free, ADR 0041's outcome (A), rather than deciding it on
	// copied syscall facts and continuing it, outcome (D). The run's own (D) cells are run_start.best_effort.
	//
	// CapGateFSOpenCompletion is an open a scored gate allows, completed on the object it scored: conditional at every
	// tier on the contract's gate.completion: held, whose in-run open deputy completes it (ADR 0041 Stage B); a run
	// records it true only while its deputy serves (an ask-range score is held either way, ADR 0008).
	CapGateFSOpenCompletion Capability = "gate.fs_open_completion"
	// CapGateFSMutationCompletion is a non-open mutation (unlink, rename, link, symlink, mkdir, mknod, truncate) or a
	// mode change a write gate allows, completed race-free: no tier, since no kernel layer evaluates a gate predicate
	// and ADR 0041 rejects emulating them (rejected option 14).
	CapGateFSMutationCompletion Capability = "gate.fs_mutation_completion"
	// CapGateExecCompletion is an exec a scored gate allows, held to the image and argv it scored: no tier, since the
	// kernel copies argv again after any decision.
	CapGateExecCompletion Capability = "gate.exec_completion"
	// CapGateNetCompletion is a connect, Fast-Open send or addressed datagram a net gate allows, performed on the
	// duplicate socket with the address it scored (ADR 0041 D6): every tier, on IP-domain sockets; addressed unix
	// datagrams stay (D); enforcing Unix stream connects use the held-inode relay (ADR 0113).
	CapGateNetCompletion Capability = "gate.net_completion"
	// CapProtectedWriteTargets is the deny_write set refused race-free, the built-in targets (agent-contract R20) and a
	// contract's fs.deny_write entries (ADR 0071) alike, since both are RuleTable.DenyWrite: only a kernel decision
	// plane, deciding by inode. It is not CapFileWriteDeny, which concerns declared grants and must not flip with the
	// plane a run gets (ADR 0041 D7).
	CapProtectedWriteTargets Capability = "fs.protected_write_targets"
	// CapSocketFamilies is ADR 0018's bound on which sockets exist under a net: section: every socket the run makes, or
	// turns another into, is one the allowlist admits (TCP, UDP, unix, netlink, and ping sockets with an ICMP entry),
	// decided in the kernel on every path it can take. Tier 1's seccomp arm decides socket(2) and socketpair(2), and
	// refuses setsockopt(2)'s TCP_ULP (ADR 0018 (7)), with io_uring refused; tier 2 adds cgroup/sock_create for every
	// inet socket and cgroup/setsockopt for every TCP_ULP on any path, and a plane mode's socket_create every family,
	// io_uring's IORING_OP_SOCKET included. A run narrows it from its attachments (NetworkGuarantees.SocketFamilies),
	// and a contract with no net: section has it false. A socket made outside the run and passed in is the socket-import
	// guard's (NetworkGuarantees.SocketImportsDenied), not this row's. Appended last, so no earlier row's index moves
	// (R23).
	CapSocketFamilies Capability = "net.socket_families"
	// CapHostSocketsRefused: a run whose contract has no net: section and no host_sockets: true reaches only its own
	// unix sockets and Tego's endpoints; every other unix destination is refused, rule host-sockets (ADR 0070). Tier 1
	// holds it by the supervisor's relay of every connect and of the datagrams it can reproduce (supervisor R7b), the
	// rest best effort below Landlock ABI 9 (host_sockets/datagram); the root tiers hold it by the same relay and
	// Landlock, with no kernel program of the run deciding it, so they have it false until their unix
	// programs are attached (ADR 0070 (5)). A run sets it from its contract and its supervisor
	// (capabilityLine). Appended last (R23).
	CapHostSocketsRefused Capability = "net.host_sockets_refused"
	// CapReadDenyNested is a deny_read target at or beneath a write entry, whose reads the Landlock ruleset cannot
	// withhold: held reads refuse them at tier landlock, the root tiers' kernel refuses them itself (ADR 0069). The
	// three deny_read rows are appended last, so no earlier row's index moves (R23).
	CapReadDenyNested Capability = "fs.deny_read.nested"
	// CapReadDenyCreatedLater is a file a deny_read name rule covers that was made during the run: no ruleset row or
	// plane row names it (ADR 0069 D3 (c), ADR 0043).
	CapReadDenyCreatedLater Capability = "fs.deny_read.created_later"
	// CapReadDenyMoved is a deny_read target inside a write entry the agent renamed or hard-linked to another name
	// before reading it there (ADR 0069 D3(b), retained launch identities).
	CapReadDenyMoved Capability = "fs.deny_read.moved"
)

// allCapabilities is the fixed row order (R23).
var allCapabilities = [...]Capability{
	CapFileWriteDeny, CapFileDeleteRename, CapReadDeny, CapExecDeny, CapNetHostDeny,
	CapUDPByDestination, CapUDPPortInKernel, CapUnixSockets, CapAsk, CapRecordExecOpenNet,
	CapRecordReads, CapCaptureModel, CapLogAllowed, CapAdoptedContainers, CapNetHTTPRules,
	CapNamespaceSandbox, CapUnixAbstractScope, CapChmodDeny,
	CapTCPDestinationKernel, CapUnixDestinationKernel, CapExecCommandArgv,
	CapGateFSOpenCompletion, CapGateFSMutationCompletion, CapGateExecCompletion, CapGateNetCompletion,
	CapProtectedWriteTargets, CapSocketFamilies, CapHostSocketsRefused,
	CapReadDenyNested, CapReadDenyCreatedLater, CapReadDenyMoved,
}

// AllCapabilities returns the thirty-one capabilities in CAPABILITIES.md row order; a fresh slice.
func AllCapabilities() []Capability { return append([]Capability(nil), allCapabilities[:]...) }

// Valid reports whether c is one of the thirty-one rows.
func (c Capability) Valid() bool {
	for _, k := range allCapabilities {
		if k == c {
			return true
		}
	}
	return false
}

// String returns the row name.
func (c Capability) String() string { return string(c) }

// Title is the row's human heading as printed in CAPABILITIES.md.
func (c Capability) Title() string {
	if t, ok := capabilityTitles[c]; ok {
		return t
	}
	return string(c)
}

// Set is the capability matrix of one run: a value produced once per run and attached to
// run_start. An absent key means "not provided"; a nil Set is valid and provides nothing.
type Set map[Capability]bool

// Has reports whether the set provides c.
func (s Set) Has(c Capability) bool { return s[c] }

// Line is one rendered row of the matrix. Detail mirrors the CAPABILITIES.md cell for the tier
// the line was rendered for, or is empty when the Set was reported without a tier.
type Line struct {
	Capability Capability
	Present    bool
	Detail     string
}

// Report renders s as one Line per capability in AllCapabilities order (R23: never reordered, so
// two runs' reports are index-comparable). Pre: none (nil is valid). Post: len == len(AllCapabilities()). Pure.
func (s Set) Report() []Line {
	lines := make([]Line, len(allCapabilities))
	for i, c := range allCapabilities {
		lines[i] = Line{Capability: c, Present: s.Has(c)}
	}
	return lines
}

// ReportFor is Report with each line's Detail filled from tier's CAPABILITIES.md column.
func (s Set) ReportFor(tier Tier) []Line {
	lines := s.Report()
	for i := range lines {
		lines[i].Detail = MatrixDetail(tier, lines[i].Capability)
	}
	return lines
}

// Clone returns a copy of s; nil stays nil.
func (s Set) Clone() Set {
	if s == nil {
		return nil
	}
	out := make(Set, len(s))
	for k, v := range s {
		out[k] = v
	}
	return out
}

// WriteReport prints lines as a fixed-width table ("yes"/"no", then the detail when present).
func WriteReport(w io.Writer, lines []Line) error {
	width := 0
	for _, l := range lines {
		if n := len(l.Capability.Title()); n > width {
			width = n
		}
	}
	for _, l := range lines {
		row := fmt.Sprintf("%-*s  %-3s", width, l.Capability.Title(), yesNo(l.Present))
		if l.Detail != "" {
			row += "  " + l.Detail
		}
		if _, err := io.WriteString(w, strings.TrimRight(row, " ")+"\n"); err != nil {
			return fmt.Errorf("backend: write report: %w", err)
		}
	}
	return nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
