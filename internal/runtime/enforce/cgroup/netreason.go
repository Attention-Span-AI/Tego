// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"net/netip"
	"time"

	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// BreadcrumbStale is how much older than the notification a breadcrumb may be and still be read as the
// decision on it (§6 E5). The row is one per run, last write wins, so an older one is some other connect's.
const BreadcrumbStale = 50 * time.Millisecond

// KernelNet is the reading half of §5 R5, for the supervisor (supervisor.Options.KernelNet): what this run's
// connect4/6 decided about an IP connect to ap on proto ("tcp" or "udp") that the supervisor relayed on the
// agent's socket, having received its notification at notified. It answers VerdictRefused with the rule and the ledger reason the
// breadcrumb carries, VerdictAllow when the programs admitted it (or none is attached, under a contract with no
// net: section), and "" when the run's breadcrumb does not name this connect: none, another run's slot, a
// datagram, another destination or protocol (a connect on the other protocol to the same address and port
// overwrites the one row too), a reason byte with no ledger code, or a decision made more than
// BreadcrumbStale before the notification arrived (E5). A read error is "" too: the caller then records
// `observed` rather than guess.
func (h *Handle) KernelNet(ap netip.AddrPort, proto string, notified time.Time) (record.Verdict, string, record.Reason) {
	if !h.prepared || h.kern == nil {
		return "", "", ""
	}
	rules := h.Rules()
	if rules.Unrestricted {
		return record.VerdictAllow, "", ""
	}
	br, found, err := h.kern.breadcrumb(h.run.CgroupID)
	if err != nil || !found {
		return "", "", ""
	}
	var ipproto uint8
	switch proto {
	case agent.ProtoTCP:
		ipproto = unix.IPPROTO_TCP
	case agent.ProtoUDP:
		ipproto = unix.IPPROTO_UDP
	default:
		return "", "", ""
	}
	if br.Op != uint8(ebpfbindings.KindConnect) || br.RunIdx != h.slot || br.Proto != ipproto || br.Port != ap.Port() ||
		breadcrumbAddr(br) != ap.Addr().WithZone("").Unmap() {
		return "", "", ""
	}
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return "", "", ""
	}
	// bpf_ktime_get_ns is CLOCK_MONOTONIC; notified carries Go's monotonic reading, so its age maps it there.
	cutoff := ts.Nano() - time.Since(notified).Nanoseconds() - BreadcrumbStale.Nanoseconds()
	if cutoff > 0 && br.MonoNS < uint64(cutoff) {
		return "", "", ""
	}
	switch ebpfbindings.Verdict(br.Verdict) {
	case ebpfbindings.VerdictAllow:
		return record.VerdictAllow, "", ""
	case ebpfbindings.VerdictRefused:
		reason := kernelReason(ebpfbindings.ReasonCode(br.Reason))
		if reason == "" {
			return "", "", ""
		}
		rule := rules.RuleName(br.RuleIdx)
		if rule == "" {
			rule = agent.UnmatchedRule
		}
		return record.VerdictRefused, rule, reason
	}
	return "", "", ""
}

// breadcrumbAddr is the destination a breadcrumb names, a v4-mapped address unmapped as the supervisor does.
func breadcrumbAddr(br ebpfbindings.Breadcrumb) netip.Addr {
	if br.Family == ebpfbindings.AFInet {
		return netip.AddrFrom4([4]byte(br.Addr[:4]))
	}
	return netip.AddrFrom16(br.Addr).Unmap()
}

// KernelDatagrams is what this run's own programs answer an addressed datagram whose destination they refuse, for
// the supervisor (supervisor.Options.KernelDatagrams; §5 R7, supervisor.md R13b): unixErrno for a unix name, EPERM
// where cgroup/sendmsg_unix is attached (6.7+) and EACCES where the decision plane's socket_sendmsg decides unix names
// in its place (enforce-plane §2.11), and udpErrno for a UDP destination, EPERM where cgroup/sendmsg4 and sendmsg6
// are attached. Each is 0 where no program of the run decides that family, and both are for a contract with no net:
// section, whose programs refuse nothing (Unrestricted), and for a handle not prepared, or detached or closed, as
// NetworkGuarantees reports. The supervisor refuses with that errno a datagram the program would refuse, so the
// datagram's one line is that refusal rather than a best-effort line beside the kernel's.
func (h *Handle) KernelDatagrams() (unixErrno, udpErrno unix.Errno) {
	if h.Rules().Unrestricted {
		return 0, 0
	}
	g := h.NetworkGuarantees()
	h.netMu.Lock()
	sockAddr := h.prepared && !h.detached && !h.closed && h.programGuarantees().UnixDestination
	h.netMu.Unlock()
	switch {
	case sockAddr:
		unixErrno = unix.EPERM // a cgroup sock_addr program's refusal
	case g.UnixDestination:
		unixErrno = unix.EACCES // the plane's step-D hooks, which return 0 or -EACCES (enforce-plane R2)
	}
	if g.UDPDestination {
		udpErrno = unix.EPERM
	}
	return unixErrno, udpErrno
}
