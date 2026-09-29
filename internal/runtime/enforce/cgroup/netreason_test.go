// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func monoNow(t *testing.T) uint64 {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatal(err)
	}
	return uint64(ts.Nano())
}

// TestKernelNetReadsTheBreadcrumb is §5 R5's reading half and §6 E5: the run's breadcrumb answers for a relayed
// connect only when it is this run's, a connect, to this destination, and no more than 50 ms older than the
// notification; anything else is unknown rather than someone else's decision.
func TestKernelNetReadsTheBreadcrumb(t *testing.T) {
	const cg = 4242
	dst := netip.MustParseAddrPort("93.184.216.34:443")
	crumb := func(mono uint64) ebpfbindings.Breadcrumb {
		br := ebpfbindings.Breadcrumb{Op: uint8(ebpfbindings.KindConnect), Verdict: uint8(ebpfbindings.VerdictRefused),
			Reason: uint8(ebpfbindings.ReasonNetNotAllowed), Family: ebpfbindings.AFInet, Proto: unix.IPPROTO_TCP,
			Port: 443, MonoNS: mono, RunIdx: 3, RuleIdx: 1}
		copy(br.Addr[:], dst.Addr().AsSlice())
		return br
	}
	mapped := func(mono uint64) ebpfbindings.Breadcrumb {
		br := crumb(mono)
		br.Family = ebpfbindings.AFInet6
		br.Addr = netip.AddrFrom4(dst.Addr().As4()).As16()
		br.Addr[10], br.Addr[11] = 0xff, 0xff
		return br
	}
	tests := []struct {
		name       string
		br         func(now uint64) (ebpfbindings.Breadcrumb, bool)
		wantV      record.Verdict
		wantRule   string
		wantReason record.Reason
	}{
		{"fresh refusal", func(now uint64) (ebpfbindings.Breadcrumb, bool) { return crumb(now), true },
			record.VerdictRefused, "net[10.0.0.0/8:443]", record.ReasonNetNotAllowed},
		{"fresh refusal of the v4-mapped spelling", func(now uint64) (ebpfbindings.Breadcrumb, bool) { return mapped(now), true },
			record.VerdictRefused, "net[10.0.0.0/8:443]", record.ReasonNetNotAllowed},
		{"no rule index is unmatched", func(now uint64) (ebpfbindings.Breadcrumb, bool) {
			br := crumb(now)
			br.RuleIdx = 0
			return br, true
		}, record.VerdictRefused, "unmatched", record.ReasonNetNotAllowed},
		{"fresh allow", func(now uint64) (ebpfbindings.Breadcrumb, bool) {
			br := crumb(now)
			br.Verdict, br.Reason = uint8(ebpfbindings.VerdictAllow), 0
			return br, true
		}, record.VerdictAllow, "", ""},
		{"none", func(uint64) (ebpfbindings.Breadcrumb, bool) { return ebpfbindings.Breadcrumb{}, false }, "", "", ""},
		{"older than 50 ms before the notification", func(now uint64) (ebpfbindings.Breadcrumb, bool) {
			return crumb(now - uint64(time.Second)), true
		}, "", "", ""},
		{"another destination", func(now uint64) (ebpfbindings.Breadcrumb, bool) {
			br := crumb(now)
			br.Port = 80
			return br, true
		}, "", "", ""},
		{"a datagram, not a connect", func(now uint64) (ebpfbindings.Breadcrumb, bool) {
			br := crumb(now)
			br.Op = uint8(ebpfbindings.KindSendmsg)
			return br, true
		}, "", "", ""},
		{"another run's slot", func(now uint64) (ebpfbindings.Breadcrumb, bool) {
			br := crumb(now)
			br.RunIdx = 9
			return br, true
		}, "", "", ""},
		{"an unknown reason byte", func(now uint64) (ebpfbindings.Breadcrumb, bool) {
			br := crumb(now)
			br.Reason = 200
			return br, true
		}, "", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k := newFakeKernel()
			notified := time.Now()
			if br, ok := tc.br(monoNow(t)); ok {
				k.crumbs = map[uint64]ebpfbindings.Breadcrumb{cg: br}
			}
			h := &Handle{kern: k, prepared: true, slot: 3, run: Run{CgroupID: cg},
				rules: RuleMaps{Rules: []string{"", "net[10.0.0.0/8:443]"}}}
			v, rule, reason := h.KernelNet(dst, "tcp", notified)
			if v != tc.wantV || rule != tc.wantRule || reason != tc.wantReason {
				t.Errorf("KernelNet = %q %q %q, want %q %q %q", v, rule, reason, tc.wantV, tc.wantRule, tc.wantReason)
			}
		})
	}
}

// TestKernelNetMatchesTheProtocol is §6 E5's guard extended to the protocol: the breadcrumb is one row per run,
// so a connect on the other protocol to the same address and port can have written it last, and its decision is
// not this connect's.
func TestKernelNetMatchesTheProtocol(t *testing.T) {
	const cg = 4242
	dst := netip.MustParseAddrPort("93.184.216.34:443")
	for _, tc := range []struct {
		name   string
		crumb  uint8 // the breadcrumb's protocol
		asked  string
		wantV  record.Verdict
		reason record.Reason
	}{
		{"tcp asked, tcp written", unix.IPPROTO_TCP, "tcp", record.VerdictRefused, record.ReasonNetNotAllowed},
		{"udp asked, udp written", unix.IPPROTO_UDP, "udp", record.VerdictRefused, record.ReasonNetNotAllowed},
		{"udp asked, tcp written last", unix.IPPROTO_TCP, "udp", "", ""},
		{"tcp asked, udp written last", unix.IPPROTO_UDP, "tcp", "", ""},
		{"a protocol no program decides", unix.IPPROTO_TCP, "raw", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			br := ebpfbindings.Breadcrumb{Op: uint8(ebpfbindings.KindConnect), Verdict: uint8(ebpfbindings.VerdictRefused),
				Reason: uint8(ebpfbindings.ReasonNetNotAllowed), Family: ebpfbindings.AFInet, Proto: tc.crumb,
				Port: 443, MonoNS: monoNow(t), RunIdx: 3, RuleIdx: 1}
			copy(br.Addr[:], dst.Addr().AsSlice())
			k := newFakeKernel()
			k.crumbs = map[uint64]ebpfbindings.Breadcrumb{cg: br}
			h := &Handle{kern: k, prepared: true, slot: 3, run: Run{CgroupID: cg},
				rules: RuleMaps{Rules: []string{"", "net[10.0.0.0/8:443]"}}}
			v, _, reason := h.KernelNet(dst, tc.asked, time.Now())
			if v != tc.wantV || reason != tc.reason {
				t.Errorf("KernelNet(%s) = %q %q, want %q %q", tc.asked, v, reason, tc.wantV, tc.reason)
			}
		})
	}
}
