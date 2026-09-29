// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// kernelConnectLine is the tier-2 kernel record's half of one connect, modelled on
// bpf/trace_proc.bpf.c's fentry/security_socket_connect: it writes a line only when a recorder reads the
// run's ring (reading), the run's row records at all (record is not off, tego_recording), the agent's own
// task made the connect (this loop answered CONTINUE; a relay runs from the launcher's cgroup, a refusal
// never reaches the hook), and the address is AF_INET or AF_INET6 with a length move_addr_to_kernel takes
// and at least the family's own (sizeof(sockaddr_in), SIN6_LEN_RFC2133).
func kernelConnectLine(reading bool, rec agent.RecordMode, continued bool, family byte, addrlen int) int {
	if !reading || rec == agent.RecordOff || !continued || addrlen > sockaddrMax {
		return 0
	}
	switch {
	case family == unix.AF_INET && addrlen >= unix.SizeofSockaddrInet4:
	case family == unix.AF_INET6 && addrlen >= 24:
	default:
		return 0
	}
	return 1
}

// TestEveryConnectHasExactlyOneLine is R7's "one line per connect" across tier × record × net: section ×
// verdict. With no net: section, at tier 2, the kernel recorder's security_socket_connect line and this
// loop's best-effort line both recorded the agent's own IP connect: two lines for one connect. The
// kernel's line is the one kept (its address is the kernel's own copy), so this loop writes none when the
// run's recorder reads (Options.KernelConnects); with no recorder, or one that reads nothing, its line is
// the only one. A refused connect never reaches the kernel's hook outside an observe run, and an observe
// run has no kernel recorder (its handle is no enforce.KernelRecorder), so its line is always this loop's.
// No combination leaves a connect with no line, except an allowed one under record: off, which keeps no
// allowed line at any tier by design.
func TestEveryConnectHasExactlyOneLine(t *testing.T) {
	const addr, unmapped = 0x40000, 0x7f0000
	type tier struct {
		name    string
		reading bool // a kernel recorder reads this run's ring
		kernel  bool // the run has a kernel recorder at all: Options.KernelConnects is set
		observe bool
	}
	tiers := []tier{
		{name: "tier 1"},
		{name: "tier 2", reading: true, kernel: true},
		{name: "tier 2 recorder reads nothing", kernel: true},
		{name: "observe", observe: true},
	}
	type dst struct {
		name   string
		sa     []byte
		family byte
	}
	allowed := []dst{
		{"v4", sockaddrIn4("203.0.113.9", 443), unix.AF_INET},
		{"v6", sockaddrIn6("2001:db8::9", 443), unix.AF_INET6},
		{"unix", sockaddrUn("@svc"), unix.AF_UNIX},
	}
	refusedUnderNet := []dst{
		{"v4", sockaddrIn4("198.51.100.7", 443), unix.AF_INET},
		{"v6", sockaddrIn6("2001:db8::7", 443), unix.AF_INET6},
		{"unix", sockaddrUn("@other"), unix.AF_UNIX},
	}
	entries := []agent.NetRule{
		netRule("svc:443", "svc", 443, "203.0.113.9", "2001:db8::9"),
		unixRuleOf("unix:@svc", "svc", true),
	}
	for _, tr := range tiers {
		for _, rec := range []agent.RecordMode{agent.RecordOff, agent.RecordSummary, agent.RecordFull} {
			for _, netSection := range []bool{false, true} {
				for _, refuse := range []bool{false, true} {
					dsts := allowed
					if refuse && netSection {
						dsts = refusedUnderNet
					}
					for _, d := range dsts {
						name := fmt.Sprintf("%s/record=%s/net=%v/refuse=%v/%s", tr.name, rec, netSection, refuse, d.name)
						t.Run(name, func(t *testing.T) {
							f := newFake()
							f.put(addr, d.sa)
							if d.family == unix.AF_UNIX {
								f.sockDomain = unix.AF_UNIX
							}
							ct := agent.Contract{HostSockets: true} // the opt-out's continued connects; the unix-only state relays (ADR 0070)
							var rules []agent.NetRule
							if netSection {
								ct.Net = &agent.NetSection{}
								rules = entries
							}
							pol := contractPolicy(&ct, rules, nil)
							pol.Record = rec
							pol.Observe = tr.observe
							opts := Options{kernel: f, Workers: 1}
							asked := 0
							if tr.kernel && rec != agent.RecordOff {
								opts.KernelConnects = func() bool {
									asked++
									if _, ok := f.lastResp(); !ok {
										t.Error("KernelConnects asked before the connect was answered: a wait there holds the agent")
									}
									return tr.reading
								}
							}
							sink := &testSink{}
							l, err := New(testListener(), pol, sink, opts)
							if err != nil {
								t.Fatal(err)
							}
							ptr := uint64(addr)
							unreadable := refuse && !netSection
							if unreadable {
								// With no net: section nothing refuses a destination, not even one this loop
								// cannot read (R5, passesUnresolved): it is continued and recorded observed by
								// this loop, since the kernel's own copy of an unmapped address fails EFAULT
								// before its hook.
								ptr = unmapped
							}
							l.handle(notifFor(connectNR(), 4242, 5, ptr, uint64(len(d.sa))))
							resp, ok := f.lastResp()
							if !ok {
								t.Fatal("the connect was not answered")
							}
							continued := resp.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0
							sup := 0
							for _, ev := range sink.all() {
								if ev.Kind == record.KindNet {
									sup++
								}
							}
							kern := kernelConnectLine(tr.reading, rec, continued, d.family, len(d.sa))
							if unreadable {
								kern = 0
							}
							want := 1
							if (!refuse || unreadable) && rec == agent.RecordOff {
								want = 0 // record: off keeps no allowed or observed line, at any tier
							}
							if sup+kern != want {
								t.Errorf("%d lines (supervisor %d, kernel %d; continued=%v), want %d", sup+kern, sup, kern,
									continued, want)
							}
							if kern == 1 && sup != 0 {
								t.Errorf("the supervisor wrote a line for a connect the kernel records")
							}
						})
					}
				}
			}
		}
	}
}

// TestContinuedConnectsTheKernelDoesNotRecordKeepTheirLine: at tier 2 with no net: section, a continued
// connect the kernel's hook does not record keeps this loop's best-effort line even while the recorder
// reads: a unix connect (no name at that hook), connect(2)'s AF_UNSPEC, a family neither parses, and an
// IP address longer than sockaddr_storage, which move_addr_to_kernel refuses before the hook, and one
// shorter than its family's address, which the hook returns early for. The recorder is never asked for them.
func TestContinuedConnectsTheKernelDoesNotRecordKeepTheirLine(t *testing.T) {
	const addr = 0x40000
	netlink := make([]byte, 12)
	netlink[0] = unix.AF_NETLINK
	long := make([]byte, sockaddrMax+8)
	copy(long, sockaddrIn4("203.0.113.9", 443))
	for _, tc := range []struct {
		name string
		sa   []byte
	}{
		{"unix", sockaddrUn("@svc")},
		{"AF_UNSPEC", unspecSockaddr("203.0.113.9", 443)},
		{"netlink", netlink},
		{"an address past sockaddr_storage", long},
		{"an AF_INET address shorter than sockaddr_in", sockaddrIn4("203.0.113.9", 443)[:8]},
		{"an AF_INET address of only its family word", sockaddrIn4("203.0.113.9", 443)[:2]},
		{"an AF_INET6 address shorter than SIN6_LEN_RFC2133", sockaddrIn6("2001:db8::9", 443)[:16]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(addr, tc.sa)
			pol := contractPolicy(&agent.Contract{HostSockets: true}, nil, nil)
			sink := &testSink{}
			l, err := New(testListener(), pol, sink, Options{kernel: f, Workers: 1, KernelConnects: func() bool {
				t.Error("asked the recorder about a connect its hook does not record")
				return true
			}})
			if err != nil {
				t.Fatal(err)
			}
			l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(tc.sa))))
			if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
				t.Fatalf("response = %+v, want CONTINUE", got)
			}
			var p netPayload
			if err := sink.one(t).DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if !p.BestEffort {
				t.Errorf("line %+v, want this loop's best-effort line", p)
			}
		})
	}
}
