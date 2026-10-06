// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// dgramCase is one addressed datagram sent through sendto and through sendmsg, on a socket of domain and type
// with protocol proto, to the address sa.
type dgramCase struct {
	name               string
	domain, typ, proto int
	sa                 []byte
	kernel             KernelDatagrams
	// errno is the refusal this loop answers, 0 for a CONTINUE; verdict and rule are the one line's, and
	// bestEffort whether it carries the mark.
	errno      unix.Errno
	verdict    record.Verdict
	rule       string
	bestEffort bool
}

// dgramPolicy declares one unix datagram socket and one UDP endpoint under a net: section, beside a write entry
// beneath which the run binds sockets of its own (SEMANTICS §5, R11a): runDgram has it bind /work/own.dg.
func dgramPolicy() *Policy {
	return contractPolicy(&agent.Contract{Net: &agent.NetSection{}}, []agent.NetRule{
		unixRuleOf("unix:/run/listed.dg", "/run/listed.dg", false),
		netRule("192.0.2.10:5353", "", 5353, "192.0.2.10"),
	}, []agent.FSRule{{Path: "/work", Kind: agent.FSWrite}})
}

// runDgram sends c through one of the two syscalls and returns the answer, the lines and the sends the loop made.
func runDgram(t *testing.T, c dgramCase, pol *Policy, form string) (sysResp, []*record.Event, *fakeKernel) {
	t.Helper()
	const addr, buf, hdrAt, iovAt = 0x40000, 0x50000, 0x60000, 0x70000
	f := newFake()
	f.sockType, f.sockDomain, f.sockProto = c.typ, c.domain, c.proto
	f.put(addr, c.sa)
	f.put(buf, []byte("hello"))
	hdr := namedMsgHdr(addr, uint32(len(c.sa)))
	putU64(hdr[msgIovOff:], iovAt)
	putU64(hdr[msgIovLenOff:], 1)
	iov := make([]byte, iovecSize)
	putU64(iov, buf)
	putU64(iov[8:], 5)
	f.put(iovAt, iov)
	f.put(hdrAt, hdr)
	sink := &testSink{}
	l, err := New(testListener(), pol, sink, Options{kernel: f, Workers: 1, KernelDatagrams: c.kernel})
	if err != nil {
		t.Fatal(err)
	}
	// The run binds /work/own.dg itself, so the write entry's implicit admit holds for it (R11a).
	f.bindsSocket(t, l, sockID{ino: 9100, cookie: 5}, "/work/own.dg")
	if form == "sendto" {
		l.handle(notifFor(sendToNR(), 42, 5, buf, 5, 0, addr, uint64(len(c.sa))))
	} else {
		l.handle(notifFor(sendMsgNR(), 42, 5, hdrAt, 0))
	}
	r, _ := f.lastResp()
	return r, sink.all(), f
}

// TestKernelDecidedDatagramIsRefusedHere is DGRAM-VERDICT (R13b, enforce-cgroup-observe §5 R7, ADR 0016): where a
// kernel program of the run decides an addressed datagram's destination on the kernel's own copy of the address
// (Options.KernelDatagrams), a datagram that program refuses is refused by this loop, with that program's errno,
// and its one line is that refusal, with no best_effort. Continued, the line said refused with best_effort of a
// refusal the kernel enforced, and allow of a non-canonical unix name the kernel refused. A destination the policy
// refuses that no program decides — a relative unix name, an address the protocol's own checks fail first, a
// family or protocol no program of the run is attached for — is refused with R10's errno (R13b as amended
// 2026-10-16), and only an admitted destination is continued, with a best_effort line.
func TestKernelDecidedDatagramIsRefusedHere(t *testing.T) {
	cgroup := KernelDatagrams{Unix: unix.EPERM, UDP: unix.EPERM}
	plane := KernelDatagrams{Unix: unix.EACCES}
	dgram, udp := unix.SOCK_DGRAM, unix.IPPROTO_UDP
	cases := []dgramCase{
		{"unix unlisted, sendmsg_unix", unix.AF_UNIX, dgram, 0, sockaddrUn("/run/other.dg"), cgroup,
			unix.EPERM, record.VerdictRefused, ruleUnmatched, false},
		{"unix unlisted, step D", unix.AF_UNIX, dgram, 0, sockaddrUn("/run/other.dg"), plane,
			unix.EACCES, record.VerdictRefused, ruleUnmatched, false},
		{"unix non-canonical under a write entry", unix.AF_UNIX, dgram, 0, sockaddrUn("/work/./own.dg"), cgroup,
			unix.EPERM, record.VerdictRefused, ruleUnmatched, false},
		{"unix non-canonical listed name", unix.AF_UNIX, dgram, 0, sockaddrUn("/run//listed.dg"), plane,
			unix.EACCES, record.VerdictRefused, ruleUnmatched, false},
		{"unix trailing slash", unix.AF_UNIX, dgram, 0, sockaddrUn("/work/own.dg/"), cgroup,
			unix.EPERM, record.VerdictRefused, ruleUnmatched, false},
		{"unix abstract unlisted", unix.AF_UNIX, dgram, 0, sockaddrUn("@other"), cgroup,
			unix.EPERM, record.VerdictRefused, ruleUnmatched, false},
		{"unix listed", unix.AF_UNIX, dgram, 0, sockaddrUn("/run/listed.dg"), cgroup,
			0, record.VerdictAllow, "net[unix:/run/listed.dg]", true},
		{"unix under a write entry", unix.AF_UNIX, dgram, 0, sockaddrUn("/work/own.dg"), cgroup,
			0, record.VerdictAllow, "fs.write[/work]", true},
		{"unix under a write entry the run did not bind: refused here", unix.AF_UNIX, dgram, 0,
			sockaddrUn("/work/stranger.dg"), cgroup, unix.EACCES, record.VerdictRefused, ruleUnixForeign, false},
		{"unix relative: the kernel leaves it to tier 1", unix.AF_UNIX, dgram, 0, sockaddrUn("own.dg"), cgroup,
			unix.EACCES, record.VerdictRefused, rulePathUnreliable, false}, // the fake has no /proc/<pid>/cwd
		{"unix with no program", unix.AF_UNIX, dgram, 0, sockaddrUn("/run/other.dg"), KernelDatagrams{UDP: unix.EPERM},
			unix.EACCES, record.VerdictRefused, ruleUnmatched, false},
		{"unix name on an IP socket: no program decides it", unix.AF_INET, dgram, udp,
			sockaddrUn("/run/other.dg"), cgroup, unix.EACCES, record.VerdictRefused, ruleUnmatched, false},
		{"udp unlisted", unix.AF_INET, dgram, udp, sockaddrIn4("203.0.113.9", 9999), cgroup,
			unix.EPERM, record.VerdictRefused, ruleUnmatched, false},
		{"udp6 unlisted", unix.AF_INET6, dgram, udp, sockaddrIn6("2001:db8::9", 9999), cgroup,
			unix.EPERM, record.VerdictRefused, ruleUnmatched, false},
		{"udp listed", unix.AF_INET, dgram, udp, sockaddrIn4("192.0.2.10", 5353), cgroup,
			0, record.VerdictAllow, "net[192.0.2.10:5353]", true},
		{"udp port 0: udp_sendmsg's EINVAL first, no program", unix.AF_INET, dgram, udp, sockaddrIn4("203.0.113.9", 0), cgroup,
			unix.EACCES, record.VerdictRefused, ruleUnmatched, false},
		{"udp with no program", unix.AF_INET, dgram, udp, sockaddrIn4("203.0.113.9", 9999), plane,
			unix.EACCES, record.VerdictRefused, ruleUnmatched, false},
		{"udp6 address on an IPv4 socket: EAFNOSUPPORT first, no program", unix.AF_INET, dgram, udp,
			sockaddrIn6("2001:db8::9", 9999), cgroup, unix.EACCES, record.VerdictRefused, ruleUnmatched, false},
		{"udp v4 address on an IPv6 socket: IPV6_V6ONLY decides, no program", unix.AF_INET6, dgram, udp,
			sockaddrIn4("203.0.113.9", 9999), cgroup, unix.EACCES, record.VerdictRefused, ruleUnmatched, false},
		{"ping socket: no sendmsg4 there", unix.AF_INET, dgram, unix.IPPROTO_ICMP,
			sockaddrIn4("203.0.113.9", 9999), cgroup, unix.EACCES, record.VerdictRefused, ruleUnmatched, false},
	}
	for _, c := range cases {
		for _, form := range []string{"sendto", "sendmsg"} {
			t.Run(c.name+"/"+form, func(t *testing.T) {
				r, evs, f := runDgram(t, c, dgramPolicy(), form)
				if len(f.sends) != 0 {
					t.Fatalf("the loop sent the datagram itself (%d sends)", len(f.sends))
				}
				switch {
				case c.errno == 0 && r.Flags != unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE:
					t.Fatalf("answer %+v, want CONTINUE", r)
				case c.errno != 0 && (r.Flags != 0 || r.Error != -int32(c.errno)):
					t.Fatalf("answer %+v, want the kernel program's %v", r, c.errno)
				}
				if len(evs) != 1 {
					t.Fatalf("%d lines, want exactly one: %+v", len(evs), evs)
				}
				var p netPayload
				if err := evs[0].DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				if evs[0].Verdict != c.verdict || evs[0].Rule != c.rule || p.BestEffort != c.bestEffort {
					t.Fatalf("line %s/%s best_effort=%t, want %s/%s best_effort=%t", evs[0].Verdict, evs[0].Rule,
						p.BestEffort, c.verdict, c.rule, c.bestEffort)
				}
				if c.verdict == record.VerdictRefused && evs[0].Reason != record.ReasonNetNotAllowed {
					t.Fatalf("reason %s, want %s", evs[0].Reason, record.ReasonNetNotAllowed)
				}
			})
		}
	}
}

// TestKernelDecidedDatagramNeedsANetSection: with no net: section the run's programs decide nothing (SEMANTICS §1),
// so every datagram is continued under the best-effort line it had, however KernelDatagrams reads.
func TestKernelDecidedDatagramNeedsANetSection(t *testing.T) {
	kd := KernelDatagrams{Unix: unix.EPERM, UDP: unix.EPERM}
	for _, c := range []dgramCase{
		{"unix", unix.AF_UNIX, unix.SOCK_DGRAM, 0, sockaddrUn("/run/other.dg"), kd, 0, record.VerdictAllow, ruleUnmatched, true},
		{"udp", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP, sockaddrIn4("203.0.113.9", 9999), kd, 0,
			record.VerdictAllow, ruleUnmatched, true},
	} {
		r, evs, _ := runDgram(t, c, contractPolicy(&agent.Contract{HostSockets: true}, nil, nil), "sendto")
		if r.Flags != unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE || len(evs) != 1 || evs[0].Verdict != c.verdict {
			t.Fatalf("%s: answer %+v, lines %+v; want CONTINUE and one %s line", c.name, r, evs, c.verdict)
		}
	}
}

// TestKernelDecidedUnixDatagramIsNeverRelayedUnderAGate keeps ADR 0041's rejected alternative 7 under the kernel's
// refusal too: a net gate that admits a unix datagram the run's kernel program refuses neither relays it nor
// continues it; it is refused with that program's errno, and an admitted one is continued as before.
func TestKernelDecidedUnixDatagramIsNeverRelayedUnderAGate(t *testing.T) {
	kd := KernelDatagrams{Unix: unix.EPERM}
	for _, c := range []dgramCase{
		{"refused", unix.AF_UNIX, unix.SOCK_DGRAM, 0, sockaddrUn("/work/./own.dg"), kd, unix.EPERM,
			record.VerdictRefused, ruleUnmatched, false},
		{"admitted", unix.AF_UNIX, unix.SOCK_DGRAM, 0, sockaddrUn("/work/own.dg"), kd, 0,
			record.VerdictAllow, "fs.write[/work]", true},
	} {
		pol := dgramPolicy()
		pol.Rules.Gate = testGate(t, gate.NetTo, "93.184.216.34:443", 90)
		for _, form := range []string{"sendto", "sendmsg"} {
			r, evs, f := runDgram(t, c, pol, form)
			name := fmt.Sprintf("%s/%s", c.name, form)
			if len(f.sends) != 0 {
				t.Fatalf("%s: the supervisor sent the agent's unix datagram itself", name)
			}
			if c.errno != 0 && r.Error != -int32(c.errno) || c.errno == 0 && r.Flags != unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE {
				t.Fatalf("%s: answer %+v", name, r)
			}
			if len(evs) != 1 || evs[0].Verdict != c.verdict {
				t.Fatalf("%s: lines %+v, want one %s", name, evs, c.verdict)
			}
		}
	}
}
