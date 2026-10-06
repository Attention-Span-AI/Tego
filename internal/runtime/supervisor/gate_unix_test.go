//go:build amd64 || arm64

// SPDX-License-Identifier: Apache-2.0
package supervisor

import (
	"context"
	"fmt"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

// TestGateNeverRelaysUnixDatagrams keeps a network gate an escalation only (ADR 0007, gate.md R4) for an
// AF_UNIX datagram. The copied-address relay that closes the rewrite race for a gated UDP sendto/sendmsg
// was taken for every allowed datagram, so under any `net` gate rule this process sent the agent's unix
// datagram itself (relayDatagram): a relative name resolved against this process's cwd, an abstract name
// escaped the agent's Landlock scope, and at tiers 2/3 a root-only socket accepted it with the receiver
// reading this process's credentials — handleConnect's reason for never relaying a unix connect. A unix
// datagram the gate scores Allow is answered exactly as without the gate (R13b's best effort: CONTINUE,
// ancillary data included, so the kernel sends it as the agent); one the gate asks about is refused
// unsupported. Nothing is ever sent from here.
func TestGateNeverRelaysUnixDatagrams(t *testing.T) {
	const addr, buf, hdrAt, iovAt = 0x40000, 0x50000, 0x60000, 0x70000
	rules := []struct {
		p     gate.Predicate
		arg   string
		score int
	}{{gate.NetTo, "93.184.216.34:443", 90}, {gate.NetUndeclared, "", 70}}
	for _, dst := range []string{"/run/systemd/journal/socket", "rel.sock", "@abstract-outside"} {
		for _, declared := range []bool{false, true} {
			for _, form := range []string{"sendto", "sendmsg", "sendmsg+control"} {
				for _, rule := range rules {
					run := func(gated bool) (sysResp, *fakeKernel, []*record.Event) {
						f := newFake()
						f.sockType = unix.SOCK_DGRAM
						f.sockDomain = unix.AF_UNIX
						// The relative name resolves against the task's cwd, as decideUnix reads it: a name this
						// loop cannot place is refused (R13b as amended 2026-10-16), and the baseline is a send
						// the policy admits.
						f.links["/proc/42/cwd"] = "/work"
						sa := sockaddrUn(dst)
						f.put(addr, sa)
						f.put(buf, []byte("hello"))
						hdr := namedMsgHdr(addr, uint32(len(sa)))
						putU64(hdr[msgIovOff:], iovAt)
						putU64(hdr[msgIovLenOff:], 1)
						if form == "sendmsg+control" {
							putU64(hdr[msgControlLenOff:], 24)
						}
						iov := make([]byte, iovecSize)
						putU64(iov, buf)
						putU64(iov[8:], 5)
						f.put(iovAt, iov)
						f.put(hdrAt, hdr)
						pol := contractPolicy(&agent.Contract{HostSockets: true}, nil, nil)
						if declared {
							path, abstract := dst, dst[0] == '@'
							if abstract {
								path = dst[1:]
							} else if dst[0] != '/' {
								path = "/work/" + dst
							}
							pol = testPolicy([]agent.NetRule{
								netRule("93.184.216.34:443", "", 443, "93.184.216.34"),
								unixRuleOf("unix:"+dst, path, abstract),
							}, nil, nil)
						}
						if gated {
							pol.Rules.Gate = testGate(t, rule.p, rule.arg, rule.score)
						}
						l, sink := newTestLoop(t, f, pol)
						l.ask = func(context.Context, ask.Request) (ask.Decision, error) {
							t.Error("unsupported unix datagram prompted")
							return ask.Decision{}, nil
						}
						if form == "sendto" {
							l.handle(notifFor(sendToNR(), 42, 5, buf, 5, 0, addr, uint64(len(sa))))
						} else {
							l.handle(notifFor(sendMsgNR(), 42, 5, hdrAt, 0))
						}
						r, _ := f.lastResp()
						return r, f, sink.all()
					}
					name := fmt.Sprintf("%s declared=%t %s gate=%d:%d", dst, declared, form, rule.p, rule.score)
					base, bf, _ := run(false)
					if len(bf.sends) != 0 || base.Flags != unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE {
						t.Fatalf("%s: ungated baseline %+v sends %d", name, base, len(bf.sends))
					}
					r, f, evs := run(true)
					if len(f.sends) != 0 {
						t.Fatalf("%s: the supervisor sent the agent's unix datagram itself: response %+v, sent to %q", name, r, f.sends[0].addr)
					}
					if rule.p == gate.NetUndeclared && !declared {
						// An undeclared unix name scored into the ask range: unsupported completion (R4).
						if r.Flags != 0 || r.Error != -int32(unix.EACCES) || len(evs) != 1 || evs[0].Authority != record.AuthorityGate {
							t.Fatalf("%s: ask on a unix datagram not refused unsupported: response %+v events %+v", name, r, evs)
						}
						continue
					}
					if r.Flags != base.Flags || r.Error != base.Error || r.Val != base.Val {
						t.Fatalf("%s: a gate Allow changed the answer: without the gate %+v, with it %+v", name, base, r)
					}
					if len(evs) != 1 {
						t.Fatalf("%s: want one line, got %+v", name, evs)
					}
					var p netPayload
					if e := evs[0].DecodePayload(&p); e != nil {
						t.Fatal(e)
					}
					if !p.BestEffort {
						t.Fatalf("%s: continued unix datagram line %+v payload %+v", name, evs[0], p)
					}
				}
			}
		}
	}
}
