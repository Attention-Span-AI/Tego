// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// contractPolicy is testPolicy over a table that carries the contract it was compiled from, which is
// what the absent-section defaults are read off (SEMANTICS §1).
func contractPolicy(c *agent.Contract, net []agent.NetRule, fs []agent.FSRule) *Policy {
	pol := testPolicy(net, fs, nil)
	pol.Rules.Contract = c
	return pol
}

// TestConnectWithNoNetSection is SEMANTICS §1's "no net: — deny nothing" at the supervisor. The Landlock
// builder leaves the net rights unhandled when net: is absent, tier 2 attaches no network program and
// agent.Evaluate reports allow, while this loop matched every connect against a resolver set with no
// rules and refused all but DNS. It must not perform those connects either: a relay runs in this
// process, which has no Landlock domain and at tier 2 is root, so the agent reached an abstract name its
// scope refuses and a socket only root may open, with the listener reading this process's credentials.
// Each destination is answered CONTINUE, so the kernel runs the agent's own connect as the agent, and is
// recorded allow with best_effort, against unmatched or the entry that names it. `net: {}` keeps
// refusing.
func TestConnectWithNoNetSection(t *testing.T) {
	const addr = 0x40000
	netlink := make([]byte, 12) // struct sockaddr_nl: a family this tier does not parse
	netlink[0] = unix.AF_NETLINK
	for _, tc := range []struct {
		name     string
		tier     backend.Tier
		sa       []byte
		sockType int
		dst      string
		rule     string
	}{
		{"an undeclared host", backend.TierLandlock, sockaddrIn4("203.0.113.9", 443), unix.SOCK_STREAM, "203.0.113.9:443", ruleUnmatched},
		{"an undeclared unix socket", backend.TierLandlock, sockaddrUn("/run/user/1000/bus"), unix.SOCK_STREAM, "unix:/run/user/1000/bus", ruleUnmatched},
		{"an abstract name", backend.TierLandlock, sockaddrUn("@/tmp/.X11-unix/X0"), unix.SOCK_STREAM, "unix:@/tmp/.X11-unix/X0", ruleUnmatched},
		{"a family this tier does not parse", backend.TierLandlock, netlink, unix.SOCK_RAW, "family(16)", ruleUnmatched},
		{"a socket under a write entry", backend.TierLandlock, sockaddrUn("/work/app.sock"), unix.SOCK_STREAM, "unix:/work/app.sock", "fs.write[/work/]"},
		{"tier 2: an undeclared host", backend.TierCgroup, sockaddrIn4("203.0.113.9", 443), unix.SOCK_STREAM, "203.0.113.9:443", ruleUnmatched},
		{"tier 2: a root-only unix socket", backend.TierCgroup, sockaddrUn("/run/docker.sock"), unix.SOCK_STREAM, "unix:/run/docker.sock", ruleUnmatched},
		{"tier 2: an abstract name", backend.TierCgroup, sockaddrUn("@/tmp/.X11-unix/X0"), unix.SOCK_STREAM, "unix:@/tmp/.X11-unix/X0", ruleUnmatched},
		{"tier 2: netlink", backend.TierCgroup, netlink, unix.SOCK_RAW, "family(16)", ruleUnmatched},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(addr, tc.sa)
			f.sockType = tc.sockType
			pol := contractPolicy(&agent.Contract{HostSockets: true}, nil, []agent.FSRule{{Path: "/work", Raw: "/work/", Kind: agent.FSWrite}})
			pol.Rules.Tier = tc.tier
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(tc.sa))))
			if len(f.connects) != 0 {
				t.Fatalf("connects = %q, want none: the loop performs no connect under a contract with no net:", f.connects)
			}
			if got, ok := f.lastResp(); !ok || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 || got.Error != 0 {
				t.Fatalf("response = %+v, want CONTINUE: the kernel performs the agent's own connect", got)
			}
			ev := sink.one(t)
			var p netPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != record.VerdictAllow || ev.Rule != tc.rule || ev.Reason != "" || p.Dst != tc.dst || !p.BestEffort {
				t.Errorf("event = %s/%s/%q dst %s best_effort=%v, want allow/%s dst %s best_effort", ev.Verdict, ev.Rule, ev.Reason, p.Dst, p.BestEffort, tc.rule, tc.dst)
			}
		})
	}

	t.Run("net: {} still refuses", func(t *testing.T) {
		f := newFake()
		sa := sockaddrIn4("203.0.113.9", 443)
		f.put(addr, sa)
		l, sink := newTestLoop(t, f, contractPolicy(&agent.Contract{Net: &agent.NetSection{}}, nil, nil))
		l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
		if got, _ := f.lastResp(); got.Error != -int32(refusalErrno) || len(f.connects) != 0 {
			t.Fatalf("response = %+v connects %d, want R10's errno and no connect", got, len(f.connects))
		}
		if ev := sink.one(t); ev.Verdict != record.VerdictRefused {
			t.Errorf("verdict = %s, want refused", ev.Verdict)
		}
	})

	// A declared entry under a contract with a net: section is still performed here (R9), abstract names
	// included: that is how a declared name reaches a listener outside the run's scope.
	t.Run("a declared abstract name is still relayed", func(t *testing.T) {
		f := newFake()
		sa := sockaddrUn("@svc")
		f.put(addr, sa)
		l, _ := newTestLoop(t, f, contractPolicy(&agent.Contract{Net: &agent.NetSection{}}, []agent.NetRule{unixRuleOf("unix:@svc", "svc", true)}, nil))
		l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
		if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || len(f.connects) != 1 {
			t.Fatalf("response = %+v connects %d, want the relayed result of one connect", got, len(f.connects))
		}
	})
}

// TestSendsWithNoNetSection: with nothing to decide, the batch refusals that exist because a decision
// could not be made or carried out do not apply, and a Fast-Open send is not performed here any more than
// a connect is. A datagram to an unrecognised family is continued like any other and so is a batch
// carrying one, an unconnected stream batch (R13c) is continued rather than refused, and a Fast-Open
// sendto is continued with no send on the duplicate. AF_UNSPEC in a send is the exception, refused here
// as under a net: section (refusesUndecidable; TestUnspecIsOnlyADisassociationInConnect has every form).
func TestSendsWithNoNetSection(t *testing.T) {
	const addr, arrayAddr, vsockAddr = 0x40000, 0x100000, 0x41000
	vsock := make([]byte, 16) // struct sockaddr_vm: a family this tier does not parse
	vsock[0] = unix.AF_VSOCK
	continuedLines := func(t *testing.T, sink *testSink, want int, dst string) {
		t.Helper()
		evs := sink.all()
		if len(evs) != want {
			t.Fatalf("%d lines, want %d: %+v", len(evs), want, evs)
		}
		for _, ev := range evs {
			var p netPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != record.VerdictAllow || ev.Rule != ruleUnmatched || !p.BestEffort || p.Dst != dst {
				t.Errorf("event = %s/%s dst %q best_effort=%v, want allow/%s dst %q best_effort",
					ev.Verdict, ev.Rule, p.Dst, p.BestEffort, ruleUnmatched, dst)
			}
		}
	}
	t.Run("sendto AF_UNSPEC on a datagram socket is refused", func(t *testing.T) {
		f := newFake()
		f.sockType = unix.SOCK_DGRAM
		sa := unspecSockaddr("203.0.113.9", 8080)
		f.put(addr, sa)
		l, sink := newTestLoop(t, f, contractPolicy(&agent.Contract{}, nil, nil))
		l.handle(notifFor(sendToNR(), 4242, 5, 0x9000, 4, 0, addr, uint64(len(sa))))
		if got, _ := f.lastResp(); got.Error != -int32(refusalErrno) {
			t.Fatalf("response = %+v, want R10's errno: udp_sendmsg sends to the sockaddr_in behind the family word", got)
		}
		ev := sink.one(t)
		var p netPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if ev.Verdict != record.VerdictRefused || ev.Rule != ruleUnmatched || p.Dst != "unspec" || p.BestEffort {
			t.Errorf("event = %s/%s dst %q best_effort=%v, want refused/%s dst unspec, enforced",
				ev.Verdict, ev.Rule, p.Dst, p.BestEffort, ruleUnmatched)
		}
	})
	t.Run("sendto to an unrecognised family on a datagram socket is continued", func(t *testing.T) {
		f := newFake()
		f.sockType = unix.SOCK_DGRAM
		f.put(addr, vsock)
		l, sink := newTestLoop(t, f, contractPolicy(&agent.Contract{}, nil, nil))
		l.handle(notifFor(sendToNR(), 4242, 5, 0x9000, 4, 0, addr, uint64(len(vsock))))
		if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
			t.Fatalf("response = %+v, want CONTINUE: with no net: there is nothing to match it against", got)
		}
		continuedLines(t, sink, 1, "family(40)")
	})
	t.Run("sendmmsg carrying an unrecognised family is continued", func(t *testing.T) {
		f := newFake()
		f.sockType = unix.SOCK_DGRAM
		f.put(arrayAddr, mmsgArray(2, func(int) uint64 { return vsockAddr }))
		f.put(vsockAddr, vsock)
		l, sink := newTestLoop(t, f, contractPolicy(&agent.Contract{}, nil, nil))
		l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, 2, 0))
		if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
			t.Fatalf("response = %+v, want CONTINUE: the undecidable-family batch refusal needs a net: section", got)
		}
		continuedLines(t, sink, 2, "family(40)")
	})
	t.Run("sendmmsg carrying AF_UNSPEC is refused whole", func(t *testing.T) {
		f := newFake()
		f.sockType = unix.SOCK_DGRAM
		f.put(arrayAddr, mmsgArray(2, func(i int) uint64 { return []uint64{addr, vsockAddr}[i] }))
		f.put(addr, unspecSockaddr("203.0.113.9", 8080))
		f.put(vsockAddr, sockaddrIn4("203.0.113.10", 53))
		l, sink := newTestLoop(t, f, contractPolicy(&agent.Contract{}, nil, nil))
		l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, 2, 0))
		if got, _ := f.lastResp(); got.Error != -int32(refusalErrno) {
			t.Fatalf("response = %+v, want R10's errno: the batch form of the sendto refusal", got)
		}
		evs := sink.all()
		if len(evs) != 2 || evs[0].Rule != ruleUnmatched || evs[1].Rule != ruleBatchSend {
			t.Fatalf("lines = %+v, want the AF_UNSPEC message unmatched and its sibling batch-send", evs)
		}
		for _, ev := range evs {
			if ev.Verdict != record.VerdictRefused {
				t.Errorf("verdict = %s, want refused", ev.Verdict)
			}
		}
	})
	t.Run("sendmmsg past the 64th: AF_UNSPEC after an unrecognised family is still reached", func(t *testing.T) {
		// mmsgDests stops at the first address that refuses the batch. Under no net: an unrecognised
		// family does not, so stopping there left an AF_UNSPEC message behind it unread and continued.
		f := newFake()
		f.sockType = unix.SOCK_DGRAM
		f.put(arrayAddr, mmsgArray(mmsgMessages+2, func(i int) uint64 {
			switch i {
			case mmsgMessages:
				return vsockAddr
			case mmsgMessages + 1:
				return addr
			}
			return 0
		}))
		f.put(vsockAddr, vsock)
		f.put(addr, unspecSockaddr("203.0.113.9", 8080))
		l, sink := newTestLoop(t, f, contractPolicy(&agent.Contract{}, nil, nil))
		l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, mmsgMessages+2, 0))
		if got, _ := f.lastResp(); got.Error != -int32(refusalErrno) {
			t.Fatalf("response = %+v, want R10's errno", got)
		}
		ev := sink.one(t)
		var p netPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if ev.Verdict != record.VerdictRefused || ev.Rule != ruleUnmatched || p.Dst != "unspec" {
			t.Errorf("tail line = %s/%s dst %q, want the AF_UNSPEC message that refused the batch", ev.Verdict, ev.Rule, p.Dst)
		}
	})
	t.Run("sendmmsg on an unconnected stream socket", func(t *testing.T) {
		f := newFake()
		f.sockType = unix.SOCK_STREAM
		f.put(arrayAddr, mmsgArray(2, func(int) uint64 { return addr }))
		f.put(addr, sockaddrIn4("203.0.113.9", 443))
		l, sink := newTestLoop(t, f, contractPolicy(&agent.Contract{}, nil, nil))
		l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, 2, 0))
		if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
			t.Fatalf("response = %+v, want CONTINUE", got)
		}
		for _, ev := range sink.all() {
			if ev.Verdict != record.VerdictAllow || ev.Rule != ruleUnmatched {
				t.Errorf("event = %s/%s, want allow/%s", ev.Verdict, ev.Rule, ruleUnmatched)
			}
		}
	})
	t.Run("Fast-Open sendto on an IP socket is relayed", func(t *testing.T) {
		// In the unix-only state a Fast-Open send on an IP socket is relayed on the duplicate, as handleConnect
		// relays the connect: continued, the kernel re-reads the descriptor and the address, and a sibling that
		// dup2s a unix socket over the one and rewrites the other reaches a host socket (ADR 0070 Decision 3,
		// review F1/HS-R1-1). Before the fix the loop answered CONTINUE and performed no send.
		f := newFake()
		f.sockType = unix.SOCK_STREAM
		sa := sockaddrIn4("203.0.113.9", 443)
		f.put(addr, sa)
		f.put(0x9000, []byte("ping"))
		l, sink := newTestLoop(t, f, contractPolicy(&agent.Contract{}, nil, nil))
		l.handle(notifFor(sendToNR(), 4242, 5, 0x9000, 4, uint64(unix.MSG_FASTOPEN), addr, uint64(len(sa))))
		if len(f.sends) != 1 || f.sends[0].flags != unix.MSG_FASTOPEN || string(f.sends[0].addr) != string(sa) {
			t.Fatalf("sends = %+v, want one relayed Fast-Open send to the copied address", f.sends)
		}
		if got, _ := f.lastResp(); got.Error != 0 || got.Val != 4 {
			t.Fatalf("response = %+v, want the relayed result (4 bytes), not CONTINUE", got)
		}
		var p netPayload
		ev := sink.one(t)
		if err := ev.DecodePayload(&p); err != nil || ev.Verdict != record.VerdictAllow || p.BestEffort {
			t.Errorf("event = %s best_effort=%v (%v), want allow enforced (the send was performed here)", ev.Verdict, p.BestEffort, err)
		}
	})
	t.Run("Fast-Open sendto on a non-IP non-unix socket is refused", func(t *testing.T) {
		// A Fast-Open-shaped send on a socket whose domain the unix-only state does not reach is refused, keyed on
		// the socket's own domain, never relayed from this process.
		f := newFake()
		f.sockType, f.sockDomain = unix.SOCK_STREAM, unix.AF_NETLINK
		sa := sockaddrIn4("203.0.113.9", 443)
		f.put(addr, sa)
		f.put(0x9000, []byte("ping"))
		l, sink := newTestLoop(t, f, contractPolicy(&agent.Contract{}, nil, nil))
		l.handle(notifFor(sendToNR(), 4242, 5, 0x9000, 4, uint64(unix.MSG_FASTOPEN), addr, uint64(len(sa))))
		if len(f.sends) != 0 {
			t.Fatalf("sends = %+v, want none: a netlink socket's send is never relayed", f.sends)
		}
		if got, _ := f.lastResp(); got.Error != -int32(refusalErrno) {
			t.Fatalf("response = %+v, want R10's errno", got)
		}
		if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Rule != ruleHostSockets {
			t.Errorf("event = %s/%s, want refused/%s", ev.Verdict, ev.Rule, ruleHostSockets)
		}
	})
}

// TestRelativeUnixConnectIsRelayedResolved: the relay runs in this process, so a relative sun_path
// relayed as the target wrote it resolves against the launcher's cwd — a different socket from the one
// decided against /proc/<pid>/cwd. The relay resolves it from the task's own cwd descriptor instead
// (relayUnix), and refuses when there is none it could resolve from.
func TestRelativeUnixConnectIsRelayedResolved(t *testing.T) {
	const addr = 0x40000
	f := newFake()
	sa := sockaddrUn("pg.sock")
	f.put(addr, sa)
	f.links["/proc/4242/cwd"] = "/work"
	declared := []agent.NetRule{unixRuleOf("unix:/work/pg.sock", "/work/pg.sock", false)}
	l, sink := newTestLoop(t, f, testPolicy(declared, nil, nil))
	l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
	if got, _ := f.lastResp(); got.Error != 0 {
		t.Fatalf("response = %+v, want the relayed result", got)
	}
	if len(f.connects) != 1 || string(f.connects[0]) != string(sockaddrUn("/work/pg.sock")) {
		t.Fatalf("connects = %q, want one to the resolved /work/pg.sock", f.connects)
	}
	if ev := sink.one(t); ev.Verdict != record.VerdictAllow || ev.Rule != "net[unix:/work/pg.sock]" {
		t.Errorf("event = %s/%s", ev.Verdict, ev.Rule)
	}

	// A resolved path longer than sun_path used to be refused, because the relay could only name the
	// socket by that path. It is now reached through the descriptor the walk from the task's cwd opened,
	// which fits whatever the path's length, as the task's own relative connect would.
	f = newFake()
	f.put(addr, sa)
	long := "/"
	for len(long) < sunPathMax {
		long += "d/"
	}
	f.links["/proc/4242/cwd"] = long
	pol := testPolicy([]agent.NetRule{unixRuleOf("unix:"+long+"pg.sock", long+"pg.sock", false)}, nil, nil)
	l, _ = newTestLoop(t, f, pol)
	l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
	if got, _ := f.lastResp(); got.Error != 0 || len(f.unixConnects) != 1 || f.unixConnects[0] != long+"pg.sock" {
		t.Fatalf("response = %+v reached %q, want the relayed result of one connect to %s", got, f.unixConnects, long+"pg.sock")
	}

	// With the cwd unreadable, resolve leaves the path relative (path-unreliable): no entry can match it
	// and there is no absolute path to relay, so it is refused and never connected from this process's
	// own cwd.
	f = newFake()
	f.put(addr, sa)
	l, sink = newTestLoop(t, f, testPolicy(declared, nil, nil))
	l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
	if got, _ := f.lastResp(); got.Error != -int32(refusalErrno) || len(f.connects) != 0 {
		t.Fatalf("unreadable cwd: response = %+v connects %q, want a refusal and no connect", got, f.connects)
	}
	if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Rule != rulePathUnreliable {
		t.Errorf("unreadable cwd: event = %s/%s, want refused/%s, the rule R11 names", ev.Verdict, ev.Rule, rulePathUnreliable)
	}
	// Under a contract with no net: section the same connect is the kernel's: it resolves the path
	// against the agent's own cwd, which is the one the agent meant.
	f = newFake()
	f.put(addr, sa)
	l, _ = newTestLoop(t, f, contractPolicy(&agent.Contract{HostSockets: true}, nil, nil))
	l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 || len(f.connects) != 0 {
		t.Fatalf("unreadable cwd, no net: response = %+v connects %q, want CONTINUE and no connect", got, f.connects)
	}

	// The relay itself never resolves a relative path from this process's cwd, whatever admitted it: from
	// a task whose root is not this process's, where a walk from its cwd could meet an absolute symlink
	// that would resolve against this process's root, it refuses (openSocketPath, errOtherRoot).
	f = newFake()
	f.put(addr, sa)
	f.links["/proc/4242/cwd"] = "/work"
	f.otherRoot = true
	l, sink = newTestLoop(t, f, testPolicy(declared, nil, nil))
	l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
	if got, _ := f.lastResp(); got.Error != -int32(refusalErrno) || len(f.connects) != 0 {
		t.Fatalf("task with its own root: response = %+v connects %q, want a refusal and no connect", got, f.connects)
	}
	if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Rule != rulePathUnreliable {
		t.Errorf("task with its own root: event = %s/%s, want refused/%s", ev.Verdict, ev.Rule, rulePathUnreliable)
	}
	if f.fdBalance() != 0 {
		t.Errorf("%d descriptors left open (E28)", f.fdBalance())
	}
}

// TestExecWithNoExecSection is SEMANTICS §1's "no exec: — deny nothing" at the supervisor: the Landlock
// builder adds EXECUTE to every read set and Evaluate reports allow, so an exec no entry names is recorded
// allow against unmatched, never as a refusal the kernel did not make. The exec open is still a read:
// under a deny_read tier 1 enforces, an undeclared binary is refused read-denied, as Evaluate's Landlock
// arm says; under one it leaves unenforced it runs. `exec: {}` keeps refusing.
func TestExecWithNoExecSection(t *testing.T) {
	nr := nrFor(t, "execve")
	fs := []agent.FSRule{
		{Path: "/home/u/.ssh", Kind: agent.FSDenyRead},
		{Path: "/work", Kind: agent.FSWrite},
		{Path: "/work/keys", Kind: agent.FSDenyRead, Unenforced: true},
		{Path: "/work/key", Kind: agent.FSDenyRead},
	}
	for _, tc := range []struct {
		name    string
		c       *agent.Contract
		path    string
		verdict record.Verdict
		rule    string
		reason  record.Reason
	}{
		{"undeclared binary", &agent.Contract{}, "/usr/bin/curl", record.VerdictAllow, ruleUnmatched, ""},
		{"under an enforced deny_read", &agent.Contract{}, "/home/u/.ssh/tool", record.VerdictRefused, "fs.deny_read[/home/u/.ssh]", record.ReasonReadDenied},
		{"under an unenforced deny_read", &agent.Contract{}, "/work/keys/tool", record.VerdictAllow, ruleUnmatched, ""},
		{"exec: {} refuses", &agent.Contract{Exec: &agent.ExecSection{}}, "/usr/bin/curl", record.VerdictRefused, ruleUnmatched, record.ReasonExecNotAllowed},
		// A linked binary under the deny_read, in a directory the agent made unsearchable
		// and run through its descriptor, is not confirmed in this view (here false). Judged on /proc/4242/fd/7 it
		// was recorded allow while the kernel refused its exec open; it is judged where the kernel spells it.
		{"under an enforced deny_read, through a descriptor not confirmed here", &agent.Contract{}, "/proc/4242/fd/7", record.VerdictRefused, "fs.deny_read[/home/u/.ssh]", record.ReasonReadDenied},
		{"elsewhere, through a descriptor not confirmed here", &agent.Contract{}, "/proc/4242/fd/6", record.VerdictAllow, ruleUnmatched, ""},
		// An unconfirmed name may be a removed one another hard link outlives, and is
		// judged without its " (deleted)" marker; with the marker the file's own deny_read missed it and the write
		// entry above it answered.
		{"a removed name under a file's deny_read, through a descriptor not confirmed here", &agent.Contract{}, "/proc/4242/fd/5", record.VerdictRefused, "fs.deny_read[/work/key]", record.ReasonReadDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.images = map[string]execImage{
				"/proc/4242/fd/7": {id: fakeID("/home/u/.ssh/sub/tool"), linked: true, link: "/home/u/.ssh/sub/tool", head: []byte("\x7fELF")},
				"/proc/4242/fd/6": {id: fakeID("/usr/bin/true"), linked: true, link: "/usr/bin/true", head: []byte("\x7fELF")},
				"/proc/4242/fd/5": {id: fakeID("/work/key"), linked: true, link: "/work/key (deleted)", head: []byte("\x7fELF")},
			}
			l, sink := newTestLoop(t, f, contractPolicy(tc.c, nil, fs))
			execAt(l, f, nr, 4242, 0, tc.path, "tool")
			wantExecAnswer(t, f, tc.verdict)
			ev := sink.one(t)
			if ev.Verdict != tc.verdict || ev.Rule != tc.rule || ev.Reason != tc.reason {
				t.Errorf("event = %s/%s/%q, want %s/%s/%q", ev.Verdict, ev.Rule, ev.Reason, tc.verdict, tc.rule, tc.reason)
			}
		})
	}
}

// TestWriteWithNoFSSection pins SEMANTICS §1's "no fs:" row as amended: no write entry is compiled, so a
// write-open anywhere is refused against unmatched, exactly as under fs: {}, and reads are allowed.
func TestWriteWithNoFSSection(t *testing.T) {
	nr := nrFor(t, "openat")
	const pathAddr = 0x10000
	for _, tc := range []struct {
		flags   int
		verdict record.Verdict
		reason  record.Reason
	}{
		{unix.O_WRONLY | unix.O_CREAT, record.VerdictRefused, record.ReasonWriteOutsideContract},
		{unix.O_RDONLY, record.VerdictAllow, ""},
	} {
		f := newFake()
		f.put(pathAddr, cstr("/work/out/report.md"))
		pol := contractPolicy(&agent.Contract{}, nil, []agent.FSRule{{Path: "/home/u/.ssh", Kind: agent.FSDenyRead}})
		pol.Rules.Record = agent.RecordFull
		l, sink := newTestLoop(t, f, pol)
		l.handle(notifFor(nr, 4242, argCWD, pathAddr, uint64(tc.flags)))
		ev := sink.one(t)
		if ev.Verdict != tc.verdict || ev.Rule != ruleUnmatched || ev.Reason != tc.reason {
			t.Errorf("flags %#x: event = %s/%s/%q, want %s/%s/%q", tc.flags, ev.Verdict, ev.Rule, ev.Reason, tc.verdict, ruleUnmatched, tc.reason)
		}
	}
}

// TestMountFamilyIsRefusedAsLandlockTopology is supervisor.md R31 (mount) and GAPS A9: a Landlock domain refuses mount,
// umount, move_mount and pivot_root, so a sandbox the agent starts cannot run in either P0 tier. The
// refusal now reaches the ledger: a refused line with reason landlock-topology for each refusal, and gap
// what=enforce why=landlock-topology once per binary. An observe run has no domain and refuses nothing.
func TestMountFamilyIsRefusedAsLandlockTopology(t *testing.T) {
	nr := nrFor(t, "mount")
	const target = 0x10000
	f := newFake()
	f.put(target, cstr("/newroot"))
	f.links["/proc/4242/exe"] = "/usr/bin/bwrap"
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
	for range 2 {
		l.handle(notifFor(nr, 4242, 0, target, 0, uint64(unix.MS_BIND), 0))
		if got, _ := f.lastResp(); got.Error != -int32(unix.EPERM) || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
			t.Fatalf("response = %+v, want EPERM, the answer the domain gives", got)
		}
	}
	var gaps, refused int
	for _, ev := range sink.all() {
		if err := ev.Validate(); err != nil {
			t.Errorf("%s event does not validate: %v", ev.Kind, err)
		}
		switch ev.Kind {
		case record.KindGap:
			gaps++
			var p record.GapPayload
			if err := ev.DecodePayload(&p); err != nil || p.What != record.GapEnforce || p.Why != string(record.ReasonLandlockTopology) || p.Binary != "/usr/bin/bwrap" {
				t.Errorf("gap payload = %+v (%v), want enforce/landlock-topology naming /usr/bin/bwrap", p, err)
			}
		case record.KindRefused:
			refused++
			var p record.RefusedPayload
			if err := ev.DecodePayload(&p); err != nil || p.Op != "mount" || p.Target != "/newroot" {
				t.Errorf("refused payload = %+v (%v), want op mount target /newroot", p, err)
			}
			if ev.Reason != record.ReasonLandlockTopology || ev.Rule != ruleUnmatched {
				t.Errorf("refused reason/rule = %s/%s", ev.Reason, ev.Rule)
			}
		default:
			t.Errorf("unexpected %s event", ev.Kind)
		}
	}
	if gaps != 1 || refused != 2 {
		t.Errorf("gaps = %d, refused = %d; want one gap for the binary and a refused line per refusal", gaps, refused)
	}

	f = newFake()
	f.put(target, cstr("/newroot"))
	pol := testPolicy(nil, nil, nil)
	pol.Observe = true
	l, sink = newTestLoop(t, f, pol)
	l.handle(notifFor(nr, 4242, 0, target, 0, 0, 0))
	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("observe: response = %+v, want CONTINUE", got)
	}
	if evs := sink.all(); len(evs) != 0 {
		t.Errorf("observe: %d events, want none: nothing was refused", len(evs))
	}
}

// TestLandlockTopologyGapIsCappedPerRun pins supervisor.md R31's bound: the landlock-topology gap is written
// once for each of at most maxTopologyBinaries binaries a run, while every refusal past the cap still gets
// EPERM and its refused line. The test above covers one binary only, so an off-by-one or a missing cap
// passed the suite.
func TestLandlockTopologyGapIsCappedPerRun(t *testing.T) {
	nr := nrFor(t, "mount")
	const target, binaries = 0x10000, maxTopologyBinaries + 6
	f := newFake()
	f.put(target, cstr("/newroot"))
	pid := func(i int) int { return 5000 + i }
	for i := range binaries {
		f.links["/proc/"+strconv.Itoa(pid(i))+"/exe"] = "/usr/bin/tool" + strconv.Itoa(i)
	}
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
	calls := 0
	for i := range binaries {
		l.handle(notifFor(nr, pid(i), 0, target, 0, uint64(unix.MS_BIND), 0))
		calls++
		if got, _ := f.lastResp(); got.Error != -int32(unix.EPERM) || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
			t.Fatalf("binary %d: response = %+v, want EPERM whatever the cap", i, got)
		}
	}
	// A binary already recorded, and one past the cap, each once more: neither writes a gap.
	for _, i := range []int{0, binaries - 1} {
		l.handle(notifFor(nr, pid(i), 0, target, 0, uint64(unix.MS_BIND), 0))
		calls++
	}
	gapped := map[string]int{}
	refused := 0
	for _, ev := range sink.all() {
		switch ev.Kind {
		case record.KindGap:
			var p record.GapPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			gapped[p.Binary]++
		case record.KindRefused:
			refused++
		}
	}
	if len(gapped) != maxTopologyBinaries || refused != calls {
		t.Errorf("gaps for %d binaries, %d refused lines; want %d and %d", len(gapped), refused, maxTopologyBinaries, calls)
	}
	for i := range binaries {
		want := 0
		if i < maxTopologyBinaries {
			want = 1
		}
		if b := "/usr/bin/tool" + strconv.Itoa(i); gapped[b] != want {
			t.Errorf("%s: %d gap lines, want %d", b, gapped[b], want)
		}
	}
}

// TestTopologyFamilyRefusesUmountPivotRootAndMoveMount is supervisor.md R31 for the other three syscalls of
// the mount family: umount2 and pivot_root each read their first argument as the target, move_mount its
// destination through the dirfd, and each is refused with EPERM as a landlock-topology refused line.
func TestTopologyFamilyRefusesUmountPivotRootAndMoveMount(t *testing.T) {
	const addr = 0x10000
	cwd := uint64(0xffffffffffffff9c) // AT_FDCWD as the kernel passes it
	for _, tc := range []struct {
		syscall, op, target string
		args                []uint64
	}{
		{"umount2", "umount", "/mnt/x", []uint64{addr, 0}},
		{"pivot_root", "pivot_root", "/mnt/x", []uint64{addr, 0}},
		{"move_mount", "move_mount", "/mnt/x", []uint64{cwd, 0, cwd, addr, 0}},
	} {
		t.Run(tc.syscall, func(t *testing.T) {
			f := newFake()
			f.put(addr, cstr(tc.target))
			f.links["/proc/4242/exe"] = "/usr/bin/bwrap"
			l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
			l.handle(notifFor(nrFor(t, tc.syscall), 4242, tc.args...))
			got, ok := f.lastResp()
			if !ok || got.Error != -int32(unix.EPERM) || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Fatalf("response = %+v, want EPERM and no CONTINUE", got)
			}
			var refused int
			for _, ev := range sink.all() {
				if ev.Kind != record.KindRefused {
					continue
				}
				refused++
				var p record.RefusedPayload
				if err := ev.DecodePayload(&p); err != nil || p.Op != tc.op || p.Target != tc.target {
					t.Errorf("refused payload = %+v (%v), want op %s target %s", p, err, tc.op, tc.target)
				}
				if ev.Reason != record.ReasonLandlockTopology || ev.Rule != ruleUnmatched {
					t.Errorf("refused reason/rule = %s/%s", ev.Reason, ev.Rule)
				}
			}
			if refused != 1 {
				t.Errorf("%d refused lines, want 1", refused)
			}
		})
	}
}

// TestKeyringSyscallsAreRefused: by default the three kernel-keyring syscalls no fs, net or
// record can see are refused with EPERM and recorded.
func TestKeyringSyscallsAreRefused(t *testing.T) {
	for _, tc := range []struct {
		syscall string
		op      string
	}{
		{"add_key", "add_key"},
		{"request_key", "request_key"},
		{"keyctl", "keyctl"},
	} {
		t.Run(tc.syscall, func(t *testing.T) {
			f := newFake()
			l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
			l.handle(notifFor(nrFor(t, tc.syscall), 4242))
			got, ok := f.lastResp()
			if !ok || got.Error != -int32(unix.EPERM) || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Fatalf("response = %+v, want EPERM and no CONTINUE (SEMANTICS §1)", got)
			}
			ev := sink.one(t)
			if ev.Kind != record.KindRefused || ev.Reason != record.ReasonReadDenied || ev.Rule != ruleKeyring {
				t.Errorf("event = %s reason=%s rule=%s, want refused/read-denied/keyring", ev.Kind, ev.Reason, ev.Rule)
			}
			var p record.RefusedPayload
			if err := ev.DecodePayload(&p); err != nil || p.Op != tc.op {
				t.Errorf("refused payload = %+v (%v), want op %q", p, err, tc.op)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("refused event does not validate: %v", err)
			}
		})
	}
}

// TestKeyringUseIsVisibleWhenContinued is the other half of the keyring rule: a contract that declares keyring: true
// has the syscalls continued, and an observe run continues them because it enforces nothing (R30). Either
// way the ledger must not go silent — the defect was zero key-related lines — so each
// binary's first use of each syscall leaves gap what=record why=keyring-<syscall>, and a repeat does not.
func TestKeyringUseIsVisibleWhenContinued(t *testing.T) {
	for _, tc := range []struct {
		name string
		pol  func() *Policy
	}{
		{"keyring: true", func() *Policy { return contractPolicy(&agent.Contract{Keyring: true}, nil, nil) }},
		{"observe", func() *Policy {
			pol := testPolicy(nil, nil, nil)
			pol.Observe = true
			return pol
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.links["/proc/4242/exe"] = "/usr/bin/klist"
			l, sink := newTestLoop(t, f, tc.pol())
			for _, sc := range []string{"keyctl", "keyctl", "request_key"} {
				l.handle(notifFor(nrFor(t, sc), 4242))
				if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
					t.Fatalf("%s: response = %+v, want CONTINUE", sc, got)
				}
			}
			evs := sink.all()
			if len(evs) != 2 {
				t.Fatalf("%d events, want one gap per binary and syscall (2): %+v", len(evs), evs)
			}
			for i, want := range []string{"keyring-keyctl", "keyring-request_key"} {
				ev := evs[i]
				var p record.GapPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				if ev.Kind != record.KindGap || p.What != record.GapRecord || p.Why != want || p.Binary != "/usr/bin/klist" {
					t.Errorf("event %d = %s %+v, want gap what=record why=%s binary=/usr/bin/klist", i, ev.Kind, p, want)
				}
				if err := ev.Validate(); err != nil {
					t.Errorf("gap does not validate: %v", err)
				}
			}
		})
	}
}

// TestExecOfADeclaredMCPServerEmitsMCP is the P0 minimum of an mcp producer (P0-DESIGN §2.2): an exec
// matching a declared mcp[].command records the server's start. Several servers share one runner, so the
// declared arguments decide which one started, and the agent's own use of the runner starts none.
func TestExecOfADeclaredMCPServerEmitsMCP(t *testing.T) {
	nr := nrFor(t, "execve")
	c := &agent.Contract{MCP: []agent.MCPServer{
		{Name: "fs", Command: []string{"npx", "-y", "@mcp/server-fs"}},
		{Name: "git", Command: []string{"npx", "-y", "@mcp/server-git"}},
	}}
	pol := contractPolicy(c, nil, nil)
	pol.Rules.Exec = []agent.ExecRule{{Raw: "npx", Path: "/usr/bin/npx", Basename: "npx", ByName: true,
		Source: "mcp:fs,mcp:git", Verdict: agent.VerdictAllow}}
	for _, tc := range []struct {
		argv []string
		want string
	}{
		{[]string{"npx", "-y", "@mcp/server-git"}, "git"},
		{[]string{"npx", "-y", "@mcp/server-fs"}, "fs"},
		{[]string{"npx", "prettier", "."}, ""},
	} {
		f := newFake()
		l, sink := newTestLoop(t, f, pol)
		execAt(l, f, nr, 4242, 0, "/usr/bin/npx", tc.argv...)
		var mcp []*record.Event
		for _, ev := range sink.all() {
			if ev.Kind == record.KindMCP {
				mcp = append(mcp, ev)
			}
		}
		if tc.want == "" {
			if len(mcp) != 0 {
				t.Errorf("%q: %d mcp events, want none", tc.argv, len(mcp))
			}
			continue
		}
		if len(mcp) != 1 {
			t.Fatalf("%q: %d mcp events, want one", tc.argv, len(mcp))
		}
		ev := mcp[0]
		var p record.MCPPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if ev.Rule != "mcp["+tc.want+"]" || ev.Verdict != record.VerdictAllow || p.Name != tc.want || p.Transport != "stdio" {
			t.Errorf("%q: mcp event = %s/%s %+v, want mcp[%s]/allow stdio", tc.argv, ev.Rule, ev.Verdict, p, tc.want)
		}
		if err := ev.Validate(); err != nil {
			t.Errorf("mcp event does not validate: %v", err)
		}
	}
}

// TestNewAsksForSyncWakeUp: New sets SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP on the listener, and a kernel
// that refuses it (below 6.6) costs nothing but the speed-up.
func TestNewAsksForSyncWakeUp(t *testing.T) {
	for _, refuse := range []error{nil, unix.EINVAL} {
		f := newFake()
		f.syncWakeUpErr = refuse
		if _, err := New(testListener(), testPolicy(nil, nil, []netip.AddrPort{}), &testSink{}, Options{kernel: f, Workers: 1}); err != nil {
			t.Fatalf("New with SET_FLAGS answering %v: %v", refuse, err)
		}
		if f.syncWakeUps != 1 {
			t.Errorf("SetSyncWakeUp calls = %d, want 1", f.syncWakeUps)
		}
	}
}

// TestZeroLengthNameIsUnaddressed: __copy_msghdr keeps an address only when msg_name is set and
// msg_namelen is not zero; a message with a pointer and a zero length goes to the socket's peer, which
// connect already decided (R13a). Reading it as an address failed as unreadable and refused the whole
// send — at any index of a sendmmsg batch up to the kernel's clamp once the batch is read that far.
func TestZeroLengthNameIsUnaddressed(t *testing.T) {
	const hdrAddr, nameAddr, arrayAddr = 0x30000, 0x40000, 0x100000
	t.Run("sendmsg", func(t *testing.T) {
		f := newFake()
		f.sockType = unix.SOCK_DGRAM
		f.connected = true
		f.put(hdrAddr, namedMsgHdr(nameAddr, 0))
		f.put(nameAddr, sockaddrIn4("203.0.113.9", 4444))
		l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
		l.handle(notifFor(sendMsgNR(), 4242, 5, hdrAddr, 0))
		if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
			t.Fatalf("response = %+v, want CONTINUE", got)
		}
		if evs := sink.all(); len(evs) != 0 || f.openFDs != 0 {
			t.Errorf("events = %d, duplicates = %d; want neither for a send with no address", len(evs), f.openFDs)
		}
	})
	for _, at := range []int{0, mmsgMessages} {
		f := newFake()
		f.sockType = unix.SOCK_DGRAM
		f.connected = true
		arr := mmsgArray(at+1, func(int) uint64 { return 0 })
		putU64(arr[at*mmsgHdrSize+msgNameOff:], nameAddr) // msg_name set, msg_namelen left 0
		f.put(arrayAddr, arr)
		f.put(nameAddr, sockaddrIn4("203.0.113.9", 4444))
		l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
		l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, uint64(at+1), 0))
		if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
			t.Fatalf("sendmmsg, zero-length name at %d: response = %+v, want CONTINUE", at, got)
		}
		if evs := sink.all(); len(evs) != 0 {
			t.Errorf("sendmmsg, zero-length name at %d: %d events, want none", at, len(evs))
		}
	}
}

// TestConnectInTheUnixOnlyState is supervisor R7b (ADR 0070): with no net: section and no host_sockets: true every
// IP destination is admitted, and it is relayed on the duplicate, never continued, so neither a sibling's rewrite of
// the address nor a descriptor swapped in after the duplicate reaches a host socket; a unix connect reaches only a
// socket a process of the run bound, or tego's own endpoint (a runtime unix: grant), and every other one is refused
// host-sockets with no connect made: a host daemon's pathname socket, an abstract name, and a socket under a write
// entry that no process of the run bound (the relay asks boundByRun, as under a net: section). A connect whose address
// could not be read is refused, not continued: nothing decides it otherwise.
func TestConnectInTheUnixOnlyState(t *testing.T) {
	const addr = 0x40000
	broker := "/run/user/1000/tego-dns/dns.sock"
	grant := agent.NetRule{Raw: "unix:" + broker, Proto: agent.ProtoUnix, UnixPath: broker, Static: true,
		Verdict: agent.VerdictAllow, Runtime: agent.DNSBrokerGrant}
	for _, tc := range []struct {
		name     string
		sa       []byte
		dst      string
		verdict  record.Verdict
		rule     string
		connects int
	}{
		{"an IP destination is relayed and allowed", sockaddrIn4("203.0.113.9", 443), "203.0.113.9:443", record.VerdictAllow, ruleUnmatched, 1},
		{"a host daemon's socket", sockaddrUn("/run/docker.sock"), "unix:/run/docker.sock", record.VerdictRefused, ruleHostSockets, 0},
		{"the session bus", sockaddrUn("/run/user/1000/bus"), "unix:/run/user/1000/bus", record.VerdictRefused, ruleHostSockets, 0},
		{"an abstract name", sockaddrUn("@/tmp/.X11-unix/X0"), "unix:@/tmp/.X11-unix/X0", record.VerdictRefused, ruleHostSockets, 0},
		{"a socket under a write entry no process of the run bound", sockaddrUn("/work/app.sock"), "unix:/work/app.sock", record.VerdictRefused, ruleHostSockets, 0},
		{"tego's own endpoint", sockaddrUn(broker), "unix:" + broker, record.VerdictAllow, grant.RuleName(), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(addr, tc.sa)
			f.sockType = unix.SOCK_STREAM
			if tc.sa[0] == unix.AF_UNIX {
				f.sockDomain = unix.AF_UNIX
			}
			pol := contractPolicy(&agent.Contract{}, []agent.NetRule{grant}, []agent.FSRule{{Path: "/work", Raw: "/work/", Kind: agent.FSWrite}})
			if !pol.Rules.HostSocketsRefused() {
				t.Fatal("the table is not in the unix-only state")
			}
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(tc.sa))))
			got, ok := f.lastResp()
			if !ok || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Fatalf("response = %+v, want an answer of this loop's own, never CONTINUE", got)
			}
			if len(f.connects) != tc.connects {
				t.Fatalf("connects = %q, want %d", f.connects, tc.connects)
			}
			if tc.connects == 0 && got.Error != -int32(refusalErrno) {
				t.Errorf("response = %+v, want R10's errno", got)
			}
			ev := sink.one(t)
			var p netPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != tc.verdict || ev.Rule != tc.rule || p.Dst != tc.dst || p.BestEffort {
				t.Errorf("event = %s/%s dst %s best_effort=%v, want %s/%s dst %s, not best effort", ev.Verdict, ev.Rule, p.Dst, p.BestEffort, tc.verdict, tc.rule, tc.dst)
			}
		})
	}
	t.Run("an address that could not be read is refused", func(t *testing.T) {
		f := newFake()
		f.sockType = unix.SOCK_STREAM
		l, sink := newTestLoop(t, f, contractPolicy(&agent.Contract{}, nil, nil))
		l.handle(notifFor(connectNR(), 4242, 5, addr, 16)) // nothing put at addr: the read fails
		if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error == 0 || len(f.connects) != 0 {
			t.Fatalf("response = %+v connects %d, want a refusal and no connect", got, len(f.connects))
		}
		if ev := sink.one(t); ev.Verdict != record.VerdictRefused {
			t.Errorf("verdict = %s, want refused", ev.Verdict)
		}
	})
}

// TestDatagramInTheUnixOnlyState is ADR 0070 for addressed datagrams at tier landlock: with no net: section and no
// host_sockets: true, an admitted datagram is never continued. An IP one is relayed on the duplicate with the copied
// address; one to a socket the run bound is relayed as the task, to the inode its name resolves to; and one to a host
// socket, pathname or abstract, is refused host-sockets with nothing sent. One the relay cannot reproduce (here,
// ancillary data) is continued, its line best effort, the residual run_start's host_sockets/datagram cell names.
func TestDatagramInTheUnixOnlyState(t *testing.T) {
	const addr, buf, hdrAt, iovAt = 0x40000, 0x41000, 0x42000, 0x43000
	for _, form := range []string{"sendto", "sendmsg", "sendmsg+control"} {
		for _, tc := range []struct {
			name     string
			sa       []byte
			dst      string
			verdict  record.Verdict
			rule     string
			unixSent []string
		}{
			{"an IP destination", sockaddrIn4("203.0.113.9", 53), "203.0.113.9:53", record.VerdictAllow, ruleUnmatched, nil},
			{"the journal's socket", sockaddrUn("/run/systemd/journal/socket"), "unix:/run/systemd/journal/socket", record.VerdictRefused, ruleHostSockets, nil},
			{"an abstract name", sockaddrUn("@outside"), "unix:@outside", record.VerdictRefused, ruleHostSockets, nil},
			{"a socket the run bound", sockaddrUn("/work/own.sock"), "unix:/work/own.sock", record.VerdictAllow, "fs.write[", []string{"/work/own.sock"}},
		} {
			t.Run(form+" "+tc.name, func(t *testing.T) {
				f := newFake()
				f.sockType = unix.SOCK_DGRAM
				f.sockDomain = unix.AF_INET
				if tc.sa[0] == unix.AF_UNIX {
					f.sockDomain = unix.AF_UNIX
				}
				f.put(addr, tc.sa)
				f.put(buf, []byte("hello"))
				hdr := namedMsgHdr(addr, uint32(len(tc.sa)))
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
				pol := contractPolicy(&agent.Contract{}, nil, []agent.FSRule{{Path: "/work", Raw: "/work/", Kind: agent.FSWrite}})
				l, sink := newTestLoop(t, f, pol)
				f.bindsSocket(t, l, sockID{ino: 9100, cookie: 1}, "/work/own.sock")
				if form == "sendto" {
					l.handle(notifFor(sendToNR(), 42, 5, buf, 5, 0, addr, uint64(len(tc.sa))))
				} else {
					l.handle(notifFor(sendMsgNR(), 42, 5, hdrAt, 0))
				}
				got, _ := f.lastResp()
				verdict, rule, sends, unixSent := tc.verdict, tc.rule, 0, tc.unixSent
				if verdict == record.VerdictAllow {
					sends = 1
				}
				continued := form == "sendmsg+control" && verdict == record.VerdictAllow
				if continued {
					// The relay cannot reproduce ancillary data: continued, its line best effort (host_sockets/datagram).
					sends, unixSent = 0, nil
				}
				if len(f.sends) != sends || !slices.Equal(f.unixSends, unixSent) {
					t.Fatalf("sends %d (%+v, unix %q), want %d (unix %q)", len(f.sends), f.sends, f.unixSends, sends, unixSent)
				}
				if isContinue := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0; isContinue != continued {
					t.Fatalf("response = %+v, want CONTINUE only for a datagram the relay cannot reproduce", got)
				}
				if sends == 1 && got.Val != 5 {
					t.Errorf("response = %+v, want the relayed send's byte count", got)
				}
				if sends == 0 && !continued && got.Error != -int32(refusalErrno) {
					t.Errorf("response = %+v, want R10's errno", got)
				}
				ev := sink.one(t)
				var p netPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				if ev.Verdict != verdict || !strings.HasPrefix(ev.Rule, rule) || p.Dst != tc.dst || p.BestEffort != continued {
					t.Errorf("event = %s/%s dst %s best_effort=%v, want %s/%s dst %s, not best effort", ev.Verdict, ev.Rule, p.Dst,
						p.BestEffort, verdict, rule, tc.dst)
				}
			})
		}
	}
}

// TestAbstractNameInTheUnixOnlyState is ADR 0070's admit of the run's own abstract sockets: a name a socket of the run
// holds now (one a task of the run called bind on, asked of the kernel) is relayed, a connect and a datagram alike,
// its line allow/unmatched; a name no socket of the run holds, and the run's own name once its socket is gone, is
// refused host-sockets with nothing connected or sent; and a lookup the kernel fails refuses unix-origin-unread.
func TestAbstractNameInTheUnixOnlyState(t *testing.T) {
	const addr, buf = 0x40000, 0x41000
	for _, tc := range []struct {
		name    string
		dst     string
		gone    bool
		diagErr error
		verdict record.Verdict
		rule    string
	}{
		{"the run's own name", "mine", false, nil, record.VerdictAllow, ruleUnmatched},
		{"a name no socket of the run holds", "theirs", false, nil, record.VerdictRefused, ruleHostSockets},
		{"the run's name after its socket closed", "mine", true, nil, record.VerdictRefused, ruleHostSockets},
		{"a lookup that fails", "mine", false, unix.EPERM, record.VerdictRefused, ruleUnixOriginUnread},
	} {
		for _, kind := range []string{"connect", "sendto"} {
			t.Run(kind+" "+tc.name, func(t *testing.T) {
				f := newFake()
				f.sockDomain = unix.AF_UNIX
				f.sockType = unix.SOCK_STREAM
				if kind == "sendto" {
					f.sockType = unix.SOCK_DGRAM
				}
				l, sink := newTestLoop(t, f, contractPolicy(&agent.Contract{}, nil, nil))
				id := f.bindsAbstract(t, l, sockID{ino: 9200, cookie: 1}, "mine")
				f.mu.Lock()
				if tc.gone {
					delete(f.abstractNames, id)
				}
				f.diagErr = tc.diagErr
				f.mu.Unlock()
				sa := sockaddrUn("@" + tc.dst)
				f.put(addr, sa)
				f.put(buf, []byte("hello"))
				if kind == "connect" {
					l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
				} else {
					l.handle(notifFor(sendToNR(), 4242, 5, buf, 5, 0, addr, uint64(len(sa))))
				}
				got, _ := f.lastResp()
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
					t.Fatalf("response = %+v, want an answer of this loop's own", got)
				}
				reached := len(f.unixConnects) + len(f.unixSends)
				if want := tc.verdict == record.VerdictAllow; (reached == 1) != want {
					t.Fatalf("connects %q sends %q, want one only when admitted", f.unixConnects, f.unixSends)
				}
				ev := sink.one(t)
				var p netPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				if ev.Verdict != tc.verdict || ev.Rule != tc.rule || p.Dst != "unix:@"+tc.dst || p.BestEffort {
					t.Errorf("event = %s/%s dst %s best_effort=%v, want %s/%s, not best effort", ev.Verdict, ev.Rule, p.Dst, p.BestEffort,
						tc.verdict, tc.rule)
				}
			})
		}
	}
}

// TestParseUnixDiagName reads UNIX_DIAG_NAME from an exact lookup's reply: the abstract name with its leading NUL,
// which UnixAbstractName strips, beside the socket's identity.
func TestParseUnixDiagName(t *testing.T) {
	ne := binary.NativeEndian
	name := "\x00mine"
	attr := make([]byte, (nlaHdrLen+len(name)+3)&^3)
	ne.PutUint16(attr[0:], uint16(nlaHdrLen+len(name)))
	ne.PutUint16(attr[2:], unixDiagName)
	copy(attr[nlaHdrLen:], name)
	body := make([]byte, unixDiagMsgLen)
	body[0], body[1], body[2] = unix.AF_UNIX, unix.SOCK_STREAM, 10
	ne.PutUint32(body[4:], 6)
	ne.PutUint32(body[8:], 18)
	body = append(body, attr...)
	msg := make([]byte, nlmsgHdrLen, nlmsgHdrLen+len(body))
	ne.PutUint32(msg[0:], uint32(nlmsgHdrLen+len(body)))
	ne.PutUint16(msg[4:], unix.SOCK_DIAG_BY_FAMILY)
	msg = append(msg, body...)
	m, err := parseUnixDiagReplyMsg(msg, sockID{ino: 6, cookie: 18})
	if err != nil || m.name != name || m.b.bound {
		t.Fatalf("reply reads %+v, %v; want name %q and no file", m, err, name)
	}
}

// TestHostSocketRefusalNamesWhatItGives: the refused line of a unix destination the unix-only state refuses names, for
// a socket on R19's list, what reaching it gives (ADR 0070 (4)), and nothing for a socket the list does not name.
func TestHostSocketRefusalNamesWhatItGives(t *testing.T) {
	const addr = 0x40000
	for path, want := range map[string]string{
		"/run/docker.sock":    "the Docker daemon, root-equivalent",
		"/run/other/app.sock": "",
	} {
		f := newFake()
		f.sockType, f.sockDomain = unix.SOCK_STREAM, unix.AF_UNIX
		sa := sockaddrUn(path)
		f.put(addr, sa)
		l, sink := newTestLoop(t, f, contractPolicy(&agent.Contract{}, nil, nil))
		l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
		ev := sink.one(t)
		var p netPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if ev.Rule != ruleHostSockets || p.What != want {
			t.Errorf("%s: rule %s what %q, want %s and %q", path, ev.Rule, p.What, ruleHostSockets, want)
		}
	}
}

// TestHostSocketWhatNamesTheSocketReached: the refused line's what is decided on the name the kernel would look up,
// not on its spelling: an unclean absolute name and a relative one under the task's cwd that name the Docker socket
// get its what, and a per-user socket is the invoking user's (/run/user/<uid>, config.InvokingUID, SUDO_UID at the
// root tiers), whatever uid and XDG_RUNTIME_DIR the supervisor itself has.
func TestHostSocketWhatNamesTheSocketReached(t *testing.T) {
	const addr = 0x40000
	const docker = "the Docker daemon, root-equivalent"
	for _, tc := range []struct{ path, cwd, want string }{
		{path: "/run//docker.sock", want: docker},
		{path: "/run/./x/../docker.sock", want: docker},
		{path: "docker.sock", cwd: "/run", want: docker},
		{path: "../docker.sock", cwd: "/run/user", want: docker},
		{path: "/run/user/1777/openssh_agent", want: "the SSH agent"},
		{path: "/run/user/0/openssh_agent", want: ""},
	} {
		f := newFake()
		f.sockType, f.sockDomain = unix.SOCK_STREAM, unix.AF_UNIX
		if tc.cwd != "" {
			f.links["/proc/4242/cwd"] = tc.cwd
		}
		sa := sockaddrUn(tc.path)
		f.put(addr, sa)
		l, sink := newTestLoop(t, f, contractPolicy(&agent.Contract{}, nil, nil))
		l.runtimeDirs = []string{"/run/user/1777"} // the invoking user's, as New reads it at the root tiers
		l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
		ev := sink.one(t)
		var p netPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if ev.Rule != ruleHostSockets || p.What != tc.want {
			t.Errorf("%s (cwd %q): rule %s what %q, want %s and %q", tc.path, tc.cwd, ev.Rule, p.What, ruleHostSockets, tc.want)
		}
	}
}

// TestHostSocketWhatNamesTheRelayWalk: a name under a write entry, which the name's own decision admits, whose relay
// walk as the task reaches a socket no process of the run bound (a symlink in the write directory to /run/docker.sock)
// is refused host-sockets, and the line's what names the socket the walk reached, not the name (ADR 0070 Decision 4;
// No test failed when the relay's sockPath was dropped), for a connect and an addressed datagram.
func TestHostSocketWhatNamesTheRelayWalk(t *testing.T) {
	const addr, bufAddr = 0x40000, 0x9000
	for _, tc := range []struct {
		name string
		nr   int32
		typ  int
		args []uint64
	}{
		{name: "connect", nr: connectNR(), typ: unix.SOCK_STREAM},
		{name: "datagram", nr: sendToNR(), typ: unix.SOCK_DGRAM, args: []uint64{bufAddr, 4, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType, f.sockDomain = tc.typ, unix.AF_UNIX
			f.symlinks["/work/link.sock"] = "/run/docker.sock"
			sa := sockaddrUn("/work/link.sock")
			f.put(addr, sa)
			f.put(bufAddr, []byte("ping"))
			pol := contractPolicy(&agent.Contract{}, nil, []agent.FSRule{{Path: "/work", Raw: "/work/", Kind: agent.FSWrite}})
			l, sink := newTestLoop(t, f, pol)
			args := append([]uint64{5}, tc.args...)
			l.handle(notifFor(tc.nr, 4242, append(args, addr, uint64(len(sa)))...))
			if len(f.unixConnects) != 0 || len(f.unixSends) != 0 {
				t.Fatalf("relayed to %v / %v, want nothing", f.unixConnects, f.unixSends)
			}
			ev := sink.one(t)
			var p netPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != record.VerdictRefused || ev.Rule != ruleHostSockets || p.What != "the Docker daemon, root-equivalent" {
				t.Errorf("event %s/%s what %q, want refused/%s naming the Docker daemon the walk reached", ev.Verdict, ev.Rule,
					p.What, ruleHostSockets)
			}
		})
	}
}

// TestHostRuntimeDirs: the per-user half of R19's list is the invoking user's runtime directory, the one compile
// names (config.InvokingUID): under sudo the SUDO_UID's /run/user, never root's or the supervisor's XDG_RUNTIME_DIR;
// otherwise /run/user/<uid> and an XDG_RUNTIME_DIR that differs from it.
func TestHostRuntimeDirs(t *testing.T) {
	for _, tc := range []struct {
		uid     int
		viaSudo bool
		xdg     string
		want    []string
	}{
		{uid: 1000, xdg: "/run/user/1000", want: []string{"/run/user/1000"}},
		{uid: 1000, xdg: "/custom/rt", want: []string{"/run/user/1000", "/custom/rt"}},
		{uid: 1000, xdg: "relative", want: []string{"/run/user/1000"}},
		{uid: 1000, viaSudo: true, xdg: "/run/user/0", want: []string{"/run/user/1000"}},
	} {
		if got := hostRuntimeDirsOf(tc.uid, tc.viaSudo, tc.xdg); !slices.Equal(got, tc.want) {
			t.Errorf("uid %d sudo %v xdg %q: %q, want %q", tc.uid, tc.viaSudo, tc.xdg, got, tc.want)
		}
	}
}

// TestUnixOnlyRefusesNonRelayableDomain: in the unix-only state a connect or an addressed datagram on a socket whose
// domain is neither IP nor unix (AF_NETLINK, which a sibling could dup2 a unix socket over, and whose connect would
// otherwise be relayed from this process — root at the root tiers) is refused, keyed on the socket's own domain and
// never relayed, with rule host-sockets. A domain that could not be read is refused too (fail closed).
func TestUnixOnlyRefusesNonRelayableDomain(t *testing.T) {
	const addr, bufAddr = 0x40000, 0x9000
	nl := make([]byte, 12) // struct sockaddr_nl: family, pad, nl_pid, nl_groups=1
	nl[0] = unix.AF_NETLINK
	nl[8] = 1
	cases := []struct {
		name    string
		typ     int
		dom     int
		domErr  bool
		nr      int32
		args    []uint64
		wantNil bool // response is CONTINUE (should never be for a refusal)
	}{
		{name: "netlink connect", typ: unix.SOCK_RAW, dom: unix.AF_NETLINK, nr: connectNR(),
			args: []uint64{5, addr, 12}},
		{name: "netlink datagram sendto", typ: unix.SOCK_DGRAM, dom: unix.AF_NETLINK, nr: sendToNR(),
			args: []uint64{5, bufAddr, 4, 0, addr, 12}},
		{name: "domain unreadable connect", typ: unix.SOCK_STREAM, dom: unix.AF_INET, domErr: true, nr: connectNR(),
			args: []uint64{5, addr, 12}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType, f.sockDomain = tc.typ, tc.dom
			if tc.domErr {
				f.sockDomainErr = unix.ENOTSOCK
			}
			f.put(addr, nl)
			f.put(bufAddr, []byte("ping"))
			l, sink := newTestLoop(t, f, contractPolicy(&agent.Contract{}, nil, nil))
			l.handle(notifFor(tc.nr, 4242, tc.args...))
			if len(f.connects) != 0 || len(f.sends) != 0 {
				t.Fatalf("relayed %d connects and %d sends, want none", len(f.connects), len(f.sends))
			}
			if got, _ := f.lastResp(); got.Error != -int32(refusalErrno) {
				t.Fatalf("response = %+v, want R10's errno", got)
			}
			if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Rule != ruleHostSockets {
				t.Errorf("event = %s/%s, want refused/%s", ev.Verdict, ev.Rule, ruleHostSockets)
			}
		})
	}
}

// TestUnixOnlyRelaysRouteQuery: an addressed send on a NETLINK_ROUTE socket to the kernel (nl_pid 0, nl_groups 0), the
// dump request glibc's getifaddrs, if_nameindex and getaddrinfo(AI_ADDRCONFIG), Go's net.Interfaces and libuv send, is
// relayed on the duplicate as the task, from the copies read, and recorded allow (HS-R2-1 medium: refused, every
// interface enumeration of a contract with no net: section failed EACCES). Any other netlink
// destination, protocol or shape stays refused host-sockets (TestUnixOnlyRefusesNonRelayableDomain).
func TestUnixOnlyRelaysRouteQuery(t *testing.T) {
	const addr, bufAddr = 0x40000, 0x9000
	nl := func(pid, groups uint32) []byte {
		b := make([]byte, 12) // struct sockaddr_nl
		binary.NativeEndian.PutUint16(b, unix.AF_NETLINK)
		binary.NativeEndian.PutUint32(b[4:], pid)
		binary.NativeEndian.PutUint32(b[8:], groups)
		return b
	}
	cases := []struct {
		name    string
		proto   int
		sa      []byte
		control bool
		relayed bool
	}{
		{name: "a route dump to the kernel is relayed as the task", proto: unix.NETLINK_ROUTE, sa: nl(0, 0), relayed: true},
		{name: "a route message to another process's port is refused", proto: unix.NETLINK_ROUTE, sa: nl(4243, 0)},
		{name: "a route message to a multicast group is refused", proto: unix.NETLINK_ROUTE, sa: nl(0, 1)},
		{name: "a short netlink address is refused", proto: unix.NETLINK_ROUTE, sa: nl(0, 0)[:8]},
		{name: "an audit message to the kernel is refused", proto: unix.NETLINK_AUDIT, sa: nl(0, 0)},
		{name: "a route message with ancillary data is refused", proto: unix.NETLINK_ROUTE, sa: nl(0, 0), control: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType, f.sockDomain, f.sockProto = unix.SOCK_RAW, unix.AF_NETLINK, tc.proto
			f.taskCreds = sys.TaskCreds{EUID: 1000, EGID: 1000, FSUID: 1000, FSGID: 1000}
			f.put(addr, tc.sa)
			dump := rtRequest(unix.RTM_GETLINK, 20)
			f.put(bufAddr, dump)
			l, sink := newTestLoop(t, f, contractPolicy(&agent.Contract{}, nil, nil))
			if tc.control {
				const hdrAt, iovAt = 0x42000, 0x43000
				hdr := namedMsgHdr(addr, uint32(len(tc.sa)))
				putU64(hdr[msgIovOff:], iovAt)
				putU64(hdr[msgIovLenOff:], 1)
				putU64(hdr[msgControlLenOff:], 32) // SCM_CREDENTIALS
				iov := make([]byte, iovecSize)
				putU64(iov, bufAddr)
				putU64(iov[8:], uint64(len(dump)))
				f.put(iovAt, iov)
				f.put(hdrAt, hdr)
				l.handle(notifFor(sendMsgNR(), 4242, 5, hdrAt, 0))
			} else {
				l.handle(notifFor(sendToNR(), 4242, 5, bufAddr, uint64(len(dump)), 0, addr, uint64(len(tc.sa))))
			}
			got, _ := f.lastResp()
			ev := sink.one(t)
			if !tc.relayed {
				if len(f.sends) != 0 || got.Error != -int32(refusalErrno) || ev.Verdict != record.VerdictRefused ||
					ev.Rule != ruleHostSockets {
					t.Fatalf("sends = %d, response = %+v, event = %s/%s; want nothing sent, R10's errno, refused/%s",
						len(f.sends), got, ev.Verdict, ev.Rule, ruleHostSockets)
				}
				return
			}
			if len(f.sendsAs) != 1 || len(f.sends) != 1 || !bytes.Equal(f.sends[0].addr, tc.sa) ||
				!bytes.Equal(f.sends[0].payload, dump) {
				t.Fatalf("sends = %+v (as the task: %v), want one relayed send of the copies", f.sends, f.sendsAs)
			}
			if !f.sendsAs[0].Equal(f.taskCreds) {
				t.Errorf("relayed with %+v, want the task's credentials %+v", f.sendsAs[0], f.taskCreds)
			}
			if got.Error != 0 || got.Val != int64(len(dump)) {
				t.Errorf("response = %+v, want the relayed result (%d bytes)", got, len(dump))
			}
			var p netPayload
			if ev.DecodePayload(&p) != nil || ev.Verdict != record.VerdictAllow || ev.Rule != ruleRouteQuery || p.BestEffort {
				t.Errorf("event = %s/%s best_effort=%v, want allow/%s, enforced", ev.Verdict, ev.Rule, p.BestEffort, ruleRouteQuery)
			}
			if n := f.fdBalance(); n != 0 {
				t.Errorf("%d descriptors left open, want the duplicate and the task view closed", n)
			}
		})
	}
}

// TestUnixOnlyConnectedSends: an addressed send without MSG_FASTOPEN on a connected stream or seqpacket socket in the
// unix-only state. The kernel never reads its address (tcp_sendmsg and unix_seqpacket_sendmsg drop it,
// unix_stream_sendmsg answers it EISCONN), so nothing decides or records it: no line names it (R13a). The descriptor is
// what the state guards, so where a relay reproduces the call exactly it is made on the duplicate, keyed on
// the duplicate's own domain and type; elsewhere it is continued, never cut, never refused for a name the kernel
// ignores, and never sent with this process's pid.
func TestUnixOnlyConnectedSends(t *testing.T) {
	const addr, bufAddr = 0x40000, 0x9000
	inet := sockaddrIn4("203.0.113.9", 443)
	docker := sockaddrUn("/run/docker.sock")
	journal := sockaddrUn("/run/systemd/journal/socket")
	type sendCase struct {
		name         string
		typ, dom     int
		sa           []byte
		size         int
		control      bool
		kernelErr    error
		wantSend     bool
		wantAddr     []byte
		wantContinue bool
		wantErrno    unix.Errno
		wantVal      int64
	}
	cases := []sendCase{
		{name: "an IP stream send goes to the peer on the duplicate with no address and no line", typ: unix.SOCK_STREAM,
			dom: unix.AF_INET, sa: inet, size: 4, wantSend: true, wantVal: 4},
		{name: "an IP stream send past what is copied is continued, not cut at sendBytes", typ: unix.SOCK_STREAM,
			dom: unix.AF_INET, sa: inet, size: sendBytes + 1, wantContinue: true},
		{name: "an IP stream send with ancillary data is continued", typ: unix.SOCK_STREAM, dom: unix.AF_INET6,
			sa: inet, size: 4, control: true, wantContinue: true},
		{name: "a unix stream send gets the kernel's EISCONN on the duplicate, nothing decided", typ: unix.SOCK_STREAM,
			dom: unix.AF_UNIX, sa: docker, size: 4, kernelErr: unix.EISCONN, wantSend: true, wantAddr: docker,
			wantErrno: unix.EISCONN, wantVal: -1},
		{name: "an SCM_RIGHTS send on a unix stream socket gets EISCONN, not CONTINUE", typ: unix.SOCK_STREAM,
			dom: unix.AF_UNIX, sa: docker, size: 4, control: true, kernelErr: unix.EISCONN, wantSend: true,
			wantAddr: docker, wantErrno: unix.EISCONN, wantVal: -1},
		{name: "a seqpacket send naming a foreign socket the kernel ignores is continued, not refused",
			typ: unix.SOCK_SEQPACKET, dom: unix.AF_UNIX, sa: journal, size: 4, wantContinue: true},
		{name: "a seqpacket record past what is copied is continued whole", typ: unix.SOCK_SEQPACKET, dom: unix.AF_UNIX,
			sa: journal, size: sendBytes + 1, wantContinue: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType, f.sockDomain, f.connected, f.sendErr = tc.typ, tc.dom, true, tc.kernelErr
			f.put(addr, tc.sa)
			f.put(bufAddr, make([]byte, tc.size))
			l, sink := newTestLoop(t, f, contractPolicy(&agent.Contract{}, nil, nil))
			if tc.control {
				const hdrAt, iovAt = 0x42000, 0x43000
				hdr := namedMsgHdr(addr, uint32(len(tc.sa)))
				putU64(hdr[msgIovOff:], iovAt)
				putU64(hdr[msgIovLenOff:], 1)
				putU64(hdr[msgControlLenOff:], 24) // an SCM_RIGHTS array, or a TCP cmsg
				iov := make([]byte, iovecSize)
				putU64(iov, bufAddr)
				putU64(iov[8:], uint64(tc.size))
				f.put(iovAt, iov)
				f.put(hdrAt, hdr)
				l.handle(notifFor(sendMsgNR(), 4242, 5, hdrAt, 0))
			} else {
				l.handle(notifFor(sendToNR(), 4242, 5, bufAddr, uint64(tc.size), 0, addr, uint64(len(tc.sa))))
			}
			got, _ := f.lastResp()
			switch {
			case tc.wantContinue:
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 || len(f.sends) != 0 {
					t.Fatalf("response = %+v, sends = %d; want CONTINUE and nothing sent from here", got, len(f.sends))
				}
			case tc.wantSend:
				if len(f.sends) != 1 {
					t.Fatalf("sends = %+v, want one send on the duplicate", f.sends)
				}
				if !bytes.Equal(f.sends[0].addr, tc.wantAddr) {
					t.Errorf("relayed address = %x, want %x", f.sends[0].addr, tc.wantAddr)
				}
				if got.Error != -int32(tc.wantErrno) || got.Val != tc.wantVal {
					t.Errorf("response = %+v, want errno %v and value %d, the kernel's answer on the duplicate", got,
						tc.wantErrno, tc.wantVal)
				}
			}
			if len(f.unixSends) != 0 {
				t.Errorf("unix relays = %v, want none: the name is not the destination", f.unixSends)
			}
			if evs := sink.all(); len(evs) != 0 {
				t.Errorf("events = %d (first %s %s), want none: the kernel ignores the address, R13a writes no line",
					len(evs), evs[0].Verdict, evs[0].Rule)
			}
		})
	}
}
