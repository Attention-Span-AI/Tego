// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// connectNR is this architecture's connect number, used to drive the dispatch table in tests.
func connectNR() int32 {
	if nativeAuditArch() == auditArchARM {
		return nrARMConnect
	}
	return nrX86Connect
}

func sendToNR() int32 {
	if nativeAuditArch() == auditArchARM {
		return nrARMSendTo
	}
	return nrX86SendTo
}

func sendMsgNR() int32 {
	if nativeAuditArch() == auditArchARM {
		return nrARMSendMsg
	}
	return nrX86SendMsg
}

func sendMMsgNR() int32 {
	if nativeAuditArch() == auditArchARM {
		return nrARMSendMMsg
	}
	return nrX86SendMMsg
}

// TestConnectDecisions drives one connect per row through the real dispatch table and checks the response
// shape, the event and the descriptor balance (R7, R9, R10, R18, I2, I11).
func TestConnectDecisions(t *testing.T) {
	const addr = 0x40000
	resolvers := []netip.AddrPort{netip.MustParseAddrPort("127.0.0.53:53")}
	rules := []agent.NetRule{
		netRule("api.example.com:443", "api.example.com", 443, "93.184.216.34"),
		netRule("10.0.0.0/8:8080", "", 8080),
		netRule("ping.example.com:0", "ping.example.com", 0, "198.51.100.7"),
	}
	rules[1].CIDR = ptrPrefix(netip.MustParsePrefix("10.0.0.0/8"))
	rules[1].Host = ""
	unixRules := []agent.NetRule{
		unixRuleOf("unix:/run/pg.sock", "/run/pg.sock", false),
		unixRuleOf("unix:@bus", "bus", true),
	}

	tests := []struct {
		name       string
		sa         []byte
		sockType   int
		dupErr     error
		connectErr error
		wantErrno  int32
		wantVal    int64
		wantCont   bool
		wantRule   string
		wantVerd   record.Verdict
		wantProto  string
		wantDst    string
		connected  bool
	}{
		{
			name: "allowed host", sa: sockaddrIn4("93.184.216.34", 443), sockType: unix.SOCK_STREAM,
			wantRule: "net[api.example.com:443]", wantVerd: record.VerdictAllow, wantProto: protoTCP,
			wantDst: "93.184.216.34:443", connected: true,
		},
		{
			name: "allowed cidr", sa: sockaddrIn4("10.1.2.3", 8080), sockType: unix.SOCK_STREAM,
			wantRule: "net[10.0.0.0/8:8080]", wantVerd: record.VerdictAllow, wantProto: protoTCP,
			wantDst: "10.1.2.3:8080", connected: true,
		},
		{
			name: "port 0 entry matches raw", sa: sockaddrIn4("198.51.100.7", 0), sockType: unix.SOCK_RAW,
			wantRule: "net[ping.example.com:0]", wantVerd: record.VerdictAllow, wantProto: protoRaw,
			wantDst: "198.51.100.7:0", connected: true,
		},
		{
			// "allow ping to this host" must not become "allow ssh to this host" (SEMANTICS §5).
			name: "port 0 entry does not admit a tcp port", sa: sockaddrIn4("198.51.100.7", 22),
			sockType: unix.SOCK_STREAM, wantErrno: -int32(unix.EACCES), wantVal: -1,
			wantRule: ruleUnmatched, wantVerd: record.VerdictRefused, wantProto: protoTCP,
			wantDst: "198.51.100.7:22",
		},
		{
			name: "unnamed unix socket", sa: []byte{unix.AF_UNIX, 0}, sockType: unix.SOCK_STREAM,
			wantErrno: -int32(unix.EACCES), wantVal: -1, wantRule: ruleUnmatched,
			wantVerd: record.VerdictRefused, wantProto: protoUnix, wantDst: "unix:",
		},
		{
			// A memset sockaddr_un with an oversized addrlen: neither a path nor a name a rule can hold.
			// It must not resolve to the target's cwd and pick up an fs.write grant.
			name: "zeroed unix sockaddr", sa: zeroedUnixAddr(), sockType: unix.SOCK_STREAM,
			wantErrno: -int32(unix.EACCES), wantVal: -1, wantRule: ruleUnmatched,
			wantVerd: record.VerdictRefused, wantProto: protoUnix, wantDst: "unix:@" + strings.Repeat("?", sunPathMax-1),
		},
		{
			name: "undeclared host", sa: sockaddrIn4("203.0.113.9", 443), sockType: unix.SOCK_STREAM,
			wantErrno: -int32(unix.EACCES), wantVal: -1, wantRule: ruleUnmatched,
			wantVerd: record.VerdictRefused, wantProto: protoTCP, wantDst: "203.0.113.9:443",
		},
		{
			name: "declared host wrong port", sa: sockaddrIn4("93.184.216.34", 8443), sockType: unix.SOCK_STREAM,
			wantErrno: -int32(unix.EACCES), wantVal: -1, wantRule: ruleUnmatched,
			wantVerd: record.VerdictRefused, wantProto: protoTCP, wantDst: "93.184.216.34:8443",
		},
		{
			name: "resolver on udp 53", sa: sockaddrIn4("127.0.0.53", 53), sockType: unix.SOCK_DGRAM,
			wantRule: ruleResolver, wantVerd: record.VerdictAllow, wantProto: protoUDP,
			wantDst: "127.0.0.53:53", connected: true,
		},
		{
			name: "resolver on tcp 53", sa: sockaddrIn4("127.0.0.53", 53), sockType: unix.SOCK_STREAM,
			wantRule: ruleResolver, wantVerd: record.VerdictAllow, wantProto: protoTCP,
			wantDst: "127.0.0.53:53", connected: true,
		},
		{
			name: "resolver address on another port", sa: sockaddrIn4("127.0.0.53", 80), sockType: unix.SOCK_STREAM,
			wantErrno: -int32(unix.EACCES), wantVal: -1, wantRule: ruleUnmatched,
			wantVerd: record.VerdictRefused, wantProto: protoTCP, wantDst: "127.0.0.53:80",
		},
		{
			name: "ipv6 undeclared", sa: sockaddrIn6("2001:db8::1", 443), sockType: unix.SOCK_STREAM,
			wantErrno: -int32(unix.EACCES), wantVal: -1, wantRule: ruleUnmatched,
			wantVerd: record.VerdictRefused, wantProto: protoTCP, wantDst: "[2001:db8::1]:443",
		},
		{
			name: "unix pathname allowed", sa: sockaddrUn("/run/pg.sock"), sockType: unix.SOCK_STREAM,
			wantRule: "net[unix:/run/pg.sock]", wantVerd: record.VerdictAllow, wantProto: protoUnix,
			wantDst: "unix:/run/pg.sock", connected: true,
		},
		{
			name: "unix abstract allowed", sa: sockaddrUn("@bus"), sockType: unix.SOCK_SEQPACKET,
			wantRule: "net[unix:@bus]", wantVerd: record.VerdictAllow, wantProto: protoUnix,
			wantDst: "unix:@bus", connected: true,
		},
		{
			name: "unix undeclared", sa: sockaddrUn("/run/other.sock"), sockType: unix.SOCK_STREAM,
			wantErrno: -int32(unix.EACCES), wantVal: -1, wantRule: ruleUnmatched,
			wantVerd: record.VerdictRefused, wantProto: protoUnix, wantDst: "unix:/run/other.sock",
		},
		{
			// The refusal does not depend on the socket, but its line names the socket's own protocol:
			// this used to be written proto=tcp on a datagram socket, because the socket was never read.
			name: "unknown family refused", sa: []byte{0x10, 0x00, 0, 0, 0, 0, 0, 0}, sockType: unix.SOCK_DGRAM,
			wantErrno: -int32(unix.EACCES), wantVal: -1, wantRule: ruleUnmatched,
			wantVerd: record.VerdictRefused, wantProto: protoUDP, wantDst: "family(16)",
		},
		{
			// An unknown family whose socket cannot be read either: still refused, and the line says the
			// socket was not read (fd-raced) rather than naming a protocol nobody read.
			name: "unknown family, duplicate raced away", sa: []byte{0x10, 0x00, 0, 0, 0, 0, 0, 0}, sockType: unix.SOCK_DGRAM,
			dupErr: unix.EBADF, wantErrno: -int32(unix.EACCES), wantVal: -1, wantRule: ruleFDRaced,
			wantVerd: record.VerdictRefused, wantProto: protoTCP, wantDst: "family(16)",
		},
		{
			name: "duplicate raced away", sa: sockaddrIn4("93.184.216.34", 443), sockType: unix.SOCK_STREAM,
			dupErr: unix.EBADF, wantErrno: -int32(unix.EACCES), wantVal: -1, wantRule: ruleFDRaced,
			wantVerd: record.VerdictRefused, wantProto: protoTCP, wantDst: "93.184.216.34:443",
		},
		{
			// This process's own descriptor table is full: no race happened, and the line says so (§7).
			name: "no descriptor for the duplicate", sa: sockaddrIn4("93.184.216.34", 443), sockType: unix.SOCK_STREAM,
			dupErr: unix.EMFILE, wantErrno: -int32(unix.EACCES), wantVal: -1, wantRule: ruleFDExhausted,
			wantVerd: record.VerdictRefused, wantProto: protoTCP, wantDst: "93.184.216.34:443",
		},
		{
			// A target that made itself non-dumpable (ssh-agent, gpg) is one pidfd_getfd refuses with EPERM at tier 1:
			// no race happened either, and the line says the socket could not be read.
			name: "non-dumpable target", sa: sockaddrIn4("93.184.216.34", 443), sockType: unix.SOCK_STREAM,
			dupErr: unix.EPERM, wantErrno: -int32(unix.EACCES), wantVal: -1, wantRule: ruleFDUnreadable,
			wantVerd: record.VerdictRefused, wantProto: protoTCP, wantDst: "93.184.216.34:443",
		},
		{
			// Below 6.9 a secondary thread's duplicate comes from its leader's table, refused for a thread cloned without
			// CLONE_FILES (openTargetPidFD's errOwnFDTable): a lasting property of the thread, not a race, so its every
			// connect is fd-unreadable, never fd-raced.
			name: "a thread with its own descriptor table", sa: sockaddrIn4("93.184.216.34", 443), sockType: unix.SOCK_STREAM,
			dupErr: errOwnFDTable, wantErrno: -int32(unix.EACCES), wantVal: -1, wantRule: ruleFDUnreadable,
			wantVerd: record.VerdictRefused, wantProto: protoTCP, wantDst: "93.184.216.34:443",
		},
		{
			// kcmp(2) missing (no CONFIG_KCMP) cannot tell whether that thread shares its leader's table: lasting too.
			name: "kcmp unavailable", sa: sockaddrIn4("93.184.216.34", 443), sockType: unix.SOCK_STREAM,
			dupErr: unix.ENOSYS, wantErrno: -int32(unix.EACCES), wantVal: -1, wantRule: ruleFDUnreadable,
			wantVerd: record.VerdictRefused, wantProto: protoTCP, wantDst: "93.184.216.34:443",
		},
		{
			// The task gone between the trap and the duplicate is the race fd-raced names.
			name: "target gone before the duplicate", sa: sockaddrIn4("93.184.216.34", 443), sockType: unix.SOCK_STREAM,
			dupErr: unix.ESRCH, wantErrno: -int32(unix.EACCES), wantVal: -1, wantRule: ruleFDRaced,
			wantVerd: record.VerdictRefused, wantProto: protoTCP, wantDst: "93.184.216.34:443",
		},
		{
			name: "system file table full", sa: sockaddrIn4("93.184.216.34", 443), sockType: unix.SOCK_STREAM,
			dupErr: unix.ENFILE, wantErrno: -int32(unix.EACCES), wantVal: -1, wantRule: ruleFDExhausted,
			wantVerd: record.VerdictRefused, wantProto: protoTCP, wantDst: "93.184.216.34:443",
		},
		{
			name: "real connect error is relayed", sa: sockaddrIn4("93.184.216.34", 443),
			sockType: unix.SOCK_STREAM, connectErr: unix.ECONNREFUSED,
			wantErrno: -int32(unix.ECONNREFUSED), wantVal: -1, wantRule: "net[api.example.com:443]",
			wantVerd: record.VerdictAllow, wantProto: protoTCP, wantDst: "93.184.216.34:443", connected: true,
		},
		{
			name: "nonblocking connect relays EINPROGRESS", sa: sockaddrIn4("93.184.216.34", 443),
			sockType: unix.SOCK_STREAM, connectErr: unix.EINPROGRESS,
			wantErrno: -int32(unix.EINPROGRESS), wantVal: -1, wantRule: "net[api.example.com:443]",
			wantVerd: record.VerdictAllow, wantProto: protoTCP, wantDst: "93.184.216.34:443", connected: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(addr, tc.sa)
			f.sockType = tc.sockType
			f.dupErr = tc.dupErr
			f.connectErr = tc.connectErr
			all := append(append([]agent.NetRule(nil), rules...), unixRules...)
			l, sink := newTestLoop(t, f, testPolicy(all, nil, resolvers))
			l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(tc.sa))))

			got, ok := f.lastResp()
			if !ok {
				t.Fatal("no response")
			}
			if f.respCount() != 1 {
				t.Fatalf("responses = %d, want exactly one (I11)", f.respCount())
			}
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Fatal("a connect was answered CONTINUE (I2)")
			}
			if got.Error != tc.wantErrno || got.Val != tc.wantVal {
				t.Errorf("response = {err %d, val %d}, want {err %d, val %d}", got.Error, got.Val, tc.wantErrno, tc.wantVal)
			}
			if connected := len(f.connects) > 0; connected != tc.connected {
				t.Errorf("connect performed on the duplicate = %v, want %v", connected, tc.connected)
			}
			if tc.connected && string(f.connects[0]) != string(tc.sa) {
				t.Errorf("connect used %v, want the bytes the target passed %v", f.connects[0], tc.sa)
			}
			ev := sink.one(t)
			if ev.Kind != record.KindNet || ev.Source != record.SourceSupervisor {
				t.Errorf("kind/source = %s/%s", ev.Kind, ev.Source)
			}
			if ev.Rule != tc.wantRule || ev.Verdict != tc.wantVerd {
				t.Errorf("rule/verdict = %s/%s, want %s/%s", ev.Rule, ev.Verdict, tc.wantRule, tc.wantVerd)
			}
			if tc.wantVerd == record.VerdictRefused && ev.Reason != record.ReasonNetNotAllowed {
				t.Errorf("reason = %q, want net-not-allowed", ev.Reason)
			}
			var p record.NetPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatalf("payload: %v", err)
			}
			if p.Proto != tc.wantProto || p.Dst != tc.wantDst {
				t.Errorf("payload = %+v, want proto %s dst %s", p, tc.wantProto, tc.wantDst)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("event does not validate: %v", err)
			}
			if f.fdBalance() != 0 {
				t.Errorf("%d descriptors left open (E28)", f.fdBalance())
			}
		})
	}
}

// TestConnectArgsUnreadableFailsClosed is R5: an address this loop cannot read refuses, never continues.
func TestConnectArgsUnreadable(t *testing.T) {
	f := newFake() // nothing mapped: every read faults
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
	l.handle(notifFor(connectNR(), 4242, 5, 0x9000, 16))
	got, ok := f.lastResp()
	if !ok || got.Error != -int32(unix.EACCES) {
		t.Fatalf("response = %+v, want EACCES (R5)", got)
	}
	ev := sink.one(t)
	if ev.Rule != ruleArgsUnreadable || ev.Verdict != record.VerdictRefused {
		t.Errorf("rule/verdict = %s/%s, want args-unreadable/refused", ev.Rule, ev.Verdict)
	}
}

// TestConnectTargetDied is R19/E1: a stale id is abandoned without a response and without an event.
func TestConnectTargetDied(t *testing.T) {
	f := newFake()
	f.put(0x40000, sockaddrIn4("93.184.216.34", 443))
	f.stale[7] = true
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
	l.handle(notifFor(connectNR(), 4242, 5, 0x40000, 16))
	if f.respCount() != 0 {
		t.Errorf("responses = %d, want none for a dead target", f.respCount())
	}
	if evs := sink.all(); len(evs) != 0 {
		t.Errorf("events = %d, want none for a decision never reached (E1)", len(evs))
	}
}

// TestSockTypeFailureFailsClosed is E33 seen from its failing side: the fd number was reused for
// something that is not a socket, so there is nothing to decide against.
func TestSockTypeFailureFailsClosed(t *testing.T) {
	f := newFake()
	f.sockTypErr = unix.ENOTSOCK
	f.put(0x40000, sockaddrIn4("93.184.216.34", 443))
	rules := []agent.NetRule{netRule("api:443", "api", 443, "93.184.216.34")}
	l, sink := newTestLoop(t, f, testPolicy(rules, nil, nil))
	l.handle(notifFor(connectNR(), 42, 5, 0x40000, 16))
	got, _ := f.lastResp()
	if got.Error != -int32(unix.EACCES) {
		t.Errorf("response = %+v, want EACCES", got)
	}
	if len(f.connects) != 0 {
		t.Error("a connect was performed on a duplicate whose type could not be read")
	}
	if ev := sink.one(t); ev.Rule != ruleFDRaced {
		t.Errorf("rule = %s, want %s", ev.Rule, ruleFDRaced)
	}
	if f.fdBalance() != 0 {
		t.Errorf("%d descriptors left open", f.fdBalance())
	}
}

// TestConnectDiesAtResponse is E2: the data was read while the target was alive, the decision was made,
// and only the answer was lost. The event still stands.
func TestConnectDiesAtResponse(t *testing.T) {
	f := newFake()
	f.put(0x40000, sockaddrIn4("203.0.113.9", 443))
	f.sendErrno = unix.ENOENT
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
	l.handle(notifFor(connectNR(), 4242, 5, 0x40000, 16))
	ev := sink.one(t)
	if ev.Verdict != record.VerdictRefused {
		t.Errorf("verdict = %s, want the decision recorded (E2)", ev.Verdict)
	}
	if f.fdBalance() != 0 {
		t.Errorf("%d descriptors left open", f.fdBalance())
	}
}

// TestUnixRelativePathResolvesAgainstCwd: a relative sun_path resolves through /proc/<pid>/cwd.
func TestUnixRelativePathResolvesAgainstCwd(t *testing.T) {
	f := newFake()
	f.links["/proc/4242/cwd"] = "/work/run"
	f.put(0x40000, sockaddrUn("pg.sock"))
	rules := []agent.NetRule{unixRuleOf("unix:/work/run/pg.sock", "/work/run/pg.sock", false)}
	l, sink := newTestLoop(t, f, testPolicy(rules, nil, nil))
	l.handle(notifFor(connectNR(), 4242, 5, 0x40000, uint64(2+len("pg.sock")+1)))
	ev := sink.one(t)
	if ev.Verdict != record.VerdictAllow || ev.Rule != "net[unix:/work/run/pg.sock]" {
		t.Fatalf("verdict/rule = %s/%s, want allow/net[unix:/work/run/pg.sock]", ev.Verdict, ev.Rule)
	}
}

// TestUnixAbstractMatchesRawBytes is E5: an abstract name is matched by the bytes the target passed,
// embedded NULs included, and is never NUL-scanned the way a pathname is.
func TestUnixAbstractMatchesRawBytes(t *testing.T) {
	const addr = 0x40000
	tests := []struct {
		name    string
		declare string
		sa      []byte
		want    record.Verdict
	}{
		{
			name: "exact bytes", declare: "a\x00b", sa: append([]byte{unix.AF_UNIX, 0, 0}, []byte("a\x00b")...),
			want: record.VerdictAllow,
		},
		{
			name: "prefix before the NUL is not a match", declare: "a",
			sa: append([]byte{unix.AF_UNIX, 0, 0}, []byte("a\x00b")...), want: record.VerdictRefused,
		},
		{
			name: "declared with a NUL, connected without", declare: "a\x00b",
			sa: append([]byte{unix.AF_UNIX, 0, 0}, []byte("a")...), want: record.VerdictRefused,
		},
		{
			// The kernel takes the whole addrlen-bounded name, so @bus and @bus followed by 40 NULs are
			// two different sockets. Matching the padded form against a declared @bus would let the run
			// reach a socket the contract never named.
			name: "zero padding makes a different name", declare: "bus",
			sa:   append(append([]byte{unix.AF_UNIX, 0, 0}, []byte("bus")...), make([]byte, 40)...),
			want: record.VerdictRefused,
		},
		{
			name:    "declared with the padding it is connected with",
			declare: "bus\x00\x00", sa: append([]byte{unix.AF_UNIX, 0, 0}, []byte("bus\x00\x00")...),
			want: record.VerdictAllow,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(addr, tc.sa)
			rules := []agent.NetRule{unixRuleOf("unix:@"+tc.declare, tc.declare, true)}
			l, sink := newTestLoop(t, f, testPolicy(rules, nil, nil))
			l.handle(notifFor(connectNR(), 42, 5, addr, uint64(len(tc.sa))))
			if ev := sink.one(t); ev.Verdict != tc.want {
				t.Errorf("verdict = %s, want %s", ev.Verdict, tc.want)
			}
		})
	}
}

// TestUnixSocketUnderWriteDirIsAllowed is SEMANTICS §5 and R11a: a socket a process of the run bound under a
// write entry may be connected to with no unix: entry; one under the same entry that the run did not bind — a
// daemon's socket from before the run, or one an outside process made (interactive-codex POC finding F6) — is
// refused unix-foreign, and nothing is connected. (The test passed an addrlen past the name before, so the connect
// failed EFAULT and the name's allow line was all it checked.)
func TestUnixSocketUnderWriteDirIsAllowed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		bound   bool
		verdict record.Verdict
		rule    string
	}{
		{"bound by the run", true, record.VerdictAllow, "fs.write[/work/proj]"},
		{"not bound by the run", false, record.VerdictRefused, ruleUnixForeign},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			sa := sockaddrUn("/work/proj/.ray/session.sock")
			f.put(0x40000, sa)
			fs := []agent.FSRule{{Path: "/work/proj", Kind: agent.FSWrite}}
			l, sink := newTestLoop(t, f, testPolicy(nil, fs, nil))
			if tc.bound {
				f.bindsSocket(t, l, sockID{ino: 9000, cookie: 3}, "/work/proj/.ray/session.sock")
			}
			l.handle(notifFor(connectNR(), 4242, 5, 0x40000, uint64(len(sa))))
			ev := sink.one(t)
			if ev.Verdict != tc.verdict || ev.Rule != tc.rule {
				t.Fatalf("verdict/rule = %s/%s, want %s/%s", ev.Verdict, ev.Rule, tc.verdict, tc.rule)
			}
			got, _ := f.lastResp()
			if connected := len(f.unixConnects) == 1; connected != tc.bound || (tc.bound && got.Error != 0) ||
				(!tc.bound && got.Error != -int32(refusalErrno)) {
				t.Fatalf("answer %+v, connects %q: want the run's socket connected and any other refused", got, f.unixConnects)
			}
		})
	}
}

// TestSendToRefusedDatagramIsRefused is R13b as amended 2026-10-16: an unconnected datagram whose
// destination the policy refuses is refused with R10's errno, its line is the refusal with no best_effort, and
// nothing is sent. Before, it was continued — the data left the kernel under a refused line marked
// best_effort — which is how net.dns.mode: off let a lookup from an unconnected socket reach the resolver.
//
// Spec: docs/p0/supervisor.md R13b; docs/p0/enforce-landlock.md R14.
func TestSendToRefusedDatagramIsRefused(t *testing.T) {
	f := newFake()
	f.sockType = unix.SOCK_DGRAM
	f.put(0x40000, sockaddrIn4("203.0.113.9", 9999))
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
	l.handle(notifFor(sendToNR(), 4242, 5, 0x50000, 4, 0, 0x40000, 16))
	got, _ := f.lastResp()
	if got.Flags != 0 || got.Error != -int32(refusalErrno) {
		t.Fatalf("response = %+v, want R10's errno for a refused datagram (R13b)", got)
	}
	if len(f.sends) != 0 {
		t.Fatalf("the loop sent the refused datagram itself (%d sends)", len(f.sends))
	}
	ev := sink.one(t)
	if ev.Verdict != record.VerdictRefused || ev.Rule != ruleUnmatched || ev.Reason != record.ReasonNetNotAllowed {
		t.Errorf("verdict/rule/reason = %s/%s/%s, want refused/unmatched/net-not-allowed", ev.Verdict, ev.Rule, ev.Reason)
	}
	var p netPayload
	if err := ev.DecodePayload(&p); err != nil || p.Proto != protoUDP {
		t.Errorf("payload = %+v (%v), want proto udp", p, err)
	}
	if p.BestEffort {
		t.Error("the refusal is marked best_effort, though it was enforced")
	}
}

// TestSendToAdmittedDatagramIsBestEffort: a datagram the policy admits is continued, so the kernel sends
// it to its own copy of the address, and its allow line says so with best_effort.
func TestSendToAdmittedDatagramIsBestEffort(t *testing.T) {
	f := newFake()
	f.sockType = unix.SOCK_DGRAM
	f.put(0x40000, sockaddrIn4("203.0.113.9", 9999))
	rules := []agent.NetRule{netRule("203.0.113.9:9999", "", 9999, "203.0.113.9")}
	l, sink := newTestLoop(t, f, testPolicy(rules, nil, nil))
	l.handle(notifFor(sendToNR(), 4242, 5, 0x50000, 4, 0, 0x40000, 16))
	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("response = %+v, want CONTINUE for an admitted datagram (R13b)", got)
	}
	ev := sink.one(t)
	var p netPayload
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != record.VerdictAllow || !p.BestEffort {
		t.Errorf("line %s best_effort=%t, want allow and best_effort", ev.Verdict, p.BestEffort)
	}
}

// TestSendToFastOpen: an addressed send on a stream socket is decided like a connect and the bytes
// are relayed on the duplicate.
func TestSendToFastOpen(t *testing.T) {
	const saAddr, bufAddr = 0x40000, 0x50000
	payload := []byte("GET / HTTP/1.1\r\n")
	rules := []agent.NetRule{netRule("93.184.216.34:443", "93.184.216.34", 443, "93.184.216.34")}
	t.Run("allowed", func(t *testing.T) {
		f := newFake()
		f.sockType = unix.SOCK_STREAM
		f.put(saAddr, sockaddrIn4("93.184.216.34", 443))
		f.put(bufAddr, payload)
		l, sink := newTestLoop(t, f, testPolicy(rules, nil, nil))
		l.handle(notifFor(sendToNR(), 4242, 5, bufAddr, uint64(len(payload)), unix.MSG_FASTOPEN, saAddr, 16))
		got, _ := f.lastResp()
		if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
			t.Fatal("a Fast-Open send was continued (R12)")
		}
		if got.Val != int64(len(payload)) || got.Error != 0 {
			t.Errorf("response = %+v, want the real byte count %d", got, len(payload))
		}
		if len(f.sends) != 1 || string(f.sends[0].payload) != string(payload) {
			t.Fatalf("relayed sends = %+v, want the target's own bytes", f.sends)
		}
		if f.sends[0].flags != unix.MSG_FASTOPEN {
			t.Errorf("relayed flags = %#x, want the target's %#x", f.sends[0].flags, unix.MSG_FASTOPEN)
		}
		if ev := sink.one(t); ev.Verdict != record.VerdictAllow {
			t.Errorf("verdict = %s, want allow", ev.Verdict)
		}
	})
	t.Run("refused", func(t *testing.T) {
		f := newFake()
		f.sockType = unix.SOCK_STREAM
		f.put(saAddr, sockaddrIn4("203.0.113.9", 443))
		f.put(bufAddr, payload)
		l, sink := newTestLoop(t, f, testPolicy(rules, nil, nil))
		l.handle(notifFor(sendToNR(), 4242, 5, bufAddr, uint64(len(payload)), 0, saAddr, 16))
		got, _ := f.lastResp()
		if got.Error != -int32(unix.EACCES) {
			t.Errorf("response = %+v, want EACCES before any byte leaves (R12)", got)
		}
		if len(f.sends) != 0 {
			t.Errorf("bytes were relayed for a refused send: %+v", f.sends)
		}
		if ev := sink.one(t); ev.Verdict != record.VerdictRefused {
			t.Errorf("verdict = %s, want refused", ev.Verdict)
		}
	})
}

// TestSendMsgWithoutAddress: a connected send carries no address, was decided at connect, and is
// continued with no event at all.
func TestSendMsgWithoutAddress(t *testing.T) {
	f := newFake()
	hdr := make([]byte, msgHdrSize)
	f.put(0x60000, hdr)
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
	l.handle(notifFor(sendMsgNR(), 4242, 5, 0x60000, 0))
	got, _ := f.lastResp()
	if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("response = %+v, want CONTINUE", got)
	}
	if evs := sink.all(); len(evs) != 0 {
		t.Errorf("events = %d, want none for a connected send", len(evs))
	}
	if f.openFDs != 0 {
		t.Errorf("took %d descriptors for a send with no address", f.openFDs)
	}
}

// TestSendMsgOnAConnectedStreamIsContinued: the kernel ignores msg_name once the socket has a peer, so
// the bytes go where the connect decision already sent them (R13a). Deciding the ignored address again
// would refuse a send the kernel was going to deliver anyway.
func TestSendMsgOnAConnectedStreamIsContinued(t *testing.T) {
	const hdrAddr, saAddr = 0x60000, 0x40000
	f := newFake()
	f.sockType = unix.SOCK_STREAM
	f.connected = true
	hdr := make([]byte, msgHdrSize)
	putU64(hdr[msgNameOff:], saAddr)
	putU32(hdr[msgNameLenOff:], 16)
	f.put(hdrAddr, hdr)
	f.put(saAddr, sockaddrIn4("203.0.113.9", 443)) // undeclared, and still not this loop's decision
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
	l.handle(notifFor(sendMsgNR(), 42, 5, hdrAddr, 0))
	got, _ := f.lastResp()
	if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("response = %+v, want CONTINUE", got)
	}
	if len(f.sends) != 0 {
		t.Errorf("bytes were relayed for a connected socket: %+v", f.sends)
	}
	if evs := sink.all(); len(evs) != 0 {
		t.Errorf("events = %d, want none", len(evs))
	}
	if f.fdBalance() != 0 {
		t.Errorf("%d descriptors left open", f.fdBalance())
	}
}

// TestSendMsgWithAncillaryDataIsRefused: the relay sends the gathered payload and cannot reproduce an
// SCM_RIGHTS array, whose descriptor numbers mean something else in this process. Refusing beats sending
// the bytes without the descriptors and reporting success.
func TestSendMsgWithAncillaryDataIsRefused(t *testing.T) {
	const hdrAddr, saAddr, iovAddr, bufAddr = 0x60000, 0x40000, 0x70000, 0x80000
	f := newFake()
	f.sockType = unix.SOCK_STREAM
	hdr := make([]byte, msgHdrSize)
	putU64(hdr[msgNameOff:], saAddr)
	putU32(hdr[msgNameLenOff:], 16)
	putU64(hdr[msgIovOff:], iovAddr)
	putU64(hdr[msgIovLenOff:], 1)
	putU64(hdr[msgControlLenOff:], 24)
	iov := make([]byte, iovecSize)
	putU64(iov[iovecBaseOff:], bufAddr)
	putU64(iov[iovecLenOff:], 2)
	f.put(hdrAddr, hdr)
	f.put(saAddr, sockaddrIn4("93.184.216.34", 443))
	f.put(iovAddr, iov)
	f.put(bufAddr, []byte("hi"))
	rules := []agent.NetRule{netRule("api:443", "api", 443, "93.184.216.34")}
	l, sink := newTestLoop(t, f, testPolicy(rules, nil, nil))
	l.handle(notifFor(sendMsgNR(), 42, 5, hdrAddr, 0))
	got, _ := f.lastResp()
	if got.Error != -int32(unix.EACCES) {
		t.Fatalf("response = %+v, want EACCES", got)
	}
	if len(f.sends) != 0 {
		t.Errorf("bytes were relayed without their ancillary data: %+v", f.sends)
	}
	if ev := sink.one(t); ev.Rule != ruleAncillary {
		t.Errorf("rule = %s, want %s", ev.Rule, ruleAncillary)
	}
}

// TestSendMsgFastOpenGathersIovecs is R12's gather path on a stream socket.
func TestSendMsgFastOpenGathersIovecs(t *testing.T) {
	const hdrAddr, saAddr, iovAddr, aAddr, bAddr = 0x60000, 0x40000, 0x70000, 0x80000, 0x81000
	f := newFake()
	f.sockType = unix.SOCK_STREAM
	hdr := make([]byte, msgHdrSize)
	putU64(hdr[msgNameOff:], saAddr)
	putU32(hdr[msgNameLenOff:], 16)
	putU64(hdr[msgIovOff:], iovAddr)
	putU64(hdr[msgIovLenOff:], 2)
	iov := make([]byte, 2*iovecSize)
	putU64(iov[iovecBaseOff:], aAddr)
	putU64(iov[iovecLenOff:], 3)
	putU64(iov[iovecSize+iovecBaseOff:], bAddr)
	putU64(iov[iovecSize+iovecLenOff:], 2)
	f.put(hdrAddr, hdr)
	f.put(saAddr, sockaddrIn4("93.184.216.34", 443))
	f.put(iovAddr, iov)
	f.put(aAddr, []byte("abc"))
	f.put(bAddr, []byte("de"))
	rules := []agent.NetRule{netRule("93.184.216.34:443", "93.184.216.34", 443, "93.184.216.34")}
	l, sink := newTestLoop(t, f, testPolicy(rules, nil, nil))
	l.handle(notifFor(sendMsgNR(), 4242, 5, hdrAddr, 0))
	if len(f.sends) != 1 || string(f.sends[0].payload) != "abcde" {
		t.Fatalf("relayed = %+v, want the gathered iovecs", f.sends)
	}
	got, _ := f.lastResp()
	if got.Val != 5 {
		t.Errorf("response val = %d, want 5", got.Val)
	}
	if ev := sink.one(t); ev.Verdict != record.VerdictAllow {
		t.Errorf("verdict = %s", ev.Verdict)
	}
}

// TestSendMMsgRecordsEveryDestination: a batch whose every destination the policy admits gets one
// CONTINUE and one best-effort event per addressed message, capped.
func TestSendMMsgRecordsEveryDestination(t *testing.T) {
	const arrayAddr, sa0, sa1 = 0x90000, 0x40000, 0x41000
	f := newFake()
	f.sockType = unix.SOCK_DGRAM
	arr := make([]byte, 2*mmsgHdrSize)
	putU64(arr[msgNameOff:], sa0)
	putU32(arr[msgNameLenOff:], 16)
	putU64(arr[mmsgHdrSize+msgNameOff:], sa1)
	putU32(arr[mmsgHdrSize+msgNameLenOff:], 16)
	f.put(arrayAddr, arr)
	f.put(sa0, sockaddrIn4("198.51.100.1", 5353))
	f.put(sa1, sockaddrIn4("198.51.100.2", 5353))
	rules := []agent.NetRule{
		netRule("198.51.100.1:5353", "", 5353, "198.51.100.1"),
		netRule("198.51.100.2:5353", "", 5353, "198.51.100.2"),
	}
	l, sink := newTestLoop(t, f, testPolicy(rules, nil, nil))
	l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, 2, 0))
	got, _ := f.lastResp()
	if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("response = %+v, want one CONTINUE for the whole syscall", got)
	}
	if f.respCount() != 1 {
		t.Fatalf("responses = %d, want exactly one", f.respCount())
	}
	evs := sink.all()
	if len(evs) != 2 {
		t.Fatalf("events = %d, want one per addressed message", len(evs))
	}
	if f.fdBalance() != 0 {
		t.Errorf("%d descriptors left open", f.fdBalance())
	}
	for i, want := range []string{"198.51.100.1:5353", "198.51.100.2:5353"} {
		var p netPayload
		if err := evs[i].DecodePayload(&p); err != nil || p.Dst != want {
			t.Errorf("event %d dst = %q (%v), want %q", i, p.Dst, err, want)
		}
		if p.Proto != protoUDP || !p.BestEffort {
			t.Errorf("event %d = {%s best_effort=%v}, want udp and best-effort", i, p.Proto, p.BestEffort)
		}
	}
}

// TestSendMMsgSkipsUnaddressedMessages: a batch with no destinations takes no duplicate and records
// nothing; the send was decided at connect (R13a).
func TestSendMMsgSkipsUnaddressedMessages(t *testing.T) {
	const arrayAddr = 0x90000
	f := newFake()
	f.put(arrayAddr, make([]byte, 2*mmsgHdrSize))
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
	l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, 2, 0))
	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("response = %+v, want CONTINUE", got)
	}
	if evs := sink.all(); len(evs) != 0 {
		t.Errorf("events = %d, want none", len(evs))
	}
	if f.openFDs != 0 {
		t.Errorf("took %d descriptors for a batch with no destinations", f.openFDs)
	}
}

// zeroedUnixAddr is the memset-then-set-the-family idiom with the full sockaddr_un length: an abstract
// name of nothing but padding.
func zeroedUnixAddr() []byte {
	b := make([]byte, 2+sunPathMax)
	b[0] = unix.AF_UNIX
	return b
}

// ptrPrefix is a helper for the CIDR fixture.
func ptrPrefix(p netip.Prefix) *netip.Prefix { return &p }

// putU64 writes a little-endian 64-bit word into a fixture buffer.
func putU64(b []byte, v uint64) {
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * i))
	}
}

// putU32 writes a little-endian 32-bit word into a fixture buffer.
func putU32(b []byte, v uint32) {
	for i := 0; i < 4; i++ {
		b[i] = byte(v >> (8 * i))
	}
}

// TestConnectUnspecDissolvesRatherThanRefusing covers connect(fd, {AF_UNSPEC}, len).
//
// R4/E4 sends every family this tier does not recognise to `unmatched -> refused`, and AF_UNSPEC fell
// into it. It does not belong there: AF_UNSPEC in connect(2) is not an unrecognised destination but the
// defined, portable request to dissolve a socket's association — the kernel routes it straight to the
// protocol's disconnect in both __inet_dgram_connect and __inet_stream_connect. It names nowhere, sends
// nothing, and can only narrow what the socket may reach, so refusing it broke a working idiom (one UDP
// socket reused across peers) for no security at all, and wrote a ledger line reading
// `refused reason=net-not-allowed dst=family(0)` about a call that named no destination.
//
// The answer is still not CONTINUE. The address this loop read is the address this loop relays (I3, I2):
// CONTINUE would re-read msg_name from the target, which another thread of the same process can rewrite
// into a real destination between the decision and the kernel's own read — turning a carve-out for a
// harmless call into an undecided connect to anywhere.
func TestConnectUnspecDissolvesRatherThanRefusing(t *testing.T) {
	const addr = 0x40000
	f := newFake()
	sa := make([]byte, 16) // sa_family = AF_UNSPEC (0), the rest zero
	f.put(addr, sa)
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))

	l.handle(notifFor(connectNR(), 4242, 5, addr, 16))

	got, ok := f.lastResp()
	if !ok {
		t.Fatal("no response")
	}
	if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
		t.Fatalf("response = %+v: a connect is never answered CONTINUE (I2), and here it would re-read an address another thread can rewrite", got)
	}
	if got.Error != 0 || got.Val != 0 {
		t.Errorf("response = {error=%d val=%d}, want the real result of the relayed disassociation (0)", got.Error, got.Val)
	}
	if len(f.connects) != 1 || len(f.connects[0]) != 16 || f.connects[0][0] != unix.AF_UNSPEC {
		t.Fatalf("connects = %v, want the exact AF_UNSPEC bytes relayed on the duplicate (I3)", f.connects)
	}
	ev := sink.one(t)
	if ev.Verdict != record.VerdictObserved || ev.Reason != "" {
		t.Errorf("event = {verdict=%s reason=%s}, want observed with no reason: nothing was decided and nothing was reached", ev.Verdict, ev.Reason)
	}
	if ev.Rule != ruleUnspec {
		t.Errorf("rule = %q, want %q", ev.Rule, ruleUnspec)
	}
	var p netPayload
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if p.Dst != "unspec" {
		t.Errorf("dst = %q, want %q", p.Dst, "unspec")
	}
	if f.fdBalance() != 0 {
		t.Errorf("%d descriptors left open", f.fdBalance())
	}
}

// TestConnectUnknownFamilyIsStillRefused keeps R4/E4 where it belongs: the carve-out is for AF_UNSPEC
// alone, not for every family this tier does not parse.
func TestConnectUnknownFamilyIsStillRefused(t *testing.T) {
	const addr = 0x40000
	f := newFake()
	sa := make([]byte, 16)
	sa[0] = unix.AF_PACKET
	f.put(addr, sa)
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))

	l.handle(notifFor(connectNR(), 4242, 5, addr, 16))

	if got, _ := f.lastResp(); got.Error != -int32(refusalErrno) {
		t.Fatalf("response = %+v, want refusalErrno for an unrecognised family (R4, E4)", got)
	}
	if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Rule != ruleUnmatched {
		t.Errorf("event = {verdict=%s rule=%s}, want a refusal with %s", ev.Verdict, ev.Rule, ruleUnmatched)
	}
	if len(f.connects) != 0 {
		t.Error("an unrecognised family was relayed onto the target's socket")
	}
}
