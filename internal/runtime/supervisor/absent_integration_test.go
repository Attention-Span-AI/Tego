// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const (
	// modeNoNet runs the target in a Landlock domain scoped for abstract unix sockets, the scope the
	// tier-1 ruleset always carries at ABI ≥ 6 (enforce-landlock R7), under a contract with no net:.
	modeNoNet = "nonet"
	// helperAbstract names the abstract socket the parent listens on, outside the target's domain.
	helperAbstract = "TEGO_SUPERVISOR_ABSTRACT"
	// helperScopeOptional lets a modeNoNet or modeUnixDgram target run without the abstract scope on a kernel below
	// Landlock ABI 6: the unix-only state's tests, whose refusals are the supervisor's (ADR 0070).
	helperScopeOptional = "TEGO_SUPERVISOR_SCOPE_OPTIONAL"

	landlockCreateRulesetVersion = 1 // LANDLOCK_CREATE_RULESET_VERSION
	landlockScopeAbstractUnix    = 1 // LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET, ABI 6
)

// restrictAbstractScope puts the target in a domain that handles nothing but the abstract-socket scope,
// so the only thing that can refuse its connects is that scope. It returns a skip reason on a kernel
// without it.
func restrictAbstractScope() string {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, landlockCreateRulesetVersion)
	if errno != 0 {
		return "landlock unavailable: " + errno.Error()
	}
	if abi < 6 {
		return "landlock ABI " + strconv.Itoa(int(abi)) + " has no abstract-socket scope (needs 6)"
	}
	attr := unix.LandlockRulesetAttr{Scoped: landlockScopeAbstractUnix}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return "landlock_create_ruleset(scoped): " + errno.Error()
	}
	defer unix.Close(int(fd)) //nolint:errcheck // the domain outlives the ruleset fd
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); errno != 0 {
		return "landlock_restrict_self: " + errno.Error()
	}
	return ""
}

// noNetChecks are the target's connects under a contract with no net: section: an abstract name bound
// outside its domain, a pathname socket under the write directory bound by the test process, one the target binds
// itself there, and an IP destination no entry names.
func noNetChecks() []checkResult {
	dir := os.Getenv(helperDir)
	ports := splitPorts(os.Getenv(helperPorts))
	var out []checkResult
	add := func(name string, err error, n int, s string) {
		out = append(out, checkResult{Name: name, Err: errText(err), N: n, Out: s})
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		add("nonet_abstract", unix.Connect(fd, &unix.SockaddrUnix{Name: "@" + os.Getenv(helperAbstract)}), 0, "")
		_ = unix.Close(fd)
	}
	fd, err = unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		add("nonet_unix", unix.Connect(fd, &unix.SockaddrUnix{Name: filepath.Join(dir, "u.sock")}), 0, "")
		_ = unix.Close(fd)
	}
	if lfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); err == nil {
		own := &unix.SockaddrUnix{Name: filepath.Join(dir, "own.sock")}
		err = unix.Bind(lfd, own)
		if err == nil {
			err = unix.Listen(lfd, 4)
		}
		if err == nil {
			if fd, err = unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); err == nil {
				err = unix.Connect(fd, own)
				_ = unix.Close(fd)
			}
		}
		add("nonet_own", err, 0, "")
		_ = unix.Close(lfd)
	}
	if lfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); err == nil {
		own := &unix.SockaddrUnix{Name: "@" + os.Getenv(helperAbstract) + "-own"}
		err = unix.Bind(lfd, own)
		if err == nil {
			err = unix.Listen(lfd, 4)
		}
		if err == nil {
			if fd, err = unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); err == nil {
				err = unix.Connect(fd, own)
				_ = unix.Close(fd)
			}
		}
		add("nonet_own_abstract", err, 0, "")
		_ = unix.Close(lfd)
	}
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		err = unix.Connect(fd, &unix.SockaddrInet4{Port: ports[1], Addr: [4]byte{127, 0, 0, 1}})
		n := 0
		buf := make([]byte, 8)
		if err == nil {
			if _, err = unix.Write(fd, []byte("ping")); err == nil {
				n, err = unix.Read(fd, buf)
			}
		}
		add("nonet_inet_payload", err, n, string(buf[:max(n, 0)]))
		_ = unix.Close(fd)
	}
	return append(out, namedOnConnectedChecks(dir, ports[0])...)
}

// namedSeqpacketRecord is the size of the record namedOnConnectedChecks sends with a name on a connected seqpacket
// pair: past sendBytes, which a relay would have cut it at.
const namedSeqpacketRecord = 100 << 10

// namedOnConnectedChecks are addressed sends on connected sockets, whose address the kernel ignores: a
// TCP sendto naming a host nothing connected to, on a socket connected to the echo server at port (one the other checks
// leave alone, so the lines they assert stay one per destination); a seqpacket record
// past sendBytes naming the foreign socket under dir, to the pair's own peer, which reads the sender's pid in
// SCM_CREDENTIALS; and a unix stream sendto naming it, which the kernel answers EISCONN.
func namedOnConnectedChecks(dir string, port int) []checkResult {
	var out []checkResult
	add := func(name string, err error, n int, s string) {
		out = append(out, checkResult{Name: name, Err: errText(err), N: n, Out: s})
	}
	foreign := &unix.SockaddrUnix{Name: filepath.Join(dir, "u.sock")}
	if fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); err == nil {
		err = unix.Connect(fd, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}})
		n := 0
		buf := make([]byte, 8)
		if err == nil {
			if err = unix.Sendto(fd, []byte("ping"), 0, &unix.SockaddrInet4{Port: 9, Addr: [4]byte{203, 0, 113, 9}}); err == nil {
				n, err = unix.Read(fd, buf)
			}
		}
		add("nonet_tcp_named", err, n, string(buf[:max(n, 0)]))
		_ = unix.Close(fd)
	}
	if pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0); err == nil {
		got, verdict := 0, ""
		err = unix.SetsockoptInt(pair[1], unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
		sent := 0
		if err == nil {
			sent, err = unix.SendmsgN(pair[0], make([]byte, namedSeqpacketRecord), nil, foreign, 0)
		}
		if err == nil {
			buf, oob := make([]byte, 2*namedSeqpacketRecord), make([]byte, unix.CmsgSpace(unix.SizeofUcred))
			var oobn int
			got, oobn, _, _, err = unix.Recvmsg(pair[1], buf, oob, 0)
			verdict = "sent=" + strconv.Itoa(sent) + " no credentials"
			if msgs, perr := unix.ParseSocketControlMessage(oob[:max(oobn, 0)]); perr == nil && len(msgs) == 1 {
				if cred, cerr := unix.ParseUnixCredentials(&msgs[0]); cerr == nil {
					verdict = "sent=" + strconv.Itoa(sent) + " pid=" + strconv.Itoa(int(cred.Pid)) + " want " + strconv.Itoa(os.Getpid())
					if int(cred.Pid) == os.Getpid() && sent == namedSeqpacketRecord {
						verdict = "whole, sender's pid"
					}
				}
			}
		}
		add("nonet_seqpacket_named", err, got, verdict)
		_ = unix.Close(pair[0])
		_ = unix.Close(pair[1])
	}
	if pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); err == nil {
		add("nonet_stream_named", unix.Sendto(pair[0], []byte("x"), 0, foreign), 0, "")
		_ = unix.Close(pair[0])
		_ = unix.Close(pair[1])
	}
	// Interface enumeration: Go's net.Interfaces sends an RTM_GETLINK dump to the kernel on a NETLINK_ROUTE socket with
	// sendto, as glibc's getifaddrs and if_nameindex do.
	ifs, err := net.Interfaces()
	add("nonet_interfaces", err, len(ifs), "")
	return out
}

// TestIntegrationNoNetSection is SEMANTICS §1's "no net:" with host_sockets: true on a real kernel (ADR 0070's
// opt-out, the reach every such contract had before it): the loop leaves every connect to the kernel, so the
// target's own Landlock domain still decides the one thing it scopes. The relay the loop used to make ran in this
// process, outside that domain, and connected the target to an abstract name its scope refuses; now the connect is
// the target's own, refused EPERM, and nothing reaches the listener. A pathname socket and an undeclared host,
// which nothing refuses, complete as the target's own connects, and each is recorded allow with best_effort.
func TestIntegrationNoNetSection(t *testing.T) {
	name := "tego-sup-nonet-" + strconv.Itoa(os.Getpid())
	ln, err := net.Listen("unix", "@"+name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	h := startHarnessWith(t, harnessOpts{mode: modeNoNet, env: []string{helperAbstract + "=" + name}, hostSockets: true})
	h.stop(t)

	if c := h.check(t, "nonet_abstract"); !isErrno(c.Err, unix.EPERM) {
		t.Errorf("abstract connect outside the domain = %q, want EPERM from the target's own scope", c.Err)
	}
	if n := accepted.Load(); n != 0 {
		t.Errorf("the listener outside the domain accepted %d connection(s), want none", n)
	}
	if c := h.check(t, "nonet_unix"); c.Err != "" {
		t.Errorf("pathname socket under the write directory = %q, want success", c.Err)
	}
	if c := h.check(t, "nonet_inet_payload"); c.Err != "" || c.Out != "pong" {
		t.Errorf("undeclared host = %+v, want the target's own connect carrying pong", c)
	}
	for _, want := range []struct{ dst, rule string }{
		{"unix:@" + name, ruleUnmatched},
		{"unix:" + filepath.Join(h.dir, "u.sock"), "fs.write[" + h.dir + "]"},
		{"127.0.0.1:" + strconv.Itoa(h.deniedPort), ruleUnmatched},
	} {
		evs := h.netEvents(t, want.dst)
		if len(evs) != 1 {
			t.Errorf("%s: %d net events, want one", want.dst, len(evs))
			continue
		}
		var p netPayload
		if err := evs[0].DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if evs[0].Verdict != record.VerdictAllow || evs[0].Rule != want.rule || !p.BestEffort {
			t.Errorf("%s: event %s/%s best_effort=%v, want allow/%s best_effort", want.dst, evs[0].Verdict, evs[0].Rule, p.BestEffort, want.rule)
		}
	}
}

// TestIntegrationUnixOnlyState is SEMANTICS §1's "no net:" row without host_sockets: true on a real kernel (ADR
// 0070): the loop relays every connect on its duplicate, so a unix socket no process of the run bound is refused
// host-sockets, an abstract one bound outside the domain and a pathname one the test process bound under the write
// directory alike, and nothing reaches the abstract listener; the sockets the target bound itself are reached, a
// pathname one admitted by the write entry and an abstract one because a socket of the run holds the name; and an IP destination no entry names is relayed and carries the payload, its line
// allow and not best effort, since the relay connected the address the loop decided.
func TestIntegrationUnixOnlyState(t *testing.T) {
	name := "tego-sup-unixonly-" + strconv.Itoa(os.Getpid())
	ln, err := net.Listen("unix", "@"+name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	h := startHarnessWith(t, harnessOpts{mode: modeNoNet, env: []string{helperAbstract + "=" + name, helperScopeOptional + "=1"}})
	h.stop(t)

	for _, foreign := range []string{"nonet_abstract", "nonet_unix"} {
		if c := h.check(t, foreign); !isErrno(c.Err, refusalErrno) {
			t.Errorf("%s: a socket the run did not bind = %q, want %v", foreign, c.Err, refusalErrno)
		}
	}
	if n := accepted.Load(); n != 0 {
		t.Errorf("the abstract listener outside the run accepted %d connection(s), want none", n)
	}
	for _, own := range []string{"nonet_own", "nonet_own_abstract"} {
		if c := h.check(t, own); (c.Err == "") != UnixDiagAvailable() {
			t.Errorf("%s: the socket the target bound = %q, want success where sock_diag reads its origin", own, c.Err)
		}
	}
	if c := h.check(t, "nonet_inet_payload"); c.Err != "" || c.Out != "pong" {
		t.Errorf("undeclared host = %+v, want a relayed connect carrying pong", c)
	}
	// An addressed send on a connected socket goes where the kernel sends it, whatever it names: the
	// TCP bytes reach the peer and no line names the address; the seqpacket record arrives whole with the sender's pid;
	// the unix stream send gets the kernel's EISCONN. The foreign name both unix sends carry adds no line to the one
	// its connect wrote (the loop below).
	if c := h.check(t, "nonet_tcp_named"); c.Err != "" || c.Out != "pong" {
		t.Errorf("named sendto on a connected TCP socket = %+v, want pong from the peer", c)
	}
	if evs := h.netEvents(t, "203.0.113.9:9"); len(evs) != 0 {
		t.Errorf("%d net events name the address a connected TCP socket ignored (first %s), want none", len(evs), evs[0].Verdict)
	}
	if c := h.check(t, "nonet_seqpacket_named"); c.Err != "" || c.N != namedSeqpacketRecord || c.Out != "whole, sender's pid" {
		t.Errorf("named record on a connected seqpacket pair = %+v, want %d bytes with the sender's pid", c, namedSeqpacketRecord)
	}
	if c := h.check(t, "nonet_stream_named"); !isErrno(c.Err, unix.EISCONN) {
		t.Errorf("named sendto on a connected unix stream pair = %q, want EISCONN", c.Err)
	}
	// A route query to the kernel is relayed as the task and recorded allow, so interface enumeration works.
	if c := h.check(t, "nonet_interfaces"); c.Err != "" || c.N == 0 {
		t.Errorf("net.Interfaces = %+v, want the host's interfaces", c)
	}
	nl := h.netEvents(t, "family(16)")
	if len(nl) == 0 {
		t.Errorf("no net event for the route query, want an allow line")
	}
	for _, ev := range nl {
		var p netPayload
		if err := ev.DecodePayload(&p); err != nil || ev.Verdict != record.VerdictAllow || p.BestEffort {
			t.Errorf("route query: event %s/%s best_effort=%v, want allow and not best effort", ev.Verdict, ev.Rule, p.BestEffort)
		}
	}
	// Without sock_diag for AF_UNIX (a kernel without unix_diag) no abstract name's holder can be read, nor which
	// socket is bound to a file the run's own bind is recorded at: those are refused unix-origin-unread, the run's own
	// included (R11a). A pathname no recorded bind reaches is foreign for certain, and stays host-sockets.
	foreignAbstract, ownPath, own, ownAbstract := ruleHostSockets, "fs.write["+h.dir+"]", record.VerdictAllow, ruleUnmatched
	if !UnixDiagAvailable() {
		foreignAbstract, ownPath, own, ownAbstract = ruleUnixOriginUnread, ruleUnixOriginUnread, record.VerdictRefused, ruleUnixOriginUnread
	}
	for _, want := range []struct {
		dst     string
		verdict record.Verdict
		rule    string
	}{
		{"unix:@" + name, record.VerdictRefused, foreignAbstract},
		{"unix:" + filepath.Join(h.dir, "u.sock"), record.VerdictRefused, ruleHostSockets},
		{"unix:" + filepath.Join(h.dir, "own.sock"), own, ownPath},
		{"unix:@" + name + "-own", own, ownAbstract},
		{"127.0.0.1:" + strconv.Itoa(h.deniedPort), record.VerdictAllow, ruleUnmatched},
	} {
		evs := h.netEvents(t, want.dst)
		if len(evs) != 1 {
			t.Errorf("%s: %d net events, want one", want.dst, len(evs))
			continue
		}
		var p netPayload
		if err := evs[0].DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if evs[0].Verdict != want.verdict || evs[0].Rule != want.rule || p.BestEffort {
			t.Errorf("%s: event %s/%s best_effort=%v, want %s/%s and not best effort", want.dst, evs[0].Verdict, evs[0].Rule,
				p.BestEffort, want.verdict, want.rule)
		}
	}
}
