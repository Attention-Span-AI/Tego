// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/deputy"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The integration suite re-executes the test binary as the target (§10): the target installs the real
// tier-1 seccomp filter that internal/runtime/enforce/landlock builds, hands its listener fd number to
// the parent over a pipe, and blocks for an ack while the parent duplicates the listener with
// pidfd_getfd exactly as launch.Child.WaitNotifyFD does and starts a real Loop over it. It runs
// unprivileged on this box (uid 1000, no_new_privs, CGO_ENABLED=0).
//
// The landlock import is test-only: the package itself never imports an enforce backend (§1), it consumes
// the filter that backend installs.
const (
	helperEnv   = "TEGO_SUPERVISOR_TARGET"
	helperDir   = "TEGO_SUPERVISOR_DIR"
	helperPorts = "TEGO_SUPERVISOR_PORTS"
	helperLoops = "TEGO_SUPERVISOR_LOOPS"
	// helperMode picks the target's checks and the parent's policy; "" is the declared-net harness.
	helperMode = "TEGO_SUPERVISOR_MODE"

	fdHandoff = 3 // the target's write end of the fd-number pipe
	fdAck     = 4 // the target's read end of the ack pipe

	// resolverAddr is the systemd-resolved stub every Ubuntu box puts in /etc/resolv.conf. Nothing needs
	// to listen on it: a UDP connect only sets the peer address, which is exactly the decision path R13a
	// describes for glibc's resolver.
	resolverAddr = "127.0.0.53:53"

	helperTimeout = 60 * time.Second
)

// checkResult is one syscall the target made under the filter.
type checkResult struct {
	Name string `json:"name"`
	Err  string `json:"err,omitempty"`
	N    int    `json:"n,omitempty"`
	Out  string `json:"out,omitempty"`
}

// targetReport is what the target prints on stdout.
type targetReport struct {
	Checks  []checkResult `json:"checks"`
	Skip    string        `json:"skip,omitempty"`
	LoopNS  int64         `json:"loop_ns,omitempty"`
	LoopOps int           `json:"loop_ops,omitempty"`
}

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) != "" {
		os.Exit(targetMain())
	}
	if args := os.Getenv(helperDeputyMain); args != "" {
		os.Exit(deputy.Main(strings.Fields(args), DeputyPinner()))
	}
	// The same leak gate as the unit build's TestMain (leakcheck_test.go).
	os.Exit(testutil.LeakCheckMain(m))
}

// targetMain is the filtered process: it installs the filter on its locked thread, publishes the listener
// fd number, waits for the supervisor and then makes one syscall per check.
func targetMain() int {
	runtime.LockOSThread()
	rep := targetReport{}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		rep.Skip = "prctl(NO_NEW_PRIVS): " + err.Error()
		return emitReport(rep)
	}
	if err := sys.CheckSeccompNotifLayout(); err != nil {
		rep.Skip = err.Error()
		return emitReport(rep)
	}
	mode := os.Getenv(helperMode)
	// Bind mounts the target makes in its own mount namespace (harnessOpts.mountNS), before the filter, which
	// would otherwise refuse the mount (R31).
	for _, kv := range splitComma(inHarnessDir(os.Getenv(helperBinds))) {
		if kv == "" {
			continue
		}
		src, dst, _ := strings.Cut(kv, "=")
		if err := unix.Mount(src, dst, "", unix.MS_BIND, ""); err != nil {
			rep.Skip = "bind mount " + kv + ": " + err.Error()
			return emitReport(rep)
		}
	}
	if mode == modeNoNet || mode == modeUnixDgram {
		// A unix-only test runs without the scope where the kernel has none (below ABI 6, where ADR 0070's abstract
		// refusal rests on the supervisor alone); a test of the opt-out needs it, since the scope is what refuses there.
		if skip := restrictAbstractScope(); skip != "" && (os.Getenv(helperScopeOptional) == "" || !strings.Contains(skip, "needs 6")) {
			rep.Skip = skip
			return emitReport(rep)
		}
	}
	// modeExec installs the memfd_create arm (SEMANTICS §4) Prepare installs for a run with an exec: section on this
	// kernel, beside the fs, net and exec arms (not the per-kernel signal or per-tier arms, BuildFilterMemfd): the sealing arm where the kernel
	// honours MFD_NOEXEC_SEAL, the refusing arm below 6.3. modeExecWalk installs no arm, standing in for an
	// anonymous image that reached the run by another route (a descriptor over SCM_RIGHTS or inherited at
	// launch), which only the supervisor's walk decides. Every other mode installs the plain filter.
	arm := landlock.MemfdOpen
	if mode == modeExec {
		arm = landlock.MemfdRefused
		if landlock.MemfdNoexecSealSupported() {
			arm = landlock.MemfdSealed
		}
	}
	// The open deputy, when the harness passes one: started here, after any Landlock domain and before the filter, as
	// the child stage starts it (launch.spawnDeputy).
	if fd := os.Getenv(helperDeputyFD); fd != "" {
		if skip := spawnTestDeputy(fd); skip != "" {
			rep.Skip = skip
			return emitReport(rep)
		}
	}
	build := func() ([]bpf.Instruction, error) {
		return landlock.BuildFilterMemfd(landlock.NativeArch(), mode == modeBenchOps, arm)
	}
	if mode == modeGateChmod || mode == modeGateChmodOff {
		// The filter of a run whose gate scores fs.write, under record: summary or off (ADR 0041 Step 2).
		build = func() ([]bpf.Instruction, error) { return landlock.BuildFilterWriteGate(landlock.NativeArch(), false) }
	}
	if mode == modeGateReadWrite {
		// The filter of a run whose gate scores fs.read only, under record: summary (gate.md R1).
		build = func() ([]bpf.Instruction, error) { return landlock.BuildFilterReadGate(landlock.NativeArch(), false) }
	}
	insts, err := build()
	if g := os.Getenv(helperFilterGate); g != "" {
		insts, err = landlock.BuildFilterGate(landlock.NativeArch(), strings.Contains(g, "r"), strings.Contains(g, "w"))
	}
	if err != nil {
		rep.Skip = "BuildFilter: " + err.Error()
		return emitReport(rep)
	}
	raw, err := bpf.Assemble(insts)
	if err != nil {
		rep.Skip = "assemble: " + err.Error()
		return emitReport(rep)
	}
	install := sys.SeccompSetFilterNewListener
	if os.Getenv(helperFilterGate) != "" {
		// A gate harness's target runs opens on several threads, as an agent does: every thread carries the filter
		// (an agent's do, from its first execve).
		install = installTSyncListener
	}
	fd, err := install(raw)
	if err != nil {
		rep.Skip = "seccomp(NEW_LISTENER): " + err.Error()
		return emitReport(rep)
	}
	var num [4]byte
	binary.LittleEndian.PutUint32(num[:], uint32(fd))
	if _, err := unix.Write(fdHandoff, num[:]); err != nil {
		return 2
	}
	var ack [1]byte
	if _, err := unix.Read(fdAck, ack[:]); err != nil {
		return 3
	}
	switch mode {
	case modeNoNet:
		rep.Checks = noNetChecks()
		return emitReport(rep)
	case modeUnixDgram:
		rep.Checks = unixDgramChecks()
		return emitReport(rep)
	case modeUnixRelay:
		rep.Checks = unixRelayChecks()
		return emitReport(rep)
	case modeGuard:
		rep.Checks = guardChecks()
		return emitReport(rep)
	case modeGateRace:
		rep.Checks = gateRaceChecks()
		return emitReport(rep)
	case modeUnixRace:
		rep.Checks = unixRaceChecks()
		return emitReport(rep)
	case modeExec, modeExecWalk:
		rep.Checks = execChecks(arm)
		return emitReport(rep)
	case modeDenyWrite, modeDenyWriteOff:
		rep.Checks = denyWriteChecks()
		return emitReport(rep)
	case modeGateChmod, modeGateChmodOff:
		rep.Checks = gateChmodChecks()
		return emitReport(rep)
	case modeGateReadWrite:
		rep.Checks = gateReadWriteChecks()
		return emitReport(rep)
	case modeBench:
		rep.LoopOps, rep.LoopNS = targetLoop()
		return emitReport(rep)
	case modeBenchOps:
		rep.LoopOps, rep.LoopNS = targetOpLoop()
		return emitReport(rep)
	case modeBenchDgram, modeBenchDgramGuard, modeBenchNoNetDgram:
		rep.LoopOps, rep.LoopNS = targetDgramLoop()
		return emitReport(rep)
	case modeBenchNoNetConnect:
		rep.LoopOps, rep.LoopNS = targetConnectLoop()
		return emitReport(rep)
	case modeHeld:
		rep.Checks = heldChecks()
		return emitReport(rep)
	case modeHeldRace:
		rep.Checks = heldRaceChecks()
		return emitReport(rep)
	case modeHeldReadRace:
		rep.Checks = heldReadRaceChecks()
		return emitReport(rep)
	case modeBenchHeld:
		rep.Checks = heldBenchLoop()
		return emitReport(rep)
	}
	rep.Checks = targetChecks()
	rep.LoopOps, rep.LoopNS = targetLoop()
	return emitReport(rep)
}

// mmsghdr is struct mmsghdr, which x/sys does not define: a msghdr and the byte count the kernel writes
// back, padded to 64 bytes on both supported architectures.
type mmsghdr struct {
	hdr unix.Msghdr
	n   uint32
	_   [4]byte
}

// sendMMsgTail sends one sendmmsg batch of head+1 one-byte datagrams on a fresh UDP socket: the first
// head to 127.0.0.1:port as AF_INET, the last to the same address behind an AF_UNSPEC family word.
func sendMMsgTail(port, head int) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd) //nolint:errcheck // a test socket
	inet := make([]byte, 16)
	inet[0] = unix.AF_INET
	inet[2], inet[3] = byte(port>>8), byte(port)
	copy(inet[4:], []byte{127, 0, 0, 1})
	unspec := append([]byte(nil), inet...)
	unspec[0] = unix.AF_UNSPEC
	payload := []byte("m")
	iov := &unix.Iovec{Base: &payload[0], Len: 1}
	msgs := make([]mmsghdr, head+1)
	for i := range msgs {
		name := inet
		if i == head {
			name = unspec
		}
		msgs[i].hdr = unix.Msghdr{Name: &name[0], Namelen: uint32(len(name)), Iov: iov, Iovlen: 1}
	}
	_, _, e := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(fd), uintptr(unsafe.Pointer(&msgs[0])), uintptr(len(msgs)), 0, 0, 0)
	runtime.KeepAlive(msgs)
	runtime.KeepAlive(iov)
	runtime.KeepAlive(payload)
	runtime.KeepAlive(inet)
	runtime.KeepAlive(unspec)
	if e != 0 {
		return e
	}
	return nil
}

// sendMMsgConnectedTail sends one sendmmsg batch on a UDP socket connected to a receiver on the declared
// port: mmsgMessages one-byte datagrams with no address, then one addressed as AF_INET to a second
// receiver on a port nothing declares. It reports the call's count, the datagrams each receiver got and
// the second receiver's port.
func sendMMsgConnectedTail(declared int) (sent, peer, other, otherPort int, err error) {
	receiver := func(port int) (int, int, error) {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
		if err != nil {
			return -1, 0, err
		}
		if err := unix.Bind(fd, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
			_ = unix.Close(fd)
			return -1, 0, err
		}
		sa, err := unix.Getsockname(fd)
		if err != nil {
			_ = unix.Close(fd)
			return -1, 0, err
		}
		return fd, sa.(*unix.SockaddrInet4).Port, nil
	}
	drain := func(fd int) int {
		got := 0
		buf := make([]byte, 4)
		for {
			if _, _, err := unix.Recvfrom(fd, buf, 0); err != nil {
				return got
			}
			got++
		}
	}
	pfd, _, err := receiver(declared)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	defer unix.Close(pfd) //nolint:errcheck // a test socket
	ofd, otherPort, err := receiver(0)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	defer unix.Close(ofd) //nolint:errcheck // a test socket
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	defer unix.Close(fd) //nolint:errcheck // a test socket
	if err := unix.Connect(fd, &unix.SockaddrInet4{Port: declared, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		return 0, 0, 0, 0, err
	}
	name := make([]byte, 16)
	name[0] = unix.AF_INET
	name[2], name[3] = byte(otherPort>>8), byte(otherPort)
	copy(name[4:], []byte{127, 0, 0, 1})
	payload := []byte("t")
	iov := &unix.Iovec{Base: &payload[0], Len: 1}
	msgs := make([]mmsghdr, mmsgMessages+1)
	for i := range msgs {
		msgs[i].hdr = unix.Msghdr{Iov: iov, Iovlen: 1}
	}
	msgs[mmsgMessages].hdr.Name, msgs[mmsgMessages].hdr.Namelen = &name[0], uint32(len(name))
	r, _, e := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(fd), uintptr(unsafe.Pointer(&msgs[0])), uintptr(len(msgs)), 0, 0, 0)
	runtime.KeepAlive(msgs)
	runtime.KeepAlive(iov)
	runtime.KeepAlive(payload)
	runtime.KeepAlive(name)
	if e != 0 {
		return 0, 0, 0, otherPort, e
	}
	return int(r), drain(pfd), drain(ofd), otherPort, nil
}

// targetChecks makes one syscall per behaviour the suite asserts, all on the filtered thread.
func targetChecks() []checkResult {
	dir := os.Getenv(helperDir)
	ports := splitPorts(os.Getenv(helperPorts))
	var out []checkResult
	add := func(name string, err error, n int, s string) {
		out = append(out, checkResult{Name: name, Err: errText(err), N: n, Out: s})
	}

	// Allowed host: the supervisor performs the connect on a duplicate, so the socket really is connected
	// and the payload flows (R9, I3).
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		err = unix.Connect(fd, &unix.SockaddrInet4{Port: ports[0], Addr: [4]byte{127, 0, 0, 1}})
		if err == nil {
			if _, werr := unix.Write(fd, []byte("ping")); werr != nil {
				err = werr
			} else {
				buf := make([]byte, 8)
				n, rerr := unix.Read(fd, buf)
				err = rerr
				add("allowed_connect_payload", err, n, string(buf[:max(n, 0)]))
			}
		}
		_ = unix.Close(fd)
	}
	add("allowed_connect", err, 0, "")

	// Undeclared host: refused before any packet leaves (R10).
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		err = unix.Connect(fd, &unix.SockaddrInet4{Port: ports[1], Addr: [4]byte{127, 0, 0, 1}})
		_ = unix.Close(fd)
	}
	add("undeclared_connect", err, 0, "")

	// MSG_FASTOPEN on a socket that already has a peer: the kernel answers EISCONN while the peer stays,
	// but connects to the send's own address once a sibling has dissolved the association, so this tier
	// decides it as R12 instead of continuing it (R13a). The undeclared address is refused before the
	// kernel sees it; the declared one is relayed and gets the kernel's own EISCONN back.
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		err = unix.Connect(fd, &unix.SockaddrInet4{Port: ports[0], Addr: [4]byte{127, 0, 0, 1}})
		if err == nil {
			undeclared := unix.Sendto(fd, []byte("x"), unix.MSG_FASTOPEN, &unix.SockaddrInet4{Port: 9, Addr: [4]byte{127, 0, 0, 3}})
			add("fastopen_connected_undeclared", undeclared, 0, "")
			declared := unix.Sendto(fd, []byte("x"), unix.MSG_FASTOPEN, &unix.SockaddrInet4{Port: ports[0], Addr: [4]byte{127, 0, 0, 1}})
			add("fastopen_connected_declared", declared, 0, "")
		}
		_ = unix.Close(fd)
	}
	if err != nil {
		add("fastopen_connected_undeclared", err, 0, "")
		add("fastopen_connected_declared", err, 0, "")
	}

	// The resolver on UDP 53: allowed by R14 without a net.allow entry.
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		err = unix.Connect(fd, &unix.SockaddrInet4{Port: 53, Addr: [4]byte{127, 0, 0, 53}})
		_ = unix.Close(fd)
	}
	add("resolver_udp_connect", err, 0, "")

	// An unconnected datagram send to the resolver: read, matched, then continued (R13b).
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		err = unix.Sendto(fd, []byte{0, 1, 0, 0}, 0, &unix.SockaddrInet4{Port: 53, Addr: [4]byte{127, 0, 0, 53}})
		_ = unix.Close(fd)
	}
	add("resolver_udp_sendto", err, 0, "")

	// An undeclared datagram send: refused before the data leaves (R13b as amended 2026-10-16).
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		err = unix.Sendto(fd, []byte("x"), 0, &unix.SockaddrInet4{Port: 9, Addr: [4]byte{203, 0, 113, 9}})
		_ = unix.Close(fd)
	}
	add("undeclared_udp_sendto", err, 0, "")

	// An AF_UNSPEC datagram whose family word is followed by a real sockaddr_in naming this target's own
	// UDP socket. udp_sendmsg sends it there as if it were AF_INET, so whether it arrives is exactly what a
	// CONTINUE would have let out; this tier refuses it instead (R4, R13b). x/sys has no Sockaddr for
	// AF_UNSPEC, hence the raw sendto.
	rfd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err == nil {
		err = unix.Bind(rfd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}})
	}
	var bound unix.Sockaddr
	if err == nil {
		bound, err = unix.Getsockname(rfd)
	}
	if err == nil {
		port := bound.(*unix.SockaddrInet4).Port
		sa := [16]byte{0, 0, byte(port >> 8), byte(port), 127, 0, 0, 1} // sa_family = AF_UNSPEC
		msg := []byte("u")
		fd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err == nil {
			_, _, e := unix.Syscall6(unix.SYS_SENDTO, uintptr(fd), uintptr(unsafe.Pointer(&msg[0])), uintptr(len(msg)),
				0, uintptr(unsafe.Pointer(&sa[0])), uintptr(len(sa)))
			if e != 0 {
				err = e
			}
			_ = unix.Close(fd)
		}
		add("unspec_udp_sendto", err, 0, "")
		buf := make([]byte, 4)
		n, _, rerr := unix.Recvfrom(rfd, buf, 0)
		add("unspec_udp_arrived", rerr, n, "")

		// The same AF_UNSPEC address as the 65th message of a sendmmsg batch whose first 64 name the
		// receiver as AF_INET: the kernel sends every message up to UIO_MAXIOV, so a handler that read
		// only the 64 it records let the 65th out undecided (R13b). Out carries the receiver's port, which
		// is the dst the 64 recorded lines name.
		err = sendMMsgTail(port, mmsgMessages)
		add("unspec_udp_sendmmsg_tail", err, 0, strconv.Itoa(port))
		got := 0
		for {
			_, _, rerr := unix.Recvfrom(rfd, buf, 0)
			if rerr != nil {
				if got == 0 {
					add("unspec_udp_sendmmsg_arrived", rerr, 0, "")
				} else {
					add("unspec_udp_sendmmsg_arrived", nil, got, "")
				}
				break
			}
			got++
		}
	} else {
		add("unspec_udp_sendto", err, 0, "")
	}
	if rfd >= 0 {
		_ = unix.Close(rfd)
	}

	// A connected UDP socket's batch whose only address lies past the 64th message: the kernel sends the
	// unaddressed messages to the peer and the addressed one to its own msg_name, a host nothing declares.
	// The first 64 carry nothing to record, and that host refuses the whole batch (R13b as amended
	// 2026-10-16). Out carries that host's port.
	sent, peer, other, otherPort, err := sendMMsgConnectedTail(ports[0])
	add("tail_udp_sendmmsg", err, sent, strconv.Itoa(otherPort))
	add("tail_udp_sendmmsg_peer", nil, peer, "")
	add("tail_udp_sendmmsg_other", nil, other, "")

	// execve of a path that does not exist: a miss, which the loop answers with the ENOENT its walk met — the errno
	// the kernel's own lookup would give — and writes no line for (R16b (0)), so the process survives to report.
	err = unix.Exec("/nonexistent/tego-integration", []string{"tego-argv-0", "--flag", "value"}, os.Environ())
	add("execve_missing", err, 0, "")
	// execve of a file that exists and that the kernel refuses (no execute bit): its argv is recorded (R16), and the
	// process survives the kernel's EACCES.
	noexec := filepath.Join(dir, "noexec")
	err = os.WriteFile(noexec, []byte("x"), 0o644)
	if err == nil {
		err = unix.Exec(noexec, []string{"tego-argv-0", "--flag", "value"}, os.Environ())
	}
	add("execve_recorded", err, 0, "")

	// A write-open and a mkdir inside a declared write directory: recorded, continued, and really done.
	wfd, err := unix.Open(filepath.Join(dir, "out.txt"), unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC, 0o600)
	if err == nil {
		_ = unix.Close(wfd)
	}
	add("write_open_inside", err, 0, "")
	add("mkdir_inside", unix.Mkdirat(unix.AT_FDCWD, filepath.Join(dir, "sub"), 0o755), 0, "")

	// A relative write-open through AT_FDCWD: the path is resolved against /proc/<pid>/cwd (R6, E7).
	if err := unix.Chdir(dir); err == nil {
		wfd, err = unix.Open("relative.txt", unix.O_WRONLY|unix.O_CREAT|unix.O_CLOEXEC, 0o600)
		if err == nil {
			_ = unix.Close(wfd)
		}
	}
	add("relative_open", err, 0, "")

	// A relative unix connect from inside dir: decided as dir/u.sock, which the contract declares, and relayed
	// from the supervisor, whose cwd is not dir. Relaying the
	// relative bytes connected to u.sock in the test process's own directory, where nothing listens; the
	// relay walks the name from the target's own cwd instead (R11).
	fd, err = unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		err = unix.Connect(fd, &unix.SockaddrUnix{Name: "u.sock"})
		_ = unix.Close(fd)
	}
	add("relative_unix_connect", err, 0, "")

	// The mount family: the domain refuses it, and the supervisor answers with the same EPERM and records
	// the refusal and the landlock-topology gap (R31).
	add("mount_refused", unix.Mount("none", filepath.Join(dir, "sub"), "tmpfs", 0, ""), 0, "")

	// TCP Fast Open: an addressed send on a stream socket is decided like a connect and, when allowed,
	// relayed on the duplicate. The loopback listener does not advertise TFO, so the kernel's own answer
	// is what comes back — the point is that the decision and the relay happened at all (R12, I3).
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		n, serr := unix.SendmsgN(fd, []byte("ping"), nil, &unix.SockaddrInet4{
			Port: ports[0], Addr: [4]byte{127, 0, 0, 1},
		}, unix.MSG_FASTOPEN)
		add("fastopen_allowed", serr, n, "")
		_ = unix.Close(fd)
	}

	// The same send to an undeclared host is refused before a byte leaves (R12).
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		_, serr := unix.SendmsgN(fd, []byte("ping"), nil, &unix.SockaddrInet4{
			Port: ports[1], Addr: [4]byte{127, 0, 0, 1},
		}, unix.MSG_FASTOPEN)
		add("fastopen_refused", serr, 0, "")
		_ = unix.Close(fd)
	}

	// A write-open outside every declared entry: this tier records it refused and continues it; Landlock,
	// not the supervisor, is what would stop it in a real run (R15, P0-DESIGN §4.3).
	wfd, err = unix.Open(filepath.Join(dir, "..", "outside.txt"), unix.O_WRONLY|unix.O_CREAT|unix.O_CLOEXEC, 0o600)
	if err == nil {
		_ = unix.Close(wfd)
	}
	add("write_open_outside", err, 0, "")
	return out
}

// targetLoop times the record-and-continue fast path over the real ioctl round trip.
func targetLoop() (int, int64) {
	n, err := strconv.Atoi(os.Getenv(helperLoops))
	if err != nil || n <= 0 {
		return 0, 0
	}
	dir := os.Getenv(helperDir)
	path := filepath.Join(dir, "sub") // already exists: the syscall fails EEXIST after being notified
	slow := injectedSlowdown()
	start := time.Now()
	for i := 0; i < n; i++ {
		if slow > 0 {
			spin(slow)
		}
		_ = unix.Mkdirat(unix.AT_FDCWD, path, 0o755)
	}
	return n, time.Since(start).Nanoseconds()
}

// emitReport prints the target's report.
func emitReport(r targetReport) int {
	b, err := json.Marshal(r)
	if err != nil {
		return 4
	}
	if _, err := unix.Write(1, append(b, '\n')); err != nil {
		return 5
	}
	return 0
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func splitPorts(s string) []int {
	out := []int{0, 0}
	for i, f := range splitComma(s) {
		if i >= len(out) {
			break
		}
		out[i], _ = strconv.Atoi(f)
	}
	return out
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == ',' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(c)
	}
	return append(out, cur)
}

// harness is one started target with the supervisor already draining its listener.
type harness struct {
	loop        *Loop
	sink        *testSink
	dir         string
	allowedPort int
	deniedPort  int
	report      targetReport
	// runErr is what Run returned, and selfStopped says it returned on its own — the listener hung up
	// when the target exited — rather than because the harness cancelled it.
	runErr      error
	selfStopped bool
}

// startHarness installs the filter in a target process, duplicates its listener into this one and runs a
// real Loop over it, exactly as runtime.Run does at step 7 of docs/p0/runtime-launch.md.
func startHarness(t *testing.T, loops int) *harness {
	t.Helper()
	return startHarnessMode(t, loops, "", nil)
}

// startHarnessMode is startHarness for one target mode: mode goes to the target, env is added to its
// environment, and modeNoNet runs the loop over a contract with no net: section.
func startHarnessMode(t *testing.T, loops int, mode string, env []string) *harness {
	t.Helper()
	return startHarnessWith(t, harnessOpts{loops: loops, mode: mode, env: env})
}

// harnessOpts are startHarnessWith's knobs. as runs the target under other credentials, which needs root
// here and leaves the target's directory and its socket open to it; declared are the unix: entries a
// modeUnixRelay loop admits besides the write directory; prepare runs on the target's directory before
// the target starts.
type harnessOpts struct {
	loops    int
	mode     string
	env      []string
	as       *syscall.Credential
	declared []string
	prepare  func(dir string)
	// mountNS starts the target in a mount namespace of its own (root only); helperBinds then names the
	// bind mounts it makes there before it installs the filter.
	mountNS bool
	// gate is the scored gate the loop's contract carries (gate.md), nil for none.
	gate *gate.Policy
	// live is the loop's Options.LiveBlocks, nil for none.
	live func() *liveblock.Set
	// kernel is the loop's Options.KernelDatagrams: the run's kernel programs a datagram's refusal stands for.
	kernel KernelDatagrams
	// timeout is how long the target may run before it is killed; 0 is helperTimeout. A test that holds the
	// target's own time to a bound longer than that gives it more, so that its bound is what fails.
	timeout time.Duration
	// outOfTime, when set, is called with the time since the ack released the target when the target was killed
	// at the timeout before it reported, before the harness fails the test for the missing report: a test that
	// holds the target's time to a bound judges that time there, so that a target too slow to finish at all fails
	// on the bound's own message, never only on the report the kill cut off.
	outOfTime func(t testing.TB, ran time.Duration)
	// deputy starts an open deputy in the target before its filter, and hands the loop its client (ADR 0041 Stage B).
	deputy bool
	// filterGate installs the gate arms of the filter instead of the plain one: "r" for a read gate, "w" for a write
	// gate, "rw" for both.
	filterGate string
	// hostSockets sets host_sockets: true in modeNoNet's, modeUnixDgram's and modeGateRace's contract with no net:
	// section, the opt-out that restores the host's unix sockets (ADR 0070); without it the loop runs in the
	// unix-only state, which reaches only the run's own unix sockets.
	hostSockets bool
	// record is the loop's record mode; "" is summary.
	record agent.RecordMode
	// workers is the loop's pool size; 0 is 4.
	workers int
	// tier is the table's tier, "" for the mode's own: a root tier's held open waits for this loop's checks before the
	// deputy opens (heldOpen).
	tier backend.Tier
	// acked runs just before the ack releases the target and reported just after its report arrives: the
	// span between them is the target's own work under the filter and the loop's answers to it, which is
	// what BenchmarkSeccompNotifyRoundTrip times.
	acked, reported func()
	// rules, when set, adjusts the loop's table once the mode built it: a held-reads run's fs.reads (ADR 0069).
	rules func(rt *agent.RuleTable, dir string)
}

// startHarnessWith is startHarness with every option.
func startHarnessWith(t testing.TB, o harnessOpts) *harness {
	t.Helper()
	loops, mode, env := o.loops, o.mode, o.env
	if err := sys.CheckSeccompNotifLayout(); err != nil {
		t.Skipf("seccomp notification unavailable: %v", err)
	}
	// The test binary the target re-executes, made absolute before prepare, which may change this process's cwd.
	self, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	// Not t.TempDir: its test-named path does not fit u.sock in sun_path (108 bytes) under a TMPDIR as long
	// as the house rules' on-disk one. The harness's own subdirectory, so that the chmod below never
	// reaches TMPDIR itself.
	dir := filepath.Join(shortTempDir(t), "h")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if o.as != nil {
		// dir and its parent are 0700 and root's: open the path to the target's uid.
		for _, d := range []string{filepath.Dir(dir), dir} {
			if err := os.Chmod(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	allowed, allowedPort := echoServer(t)
	_, deniedPort := echoServer(t)
	// The target's relative unix connect (relative_unix_connect) lands here only if the relay names the
	// path it was decided as.
	unixL, err := net.Listen("unix", filepath.Join(dir, "u.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unixL.Close() })
	if o.as != nil {
		if err := os.Chmod(filepath.Join(dir, "u.sock"), 0o777); err != nil {
			t.Fatal(err)
		}
	}
	if o.prepare != nil {
		o.prepare(dir)
	}
	go func() {
		for {
			c, err := unixL.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	handoffR, handoffW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer handoffW.Close() //nolint:errcheck // the child keeps its own copy
	ackR, ackW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer ackR.Close() //nolint:errcheck // the child keeps its own copy

	if o.as != nil {
		self = testutil.ExecutableForAnyUID(t) // the target runs as another uid
	}
	timeout := helperTimeout
	if o.timeout > 0 {
		timeout = o.timeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	cmd := exec.CommandContext(ctx, self, "-test.run=^$")
	cmd.Env = append(os.Environ(),
		helperEnv+"=1",
		helperDir+"="+dir,
		helperPorts+"="+strconv.Itoa(allowedPort)+","+strconv.Itoa(deniedPort),
		helperLoops+"="+strconv.Itoa(loops),
		helperMode+"="+mode,
	)
	cmd.Env = append(cmd.Env, env...)
	cmd.ExtraFiles = []*os.File{handoffW, ackR}
	deputyLauncher := -1
	if o.deputy {
		l, stage, err := deputy.Socketpair()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		deputyLauncher = l
		stageF := os.NewFile(uintptr(stage), "deputy-stage")
		defer stageF.Close() //nolint:errcheck // the target keeps its own copy
		cmd.ExtraFiles = append(cmd.ExtraFiles, stageF)
		cmd.Env = append(cmd.Env, helperDeputyFD+"="+strconv.Itoa(2+len(cmd.ExtraFiles)))
	}
	if o.filterGate != "" {
		cmd.Env = append(cmd.Env, helperFilterGate+"="+o.filterGate)
	}
	if o.as != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: o.as}
	}
	if o.mountNS {
		// The runtime makes the new namespace's mounts private before the exec, so the target's bind mounts
		// never reach this process's tree.
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		cmd.SysProcAttr.Unshareflags = syscall.CLONE_NEWNS
	}
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	// The target holds its own copy: once it exits without publishing a fd, the read below sees EOF at once.
	_ = handoffW.Close()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		cancel()
		_ = allowed.Close()
	})

	// The fd number arrives the way the child stage publishes it (runtime-launch R6), then pidfd_getfd
	// lifts the listener into this process: the agent never holds the supervisor's descriptor.
	if err := handoffR.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var num [4]byte
	if _, err := handoffR.Read(num[:]); err != nil {
		// A target that skip-reports before its filter (no scope below ABI 6, no NO_NEW_PRIVS) publishes no fd
		// and exits: its report says why, and the test skips on that reason instead of failing on the silence.
		_ = cmd.Process.Kill()
		var rep targetReport
		if json.NewDecoder(stdout).Decode(&rep) == nil && rep.Skip != "" {
			t.Skip(rep.Skip)
		}
		t.Fatalf("no listener fd from the target: %v", err)
	}
	childFD := int(binary.LittleEndian.Uint32(num[:]))
	// cmd.Process.Pid is a process id and this only feeds pidfd_getfd, which either scope satisfies:
	// process scope is the one that is always available, including below Linux 6.9.
	pidfd, err := sys.PidfdOpenProcess(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("pidfd_open: %v", err)
	}
	defer unix.Close(pidfd) //nolint:errcheck // closed once the duplicate is taken
	notifyFD, err := sys.Strict(sys.PidfdGetfdFD(pidfd, childFD))
	if err != nil {
		t.Fatalf("pidfd_getfd(listener): %v", err)
	}

	rules := []agent.NetRule{{
		Raw: "127.0.0.1:" + strconv.Itoa(allowedPort), Host: "127.0.0.1", Port: allowedPort,
		Proto: agent.ProtoInet, Verdict: agent.VerdictAllow, Static: true,
		IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	}}
	fs := []agent.FSRule{{Path: dir, Kind: agent.FSWrite}}
	set := dns.NewSet(rules, []netip.AddrPort{netip.MustParseAddrPort(resolverAddr)}, dns.Options{})
	// The harness's own u.sock is bound by this process, outside the target, so the write entry's implicit
	// admit does not reach it (R11a): the default contract names it, and relative_unix_connect is decided as the
	// entry's path and relayed to it.
	declaredSock := agent.NetRule{Raw: "unix:" + filepath.Join(dir, "u.sock"), Proto: agent.ProtoUnix,
		UnixPath: filepath.Join(dir, "u.sock"), Verdict: agent.VerdictAllow, Static: true}
	rt := &agent.RuleTable{Net: append(slices.Clone(rules), declaredSock), FS: fs, Record: agent.RecordSummary}
	switch mode {
	case modeNoNet, modeUnixDgram, modeGateRace, modeUnixRace, modeBenchNoNetDgram, modeBenchNoNetConnect:
		rt = &agent.RuleTable{FS: fs, Record: agent.RecordSummary, Tier: backend.TierLandlock,
			Contract: &agent.Contract{HostSockets: o.hostSockets}}
		set = dns.NewSet(nil, []netip.AddrPort{netip.MustParseAddrPort(resolverAddr)}, dns.Options{})
	case modeUnixRelay:
		var unixRules []agent.NetRule
		for _, p := range o.declared {
			unixRules = append(unixRules, agent.NetRule{
				Raw: "unix:" + p, Proto: agent.ProtoUnix, UnixPath: p, Verdict: agent.VerdictAllow, Static: true,
			})
		}
		fs[0].Resolved = dir
		rt = &agent.RuleTable{Net: unixRules, FS: fs, Record: agent.RecordSummary, Tier: backend.TierLandlock,
			Contract: &agent.Contract{Net: &agent.NetSection{}}}
		set = dns.NewSet(nil, []netip.AddrPort{netip.MustParseAddrPort(resolverAddr)}, dns.Options{})
	case modeGuard, modeBenchDgramGuard:
		// No net: section, capture: forwarder, and the allowed port's echo server standing in for the model.
		rt = &agent.RuleTable{FS: fs, Record: agent.RecordSummary, Tier: backend.TierLandlock, Capture: agent.CaptureForwarder,
			Contract: &agent.Contract{Models: []agent.ModelEndpoint{{Provider: "anthropic", Host: "127.0.0.1", Port: allowedPort}}}}
		set = dns.NewSet(nil, []netip.AddrPort{netip.MustParseAddrPort(resolverAddr)}, dns.Options{})
	case modeExec, modeExecWalk:
		rt = execRuleTable(fs, env)
	case modeDenyWrite, modeDenyWriteOff:
		rt = denyWriteRuleTable(dir, mode)
		set = dns.NewSet(nil, []netip.AddrPort{netip.MustParseAddrPort(resolverAddr)}, dns.Options{})
	case modeGateChmod, modeGateChmodOff:
		rt = gateChmodRuleTable(dir, mode)
		set = dns.NewSet(nil, []netip.AddrPort{netip.MustParseAddrPort(resolverAddr)}, dns.Options{})
	case modeGateReadWrite:
		rt = gateReadWriteRuleTable(dir)
		set = dns.NewSet(nil, []netip.AddrPort{netip.MustParseAddrPort(resolverAddr)}, dns.Options{})
	case modeHeld:
		rt.DenyWrite = heldDenyWrite(dir)
	case modeBenchOps:
		// record: full, as the filter the target installs is, at the tier that filter serves.
		rt = &agent.RuleTable{FS: fs, Record: agent.RecordFull, Tier: backend.TierLandlock, Contract: &agent.Contract{}}
		set = dns.NewSet(nil, []netip.AddrPort{netip.MustParseAddrPort(resolverAddr)}, dns.Options{})
	}
	rt.Gate = o.gate
	if o.tier != "" {
		rt.Tier = o.tier
	}
	if o.gate != nil && rt.Workdir == "" {
		rt.Workdir = dir // a gate scores the worktree the contract compiled in (gate.md)
	}
	if o.record != "" {
		rt.Record = o.record
	}
	if o.rules != nil {
		o.rules(rt, dir)
	}
	pol := &Policy{
		Rules:    rt,
		Resolver: set,
		RunID:    "2026-09-22T00-00-00Z-integ",
		Agent:    "claude-code",
	}
	sink := &testSink{}
	opts := Options{Workers: 4, KernelDatagrams: o.kernel, LiveBlocks: o.live}
	if o.workers > 0 {
		opts.Workers = o.workers
	}
	if deputyLauncher >= 0 {
		c, err := deputy.Hello(deputyLauncher, 20*time.Second)
		if err != nil {
			_ = unix.Close(deputyLauncher)
			t.Fatalf("deputy hello: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
		opts.Deputy = c
	}
	loop, err := New(notifyFD, pol, sink, opts)
	if err != nil {
		t.Fatal(err)
	}
	runCtx, runCancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- loop.Run(runCtx) }()

	if o.acked != nil {
		o.acked()
	}
	if _, err := ackW.Write([]byte{1}); err != nil {
		runCancel()
		t.Fatalf("ack: %v", err)
	}
	released := time.Now()
	_ = ackW.Close()

	var rep targetReport
	if err := json.NewDecoder(stdout).Decode(&rep); err != nil {
		runCancel()
		if ctx.Err() != nil {
			ran := time.Since(released)
			if o.outOfTime != nil {
				o.outOfTime(t, ran)
			}
			t.Fatalf("target report: %v (the target was still running %v after the ack and was killed at its %v "+
				"timeout)", err, ran.Round(time.Millisecond), timeout)
		}
		t.Fatalf("target report: %v", err)
	}
	if o.reported != nil {
		o.reported()
	}
	if err := cmd.Wait(); err != nil {
		t.Logf("target exited: %v", err)
	}
	// Wait for Run to finish before anything is asserted: a handler emits its event just after it answers
	// the notification, so the target can be gone while the last event is still in flight. Once the last
	// task carrying the filter has exited the listener hangs up and Run returns by itself; the cancel is
	// only the backstop.
	h := &harness{
		loop: loop, sink: sink, dir: dir, allowedPort: allowedPort, deniedPort: deniedPort, report: rep,
	}
	select {
	case err := <-done:
		h.runErr, h.selfStopped = err, true
	case <-time.After(10 * time.Second):
		runCancel()
		select {
		case h.runErr = <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("Run did not return after cancellation (E24)")
		}
	}
	runCancel()
	if rep.Skip != "" {
		t.Skip(rep.Skip)
	}
	return h
}

// stop checks how the loop ended and returns its metrics.
func (h *harness) stop(t testing.TB) Metrics {
	t.Helper()
	if h.runErr != nil {
		t.Fatalf("Run: %v", h.runErr)
	}
	return h.loop.Metrics()
}

// check finds one of the target's results.
func (h *harness) check(t *testing.T, name string) checkResult {
	t.Helper()
	for _, c := range h.report.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("the target did not report %q: %+v", name, h.report.Checks)
	return checkResult{}
}

// netEvents returns the net events whose destination matches dst.
func (h *harness) netEvents(t *testing.T, dst string) []*record.Event {
	t.Helper()
	var out []*record.Event
	for _, ev := range h.sink.all() {
		if ev.Kind != record.KindNet {
			continue
		}
		var p record.NetPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatalf("payload: %v", err)
		}
		if p.Dst == dst {
			out = append(out, ev)
		}
	}
	return out
}

// TestIntegrationSupervisor drives a real listener end to end: an allowed connect completes through the
// supervisor with its payload, an undeclared one is refused with a reason, the resolver is allowed on UDP,
// argv is recorded, and the advisory filesystem events carry the nearest-wins verdict.
func TestIntegrationSupervisor(t *testing.T) {
	h := startHarness(t, 0)

	t.Run("allowed connect completes", func(t *testing.T) {
		if c := h.check(t, "allowed_connect"); c.Err != "" {
			t.Fatalf("connect to the declared host failed: %s", c.Err)
		}
		c := h.check(t, "allowed_connect_payload")
		if c.Err != "" || c.Out != "pong" {
			t.Fatalf("payload check = %+v, want pong over the supervisor's own connect", c)
		}
		evs := h.netEvents(t, "127.0.0.1:"+portOf(t, h, 0))
		if len(evs) == 0 {
			t.Fatal("no net event for the allowed connect")
		}
		ev := evs[0]
		wantRule := "net[127.0.0.1:" + strconv.Itoa(h.allowedPort) + "]"
		if ev.Verdict != record.VerdictAllow || ev.Rule != wantRule || ev.Source != record.SourceSupervisor {
			t.Errorf("event = {%s %s %s}, want allow/%s/supervisor", ev.Verdict, ev.Rule, ev.Source, wantRule)
		}
		if err := ev.Validate(); err != nil {
			t.Errorf("event does not validate: %v", err)
		}
	})

	t.Run("undeclared connect is refused with a reason", func(t *testing.T) {
		c := h.check(t, "undeclared_connect")
		if !isErrno(c.Err, unix.EACCES) {
			t.Fatalf("connect error = %q, want EACCES (R10)", c.Err)
		}
		evs := h.netEvents(t, "127.0.0.1:"+portOf(t, h, 1))
		if len(evs) == 0 {
			t.Fatal("no net event for the refused connect")
		}
		ev := evs[0]
		if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonNetNotAllowed || ev.Rule != ruleUnmatched {
			t.Errorf("event = {%s %s %s}, want refused/net-not-allowed/unmatched", ev.Verdict, ev.Reason, ev.Rule)
		}
	})

	t.Run("resolver is allowed on udp 53", func(t *testing.T) {
		if c := h.check(t, "resolver_udp_connect"); c.Err != "" {
			t.Fatalf("connect to the resolver failed: %s", c.Err)
		}
		if c := h.check(t, "resolver_udp_sendto"); c.Err != "" {
			t.Fatalf("sendto the resolver failed: %s", c.Err)
		}
		evs := h.netEvents(t, resolverAddr)
		if len(evs) < 2 {
			t.Fatalf("resolver events = %d, want the connect and the send", len(evs))
		}
		for _, ev := range evs {
			if ev.Verdict != record.VerdictAllow || ev.Rule != ruleResolver {
				t.Errorf("event = {%s %s}, want allow/net.resolver (R14)", ev.Verdict, ev.Rule)
			}
			var p record.NetPayload
			_ = ev.DecodePayload(&p)
			if p.Proto != protoUDP {
				t.Errorf("proto = %s, want udp", p.Proto)
			}
		}
	})

	t.Run("undeclared datagram is refused", func(t *testing.T) {
		// R13b as amended 2026-10-16: a refusal needs no race, so the supervisor answers R10's
		// errno and nothing leaves. Continued, as before, the send was the kernel's to answer and the line said
		// refused with best_effort while the datagram went out.
		if c := h.check(t, "undeclared_udp_sendto"); !isErrno(c.Err, unix.EACCES) {
			t.Fatalf("sendto = %q, want EACCES: a datagram the policy refuses is refused (R13b)", c.Err)
		}
		evs := h.netEvents(t, "203.0.113.9:9")
		if len(evs) != 1 || evs[0].Verdict != record.VerdictRefused {
			t.Fatalf("events = %+v, want one refused record (R13b)", evs)
		}
		var p netPayload
		if err := evs[0].DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.BestEffort {
			t.Errorf("the refusal is marked best_effort, though it was enforced")
		}
	})

	t.Run("an AF_UNSPEC datagram is refused, not continued", func(t *testing.T) {
		if c := h.check(t, "unspec_udp_sendto"); !isErrno(c.Err, unix.EACCES) {
			t.Fatalf("sendto = %q, want EACCES: outside connect(2) AF_UNSPEC is an unrecognized family (R4, E4)", c.Err)
		}
		if c := h.check(t, "unspec_udp_arrived"); !isErrno(c.Err, unix.EAGAIN) {
			t.Fatalf("receiver = {n=%d err=%q}, want nothing delivered: udp_sendmsg sends AF_UNSPEC to the sockaddr_in behind it", c.N, c.Err)
		}
		// One line from the sendto above and one from the sendmmsg batch below: each call refused once.
		evs := h.netEvents(t, "unspec")
		if len(evs) != 2 {
			t.Fatalf("events = %d, want one refusal per call", len(evs))
		}
		for _, ev := range evs {
			if ev.Verdict != record.VerdictRefused || ev.Rule != ruleUnmatched || ev.Reason != record.ReasonNetNotAllowed {
				t.Errorf("event = {%s %s %s}, want refused/unmatched/net-not-allowed", ev.Verdict, ev.Rule, ev.Reason)
			}
			var p netPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if p.Proto != protoUDP {
				t.Errorf("proto = %q, want udp: the refusal names the socket it was made on", p.Proto)
			}
		}
	})

	t.Run("an AF_UNSPEC message past the 64th refuses the whole batch", func(t *testing.T) {
		c := h.check(t, "unspec_udp_sendmmsg_tail")
		if !isErrno(c.Err, unix.EACCES) {
			t.Fatalf("sendmmsg = %q, want EACCES: the kernel sends message 65 too (R13b)", c.Err)
		}
		if a := h.check(t, "unspec_udp_sendmmsg_arrived"); !isErrno(a.Err, unix.EAGAIN) {
			t.Fatalf("receiver = {n=%d err=%q}, want nothing delivered from a refused batch", a.N, a.Err)
		}
		evs := h.netEvents(t, "127.0.0.1:"+c.Out)
		if len(evs) != mmsgMessages {
			t.Fatalf("events for the AF_INET messages = %d, want the %d this tier records", len(evs), mmsgMessages)
		}
		for _, ev := range evs {
			var p netPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if ev.Verdict != record.VerdictRefused || p.BestEffort || p.Proto != protoUDP {
				t.Errorf("event = {%s best_effort=%v %s}, want an enforced udp refusal", ev.Verdict, p.BestEffort, p.Proto)
			}
		}
	})

	t.Run("a datagram past the 64th message to an undeclared host refuses the batch", func(t *testing.T) {
		c := h.check(t, "tail_udp_sendmmsg")
		if !isErrno(c.Err, unix.EACCES) {
			t.Fatalf("sendmmsg = {n=%d err=%q}, want EACCES: the batch carries a destination the policy refuses (R13b)", c.N, c.Err)
		}
		if p := h.check(t, "tail_udp_sendmmsg_peer"); p.N != 0 {
			t.Errorf("the peer got %d datagrams, want none from a refused batch", p.N)
		}
		if o := h.check(t, "tail_udp_sendmmsg_other"); o.N != 0 {
			t.Fatalf("the undeclared receiver got %d datagrams, want none from a refused batch", o.N)
		}
		evs := h.netEvents(t, "127.0.0.1:"+c.Out)
		if len(evs) != 1 {
			t.Fatalf("events for the undeclared receiver = %d, want the one line that names the refusal (R13b)", len(evs))
		}
		var p netPayload
		if err := evs[0].DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if ev := evs[0]; ev.Verdict != record.VerdictRefused || ev.Rule != ruleUnmatched || ev.Reason != record.ReasonNetNotAllowed ||
			p.BestEffort || p.Proto != protoUDP {
			t.Errorf("event = {%s %s %s best_effort=%v %s}, want an enforced udp refused/unmatched/net-not-allowed",
				ev.Verdict, ev.Rule, ev.Reason, p.BestEffort, p.Proto)
		}
	})

	t.Run("MSG_FASTOPEN on a connected socket is decided, not continued", func(t *testing.T) {
		if c := h.check(t, "fastopen_connected_undeclared"); !isErrno(c.Err, unix.EACCES) {
			t.Fatalf("sendto = %q, want EACCES: a peer this loop saw is not one the kernel is bound to see (R12)", c.Err)
		}
		if c := h.check(t, "fastopen_connected_declared"); !isErrno(c.Err, unix.EISCONN) {
			t.Fatalf("sendto = %q, want the kernel's own EISCONN, relayed", c.Err)
		}
		evs := h.netEvents(t, "127.0.0.3:9")
		if len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Rule != ruleUnmatched {
			t.Fatalf("events = %+v, want one refused/unmatched line", evs)
		}
	})

	t.Run("argv is recorded", func(t *testing.T) {
		if c := h.check(t, "execve_missing"); !isErrno(c.Err, unix.ENOENT) {
			t.Fatalf("execve of a missing path = %q, want the ENOENT the lookup meets (R16b (0))", c.Err)
		}
		if c := h.check(t, "execve_recorded"); !isErrno(c.Err, unix.EACCES) {
			t.Fatalf("execve of a file with no execute bit = %q, want EACCES", c.Err)
		}
		noexec := filepath.Join(h.dir, "noexec")
		var found *record.Event
		var payload execPayload
		for _, ev := range h.sink.all() {
			if ev.Kind != record.KindExec {
				continue
			}
			var p execPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if p.Path == "/nonexistent/tego-integration" {
				t.Errorf("a line for a miss (%s %s): R16b (0) writes none", ev.Verdict, ev.Rule)
			}
			if p.Path == noexec {
				found, payload = ev, p
			}
		}
		if found == nil {
			t.Fatal("no exec event for the attempted execve")
		}
		if len(payload.Argv) != 3 || payload.Argv[0] != "tego-argv-0" || payload.Argv[2] != "value" {
			t.Errorf("argv = %q, want the target's own vector", payload.Argv)
		}
		if payload.ArgvTruncated {
			t.Error("argv_truncated on a three-word argv")
		}
		if payload.ExecID == "" || payload.ParentExecID == "" {
			t.Errorf("exec ids = %q/%q, want both", payload.ExecID, payload.ParentExecID)
		}
		if found.Source != record.SourceSeccomp {
			t.Errorf("source = %s, want seccomp (advisory)", found.Source)
		}
	})

	t.Run("filesystem records carry the nearest-wins verdict", func(t *testing.T) {
		for _, name := range []string{"write_open_inside", "mkdir_inside"} {
			if c := h.check(t, name); c.Err != "" {
				t.Errorf("%s = %q, want the syscall to have been continued", name, c.Err)
			}
		}
		want := map[string]record.Verdict{
			filepath.Join(h.dir, "out.txt"): record.VerdictAllow,
			filepath.Join(h.dir, "sub"):     record.VerdictAllow,
		}
		outside := filepath.Clean(filepath.Join(h.dir, "..", "outside.txt"))
		want[outside] = record.VerdictRefused
		seen := map[string]record.Verdict{}
		for _, ev := range h.sink.all() {
			if ev.Kind != record.KindFS {
				continue
			}
			var p record.FSPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if _, ok := want[p.Path]; ok {
				seen[p.Path] = ev.Verdict
			}
		}
		for path, verdict := range want {
			got, ok := seen[path]
			if !ok {
				t.Errorf("no fs event for %s", path)
				continue
			}
			if got != verdict {
				t.Errorf("%s verdict = %s, want %s", path, got, verdict)
			}
		}
	})

	t.Run("fast open is decided like a connect", func(t *testing.T) {
		// sendmsg carries the address inside a struct, so this exercises the msghdr reader as well.
		if c := h.check(t, "fastopen_refused"); !isErrno(c.Err, unix.EACCES) {
			t.Errorf("refused fast-open send = %q, want EACCES (R12)", c.Err)
		}
		evs := h.netEvents(t, "127.0.0.1:"+portOf(t, h, 1))
		var refusedSend bool
		for _, ev := range evs {
			if ev.Verdict == record.VerdictRefused {
				refusedSend = true
			}
		}
		if !refusedSend {
			t.Error("no refused event for the undeclared fast-open send")
		}
		allowed := h.check(t, "fastopen_allowed")
		t.Logf("allowed fast-open send returned n=%d err=%q (the loopback listener need not support TFO)",
			allowed.N, allowed.Err)
		if isErrno(allowed.Err, unix.EACCES) {
			t.Error("a declared host's fast-open send was refused")
		}
	})

	t.Run("relative paths resolve through the target's cwd", func(t *testing.T) {
		if c := h.check(t, "relative_open"); c.Err != "" {
			t.Fatalf("relative open failed: %s", c.Err)
		}
		want := filepath.Join(h.dir, "relative.txt")
		for _, ev := range h.sink.all() {
			if ev.Kind != record.KindFS {
				continue
			}
			var p record.FSPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if p.Path == want {
				if ev.Verdict != record.VerdictAllow {
					t.Errorf("verdict = %s, want allow inside the write directory", ev.Verdict)
				}
				return
			}
		}
		t.Errorf("no fs event resolved to %s (R6)", want)
	})

	t.Run("a relative unix connect is relayed to the socket it was decided as", func(t *testing.T) {
		if c := h.check(t, "relative_unix_connect"); c.Err != "" {
			t.Fatalf("connect(\"u.sock\") from inside %s = %q, want it to reach %s/u.sock (R11)", h.dir, c.Err, h.dir)
		}
	})

	t.Run("the mount family is refused and recorded as landlock-topology", func(t *testing.T) {
		if c := h.check(t, "mount_refused"); !isErrno(c.Err, unix.EPERM) {
			t.Fatalf("mount = %q, want EPERM (R31)", c.Err)
		}
		var refused, gaps int
		for _, ev := range h.sink.all() {
			switch {
			case ev.Kind == record.KindRefused && ev.Reason == record.ReasonLandlockTopology:
				refused++
			case ev.Kind == record.KindGap:
				var p record.GapPayload
				if err := ev.DecodePayload(&p); err == nil && p.Why == string(record.ReasonLandlockTopology) {
					gaps++
				}
			}
		}
		if refused != 1 || gaps != 1 {
			t.Errorf("landlock-topology lines: refused %d, gap %d; want one of each", refused, gaps)
		}
	})

	m := h.stop(t)
	if m.Notifications == 0 {
		t.Fatal("run_end.supervisor would carry no notifications")
	}
	t.Logf("metrics: notifications=%d held_ms=%d anomalies=%d", m.Notifications, m.HeldMS, m.Anomalies)
	// One line per notification, except the one sendmmsg batch, which R13b records per message: its 64
	// AF_INET messages and the AF_UNSPEC one that refused it are 65 lines from one notification; and the
	// mount, whose refused line is joined by the binary's first landlock-topology gap (R31).
	batchExtra := int64(mmsgMessages) + 1
	if int64(len(h.sink.all())) > m.Notifications+batchExtra {
		t.Errorf("more events (%d) than notifications (%d) plus the batch's own %d", len(h.sink.all()), m.Notifications, batchExtra)
	}
}

// TestIntegrationFastPath measures the real round trip of the record-and-continue path against
// P0-DESIGN §9's under-10 µs budget. The assertion is against the soft ceiling rather than the budget so
// a loaded CI box does not fail the suite; the measured figure is logged either way.
//
// The figure is the best of up to three runs: a mean over 2000 operations absorbs every scheduling stall of
// a loaded box (211 µs against the 200 µs ceiling with the load average near 40, 2026-09-29), while the path's
// own cost is what the best run shows. The ceiling is the soft ceiling or, on a box whose scheduler alone
// costs more, noiseFactor times the median pipe ping-pong measured in the same run (noiseGauge): a per-op slowdown
// still exceeds it, a busy machine no longer does. A run under the ceiling ends the loop early.
func TestIntegrationFastPath(t *testing.T) {
	const ops, attempts = 2000, 3
	best := time.Duration(1<<63 - 1)
	ceiling, gauge := SoftCeiling, new(noiseGauge)
	for i := 0; i < attempts && best > ceiling; i++ {
		h := startHarness(t, ops)
		m := h.stop(t)
		if h.report.LoopOps != ops {
			t.Fatalf("the target reported %d operations, want %d", h.report.LoopOps, ops)
		}
		per := time.Duration(h.report.LoopNS / int64(h.report.LoopOps))
		t.Logf("attempt %d: record+CONTINUE round trip %v per notification over %d operations (budget %v)",
			i+1, per, ops, 10*time.Microsecond)
		t.Logf("metrics: notifications=%d held_ms=%d anomalies=%d", m.Notifications, m.HeldMS, m.Anomalies)
		best = min(best, per)
		if best > ceiling {
			ceiling = max(ceiling, gauge.ceiling(t))
		}
	}
	if best > ceiling {
		t.Errorf("round trip %v, the best of %d runs, exceeds the ceiling %v", best, attempts, ceiling)
	}
}

// TestIntegrationListenerHangup is the end of a run: once the last task carrying the filter is gone the
// listener hangs up, every notified syscall would fail ENOSYS on its own, and Run returns on its own with
// no cancellation at all.
//
// It is also the evidence behind this package's one deviation from the spec: docs/p0/supervisor.md E24
// says closing the notify fd unblocks every pending NOTIF_RECV. It does not — the ioctl sleeps in
// down_interruptible on a semaphore that a close does not post (measured on 6.17: a RECV blocked before
// the close was still blocked two seconds after it). The loop therefore polls first and calls RECV only
// with a notification already pending, which is what makes this test finish.
func TestIntegrationListenerHangup(t *testing.T) {
	h := startHarness(t, 0) // startHarness waits for Run before it returns
	if !h.selfStopped {
		t.Error("Run had to be cancelled; it should have ended when the listener hung up")
	}
	if h.runErr != nil {
		t.Fatalf("Run = %v, want nil once the listener hung up", h.runErr)
	}
	if m := h.loop.Metrics(); m.Notifications == 0 {
		t.Error("no notifications were counted")
	}
}

// echoServer starts a loopback listener that answers "ping" with "pong" and returns it with its port.
func echoServer(t testing.TB) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close() //nolint:errcheck // test server
				buf := make([]byte, 16)
				n, err := conn.Read(buf)
				if err != nil || string(buf[:n]) != "ping" {
					return
				}
				_, _ = conn.Write([]byte("pong"))
			}()
		}
	}()
	return ln, ln.Addr().(*net.TCPAddr).Port
}

// portOf returns the allowed (0) or denied (1) port the harness handed the target.
func portOf(t *testing.T, h *harness, which int) string {
	t.Helper()
	if which == 0 {
		return strconv.Itoa(h.allowedPort)
	}
	return strconv.Itoa(h.deniedPort)
}

// isErrno reports whether the target's error text is the named errno: the target reports errno.Error().
func isErrno(s string, e unix.Errno) bool { return s == e.Error() }
