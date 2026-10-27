// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// modeUnixRace runs the target in ADR 0070's unix-only state (no net: section, host_sockets off) without the
// abstract-socket scope, so the supervisor alone stands between it and the host's sockets, while a sibling thread
// rewrites the family of each connect's and send's address between an IP destination, a foreign pathname socket and a
// foreign abstract one, and dup3s a unix socket and an IP socket in turn over the descriptor the call names.
const modeUnixRace = "unixrace"

// helperUnixRace carries the race: the syscall kind (connect, sendto or sendmsg), the benign IP port, the attempts
// and the tail every address shares (unixRaceAddr).
const helperUnixRace = "TEGO_SUPERVISOR_UNIX_RACE"

// unixRaceAttempts is how many syscalls of each kind the target races (ADR 0070 acceptance (6)).
const unixRaceAttempts = 10000

// unixRaceAddrLen is the fixed address length of every raced call: the whole struct sockaddr_un, so an abstract name
// is its 107 bytes and a pathname ends at its NUL.
const unixRaceAddrLen = sunPathOff + sunPathMax

// unixRacePathname is the foreign pathname socket's name, relative to the target's working directory (the harness
// directory, a write entry): the bytes after the first word are 7f 00 00 01 in every image, which ends it there.
const unixRacePathname = "ff\x7f"

// unixRaceAddr lays out the raced address: the first word (the family and the next two bytes) is the only one the
// sibling stores, and the bytes after it are fixed, 127.0.0.1 then tail, so any word the supervisor reads, torn or
// whole, is an IP address on loopback or a unix name; a rewrite can never aim a call off the host. The three first
// words make 127.0.0.1:port, the pathname unixRacePathname and the abstract name unixRaceAbstract(tail).
func unixRaceAddr(port int, tail string) (fixed []byte, firsts []uint32) {
	fixed = make([]byte, 112)
	copy(fixed[4:], []byte{127, 0, 0, 1})
	copy(fixed[8:], tail)
	first := func(family uint16, b0, b1 byte) uint32 {
		var w [4]byte
		binary.NativeEndian.PutUint16(w[:], family)
		w[2], w[3] = b0, b1
		return binary.NativeEndian.Uint32(w[:])
	}
	return fixed, []uint32{
		first(unix.AF_INET, byte(port>>8), byte(port)),
		first(unix.AF_UNIX, unixRacePathname[0], unixRacePathname[1]),
		first(unix.AF_UNIX, 0, 'u'),
	}
}

// unixRaceAbstract is the abstract name the third first word names: 'u', the fixed 7f 00 00 01, and the tail up to
// the fixed length.
func unixRaceAbstract(tail string) string {
	b := make([]byte, 112)
	copy(b[8:], tail)
	return "u\x7f\x00\x00\x01" + string(b[8:unixRaceAddrLen])
}

// The descriptor slots of the race: each attempt's fresh IP and unix sockets sit at the first two, and the third
// is the descriptor the syscall names, which the sibling points at one or the other.
const (
	unixRaceInetSlot = 900
	unixRaceUnixSlot = 901
	unixRaceTarget   = 902
)

// unixRaceChecks makes unixRaceAttempts syscalls of one kind on fresh sockets, connects on stream sockets or addressed
// sends on datagram ones, from the harness directory. The check's N is how many of the attempts' unix sockets the
// target saw connected to a peer (a connect that reached a foreign socket); Out counts the outcomes.
func unixRaceChecks() []checkResult {
	fields := strings.SplitN(os.Getenv(helperUnixRace), ",", 4)
	if len(fields) != 4 {
		return []checkResult{{Name: "unixrace_env", Err: helperUnixRace + ": want kind, port, attempts and tail"}}
	}
	kind, tail := fields[0], fields[3]
	port, err1 := strconv.Atoi(fields[1])
	attempts, err2 := strconv.Atoi(fields[2])
	if err := errors.Join(err1, err2); err != nil {
		return []checkResult{{Name: "unixrace_env", Err: err.Error()}}
	}
	if err := unix.Chdir(os.Getenv(helperDir)); err != nil {
		return []checkResult{{Name: "unixrace_env", Err: "chdir: " + err.Error()}}
	}
	// inetType and unixType are the slots' socket types: a connect flips between two stream sockets, a datagram send
	// between two datagram ones, and the stream-send kinds put a stream socket in the inet slot (a Fast-Open sendto for
	// sendtostream, a connected one for sendtoconn, review F1/HS-R1-1) against a datagram socket in the unix slot, so a
	// flip to the unix slot is the datagram the supervisor must not deliver to a foreign receiver. sendFlags carries
	// MSG_FASTOPEN for sendtostream; connectInet connects the inet socket to the benign TCP listener for sendtoconn.
	inetType, unixType, sendFlags, connectInet := unix.SOCK_STREAM, unix.SOCK_STREAM, 0, false
	switch kind {
	case "connect":
	case "sendtostream":
		inetType, unixType, sendFlags = unix.SOCK_STREAM, unix.SOCK_DGRAM, unix.MSG_FASTOPEN
	case "sendtoconn":
		inetType, unixType, connectInet = unix.SOCK_STREAM, unix.SOCK_DGRAM, true
	default:
		inetType, unixType = unix.SOCK_DGRAM, unix.SOCK_DGRAM
	}
	fixed, firsts := unixRaceAddr(port, tail)
	// words is the address the calls name; a []uint32 keeps word 0 aligned for the sibling's atomic stores.
	words := make([]uint32, len(fixed)/4)
	for i := range words {
		words[i] = binary.NativeEndian.Uint32(fixed[i*4:])
	}
	addr := uintptr(unsafe.Pointer(&words[0]))
	payload := []byte("x")
	iov := unix.Iovec{Base: &payload[0]}
	iov.SetLen(len(payload))
	msg := unix.Msghdr{Name: (*byte)(unsafe.Pointer(&words[0])), Namelen: unixRaceAddrLen, Iov: &iov}
	msg.SetIovlen(1)
	slots := []int{unixRaceInetSlot, unixRaceUnixSlot}

	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; !stop.Load(); i++ {
			atomic.StoreUint32(&words[0], firsts[i%len(firsts)])
			_ = unix.Dup3(slots[i%len(slots)], unixRaceTarget, unix.O_CLOEXEC)
		}
	}()
	counts := map[string]int{}
	reached := 0
	// benign is the loopback address the inet socket connects to for sendtoconn: 127.0.0.1:port, the TCP listener.
	benign := &unix.SockaddrInet4{Port: port}
	copy(benign.Addr[:], []byte{127, 0, 0, 1})
	for i := range attempts {
		ifd, err := unix.Socket(unix.AF_INET, inetType|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			counts["socket "+err.Error()]++
			continue
		}
		if connectInet {
			if err := unix.Connect(ifd, benign); err != nil {
				_ = unix.Close(ifd)
				counts["connect "+err.Error()]++
				continue
			}
		}
		ufd, err := unix.Socket(unix.AF_UNIX, unixType|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			_ = unix.Close(ifd)
			counts["socket "+err.Error()]++
			continue
		}
		// The slots take this attempt's sockets before the call's descriptor does, so the call only ever names one of
		// them, whichever the sibling pointed it at last.
		_ = unix.Dup3(ifd, unixRaceInetSlot, unix.O_CLOEXEC)
		_ = unix.Dup3(ufd, unixRaceUnixSlot, unix.O_CLOEXEC)
		_ = unix.Close(ifd)
		_ = unix.Close(ufd)
		_ = unix.Dup3(slots[i%len(slots)], unixRaceTarget, unix.O_CLOEXEC)
		var e unix.Errno
		switch kind {
		case "connect":
			_, _, e = unix.Syscall(unix.SYS_CONNECT, unixRaceTarget, addr, unixRaceAddrLen)
		case "sendmsg":
			_, _, e = unix.Syscall(unix.SYS_SENDMSG, unixRaceTarget, uintptr(unsafe.Pointer(&msg)), 0)
		default: // sendto, sendtostream (MSG_FASTOPEN), sendtoconn
			_, _, e = unix.Syscall6(unix.SYS_SENDTO, unixRaceTarget, uintptr(unsafe.Pointer(&payload[0])), 1,
				uintptr(sendFlags), addr, unixRaceAddrLen)
		}
		if e != 0 {
			counts[e.Error()]++
		} else {
			counts["ok"]++
		}
		if peer, err := unix.Getpeername(unixRaceUnixSlot); err == nil {
			if su, ok := peer.(*unix.SockaddrUnix); ok && su.Name != "" {
				reached++
			}
		}
	}
	stop.Store(true)
	<-done
	runtime.KeepAlive(payload)
	runtime.KeepAlive(words)
	runtime.KeepAlive(&msg)
	for _, fd := range []int{unixRaceInetSlot, unixRaceUnixSlot, unixRaceTarget} {
		_ = unix.Close(fd)
	}
	var parts []string
	for k, v := range counts {
		parts = append(parts, k+"="+strconv.Itoa(v))
	}
	return []checkResult{{Name: "unixrace_" + kind, N: reached, Out: strings.Join(parts, " ")}}
}

// countingUnix is a unix listener (network unix) or receiver (unixgram) the test process binds at addr, outside the
// run, that counts the connections it accepts or the datagrams it receives.
func countingUnix(t *testing.T, network, addr string) *atomic.Int64 {
	t.Helper()
	var n atomic.Int64
	if network == "unix" {
		l, err := net.Listen(network, addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				n.Add(1)
				_ = c.Close()
			}
		}()
		return &n
	}
	c, err := net.ListenUnixgram(network, &net.UnixAddr{Name: addr, Net: network})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			if _, _, err := c.ReadFromUnix(buf); err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			n.Add(1)
		}
	}()
	return &n
}

// countingTCPBytes is a loopback TCP listener that counts the bytes its connections carry, each read to its end.
func countingTCPBytes(t *testing.T) (*atomic.Int64, int) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	var n atomic.Int64
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
				got, _ := io.Copy(io.Discard, c)
				n.Add(got)
			}()
		}
	}()
	return &n, l.Addr().(*net.TCPAddr).Port
}

// fastOpenClient reports whether this kernel sends TCP Fast Open as a client (net.ipv4.tcp_fastopen bit 0).
func fastOpenClient() bool {
	b, err := os.ReadFile("/proc/sys/net/ipv4/tcp_fastopen")
	if err != nil {
		return false
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return err == nil && v&1 != 0
}

// TestIntegrationUnixOnlyRaceFree is ADR 0070's race-free claim on a real kernel, real filter and real Loop, with the
// supervisor alone deciding (no Landlock scope or RESOLVE_UNIX in the target): unixRaceAttempts connects, then
// addressed sendtos and sendmsgs, while a sibling thread flips the address between an IP destination, a foreign
// pathname socket under the run's write entry and a foreign abstract one, and flips the descriptor between an IP
// socket and a unix socket. Every call is performed on the supervisor's own duplicate with the copy it decided, keyed
// on that duplicate's domain (ADR 0041 D6), so no flip after the copy reaches the kernel: the foreign sockets receive
// nothing, and the IP destination receives the relayed calls, which proves the race ran.
func TestIntegrationUnixOnlyRaceFree(t *testing.T) {
	for _, kind := range []string{"connect", "sendto", "sendmsg", "sendtostream", "sendtoconn"} {
		t.Run(kind, func(t *testing.T) {
			// The foreign unix receivers match the unix slot's type: a connect flips between stream sockets, every
			// send kind puts a datagram socket in the unix slot (the stream-send kinds among them), so the
			// datagram a flip delivers lands on a unixgram receiver.
			network := "unix"
			tcp := kind == "connect" || kind == "sendtostream" || kind == "sendtoconn"
			if kind != "connect" {
				network = "unixgram"
			}
			tail := "tego-unixrace-" + kind + "-" + strconv.Itoa(os.Getpid()) + "-"
			foreignAbstract := countingUnix(t, network, "@"+unixRaceAbstract(tail))
			var foreignPath *atomic.Int64
			prepare := func(dir string) { foreignPath = countingUnix(t, network, filepath.Join(dir, unixRacePathname)) }
			var benign *atomic.Int64
			var port int
			switch {
			case kind == "connect":
				benign, port = countingTCP(t)
			case tcp:
				// A stream-send kind proves its relay by the bytes the peer reads, not by accepts: sendtoconn connects
				// before every send, so an accept comes whether or not a send was relayed.
				benign, port = countingTCPBytes(t)
			default:
				benign, port = countingUDP(t)
			}
			env := []string{helperUnixRace + "=" + strings.Join([]string{kind, strconv.Itoa(port),
				strconv.Itoa(unixRaceAttempts), tail}, ",")}
			h := startHarnessWith(t, harnessOpts{mode: modeUnixRace, env: env, prepare: prepare, timeout: 3 * helperTimeout})
			h.stop(t)
			// Every relayed connect completed before the target closed it, and every datagram was queued by the call
			// that sent it; the receivers only need a moment to count them.
			time.Sleep(300 * time.Millisecond)
			c := h.check(t, "unixrace_"+kind)
			t.Logf("%s: outcomes %s; foreign pathname %d, foreign abstract %d, target-seen unix peers %d, benign %d",
				kind, c.Out, foreignPath.Load(), foreignAbstract.Load(), c.N, benign.Load())
			if foreignPath.Load() != 0 || foreignAbstract.Load() != 0 || c.N != 0 {
				t.Fatalf("%s: %d foreign pathname and %d foreign abstract arrivals of %d attempts (target saw %d unix peers); want none",
					kind, foreignPath.Load(), foreignAbstract.Load(), unixRaceAttempts, c.N)
			}
			// The race ran: the relayed calls reached the benign IP destination (a connect accepted, a datagram
			// received, the bytes of a connected or Fast-Open send read), or, where this kernel's TCP Fast Open client
			// is off, the Fast-Open sends met the kernel's own EOPNOTSUPP. R10's refusal of a foreign flip proves
			// nothing about the benign relay and is not counted.
			ran := benign.Load() != 0
			if kind == "sendtostream" && !fastOpenClient() {
				ran = strings.Contains(c.Out, unix.EOPNOTSUPP.Error())
			}
			if !ran {
				t.Fatalf("%s: nothing reached the IP destination either (%s); the race did not run", kind, c.Out)
			}
		})
	}
}
