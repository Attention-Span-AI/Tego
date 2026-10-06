// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"errors"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
)

// modeGateRace runs the target under a contract with no net: section and a `net to` gate that refuses two
// loopback ports, while a sibling thread rewrites the address of each connect and send between a benign
// destination, a unix-spelled copy of the gated one and the gated one itself (ADR 0041 Step 3, D6).
const modeGateRace = "gaterace"

// helperRace carries the race: the syscall kind (connect, fastopen or sendto), then the benign TCP, gated TCP,
// benign UDP and gated UDP ports and the attempts.
const helperRace = "TEGO_SUPERVISOR_RACE"

// gateRaceAttempts is how many syscalls of each kind the target races. Before ADR 0041 about one in five
// reached the gated port, so a fixed loop that lets none through is the race closed, not a lucky run.
const gateRaceAttempts = 600

// raceWord is the first 32 bits of a sockaddr_in in memory, family then port in network order: one aligned
// store changes both, so the kernel and the supervisor each read one whole state, never half of one.
func raceWord(family uint16, port int) uint32 {
	return uint32(family) | uint32(port>>8&0xff)<<16 | uint32(port&0xff)<<24
}

// gateRaceChecks makes gateRaceAttempts syscalls of one kind (connects, Fast-Open sends or UDP sendtos), with
// a sibling goroutine (on another thread: the filtered one is locked) cycling the address through benign,
// unix-spelled gated and gated. The check's N is how many reached the gated port as the target sees it (the
// peer a connected socket ended up with); Out counts the outcomes. gate_direct is the control: the gated
// address, unraced, is refused.
func gateRaceChecks() []checkResult {
	kind, rest, _ := strings.Cut(os.Getenv(helperRace), ",")
	var ports []int
	for _, f := range splitComma(rest) {
		n, err := strconv.Atoi(f)
		if err != nil {
			return []checkResult{{Name: "race_env", Err: helperRace + ": " + err.Error()}}
		}
		ports = append(ports, n)
	}
	if len(ports) != 5 {
		return []checkResult{{Name: "race_env", Err: helperRace + ": want five numbers"}}
	}
	benignTCP, gatedTCP, benignUDP, gatedUDP, attempts := ports[0], ports[1], ports[2], ports[3], ports[4]
	var out []checkResult

	// words is the sockaddr_in the syscalls name; a []uint32 keeps word 0 aligned for the atomic stores.
	words := make([]uint32, 4)
	words[1] = 0x0100007f // 127.0.0.1
	addr := uintptr(unsafe.Pointer(&words[0]))

	direct := func() error {
		atomic.StoreUint32(&words[0], raceWord(unix.AF_INET, gatedTCP))
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd) //nolint:errcheck // a test socket
		if _, _, e := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), addr, 16); e != 0 {
			return e
		}
		return nil
	}
	out = append(out, checkResult{Name: "gate_direct", Err: errText(direct())})

	{
		benign, gated, typ := benignTCP, gatedTCP, unix.SOCK_STREAM
		if kind == "sendto" {
			benign, gated, typ = benignUDP, gatedUDP, unix.SOCK_DGRAM
		}
		states := []uint32{raceWord(unix.AF_INET, benign), raceWord(unix.AF_UNIX, gated), raceWord(unix.AF_INET, gated)}
		var stop atomic.Bool
		done := make(chan struct{})
		go func() {
			defer close(done)
			for i := 0; !stop.Load(); i++ {
				atomic.StoreUint32(&words[0], states[i%len(states)])
			}
		}()
		counts := map[string]int{}
		reached := 0
		payload := []byte("x")
		for range attempts {
			fd, err := unix.Socket(unix.AF_INET, typ|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				counts["socket "+err.Error()]++
				continue
			}
			var e unix.Errno
			switch kind {
			case "connect":
				_, _, e = unix.Syscall(unix.SYS_CONNECT, uintptr(fd), addr, 16)
			case "fastopen", "sendto":
				flags := 0
				if kind == "fastopen" {
					flags = unix.MSG_FASTOPEN
				}
				_, _, e = unix.Syscall6(unix.SYS_SENDTO, uintptr(fd), uintptr(unsafe.Pointer(&payload[0])), 1,
					uintptr(flags), addr, 16)
			}
			if e != 0 {
				counts[e.Error()]++
			} else {
				counts["ok"]++
				if peer, err := unix.Getpeername(fd); err == nil {
					if in4, ok := peer.(*unix.SockaddrInet4); ok && in4.Port == gated {
						reached++
					}
				}
			}
			_ = unix.Close(fd)
		}
		stop.Store(true)
		<-done
		runtime.KeepAlive(payload)
		var parts []string
		for k, v := range counts {
			parts = append(parts, k+"="+strconv.Itoa(v))
		}
		out = append(out, checkResult{Name: "race_" + kind, N: reached, Out: strings.Join(parts, " ")})
	}
	runtime.KeepAlive(words)
	return out
}

// countingTCP is a loopback TCP listener that counts the connections it accepts.
func countingTCP(t *testing.T) (*atomic.Int64, int) {
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
			n.Add(1)
			_ = c.Close()
		}
	}()
	return &n, l.Addr().(*net.TCPAddr).Port
}

// countingUDP is a loopback UDP socket that counts the datagrams it receives, drained as they arrive so a
// full receive buffer never hides one.
func countingUDP(t *testing.T) (*atomic.Int64, int) {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	var n atomic.Int64
	go func() {
		buf := make([]byte, 64)
		for {
			if _, _, err := c.ReadFromUDP(buf); err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			n.Add(1)
		}
	}()
	return &n, c.LocalAddr().(*net.UDPAddr).Port
}

// gateRaceRun starts the race target under a contract with no net: section and a gate that refuses gatedTCP
// and gatedUDP, races kind, and returns the harness and the receivers' counts once the target has reported.
func gateRaceRun(t *testing.T, kind string) (h *harness, gatedTCPs, gatedUDPs, benignTCPs, benignUDPs int64) {
	t.Helper()
	benignT, benignTCP := countingTCP(t)
	gatedT, gatedTCP := countingTCP(t)
	benignU, benignUDP := countingUDP(t)
	gatedU, gatedUDP := countingUDP(t)
	g, err := gate.New([]gate.Rule{
		{Predicate: gate.NetTo, Argument: "127.0.0.1:" + strconv.Itoa(gatedTCP), Score: 90},
		{Predicate: gate.NetTo, Argument: "127.0.0.1:" + strconv.Itoa(gatedUDP), Score: 90},
	}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	env := helperRace + "=" + strings.Join([]string{
		kind, strconv.Itoa(benignTCP), strconv.Itoa(gatedTCP), strconv.Itoa(benignUDP), strconv.Itoa(gatedUDP),
		strconv.Itoa(gateRaceAttempts),
	}, ",")
	h = startHarnessWith(t, harnessOpts{mode: modeGateRace, env: []string{env}, gate: g})
	h.stop(t)
	// Every connect completed its handshake before the target closed it, and every datagram was queued by
	// the call that sent it; the receivers' goroutines only need a moment to count them.
	time.Sleep(300 * time.Millisecond)
	return h, gatedT.Load(), gatedU.Load(), benignT.Load(), benignU.Load()
}

// TestGateConnectRelayedRaceFree, TestGateFastOpenRelayedRaceFree and TestGateSendtoRelayedRaceFree are ADR
// 0041 Step 3 (findings failopen-1, supervisor-2's net half) on a real kernel, real filter and real Loop: under
// a contract with no net: section, a `net to` gate that refuses a destination is not raced past by a sibling
// thread that rewrites the address after the supervisor copied it. Before, a connect or Fast-Open send the
// gate scored Allow (a benign copy, or a unix-spelled one on the IP socket) was answered CONTINUE, the kernel
// read the address again, and about one in five reached the gated listener. Now every connect, Fast-Open send
// and addressed datagram on an IP-domain socket under a net gate is performed on the duplicate with the copy
// the gate scored (gate.md R4, D6), so none does: the benign copy reaches the benign port, the unix-spelled
// one gets the kernel's own EAFNOSUPPORT, and the gated one is refused.
func TestGateConnectRelayedRaceFree(t *testing.T) {
	h, gatedTCP, _, benignTCP, _ := gateRaceRun(t, "connect")
	if c := h.check(t, "gate_direct"); !isErrno(c.Err, refusalErrno) {
		t.Fatalf("an unraced connect to the gated port = %q, want the gate's refusal", c.Err)
	}
	assertRaceClosed(t, h, "race_connect", gatedTCP, benignTCP)
}

// TestGateFastOpenRelayedRaceFree is TestGateConnectRelayedRaceFree for sendto(MSG_FASTOPEN) on a fresh TCP
// socket, which connects to the address the kernel reads (R12).
func TestGateFastOpenRelayedRaceFree(t *testing.T) {
	h, gatedTCP, _, benignTCP, _ := gateRaceRun(t, "fastopen")
	if strings.Contains(h.check(t, "race_fastopen").Out, unix.EOPNOTSUPP.Error()) {
		t.Skip("TCP Fast Open client disabled on this host (net.ipv4.tcp_fastopen)")
	}
	assertRaceClosed(t, h, "race_fastopen", gatedTCP, benignTCP)
}

// TestGateSendtoRelayedRaceFree is TestGateConnectRelayedRaceFree for an addressed UDP datagram, which
// relayDatagram already sent from the copy before ADR 0041: it holds that, with the family flip included.
func TestGateSendtoRelayedRaceFree(t *testing.T) {
	h, _, gatedUDP, _, benignUDP := gateRaceRun(t, "sendto")
	assertRaceClosed(t, h, "race_sendto", gatedUDP, benignUDP)
}

// assertRaceClosed fails when anything reached the gated receiver, or when nothing reached the benign one (a
// race that never ran proves nothing).
func assertRaceClosed(t *testing.T, h *harness, check string, gated, benign int64) {
	t.Helper()
	c := h.check(t, check)
	t.Logf("%s: outcomes %s; gated receiver %d, target-seen gated peers %d, benign receiver %d", check, c.Out, gated, c.N, benign)
	if gated != 0 || c.N != 0 {
		t.Fatalf("%s: %d of %d reached the gated port (target saw %d gated peers); want none", check, gated, gateRaceAttempts, c.N)
	}
	if benign == 0 {
		t.Fatalf("%s: nothing reached the benign port either (%s); the race did not run", check, c.Out)
	}
}
