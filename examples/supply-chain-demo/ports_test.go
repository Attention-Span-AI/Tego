// SPDX-License-Identifier: Apache-2.0

package supplychain

import (
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// minDemoPort is the lowest port a demo world takes: above the well-known ports, the common development ports and the
// demo's own 8801 to 8803, which a presenter's demo on the same machine may hold.
const minDemoPort = 10000

// handed are the ports freePort gave out in this process, so no two worlds, or two ports of one world, share one.
var handed = struct {
	sync.Mutex
	ports map[int]bool
}{ports: map[int]bool{}}

// freePort is a TCP port on 127.0.0.1 that nothing listens on now and that the kernel never hands out on its own: it
// lies outside the machine's ephemeral range (ephemeralRange), from which every port 0 bind and every outgoing
// connect takes its port. The demo binds these ports by number only later (setup's units; the dashboard never, in
// these tests), and its check calls a port busy when a connect to it succeeds. A port 0 bind closed at once left the
// port in that range, where the integration step's other packages, run side by side and many binding port 0, could
// be handed it in between: TestCheckNamesEachFailure then found "something already listens on the dashboard address
// 127.0.0.1:44311" (gate, 2026-11-10). Outside the range only a bind that names the port can take it.
func freePort(t testing.TB) int {
	t.Helper()
	lo, hi, err := ephemeralRange()
	if err != nil {
		t.Fatal(err)
	}
	below := max(lo-minDemoPort, 0)               // minDemoPort .. lo-1
	above := max(65535-max(hi, minDemoPort-1), 0) // max(hi+1, minDemoPort) .. 65535
	if below+above == 0 {
		t.Fatalf("the ephemeral range %d-%d leaves no port from %d to 65535 that the kernel never hands out", lo, hi, minDemoPort)
	}
	handed.Lock()
	defer handed.Unlock()
	for range 256 {
		i := rand.IntN(below + above)
		p := minDemoPort + i
		if i >= below {
			p = max(hi+1, minDemoPort) + i - below
		}
		if handed.ports[p] {
			continue
		}
		l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err != nil {
			continue // something listens there now
		}
		_ = l.Close()
		handed.ports[p] = true
		return p
	}
	t.Fatalf("no free port from %d to 65535 outside the ephemeral range %d-%d in 256 tries", minDemoPort, lo, hi)
	return 0
}

// ephemeralRange is the machine's ephemeral port range, inclusive (net.ipv4.ip_local_port_range, which IPv6 uses
// too).
func ephemeralRange() (lo, hi int, err error) {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return 0, 0, err
	}
	f := strings.Fields(string(b))
	if len(f) == 2 {
		lo, err1 := strconv.Atoi(f[0])
		hi, err2 := strconv.Atoi(f[1])
		if err1 == nil && err2 == nil && lo > 0 && lo <= hi && hi <= 65535 {
			return lo, hi, nil
		}
	}
	return 0, 0, fmt.Errorf("ip_local_port_range %q: want two ports, low first", strings.TrimSpace(string(b)))
}

// TestFreePortIsNeverHandedOutByTheKernel: the ports a demo world gets lie outside the machine's ephemeral range,
// from which the kernel takes every port 0 bind and every outgoing connect's port, so no other process can be handed
// one while the demo has not bound it yet; each is free when picked, and no two are the same.
func TestFreePortIsNeverHandedOutByTheKernel(t *testing.T) {
	lo, hi, err := ephemeralRange()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for range 8 {
		p := freePort(t)
		if p >= lo && p <= hi {
			t.Errorf("port %d is in the ephemeral range %d-%d: a port 0 bind elsewhere can be handed it", p, lo, hi)
		}
		if p < minDemoPort || p > 65535 {
			t.Errorf("port %d is outside %d-65535", p, minDemoPort)
		}
		if seen[p] {
			t.Errorf("port %d was handed out twice", p)
		}
		seen[p] = true
		l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err != nil {
			t.Errorf("port %d is not free: %v", p, err)
			continue
		}
		_ = l.Close()
	}
}
