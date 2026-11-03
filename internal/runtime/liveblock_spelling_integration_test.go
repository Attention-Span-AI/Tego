// SPDX-License-Identifier: Apache-2.0

//go:build integration && linux

package runtime

import (
	"context"
	"encoding/json"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
)

// spellingProbe waits for the test's word, then dials the server outside the run in every spelling of this host and
// writes what each came to as JSON. A connect from a socket bound to 127.0.0.3 to 0.0.0.0 lands on 127.0.0.3.
const spellingProbe = `import errno, json, os, socket, sys, time
port, other, lan, go, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
while not os.path.exists(go):
    time.sleep(0.02)

def dial(family, addr, source=None):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        if source:
            s.bind((source, 0))
        s.connect(addr)
        return "connected"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno))
    finally:
        s.close()

res = {
    "named": dial(socket.AF_INET, ("127.0.0.1", port)),
    "mapped": dial(socket.AF_INET6, ("::ffff:127.0.0.1", port)),
    "unspecified": dial(socket.AF_INET, ("0.0.0.0", port)),
    "unspecified mapped": dial(socket.AF_INET6, ("::ffff:0.0.0.0", port)),
    "unspecified v6": dial(socket.AF_INET6, ("::", port)),
    "unspecified from a bound socket": dial(socket.AF_INET, ("0.0.0.0", port), "127.0.0.3"),
    "other loopback": dial(socket.AF_INET, ("127.0.0.2", port)),
    "v6 loopback": dial(socket.AF_INET6, ("::1", port)),
    "other port": dial(socket.AF_INET, ("127.0.0.1", other)),
}
if lan:
    res["lan"] = dial(socket.AF_INET, (lan, port))
json.dump(res, open(out, "w"))
`

// TestIntegrationLiveBlockEverySpelling is `tego block net 127.0.0.1:P` on the real kernel, on a contract with no net:
// section, where the block is the only refusal. A server on all interfaces outside the run takes no connection on the
// blocked port in any spelling of this host, and the same program's connect to another port goes through.
func TestIntegrationLiveBlockEverySpelling(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	listen := func(accepted *atomic.Int64) int {
		l, err := net.Listen("tcp", ":0") // every interface, both families
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
				accepted.Add(1)
				_ = c.Close()
			}
		}()
		return l.Addr().(*net.TCPAddr).Port
	}
	var blocked, other atomic.Int64
	port, otherPort := listen(&blocked), listen(&other)
	lan := ""
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
			lan = n.IP.String()
			break
		}
	}

	f := newFixture(t, contractFor("liveblockspelling", []string{python}, []string{python, resolved}))
	script := filepath.Join(f.dir, "probe.py")
	if err := os.WriteFile(script, []byte(spellingProbe), 0o644); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, script)
	word, out := filepath.Join(f.out, "go"), filepath.Join(f.out, "result.json")
	argv := []string{python, script, strconv.Itoa(port), strconv.Itoa(otherPort), lan, word, out}
	got := runUnderLiveBlock(t, f, argv, "127.0.0.1:"+strconv.Itoa(port), word, out)
	for name, v := range got {
		want := "EACCES"
		if name == "other port" {
			want = "connected"
		}
		if v != want {
			t.Errorf("%s = %s, want %s", name, v, want)
		}
	}
	if n := blocked.Load(); n != 0 {
		t.Errorf("the blocked server took %d connections (%v)", n, got)
	}
	if n := other.Load(); n != 1 {
		t.Errorf("the other server took %d connections, want 1", n)
	}
}

// runUnderLiveBlock runs argv on f, puts a net block on value in force, says the word the probe waits for, and returns
// the JSON the probe wrote to out.
func runUnderLiveBlock(t *testing.T, f *fixture, argv []string, value, word, out string) map[string]string {
	t.Helper()
	ran := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), f.rt, argv, f.deps(t, nil))
		ran <- err
	}()

	deadline := time.Now().Add(30 * time.Second)
	dir := liveRunDir(t, f.root, ran, deadline, 10*time.Millisecond)
	value, err := liveblock.Normalize(liveblock.KindNet, value)
	if err != nil {
		t.Fatal(err)
	}
	updateOverlay(t, dir, filepath.Base(dir), func(o *liveblock.Overlay) error {
		_, _, err := o.Add(liveblock.KindNet, value, "t", time.Now())
		return err
	})
	inForce := false
	for !inForce && time.Now().Before(deadline) {
		raw, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
		if inForce = err == nil && strings.Contains(string(raw), "live-block-added"); !inForce {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !inForce {
		select {
		case err := <-ran:
			t.Fatalf("the block never came into force: the run ended first (%v)", err)
		default:
			t.Fatal("the block never came into force")
		}
	}
	if err := os.WriteFile(word, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := <-ran; err != nil {
		t.Fatalf("Run: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the probe wrote nothing: %v", err)
	}
	got := map[string]string{}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

// liveRunDir waits until deadline, looking every poll, for root's one run directory to be live, its lock held by its
// launcher, and returns it; ran is the run's Run, and the test fails with its error should it end first. A live-block
// writer writes a run's overlay only then, as tego block and the dashboard do (the CLI's applyBlock and
// runact.BlockUntil refuse a run whose lock nobody holds). The launcher makes the run directory, opens its ledger
// there only while the directory holds nothing (ledger.WithFreshRunDir: a directory swapped in under the run's name is
// never written through), and takes the lock after that. An overlay written as soon as the directory appeared could
// land in between: the launcher then refused the run, as it must, and removed its directory under the write, so the
// rename into live-block.json failed with ENOENT, or the block never came into force.
func liveRunDir(t *testing.T, root string, ran <-chan error, deadline time.Time, poll time.Duration) string {
	t.Helper()
	for {
		if dirs := runDirs(t, root); len(dirs) == 1 {
			if held, _, err := ProbeLock(dirs[0]); err == nil && held {
				return dirs[0]
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("no run directory whose lock its launcher holds")
		}
		select {
		case err := <-ran:
			t.Fatalf("the run ended before its launcher held its lock: %v", err)
		default:
		}
		time.Sleep(poll)
	}
}

// TestIntegrationAnOverlayWrittenOnceTheLockIsHeldKeepsTheRun pins what liveRunDir relies on: the launcher takes its
// run's lock only after its ledger accepted the run directory as one that holds nothing, so a live-block writer that
// waits for the lock, as every writer of the product does, never makes a run refuse its own directory, however soon
// after the lock it writes. Here the overlay is written the moment the lock is seen (no pause between looks). Written
// the moment the directory appeared instead, every one of 20 runs was refused: "open ledger: ledger: run directory
// ... already holds [live-block.lock .live-block.json.<random>], not the one this process made".
func TestIntegrationAnOverlayWrittenOnceTheLockIsHeldKeepsTheRun(t *testing.T) {
	sleep, err := filepath.EvalSymlinks("/bin/sleep")
	if err != nil {
		t.Skipf("no sleep: %v", err)
	}
	for i := range 5 {
		f := newFixture(t, contractFor("lockfirst", []string{"/bin/sh"},
			[]string{"/bin/sh", "/usr/bin/sh", "/bin/sleep", "/usr/bin/sleep", sleep}))
		ran := make(chan error, 1)
		go func() {
			_, err := Run(context.Background(), f.rt, []string{"/bin/sh", "-c", "while [ ! -e out/go ]; do sleep 0.01; done"},
				f.deps(t, nil))
			ran <- err
		}()
		dir := liveRunDir(t, f.root, ran, time.Now().Add(30*time.Second), 0)
		_, werr := liveblock.Update(context.Background(), dir, filepath.Base(dir), func(o *liveblock.Overlay) (bool, error) {
			_, _, err := o.Add(liveblock.KindNet, "127.0.0.1:9", "t", time.Now())
			return true, err
		})
		touch(t, filepath.Join(f.out, "go"))
		if err := <-ran; err != nil || werr != nil {
			t.Fatalf("run %d: an overlay written once the lock was held (write: %v) made the run fail: %v", i, werr, err)
		}
	}
}

// groupProbe waits for the test's word, then sends a labelled datagram to the port under test at every address a UDP
// server on all interfaces hears, and writes what each send came to as JSON. Refused, nothing leaves the machine.
const groupProbe = `import errno, json, os, socket, sys, time
port, other, bcast, scope, go, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), sys.argv[5], sys.argv[6]
while not os.path.exists(go):
    time.sleep(0.02)

def send(label, family, addr, connected=False):
    s = socket.socket(family, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if connected:
            s.connect(addr)
            s.send(label.encode())
        else:
            s.sendto(label.encode(), addr)
        return "sent"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno))
    finally:
        s.close()

A, B = socket.AF_INET, socket.AF_INET6
res = {
    "limited broadcast": send("limited broadcast", A, ("255.255.255.255", port)),
    "all-hosts group": send("all-hosts group", A, ("224.0.0.1", port)),
    "all-hosts group, connected": send("all-hosts group, connected", A, ("224.0.0.1", port), True),
    "all-hosts group, mapped": send("all-hosts group, mapped", B, ("::ffff:224.0.0.1", port)),
    "other port": send("other port", A, ("127.0.0.1", other)),
}
if bcast:
    res["subnet broadcast"] = send("subnet broadcast", A, (bcast, port))
if scope:
    res["IPv6 all-nodes group"] = send("IPv6 all-nodes group", B, ("ff02::1", port, 0, scope))
json.dump(res, open(out, "w"))
`

// heardUDP is what a UDP server on every interface heard, by the datagrams' labels.
type heardUDP struct {
	mu     sync.Mutex
	labels map[string]int
}

func (h *heardUDP) serve(t *testing.T, c net.PacketConn) {
	t.Helper()
	t.Cleanup(func() { _ = c.Close() })
	go func() {
		b := make([]byte, 128)
		for {
			n, _, err := c.ReadFrom(b)
			if err != nil {
				return
			}
			h.mu.Lock()
			if h.labels == nil {
				h.labels = map[string]int{}
			}
			h.labels[string(b[:n])]++
			h.mu.Unlock()
		}
	}()
}

func (h *heardUDP) heard() map[string]int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return maps.Clone(h.labels)
}

// TestIntegrationLiveBlockReachesAGroupAndABroadcast is `tego block net 127.0.0.1:P` on the real kernel against a UDP
// server on all interfaces, on a contract with no net: section: a datagram to a multicast group, the limited broadcast
// or this host's subnet broadcast is delivered to that server, so the block refuses each with EACCES and the server
// hears none of them, while a datagram to another port goes through. An address this machine has no route for is
// refused all the same, since the block is decided before the kernel looks.
func TestIntegrationLiveBlockReachesAGroupAndABroadcast(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	var heard heardUDP
	c4, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	heard.serve(t, c4)
	port := c4.LocalAddr().(*net.UDPAddr).Port
	if c6, err := net.ListenPacket("udp6", "[::]:"+strconv.Itoa(port)); err == nil {
		heard.serve(t, c6) // a host with no IPv6 sends no IPv6 group datagram
	}
	otherConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var other heardUDP
	other.serve(t, otherConn)
	otherPort := otherConn.LocalAddr().(*net.UDPAddr).Port

	bcast, scope := "", 0
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if v4 := n.IP.To4(); v4 != nil && bcast == "" && i.Flags&net.FlagBroadcast != 0 {
				b := make(net.IP, net.IPv4len)
				for k := range b {
					b[k] = v4[k] | ^n.Mask[k]
				}
				bcast = b.String()
			}
			if n.IP.To4() == nil && n.IP.IsLinkLocalUnicast() && scope == 0 {
				scope = i.Index
			}
		}
	}

	f := newFixture(t, contractFor("liveblockgroup", []string{python}, []string{python, resolved}))
	script := filepath.Join(f.dir, "probe.py")
	if err := os.WriteFile(script, []byte(groupProbe), 0o644); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, script)
	word, out := filepath.Join(f.out, "go"), filepath.Join(f.out, "result.json")
	argv := []string{python, script, strconv.Itoa(port), strconv.Itoa(otherPort), bcast, strconv.Itoa(scope), word, out}
	got := runUnderLiveBlock(t, f, argv, "127.0.0.1:"+strconv.Itoa(port), word, out)
	time.Sleep(300 * time.Millisecond)
	for name, v := range got {
		want := "EACCES"
		if name == "other port" {
			want = "sent"
		}
		if v != want {
			t.Errorf("%s = %s, want %s", name, v, want)
		}
	}
	if h := heard.heard(); len(h) != 0 {
		t.Errorf("the server on the blocked port heard %v (%v)", h, got)
	}
	if h := other.heard(); h["other port"] != 1 {
		t.Errorf("the server on the other port heard %v", h)
	}
}
