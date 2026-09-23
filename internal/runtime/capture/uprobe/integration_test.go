// SPDX-License-Identifier: Apache-2.0

//go:build integration

package uprobe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// requireRoot skips a test that cannot run unprivileged, saying so rather than failing. This box has no
// root, so every test in this file skips here and runs in test/vm (CONTRIBUTING.md: "Anything that needs root
// or a specific kernel").
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: loading the capture object and attaching a uprobe both need privilege")
	}
}

// requireObjects skips when this binary was built without the compiled BPF objects, which is every build
// that did not run `go generate ./internal/bpf/...` and build with -tags tegobpf (bpf/README.md).
func requireObjects(t *testing.T) {
	t.Helper()
	if !bpf.Available() {
		t.Skipf("needs the compiled objects: %v", bpf.ErrNotGenerated)
	}
}

// bpffsPinRoot makes a private pin root on the host's bpf filesystem with one build's maps directory in it,
// laid out as the tier-2 backend lays one out at Prepare, and removes it when the test ends. It has to be
// bpffs: a map is pinned by creating a file there, and a t.TempDir() on tmpfs can hold no pin, which is why
// these tests could never load the object before.
func bpffsPinRoot(t *testing.T, hash string) (root, maps string) {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}
	root = filepath.Join("/sys/fs/bpf", "tego-uprobe-test-"+strconv.Itoa(os.Getpid())+"-"+strings.ToLower(t.Name()))
	maps = filepath.Join(root, hash, "maps")
	if err := os.MkdirAll(maps, 0o700); err != nil {
		t.Skipf("no writable bpf filesystem at /sys/fs/bpf: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root, maps
}

// seedRunSet pins the build's run set, capture ring outer and capture counters where the tier-2 backend pins them, puts a 4 MiB
// capture ring at each run's slot and gives each cgroup its slot, which is what Prepare has done by the time any
// capture source starts (ADR 0026 (1), (3)). A source reads its own slot from the run set and reads the ring at
// it, so every Kernel-mode test seeds both before Start, exactly as a run does. The specs are the capture
// object's own, which LoadCollection then finds pinned and shares.
func seedRunSet(t *testing.T, maps string, rows map[uint64]uint32) *ebpf.Map {
	return seedRuns(t, maps, rows, nil)
}

// seedRuns is seedRunSet with the slots that get no capture ring, as a run whose capture is not uprobe or whose
// ring the host's budget had no room for.
func seedRuns(t *testing.T, maps string, rows map[uint64]uint32, noRing map[uint32]bool) *ebpf.Map {
	t.Helper()
	spec, err := bpf.Load(bpf.ObjectUprobeSSL)
	if err != nil {
		t.Fatalf("load %s: %v", bpf.ObjectUprobeSSL, err)
	}
	pinned := map[string]*ebpf.Map{}
	for _, name := range []string{bpf.MapRunSet, bpf.MapCaptureEvents, bpf.MapCaptureLost, bpf.MapCaptureMiss} {
		ms := spec.Maps[name]
		if ms == nil {
			t.Fatalf("%s declares no %s", bpf.ObjectUprobeSSL, name)
		}
		m, err := ebpf.NewMapWithOptions(ms.Copy(), ebpf.MapOptions{PinPath: maps})
		if err != nil {
			t.Fatalf("pin %s: %v", name, err)
		}
		t.Cleanup(func() { _ = m.Close() })
		pinned[name] = m
	}
	for cg, slot := range rows {
		if !noRing[slot] {
			ring, err := bpf.NewRing(bpf.RingCapture, 4<<20)
			if err != nil {
				t.Fatal(err)
			}
			if err := bpf.InsertRing(pinned[bpf.MapCaptureEvents], slot, ring); err != nil {
				t.Fatal(err)
			}
			_ = ring.Close()
		}
		row := bpf.Run{RunIdx: slot, Descendants: 1, Tier: 2, Record: uint8(bpf.RecordFull)}
		if err := pinned[bpf.MapRunSet].Update(&cg, &row, ebpf.UpdateAny); err != nil {
			t.Fatalf("insert cgroup %d into the run set: %v", cg, err)
		}
	}
	return pinned[bpf.MapRunSet]
}

// TestLoadCaptureObject loads bpf/uprobe_ssl.bpf.c into the kernel and asserts the verifier accepts every
// program, that the capture maps are pinned under the names openPinned opens, and that openPinned then
// opens them.
func TestLoadCaptureObject(t *testing.T) {
	requireObjects(t)
	requireRoot(t)
	root, maps := bpffsPinRoot(t, "integration")
	coll, err := LoadCollection(root, "integration")
	if err != nil {
		t.Fatalf("LoadCollection: %v", err)
	}
	defer coll.Close()
	for _, name := range bpf.SSLSinglePrograms {
		if _, ok := coll.Programs[name]; !ok {
			t.Errorf("program %q missing from the loaded object", name)
		}
	}
	for _, name := range bpf.CaptureMaps {
		if _, ok := coll.Maps[name]; !ok {
			t.Errorf("map %q missing from the loaded object", name)
		}
		if _, err := os.Stat(filepath.Join(maps, name)); err != nil {
			t.Errorf("map %q is not pinned where the build's pins live: %v", name, err)
		}
	}
	if m := coll.Maps[CaptureEventsMapName]; m == nil || m.Type() != ebpf.HashOfMaps {
		t.Errorf("the capture ring outer is %v, want a HASH_OF_MAPS of the runs' rings", m)
	}
	rings, lost, err := openPinned(root, "integration")
	if err != nil {
		t.Fatalf("openPinned after LoadCollection: %v", err)
	}
	defer rings.Close()
	defer lost.Close()
	if n, err := (&slotLost{m: lost, slot: 7}).Lost(); err != nil || n != 0 {
		t.Errorf("fresh lost counter = %d, %v", n, err)
	}
}

// TestAttachToSystemLibssl attaches every probe R1-R3 asks for to the host's own libssl and detaches
// again, which is the one step of this component that cannot be tested without a kernel.
func TestAttachToSystemLibssl(t *testing.T) {
	requireObjects(t)
	requireRoot(t)
	path := systemLibssl(t)
	bin, err := readBinary(path)
	if err != nil {
		t.Fatalf("readBinary(%s): %v", path, err)
	}
	t.Logf("%s: build id %q, writes %v, reads %v", path, bin.BuildID, bin.WriteSymbols(), bin.ReadSymbols())
	root, _ := bpffsPinRoot(t, "integration")
	coll, err := LoadCollection(root, "integration")
	if err != nil {
		t.Fatalf("LoadCollection: %v", err)
	}
	defer coll.Close()
	att := NewAttacher(coll)
	defer att.Close()
	var closers []func()
	for _, p := range probesFor(bin) {
		l, err := att.Attach(bin.Path, p)
		if err != nil {
			t.Fatalf("attach %s: %v", p, err)
		}
		closers = append(closers, func() { _ = l.Close() })
	}
	if len(closers) == 0 {
		t.Fatal("no probes placed")
	}
	for _, c := range closers {
		c()
	}
}

// TestIntegrationStopReadsTheLostCounterLast is Stop's last poll of the kernel's drop counter: chunks the
// kernel could not reserve since the last poll must reach the gap report, so the counter has to be read
// before it is closed. Closing it with the ring made that read fail ("bad file descriptor"), and the drops
// of a run's last poll window became a silence where §8 I7 requires ring-buffer-drop.
func TestIntegrationStopReadsTheLostCounterLast(t *testing.T) {
	requireObjects(t)
	requireRoot(t)
	const hash = "integration"
	root, maps := bpffsPinRoot(t, hash)
	cg := selfCgroupID(t)
	seedRunSet(t, maps, map[uint64]uint32{cg: 1})
	u, err := New(Options{Kernel: true, PinRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	u.FollowKernel(hash)
	if err := u.Start(context.Background(), source.RunRef{ID: "r-int-lost", Agent: "a", CgroupID: cg}, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	if gaps := u.Gaps(); len(gaps) != 0 {
		t.Fatalf("the source did not come up: %+v", gaps)
	}
	lost, err := ebpf.LoadPinnedMap(filepath.Join(maps, LostMapName), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lost.Close()
	if err := lost.Update(uint32(1), uint64(3), ebpf.UpdateAny); err != nil {
		t.Fatalf("count three drops: %v", err)
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := gapCount(u.Gaps(), GapRingBufferDrop); got != 3 {
		t.Fatalf("ring-buffer-drop = %d after Stop, want the 3 drops of the last window: %+v", got, u.Gaps())
	}
}

// TestIntegrationRecordDropsAreNotCaptures: on a real kernel, the kernel record's lost counter,
// tego_lost, is bumped while a source runs, and the source reports no ring-buffer-drop, because capture's
// reserve failures are counted in its own tego_capture_lost. The two mechanisms shared tego_lost, so each
// reported the other's drops as a gap of its own.
func TestIntegrationRecordDropsAreNotCaptures(t *testing.T) {
	requireObjects(t)
	requireRoot(t)
	const hash = "integration"
	root, maps := bpffsPinRoot(t, hash)
	cg := selfCgroupID(t)
	seedRunSet(t, maps, map[uint64]uint32{cg: 1})
	u, err := New(Options{Kernel: true, PinRoot: root, Preattach: func() []string { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	u.FollowKernel(hash)
	if err := u.Start(context.Background(), source.RunRef{ID: "r-int-h10", Agent: "a", CgroupID: cg}, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	if gaps := u.Gaps(); len(gaps) != 0 {
		t.Fatalf("the source did not come up: %+v", gaps)
	}
	record, err := ebpf.LoadPinnedMap(filepath.Join(maps, bpf.MapLost), nil)
	if err != nil {
		t.Fatalf("the record's lost counter is not pinned beside capture's: %v", err)
	}
	defer record.Close()
	if err := record.Update(uint32(1), uint64(5), ebpf.UpdateAny); err != nil {
		t.Fatalf("count five record drops: %v", err)
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := gapCount(u.Gaps(), GapRingBufferDrop); got != 0 {
		t.Fatalf("ring-buffer-drop = %d after the kernel record lost 5 samples and capture lost none", got)
	}
}

// captureClient is a CPython TLS client in the shape R4 has to handle: `import ssl` is what loads _ssl and
// with it libssl, so at the exec the process maps no libssl at all. It stops twice on stdin so the test can
// hand the source the exec and then the library's open at the points the kernel record would.
const captureClient = `import sys
print("started", flush=True); sys.stdin.readline()
import socket, ssl
print("ready", flush=True); sys.stdin.readline()
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
body = b'{"model":"opus"}\n'
with socket.create_connection(("127.0.0.1", int(sys.argv[1]))) as raw:
    with ctx.wrap_socket(raw, server_hostname="api.anthropic.com") as s:
        s.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\n"
                  b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        data = b""
        while not (b"\r\n\r\n" in data and data.endswith(b"\n")):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
print("done", len(data), flush=True)
`

// captureResponse is what the in-process server answers.
const captureResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nRequest-Id: req_int\r\n" +
	"Content-Length: 22\r\n\r\n{\"id\":\"msg_01\",\"x\":1}\n"

// TestIntegrationCapturesAPythonExchange is the uprobe half of kill test 2 on one exchange, in the shape
// production runs it (Options.Kernel): the source loads the capture object under a build's pins, a real
// CPython client in this test's cgroup — the cgroup in the run set — talks TLS to a server over loopback,
// and the plaintext comes back as one ssl_request and one ssl_response. The server is crypto/tls in this
// process, which maps no libssl, so the only probes that fire are the client's.
//
// OnExec and OnOpen are called where the kernel record would call them: at the exec, which sees no libssl,
// and at the open of libssl.so.3 that `import ssl` makes. No gap may be left for the client. Pre-attach is
// off here, so the probes are the ones the open places: that is R4's path for a libssl pre-attach does not
// name, and TestIntegrationPreattachCapturesTheFirstRequest is the one for the host's own.
func TestIntegrationCapturesAPythonExchange(t *testing.T) {
	requireObjects(t)
	requireRoot(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	const hash = "integration"
	root, maps := bpffsPinRoot(t, hash)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	served := make(chan error, 1)
	go func() { served <- serveOne(ln) }()

	cg := selfCgroupID(t)
	// The run set the probes filter on (R9) and the source scopes itself by: this test's own cgroup,
	// inserted as Prepare inserts a run's, before the source starts.
	seedRunSet(t, maps, map[uint64]uint32{cg: 1})
	u, err := New(Options{Kernel: true, PinRoot: root, Preattach: func() []string { return nil }, Logger: testLogger(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	u.FollowKernel(hash)
	sink := &fakeSink{}
	if err := u.Start(context.Background(), source.RunRef{ID: "r-int-capture", Agent: "a", CgroupID: cg}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = u.Stop() })
	if gaps := u.Gaps(); len(gaps) != 0 {
		t.Fatalf("the source did not come up: %+v", gaps)
	}

	port := ln.Addr().(*net.TCPAddr).Port
	cmd := exec.Command(python, "-c", captureClient, strconv.Itoa(port))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start python3: %v", err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	out := bufio.NewReader(stdoutPipe)
	expect := func(want string) string {
		t.Helper()
		line, err := out.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, want) {
			t.Fatalf("python3 said %q (%v), want %q", line, err, want)
		}
		return line
	}
	pid := cmd.Process.Pid

	expect("started")
	u.OnExec(pid, cg, "")
	if _, err := io.WriteString(stdin, "\n"); err != nil {
		t.Fatal(err)
	}
	expect("ready")
	lib := mappedLibssl(t, pid)
	u.OnOpen(pid, cg, lib)
	if u.cache.size() != 1 {
		t.Fatalf("the open of %s attached nothing; gaps %+v", lib, u.Gaps())
	}
	if _, err := io.WriteString(stdin, "\n"); err != nil {
		t.Fatal(err)
	}
	t.Logf("python3: %s", strings.TrimSpace(expect("done")))
	if err := <-served; err != nil {
		t.Fatalf("server: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("python3: %v", err)
	}
	u.OnExit(pid)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && len(sink.events()) < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	evs := sink.events()
	var req, resp *record.Event
	for _, ev := range evs {
		switch ev.Kind {
		case record.KindSSLRequest:
			req = ev
		case record.KindSSLResponse:
			resp = ev
		}
	}
	if req == nil || resp == nil {
		t.Fatalf("events %+v, want one ssl_request and one ssl_response; gaps %+v", evs, u.Gaps())
	}
	var rp record.SSLRequestPayload
	if err := json.Unmarshal(req.Payload, &rp); err != nil {
		t.Fatal(err)
	}
	if rp.Method != "POST" || rp.Path != "/v1/messages" || rp.Host != "api.anthropic.com" || rp.Size != 17 {
		t.Errorf("ssl_request payload %+v", rp)
	}
	var sp record.SSLResponsePayload
	if err := json.Unmarshal(resp.Payload, &sp); err != nil {
		t.Fatal(err)
	}
	if sp.Status != 200 || sp.RequestID != "req_int" {
		t.Errorf("ssl_response payload %+v", sp)
	}
	if req.PID != pid || req.Cgroup != cg || req.Source != record.SourceSSL {
		t.Errorf("ssl_request stamped pid %d cgroup %d source %s, want %d %d %s", req.PID, req.Cgroup, req.Source,
			pid, cg, record.SourceSSL)
	}
	if gaps := u.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps %+v for a client whose exchange was captured", gaps)
	}
	if n := u.cache.size(); n != 0 {
		t.Errorf("%d binaries still attached after Stop (I9)", n)
	}
}

// eagerClient is a CPython TLS client with no pause at all: its first SSL_write comes straight after the
// `import ssl` that loads libssl, which is kill test 2's agent in the shape that lost its first request on
// the 6.1 and 6.12 kernels of the matrix, when the probes went on at the open.
const eagerClient = `import socket, ssl, sys
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
body = b'{"model":"opus"}\n'
with socket.create_connection(("127.0.0.1", int(sys.argv[1]))) as raw:
    with ctx.wrap_socket(raw, server_hostname="api.anthropic.com") as s:
        s.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\n"
                  b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        data = b""
        while not (b"\r\n\r\n" in data and data.endswith(b"\n")):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
print("done", len(data), flush=True)
`

// conversationClient is CPython in shapes that used to lose capture: a request body over R6's 128 KiB
// handed to one SSL_write_ex (C2), several exchanges on a keep-alive connection after it, and a second
// connection after the first is closed, whose SSL_free the probe reports (C4), glibc free to hand the new
// SSL_new the old address.
const conversationClient = `import socket, ssl, sys
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
port = int(sys.argv[1])
def exchange(s, body):
    s.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\n"
              b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    data = b""
    while b"\r\n\r\n" not in data:
        data += s.recv(65536)
    head, _, rest = data.partition(b"\r\n\r\n")
    n = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            n = int(line.split(b":")[1])
    while len(rest) < n:
        rest += s.recv(65536)
big = b'{"model":"opus","messages":[' + b'{"role":"user","content":"x"},' * 10000 + b'{}]}'
for conn in range(2):
    with socket.create_connection(("127.0.0.1", port)) as raw:
        with ctx.wrap_socket(raw, server_hostname="api.anthropic.com") as s:
            if conn == 0:
                exchange(s, big)
            exchange(s, b'{"model":"opus"}')
            exchange(s, b'{"model":"opus"}')
print("done", len(big), flush=True)
`

// TestIntegrationLongConversationAndReusedConnections runs conversationClient against a keep-alive HTTP/1.1
// server as root: every exchange is recorded, the one over 128 KiB as its prefix with the connection going on
// after it (the kernel naming the tail it dropped), the chunks numbered by the kernel pair as they
// should (C3), and both connections are over once the client has freed them (C4, SSL_free's close record).
func TestIntegrationLongConversationAndReusedConnections(t *testing.T) {
	requireObjects(t)
	requireRoot(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	if len(systemLibraries("/", nil)) == 0 {
		t.Skip("this host has no libssl for pre-attach to find")
	}
	const hash = "integration"
	root, maps := bpffsPinRoot(t, hash)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		body := fmt.Sprintf(`{"id":"msg_%d","read":%d}`, n, n)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = io.WriteString(w, body)
	}), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	cg := selfCgroupID(t)
	seedRunSet(t, maps, map[uint64]uint32{cg: 1})
	u, err := New(Options{Kernel: true, PinRoot: root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	u.FollowKernel(hash)
	sink := &fakeSink{}
	if err := u.Start(context.Background(), source.RunRef{ID: "r-int-conversation", Agent: "a", CgroupID: cg}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = u.Stop() })
	if u.cache.size() == 0 {
		t.Fatalf("Start pre-attached nothing; gaps %+v", u.Gaps())
	}
	out, err := exec.Command(python, "-c", conversationClient, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)).CombinedOutput()
	if err != nil {
		t.Fatalf("python3: %v: %s", err, out)
	}
	t.Logf("python3: %s", strings.TrimSpace(string(out)))
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && (len(sink.events()) < 10 || u.asm.Conns() != 0) {
		time.Sleep(10 * time.Millisecond)
	}
	conns := u.asm.Conns()
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	var reqs []record.SSLRequestPayload
	var resps int
	for _, ev := range sink.events() {
		switch ev.Kind {
		case record.KindSSLRequest:
			var p record.SSLRequestPayload
			if err := json.Unmarshal(ev.Payload, &p); err != nil {
				t.Fatal(err)
			}
			reqs = append(reqs, p)
		case record.KindSSLResponse:
			resps++
		}
	}
	if len(reqs) != 5 || resps != 5 {
		t.Fatalf("%d requests and %d responses, want 5 exchanges on two connections; gaps %+v", len(reqs), resps, u.Gaps())
	}
	if reqs[0].Size >= 300_000 || reqs[0].Size < 64<<10 {
		t.Errorf("the request over 128 KiB was recorded as %d bytes, want the prefix before the hole", reqs[0].Size)
	}
	if conns != 0 {
		t.Errorf("%d connections still open after the client freed both: no SSL_free record reached the reader", conns)
	}
	if gaps := u.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps %+v", gaps)
	}
}

// TestIntegrationPreattachCapturesTheFirstRequest is R4's pre-attach on a real kernel: Start places the
// probes on the host's libssl before the client exists, so the client's first request is captured with no
// OnExec and no OnOpen at all, which is the limit of a kernel record whose drain of the open, and an attach
// after it, come later than the client's first SSL_write. Without the pre-attach nothing places a probe here
// and the ring stays empty.
func TestIntegrationPreattachCapturesTheFirstRequest(t *testing.T) {
	requireObjects(t)
	requireRoot(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	if len(systemLibraries("/", nil)) == 0 {
		t.Skip("this host has no libssl for pre-attach to find")
	}
	const hash = "integration"
	root, maps := bpffsPinRoot(t, hash)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	served := make(chan error, 1)
	go func() { served <- serveOne(ln) }()

	cg := selfCgroupID(t)
	seedRunSet(t, maps, map[uint64]uint32{cg: 1})
	u, err := New(Options{Kernel: true, PinRoot: root, Logger: testLogger(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	u.FollowKernel(hash)
	sink := &fakeSink{}
	if err := u.Start(context.Background(), source.RunRef{ID: "r-int-preattach", Agent: "a", CgroupID: cg}, sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = u.Stop() })
	if gaps := u.Gaps(); len(gaps) != 0 {
		t.Fatalf("the source did not come up: %+v", gaps)
	}
	if u.cache.size() == 0 {
		t.Fatalf("Start pre-attached nothing; the host's libssl is %q", systemLibraries("/", nil))
	}

	out, err := exec.Command(python, "-c", eagerClient, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)).CombinedOutput()
	if err != nil {
		t.Fatalf("python3: %v: %s", err, out)
	}
	if err := <-served; err != nil {
		t.Fatalf("server: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && len(sink.events()) < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	var kinds []record.Kind
	for _, ev := range sink.events() {
		kinds = append(kinds, ev.Kind)
	}
	if len(kinds) != 2 || kinds[0] != record.KindSSLRequest || kinds[1] != record.KindSSLResponse {
		t.Fatalf("events %v, want the client's first request and its response; gaps %+v", kinds, u.Gaps())
	}
	if gaps := u.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps %+v for a client whose exchange was captured", gaps)
	}
	if n := u.cache.size(); n != 0 {
		t.Errorf("%d binaries still attached after Stop (I9)", n)
	}
}

// TestIntegrationARunWithoutACaptureRingDoesNotCapture: a run the tier-2 backend gave no capture ring (the host's
// bpf.ring_budget had no room for it) has nothing to read. Its Kernel-mode source loads nothing and attaches
// nothing, says mechanism-unavailable, and names the budget in its cause, which the runtime's refusal of a
// budgeted run carries (limits-check-doctor-cli R32).
func TestIntegrationARunWithoutACaptureRingDoesNotCapture(t *testing.T) {
	requireObjects(t)
	requireRoot(t)
	const hash = "integration"
	root, maps := bpffsPinRoot(t, hash)
	cg := selfCgroupID(t)
	seedRuns(t, maps, map[uint64]uint32{cg: 1}, map[uint32]bool{1: true})
	u, err := New(Options{Kernel: true, PinRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	u.FollowKernel(hash)
	if err := u.Start(context.Background(), source.RunRef{ID: "r-int-noring", Agent: "a", CgroupID: cg}, &fakeSink{}); err != nil {
		t.Fatalf("Start failed the run: %v", err)
	}
	defer u.Stop()
	gaps := u.Gaps()
	if len(gaps) != 1 || gaps[0].Why != GapMechanismUnavailable || gaps[0].Binary != Name {
		t.Fatalf("gaps %+v, want mechanism-unavailable binary=%s", gaps, Name)
	}
	if !strings.Contains(u.UnavailableCause(), "bpf.ring_budget") {
		t.Errorf("cause %q does not name the ring budget", u.UnavailableCause())
	}
	if u.opts.Attacher != nil || len(u.kernel) != 0 {
		t.Error("a source with no ring holds a collection or an attacher")
	}
}

// offRunClient is a CPython client that makes one TLS exchange at once, through the host's libssl.
const offRunClient = `import socket, ssl, sys
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
body = b'{"model":"opus"}\n'
with socket.create_connection(("127.0.0.1", int(sys.argv[1]))) as raw:
    with ctx.wrap_socket(raw, server_hostname="api.anthropic.com") as s:
        s.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\n"
                  b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        data = b""
        while not (b"\r\n\r\n" in data and data.endswith(b"\n")):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
`

// TestIntegrationACaptureOffRunBesideACaptureRunLeavesNoChunk is ADR 0026 (3) on a real kernel: the probes a
// capture run places on the host's libssl fire for every process of the build's run set, a capture: off run's
// too, and that run has no capture ring. Its client's exchange leaves no chunk on any ring: the capture run
// records its own exchange alone, and the probes count the off run's calls as misses at its slot.
func TestIntegrationACaptureOffRunBesideACaptureRunLeavesNoChunk(t *testing.T) {
	requireObjects(t)
	requireRoot(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	if len(systemLibraries("/", nil)) == 0 {
		t.Skip("this host has no libssl for pre-attach to find")
	}
	const hash = "integration"
	root, maps := bpffsPinRoot(t, hash)
	onDir, onFD, onID := childCgroupOf(t, "on")
	_, offFD, offID := childCgroupOf(t, "off")
	seedRuns(t, maps, map[uint64]uint32{onID: 1, offID: 2}, map[uint32]bool{2: true})
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	served := make(chan error, 2)
	go func() { served <- serveOne(ln) }()
	go func() { served <- serveOne(ln) }()

	u, err := New(Options{Kernel: true, PinRoot: root, StateDir: t.TempDir(), Logger: testLogger(t)})
	if err != nil {
		t.Fatal(err)
	}
	u.FollowKernel(hash)
	sink := &fakeSink{}
	if err := u.Start(context.Background(), source.RunRef{ID: "r-int-on", Agent: "a", CgroupID: onID}, sink); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = u.Stop() })
	if gaps := u.Gaps(); len(gaps) != 0 {
		t.Fatalf("the capture run's source did not come up: %+v", gaps)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	for _, fd := range []int{offFD, onFD} {
		cmd := exec.Command(python, "-c", offRunClient, port)
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("python3: %v: %s", err, out)
		}
	}
	for range 2 {
		if err := <-served; err != nil {
			t.Fatalf("server: %v", err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && len(sink.events()) < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	evs := sink.events()
	if len(evs) != 2 {
		t.Fatalf("%d events, want the capture run's one exchange: %+v", len(evs), evs)
	}
	for _, ev := range evs {
		if ev.Cgroup != onID {
			t.Errorf("the capture run recorded %s of cgroup %d, the capture: off run's", ev.Kind, ev.Cgroup)
		}
	}
	miss, err := ebpf.LoadPinnedMap(filepath.Join(maps, bpf.MapCaptureMiss), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer miss.Close()
	if n, err := bpf.SlotCount(miss, 2); err != nil || n == 0 {
		t.Errorf("misses at the capture: off run's slot = %d, %v: its TLS calls never met the probes", n, err)
	}
	_ = onDir
}

// childCgroupOf makes a cgroup under this process's own, named with suffix, and returns its path, an O_PATH
// descriptor for CLONE_INTO_CGROUP and its id.
func childCgroupOf(t *testing.T, suffix string) (string, int, uint64) {
	t.Helper()
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	var rel string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			rel = p
		}
	}
	if rel == "" {
		t.Skip("not on a cgroup v2 hierarchy")
	}
	dir := filepath.Join("/sys/fs/cgroup", rel, "tego-uprobe-test-"+strconv.Itoa(os.Getpid())+"-"+suffix)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Skipf("cannot make a child cgroup: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	return dir, fd, st.Ino
}

// serveOne answers one HTTP/1.1 request over TLS with captureResponse.
func serveOne(ln net.Listener) error {
	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	r := bufio.NewReader(conn)
	length := 0
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read request head: %w", err)
		}
		if line == "\r\n" {
			break
		}
		if v, ok := strings.CutPrefix(strings.ToLower(line), "content-length:"); ok {
			length, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
	if _, err := io.CopyN(io.Discard, r, int64(length)); err != nil {
		return fmt.Errorf("read request body: %w", err)
	}
	_, err = io.WriteString(conn, captureResponse)
	return err
}

// selfSigned is a throwaway server certificate.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "api.anthropic.com"},
		DNSNames:     []string{"api.anthropic.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// selfCgroupID is this process's cgroup v2 id: the inode number of its cgroup directory, which is what
// bpf_get_current_cgroup_id returns.
func selfCgroupID(t *testing.T) uint64 {
	t.Helper()
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	var rel string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			rel = p
		}
	}
	if rel == "" {
		t.Skip("not on a cgroup v2 hierarchy")
	}
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join("/sys/fs/cgroup", rel), &st); err != nil {
		t.Fatalf("stat this process's cgroup: %v", err)
	}
	return st.Ino
}

// mappedLibssl is the libssl a live process maps, as its own maps name it.
func mappedLibssl(t *testing.T, pid int) string {
	t.Helper()
	libs, err := proc.New().Libraries(pid)
	if err != nil {
		t.Fatalf("maps of %d: %v", pid, err)
	}
	for _, l := range libs {
		if libsslName.MatchString(filepath.Base(l)) {
			return l
		}
	}
	t.Fatalf("pid %d maps no libssl after `import ssl`: %v", pid, libs)
	return ""
}

// systemLibssl finds this host's libssl through the running process's own mappings, which is the same
// path R4 takes at runtime.
func systemLibssl(t *testing.T) string {
	t.Helper()
	path, err := findSystemLibssl()
	if err != nil {
		t.Skipf("no libssl on this host: %v", err)
	}
	return path
}

// findSystemLibssl is systemLibssl's search.
func findSystemLibssl() (string, error) {
	libs, err := proc.New().Libraries(os.Getpid())
	if err == nil {
		for _, l := range libs {
			if libsslName.MatchString(filepath.Base(l)) {
				return l, nil
			}
		}
	}
	// The test binary is static Go and maps no libssl of its own. It reads the loader cache and the default
	// library directories as pre-attach does (systemLibraries), not `ldconfig -p`: /sbin is not on a
	// non-root user's PATH.
	if found := systemLibraries("", nil); len(found) > 0 {
		return found[0], nil
	}
	return "", errors.New("neither /etc/ld.so.cache nor a default library directory names a native libssl")
}

// TestSystemLibsslIgnoresPATH: the host's libssl is found whatever PATH holds. A PATH without /sbin, a
// non-root user's usual one, hid ldconfig from the old search, and every test that needs the host's libssl
// skipped on a host that has one. The loader cache is the source of truth, as for pre-attach (R7).
func TestSystemLibsslIgnoresPATH(t *testing.T) {
	data, err := os.ReadFile("/etc/ld.so.cache")
	if err != nil || !bytes.Contains(data, []byte("libssl.so.")) {
		t.Skip("this host's loader cache names no libssl")
	}
	t.Setenv("PATH", "/nonexistent")
	path, err := findSystemLibssl()
	if err != nil {
		t.Fatalf("the loader cache names a libssl and, with PATH=/nonexistent, none was found: %v", err)
	}
	t.Logf("found %s", path)
}

// TestReadSystemLibssl needs no privilege at all: it asserts that the symbol rules of R1-R3 make sense
// against whatever OpenSSL this host actually ships, which is the check most likely to catch a real
// upstream change.
func TestReadSystemLibssl(t *testing.T) {
	path := systemLibssl(t)
	bin, err := readBinary(path)
	if err != nil {
		if errors.Is(err, ErrNoSymbols) {
			t.Skipf("%s exports no OpenSSL symbols (a stripped or non-OpenSSL TLS build)", path)
		}
		t.Fatalf("readBinary(%s): %v", path, err)
	}
	writes := bin.WriteSymbols()
	if len(writes) == 0 {
		t.Fatalf("%s exports no write entry point", path)
	}
	if len(writes) > 2 {
		t.Errorf("%d write hooks, want at most SSL_write plus one _ex variant (R2): %v", len(writes), writes)
	}
	for _, s := range writes {
		if bin.Offsets[s] == 0 {
			t.Errorf("%s resolved to offset 0", s)
		}
	}
	t.Logf("%s: build id %q, writes %v, reads %v", path, bin.BuildID, writes, bin.ReadSymbols())
}

// testLogger sends the source's debug lines, which carry each gap's detail, to the test's log: a gap is
// otherwise only its reason and count, and a failure seen only on the CI runner (a malformed gap for a
// captured exchange, Python 3.12 and OpenSSL 3.0) could not say which rule fired.
func testLogger(t *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(tLogWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// tLogWriter is an io.Writer onto t.Log.
type tLogWriter struct{ t *testing.T }

func (w tLogWriter) Write(p []byte) (int, error) {
	w.t.Helper()
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
