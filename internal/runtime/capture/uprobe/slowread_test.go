// SPDX-License-Identifier: Apache-2.0

//go:build integration

package uprobe

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// keepAliveClient makes three exchanges on one TLS connection, the request bodies "1", "22" and "333",
// printing each response body and "done". Before each request it prints "sending <n>".
const keepAliveClient = `import socket, ssl, sys
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
port = int(sys.argv[1])
def exchange(s, body):
    print("sending", len(body), flush=True)
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
    return rest
with socket.create_connection(("127.0.0.1", port)) as raw:
    with ctx.wrap_socket(raw, server_hostname="api.anthropic.com") as s:
        print(exchange(s, b'1'), flush=True)
        print(exchange(s, b'22'), flush=True)
        print(exchange(s, b'333'), flush=True)
print("done", flush=True)
`

// keepAliveServer answers each request with request-id req_<body length>, after hold(body length) returns.
func keepAliveServer(t *testing.T, hold func(n int64)) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tln := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		hold(n)
		body := fmt.Sprintf(`{"id":"msg_%d"}`, n)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("request-id", fmt.Sprintf("req_%d", n))
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = io.WriteString(w, body)
	})}
	go func() { _ = srv.Serve(tln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// startKeepAliveCapture starts a kernel-mode source on a run's cgroup (runCgroup) and returns it with its sink,
// the pinned maps directory and the descriptor that starts the client in the run's cgroup (inRun).
func startKeepAliveCapture(t *testing.T) (*Uprobe, *fakeSink, string, int) {
	t.Helper()
	requireObjects(t)
	requireRoot(t)
	if len(systemLibraries("/", nil)) == 0 {
		t.Skip("no libssl")
	}
	const hash = "integration"
	root, maps := bpffsPinRoot(t, hash)
	cgFD, cg := runCgroup(t)
	seedRunSet(t, maps, map[uint64]uint32{cg: 1})
	u, err := New(Options{Kernel: true, PinRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	u.FollowKernel(hash)
	sink := &fakeSink{}
	if err := u.Start(context.Background(), source.RunRef{ID: "r-slow", Agent: "a", CgroupID: cg}, sink); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = u.Stop() })
	return u, sink, maps, cgFD
}

// pairedResponses maps each ssl_response's request_id to the size of the ssl_request it was paired with (Pair),
// or -1 for a response paired with no request line.
func pairedResponses(t *testing.T, sink *fakeSink) map[string]int {
	t.Helper()
	sizes := map[uint64]int{}
	for _, ev := range sink.events() {
		if ev.Kind == record.KindSSLRequest {
			var p record.SSLRequestPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			sizes[ev.Pair] = p.Size
		}
	}
	out := map[string]int{}
	for _, ev := range sink.events() {
		if ev.Kind != record.KindSSLResponse {
			continue
		}
		var p record.SSLResponsePayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		size, ok := sizes[ev.Pair]
		if !ok || ev.Pair == 0 {
			size = -1
		}
		out[p.RequestID] = size
		t.Logf("response %s paired with the request of %d bytes, latency_ms=%d", p.RequestID, size, p.LatencyMS)
	}
	return out
}

// TestIntegrationSlowFirstByteKeepsPairing: a response whose first byte comes 62 s after its request, as a
// long non-streaming completion's does, is captured and paired with its own request, and the two exchanges
// after it on the same keep-alive connection with theirs. Under the old 60 s bound on a read's entry to its
// return, the kernel dropped that read with no number and no record, and request 1 was paired with response 2.
func TestIntegrationSlowFirstByteKeepsPairing(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	u, sink, _, cgFD := startKeepAliveCapture(t)
	port := keepAliveServer(t, func(n int64) {
		if n == 1 {
			time.Sleep(62 * time.Second)
		}
	})
	out, err := inRun(exec.Command(python, "-c", keepAliveClient, strconv.Itoa(port)), cgFD).CombinedOutput()
	if err != nil {
		t.Fatalf("python3: %v: %s", err, out)
	}
	time.Sleep(2 * time.Second)
	if err := u.Stop(); err != nil {
		t.Fatal(err)
	}
	got := pairedResponses(t, sink)
	want := map[string]int{"req_1": 1, "req_2": 2, "req_3": 3}
	if len(got) != len(want) {
		t.Errorf("responses %v, want %v", got, want)
	}
	for id, size := range want {
		if got[id] != size {
			t.Errorf("response %s paired with the request of %d bytes, want %d", id, got[id], size)
		}
	}
	if gaps := u.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps %+v for three whole exchanges", gaps)
	}
}

// TestIntegrationStaleReadIsAGap: a read whose scratch row is older than bpf.SSLMaxCallNS — a row whose own
// return was missed, or one a reused pid inherited — is emitted by the kernel as a numbered stale hole, not
// dropped (edge case #3). The test ages the row of the client's read of response 1 while the server holds the
// response back; the source records gap why=size-cap for it, and the two later exchanges on the connection
// are each paired with their own request. Dropped with no number, response 2 was paired with request 1.
func TestIntegrationStaleReadIsAGap(t *testing.T) {
	unreadReadIsAGap(t, func(m *ebpf.Map, k bpf.SSLKey, v bpf.SSLScratch) error {
		// Older than any bound as the probe computes it (now - enter_ns, unsigned). A guest booted a minute
		// ago has no timestamp 30 minutes back, so the row is set half the clock's range away instead, which
		// the subtraction reads as that far in the past.
		v.EnterNS = 1 << 63
		return m.Update(&k, &v, ebpf.UpdateExist)
	})
}

// TestIntegrationEvictedReadIsAGap: a read whose scratch row the LRU evicted before it returned (R5) is a
// numbered hole too, never a dropped read: the test deletes the row of the client's read of response 1, as an
// eviction under a burst would, and the source records gap why=size-cap and pairs the later exchanges with
// their own requests.
func TestIntegrationEvictedReadIsAGap(t *testing.T) {
	unreadReadIsAGap(t, func(m *ebpf.Map, k bpf.SSLKey, _ bpf.SSLScratch) error { return m.Delete(&k) })
}

// unreadReadIsAGap runs three exchanges on one keep-alive connection, applies mutate to the scratch row of the
// client's read of response 1 while the server holds that response back, and checks that response 1 is a
// size-cap gap and responses 2 and 3 are paired with their own requests.
func unreadReadIsAGap(t *testing.T, mutate func(m *ebpf.Map, k bpf.SSLKey, v bpf.SSLScratch) error) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	u, sink, maps, cgFD := startKeepAliveCapture(t)
	got1 := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	port := keepAliveServer(t, func(n int64) {
		if n == 1 {
			once.Do(func() { close(got1) })
			<-release
		}
	})
	cmd := inRun(exec.Command(python, "-c", keepAliveClient, strconv.Itoa(port)), cgFD)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start python3: %v", err)
	}
	lines := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	select {
	case <-got1:
	case <-time.After(30 * time.Second):
		close(release)
		t.Fatalf("the server never saw request 1; python3: %s", stderr.String())
	}
	// The client is in SSL_read for response 1 once the server has its request; give it the moment to get there.
	time.Sleep(500 * time.Millisecond)
	scratch, err := ebpf.LoadPinnedMap(filepath.Join(maps, bpf.MapSSLScratch), nil)
	if err != nil {
		close(release)
		t.Fatalf("open %s: %v", bpf.MapSSLScratch, err)
	}
	defer scratch.Close()
	changed := 0
	var (
		key bpf.SSLKey
		val bpf.SSLScratch
	)
	it := scratch.Iterate()
	var keys []bpf.SSLKey
	for it.Next(&key, &val) {
		if uint32(key.PidTgid>>32) == uint32(cmd.Process.Pid) {
			keys = append(keys, key)
		}
	}
	for _, k := range keys {
		if err := scratch.Lookup(&k, &val); err != nil {
			continue
		}
		if err := mutate(scratch, k, val); err == nil {
			changed++
		}
	}
	close(release)
	if changed == 0 {
		t.Fatalf("no in-flight read of pid %d in %s to change", cmd.Process.Pid, bpf.MapSSLScratch)
	}
	var said []string
	for l := range lines {
		said = append(said, l)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("python3: %v: %s %s", err, said, stderr.String())
	}
	time.Sleep(2 * time.Second)
	if err := u.Stop(); err != nil {
		t.Fatal(err)
	}
	got := pairedResponses(t, sink)
	if _, ok := got["req_1"]; ok {
		t.Errorf("response 1, whose read was stale, was recorded: %v", got)
	}
	for id, size := range map[string]int{"req_2": 2, "req_3": 3} {
		if got[id] != size {
			t.Errorf("response %s paired with the request of %d bytes, want %d: %v", id, got[id], size, got)
		}
	}
	if n := gapCount(u.Gaps(), GapSizeCap); n < 1 {
		t.Errorf("no gap why=size-cap for the stale read (edge case #3): %+v", u.Gaps())
	}
}
