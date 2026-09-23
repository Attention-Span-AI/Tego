// SPDX-License-Identifier: Apache-2.0

//go:build integration

package observe

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/capture/uprobe"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// kernelClient is the agent of TestIntegrationKernelRecordDrivesCapture: a read, an exec and a write the
// record must carry with source=kernel, then one TLS exchange over CPython's ssl, which loads libssl only
// at `import ssl`. The pause after the import stands for the work an agent does before its first request;
// the attach the library's open triggers is asynchronous to the process (capture-derive.md R4).
const kernelClient = `import os, subprocess, sys, time
open("/etc/hostname").read()
subprocess.run(["true"], check=True)
with open(os.path.join(sys.argv[2], "result.txt"), "w") as f:
    f.write("x\n")
import socket, ssl
time.sleep(0.5)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
body = b'{"model":"opus"}\n'
with socket.create_connection(("127.0.0.1", int(sys.argv[1]))) as raw:
    with ctx.wrap_socket(raw, server_hostname="api.anthropic.com") as s:
        s.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: "
                  + str(len(body)).encode() + b"\r\n\r\n" + body)
        data = b""
        while not (b"\r\n\r\n" in data and data.endswith(b"\n")):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
print("done", len(data), flush=True)
`

// TestIntegrationKernelRecordDrivesCapture is the tier-2 record and the uprobe wiring together, on the real
// objects, as root: the trace_proc programs loaded and pinned the way the tier-2 loader pins them and
// attached host-wide, one cgroup in the run set, a recorder opened from the pins by BPFHash, and a uprobe
// source in Kernel mode fed only by that recorder's process hook — nothing in the test calls OnExec or
// OnOpen. A CPython child in the run's cgroup must come out as source=kernel exec and fs events, and its
// TLS exchange as an ssl_request and ssl_response.
func TestIntegrationKernelRecordDrivesCapture(t *testing.T) {
	if !bpf.Available() {
		t.Skipf("needs the compiled objects: %v", bpf.ErrNotGenerated)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	const hash = "kernel0"
	root, maps := pinRoot(t, hash)
	coll := loadTraceProc(t, maps)

	// The run's cgroup: a child of this test's own, so the test process itself is not in the run set and
	// the launcher-side opens the capture source makes are not fed back to it.
	cgDir, cgFD, cgID := childCgroup(t, "run")
	row := bpf.Run{RunIdx: 1, Descendants: 1, Tier: 2, Record: uint8(bpf.RecordFull)}
	placeRunRings(t, coll, row.RunIdx)
	if err := coll.Maps[bpf.MapRunSet].Update(&cgID, &row, ebpf.UpdateAny); err != nil {
		t.Fatalf("insert the run's cgroup into the run set: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{throwawayCert(t)}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	served := make(chan error, 1)
	go func() { served <- answerOne(ln) }()

	run := source.RunRef{ID: "r-int-kernel", Agent: "a", CgroupID: cgID}
	sink := &fakeSink{}
	logger := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	up, err := uprobe.New(uprobe.Options{Kernel: true, PinRoot: root, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := New(Options{
		Rules:   &agent.RuleTable{Record: agent.RecordFull, Tier: backend.TierCgroup, Capture: agent.CaptureUprobe},
		BPFHash: hash, PinRoot: root, FlushInterval: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New over the loader's pins: %v", err)
	}
	// What runtime.followKernelRecord does, in the order it does it.
	if err := rec.AddProcessHook(up); err != nil {
		t.Fatal(err)
	}
	up.FollowKernel(hash)
	ctx := context.Background()
	if err := up.Start(ctx, run, sink); err != nil {
		t.Fatal(err)
	}
	defer up.Stop()
	if err := rec.Start(ctx, run, sink); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()
	if gaps := up.Gaps(); len(gaps) != 0 {
		t.Fatalf("the capture source did not come up: %+v", gaps)
	}

	out := t.TempDir()
	if err := os.Chmod(out, 0o777); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "-c", kernelClient, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port), out)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: cgFD}
	cmd.Stderr = os.Stderr
	stdout, err := cmd.Output()
	if err != nil {
		t.Fatalf("python3 in the run's cgroup: %v", err)
	}
	t.Logf("python3: %s", strings.TrimSpace(string(stdout)))
	pid := cmd.Process.Pid
	if err := <-served; err != nil {
		t.Fatalf("server: %v", err)
	}

	byKind := func(k record.Kind) []*record.Event {
		var got []*record.Event
		for _, ev := range sink.all() {
			if ev.Kind == k {
				got = append(got, ev)
			}
		}
		return got
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && (len(byKind(record.KindSSLResponse)) == 0 || len(byKind(record.KindExec)) < 2) {
		time.Sleep(20 * time.Millisecond)
	}
	if err := rec.Stop(); err != nil {
		t.Fatalf("recorder Stop: %v", err)
	}
	if err := up.Stop(); err != nil {
		t.Fatalf("capture Stop: %v", err)
	}
	_ = os.Remove(cgDir)

	kinds := map[record.Kind]int{}
	for _, ev := range sink.all() {
		kinds[ev.Kind]++
	}
	t.Logf("events by kind %v; record gaps %+v", kinds, rec.Gaps())
	if hasWhy(rec.Gaps(), runtime.GapKernelRecordUnavailable) {
		t.Errorf("record gaps %+v: a run alone on its build did not read its ring", rec.Gaps())
	}
	for i, ev := range byKind(record.KindFS) {
		if i < 8 {
			t.Logf("fs pid %d rule %s verdict %s payload %s", ev.PID, ev.Rule, ev.Verdict, ev.Payload)
		}
	}
	execs := map[string]*record.Event{}
	for _, ev := range byKind(record.KindExec) {
		var p record.ExecPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatal(err)
		}
		execs[filepath.Base(p.Path)] = ev
		if ev.Source != record.SourceKernel || ev.Cgroup != cgID || ev.Run != run.ID {
			t.Errorf("exec %s stamped source %s cgroup %d run %s", p.Path, ev.Source, ev.Cgroup, ev.Run)
		}
	}
	var sawPython, sawTrue bool
	for base, ev := range execs {
		sawPython = sawPython || (strings.HasPrefix(base, "python3") && ev.PID == pid)
		sawTrue = sawTrue || base == "true"
	}
	if !sawPython || !sawTrue {
		t.Errorf("exec events %v, want the child's python3 (pid %d) and true", keys(execs), pid)
	}
	var sawWrite, sawRead bool
	for _, ev := range byKind(record.KindFS) {
		var p record.FSPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if ev.Source != record.SourceKernel {
			t.Errorf("fs event %+v has source %s", p, ev.Source)
		}
		sawWrite = sawWrite || p.Path == filepath.Join(out, "result.txt")
		sawRead = sawRead || (p.Path == "/etc/hostname" || p.Count > 0)
	}
	if !sawWrite || !sawRead {
		t.Errorf("fs events: write of result.txt %v, a read %v", sawWrite, sawRead)
	}
	reqs, resps := byKind(record.KindSSLRequest), byKind(record.KindSSLResponse)
	if len(reqs) != 1 || len(resps) != 1 {
		t.Fatalf("%d ssl_request and %d ssl_response, want one each; capture gaps %+v", len(reqs), len(resps), up.Gaps())
	}
	var rp record.SSLRequestPayload
	if err := json.Unmarshal(reqs[0].Payload, &rp); err != nil {
		t.Fatal(err)
	}
	if rp.Method != "POST" || rp.Path != "/v1/messages" || reqs[0].PID != pid {
		t.Errorf("ssl_request %+v from pid %d, want POST /v1/messages from %d", rp, reqs[0].PID, pid)
	}
	for _, g := range up.Gaps() {
		if strings.Contains(g.Binary, "python3") {
			t.Errorf("capture gap %+v for the python3 process whose exchange was captured", g)
		}
	}
	t.Logf("record gaps %+v, capture gaps %+v", rec.Gaps(), up.Gaps())
}

// sdkClient is kill test 7 (b)'s client in the run: the Anthropic Python SDK on system Python, whose httpx2
// transport speaks TLS through CPython's ssl and so through the system libssl. The certificate is the test's
// own, so verification is off; nothing else about the client is changed.
const sdkClient = `import ssl, sys
import anthropic, httpx2
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
client = anthropic.Anthropic(api_key="sk-ant-test", base_url="https://127.0.0.1:" + sys.argv[1],
                             http_client=httpx2.Client(verify=ctx), max_retries=0)
m = client.messages.create(model="claude-test", max_tokens=16, messages=[{"role": "user", "content": "hi"}])
print("done", m.id, anthropic.__version__, ssl.OPENSSL_VERSION, flush=True)
`

// sdkReply is a Messages API response the SDK parses.
const sdkReply = `{"id":"msg_sdk","type":"message","role":"assistant","model":"claude-test",` +
	`"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","stop_sequence":null,` +
	`"usage":{"input_tokens":3,"output_tokens":1}}`

// TestIntegrationKernelRecordCapturesTheAnthropicSDK is the acceptance client on this host's OpenSSL,
// wired as a run wires it: the Anthropic Python SDK (httpx2 over CPython's ssl) in the run's cgroup, the
// kernel record driving the uprobe source through its hook, and the exchange coming back as one
// ssl_request POST /v1/messages and one ssl_response 200. It needs the SDK the kill tests cache
// (test/e2e/pydeps.sh), named by TEGO_ANTHROPIC_SITE because the guest has no package index.
func TestIntegrationKernelRecordCapturesTheAnthropicSDK(t *testing.T) {
	if !bpf.Available() {
		t.Skipf("needs the compiled objects: %v", bpf.ErrNotGenerated)
	}
	site := os.Getenv("TEGO_ANTHROPIC_SITE")
	if site == "" {
		t.Skip("TEGO_ANTHROPIC_SITE names no Anthropic SDK site directory (test/e2e/pydeps.sh's anthropic-site)")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	const hash = "kernel2"
	root, maps := pinRoot(t, hash)
	coll := loadTraceProc(t, maps)
	cgDir, cgFD, cgID := childCgroup(t, "sdk")
	row := bpf.Run{RunIdx: 1, Descendants: 1, Tier: 2, Record: uint8(bpf.RecordFull)}
	placeRunRings(t, coll, row.RunIdx)
	if err := coll.Maps[bpf.MapRunSet].Update(&cgID, &row, ebpf.UpdateAny); err != nil {
		t.Fatalf("insert the run's cgroup into the run set: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{throwawayCert(t)}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	served := make(chan error, 1)
	go func() { served <- answerWith(ln, "application/json", sdkReply) }()

	run := source.RunRef{ID: "r-int-sdk", Agent: "a", CgroupID: cgID}
	sink := &fakeSink{}
	up, err := uprobe.New(uprobe.Options{Kernel: true, PinRoot: root,
		Rules: &agent.RuleTable{Record: agent.RecordFull}})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := New(Options{
		Rules:   &agent.RuleTable{Record: agent.RecordFull, Tier: backend.TierCgroup, Capture: agent.CaptureUprobe},
		BPFHash: hash, PinRoot: root, FlushInterval: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.AddProcessHook(up); err != nil {
		t.Fatal(err)
	}
	up.FollowKernel(hash)
	ctx := context.Background()
	if err := up.Start(ctx, run, sink); err != nil {
		t.Fatal(err)
	}
	defer up.Stop()
	if err := rec.Start(ctx, run, sink); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()

	cmd := exec.Command(python, "-c", sdkClient, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	cmd.Env = append(os.Environ(), "PYTHONPATH="+site, "PYTHONDONTWRITEBYTECODE=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: cgFD}
	cmd.Stderr = os.Stderr
	stdout, err := cmd.Output()
	if err != nil {
		t.Fatalf("the SDK client in the run's cgroup: %v", err)
	}
	t.Logf("python3: %s", strings.TrimSpace(string(stdout)))
	if err := <-served; err != nil {
		t.Fatalf("server: %v", err)
	}
	count := func(k record.Kind) (n int) {
		for _, ev := range sink.all() {
			if ev.Kind == k {
				n++
			}
		}
		return n
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && count(record.KindSSLResponse) == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if err := rec.Stop(); err != nil {
		t.Fatalf("recorder Stop: %v", err)
	}
	if err := up.Stop(); err != nil {
		t.Fatalf("capture Stop: %v", err)
	}
	_ = os.Remove(cgDir)
	var req, resp *record.Event
	for _, ev := range sink.all() {
		switch ev.Kind {
		case record.KindSSLRequest:
			req = ev
		case record.KindSSLResponse:
			resp = ev
		}
	}
	if count(record.KindSSLRequest) != 1 || count(record.KindSSLResponse) != 1 {
		t.Fatalf("%d ssl_request and %d ssl_response, want one each; capture gaps %+v", count(record.KindSSLRequest),
			count(record.KindSSLResponse), up.Gaps())
	}
	var rp record.SSLRequestPayload
	if err := json.Unmarshal(req.Payload, &rp); err != nil {
		t.Fatal(err)
	}
	var sp record.SSLResponsePayload
	if err := json.Unmarshal(resp.Payload, &sp); err != nil {
		t.Fatal(err)
	}
	if rp.Method != "POST" || rp.Path != "/v1/messages" || sp.Status != 200 || req.PID != cmd.Process.Pid {
		t.Errorf("ssl_request %+v from pid %d, ssl_response %+v; want POST /v1/messages from %d answered 200", rp,
			req.PID, sp, cmd.Process.Pid)
	}
	for _, g := range up.Gaps() {
		if strings.Contains(g.Binary, "python3") {
			t.Errorf("capture gap %+v for the SDK process whose exchange was captured", g)
		}
	}
	t.Logf("ssl_request %+v; ssl_response %+v; record gaps %+v; capture gaps %+v", rp, sp, rec.Gaps(), up.Gaps())
}

// openssl30Request is the plaintext TestIntegrationKernelRecordCapturesOpenSSL30's s_client client writes.
const openssl30Request = "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: 17\r\n\r\n{\"model\":\"opus\"}\n"

// TestIntegrationKernelRecordCapturesOpenSSL30: the same kernel-record-driven capture as
// TestIntegrationKernelRecordDrivesCapture, on OpenSSL 3.0, which has no SSL_write_ex2 and so is where R2's
// SSL_write_ex fallback is the write symbol set. The libraries are Ubuntu 24.04's libssl3t64 3.0.13, and the
// clients are that release's own openssl s_client (SSL_write, SSL_read) and CPython 3.12 (whose ssl module
// writes through SSL_write_ex), neither of which this box's userland can supply: TEGO_OPENSSL30_LIB names the
// directory holding libssl.so.3 and libcrypto.so.3, TEGO_OPENSSL30_BIN the openssl binary, and
// TEGO_OPENSSL30_PYTHONHOME a python3.12 tree (<home>/bin/python3.12). Each client's library is loaded from
// that directory by the dynamic loader, which is the open that reaches OnOpen and attaches it.
func TestIntegrationKernelRecordCapturesOpenSSL30(t *testing.T) {
	if !bpf.Available() {
		t.Skipf("needs the compiled objects: %v", bpf.ErrNotGenerated)
	}
	lib := os.Getenv("TEGO_OPENSSL30_LIB")
	if lib == "" {
		t.Skip("TEGO_OPENSSL30_LIB names no directory holding an OpenSSL 3.0 libssl.so.3")
	}
	// Each client names the variable it needs, checked inside its own subtest before anything is built: a
	// client whose files were not supplied skips alone, and the other still runs. cmd is handed the subtest's
	// t, because a Skip or Fatal on the parent's from inside a subtest fails the whole test instead.
	clients := []struct {
		name, need, why string
		cmd             func(t *testing.T, port, out string) *exec.Cmd
	}{
		{"openssl s_client", "TEGO_OPENSSL30_BIN", "no OpenSSL 3.0 openssl binary", func(t *testing.T, port, out string) *exec.Cmd {
			bin := os.Getenv("TEGO_OPENSSL30_BIN")
			req := filepath.Join(out, "request")
			if err := os.WriteFile(req, []byte(openssl30Request), 0o644); err != nil {
				t.Fatal(err)
			}
			// The pause stands for an agent's work between loading libssl and its first request: the
			// attach the library's open triggers is asynchronous to the process (capture-derive.md R4).
			return exec.Command("/bin/sh", "-c", `(sleep 1; cat "$1") | "$2" s_client -quiet -connect 127.0.0.1:"$3" `+
				`-servername api.anthropic.com`, "sh", req, bin, port)
		}},
		{"CPython ssl", "TEGO_OPENSSL30_PYTHONHOME", "no python3.12 tree linked against OpenSSL 3", func(t *testing.T, port, out string) *exec.Cmd {
			home := os.Getenv("TEGO_OPENSSL30_PYTHONHOME")
			cmd := exec.Command(filepath.Join(home, "bin", "python3.12"), "-c", kernelClient, port, out)
			cmd.Env = append(os.Environ(), "PYTHONHOME="+home, "PYTHONDONTWRITEBYTECODE=1")
			return cmd
		}},
	}
	for i, c := range clients {
		t.Run(c.name, func(t *testing.T) {
			if os.Getenv(c.need) == "" {
				t.Skipf("%s names %s", c.need, c.why)
			}
			hash := fmt.Sprintf("ossl30-%d", i)
			root, maps := pinRoot(t, hash)
			coll := loadTraceProc(t, maps)
			cgDir, cgFD, cgID := childCgroup(t, fmt.Sprintf("ossl30-%d", i))
			row := bpf.Run{RunIdx: 1, Descendants: 1, Tier: 2, Record: uint8(bpf.RecordFull)}
			placeRunRings(t, coll, row.RunIdx)
			if err := coll.Maps[bpf.MapRunSet].Update(&cgID, &row, ebpf.UpdateAny); err != nil {
				t.Fatalf("insert the run's cgroup into the run set: %v", err)
			}
			ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{throwawayCert(t)}})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			served := make(chan error, 1)
			go func() { served <- answerOne(ln) }()

			var logged lockedBuffer
			logger := slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))
			run := source.RunRef{ID: "r-int-ossl30", Agent: "a", CgroupID: cgID}
			sink := &fakeSink{}
			up, err := uprobe.New(uprobe.Options{Kernel: true, PinRoot: root, Logger: logger})
			if err != nil {
				t.Fatal(err)
			}
			rec, err := New(Options{
				Rules:   &agent.RuleTable{Record: agent.RecordFull, Tier: backend.TierCgroup, Capture: agent.CaptureUprobe},
				BPFHash: hash, PinRoot: root, FlushInterval: 200 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := rec.AddProcessHook(up); err != nil {
				t.Fatal(err)
			}
			up.FollowKernel(hash)
			ctx := context.Background()
			if err := up.Start(ctx, run, sink); err != nil {
				t.Fatal(err)
			}
			defer up.Stop()
			if err := rec.Start(ctx, run, sink); err != nil {
				t.Fatal(err)
			}
			defer rec.Stop()

			out := t.TempDir()
			if err := os.Chmod(out, 0o777); err != nil {
				t.Fatal(err)
			}
			cmd := c.cmd(t, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port), out)
			if cmd.Env == nil {
				cmd.Env = os.Environ()
			}
			cmd.Env = append(cmd.Env, "LD_LIBRARY_PATH="+lib)
			cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: cgFD}
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s in the run's cgroup: %v: %s", c.name, err, output)
			}
			if err := <-served; err != nil {
				t.Fatalf("server: %v", err)
			}
			byKind := func(k record.Kind) []*record.Event {
				var got []*record.Event
				for _, ev := range sink.all() {
					if ev.Kind == k {
						got = append(got, ev)
					}
				}
				return got
			}
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) && len(byKind(record.KindSSLResponse)) == 0 {
				time.Sleep(20 * time.Millisecond)
			}
			if err := rec.Stop(); err != nil {
				t.Fatalf("recorder Stop: %v", err)
			}
			if err := up.Stop(); err != nil {
				t.Fatalf("capture Stop: %v", err)
			}
			_ = os.Remove(cgDir)

			// The library attached is the 3.0 one, with R2's fallback: SSL_write and SSL_write_ex, no _ex2.
			attached := ""
			for _, line := range strings.Split(logged.String(), "\n") {
				if strings.Contains(line, "uprobe: attached "+filepath.Join(lib, "libssl.so.3")) {
					attached = line
				}
			}
			if !strings.Contains(attached, "writes [SSL_write SSL_write_ex]") {
				t.Errorf("no attach of %s with writes [SSL_write SSL_write_ex] in the source's log:\n%s", lib, logged.String())
			}
			reqs, resps := byKind(record.KindSSLRequest), byKind(record.KindSSLResponse)
			if len(reqs) != 1 || len(resps) != 1 {
				t.Fatalf("%d ssl_request and %d ssl_response, want one each; capture gaps %+v; client: %s", len(reqs),
					len(resps), up.Gaps(), output)
			}
			var rp record.SSLRequestPayload
			if err := json.Unmarshal(reqs[0].Payload, &rp); err != nil {
				t.Fatal(err)
			}
			var sp record.SSLResponsePayload
			if err := json.Unmarshal(resps[0].Payload, &sp); err != nil {
				t.Fatal(err)
			}
			if rp.Method != "POST" || rp.Path != "/v1/messages" || sp.Status != 200 || reqs[0].Cgroup != cgID {
				t.Errorf("ssl_request %+v, ssl_response %+v in cgroup %d; want POST /v1/messages answered 200 in %d",
					rp, sp, reqs[0].Cgroup, cgID)
			}
			t.Logf("%s; ssl_request %+v; ssl_response %+v; capture gaps %+v", attached, rp, sp, up.Gaps())
		})
	}
}

// lockedBuffer is a log sink the drain goroutine and the test read and write at once.
type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// waitDrained waits, for up to ten seconds, until rec's drain goroutine has read everything the ring holds. It
// replaced fixed 300 ms sleeps before Stop, which a loaded host could outrun. The ring's producer and consumer
// positions are read without the reader's lock, as Stop's own final drain reads them (ringbuf.Reader.AvailableBytes).
// A recorder over a reader that cannot say, or one that read nothing (inert), returns at once. A ring still not empty
// at the deadline is left to Stop and to the checks after it.
func waitDrained(t *testing.T, rec *Recorder) {
	t.Helper()
	f, ok := rec.reader.(flushReader)
	if !ok {
		return
	}
	deadline := time.Now().Add(10 * time.Second)
	for f.AvailableBytes() > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
}

// placeRunRings is the ring half of tier 2's Prepare for one run (ADR 0026 (1), (3)): a 4 MiB record ring and a
// 1 MiB capture ring at the run's slot, placed before its run-set row as Prepare places them. It returns the record
// ring.
func placeRunRings(t *testing.T, coll *ebpf.Collection, slot uint32) *ebpf.Map {
	t.Helper()
	var record *ebpf.Map
	for _, r := range []struct {
		kind string
		size uint32
	}{{bpf.RingRecord, 1 << 22}, {bpf.RingCapture, 1 << 20}} {
		ring, err := bpf.NewRing(r.kind, r.size)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ring.Close() })
		if err := bpf.InsertRing(coll.Maps[bpf.OuterOf(r.kind)], slot, ring); err != nil {
			t.Fatal(err)
		}
		if r.kind == bpf.RingRecord {
			record = ring
		}
	}
	return record
}

// loadTraceProc is the record's half of tier 2's Prepare: trace_proc with its maps pinned by name under maps, and
// every program attached host-wide until the test ends, each the way the backend attaches it (bpf.AttachTrace:
// the syscall result programs as tracepoints, the rest as tracing programs). The runs' rings are placeRunRings'.
func loadTraceProc(t *testing.T, maps string) *ebpf.Collection {
	t.Helper()
	spec, err := bpf.Load(bpf.ObjectTraceProc)
	if err != nil {
		t.Fatal(err)
	}
	// The backend leaves out what this kernel's BTF lacks (security_file_truncate below 6.2): trace_proc does not
	// load whole there.
	if kspec, err := btf.LoadKernelSpec(); err == nil {
		for name, fn := range bpf.OptionalTracePrograms {
			var f *btf.Func
			if kspec.TypeByName(fn, &f) != nil {
				delete(spec.Programs, name)
			}
		}
	}
	dropAbsentExecResults(spec)
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: maps}})
	if err != nil {
		t.Fatalf("load %s: %v", bpf.ObjectTraceProc, err)
	}
	t.Cleanup(coll.Close)
	for _, name := range bpf.TracePrograms {
		if coll.Programs[name] == nil {
			continue
		}
		l, err := bpf.AttachTrace(name, coll.Programs[name])
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		t.Cleanup(func() { _ = l.Close() })
	}
	return coll
}

func dropAbsentExecResults(spec *ebpf.CollectionSpec) {
	for name, event := range bpf.ExecResultTracepoints {
		if !bpf.ExecResultTracepointAvailable(event) {
			delete(spec.Programs, name)
		}
	}
}

// concurrentClient is the agent of TestIntegrationConcurrentRunsOfOneBuild: it opens its run's own file argv[3]
// times, execs true, and makes one TLS exchange with the fake model endpoint on argv[1], through the host's
// libssl, whose probes are the build's shared ones.
const concurrentClient = `import os, subprocess, sys, time
path = sys.argv[2]
for _ in range(int(sys.argv[3])):
    os.close(os.open(path, os.O_RDONLY))
subprocess.run(["true"], check=True)
import socket, ssl
time.sleep(0.3)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
body = b'{"model":"opus"}\n'
with socket.create_connection(("127.0.0.1", int(sys.argv[1]))) as raw:
    with ctx.wrap_socket(raw, server_hostname="api.anthropic.com") as s:
        s.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: "
                  + str(len(body)).encode() + b"\r\n\r\n" + body)
        data = b""
        while not (b"\r\n\r\n" in data and data.endswith(b"\n")):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
`

// concurrentOpens is how many times each run's agent opens its own file: open-heavy, and about 1 MB of the run's
// 2 MiB ring (the default record.ringbuf), so a run whose reader fell behind would show as a loss, not a flake.
const concurrentOpens = 3000

// TestIntegrationConcurrentRunsOfOneBuild is capture-derive.md E26 and ADR 0026's verification on the real objects, as root: 2, 8 and 32
// runs of one build at once, each with its own record and capture ring at its own slot at the default size, its
// own recorder and its own uprobe source over the build's shared capture probes, each agent opening its own file
// 3,000 times, execing true and making one TLS exchange. Each run's record has every exec and open of its own
// processes and none of another's, no ring lost anything, no run says kernel-record-unavailable or
// mechanism-unavailable, and each run's exchange is captured exactly once. Before, the second run of a build had
// no kernel record and no capture (one ring per build took one reader).
func TestIntegrationConcurrentRunsOfOneBuild(t *testing.T) {
	if !bpf.Available() {
		t.Skipf("needs the compiled objects: %v", bpf.ErrNotGenerated)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	for _, n := range []int{2, 8, 32} {
		t.Run(strconv.Itoa(n), func(t *testing.T) { concurrentRuns(t, python, n) })
	}
}

// concurrentRuns is one round of TestIntegrationConcurrentRunsOfOneBuild with n runs.
func concurrentRuns(t *testing.T, python string, n int) {
	hash := fmt.Sprintf("conc%d", n)
	root, maps := pinRoot(t, hash)
	coll := loadTraceProc(t, maps)
	state := t.TempDir()
	files := t.TempDir()
	rules := &agent.RuleTable{Record: agent.RecordFull, Tier: backend.TierCgroup, Capture: agent.CaptureUprobe}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{throwawayCert(t)}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	served := make(chan error, n)
	for range n {
		go func() { served <- answerOne(ln) }()
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	type side struct {
		run  source.RunRef
		fd   int
		path string
		rec  *Recorder
		up   *uprobe.Uprobe
		sink *fakeSink
		hook *hookLog
	}
	ctx := context.Background()
	sides := make([]*side, n)
	for i := range n {
		_, fd, cg := childCgroup(t, fmt.Sprintf("c%d-%d", n, i))
		slot := uint32(i + 1)
		// Prepare's order: the run's rings at its slot, then its run-set row.
		for _, kind := range []string{bpf.RingRecord, bpf.RingCapture} {
			ring, err := bpf.NewRing(kind, uint32(config.DefaultRingbuf))
			if err != nil {
				t.Fatal(err)
			}
			if err := bpf.InsertRing(coll.Maps[bpf.OuterOf(kind)], slot, ring); err != nil {
				t.Fatal(err)
			}
			_ = ring.Close()
		}
		row := bpf.Run{RunIdx: slot, Descendants: 1, Tier: 2, Record: uint8(bpf.RecordFull)}
		if err := coll.Maps[bpf.MapRunSet].Update(&cg, &row, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(files, fmt.Sprintf("run-%d", i))
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		rec, err := New(Options{Rules: rules, BPFHash: hash, PinRoot: root, FlushInterval: 200 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		up, err := uprobe.New(uprobe.Options{Kernel: true, PinRoot: root, StateDir: state, Rules: rules})
		if err != nil {
			t.Fatal(err)
		}
		s := &side{run: source.RunRef{ID: fmt.Sprintf("r-%d", i), Agent: "a", CgroupID: cg}, fd: fd, path: path,
			rec: rec, up: up, sink: &fakeSink{}, hook: &hookLog{}}
		// runtime.followKernelRecord's order: the hooks, the build, then the recorder before the source.
		for _, h := range []source.ProcessHook{s.hook, up} {
			if err := rec.AddProcessHook(h); err != nil {
				t.Fatal(err)
			}
		}
		up.FollowKernel(hash)
		if err := rec.Start(ctx, s.run, s.sink); err != nil {
			t.Fatal(err)
		}
		if err := up.Start(ctx, s.run, s.sink); err != nil {
			t.Fatal(err)
		}
		sides[i] = s
	}
	defer func() {
		for _, s := range sides {
			_ = s.rec.Stop()
			_ = s.up.Stop()
		}
	}()

	var wg sync.WaitGroup
	for _, s := range sides {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command(python, "-c", concurrentClient, port, s.path, strconv.Itoa(concurrentOpens))
			cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: s.fd}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%s's agent: %v: %s", s.run.ID, err, out)
			}
		}()
	}
	wg.Wait()
	for range n {
		if err := <-served; err != nil {
			t.Errorf("server: %v", err)
		}
	}
	deadline := time.Now().Add(30 * time.Second)
	for _, s := range sides {
		for time.Now().Before(deadline) && len(s.sink.byKind(record.KindSSLResponse)) < 1 {
			time.Sleep(20 * time.Millisecond)
		}
		waitDrained(t, s.rec)
	}
	for _, s := range sides {
		if err := s.rec.Stop(); err != nil {
			t.Errorf("%s recorder Stop: %v", s.run.ID, err)
		}
		if err := s.up.Stop(); err != nil {
			t.Errorf("%s uprobe Stop: %v", s.run.ID, err)
		}
	}

	for _, s := range sides {
		opens, trues := 0, 0
		for _, ev := range s.sink.all() {
			if ev.Cgroup != s.run.CgroupID {
				t.Errorf("%s recorded %s of cgroup %d, another run's (its own is %d)", s.run.ID, ev.Kind, ev.Cgroup,
					s.run.CgroupID)
				continue
			}
			switch ev.Kind {
			case record.KindFS:
				var p record.FSPayload
				if json.Unmarshal(ev.Payload, &p) == nil && p.Path == s.path {
					opens += max(p.Count, 1)
				}
			case record.KindExec:
				var p record.ExecPayload
				if json.Unmarshal(ev.Payload, &p) == nil && filepath.Base(p.Path) == "true" {
					trues++
				}
			}
		}
		if opens != concurrentOpens || trues != 1 {
			t.Errorf("%s recorded %d opens of its file and %d execs of true, want %d and 1", s.run.ID, opens, trues,
				concurrentOpens)
		}
		for _, c := range s.hook.all() {
			if f := strings.Fields(c); f[0] != "exit" && (len(f) < 3 || f[2] != strconv.FormatUint(s.run.CgroupID, 10)) {
				t.Errorf("%s fed its hook another run's process: %q", s.run.ID, c)
			}
		}
		if n := len(s.sink.byKind(record.KindSSLRequest)); n != 1 || len(s.sink.byKind(record.KindSSLResponse)) != 1 {
			t.Errorf("%s captured %d requests and %d responses, want its one exchange once", s.run.ID, n,
				len(s.sink.byKind(record.KindSSLResponse)))
		}
		for _, g := range append(s.rec.Gaps(), s.up.Gaps()...) {
			switch g.Why {
			case runtime.GapKernelRecordUnavailable, uprobe.GapMechanismUnavailable, GapRingbufFull,
				uprobe.GapRingBufferDrop, GapMalformedRecord:
				t.Errorf("%s gap %+v", s.run.ID, g)
			}
		}
	}
	t.Logf("%d runs of one build: each recorded its own %d opens and one exchange", n, concurrentOpens)
}

// testWriter sends a logger's lines to the test log.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}

// keys lists a map's keys for a failure message.
func keys(m map[string]*record.Event) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// childCgroup makes a cgroup under this process's own, named with suffix, and returns its path, an O_PATH
// descriptor for CLONE_INTO_CGROUP and its id (the directory's inode, what bpf_get_current_cgroup_id returns).
func childCgroup(t *testing.T, suffix string) (string, int, uint64) {
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
	dir := filepath.Join("/sys/fs/cgroup", rel, "tego-observe-test-"+strconv.Itoa(os.Getpid())+"-"+suffix)
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

// answerOne serves one HTTP/1.1 request over TLS.
func answerOne(ln net.Listener) error { return answerWith(ln, "", "{\"id\":\"msg_01\",\"x\":1}\n") }

// answerWith serves one HTTP/1.1 request over TLS with a 200 carrying body, and contentType when set.
func answerWith(ln net.Listener, contentType, body string) error {
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
		return err
	}
	head := "HTTP/1.1 200 OK\r\n"
	if contentType != "" {
		head += "Content-Type: " + contentType + "\r\nRequest-Id: req_sdk\r\n"
	}
	_, err = io.WriteString(conn, head+"Content-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
	return err
}

// throwawayCert is a self-signed server certificate.
func throwawayCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "api.anthropic.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
